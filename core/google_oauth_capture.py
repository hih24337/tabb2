import base64
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from core.tabbit_client import (
    TOKEN_METADATA_HEADER_KEYS,
    encode_token_metadata,
    sanitize_token_diagnostics,
)


TABBIT_ORIGIN = "https://web.tabbitbrowser.com"
GOOGLE_CLIENT_ID = "448526856882-gks4gsvgspqkcdt8jsql5b5en0mk3v15.apps.googleusercontent.com"
CAPTURE_TIMEOUT_SECONDS = 600
CHROME_IDENTITY_GRACE_SECONDS = 5
MOA_EXTENSION_ID = "nmbemfeekdkfhjikjegnegkndcehpfej"
MOA_CERTIFICATE_PROBE_INTERVAL_SECONDS = 5


@dataclass
class CaptureResult:
    kind: str
    value: str
    chrome_identity_header: str | None = None
    browser_headers: dict[str, str] = field(default_factory=dict)
    diagnostics: dict[str, object] = field(default_factory=dict)


@dataclass
class CaptureJob:
    id: str
    name: str
    force_relogin: bool = False
    status: str = "starting"
    message: str = "正在启动浏览器..."
    result: CaptureResult | None = None
    token_id: str | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    process: subprocess.Popen | None = None
    user_data_dir: str | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)


class GoogleOAuthCaptureManager:
    def __init__(self):
        self._jobs: dict[str, CaptureJob] = {}
        self._lock = threading.Lock()

    def start(self, name: str, force_relogin: bool = False) -> CaptureJob:
        job = CaptureJob(id=str(uuid.uuid4()), name=name, force_relogin=force_relogin)
        with self._lock:
            self._jobs[job.id] = job

        thread = threading.Thread(target=self._run_capture, args=(job,), daemon=True)
        thread.start()
        return job

    def get(self, job_id: str) -> CaptureJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job:
            return False
        job.stop_event.set()
        job.status = "cancelled"
        job.message = "已取消"
        self._cleanup(job)
        return True

    def _run_capture(self, job: CaptureJob):
        try:
            browser_path = _find_browser()
            debug_port = _free_port()
            user_data_dir = tempfile.mkdtemp(prefix="tabbit-google-login-")
            # force_relogin 时只 seed 浏览器启动必需的最小数据，跳过所有认证相关文件
            _seed_user_profile(user_data_dir, auth_only=not job.force_relogin)
            job.user_data_dir = user_data_dir
            login_url = f"{TABBIT_ORIGIN}/login"

            # Capture stderr for debugging launch issues
            stderr_log_path = Path(user_data_dir) / "_capture_stderr.log"
            stderr_log_file = open(stderr_log_path, "w", encoding="utf-8")

            job.process = subprocess.Popen(
                [
                    browser_path,
                    f"--remote-debugging-port={debug_port}",
                    f"--user-data-dir={user_data_dir}",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--start-maximized",
                    f"--app={login_url}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=stderr_log_file,
            )
            job.status = "waiting"
            job.message = f"Chrome 窗口（Tabbit AI）已打开，请点击页面右上角的 Tabbit2API Google 登录按钮。(pid={job.process.pid}, port={debug_port})"

            websocket_url = _wait_for_debugger(debug_port, job.stop_event)
            result = _listen_for_login_result(websocket_url, job.stop_event)
            if job.stop_event.is_set():
                return

            job.result = result
            job.status = "captured"
            job.message = "已捕获 Tabbit 登录凭据，正在保存 Token..."
        except Exception as exc:
            if not job.stop_event.is_set():
                job.status = "error"
                job.error = _safe_error(exc)
                job.message = job.error
        finally:
            self._cleanup(job)

    def _cleanup(self, job: CaptureJob):
        process = job.process
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

        if job.user_data_dir:
            shutil.rmtree(job.user_data_dir, ignore_errors=True)
            job.user_data_dir = None


def _find_browser() -> str:
    env_path = os.environ.get("TABBIT_BROWSER_PATH") or os.environ.get("GOOGLE_CHROME_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    candidates: list[str] = []
    if os.name == "nt":
        candidates.extend(_windows_browser_candidates(os.environ))
    elif sys_platform() == "darwin":
        candidates.extend(
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ]
        )

    for name in ("google-chrome", "chrome", "chromium", "chromium-browser", "msedge", "microsoft-edge"):
        resolved = shutil.which(name)
        if resolved:
            candidates.append(resolved)

    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    raise RuntimeError("未找到 Chrome 或 Edge。可设置 TABBIT_BROWSER_PATH 指向浏览器可执行文件。")


def _windows_browser_candidates(roots: dict[str, str | None]) -> list[str]:
    candidates: list[str] = []

    for root_name in ("LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"):
        root = roots.get(root_name)
        if not root:
            continue
        candidates.extend(
            [
                str(Path(root) / "Tabbit/Application/tabbit.exe"),
                str(Path(root) / "Tabbit/Tabbit.exe"),
                str(Path(root) / "Programs/Tabbit/Tabbit.exe"),
            ]
        )

    for root_name in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        root = roots.get(root_name)
        if not root:
            continue
        candidates.extend(
            [
                str(Path(root) / "Google/Chrome/Application/chrome.exe"),
                str(Path(root) / "Microsoft/Edge/Application/msedge.exe"),
            ]
        )

    return candidates


def _seed_user_profile(temp_user_data_dir: str, auth_only: bool = True):
    """
    Clone the minimum profile subset from local Tabbit data so the spawned
    browser can reuse existing login state when available.

    When auth_only=False (force_relogin mode), do NOT copy anything from
    the Tabbit profile. The browser will start with a completely clean
    profile, guaranteeing no cached auth state. This is slower to start
    but forces the user to re-authenticate from scratch.
    """
    if not auth_only:
        # force_relogin: skip all profile seeding for a clean slate
        return

    tabbit_user_data = Path(os.environ.get("LOCALAPPDATA", "")) / "Tabbit" / "User Data"
    if not tabbit_user_data.exists():
        return

    destination = Path(temp_user_data_dir)
    source_local_state = tabbit_user_data / "Local State"
    if source_local_state.exists():
        try:
            shutil.copy2(source_local_state, destination / "Local State")
        except Exception:
            pass

    source_default = tabbit_user_data / "Default"
    if not source_default.exists():
        return

    target_default = destination / "Default"
    target_default.mkdir(parents=True, exist_ok=True)

    preserve_paths = [
        "Network",
        "Preferences",
        "Web Data",
        "Local Storage",
        "Session Storage",
        "Cookies",
        "Login Data",
        "IndexedDB",
        "Local Extension Settings",
        "Sync Extension Settings",
        "Extension State",
    ]
    for relative in preserve_paths:
        src = source_default / relative
        dst = target_default / relative
        if not src.exists():
            continue
        try:
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
        except Exception:
            # Best-effort only: locked files should not break capture startup.
            continue


def sys_platform() -> str:
    import sys

    return sys.platform


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_debugger(port: int, stop_event: threading.Event) -> str:
    deadline = time.time() + 15
    last_error: Exception | None = None
    while time.time() < deadline and not stop_event.is_set():
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=1) as resp:
                targets = json.loads(resp.read().decode("utf-8"))
            for target in targets:
                url = target.get("url", "")
                ws_url = target.get("webSocketDebuggerUrl")
                if ws_url and ("web.tabbitbrowser.com" in url or target.get("type") == "page"):
                    return ws_url
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)

    if stop_event.is_set():
        raise RuntimeError("捕获已取消")
    raise RuntimeError(f"浏览器 DevTools 启动失败: {_safe_error(last_error)}")


def _listen_for_login_result(websocket_url: str, stop_event: threading.Event) -> CaptureResult:
    parsed = urllib.parse.urlparse(websocket_url)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("拒绝连接非本机 DevTools 地址")

    sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=5)
    sock.settimeout(1)
    try:
        _websocket_handshake(sock, parsed)
        _cdp_send(sock, 1, "Network.enable")
        _cdp_send(sock, 2, "Page.enable")
        _cdp_send(sock, 3, "Runtime.enable")
        _cdp_send(sock, 4, "Network.getCookies", {"urls": [TABBIT_ORIGIN]})
        _cdp_send(sock, 5, "Runtime.evaluate", _capture_overlay_eval_params())
        _cdp_send(sock, 6, "Runtime.evaluate", _moa_certificate_eval_params())

        deadline = time.time() + CAPTURE_TIMEOUT_SECONDS
        command_id = 7
        last_cookie_probe = time.time()
        last_overlay_probe = time.time()
        last_moa_probe = time.time()
        chrome_identity_header = None
        browser_headers: dict[str, str] = {}
        diagnostics: dict[str, object] = {}
        pending_id_token = None
        pending_id_token_seen_at = None
        pending_token_value = None
        pending_token_seen_at = None
        while time.time() < deadline and not stop_event.is_set():
            try:
                message = _websocket_recv(sock)
            except socket.timeout:
                now = time.time()
                if now - last_cookie_probe >= 2:
                    _cdp_send(sock, command_id, "Network.getCookies", {"urls": [TABBIT_ORIGIN]})
                    command_id += 1
                    last_cookie_probe = now
                if now - last_overlay_probe >= 2:
                    _cdp_send(sock, command_id, "Runtime.evaluate", _capture_overlay_eval_params())
                    command_id += 1
                    last_overlay_probe = now
                if now - last_moa_probe >= MOA_CERTIFICATE_PROBE_INTERVAL_SECONDS:
                    _cdp_send(sock, command_id, "Runtime.evaluate", _moa_certificate_eval_params())
                    command_id += 1
                    last_moa_probe = now
                continue

            if not message:
                continue

            chrome_identity_header = (
                _extract_chrome_identity_header_from_cdp(message)
                or chrome_identity_header
            )
            browser_headers.update(_extract_browser_header_profile_from_cdp(message))
            diagnostics.update(_extract_moa_certificate_diagnostics_from_cdp(message))
            if chrome_identity_header and pending_id_token:
                return CaptureResult(
                    kind="id_token",
                    value=pending_id_token,
                    chrome_identity_header=chrome_identity_header,
                    browser_headers=dict(browser_headers),
                    diagnostics=dict(diagnostics),
                )
            if chrome_identity_header and pending_token_value:
                token_value = _append_chrome_identity_header(
                    pending_token_value,
                    chrome_identity_header,
                )
                token_value = _append_token_metadata(
                    token_value,
                    browser_headers=browser_headers,
                    diagnostics=diagnostics,
                )
                return CaptureResult(
                    kind="tabbit_token",
                    value=token_value,
                    diagnostics=dict(diagnostics),
                )

            runtime_id_token = _extract_runtime_id_token_from_cdp(message)
            if runtime_id_token:
                if chrome_identity_header:
                    return CaptureResult(
                        kind="id_token",
                        value=runtime_id_token,
                        chrome_identity_header=chrome_identity_header,
                        browser_headers=dict(browser_headers),
                        diagnostics=dict(diagnostics),
                    )
                pending_id_token = runtime_id_token
                pending_id_token_seen_at = time.time()

            request_id = _request_id_for_post_data(message)
            if request_id:
                _cdp_send(sock, command_id, "Network.getRequestPostData", {"requestId": request_id})
                command_id += 1

            id_token = _extract_id_token_from_cdp(message)
            if id_token:
                if chrome_identity_header:
                    return CaptureResult(
                        kind="id_token",
                        value=id_token,
                        chrome_identity_header=chrome_identity_header,
                        browser_headers=dict(browser_headers),
                        diagnostics=dict(diagnostics),
                    )
                pending_id_token = id_token
                pending_id_token_seen_at = time.time()

            token_value = _extract_tabbit_token_from_cdp(
                message,
                chrome_identity_header=chrome_identity_header,
                browser_headers=browser_headers,
                diagnostics=diagnostics,
            )
            if token_value:
                if chrome_identity_header:
                    return CaptureResult(
                        kind="tabbit_token",
                        value=token_value,
                        diagnostics=dict(diagnostics),
                    )
                pending_token_value = token_value
                pending_token_seen_at = time.time()

            now = time.time()
            if (
                pending_id_token
                and pending_id_token_seen_at
                and now - pending_id_token_seen_at >= CHROME_IDENTITY_GRACE_SECONDS
            ):
                return CaptureResult(
                    kind="id_token",
                    value=pending_id_token,
                    diagnostics=dict(diagnostics),
                )
            if (
                pending_token_value
                and pending_token_seen_at
                and now - pending_token_seen_at >= CHROME_IDENTITY_GRACE_SECONDS
            ):
                token_value = _append_token_metadata(
                    pending_token_value,
                    diagnostics=diagnostics,
                )
                return CaptureResult(
                    kind="tabbit_token",
                    value=token_value,
                    diagnostics=dict(diagnostics),
                )
            if now - last_cookie_probe >= 2:
                _cdp_send(sock, command_id, "Network.getCookies", {"urls": [TABBIT_ORIGIN]})
                command_id += 1
                last_cookie_probe = now
            if now - last_overlay_probe >= 2:
                _cdp_send(sock, command_id, "Runtime.evaluate", _capture_overlay_eval_params())
                command_id += 1
                last_overlay_probe = now
            if now - last_moa_probe >= MOA_CERTIFICATE_PROBE_INTERVAL_SECONDS:
                _cdp_send(sock, command_id, "Runtime.evaluate", _moa_certificate_eval_params())
                command_id += 1
                last_moa_probe = now

        if stop_event.is_set():
            raise RuntimeError("捕获已取消")
        raise RuntimeError("登录超时，未捕获到 Tabbit 登录凭据")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _websocket_handshake(sock: socket.socket, parsed: urllib.parse.ParseResult):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port or 80}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    if b" 101 " not in response.split(b"\r\n", 1)[0]:
        raise RuntimeError("DevTools WebSocket 握手失败")


def _cdp_send(sock: socket.socket, message_id: int, method: str, params: dict[str, object] | None = None):
    payload = json.dumps({"id": message_id, "method": method, "params": params or {}}).encode("utf-8")
    _websocket_send(sock, payload)


def _capture_overlay_eval_params() -> dict[str, object]:
    return {
        "expression": _capture_overlay_expression(),
        "awaitPromise": False,
        "returnByValue": True,
    }


def _moa_certificate_eval_params() -> dict[str, object]:
    extension_id = json.dumps(MOA_EXTENSION_ID)
    return {
        "expression": f"""
(() => new Promise((resolve) => {{
  const runtime = window.chrome && window.chrome.runtime;
  if (!runtime || typeof runtime.sendMessage !== "function") {{
    resolve({{ success: false, error: "chrome.runtime.sendMessage unavailable" }});
    return;
  }}

  let settled = false;
  const finish = (value) => {{
    if (settled) return;
    settled = true;
    resolve(value || {{}});
  }};

  try {{
    runtime.sendMessage(
      {extension_id},
      {{
        type: "check_moa_certificate",
        data: {{}},
        timestamp: Date.now()
      }},
      (response) => {{
        if (runtime.lastError) {{
          finish({{ success: false, error: runtime.lastError.message || String(runtime.lastError) }});
          return;
        }}
        finish(response || {{}});
      }}
    );
    setTimeout(() => finish({{ success: false, error: "moa certificate probe timed out" }}), 3000);
  }} catch (error) {{
    finish({{ success: false, error: error && error.message ? error.message : String(error) }});
  }}
}}))()
""",
        "awaitPromise": True,
        "returnByValue": True,
    }


def _capture_overlay_expression() -> str:
    client_id = json.dumps(GOOGLE_CLIENT_ID)
    return f"""
(() => {{
  const allowedHost = location.hostname === "web.tabbitbrowser.com" || location.hostname.endsWith(".tabbitbrowser.com");
  if (!allowedHost) return "";

  window.__tabbit2apiCapturedCredential = window.__tabbit2apiCapturedCredential || "";

  const renderGoogleButton = () => {{
    const status = document.getElementById("tabbit2api-google-status");
    const buttonHost = document.getElementById("tabbit2api-google-button");
    if (!buttonHost || !window.google || !window.google.accounts || !window.google.accounts.id) return false;
    if (buttonHost.dataset.rendered === "1") return true;

    buttonHost.dataset.rendered = "1";
    window.google.accounts.id.initialize({{
      client_id: {client_id},
      callback: (response) => {{
        window.__tabbit2apiCapturedCredential = response && response.credential ? response.credential : "";
        if (status) {{
          status.textContent = window.__tabbit2apiCapturedCredential
            ? "已捕获登录凭据，正在保存..."
            : "未收到登录凭据，请重试。";
        }}
      }},
      auto_select: false,
      cancel_on_tap_outside: false,
      ux_mode: "popup",
      use_fedcm_for_button: false,
      use_fedcm_for_prompt: false
    }});
    window.google.accounts.id.renderButton(buttonHost, {{
      theme: "outline",
      size: "large",
      type: "standard",
      shape: "rectangular",
      text: "signin_with",
      width: 280
    }});
    if (status) status.textContent = "请点击上方 Google 登录按钮。";
    return true;
  }};

  if (!document.getElementById("tabbit2api-google-capture")) {{
    const root = document.createElement("div");
    root.id = "tabbit2api-google-capture";
    root.style.cssText = [
      "position:fixed",
      "top:16px",
      "right:16px",
      "z-index:2147483647",
      "width:320px",
      "box-sizing:border-box",
      "padding:14px",
      "border-radius:10px",
      "background:#111827",
      "color:#f9fafb",
      "box-shadow:0 16px 40px rgba(0,0,0,.35)",
      "font-family:Arial,'Microsoft YaHei',sans-serif",
      "line-height:1.4",
      "border:1px solid rgba(255,255,255,.14)"
    ].join(";");
    root.innerHTML = [
      '<div style="font-size:14px;font-weight:700;margin-bottom:6px">Tabbit2API Google 登录</div>',
      '<div style="font-size:12px;color:#d1d5db;margin-bottom:10px">在 Tabbit 官方域名内登录，可避开 localhost 的 OAuth 来源限制。</div>',
      '<div id="tabbit2api-google-button" style="min-height:40px"></div>',
      '<div id="tabbit2api-google-status" style="font-size:12px;color:#9ca3af;margin-top:10px">正在加载 Google 登录按钮...</div>'
    ].join("");
    (document.body || document.documentElement).appendChild(root);

    window.__tabbit2apiRenderGoogleButton = renderGoogleButton;
    if (!renderGoogleButton()) {{
      const existingScript = document.querySelector('script[src="https://accounts.google.com/gsi/client"]');
      const script = existingScript || document.createElement("script");
      if (!existingScript) {{
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.defer = true;
        script.onload = renderGoogleButton;
        script.onerror = () => {{
          const status = document.getElementById("tabbit2api-google-status");
          if (status) status.textContent = "Google 登录组件加载失败，请检查网络。";
        }};
        document.head.appendChild(script);
      }}
      if (!window.__tabbit2apiGoogleRenderTimer) {{
        window.__tabbit2apiGoogleRenderTimer = window.setInterval(() => {{
          if (renderGoogleButton()) {{
            window.clearInterval(window.__tabbit2apiGoogleRenderTimer);
            window.__tabbit2apiGoogleRenderTimer = 0;
          }}
        }}, 500);
      }}
    }}
  }} else if (typeof window.__tabbit2apiRenderGoogleButton === "function") {{
    window.__tabbit2apiRenderGoogleButton();
  }}

  return window.__tabbit2apiCapturedCredential || "";
}})()
"""


def _websocket_send(sock: socket.socket, payload: bytes, opcode: int = 0x1):
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))

    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def _websocket_recv(sock: socket.socket) -> str:
    first = _recv_exact(sock, 2)
    opcode = first[0] & 0x0F
    masked = bool(first[1] & 0x80)
    length = first[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]

    mask = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))

    if opcode == 0x8:
        raise RuntimeError("DevTools WebSocket 已关闭")
    if opcode == 0x9:
        _websocket_send(sock, payload, opcode=0xA)
        return ""
    if opcode != 0x1:
        return ""
    return payload.decode("utf-8", errors="replace")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("DevTools WebSocket 连接中断")
        data += chunk
    return data


def _extract_id_token_from_cdp(message: str) -> str | None:
    try:
        event = json.loads(message)
    except json.JSONDecodeError:
        return None

    params = event.get("params")
    if not isinstance(params, dict):
        return None

    request = params.get("request")
    if isinstance(request, dict):
        post_data = request.get("postData")
        if isinstance(post_data, str):
            token = _extract_id_token(post_data)
            if token:
                return token

    return _extract_id_token(message)


def _extract_runtime_id_token_from_cdp(message: str) -> str | None:
    try:
        event = json.loads(message)
    except json.JSONDecodeError:
        return None

    result = event.get("result")
    if not isinstance(result, dict):
        return None

    runtime_result = result.get("result")
    if not isinstance(runtime_result, dict):
        return None

    value = runtime_result.get("value")
    if isinstance(value, str) and _looks_like_jwt(value):
        return value
    return None


def _extract_chrome_identity_header_from_cdp(message: str) -> str | None:
    try:
        event = json.loads(message)
    except json.JSONDecodeError:
        return None

    params = event.get("params")
    if not isinstance(params, dict):
        return None

    header_sets = []
    headers = params.get("headers")
    if isinstance(headers, dict):
        header_sets.append(headers)

    request = params.get("request")
    if isinstance(request, dict):
        request_headers = request.get("headers")
        if isinstance(request_headers, dict):
            header_sets.append(request_headers)

    for headers in header_sets:
        for name, value in headers.items():
            if str(name).lower() != "x-chrome-id-consistency-request":
                continue
            if isinstance(value, str) and value.strip():
                return value.strip()

    return None


def _extract_browser_header_profile_from_cdp(message: str) -> dict[str, str]:
    try:
        event = json.loads(message)
    except json.JSONDecodeError:
        return {}

    params = event.get("params")
    if not isinstance(params, dict):
        return {}

    header_sets = []
    headers = params.get("headers")
    if isinstance(headers, dict):
        header_sets.append(headers)

    request = params.get("request")
    if isinstance(request, dict):
        request_headers = request.get("headers")
        if isinstance(request_headers, dict):
            header_sets.append(request_headers)

    profile: dict[str, str] = {}
    for headers in header_sets:
        for name, value in headers.items():
            normalized_name = str(name).lower()
            if normalized_name not in TOKEN_METADATA_HEADER_KEYS:
                continue
            if isinstance(value, str) and value.strip():
                profile[normalized_name] = value.strip()
    return profile


def _extract_moa_certificate_diagnostics_from_cdp(message: str) -> dict[str, object]:
    try:
        event = json.loads(message)
    except json.JSONDecodeError:
        return {}

    result = event.get("result")
    if not isinstance(result, dict):
        return {}

    runtime_result = result.get("result")
    if not isinstance(runtime_result, dict):
        return {}

    value = runtime_result.get("value")
    if not isinstance(value, dict):
        return {}

    diagnostics: dict[str, object] = {}
    success = value.get("success")
    if isinstance(success, bool):
        diagnostics["moa_check_success"] = success

    data = value.get("data")
    if isinstance(data, dict):
        has_moa_certificate = data.get("hasMoaCertificate")
        if isinstance(has_moa_certificate, bool):
            diagnostics["has_moa_certificate"] = has_moa_certificate
        platform = data.get("platform")
        if isinstance(platform, str) and platform:
            diagnostics["moa_platform"] = platform

    error = value.get("error")
    if isinstance(error, str) and error:
        diagnostics["moa_error"] = error
        diagnostics.setdefault("moa_check_available", False)

    return sanitize_token_diagnostics(diagnostics)


def _append_chrome_identity_header(token_value: str, chrome_identity_header: str) -> str:
    parts = token_value.split("|")
    while len(parts) < 3:
        parts.append("")
    if len(parts) == 3:
        parts.append(chrome_identity_header)
    else:
        parts[3] = chrome_identity_header
    return "|".join(parts)


def _append_token_metadata(
    token_value: str,
    browser_headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    diagnostics: dict[str, object] | None = None,
) -> str:
    parts = token_value.split("|", 4)
    metadata: dict[str, object] = {}
    if len(parts) > 4:
        try:
            padded = parts[4] + ("=" * ((4 - len(parts[4]) % 4) % 4))
            decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
            existing = json.loads(decoded)
            if isinstance(existing, dict):
                metadata.update(existing)
        except Exception:
            metadata = {}

    if browser_headers:
        metadata["headers"] = {
            key: value
            for key, value in browser_headers.items()
            if key in TOKEN_METADATA_HEADER_KEYS and isinstance(value, str) and value
        }
    if cookies:
        metadata["cookies"] = {
            key: value
            for key, value in cookies.items()
            if isinstance(key, str) and isinstance(value, str) and value
        }
    sanitized_diagnostics = sanitize_token_diagnostics(diagnostics)
    if sanitized_diagnostics:
        metadata["diagnostics"] = sanitized_diagnostics
    if not metadata:
        return token_value

    while len(parts) < 4:
        parts.append("")
    if len(parts) == 4:
        parts.append(encode_token_metadata(metadata))
    else:
        parts[4] = encode_token_metadata(metadata)
    return "|".join(parts)


def _extract_tabbit_token_from_cdp(
    message: str,
    chrome_identity_header: str | None = None,
    browser_headers: dict[str, str] | None = None,
    diagnostics: dict[str, object] | None = None,
) -> str | None:
    token = ""
    next_auth = ""
    captured_cookies: dict[str, str] = {}
    try:
        event = json.loads(message)
    except json.JSONDecodeError:
        return None

    params = event.get("params")
    if not isinstance(params, dict):
        params = {}

    response = params.get("response")
    if isinstance(response, dict):
        url = response.get("url", "")
        if isinstance(url, str) and "web.tabbitbrowser.com" not in url:
            response = None
        if response:
            headers = response.get("headers")
            if isinstance(headers, dict):
                header_text = "\n".join(str(value) for value in headers.values())
                token, next_auth = _extract_tabbit_cookies(header_text)

    result = event.get("result")
    if isinstance(result, dict):
        cookies = result.get("cookies")
        if isinstance(cookies, list):
            for cookie in cookies:
                if not isinstance(cookie, dict):
                    continue
                name = str(cookie.get("name", "")).lower()
                value = cookie.get("value")
                if not isinstance(value, str):
                    continue
                captured_cookies[str(cookie.get("name", ""))] = value
                if name == "token":
                    token = value
                elif name == "next-auth.session-token":
                    next_auth = value

    if not token:
        token, next_auth = _extract_tabbit_cookies(message)

    if not token:
        return None

    parts = [token, next_auth, str(uuid.uuid4())]
    if chrome_identity_header:
        parts.append(chrome_identity_header)
    return _append_token_metadata(
        "|".join(parts),
        browser_headers=browser_headers,
        cookies=captured_cookies,
        diagnostics=diagnostics,
    )


def _extract_tabbit_cookies(text: str) -> tuple[str, str]:
    token = ""
    next_auth = ""
    for name, value in re.findall(r"(?i)(token|next-auth\.session-token)=([^;\s,\"]+)", text):
        if name.lower() == "token":
            token = urllib.parse.unquote(value)
        elif name.lower() == "next-auth.session-token":
            next_auth = urllib.parse.unquote(value)
    return token, next_auth


def _request_id_for_post_data(message: str) -> str | None:
    try:
        event = json.loads(message)
    except json.JSONDecodeError:
        return None

    if event.get("method") != "Network.requestWillBeSent":
        return None

    params = event.get("params")
    if not isinstance(params, dict):
        return None

    request = params.get("request")
    if not isinstance(request, dict):
        return None
    if request.get("method") != "POST":
        return None

    url = request.get("url", "")
    if not isinstance(url, str) or (
        "accounts.google.com" not in url and "web.tabbitbrowser.com" not in url
    ):
        return None

    request_id = params.get("requestId")
    return request_id if isinstance(request_id, str) else None


def _extract_id_token(text: str) -> str | None:
    parsed = urllib.parse.parse_qs(text)
    for key in ("id_token", "credential"):
        values = parsed.get(key)
        if values and _looks_like_jwt(values[0]):
            return values[0]

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("id_token", "credential"):
                value = data.get(key)
                if isinstance(value, str) and _looks_like_jwt(value):
                    return value
    except json.JSONDecodeError:
        pass

    match = re.search(r"(?:id_token|credential)[\"'=:\s]+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", text)
    if match and _looks_like_jwt(match.group(1)):
        return match.group(1)
    return None


def _looks_like_jwt(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value))


def _safe_error(exc: Exception | None) -> str:
    if exc is None:
        return "未知错误"
    text = str(exc)
    text = re.sub(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[redacted-token]", text)
    return text[:300]

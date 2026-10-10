import re
import json
import uuid
import hashlib
import hmac
import base64
import time
import urllib.parse
import os
from typing import AsyncGenerator

import httpx

TOKEN_METADATA_HEADER_KEYS = {
    "user-agent": "User-Agent",
    "sec-ch-ua": "sec-ch-ua",
    "sec-ch-ua-mobile": "sec-ch-ua-mobile",
    "sec-ch-ua-platform": "sec-ch-ua-platform",
    "accept-language": "accept-language",
}
TOKEN_METADATA_DIAGNOSTIC_KEYS = {
    "has_moa_certificate",
    "moa_platform",
    "moa_check_success",
    "moa_check_available",
    "moa_error",
}
CHAT_SIGNING_KEY = "f8d0e6a73f8d4b1a9c3d2e1f9a4b7c6d"
TABBIT_REQUEST_CONTEXT = "0.30.18(10030018)"


def encode_token_metadata(metadata: dict) -> str:
    raw = json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_token_metadata(value: str | None) -> dict:
    if not value:
        return {}
    try:
        padded = value + ("=" * ((4 - len(value) % 4) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        metadata = json.loads(decoded)
        return metadata if isinstance(metadata, dict) else {}
    except Exception:
        return {}


def sanitize_token_diagnostics(diagnostics: object) -> dict[str, object]:
    if not isinstance(diagnostics, dict):
        return {}

    sanitized: dict[str, object] = {}
    for key, value in diagnostics.items():
        if key not in TOKEN_METADATA_DIAGNOSTIC_KEYS:
            continue
        if isinstance(value, bool):
            sanitized[key] = value
        elif isinstance(value, str) and value.strip():
            sanitized[key] = value.strip()[:200]
    return sanitized


def token_diagnostics_from_value(token_value: str | None) -> dict[str, object]:
    if not token_value:
        return {}
    parts = token_value.split("|", 4)
    metadata = decode_token_metadata(parts[4] if len(parts) > 4 else None)
    return sanitize_token_diagnostics(metadata.get("diagnostics"))


def _read_windows_registry_string(path: str, value_name: str) -> str | None:
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value if isinstance(value, str) and value else None
    except Exception:
        return None


def _read_windows_default_browser_prog_id(scheme: str) -> str | None:
    if os.name != "nt":
        return None

    base_path = (
        "Software\\Microsoft\\Windows\\Shell\\Associations\\"
        f"UrlAssociations\\{scheme}"
    )
    return _read_windows_registry_string(
        f"{base_path}\\UserChoiceLatest\\ProgId",
        "ProgId",
    ) or _read_windows_registry_string(
        f"{base_path}\\UserChoice",
        "ProgId",
    )


def get_local_tabbit_environment_diagnostics() -> dict[str, object]:
    diagnostics: dict[str, object] = {}
    if os.name != "nt":
        return diagnostics

    http_prog_id = _read_windows_default_browser_prog_id("http")
    https_prog_id = _read_windows_default_browser_prog_id("https")
    if http_prog_id or https_prog_id:
        diagnostics["windows_default_browser"] = {
            "http_prog_id": http_prog_id or "",
            "https_prog_id": https_prog_id or "",
        }
        diagnostics["tabbit_is_default_browser"] = all(
            "tabbit" in (value or "").lower()
            for value in (http_prog_id, https_prog_id)
        )
    return diagnostics


def build_tabbit_error_message(
    error,
    token_value: str | None = None,
    local_diagnostics: dict[str, object] | None = None,
) -> str:
    message = f"[Tabbit API Error {error.code}] {error.message}"
    is_update_gate = error.code == 493 or error.action == "update_version"
    if not is_update_gate:
        return message

    token_diagnostics = token_diagnostics_from_value(token_value)
    diagnostics = local_diagnostics or {}
    parts = [message]

    if token_diagnostics.get("has_moa_certificate") is False:
        parts.append(
            "Diagnostics: hasMoaCertificate=false. Tabbit AI entitlement is "
            "not active for this local Tabbit profile."
        )
    else:
        parts.append(
            "Diagnostics: Tabbit rejected AI access with update_version. "
            "This is usually an app entitlement/default-browser gate, not a "
            "plain token refresh problem."
        )

    windows_default = diagnostics.get("windows_default_browser")
    if isinstance(windows_default, dict):
        http_prog_id = windows_default.get("http_prog_id", "")
        https_prog_id = windows_default.get("https_prog_id", "")
        parts.append(
            f"Local default browser: http={http_prog_id or 'unknown'}, "
            f"https={https_prog_id or 'unknown'}."
        )

    if diagnostics.get("tabbit_is_default_browser") is True:
        parts.append(
            "Tabbit is already the system default browser. Open the real "
            "Tabbit browser profile, activate Tabbit AI/MOA entitlement, make "
            "sure any in-browser AI membership prompt is cleared, then "
            "capture/login again and retest."
        )
    else:
        parts.append(
            "Set Tabbit as the system default browser, reopen Tabbit, make sure "
            "the in-browser AI membership/default-browser prompt is cleared, then "
            "capture/login again and retest."
        )
    return " ".join(parts)


def build_chat_signature_headers(
    body: str,
    timestamp: str | None = None,
    signature: str | None = None,
    signing_key: str = CHAT_SIGNING_KEY,
) -> dict[str, str]:
    resolved_timestamp = timestamp or str(int(time.time() * 1000))
    resolved_signature = signature or str(uuid.uuid4())
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    signed_payload = f"{resolved_timestamp}.{resolved_signature}.{body_hash}"
    nonce = hmac.new(
        signing_key.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "x-timestamp": resolved_timestamp,
        "x-nonce": nonce,
        "x-signature": resolved_signature,
    }


class TabbitApiError(Exception):
    """Raised when the Tabbit upstream API returns an error event."""

    def __init__(self, code: int = 0, message: str = "", action: str = ""):
        self.code = code
        self.message = message
        self.action = action
        super().__init__(f"Tabbit API error {code}: {message} (action={action})")

MODEL_MAP = {
    "best": "最佳",
    "gpt-5.2-chat": "GPT-5.2-Chat",
    "gpt-5.1-chat": "GPT-5.1-Chat",
    "gemini-3.1-pro": "Gemini-3.1-Pro",
    "gemini-3-flash": "Gemini-3-Flash",
    "gemini-2.5-flash": "Gemini-2.5-Flash",
    "claude-sonnet-4.6": "Claude-Sonnet-4.6",
    "claude-haiku-4.5": "Claude-Haiku-4.5",
    "glm-5": "GLM-5",
    "deepseek-v3.2": "DeepSeek-V3.2",
    "minimax-m2.5": "MiniMax-M2.5",
    "kimi-k2.5": "Kimi-K2.5",
    "qwen3.5-plus": "Qwen3.5-Plus",
    "doubao-seed-1.8": "Doubao-Seed-1.8",
}

MODEL_CONFIG_CACHE_TTL_SECONDS = 300
_model_config_cache: tuple[float, str, list[dict]] | None = None


def model_id_from_display_name(display_name: str) -> str:
    model_id = re.sub(r"[^a-z0-9.]+", "-", display_name.lower()).strip("-")
    return model_id or display_name.lower()


def _fallback_model_options() -> list[dict]:
    return [
        {
            "id": model_id,
            "object": "model",
            "owned_by": "tabbit",
            "display_name": display_name,
        }
        for model_id, display_name in MODEL_MAP.items()
    ]


async def get_available_models(base_url: str | None = None) -> list[dict]:
    global _model_config_cache

    resolved_base_url = (base_url or "https://web.tabbitbrowser.com").rstrip("/")
    now = time.time()
    if (
        _model_config_cache
        and _model_config_cache[1] == resolved_base_url
        and now - _model_config_cache[0] < MODEL_CONFIG_CACHE_TTL_SECONDS
    ):
        return [dict(item) for item in _model_config_cache[2]]

    try:
        async with httpx.AsyncClient(verify=False, timeout=8) as client:
            resp = await client.get(
                f"{resolved_base_url}/proxy/v1/model_config/models",
                params={"a": "0"},
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Referer": f"{resolved_base_url}/newtab",
                },
            )
        resp.raise_for_status()
        body = resp.json()
        raw_models = body.get("models") if isinstance(body, dict) else None
        if not isinstance(raw_models, list):
            raise ValueError("Tabbit model response missing models")

        models: list[dict] = []
        seen: set[str] = set()
        for item in sorted(
            raw_models,
            key=lambda value: value.get("sort_order", 9999)
            if isinstance(value, dict)
            else 9999,
        ):
            if not isinstance(item, dict):
                continue
            display_name = item.get("display_name")
            if not isinstance(display_name, str) or not display_name.strip():
                continue
            model_id = model_id_from_display_name(display_name.strip())
            if model_id in seen:
                continue
            seen.add(model_id)
            models.append(
                {
                    "id": model_id,
                    "object": "model",
                    "owned_by": "tabbit",
                    "display_name": display_name.strip(),
                    "supports_images": bool(item.get("supports_images")),
                    "supports_tools": bool(item.get("supports_tools")),
                    "support_thinking": bool(item.get("support_thinking")),
                    "use_thinking": bool(item.get("use_thinking")),
                    "model_access_type": item.get("model_access_type"),
                }
            )

        if not models:
            raise ValueError("Tabbit model response empty")

        _model_config_cache = (now, resolved_base_url, models)
        return [dict(item) for item in models]
    except Exception:
        return _fallback_model_options()


async def get_available_model_map(base_url: str | None = None) -> dict[str, str]:
    models = await get_available_models(base_url)
    return {
        item["id"]: item.get("display_name", item["id"])
        for item in models
        if isinstance(item.get("id"), str)
    }


async def resolve_tabbit_model(
    model: str | None,
    base_url: str | None = None,
    default_model: str = "best",
) -> str:
    requested = (model or default_model or "best").lower()
    model_map = await get_available_model_map(base_url)

    if requested in model_map:
        return model_map[requested]
    if requested in MODEL_MAP:
        return MODEL_MAP[requested]

    for display_name in model_map.values():
        if display_name.lower() == requested:
            return display_name

    default_key = (default_model or "best").lower()
    return model_map.get(default_key) or MODEL_MAP.get(default_key) or model_map.get("best") or MODEL_MAP["best"]


class TabbitClient:
    def __init__(self, token_str: str, base_url: str | None = None, client_id: str | None = None):
        parts = token_str.split("|", 4)
        self.jwt_token = parts[0]
        self.next_auth = parts[1] if len(parts) > 1 and parts[1] else None
        self.device_id = parts[2] if len(parts) > 2 and parts[2] else str(uuid.uuid4())
        self.chrome_identity_header = parts[3] if len(parts) > 3 and parts[3] else None
        self.metadata = decode_token_metadata(parts[4] if len(parts) > 4 else None)
        self.user_id = self._extract_user_id(self.jwt_token)
        self.base_url = base_url or "https://web.tabbitbrowser.com"
        self.client_id = client_id or "e7fa44387b1238ef1f6f"

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15, read=120, write=15, pool=15),
            follow_redirects=False,
            verify=False,
        )

    def _extract_user_id(self, token: str) -> str:
        try:
            payload = json.loads(
                base64.urlsafe_b64decode(token.split(".")[1] + "==")
            )
            return payload.get("id", payload.get("sub", str(uuid.uuid4())))
        except Exception:
            return str(uuid.uuid4())

    def _get_headers(self, referer_path: str = "/newtab") -> dict:
        chrome_identity_header = self.chrome_identity_header or (
            f"version=1,client_id={self.client_id},"
            f"device_id={self.device_id},sync_account_id={self.user_id},"
            "signin_mode=all_accounts,signout_mode=show_confirmation"
        )
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not:A-Brand";v="99", "Tabbit";v="145", "Chromium";v="145"',
            "sec-ch-ua-platform": '"Windows"',
            "x-chrome-id-consistency-request": chrome_identity_header,
            "referer": f"{self.base_url}{referer_path}",
        }
        metadata_headers = self.metadata.get("headers")
        if isinstance(metadata_headers, dict):
            for source_key, target_key in TOKEN_METADATA_HEADER_KEYS.items():
                value = metadata_headers.get(source_key)
                if isinstance(value, str) and value.strip():
                    headers[target_key] = value.strip()
        return headers

    def _get_cookies(self) -> dict:
        metadata_cookies = self.metadata.get("cookies")
        cookies = dict(metadata_cookies) if isinstance(metadata_cookies, dict) else {}
        cookies.update({
            "token": self.jwt_token,
            "user_id": self.user_id,
            "managed": "tab_browser",
            "NEXT_LOCALE": "zh",
        })
        if self.next_auth:
            cookies["next-auth.session-token"] = self.next_auth
        return cookies

    async def create_chat_session(self) -> str:
        router_state = [
            "",
            {
                "children": [
                    "chat",
                    {
                        "children": [
                            ["id", "new", "d"],
                            {"children": ["__PAGE__", {}, None, "refetch"]},
                            None,
                            None,
                        ]
                    },
                    None,
                    None,
                ]
            },
            None,
            None,
        ]
        headers = {
            **self._get_headers("/chat/new"),
            "rsc": "1",
            "next-router-state-tree": urllib.parse.quote(json.dumps(router_state)),
        }

        resp = await self.client.get(
            f"{self.base_url}/chat/new",
            params={"_rsc": "auto"},
            headers=headers,
            cookies=self._get_cookies(),
        )

        text = resp.text
        match = re.search(
            r"/chat/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            text,
        )
        if match:
            return match.group(1)
        raise Exception("Failed to extract chat session_id from RSC response")

    async def send_message(
        self, session_id: str, content: str, model: str
    ) -> AsyncGenerator[dict, None]:
        payload = {
            "chat_session_id": session_id,
            "message_id": None,
            "content": content,
            "selected_model": model,
            "parallel_group_id": None,
            "task_name": "chat",
            "agent_mode": False,
            "metadatas": {"html_content": f"<p>{content}</p>"},
            "references": [],
            "entity": {
                "key": hashlib.md5(b"").hexdigest(),
                "extras": {"type": "tab", "url": ""},
            },
        }

        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        headers = {
            **self._get_headers(f"/chat/{session_id}"),
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
            "x-req-ctx": base64.b64encode(
                TABBIT_REQUEST_CONTEXT.encode("utf-8")
            ).decode("ascii"),
            "unique-uuid": str(uuid.uuid4()),
            **build_chat_signature_headers(body),
        }

        async with self.client.stream(
            "POST",
            f"{self.base_url}/api/v1/chat/completion",
            content=body,
            headers=headers,
            cookies=self._get_cookies(),
        ) as resp:
            if resp.status_code != 200:
                body = await resp.aread()
                raise Exception(
                    f"Tabbit API error {resp.status_code}: {body.decode()}"
                )

            current_event = None
            async for line in resp.aiter_lines():
                if line.startswith("event:"):
                    current_event = line[len("event:") :].strip()
                elif line.startswith("data:") and current_event:
                    data_str = line[len("data:") :].strip()
                    try:
                        data = json.loads(data_str)
                    except Exception:
                        continue

                    # Check for upstream error events
                    if current_event == "error" and isinstance(data, dict):
                        error_code = data.get("code", 0)
                        error_msg = data.get("message", "Unknown error")
                        raise TabbitApiError(
                            code=error_code,
                            message=error_msg,
                            action=data.get("action", ""),
                        )

                    yield {"event": current_event, "data": data}
                    if current_event == "close":
                        break

import unittest
import sys
import json
import asyncio
import hashlib
import hmac
import tempfile
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.google_oauth_capture import (
    _append_chrome_identity_header,
    _append_token_metadata,
    _extract_browser_header_profile_from_cdp,
    _extract_chrome_identity_header_from_cdp,
    _extract_moa_certificate_diagnostics_from_cdp,
    _extract_tabbit_token_from_cdp,
    _seed_user_profile,
    _windows_browser_candidates,
    CaptureResult,
)
from core.tabbit_client import (
    CHAT_SIGNING_KEY,
    TabbitApiError,
    TabbitClient,
    build_chat_signature_headers,
    build_tabbit_error_message,
    encode_token_metadata,
    get_local_tabbit_environment_diagnostics,
)
from core.token_manager import TokenManager
from routes.admin_api import _probe_tabbit_chat, exchange_google_id_token
from routes.claude_api import _stream_claude_response
from routes.openai_compat import _stream_handler


class FailingTabbitClient:
    async def send_message(self, session_id: str, content: str, model: str):
        if False:
            yield {}
        raise TabbitApiError(
            code=493,
            message="current browser version is too old",
            action="update_version",
        )


class TabbitErrorHandlingTests(unittest.IsolatedAsyncioTestCase):
    def test_tabbit_api_error_preserves_upstream_message(self):
        error = TabbitApiError(
            code=493,
            message="current browser version is too old",
            action="update_version",
        )

        self.assertEqual(error.message, "current browser version is too old")
        self.assertEqual(error.code, 493)
        self.assertEqual(error.action, "update_version")

    def test_chat_signature_headers_match_frontend_algorithm(self):
        body = '{"content":"ping"}'
        timestamp = "1700000000000"
        nonce = "00000000-0000-4000-8000-000000000000"
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        expected_nonce = hmac.new(
            CHAT_SIGNING_KEY.encode("utf-8"),
            f"{timestamp}.{nonce}.{body_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        headers = build_chat_signature_headers(
            body,
            timestamp=timestamp,
            signature=nonce,
        )

        self.assertEqual(headers["x-timestamp"], timestamp)
        self.assertEqual(headers["x-signature"], nonce)
        self.assertEqual(headers["x-nonce"], expected_nonce)

    async def test_tabbit_client_uses_current_completion_endpoint_shape(self):
        class FakeResponse:
            status_code = 200

            async def aiter_lines(self):
                yield "event: message_chunk"
                yield 'data: {"content":"ok"}'
                yield "event: finish"
                yield "data: {}"

        class FakeStream:
            async def __aenter__(self):
                return FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeHttpClient:
            def __init__(self):
                self.calls = []

            def stream(self, method, url, content, headers, cookies):
                self.calls.append(
                    {
                        "method": method,
                        "url": url,
                        "body": json.loads(content),
                        "headers": headers,
                        "cookies": cookies,
                    }
                )
                return FakeStream()

        client = TabbitClient(
            "jwt-token|next-auth|device-id|chrome-identity",
            base_url="https://web.tabbitbrowser.com",
        )
        await client.client.aclose()
        fake_http = FakeHttpClient()
        client.client = fake_http

        events = [
            event
            async for event in client.send_message(
                "session-id",
                "hello",
                "GPT-5.5",
            )
        ]

        self.assertEqual(events[0]["event"], "message_chunk")
        call = fake_http.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(
            call["url"],
            "https://web.tabbitbrowser.com/api/v1/chat/completion",
        )
        self.assertEqual(call["body"]["chat_session_id"], "session-id")
        self.assertEqual(call["body"]["message_id"], None)
        self.assertEqual(call["body"]["content"], "hello")
        self.assertEqual(call["body"]["selected_model"], "GPT-5.5")
        self.assertEqual(call["body"]["parallel_group_id"], None)
        self.assertEqual(call["body"]["task_name"], "chat")
        self.assertEqual(call["body"]["references"], [])
        self.assertEqual(call["headers"]["x-req-ctx"], "MC4zMC4xOCgxMDAzMDAxOCk=")
        self.assertIn("unique-uuid", call["headers"])
        self.assertEqual(call["headers"]["Cache-Control"], "no-cache")
        self.assertEqual(call["cookies"]["token"], "jwt-token")

    def test_tabbit_client_uses_captured_chrome_identity_header(self):
        captured_header = (
            "version=1,client_id=captured-client,device_id=captured-device,"
            "sync_account_id=captured-user,signin_mode=all_accounts,"
            "signout_mode=show_confirmation"
        )
        client = TabbitClient(
            f"jwt-token|next-auth|fallback-device|{captured_header}",
            client_id="configured-client",
        )
        try:
            headers = client._get_headers()
        finally:
            asyncio.run(client.client.aclose())

        self.assertEqual(
            headers["x-chrome-id-consistency-request"],
            captured_header,
        )

    def test_tabbit_client_uses_captured_browser_header_metadata(self):
        metadata = encode_token_metadata(
            {
                "headers": {
                    "user-agent": "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
                    "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Tabbit";v="146"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                },
                "cookies": {
                    "SAPISID": "captured-sapisid",
                    "expires_in": "604800",
                },
            }
        )
        client = TabbitClient(
            f"jwt-token|next-auth|device-id|version=1,client_id=c,device_id=d|{metadata}"
        )
        try:
            headers = client._get_headers()
            cookies = client._get_cookies()
        finally:
            asyncio.run(client.client.aclose())

        self.assertEqual(headers["User-Agent"], "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36")
        self.assertEqual(
            headers["sec-ch-ua"],
            '"Chromium";v="146", "Not-A.Brand";v="24", "Tabbit";v="146"',
        )
        self.assertEqual(headers["sec-ch-ua-mobile"], "?0")
        self.assertEqual(cookies["SAPISID"], "captured-sapisid")
        self.assertEqual(cookies["expires_in"], "604800")

    def test_extracts_chrome_identity_header_from_cdp_extra_info(self):
        captured_header = (
            "version=1,client_id=captured-client,device_id=captured-device,"
            "sync_account_id=captured-user,signin_mode=all_accounts,"
            "signout_mode=show_confirmation"
        )
        message = json.dumps(
            {
                "method": "Network.requestWillBeSentExtraInfo",
                "params": {
                    "headers": {
                        "X-Chrome-Id-Consistency-Request": captured_header,
                    }
                },
            }
        )

        self.assertEqual(
            _extract_chrome_identity_header_from_cdp(message),
            captured_header,
        )

    def test_extracts_browser_header_profile_from_cdp(self):
        message = json.dumps(
            {
                "method": "Network.requestWillBeSentExtraInfo",
                "params": {
                    "headers": {
                        "User-Agent": "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
                        "Sec-CH-UA": '"Chromium";v="146", "Not-A.Brand";v="24", "Tabbit";v="146"',
                        "Sec-CH-UA-Mobile": "?0",
                        "Sec-CH-UA-Platform": '"Windows"',
                        "Cookie": "token=secret",
                    }
                },
            }
        )

        self.assertEqual(
            _extract_browser_header_profile_from_cdp(message),
            {
                "user-agent": "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
                "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Tabbit";v="146"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            },
        )

    def test_extracts_moa_certificate_diagnostics_from_cdp(self):
        message = json.dumps(
            {
                "id": 6,
                "result": {
                    "result": {
                        "type": "object",
                        "value": {
                            "success": True,
                            "data": {
                                "hasMoaCertificate": False,
                                "platform": "win",
                            },
                        },
                    }
                },
            }
        )

        self.assertEqual(
            _extract_moa_certificate_diagnostics_from_cdp(message),
            {
                "has_moa_certificate": False,
                "moa_platform": "win",
                "moa_check_success": True,
            },
        )

    def test_captured_tabbit_token_preserves_chrome_identity_header(self):
        captured_header = (
            "version=1,client_id=captured-client,device_id=captured-device,"
            "sync_account_id=captured-user,signin_mode=all_accounts,"
            "signout_mode=show_confirmation"
        )
        message = json.dumps(
            {
                "result": {
                    "cookies": [
                        {"name": "token", "value": "jwt-token"},
                        {
                            "name": "next-auth.session-token",
                            "value": "next-auth-token",
                        },
                    ]
                }
            }
        )

        token_value = _extract_tabbit_token_from_cdp(
            message,
            chrome_identity_header=captured_header,
        )

        self.assertIsNotNone(token_value)
        self.assertEqual(token_value.split("|")[3], captured_header)

    def test_captured_tabbit_token_preserves_browser_metadata(self):
        browser_headers = {
            "user-agent": "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Tabbit";v="146"',
        }
        message = json.dumps(
            {
                "result": {
                    "cookies": [
                        {"name": "token", "value": "jwt-token"},
                        {"name": "SAPISID", "value": "captured-sapisid"},
                    ]
                }
            }
        )

        token_value = _extract_tabbit_token_from_cdp(
            message,
            browser_headers=browser_headers,
        )
        client = TabbitClient(token_value)
        try:
            headers = client._get_headers()
            cookies = client._get_cookies()
        finally:
            asyncio.run(client.client.aclose())

        self.assertEqual(headers["User-Agent"], browser_headers["user-agent"])
        self.assertEqual(cookies["SAPISID"], "captured-sapisid")

    def test_captured_tabbit_token_preserves_moa_diagnostics(self):
        token_value = _append_token_metadata(
            "jwt-token||device-id",
            diagnostics={
                "has_moa_certificate": False,
                "moa_platform": "win",
            },
        )
        client = TabbitClient(token_value)
        try:
            diagnostics = client.metadata.get("diagnostics")
        finally:
            asyncio.run(client.client.aclose())

        self.assertEqual(
            diagnostics,
            {
                "has_moa_certificate": False,
                "moa_platform": "win",
            },
        )

    def test_update_version_error_message_reports_missing_moa_certificate(self):
        metadata = encode_token_metadata(
            {
                "diagnostics": {
                    "has_moa_certificate": False,
                    "moa_platform": "win",
                }
            }
        )
        message = build_tabbit_error_message(
            TabbitApiError(
                code=493,
                message="current browser version is too old",
                action="update_version",
            ),
            token_value=f"jwt-token||device-id||{metadata}",
        )

        self.assertIn("hasMoaCertificate=false", message)
        self.assertIn("default browser", message)

    def test_update_version_error_message_does_not_ask_to_set_default_when_tabbit_is_default(self):
        metadata = encode_token_metadata(
            {
                "diagnostics": {
                    "has_moa_certificate": False,
                    "moa_platform": "win",
                }
            }
        )
        message = build_tabbit_error_message(
            TabbitApiError(
                code=493,
                message="current browser version is too old",
                action="update_version",
            ),
            token_value=f"jwt-token||device-id||{metadata}",
            local_diagnostics={
                "tabbit_is_default_browser": True,
                "windows_default_browser": {
                    "http_prog_id": "TabbitHTM.abc",
                    "https_prog_id": "TabbitHTM.abc",
                },
            },
        )

        self.assertIn("Tabbit is already the system default browser", message)
        self.assertIn("activate Tabbit AI/MOA entitlement", message)
        self.assertNotIn("Set Tabbit as the system default browser", message)

    def test_captured_tabbit_token_keeps_empty_next_auth_slot(self):
        captured_header = (
            "version=1,client_id=captured-client,device_id=captured-device,"
            "sync_account_id=captured-user,signin_mode=all_accounts,"
            "signout_mode=show_confirmation"
        )
        message = json.dumps(
            {
                "result": {
                    "cookies": [
                        {"name": "token", "value": "jwt-token"},
                    ]
                }
            }
        )

        token_value = _extract_tabbit_token_from_cdp(
            message,
            chrome_identity_header=captured_header,
        )

        self.assertIsNotNone(token_value)
        parts = token_value.split("|")
        self.assertEqual(parts[1], "")
        self.assertEqual(parts[3], captured_header)

    def test_appends_late_chrome_identity_header_to_pending_token(self):
        captured_header = (
            "version=1,client_id=captured-client,device_id=captured-device,"
            "sync_account_id=captured-user,signin_mode=all_accounts,"
            "signout_mode=show_confirmation"
        )

        token_value = _append_chrome_identity_header(
            "jwt-token||generated-device",
            captured_header,
        )

        self.assertEqual(
            token_value,
            f"jwt-token||generated-device|{captured_header}",
        )

    def test_capture_result_can_carry_chrome_identity_header(self):
        captured_header = (
            "version=1,client_id=captured-client,device_id=captured-device,"
            "sync_account_id=captured-user,signin_mode=all_accounts,"
            "signout_mode=show_confirmation"
        )

        result = CaptureResult(
            kind="id_token",
            value="google-id-token",
            chrome_identity_header=captured_header,
            browser_headers={
                "user-agent": "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
            },
        )

        self.assertEqual(result.chrome_identity_header, captured_header)
        self.assertEqual(
            result.browser_headers["user-agent"],
            "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
        )

    def test_windows_browser_candidates_prefer_tabbit(self):
        candidates = _windows_browser_candidates(
            {
                "PROGRAMFILES": r"C:\Program Files",
                "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
                "LOCALAPPDATA": r"C:\Users\alice\AppData\Local",
            }
        )

        self.assertIn(r"C:\Users\alice\AppData\Local\Tabbit\Application\tabbit.exe", candidates)
        self.assertIn(r"C:\Program Files\Google\Chrome\Application\chrome.exe", candidates)
        self.assertLess(
            candidates.index(r"C:\Users\alice\AppData\Local\Tabbit\Application\tabbit.exe"),
            candidates.index(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        )

    def test_seed_user_profile_preserves_extension_settings(self):
        with tempfile.TemporaryDirectory() as source_root:
            with tempfile.TemporaryDirectory() as destination:
                source_profile = Path(source_root) / "Tabbit" / "User Data" / "Default"
                for relative in (
                    "Local Extension Settings/nmbemfeekdkfhjikjegnegkndcehpfej",
                    "Sync Extension Settings/nmbemfeekdkfhjikjegnegkndcehpfej",
                    "Extension State",
                ):
                    source_dir = source_profile / relative
                    source_dir.mkdir(parents=True)
                    (source_dir / "CURRENT").write_text("manifest", encoding="utf-8")

                with patch.dict("core.google_oauth_capture.os.environ", {"LOCALAPPDATA": source_root}):
                    _seed_user_profile(destination)

                for relative in (
                    "Local Extension Settings/nmbemfeekdkfhjikjegnegkndcehpfej/CURRENT",
                    "Sync Extension Settings/nmbemfeekdkfhjikjegnegkndcehpfej/CURRENT",
                    "Extension State/CURRENT",
                ):
                    self.assertTrue((Path(destination) / "Default" / relative).exists())

    def test_windows_default_browser_diagnostics_prefers_user_choice_latest(self):
        values = {
            (
                "Software\\Microsoft\\Windows\\Shell\\Associations\\"
                "UrlAssociations\\http\\UserChoiceLatest\\ProgId",
                "ProgId",
            ): "TabbitHTM.abc",
            (
                "Software\\Microsoft\\Windows\\Shell\\Associations\\"
                "UrlAssociations\\https\\UserChoiceLatest\\ProgId",
                "ProgId",
            ): "TabbitHTM.abc",
            (
                "Software\\Microsoft\\Windows\\Shell\\Associations\\"
                "UrlAssociations\\http\\UserChoice",
                "ProgId",
            ): "MSEdgeHTM",
            (
                "Software\\Microsoft\\Windows\\Shell\\Associations\\"
                "UrlAssociations\\https\\UserChoice",
                "ProgId",
            ): "MSEdgeHTM",
        }

        with patch("core.tabbit_client.os.name", "nt"):
            with patch(
                "core.tabbit_client._read_windows_registry_string",
                side_effect=lambda path, value_name: values.get((path, value_name)),
            ):
                diagnostics = get_local_tabbit_environment_diagnostics()

        self.assertEqual(
            diagnostics["windows_default_browser"],
            {"http_prog_id": "TabbitHTM.abc", "https_prog_id": "TabbitHTM.abc"},
        )
        self.assertTrue(diagnostics["tabbit_is_default_browser"])

    def test_windows_default_browser_diagnostics_falls_back_to_user_choice(self):
        values = {
            (
                "Software\\Microsoft\\Windows\\Shell\\Associations\\"
                "UrlAssociations\\http\\UserChoice",
                "ProgId",
            ): "MSEdgeHTM",
            (
                "Software\\Microsoft\\Windows\\Shell\\Associations\\"
                "UrlAssociations\\https\\UserChoice",
                "ProgId",
            ): "MSEdgeHTM",
        }

        with patch("core.tabbit_client.os.name", "nt"):
            with patch(
                "core.tabbit_client._read_windows_registry_string",
                side_effect=lambda path, value_name: values.get((path, value_name)),
            ):
                diagnostics = get_local_tabbit_environment_diagnostics()

        self.assertEqual(
            diagnostics["windows_default_browser"],
            {"http_prog_id": "MSEdgeHTM", "https_prog_id": "MSEdgeHTM"},
        )
        self.assertFalse(diagnostics["tabbit_is_default_browser"])


class ChatProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_probe_tabbit_chat_sends_smoke_message(self):
        class WorkingClient:
            def __init__(self):
                self.sent = False

            async def create_chat_session(self):
                return "session-id"

            async def send_message(self, session_id: str, content: str, model: str):
                self.sent = True
                self.session_id = session_id
                self.content = content
                self.model = model
                yield {"event": "message_chunk", "data": {"content": "ok"}}

        client = WorkingClient()

        session_id = await _probe_tabbit_chat(client, "Best")

        self.assertEqual(session_id, "session-id")
        self.assertTrue(client.sent)
        self.assertEqual(client.model, "Best")

    async def test_claude_stream_returns_visible_error_and_closes(self):
        chunks = []

        with self.assertLogs("tabbit2openai", level="ERROR"):
            async for chunk in _stream_claude_response(
                FailingTabbitClient(),
                "session-id",
                "hello",
                "Best",
                {"model": "claude-sonnet-4-5", "messages": []},
                "token-a",
                "",
            ):
                chunks.append(chunk)

        payload = "".join(chunks)

        self.assertIn("event: message_start", payload)
        self.assertIn("[Tabbit API Error 493] current browser version is too old", payload)
        self.assertIn("event: message_stop", payload)


class GoogleExchangeTests(unittest.IsolatedAsyncioTestCase):
    async def test_google_exchange_preserves_captured_chrome_identity_header(self):
        captured_header = (
            "version=1,client_id=captured-client,device_id=captured-device,"
            "sync_account_id=captured-user,signin_mode=all_accounts,"
            "signout_mode=show_confirmation"
        )

        class Config:
            def get(self, *keys, default=None):
                if keys == ("tabbit", "base_url"):
                    return "https://web.tabbitbrowser.com"
                return default

        class Response:
            status_code = 200
            text = ""

            def json(self):
                return {"success": True, "data": {}}

            @property
            def headers(self):
                class Headers:
                    def multi_items(self):
                        return [
                            ("set-cookie", "token=jwt-token; Path=/"),
                            (
                                "set-cookie",
                                "next-auth.session-token=next-auth-token; Path=/",
                            ),
                        ]

                return Headers()

        captured_requests = []

        class AsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, *args, **kwargs):
                captured_requests.append(kwargs)
                return Response()

        with patch("httpx.AsyncClient", AsyncClient):
            data = await exchange_google_id_token(
                Config(),
                "header.payload.signature",
                chrome_identity_header=captured_header,
                browser_headers={
                    "user-agent": "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
                    "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Tabbit";v="146"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                },
            )

        parts = data["token_value"].split("|")
        self.assertEqual(parts[0], "jwt-token")
        self.assertEqual(parts[1], "next-auth-token")
        self.assertEqual(parts[3], captured_header)
        self.assertEqual(
            captured_requests[0]["headers"]["x-chrome-id-consistency-request"],
            captured_header,
        )
        self.assertEqual(
            captured_requests[0]["headers"]["User-Agent"],
            "Mozilla/5.0 Chrome/146.0.0.0 Safari/537.36",
        )
        self.assertEqual(
            captured_requests[0]["headers"]["sec-ch-ua"],
            '"Chromium";v="146", "Not-A.Brand";v="24", "Tabbit";v="146"',
        )
        self.assertEqual(len(parts), 5)


class TokenManagerTests(unittest.TestCase):
    def test_visible_upstream_errors_do_not_cool_down_token_pool(self):
        class MemoryConfig:
            def __init__(self):
                self.config = {
                    "tokens": [
                        {
                            "id": "token-id",
                            "name": "token",
                            "value": "jwt-token||device-id",
                            "enabled": True,
                            "error_count": 2,
                            "status": "error",
                        }
                    ]
                }

            def get(self, *keys, default=None):
                value = self.config
                for key in keys:
                    if not isinstance(value, dict):
                        return default
                    value = value.get(key)
                    if value is None:
                        return default
                return value

            def save(self):
                pass

        manager = TokenManager(MemoryConfig())

        manager.report_error("token-id", cooldown=False)

        self.assertEqual(manager.get_token_status("token-id"), "error")
        self.assertEqual(len(manager._get_available_tokens()), 1)
        self.assertNotIn("token-id", manager._cooldowns)


class OpenAIStreamErrorHandlingTests(unittest.IsolatedAsyncioTestCase):
    async def test_openai_stream_returns_visible_error_and_done(self):
        chunks = []

        async for chunk in _stream_handler(
            FailingTabbitClient(),
            "session-id",
            "hello",
            "Best",
            "best",
            "chatcmpl-test",
            "token-a",
            "",
        ):
            chunks.append(chunk)

        payload = "".join(chunks)

        self.assertIn("[Tabbit API Error 493] current browser version is too old", payload)
        self.assertIn("data: [DONE]", payload)


if __name__ == "__main__":
    unittest.main()

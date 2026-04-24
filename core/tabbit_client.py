import re
import json
import uuid
import hashlib
import base64
import time
import urllib.parse
from typing import AsyncGenerator

import httpx

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
        parts = token_str.split("|")
        self.jwt_token = parts[0]
        self.next_auth = parts[1] if len(parts) > 1 else None
        self.device_id = parts[2] if len(parts) > 2 else str(uuid.uuid4())
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
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not:A-Brand";v="99", "Tabbit";v="145", "Chromium";v="145"',
            "sec-ch-ua-platform": '"Windows"',
            "x-chrome-id-consistency-request": (
                f"version=1,client_id={self.client_id},"
                f"device_id={self.device_id},sync_account_id={self.user_id},"
                "signin_mode=all_accounts,signout_mode=show_confirmation"
            ),
            "referer": f"{self.base_url}{referer_path}",
        }

    def _get_cookies(self) -> dict:
        cookies = {
            "token": self.jwt_token,
            "user_id": self.user_id,
            "managed": "tab_browser",
            "NEXT_LOCALE": "zh",
        }
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
            "content": content,
            "selected_model": model,
            "agent_mode": False,
            "metadatas": {"html_content": f"<p>{content}</p>"},
            "entity": {
                "key": hashlib.md5(b"").hexdigest(),
                "extras": {"type": "tab", "url": ""},
            },
        }

        headers = {
            **self._get_headers(f"/chat/{session_id}"),
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }

        async with self.client.stream(
            "POST",
            f"{self.base_url}/chat/send",
            json=payload,
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
                        yield {"event": current_event, "data": json.loads(data_str)}
                    except Exception:
                        pass

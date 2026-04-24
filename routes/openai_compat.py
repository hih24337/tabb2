import json
import time
import uuid
import logging

from fastapi import APIRouter, HTTPException, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.tabbit_client import TabbitClient, get_available_models, resolve_tabbit_model
from core.token_manager import TokenManager
from core.log_store import LogStore, LogEntry
from core.config import ConfigManager

logger = logging.getLogger("tabbit2openai")

router = APIRouter()

# 这些在 tabbit2api.py 中通过 app.state 注入
_tm: TokenManager | None = None
_cfg: ConfigManager | None = None
_logs: LogStore | None = None
_fallback_clients: dict[str, TabbitClient] = {}


def init(token_manager: TokenManager, config: ConfigManager, log_store: LogStore):
    global _tm, _cfg, _logs
    _tm = token_manager
    _cfg = config
    _logs = log_store


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "best"
    messages: list[ChatMessage]
    stream: bool = False


def _build_content(messages: list[ChatMessage]) -> str:
    system_prompt = _cfg.get("proxy", "system_prompt") if _cfg else ""
    if len(messages) == 1 and not system_prompt:
        return messages[0].content
    parts = []
    if system_prompt:
        parts.append(f"[System]: {system_prompt}")
    for m in messages:
        label = {"user": "User", "assistant": "Assistant", "system": "System"}.get(
            m.role, m.role.capitalize()
        )
        parts.append(f"[{label}]: {m.content}")
    return "\n\n".join(parts) + "\n\n[Assistant]:"


async def _get_client_and_token(
    authorization: str | None,
) -> tuple[TabbitClient, str, str]:
    """返回 (client, token_name, token_id)"""
    # 若 token 池非空，走轮询
    if _tm.has_tokens:
        # 校验 proxy api_key
        api_key = _cfg.get("proxy", "api_key")
        if api_key:
            bearer = (authorization or "").replace("Bearer ", "")
            if bearer != api_key:
                raise HTTPException(status_code=401, detail="invalid api key")
        token_info, client = await _tm.get_next()
        if token_info is None:
            raise HTTPException(
                status_code=503, detail="no available tokens (all cooling down)"
            )
        return client, token_info.get("name", "unknown"), token_info["id"]

    # fallback: 从 Authorization 读 token（向后兼容）
    token = (authorization or "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="missing token")
    if token not in _fallback_clients:
        _fallback_clients[token] = TabbitClient(
            token,
            _cfg.get("tabbit", "base_url"),
            _cfg.get("tabbit", "client_id"),
        )
    return _fallback_clients[token], "bearer", ""


async def _stream_handler(client, session_id, content, tabbit_model, req_model, completion_id, token_name, token_id):
    start = time.time()
    error_msg = ""
    try:
        yield (
            f"data: {json.dumps({'id': completion_id, 'object': 'chat.completion.chunk', 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': ''}, 'finish_reason': None}]})}\n\n"
        )

        async for event in client.send_message(session_id, content, tabbit_model):
            et, ed = event["event"], event["data"]
            if et == "message_chunk" and "content" in ed:
                chunk = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": ed["content"]},
                            "finish_reason": None,
                        }
                    ],
                }
                yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
            elif et in ("message_finish", "finish"):
                yield (
                    f"data: {json.dumps({'id': completion_id, 'object': 'chat.completion.chunk', 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
                )

        yield "data: [DONE]\n\n"
        if token_id:
            _tm.report_success(token_id)
    except Exception as e:
        error_msg = str(e)
        if token_id:
            _tm.report_error(token_id)
        raise
    finally:
        duration = time.time() - start
        _logs.add(
            LogEntry(
                model=req_model,
                token_name=token_name,
                stream=True,
                status="success" if not error_msg else "error",
                duration=duration,
                error=error_msg,
            )
        )


@router.post("/v1/chat/completions")
async def chat_completions(
    req: ChatCompletionRequest, authorization: str = Header(None)
):
    client, token_name, token_id = await _get_client_and_token(authorization)
    tabbit_model = await resolve_tabbit_model(
        req.model,
        _cfg.get("tabbit", "base_url") if _cfg else None,
    )
    content = _build_content(req.messages)

    try:
        session_id = await client.create_chat_session()
    except Exception as e:
        if token_id:
            _tm.report_error(token_id)
        _logs.add(
            LogEntry(
                model=req.model,
                token_name=token_name,
                stream=req.stream,
                status="error",
                error=str(e),
            )
        )
        raise HTTPException(status_code=502, detail=str(e))

    completion_id = f"chatcmpl-{uuid.uuid4().hex}"

    if req.stream:
        return StreamingResponse(
            _stream_handler(
                client,
                session_id,
                content,
                tabbit_model,
                req.model,
                completion_id,
                token_name,
                token_id,
            ),
            media_type="text/event-stream",
        )

    # 非流式
    start = time.time()
    full_text = ""
    error_msg = ""
    try:
        async for event in client.send_message(session_id, content, tabbit_model):
            if event["event"] == "message_chunk":
                full_text += event["data"].get("content", "")
        if token_id:
            _tm.report_success(token_id)
    except Exception as e:
        error_msg = str(e)
        if token_id:
            _tm.report_error(token_id)
        raise HTTPException(status_code=502, detail=str(e))
    finally:
        duration = time.time() - start
        _logs.add(
            LogEntry(
                model=req.model,
                token_name=token_name,
                stream=False,
                status="success" if not error_msg else "error",
                duration=duration,
                error=error_msg,
            )
        )

    return {
        "id": completion_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": full_text},
                "finish_reason": "stop",
            }
        ],
    }


@router.get("/v1/models")
async def list_models():
    models = await get_available_models(_cfg.get("tabbit", "base_url") if _cfg else None)
    return {
        "object": "list",
        "data": models,
    }

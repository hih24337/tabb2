"""
Claude Messages API 兼容层
将 Anthropic Messages API 请求转换为 Tabbit 可用的格式，
并将 Tabbit 的流式响应转换回 Claude SSE 格式。

参考: https://github.com/CassiopeiaCode/b4u2cc
"""

import re
import json
import math
import uuid
import secrets
import logging
from typing import Any

logger = logging.getLogger("tabbit2openai")

# ── 常量 ──

THINKING_START_TAG = "<thinking>"
THINKING_END_TAG = "</thinking>"

# ── 触发信号 ──


def random_trigger_signal() -> str:
    """生成随机触发信号，如 <<CALL_a3f1b2>>"""
    hex_str = secrets.token_hex(3)  # 6 位十六进制
    return f"<<CALL_{hex_str}>>"


def generate_tool_id() -> str:
    """生成工具调用 ID，格式: toolu_ + 12位随机字符"""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    suffix = "".join(secrets.choice(chars) for _ in range(12))
    return f"toolu_{suffix}"


# ── 工具 Prompt 注入 ──

TOOL_PROMPT_TEMPLATE = """
In this environment you have access to a set of tools you can use to answer the user's question.

When you need to use a tool, you MUST strictly follow the format below.

**1. Available Tools:**
Here is the list of tools you can use. You have access ONLY to these tools and no others.
<antml\\b:tools>
{tools_list}
</antml\\b:tools>

**2. Tool Call Procedure:**
When you decide to call a tool, you MUST output EXACTLY this trigger signal: {trigger_signal}
The trigger signal MUST be output on a completely empty line by itself before any tool calls.
Do NOT add any other text, spaces, or characters before or after {trigger_signal} on that line.
You may provide explanations or reasoning before outputting {trigger_signal}, but once you decide to make a tool call, {trigger_signal} must come first.
You MUST output the trigger signal {trigger_signal} ONLY ONCE per response. Never output multiple trigger signals in a single response.

After outputting the trigger signal, immediately provide your tool calls enclosed in <invoke> XML tags.

**3. XML Format for Tool Calls:**
Your tool calls must be structured EXACTLY as follows. This is the ONLY format you can use, and any deviation will result in failure.

<antml\\b:format>
{trigger_signal}
<invoke name="Write">
<parameter name="file_path">C:\\path\\weather.css</parameter>
<parameter name="content"> body {{ background-color: lightblue; }} </parameter>
</invoke>
</antml\\b:format>

IMPORTANT RULES:
  - You may provide explanations or reasoning before deciding to call a tool.
  - Once you decide to call a tool, you must first output the trigger signal {trigger_signal} on a separate line by itself.
  - The trigger signal may only appear once per response and must not be repeated.
  - Tool calls must use the exact XML format below: immediately after the trigger signal, use <invoke> and <parameter> tags.
  - No additional text may be added after the closing </invoke> tag.
  - Parameters must retain punctuation (including hyphen prefixes) exactly as defined.
  - Encode arrays and objects in JSON before placing inside <parameter>.
  - Be concise when not using tools.
  - 在调用工具后会得到工具调用结果，所以请在一次工具调用得到结果后再调用下一个。
  """


def _escape_xml(text: str) -> str:
    return text.replace("<", "&lt;").replace(">", "&gt;")


def build_tools_xml(tools: list[dict]) -> str:
    """将 Claude 工具定义转换为 XML 格式"""
    if not tools:
        return "<function_list>None</function_list>"

    items = []
    for idx, tool in enumerate(tools):
        schema = tool.get("input_schema", {})
        props = schema.get("properties", {})
        required = schema.get("required", [])

        param_lines = []
        for name, info in props.items():
            ptype = info.get("type", "any")
            desc = info.get("description", "")
            is_required = name in required
            enum_vals = info.get("enum")
            lines = [
                f'    <parameter name="{name}">',
                f"      <type>{ptype}</type>",
                f"      <required>{str(is_required).lower()}</required>",
            ]
            if desc:
                lines.append(
                    f"      <description>{_escape_xml(str(desc))}</description>"
                )
            if enum_vals is not None:
                lines.append(
                    f"      <enum>{_escape_xml(json.dumps(enum_vals))}</enum>"
                )
            lines.append("    </parameter>")
            param_lines.append("\n".join(lines))

        req_xml = (
            "\n".join(f"    <param>{r}</param>" for r in required)
            if required
            else "    <param>None</param>"
        )
        params_xml = "\n".join(param_lines) if param_lines else "None"

        item = "\n".join(
            [
                f'  <tool id="{idx + 1}">',
                f"    <name>{tool['name']}</name>",
                f"    <description>{_escape_xml(tool.get('description', 'None'))}</description>",
                "    <required>",
                req_xml,
                "    </required>",
                f"    <parameters>\n{params_xml}\n    </parameters>",
                "  </tool>",
            ]
        )
        items.append(item)

    return f"<function_list>\n{chr(10).join(items)}\n</function_list>"


def build_tool_prompt(tools: list[dict], trigger_signal: str) -> str:
    """构建完整的工具提示词"""
    tools_xml = build_tools_xml(tools)
    return (
        TOOL_PROMPT_TEMPLATE.replace("{tools_list}", tools_xml).replace(
            "{trigger_signal}", trigger_signal
        )
    )


# ── Claude 消息 → 纯文本 ──


def normalize_blocks(
    content: str | list[dict], trigger_signal: str | None = None
) -> str:
    """将 Claude 消息 content（字符串或 block 数组）扁平化为纯文本"""
    if isinstance(content, str):
        # 过滤裸标签防注入
        text = re.sub(r"<invoke\b[^>]*>[\s\S]*?</invoke>", "", content, flags=re.I)
        text = re.sub(
            r"<tool_result\b[^>]*>[\s\S]*?</tool_result>", "", text, flags=re.I
        )
        return text

    parts = []
    for block in content:
        btype = block.get("type", "")
        if btype == "text":
            text = block.get("text", "")
            text = re.sub(
                r"<invoke\b[^>]*>[\s\S]*?</invoke>", "", text, flags=re.I
            )
            text = re.sub(
                r"<tool_result\b[^>]*>[\s\S]*?</tool_result>", "", text, flags=re.I
            )
            parts.append(text)
        elif btype == "thinking":
            parts.append(
                f"{THINKING_START_TAG}{block.get('thinking', '')}{THINKING_END_TAG}"
            )
        elif btype == "tool_result":
            content_str = block.get("content", "")
            if not isinstance(content_str, str):
                # tool_result content 可能是数组
                if isinstance(content_str, list):
                    text_parts = []
                    for item in content_str:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text_parts.append(item.get("text", ""))
                    content_str = "\n".join(text_parts)
                else:
                    content_str = json.dumps(content_str, ensure_ascii=False)
            tool_use_id = block.get("tool_use_id", "")
            parts.append(f'<tool_result id="{tool_use_id}">{content_str}</tool_result>')
        elif btype == "tool_use":
            params = block.get("input", {})
            param_lines = []
            for key, value in params.items():
                str_val = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
                param_lines.append(f'<parameter name="{key}">{str_val}</parameter>')
            trigger = f"{trigger_signal}\n" if trigger_signal else ""
            params_str = "\n".join(param_lines)
            parts.append(
                f'{trigger}<invoke name="{block.get("name", "")}">\n{params_str}\n</invoke>'
            )
    return "\n".join(parts)


def map_claude_to_content(
    body: dict, trigger_signal: str | None = None
) -> str:
    """
    将完整的 Claude Messages API 请求转换为单条 Tabbit 消息文本。
    包含系统提示、工具 prompt、消息历史。
    """
    parts = []

    # 0. 注入的全局 system prompt
    injected = body.get("_injected_system_prompt", "")
    if injected:
        parts.append(f"[System]: {injected}")

    # 1. 工具 prompt
    tools = body.get("tools", [])
    if tools and trigger_signal:
        parts.append(f"[System]: {build_tool_prompt(tools, trigger_signal)}")

    # 2. 原始 system prompt
    system = body.get("system")
    if system:
        if isinstance(system, list):
            sys_text = "\n".join(
                b.get("text", "") if isinstance(b, dict) else str(b) for b in system
            )
        else:
            sys_text = system
        parts.append(f"[System]: {sys_text}")

    # 3. 消息历史
    messages = body.get("messages", [])
    thinking_enabled = (
        body.get("thinking", {}).get("type") == "enabled"
        if isinstance(body.get("thinking"), dict)
        else False
    )

    for msg in messages:
        role = msg.get("role", "user")
        label = "Assistant" if role == "assistant" else "User"
        content = normalize_blocks(msg.get("content", ""), trigger_signal)

        # thinking hint（仅对 user 消息）
        if role == "user" and thinking_enabled:
            content += "<antml\\b:thinking_mode>interleaved</antml><antml\\b:max_thinking_length>16000</antml>"

        parts.append(f"[{label}]: {content}")

    # 4. 末尾提示
    parts.append("[Assistant]:")

    return "\n\n".join(parts)


# ── 流解析器 ──


def _parse_invoke_xml(xml: str) -> dict | None:
    """解析 <invoke> XML，返回 {name, arguments}"""
    try:
        name_match = re.search(r'<invoke[^>]*name="([^"]+)"[^>]*>', xml, re.I)
        if not name_match:
            return None
        name = name_match.group(1)
        params: dict[str, Any] = {}
        for m in re.finditer(
            r'<parameter[^>]*name="([^"]+)"[^>]*>([\s\S]*?)</parameter>', xml, re.I
        ):
            key = m.group(1)
            raw = m.group(2).strip()
            if raw:
                try:
                    params[key] = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    params[key] = raw
            else:
                params[key] = ""
        return {"name": name, "arguments": params}
    except Exception:
        return None


class ToolifyParser:
    """
    流式文本解析器。逐字符输入，检测：
    - 触发信号 → 工具调用 (<invoke>)
    - <thinking>...</thinking> → 思考块
    - 其余 → 普通文本

    事件类型: text / tool_call / thinking / end

    设计要点：
    - 文本实时发出，不再等待 256 字符缓冲
    - 需要前瞻检测 <thinking> 和 trigger_signal，保留一个安全窗口
    - 窗口长度 = max(len(THINKING_START_TAG), len(trigger_signal or ''))
    """

    # 前瞻安全边距：多保留几个字符防止切割多字节 UTF-8（实际 ASCII 标签无此问题，但留余量）
    _LOOKAHEAD_PAD = 2

    def __init__(
        self, trigger_signal: str | None = None, thinking_enabled: bool = False
    ):
        self.trigger_signal = trigger_signal
        self.thinking_enabled = thinking_enabled
        self.buffer = ""
        self.capture_buffer = ""
        self.capturing = False
        self.thinking_mode = False
        self.thinking_buffer = ""
        self.events: list[dict] = []

    @property
    def _safe_window(self) -> int:
        """前瞻安全窗口：必须 >= 可能匹配的最长标签长度"""
        candidates = [len(THINKING_START_TAG)]
        if self.trigger_signal:
            candidates.append(len(self.trigger_signal))
        return max(candidates) + self._LOOKAHEAD_PAD

    def feed_char(self, char: str):
        if not self.trigger_signal:
            self._handle_char_without_trigger(char)
            return

        # 启用工具协议
        if self.thinking_enabled:
            self._check_thinking_mode(char)
            if self.thinking_mode:
                self.thinking_buffer += char
                return

        if self.capturing:
            self.capture_buffer += char
            self._try_emit_invokes()
            return

        self.buffer += char
        if self.buffer.endswith(self.trigger_signal):
            text_before = self.buffer[: -len(self.trigger_signal)]
            if text_before:
                self.events.append({"type": "text", "content": text_before})
            self.buffer = ""
            self.capturing = True
            self.capture_buffer = ""
        else:
            self._flush_safe_text()

    def finish(self):
        if self.buffer:
            self.events.append({"type": "text", "content": self.buffer})
        if self.thinking_enabled and self.thinking_mode and self.thinking_buffer:
            content = self.thinking_buffer
            if content.endswith(THINKING_END_TAG):
                content = content[: -len(THINKING_END_TAG)]
            content = re.sub(r"^\s*>\s*", "", content)
            if content:
                self.events.append({"type": "thinking", "content": content})
        self._try_emit_invokes(force=True)
        self.events.append({"type": "end"})
        self.buffer = ""
        self.capture_buffer = ""
        self.capturing = False
        self.thinking_buffer = ""
        self.thinking_mode = False

    def consume_events(self) -> list[dict]:
        pending = self.events[:]
        self.events.clear()
        return pending

    def _flush_safe_text(self):
        """将 buffer 中安全的部分作为 text 事件发出，保留前瞻窗口。

        核心思路：buffer 尾部可能是不完整的 <thinking> 或 trigger_signal 前缀，
        需要保留足够长的尾部来等后续字符确认。其余部分可以立即发出。
        """
        window = self._safe_window
        if len(self.buffer) <= window:
            return

        safe_end = len(self.buffer) - window
        safe_text = self.buffer[:safe_end]
        self.buffer = self.buffer[safe_end:]
        if safe_text:
            self.events.append({"type": "text", "content": safe_text})

    def _try_emit_invokes(self, force: bool = False):
        lower = self.capture_buffer.lower()
        start_idx = lower.find("<invoke")

        if start_idx == -1:
            if not force:
                return
            if self.capture_buffer:
                self.events.append({"type": "text", "content": self.capture_buffer})
                self.capture_buffer = ""
            self.capturing = False
            return

        end_idx = self.capture_buffer.find("</invoke>", start_idx)
        if end_idx == -1:
            return  # 等待更多数据

        end_pos = end_idx + len("</invoke>")
        invoke_xml = self.capture_buffer[start_idx:end_pos]

        # 检查 </invoke> 后面是否有非工具内容
        after = self.capture_buffer[end_pos:]
        after_trimmed = after.lstrip()
        if (
            after_trimmed
            and not after_trimmed.lower().startswith("<invoke")
            and not force
        ):
            self.events.append({"type": "text", "content": self.capture_buffer})
            self.capture_buffer = ""
            self.capturing = False
            return

        # 前面的文本
        before = self.capture_buffer[:start_idx]
        if before:
            self.events.append({"type": "text", "content": before})

        parsed = _parse_invoke_xml(invoke_xml)
        if parsed:
            self.events.append({"type": "tool_call", "call": parsed})
            # 过滤后续 <invoke> 标签
            remaining = after
            while True:
                trimmed = remaining.lstrip()
                if not trimmed:
                    break
                if trimmed.lower().startswith("<invoke"):
                    next_end = trimmed.find("</invoke>")
                    if next_end != -1:
                        remaining = trimmed[next_end + len("</invoke>") :]
                        continue
                # 非工具内容，保留
                if trimmed.strip():
                    self.events.append({"type": "text", "content": remaining})
                break
        else:
            self.events.append({"type": "text", "content": self.capture_buffer})

        self.capture_buffer = ""
        self.capturing = False

    def _handle_char_without_trigger(self, char: str):
        if not self.thinking_enabled:
            self.buffer += char
            self._flush_safe_text_no_trigger()
            return

        if self.thinking_mode:
            self.thinking_buffer += char
            if self.thinking_buffer.endswith(THINKING_END_TAG):
                content = self.thinking_buffer[: -len(THINKING_END_TAG)]
                content = re.sub(r"^\s*>\s*", "", content)
                if content:
                    self.events.append({"type": "thinking", "content": content})
                self.thinking_buffer = ""
                self.thinking_mode = False
            else:
                self._flush_thinking_safe()
            return

        self.buffer += char
        if self.buffer.endswith(THINKING_START_TAG):
            text_before = self.buffer[: -len(THINKING_START_TAG)]
            if text_before:
                self.events.append({"type": "text", "content": text_before})
            self.buffer = ""
            self.thinking_mode = True
            self.thinking_buffer = ""
        else:
            self._flush_safe_text_no_trigger()

    def _flush_safe_text_no_trigger(self):
        """无 trigger signal 时，只需前瞻 <thinking> 标签。"""
        if not self.thinking_enabled:
            # 完全不需要前瞻，每个字符都可以实时发出
            if self.buffer:
                self.events.append({"type": "text", "content": self.buffer})
                self.buffer = ""
            return
        window = len(THINKING_START_TAG) + self._LOOKAHEAD_PAD
        if len(self.buffer) <= window:
            return
        safe_end = len(self.buffer) - window
        safe_text = self.buffer[:safe_end]
        self.buffer = self.buffer[safe_end:]
        if safe_text:
            self.events.append({"type": "text", "content": safe_text})

    def _flush_thinking_safe(self):
        """Thinking 缓冲区也需要实时发出，但保留 </thinking> 前瞻窗口。"""
        window = len(THINKING_END_TAG) + self._LOOKAHEAD_PAD
        if len(self.thinking_buffer) <= window:
            return
        safe_end = len(self.thinking_buffer) - window
        content = self.thinking_buffer[:safe_end]
        self.thinking_buffer = self.thinking_buffer[safe_end:]
        if content:
            self.events.append({"type": "thinking", "content": content})

    def _check_thinking_mode(self, char: str):
        if not self.thinking_mode:
            temp = self.buffer + char
            if temp.endswith(THINKING_START_TAG):
                text_before = self.buffer[: -len(THINKING_START_TAG) + 1]
                if text_before:
                    self.events.append({"type": "text", "content": text_before})
                self.buffer = ""
                self.thinking_mode = True
                self.thinking_buffer = ""
        else:
            if self.thinking_buffer.endswith(THINKING_END_TAG):
                content = self.thinking_buffer[: -len(THINKING_END_TAG)]
                content = re.sub(r"^\s*>\s*", "", content)
                if content:
                    self.events.append({"type": "thinking", "content": content})
                self.thinking_buffer = ""
                self.thinking_mode = False


# ── Claude SSE 输出 ──


def estimate_tokens(text: str) -> int:
    """简单的 token 估算: ~4 字符 ≈ 1 token"""
    return max(1, math.ceil(len(text) / 4))


class ClaudeSSEWriter:
    """
    将解析器事件转换为 Claude Messages API SSE 格式。
    生成器接口：调用 handle_events() 产出 SSE 行。
    """

    def __init__(self, request_id: str, model: str, input_tokens: int = 0):
        self.request_id = request_id
        self.model = model
        self.input_tokens = input_tokens
        self.next_block_index = 0
        self.text_block_open = False
        self.thinking_block_open = False
        self.finished = False
        self.total_output_tokens = 0
        self.has_tool_call = False

    def init_event(self) -> str:
        """生成 message_start SSE 事件"""
        return self._sse(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": f"msg_{self.request_id}",
                    "type": "message",
                    "role": "assistant",
                    "model": self.model,
                    "stop_sequence": None,
                    "usage": {
                        "input_tokens": self.input_tokens,
                        "output_tokens": 0,
                    },
                    "content": [],
                    "stop_reason": None,
                },
            },
        )

    def handle_events(self, events: list[dict]) -> list[str]:
        """处理解析器事件，返回 SSE 行列表"""
        output = []
        for event in events:
            etype = event["type"]
            if etype == "text":
                if self.thinking_block_open:
                    output.extend(self._end_thinking_block())
                output.extend(self._emit_text(event["content"]))
            elif etype == "thinking":
                output.extend(self._flush_text_block())
                output.extend(self._emit_thinking(event["content"]))
            elif etype == "tool_call":
                self.has_tool_call = True
                output.extend(self._flush_text_block())
                output.extend(self._end_thinking_block())
                output.extend(self._emit_tool_call(event["call"]))
            elif etype == "end":
                output.extend(self._finish())
        return output

    def _emit_text(self, text: str) -> list[str]:
        lines = []
        if not self.text_block_open:
            idx = self.next_block_index
            self.next_block_index += 1
            self.text_block_open = True
            lines.append(
                self._sse(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": idx,
                        "content_block": {"type": "text", "text": ""},
                    },
                )
            )
        self.total_output_tokens += estimate_tokens(text)
        lines.append(
            self._sse(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": self.next_block_index - 1,
                    "delta": {"type": "text_delta", "text": text},
                },
            )
        )
        return lines

    def _flush_text_block(self) -> list[str]:
        if not self.text_block_open:
            return []
        self.text_block_open = False
        return [
            self._sse(
                "content_block_stop",
                {
                    "type": "content_block_stop",
                    "index": self.next_block_index - 1,
                },
            )
        ]

    def _emit_thinking(self, content: str) -> list[str]:
        lines = []
        if not self.thinking_block_open:
            idx = self.next_block_index
            self.next_block_index += 1
            self.thinking_block_open = True
            lines.append(
                self._sse(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": idx,
                        "content_block": {"type": "thinking", "thinking": ""},
                    },
                )
            )
        self.total_output_tokens += estimate_tokens(content)
        lines.append(
            self._sse(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": self.next_block_index - 1,
                    "delta": {"type": "thinking_delta", "thinking": content},
                },
            )
        )
        return lines

    def _end_thinking_block(self) -> list[str]:
        if not self.thinking_block_open:
            return []
        self.thinking_block_open = False
        return [
            self._sse(
                "content_block_stop",
                {
                    "type": "content_block_stop",
                    "index": self.next_block_index - 1,
                },
            )
        ]

    def _emit_tool_call(self, call: dict) -> list[str]:
        lines = []
        lines.extend(self._flush_text_block())
        idx = self.next_block_index
        self.next_block_index += 1
        tool_id = generate_tool_id()

        lines.append(
            self._sse(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": idx,
                    "content_block": {
                        "type": "tool_use",
                        "id": tool_id,
                        "name": call["name"],
                        "input": {},
                    },
                },
            )
        )

        input_json = json.dumps(call["arguments"], ensure_ascii=False)
        self.total_output_tokens += estimate_tokens(input_json)
        lines.append(
            self._sse(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "input_json_delta", "partial_json": input_json},
                },
            )
        )

        lines.append(
            self._sse(
                "content_block_stop",
                {"type": "content_block_stop", "index": idx},
            )
        )
        return lines

    def _finish(self) -> list[str]:
        if self.finished:
            return []
        self.finished = True
        lines = []
        lines.extend(self._flush_text_block())
        lines.extend(self._end_thinking_block())

        stop_reason = "tool_use" if self.has_tool_call else "end_turn"
        output_tokens = max(1, self.total_output_tokens)

        lines.append(
            self._sse(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {
                        "stop_reason": stop_reason,
                        "stop_sequence": None,
                    },
                    "usage": {"output_tokens": output_tokens},
                },
            )
        )
        lines.append(self._sse("message_stop", {"type": "message_stop"}))
        return lines

    @staticmethod
    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

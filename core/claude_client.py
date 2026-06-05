"""
Unified LLM client — supports Ollama (local, free) and Anthropic (cloud).

Provider is selected via LLM_PROVIDER env var:
  "ollama"    — local model via Ollama (http://localhost:11434)
  "anthropic" — Anthropic Claude API (requires API key + credits)

All callers use run_agent() / run_agent_loop() — the returned response object
exposes the same .content[].text and .usage interface regardless of provider.
"""
import os
import json
import httpx
from dataclasses import dataclass, field
from typing import Optional


# ── Unified response types (compatible with Anthropic response shape) ─────────

@dataclass
class _Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class _ContentBlock:
    type: str = "text"
    text: str = ""


@dataclass
class UnifiedResponse:
    content: list
    usage: _Usage
    stop_reason: str = "end_turn"


# ── Ollama client ─────────────────────────────────────────────────────────────

def _ollama_chat(
    system_prompt: str,
    messages: list,
    max_tokens: int = 8096,
) -> UnifiedResponse:
    base_url = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = os.environ.get("OLLAMA_MODEL", "llama3.1")

    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "stream": False,
        "options": {"num_predict": max_tokens},
    }
    resp = httpx.post(f"{base_url}/api/chat", json=payload, timeout=180.0)
    resp.raise_for_status()
    data = resp.json()
    text = data.get("message", {}).get("content", "")
    tokens = data.get("prompt_eval_count", 0) + data.get("eval_count", 0)

    return UnifiedResponse(
        content=[_ContentBlock(type="text", text=text)],
        usage=_Usage(input_tokens=tokens, output_tokens=0),
        stop_reason="end_turn",
    )


# ── Anthropic client ──────────────────────────────────────────────────────────

_anthropic_client = None


def _get_anthropic():
    global _anthropic_client
    if _anthropic_client is None:
        import anthropic
        _anthropic_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _anthropic_client


def _anthropic_chat(
    system_prompt: str,
    messages: list,
    tools: list = None,
    model: str = "claude-opus-4-7",
    max_tokens: int = 8096,
):
    return _get_anthropic().messages.create(
        model=model,
        max_tokens=max_tokens,
        system=[{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}],
        messages=messages,
        tools=tools or [],
    )


# ── Public API ────────────────────────────────────────────────────────────────

def _provider() -> str:
    return os.environ.get("LLM_PROVIDER", "ollama").lower()


def run_agent(
    system_prompt: str,
    messages: list,
    tools: list = None,
    model: str = "claude-opus-4-7",
    max_tokens: int = 8096,
) -> UnifiedResponse:
    """Run a single LLM turn. Returns a UnifiedResponse with .content[].text and .usage."""
    if _provider() == "anthropic":
        raw = _anthropic_chat(system_prompt, messages, tools, model, max_tokens)
        # Wrap Anthropic response into our unified shape
        content = [_ContentBlock(type=b.type, text=getattr(b, "text", "")) for b in raw.content]
        usage = _Usage(
            input_tokens=raw.usage.input_tokens,
            output_tokens=raw.usage.output_tokens,
        )
        return UnifiedResponse(content=content, usage=usage, stop_reason=raw.stop_reason)

    # Ollama — tools not supported; just do a plain chat call
    return _ollama_chat(system_prompt, messages, max_tokens)


def run_agent_loop(
    system_prompt: str,
    initial_messages: list,
    tools: list,
    max_iterations: int = 10,
    model: str = "claude-opus-4-7",
) -> list:
    """
    Agentic loop — runs until stop_reason == 'end_turn' or max_iterations.
    Tool use is only supported with the Anthropic provider; Ollama falls back
    to a single-turn call.
    """
    if _provider() != "anthropic":
        # Ollama: single turn, no tool calls
        response = _ollama_chat(system_prompt, initial_messages)
        messages = list(initial_messages)
        messages.append({"role": "assistant", "content": response.content[0].text})
        return messages

    # Anthropic agentic loop
    messages = list(initial_messages)
    for _ in range(max_iterations):
        raw = _anthropic_chat(system_prompt, messages, tools, model)
        messages.append({"role": "assistant", "content": raw.content})

        if raw.stop_reason == "end_turn":
            break

        tool_uses = [b for b in raw.content if b.type == "tool_use"]
        if not tool_uses:
            break

        tool_results = []
        for tool_use in tool_uses:
            result = _dispatch_tool(tool_use.name, tool_use.input)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": str(result),
            })
        messages.append({"role": "user", "content": tool_results})

    return messages


def _dispatch_tool(name: str, inputs: dict) -> str:
    handler = _tool_registry.get(name)
    if handler is None:
        return f"Unknown tool: {name}"
    return handler(**inputs)


_tool_registry: dict = {}


def register_tool(name: str, handler):
    _tool_registry[name] = handler

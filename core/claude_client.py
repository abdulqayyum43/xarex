import os
import anthropic
from typing import Optional

_client: Optional[anthropic.Anthropic] = None


def get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _client


def run_agent(
    system_prompt: str,
    messages: list,
    tools: list = None,
    model: str = "claude-opus-4-7",
    max_tokens: int = 8096,
) -> anthropic.types.Message:
    """Run a single Claude agent turn with prompt caching on the system prompt."""
    return get_client().messages.create(
        model=model,
        max_tokens=max_tokens,
        system=[
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=messages,
        tools=tools or [],
    )


def run_agent_loop(
    system_prompt: str,
    initial_messages: list,
    tools: list,
    max_iterations: int = 10,
    model: str = "claude-opus-4-7",
) -> list:
    """Run an agentic loop until Claude stops calling tools or hits max_iterations."""
    messages = list(initial_messages)
    for _ in range(max_iterations):
        response = run_agent(system_prompt, messages, tools, model)
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            break

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            break

        tool_results = []
        for tool_use in tool_uses:
            result = _dispatch_tool(tool_use.name, tool_use.input)
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": str(result),
                }
            )
        messages.append({"role": "user", "content": tool_results})

    return messages


def _dispatch_tool(name: str, inputs: dict) -> str:
    """Registry hook — individual agents register their tool handlers at import time."""
    handler = _tool_registry.get(name)
    if handler is None:
        return f"Unknown tool: {name}"
    return handler(**inputs)


_tool_registry: dict = {}


def register_tool(name: str, handler):
    _tool_registry[name] = handler

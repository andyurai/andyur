"""A minimal tool-using LLM agent, used for BOTH sides of the demo.

The support agent and the τ²-style customer simulator are the same machinery: an
LLM with a system prompt, a set of tools that are its slice of the shared app's
API, and a running history. They differ only in prompt and tool surface. On each
turn it takes the other party's message, runs a tool-use loop against the app
(diagnosing, acting), and returns the natural-language message it sends back.

The dual control is real: each agent can only call the tools in its own surface,
and app.dispatch refuses anything else, so neither can reach across the boundary
no matter what the model tries.
"""

import json
import os
from typing import Callable

import httpx

API = "https://api.anthropic.com/v1/messages"
MAX_TOOL_STEPS = 8  # per turn, so a confused model cannot loop forever


class LLMAgent:
    """A tool-using LLM agent. Tool execution is delegated to `dispatch_fn(actor,
    name, args) -> dict`, so the same agent can act on an in-process app OR on a
    remote app service, without knowing which."""

    def __init__(self, actor: str, system: str, tools: list,
                 dispatch_fn: Callable, model: str, key: str | None = None,
                 temperature: float = 0.7):
        self.actor = actor                 # "agent" or "advertiser"
        self.system = system
        self.tools = tools
        self.dispatch_fn = dispatch_fn
        self.model = model
        self.temperature = temperature
        self.key = key or os.environ["ANTHROPIC_API_KEY"]
        self.history: list = []            # anthropic messages

    def _call(self, messages: list) -> dict:
        r = httpx.post(
            API,
            headers={"x-api-key": self.key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": 700, "temperature": self.temperature,
                  "system": self.system, "tools": self.tools, "messages": messages},
            timeout=90,
        )
        r.raise_for_status()
        return r.json()

    def respond(self, incoming: str) -> tuple[str, list]:
        """Process one inbound message; return (reply_text, tool_calls_this_turn).
        tool_calls is a list of (tool_name, args, result_ok) for the transcript."""
        messages = self.history + [{"role": "user", "content": incoming}]
        calls: list = []
        text = ""
        for _ in range(MAX_TOOL_STEPS):
            resp = self._call(messages)
            messages.append({"role": "assistant", "content": resp["content"]})
            if resp.get("stop_reason") == "tool_use":
                tool_results = []
                for block in resp["content"]:
                    if block.get("type") == "tool_use":
                        result = self.dispatch_fn(self.actor, block["name"],
                                                  block.get("input", {}))
                        calls.append((block["name"], block.get("input", {}),
                                      bool(result.get("ok"))))
                        tool_results.append({
                            "type": "tool_result", "tool_use_id": block["id"],
                            "content": json.dumps(result),
                        })
                messages.append({"role": "user", "content": tool_results})
                continue
            # end_turn: the final text is the message to the other party
            text = "".join(b.get("text", "") for b in resp["content"]
                           if b.get("type") == "text").strip()
            break
        self.history = messages
        return text, calls

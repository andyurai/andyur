"""A conforming Andyur agent built on the OpenAI Agents SDK — zero Andyur
imports.

The second independent framework for ADR-008's acceptance gate. It uses the
`agents` package (OpenAI Agents SDK) with its OWN OpenAI model client and its
OWN MCP client (`agents.mcp`), and runs under Andyur through
`andyur-agent-runtime/v1`:

  1. reads ANDYUR_RUNTIME_URL / ANDYUR_RUNTIME_TOKEN and GET /v1/context;
  2. builds an AsyncOpenAI client pointed at the context's model_base_url
     (the proxy's OpenAI-compatible surface) with a throwaway key -- the
     proxy injects the real credential;
  3. attaches the granted MCP tools from mcp_url via MCPServerStreamableHttp;
  4. runs the agent (model -> tool_call -> MCP tool -> model -> final);
  5. maps the run's items onto neutral /v1 events and POSTs them, then done.

Model/agent/MCP wiring is all the OpenAI SDK's; Andyur sees only the runtime
protocol.
"""

import asyncio
import json
import os
import sys
import time

import httpx
from openai import AsyncOpenAI
from agents import (Agent, Runner, OpenAIChatCompletionsModel,
                    set_tracing_disabled)
from agents.mcp import MCPServerStreamableHttp

PROTOCOL = "andyur-agent-runtime/v1"
CONNECT_TIMEOUT_S = 120.0
EXIT_OK = 0
EXIT_FATAL = 1
EXIT_UNSUPPORTED_PROTOCOL = 3

# The SDK's tracing exporter phones home to OpenAI; a confined BYOA agent has
# no egress for that and no key. Off.
set_tracing_disabled(True)


def fetch_context(runtime_url: str, headers: dict) -> dict:
    deadline = time.monotonic() + CONNECT_TIMEOUT_S
    while True:
        try:
            r = httpx.get(f"{runtime_url}/v1/context", headers=headers,
                          timeout=30.0)
        except httpx.ConnectError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
            continue
        r.raise_for_status()
        return r.json()


def _event(**fields) -> bytes:
    base = {"kind": "msg", "record": {}, "texts": [], "tools": [],
            "results": [], "result": None}
    base.update(fields)
    return (json.dumps(base) + "\n").encode()


def _done(exit_code: int, error) -> bytes:
    return (json.dumps({"kind": "done", "exit": exit_code,
                        "error": error}) + "\n").encode()


def _item_events(items) -> list:
    """Best-effort map of Agents-SDK run items onto neutral events. Defensive
    across SDK versions: classify by class name and pull names/outputs by
    getattr rather than a fixed schema."""
    def _call_id(raw, default):
        # The SDK carries call_id on the raw item as an attribute or a dict
        # key depending on version; try both so the call and its result share
        # one id and the neutral events correlate.
        if raw is None:
            return default
        cid = getattr(raw, "call_id", None)
        if cid is None and isinstance(raw, dict):
            cid = raw.get("call_id")
        return cid or default

    out = []
    for item in items:
        cls = type(item).__name__
        raw = getattr(item, "raw_item", None)
        if cls == "ToolCallItem":
            name = (getattr(raw, "name", None)
                    or getattr(getattr(raw, "function", None), "name", None)
                    or "tool")
            out.append(_event(record={"framework": "openai-agents",
                                      "type": "tool_call"},
                              tools=[{"id": _call_id(raw, "call"),
                                      "name": name, "input": {}}]))
        elif cls == "ToolCallOutputItem":
            out.append(_event(record={"framework": "openai-agents",
                                      "type": "tool_result"},
                              results=[{"tool_use_id": _call_id(raw, "call"),
                                        "content": str(getattr(item, "output", "")),
                                        "is_error": False}]))
    return out


async def build_events(context: dict):
    error = None
    exit_code = EXIT_OK
    events: list = []
    try:
        services = context["services"]
        prompt = (context.get("input") or {}).get("prompt", "hello")
        # The effective model from the run context (platform-enforced anyway).
        model_id = context.get("model") or "default"

        client = AsyncOpenAI(
            base_url=f"{services['model_base_url']}/v1",
            api_key="unused-the-proxy-injects-the-real-one", max_retries=0)
        model = OpenAIChatCompletionsModel(
            model=model_id, openai_client=client)

        async with MCPServerStreamableHttp(
                name="andyur",
                params={"url": services["mcp_url"],
                        "headers": services.get("mcp_headers") or {}}) as server:
            agent = Agent(name="byoa-openai-agent",
                          instructions="Use the available tool, then answer.",
                          model=model, mcp_servers=[server])
            result = await Runner.run(agent, prompt, max_turns=6)

        events.extend(_item_events(result.new_items))
        final = str(result.final_output or "openai-agents run complete")
        events.append(_event(record={"framework": "openai-agents",
                                     "type": "result"},
                             texts=[final],
                             result={"result": final, "is_error": False,
                                     "num_turns": 1}))
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        exit_code = EXIT_FATAL
    for ev in events:
        yield ev
    yield _done(exit_code, error)


async def _amain() -> int:
    runtime_url = os.environ.get("ANDYUR_RUNTIME_URL")
    if not runtime_url:
        print("[openai-agent] ANDYUR_RUNTIME_URL not set", file=sys.stderr)
        return EXIT_FATAL
    token = os.environ.get("ANDYUR_RUNTIME_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    context = await asyncio.to_thread(fetch_context, runtime_url, headers)
    if context.get("protocol_version") != PROTOCOL:
        print(f"[openai-agent] unsupported protocol "
              f"{context.get('protocol_version')!r}", file=sys.stderr)
        return EXIT_UNSUPPORTED_PROTOCOL

    async def body():
        async for ev in build_events(context):
            yield ev

    async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, read=None, write=None)) as http:
        resp = await http.post(f"{runtime_url}/v1/events", headers=headers,
                               content=body())
        if resp.status_code != 200:
            print(f"[openai-agent] /v1/events -> {resp.status_code}",
                  file=sys.stderr)
            return EXIT_FATAL
    return EXIT_OK


def main() -> None:
    try:
        sys.exit(asyncio.run(_amain()))
    except Exception as exc:
        print(f"[openai-agent] fatal: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

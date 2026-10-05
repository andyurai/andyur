"""A conforming Andyur agent built on LangGraph — zero Andyur imports.

This is the second-framework proof (ADR-008 acceptance gate): a real
LangGraph ReAct agent, using langchain-openai for the model and
langchain-mcp-adapters for tools, runs under Andyur through
`andyur-agent-runtime/v1` without importing any Andyur package. It:

  1. reads ANDYUR_RUNTIME_URL / ANDYUR_RUNTIME_TOKEN and GET /v1/context;
  2. points ChatOpenAI at the context's `model_base_url` (Andyur's model
     proxy speaks the OpenAI-compatible surface its LiteLLM gateway exposes),
     with a throwaway key -- the proxy injects the real credential the agent
     never holds;
  3. loads the granted MCP tools from `mcp_url` via langchain-mcp-adapters,
     the framework's own MCP client (not Andyur's);
  4. runs a prebuilt ReAct graph: model -> tool_call -> MCP tool -> model ->
     final answer;
  5. maps the graph's message trace onto neutral /v1 events and POSTs them,
     ending with the `done` sentinel.

The point is that every framework-specific choice (graph, model client, MCP
client) is LangChain/LangGraph's, and Andyur sees only the runtime protocol.
"""

import asyncio
import json
import os
import sys
import time
import urllib.parse

import httpx
from langchain_core.messages import AIMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

PROTOCOL = "andyur-agent-runtime/v1"
CONNECT_TIMEOUT_S = 120.0
EXIT_OK = 0
EXIT_FATAL = 1
EXIT_UNSUPPORTED_PROTOCOL = 3


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


async def build_events(context: dict):
    """Run the LangGraph agent and yield neutral /v1 events, then done."""
    error = None
    exit_code = EXIT_OK
    events: list[bytes] = []
    try:
        services = context["services"]
        prompt = (context.get("input") or {}).get("prompt", "hello")
        # The effective model from the run context (the platform enforces it
        # regardless; the agent sends the one it was told).
        model_id = context.get("model") or "default"

        # OpenAI-compatible: base_url is the proxy root + /v1, so the client
        # POSTs .../v1/chat/completions, which the proxy forwards upstream.
        model = ChatOpenAI(
            model=model_id,
            base_url=f"{services['model_base_url']}/v1",
            api_key="unused-the-proxy-injects-the-real-one",
            temperature=0, max_retries=0)

        client = MultiServerMCPClient({
            "andyur": {
                "url": services["mcp_url"],
                "transport": "streamable_http",
                "headers": services.get("mcp_headers") or {},
            }
        })
        tools = await client.get_tools()
        if not tools:
            raise RuntimeError("no MCP tools available from the sidecar")

        agent = create_react_agent(model, tools)
        result = await agent.ainvoke({"messages": [("user", prompt)]})

        # Map the framework's message trace onto neutral events.
        last_text = ""
        for msg in result["messages"]:
            if isinstance(msg, AIMessage):
                text = msg.content if isinstance(msg.content, str) else ""
                calls = getattr(msg, "tool_calls", None) or []
                if text:
                    last_text = text
                    events.append(_event(
                        record={"framework": "langgraph", "type": "ai"},
                        texts=[text]))
                if calls:
                    events.append(_event(
                        record={"framework": "langgraph", "type": "tool_calls"},
                        tools=[{"id": c.get("id", "call"),
                                "name": c.get("name", ""),
                                "input": c.get("args", {})} for c in calls]))
            elif isinstance(msg, ToolMessage):
                events.append(_event(
                    record={"framework": "langgraph", "type": "tool_result"},
                    results=[{"tool_use_id": msg.tool_call_id,
                              "content": str(msg.content), "is_error": False}]))
        events.append(_event(
            record={"framework": "langgraph", "type": "result"},
            texts=[last_text],
            result={"result": last_text or "langgraph run complete",
                    "is_error": False, "num_turns": 1}))
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        exit_code = EXIT_FATAL
    for ev in events:
        yield ev
    yield _done(exit_code, error)


async def _amain() -> int:
    runtime_url = os.environ.get("ANDYUR_RUNTIME_URL")
    if not runtime_url:
        print("[langgraph-agent] ANDYUR_RUNTIME_URL not set", file=sys.stderr)
        return EXIT_FATAL
    token = os.environ.get("ANDYUR_RUNTIME_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    context = await asyncio.to_thread(fetch_context, runtime_url, headers)
    if context.get("protocol_version") != PROTOCOL:
        print(f"[langgraph-agent] unsupported protocol "
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
            print(f"[langgraph-agent] /v1/events -> {resp.status_code}",
                  file=sys.stderr)
            return EXIT_FATAL
    return EXIT_OK


def main() -> None:
    try:
        sys.exit(asyncio.run(_amain()))
    except Exception as exc:
        print(f"[langgraph-agent] fatal: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

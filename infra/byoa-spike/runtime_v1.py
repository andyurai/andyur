"""DISPOSABLE conformance harness for `andyur-agent-runtime/v1` (ADR-008 C1).

This module is test scaffolding, not production code, and it is built to be
deleted: when the runner-integration phase (ADR-008 C2) teaches the
production channel the /v1 route names, the shim here dies with the spike.
Until then it lets the conformance gate and the fast-lane tests drive a real
third-party agent against the REAL enforcement components:

    hello agent  --/v1/context, /v1/events-->  RuntimeV1Shim
                                                  |  (path mapping only)
                                                  v
                                        REAL runner.AgentChannel
                                        (auth, sanitize-on-receipt,
                                         stream budgets, done semantics)

    hello agent  --model_base_url-->  REAL runner.ModelProxy  --key-->  stub
                                      (credential injection)         gateway

    hello agent  --mcp_url-->  real MCP SDK server (test tools)

Three explicitly-labeled TEST DOUBLES live here -- the upstream model gateway,
the MCP tool server, and the /v1 path shim. Everything security-relevant that
the gate asserts (credential injection, sanitize, budgets, refusal semantics)
happens inside real Andyur components or the real MCP SDK, never inside a
double. The stub gateway holds a CANARY credential so secret-absence is
proved by value: the canary must reach the gateway (the proxy injected it)
and must never appear in anything the agent could read.
"""

from __future__ import annotations

import asyncio
import json
import secrets

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

import mcp.types as mcp_types
from mcp.server.lowlevel import Server as McpServer
from mcp.server.fastmcp.server import StreamableHTTPASGIApp
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from andyur.runner import agentchannel
# One source of truth for the protocol string: the agentspec package owns it.
# The reference agent (agent.py) cannot import it -- it is deliberately
# zero-import -- so its own literal is pinned to this value by a test instead.
from andyur.agentspec import PROTOCOL_V1


def make_canary() -> str:
    """A unique credential-shaped value the harness plants as the gateway key.
    Secret-absence checks search for THIS VALUE, which cannot false-negative
    the way key-name heuristics do."""
    return "canary-gateway-key-" + secrets.token_urlsafe(24)


# The effective model the harness advertises. The stub echoes whatever model a
# request names, so any string works here; a distinctive, vendor-tagged value
# lets the gate prove the agent READ it from context rather than hardcoding one.
# It is intentionally a Claude id even for the OpenAI-surface agents: the model
# id is vendor-neutral from the agent's view (the gateway/LiteLLM maps it), so
# an OpenAI-style client legitimately sends a claude-* effective model.
DEFAULT_EFFECTIVE_MODEL = "claude-sonnet-4-5"


def build_context(*, run_id: str, agent_id: str, prompt: str,
                  model_base_url: str, mcp_url: str,
                  model: str | None = DEFAULT_EFFECTIVE_MODEL,
                  mcp_headers: dict | None = None,
                  deadline: str | None = None,
                  protocol_version: str = PROTOCOL_V1) -> dict:
    """The v1 context document. Carries the effective `model` the way the real
    server /context carries `registry_model`: the run-readable context surfaces
    which model the agent runs on, but never the operator-only resolution
    internals (ceiling, reach_urls). Advertises the REAL channel budgets so a
    conforming agent reads the limits the enforcement actually applies."""
    return {
        "protocol_version": protocol_version,
        "run_id": run_id,
        "agent_id": agent_id,
        # The effective model, fixed by the platform from the approved
        # resolution (or its default). The agent sends this to the model
        # service; the platform enforces it regardless, so it is transparency,
        # not a lever. null means "use the service's default".
        "model": model,
        "input": {"prompt": prompt},
        "services": {
            "model_base_url": model_base_url,
            "mcp_url": mcp_url,
            "mcp_headers": mcp_headers or {},
            "extra_mcp_servers": {},
        },
        "limits": {
            "deadline": deadline,
            "max_line_bytes": agentchannel._MAX_LINE,
            "max_stream_bytes": agentchannel._MAX_STREAM,
        },
        "trace": {"traceparent": None},
    }


class _LoopServer:
    """One uvicorn server running as a task in the CURRENT event loop --
    the AgentChannel's own start/stop shape, factored for the harness apps."""

    def __init__(self, app, host: str = "127.0.0.1", port: int = 0):
        self._server = uvicorn.Server(uvicorn.Config(
            app, host=host, port=port, log_level="warning"))
        self._host = host
        self._task: asyncio.Task | None = None

    async def start(self) -> str:
        self._task = asyncio.create_task(self._server.serve())
        while not self._server.started:
            if self._task.done():
                await self._task
                raise RuntimeError("harness server failed to start")
            await asyncio.sleep(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://{self._host}:{port}"

    async def stop(self) -> None:
        self._server.should_exit = True
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()


class RuntimeV1Shim:
    """Serves the v1 route names by proxying to a real AgentChannel.

    PATH MAPPING ONLY: /v1/context -> GET <channel>/inputs and /v1/events ->
    POST <channel>/stream, streaming the body through unbuffered. Every
    decision -- authorization, sanitize, budgets, the 409 second-stream
    refusal -- is the channel's; the shim forwards the Authorization header
    and the status code and adds nothing."""

    def __init__(self, channel_url: str, host: str = "127.0.0.1"):
        self._channel_url = channel_url
        self._host = host
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, read=None, write=None))
        self._server: _LoopServer | None = None
        # Counted so a refusal check can prove the workload actually RAN and
        # received its context before refusing. Without this, a container that
        # never started satisfies "exited non-zero and stayed silent".
        self.context_fetches = 0

    def _auth_headers(self, request: Request) -> dict:
        auth = request.headers.get("authorization")
        return {"Authorization": auth} if auth else {}

    async def _context(self, request: Request) -> Response:
        upstream = await self._client.get(
            f"{self._channel_url}/inputs", headers=self._auth_headers(request))
        if upstream.status_code < 300:
            # Counted only when the workload actually RECEIVED its context: an
            # unauthenticated GET that got a 401 never saw the version it is
            # supposed to refuse, so it must not count as having read it.
            self.context_fetches += 1
        media = upstream.headers.get("content-type", "text/plain")
        return Response(upstream.content, status_code=upstream.status_code,
                        media_type=media)

    async def _events(self, request: Request) -> Response:
        try:
            upstream = await self._client.post(
                f"{self._channel_url}/stream",
                headers=self._auth_headers(request),
                content=request.stream())
        except (ClientDisconnect, httpx.HTTPError) as exc:
            # The agent died mid-stream (or the channel aborted the upload).
            # The CHANNEL has already synthesized the failed done -- this
            # response goes to a peer that is gone; answer quietly instead of
            # stack-tracing the harness log.
            return PlainTextResponse(
                f"stream aborted: {type(exc).__name__}", status_code=502)
        return PlainTextResponse(upstream.text,
                                 status_code=upstream.status_code)

    async def start(self) -> str:
        app = Starlette(routes=[
            Route("/v1/context", self._context, methods=["GET"]),
            Route("/v1/events", self._events, methods=["POST"]),
        ])
        self._server = _LoopServer(app, host=self._host)
        return await self._server.start()

    async def stop(self) -> None:
        if self._server is not None:
            await self._server.stop()
        await self._client.aclose()


class StubModelGateway:
    """TEST DOUBLE: the upstream the real ModelProxy forwards to. It records
    the authorization it saw (so the harness proves the proxy injected the
    canary and the agent sent none) and answers TWO model APIs:

        POST /v1/messages          Anthropic Messages (the stdlib reference
                                   agent and any Anthropic-native framework)
        POST /v1/chat/completions  OpenAI Chat Completions (LangGraph via
                                   langchain-openai, the OpenAI Agents SDK,
                                   and everything else OpenAI-compatible --
                                   the shape Andyur's production LiteLLM
                                   gateway speaks)

    The OpenAI path is SCRIPTED to drive a real agentic loop: on the first
    turn, if the caller offered tools, it returns a tool_call for the first
    one; once it sees the tool's result in the message history, it returns a
    final answer. So a real framework's ReAct loop actually fires -- model ->
    tool_call -> MCP call -> model -> final -- rather than a single canned
    reply. The Anthropic path stays a single text reply (the stdlib agent
    calls the MCP tool directly, not through model tool-calling)."""

    def __init__(self, host: str = "127.0.0.1", delay_s: float = 0.0):
        self.seen_authorization: list[str | None] = []
        self.seen_models: list[str | None] = []
        self._host = host
        # A response delay lets the gate hold an agent MID-RUN (stream open,
        # model call in flight) long enough to kill it and prove the platform
        # fails the run closed.
        self._delay_s = delay_s
        # Releasable, not a bare sleep: an in-flight delayed reply blocks
        # uvicorn's graceful shutdown for the whole delay (the G6 kill
        # scenario), and force-cancelling it stack-traces the harness log.
        # stop() releases every pending delay first.
        self._release = asyncio.Event()
        self._server: _LoopServer | None = None

    async def _gate(self, request: Request) -> bool:
        """Record auth and apply the optional mid-run delay. Returns False
        when a shutdown cancelled the delay (the caller should 503)."""
        self.seen_authorization.append(request.headers.get("authorization"))
        if self._delay_s and not self._release.is_set():
            try:
                await asyncio.wait_for(self._release.wait(),
                                       timeout=self._delay_s)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                return False
        return True

    async def _messages(self, request: Request) -> Response:
        if not await self._gate(request):
            return PlainTextResponse("shutting down", status_code=503)
        body = await request.json()
        self.seen_models.append(body.get("model"))
        prompt = ""
        for message in body.get("messages", []):
            if isinstance(message.get("content"), str):
                prompt = message["content"]
        return JSONResponse({
            "id": "msg_stub", "type": "message", "role": "assistant",
            "model": body.get("model", "stub"),
            "content": [{"type": "text",
                         "text": f"stub reply to {len(prompt)} chars"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        })

    async def _chat_completions(self, request: Request) -> Response:
        if not await self._gate(request):
            return PlainTextResponse("shutting down", status_code=503)
        body = await request.json()
        self.seen_models.append(body.get("model"))
        messages = body.get("messages", [])
        tools = body.get("tools", [])
        # A tool round has happened once the history carries either a tool-role
        # message or an assistant turn that requested tool_calls -- frameworks
        # serialize the result leg differently, so detect both.
        already_called = any(
            m.get("role") == "tool" or m.get("tool_calls") for m in messages)
        model = body.get("model", "stub")
        base = {"id": "chatcmpl-stub", "object": "chat.completion",
                "created": 0, "model": model,
                "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                          "total_tokens": 2}}

        # Bound the tool loop against a misbehaving client that never echoes
        # the tool result back into its history: `already_called` would stay
        # false forever and the stub would keep issuing tool_calls up to the
        # framework's own max_turns. Counting the assistant tool_call turns in
        # the history caps it regardless of what the client echoes.
        prior_tool_turns = sum(
            1 for m in messages
            if m.get("role") == "assistant" and m.get("tool_calls"))
        if tools and not already_called and prior_tool_turns < 1:
            # First turn with tools on offer: call the first one. The frame-
            # work will route this to its MCP client and feed us the result.
            fn = tools[0].get("function", {})
            name = fn.get("name", "echo")
            base["choices"] = [{
                "index": 0, "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": None,
                            "tool_calls": [{
                                "id": "call_stub_1", "type": "function",
                                "function": {"name": name,
                                             "arguments": '{"text": "hello from the model"}'}}]},
            }]
            return JSONResponse(base)

        # No tools, or the tool result is already in history: final answer.
        tool_text = ""
        for m in messages:
            if m.get("role") == "tool":
                c = m.get("content")
                tool_text = c if isinstance(c, str) else json.dumps(c)
        summary = (f"final answer after the tool returned {len(tool_text)} chars"
                   if already_called else "final answer (no tool call)")
        base["choices"] = [{
            "index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": summary},
        }]
        return JSONResponse(base)

    async def start(self) -> str:
        app = Starlette(routes=[
            Route("/v1/messages", self._messages, methods=["POST"]),
            Route("/v1/chat/completions", self._chat_completions,
                  methods=["POST"]),
        ])
        self._server = _LoopServer(app, host=self._host)
        return await self._server.start()

    async def stop(self) -> None:
        self._release.set()
        if self._server is not None:
            await self._server.stop()


def _build_tool_server(seen_calls: list) -> McpServer:
    server = McpServer("byoa-conformance-tools")

    @server.list_tools()
    async def _list() -> list[mcp_types.Tool]:
        return [mcp_types.Tool(
            name="echo",
            description="Echo the supplied text back. Conformance test tool.",
            inputSchema={"type": "object",
                         "properties": {"text": {"type": "string"}}},
        )]

    @server.call_tool()
    async def _call(name: str, arguments: dict) -> list[mcp_types.TextContent]:
        # Record the call HARNESS-SIDE, before answering. This is the tool
        # leg's equivalent of the gateway's seen_authorization/seen_models:
        # it makes "a granted MCP tool was actually invoked" an independently
        # observed fact, not something the gate has to take from the agent's
        # self-reported events (which a compromised agent could forge).
        seen_calls.append((name, dict(arguments)))
        if name != "echo":
            raise ValueError(f"unknown tool {name!r}")
        return [mcp_types.TextContent(
            type="text", text=f"echo: {arguments.get('text', '')}")]

    return server


class StubMcpService:
    """TEST DOUBLE tools behind the REAL MCP SDK transport: the same
    streamable-HTTP session manager the production ToolService serves, so
    the agent's hand-rolled MCP client is proven against the real wire.

    `seen_calls` records every `tools/call` the transport actually received,
    so a gate can prove the tool leg from harness observation rather than the
    agent's word. Like the model stub, this double does NOT authenticate: it
    answers any caller. Credential handling is proven by the model canary and
    tool authority is a server-side control; this double certifies the wire
    and the round trip, not an auth-rejecting tool server."""

    def __init__(self, host: str = "127.0.0.1"):
        self.seen_calls: list = []
        # stateless: agents do not DELETE their MCP session, and a stateful
        # manager then holds a live session task at shutdown -- the harness
        # teardown times out cancelling it and stack-traces. The wire the
        # agent speaks (initialize/initialized/tools) is identical; the
        # production ToolService stays stateful and is not what this double
        # certifies.
        self._manager = StreamableHTTPSessionManager(
            app=_build_tool_server(self.seen_calls), json_response=True,
            stateless=True)
        self._host = host
        self._server: _LoopServer | None = None

    async def start(self) -> str:
        app = Starlette(
            routes=[Route("/mcp", StreamableHTTPASGIApp(self._manager),
                          methods=["GET", "POST", "DELETE"])],
            lifespan=lambda app: self._manager.run(),
        )
        self._server = _LoopServer(app, host=self._host)
        base = await self._server.start()
        return f"{base}/mcp"

    async def stop(self) -> None:
        if self._server is not None:
            await self._server.stop()

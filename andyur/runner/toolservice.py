"""The andyur platform tools, served over loopback HTTP instead of in-process.

WHY THIS EXISTS. Today the platform tools (memory, tasks, messages, graph) run
as an in-process SDK MCP server: `create_sdk_mcp_server` hands the SDK a Python
object, and the SDK bridges it to the agent CLI over the SDK's own control
protocol on the CLI's stdio. That bridge only works because the ClaudeSDKClient
and the tool object live in the SAME process -- and that process holds the run
token the tools authenticate with.

The container split moves the SDK driver (and the CLI it spawns) into its own
process/container that must hold NOTHING. So the tools can no longer ride the
in-process bridge; they have to be a real service the agent reaches over the
network. This module is that service: the SAME tool object
`build_platform_server` already builds (single source of truth), served over
streamable-HTTP on loopback.

    agent CLI (uid 1001)  --http://127.0.0.1:PORT/mcp-->  this service (sidecar A)
                                                          |
                                                          +-- holds the run token,
                                                              calls the control plane

The run token stays in the sidecar, exactly as it does with the in-process
server. The agent calls a tool; the sidecar performs the audited control-plane
call as this agent/run. The agent never holds the token, whichever transport the
tools use.

ACCESS CONTROL IS THE LOOPBACK BOUNDARY, same argument as the model proxy: the
service binds 127.0.0.1, so inside the run's own network namespace the only
callers are this run's own processes (the agent CLI and, later, the split agent
process). The tools do only this agent's own operations, scoped by the run token
the sidecar holds -- so an unauthenticated loopback caller is this run acting as
itself, which is exactly what the in-process server allowed too. An OPTIONAL
per-run bearer token (ANDYUR_AGENT_SPLIT_TOKEN path) is layered on as defense in
depth for a shared network namespace; it defends the port from OTHER processes,
never from the agent, since whatever the agent must present the agent can read.
"""

from __future__ import annotations

import hmac
import os
import threading

from ..execconfig import MCP_PATH as _MCP_PATH

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp.server.fastmcp.server import StreamableHTTPASGIApp
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from .. import identity, otel
from .. import config
from .driver import build_platform_server

SERVICE_NAME = "andyur-runner"
# The same bound the front's /llm enforces (execfront.MAX_BODY_BYTES).
MAX_BODY_BYTES = int(os.environ.get("ANDYUR_LLM_MAX_BODY_BYTES", str(2 * 1024 * 1024)))

# Where the streamable-HTTP endpoint is mounted; the agent's SDK is handed
# f"{base_url}{MCP_PATH}" as an McpHttpServerConfig url.
# BOUND to execconfig.MCP_PATH, not a second copy: exec/v1 resolves
# services.tools.mcp_url to this same endpoint, and the two cannot be
# allowed to disagree about where the tools are served.
MCP_PATH = _MCP_PATH


class _TokenGuard:
    """An ASGI wrapper enforcing the optional per-run token before the MCP app.

    A class instance (not a bare function) so Starlette's Route treats it as an
    ASGI app -- StreamableHTTPASGIApp is wrapped the same way. When no token is
    configured the loopback boundary is the control and this passes through.
    """

    def __init__(self, app, token: str | None):
        self._app = app
        self._token = token

    async def __call__(self, scope, receive, send) -> None:
        headers = dict(scope.get("headers") or [])
        # Bounded like the front's /llm: a declared body beyond the per-run
        # bound is refused by name before the SDK parses it (R MED-2: a 1 MiB
        # tool name reached the SDK's logger).
        declared = headers.get(b"content-length", b"").decode(errors="replace")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            _decided("refused", "body_too_large")
            resp = JSONResponse({"error": "body_too_large",
                                 "detail": "request body exceeds the per-run MCP call limit"},
                                status_code=413)
            await resp(scope, receive, send)
            return
        if self._token is not None:
            # One shared bearer parser (RFC 9110 sec 11.1 case-insensitive scheme).
            # errors="replace": a non-UTF-8 header is a refused credential (401),
            # not a server fault (500).
            presented = identity.bearer_token(
                headers.get(b"authorization", b"").decode(errors="replace"))
            # Constant-time: the bearer is the only thing between a peer on
            # the run's network and this run's tools (R LOW, PR #21).
            if presented is None or not hmac.compare_digest(
                    presented.encode(), self._token.encode()):
                # RFC 6750 sec 3: a 401 to a bearer-protected resource carries
                # the challenge. The refusal BY NAME on the request's span and
                # the counter (never the bearer itself) -- the same code the
                # body carries (observability-exit-criteria.md 1, 3).
                _decided("refused", "bearer_rejected")
                resp = JSONResponse({"error": "bearer_rejected", "detail": "unauthorized"},
                                    status_code=401, headers={"WWW-Authenticate": "Bearer"})
                await resp(scope, receive, send)
                return
        _decided("admitted", "none")
        await self._app(scope, receive, send)


def _decided(outcome: str, refusal: str) -> None:
    """One MCP-boundary decision on the span and the counter; telemetry never
    changes the response."""
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        span.set_attribute("andyur.decision", outcome)
        span.set_attribute("andyur.refusal", refusal)
    except Exception:
        pass
    otel.try_record_metric(SERVICE_NAME, "andyur.mcp.decisions", 1,
                           andyur__outcome=("success" if outcome == "admitted" else "denied"),
                           andyur__refusal=refusal)


def build_app(agent_name: str, origin_trace: str | None, run_id: str | None,
              token: str | None) -> Starlette:
    """A Starlette app serving the andyur MCP tools at MCP_PATH.

    The tools come from build_platform_server -- the EXACT object the in-process
    path uses -- so tool bodies, auth, and audited control-plane calls are shared
    with the non-split path and cannot drift.
    """
    # build_platform_server returns an McpSdkServerConfig dict whose `instance`
    # is a standard low-level mcp.server.Server. That is what the streamable-HTTP
    # session manager serves.
    server = build_platform_server(agent_name, origin_trace, run_id)["instance"]
    # Stateful sessions (the flow the agent's HTTP MCP client speaks: one
    # initialize, then many tool calls under the returned Mcp-Session-Id).
    # json_response keeps replies as plain JSON rather than an SSE stream, which
    # is enough for request/response tool calls and simpler to reason about.
    manager = StreamableHTTPSessionManager(app=server, json_response=True)
    asgi = StreamableHTTPASGIApp(manager)
    guarded = _TokenGuard(asgi, token)

    # Every request at this boundary is a SERVER span in the RUN's trace
    # (origin_trace, the run record's traceparent, as a trusted fixed parent;
    # the caller's own trace headers are never read as identity), with the
    # andyur.http.server.* metrics ObservedASGI records.
    return otel.ObservedASGI(Starlette(
        # A Route (not a Mount) for the exact path, matching FastMCP itself: a
        # Mount redirects the bare path to a trailing slash (307), which would
        # slip past the token guard for that request. The streamable-HTTP methods
        # are GET (open the SSE/stream), POST (JSON-RPC), and DELETE (end session).
        routes=[Route(MCP_PATH, endpoint=guarded, methods=["GET", "POST", "DELETE"])],
        # The session manager's task group must be live for the life of the app;
        # its run() context is the app lifespan.
        lifespan=lambda app: manager.run(),
    ), service_name=SERVICE_NAME, operation="mcp", parent_traceparent=origin_trace)


class ToolService:
    """The andyur tool service, running in a thread for the life of one run.

    Mirrors ModelProxy's shape deliberately: a daemon thread hosting uvicorn, a
    start() that blocks until the socket is up and returns the URL, and a stop()
    that ends with the run. Both are loopback services the sidecar holds and the
    agent merely uses.
    """

    def __init__(self, agent_name: str, origin_trace: str | None = None,
                 run_id: str | None = None, token: str | None = None,
                 host: str = "127.0.0.1", advertise_host: str | None = None,
                 port: int = 0):
        self._server = uvicorn.Server(uvicorn.Config(
            build_app(agent_name, origin_trace, run_id, token),
            host=host, port=port, log_level="warning", loop="asyncio", timeout_graceful_shutdown=config.THREAD_SERVER_GRACEFUL_SHUTDOWN_SECONDS,
        ))
        self._thread: threading.Thread | None = None
        self._host = host
        self._advertise_host = advertise_host or host

    def start(self) -> str:
        """Start serving and return the base MCP URL to hand the agent."""
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("the andyur tool service failed to start")
            threading.Event().wait(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://{self._advertise_host}:{port}{MCP_PATH}"

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)

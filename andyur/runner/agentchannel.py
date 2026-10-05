"""Trusted side of the agent runtime channel.

The production channel serves both the frozen public BYOA protocol and the
legacy internal route names during migration:

    GET  /v1/context   (legacy alias: /inputs)
    POST /v1/events    (legacy alias: /stream)

Both route pairs terminate in the same handlers.  There is no protocol shim and
therefore no second authorization, sanitization, stream-budget, or completion
implementation that can drift from production.
"""

from __future__ import annotations

import asyncio
import json
import os

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from .. import identity
from .protocol import KIND_DONE, done_event, sanitize
from .. import config

_QUEUE_MAX = 2048
_MAX_LINE = int(os.environ.get("ANDYUR_CHANNEL_MAX_LINE_BYTES", str(8 * 1024 * 1024)))
_MAX_STREAM = int(os.environ.get("ANDYUR_CHANNEL_MAX_STREAM_BYTES", str(64 * 1024 * 1024)))


class AgentChannel:
    """One run-bound channel between the trusted sidecar and untrusted agent."""

    def __init__(self, inputs: dict, token: str | None = None,
                 host: str = "127.0.0.1", port: int = 0):
        self._inputs = inputs
        self._token = token
        self._host = host
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._saw_done = False
        self._stream_open = False
        self.done: dict | None = None
        self.connected: asyncio.Event = asyncio.Event()
        self._server = uvicorn.Server(uvicorn.Config(
            self._build_app(), host=host, port=port, log_level="warning", loop="asyncio", timeout_graceful_shutdown=config.THREAD_SERVER_GRACEFUL_SHUTDOWN_SECONDS,
        ))
        self._task: asyncio.Task | None = None

    async def _serve(self) -> None:
        try:
            await self._server.serve()
        except SystemExit as exc:
            raise RuntimeError(
                f"the agent channel could not bind {self._host}:"
                f"{self._server.config.port} (uvicorn exited {exc.code}); "
                "another process is probably holding the channel port"
            ) from exc

    async def start(self) -> str:
        self._task = asyncio.create_task(self._serve())
        while not self._server.started:
            if self._task.done():
                await self._task
                raise RuntimeError("the agent channel failed to start")
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

    async def inject_done(self, exit_code: int, error: str | None) -> None:
        if self._saw_done:
            return
        self._saw_done = True
        await self._queue.put(done_event(exit_code, error))

    async def messages(self):
        while True:
            ev = await self._queue.get()
            if ev.get("kind") == KIND_DONE:
                self.done = ev
                return
            yield ev

    def _authorized(self, request) -> bool:
        if self._token is None:
            return True
        # One shared bearer parser (RFC 9110 sec 11.1 case-insensitive scheme), so
        # the frozen public BYOA channel and the server agree on the same rule.
        return identity.bearer_token(request.headers.get("authorization")) == self._token

    def _build_app(self) -> Starlette:
        async def ready(_request):
            return PlainTextResponse("ready")

        async def context(request):
            if not self._authorized(request):
                return PlainTextResponse("unauthorized", status_code=401)
            return JSONResponse(self._inputs)

        async def events(request):
            if not self._authorized(request):
                return PlainTextResponse("unauthorized", status_code=401)
            if self._stream_open:
                return PlainTextResponse("a stream is already open", status_code=409)
            self._stream_open = True
            self.connected.set()
            buffer = bytearray()
            total = 0
            overflow: str | None = None
            try:
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > _MAX_STREAM:
                        overflow = (f"the agent's stream exceeded the "
                                    f"{_MAX_STREAM} byte budget")
                        break
                    buffer.extend(chunk)
                    while True:
                        nl = buffer.find(b"\n")
                        if nl < 0:
                            break
                        if nl > _MAX_LINE:
                            overflow = (f"the agent sent a line longer than "
                                        f"{_MAX_LINE} bytes")
                            break
                        line = bytes(buffer[:nl])
                        del buffer[:nl + 1]
                        await self._ingest(line)
                    if overflow:
                        break
                    if len(buffer) > _MAX_LINE:
                        overflow = (f"the agent sent a line longer than "
                                    f"{_MAX_LINE} bytes")
                        break
                if overflow is None:
                    await self._ingest(bytes(buffer))
            except Exception:
                pass
            finally:
                if not self._saw_done:
                    await self._queue.put(done_event(
                        -1, overflow or "agent process stream ended without completion"))
                    self._saw_done = True
            if overflow:
                return PlainTextResponse(overflow, status_code=413)
            return PlainTextResponse("ok")

        # v1 is the public contract.  Legacy aliases remain temporarily so the
        # builtin Claude forwarding process can migrate independently.  Aliases
        # deliberately point at the exact same callables.
        return Starlette(routes=[
            Route("/ready", endpoint=ready, methods=["GET"]),
            Route("/v1/context", endpoint=context, methods=["GET"]),
            Route("/v1/events", endpoint=events, methods=["POST"]),
            Route("/inputs", endpoint=context, methods=["GET"]),
            Route("/stream", endpoint=events, methods=["POST"]),
        ])

    async def _ingest(self, line: bytes) -> None:
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except (ValueError, TypeError, RecursionError):
            return
        if not isinstance(ev, dict):
            return
        ev = sanitize(ev)
        if ev.get("kind") == KIND_DONE:
            self._saw_done = True
        await self._queue.put(ev)

"""The exec/v1 sidecar's front on the proxy port: readiness and the model path.

WHY THIS EXISTS. An exec/v1 workload is handed two URLs on the proxy Pod's
`proxy_port` (CHANNEL_PORT, 8765): the Pod's readiness probe (`GET /ready`,
which the controller waits on before it creates the untrusted agent Pod) and
`services.model.base_url` (`http://<proxy-ip>:8765/llm`, resolved by
`_bind_exec_configuration`). In runtime-v1 that port is served by AgentChannel.
The serve-only sidecar never constructs a channel (ADR-011: a stock workload
has no result/done sink), so until this module nothing listened there at all:
every REAL exec/v1 launch would have rolled back at READY_TIMEOUT, and the
model URL the workload was given pointed at a closed port. The live gate had
stubbed the proxy, which is why nothing saw it (R, PR #21 MED-2).

This is that listener, and only that: `/ready`, and `/llm/*` -- ONLY the model-call
endpoints (`modelpolicy.FRONT_LLM_PATHS`, POST), every request pinned to the
run's granted model -- forwarded to the sidecar's own model proxy (the
loopback/advertised URL `_start_model_proxy` or the tool gateway returned), or
in local-model mode to the platform's Ollama. Nothing else is exposed on the port -- no context,
no events, no finish -- and nothing else is REACHABLE through it: the forwarded
path is the request's RAW path with the `/llm` prefix stripped and every dot
segment refused by name (`forward_path`). In Kubernetes the upstream is the
ToolSidecar, whose ONE listener also serves `/tools/*` -- the delegated-token
tool leg a stock workload is never handed -- and a first cut forwarded the
route-decoded remainder, so `/llm/../tools/x` (and its `%2e%2e`, `x/../..`,
`./..` spellings) reached it (R HIGH-1, PR #21; httpx and curl normalise `..`
client-side, which is why only a raw socket shows it). With no model proxy to
forward to, `/llm/*` answers 503 by name rather than a connection refused the
workload would report as its own network fault; a dead upstream is a 502.
Bodies are bounded (ANDYUR_LLM_MAX_BODY_BYTES, the same cap as the sidecar's
own /llm) and streamed, never buffered whole.

OBSERVED (observability-exit-criteria.md 1-3, 5; production-gaps row 21). This
hop is the one place the platform sees a stock workload's model calls, and
ADR-011 D8 says it stays observed -- so every request here is a SERVER span in
the RUN'S trace (`ObservedASGI` with the run record's traceparent as a trusted,
fixed parent; the workload's own `traceparent`/`tracestate`/`baggage` are
never read as identity and are dropped before the forward, and the front's
own span context is injected upstream instead). Every decision carries its
reason BY NAME: `andyur.decision` is `forwarded` or `refused`, `andyur.refusal`
is the `modelpolicy.Refusal` code the error body carries too. Untrusted values
on the span (the path, a model name) are redacted and bounded
(`otel.safe_attribute`); readiness probes are metrics-only, never a span.
Metrics: `andyur.execfront.decisions` {outcome, refusal} and the capped
resource, `andyur.execfront.request_bytes`. Telemetry never changes a control's
outcome: every recording call is wrapped so an exporter failure cannot alter a
response.

Same shape as ToolService and ModelProxy: a daemon thread hosting uvicorn, a
start() that blocks until the socket is up, a stop() that ends with the run.
"""

from __future__ import annotations

import os
import threading
from urllib.parse import unquote

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

# The same hop-by-hop and credential hygiene as the model proxy's own hop: these
# headers describe the workload-to-front connection and mean nothing on the
# front-to-proxy one, and the workload's throwaway model key is dropped here
# exactly as the proxy would drop it before injecting the real credential.
from .modelproxy import _DROP_REQ, _DROP_RESP
from .. import modelpolicy, otel
from .. import config

SERVICE_NAME = "andyur-runner"
OPERATION = "execfront"
READY_PATH = "/ready"
LLM_PREFIX = "/llm"
# The same bound the sidecar's own /llm enforces (proxy/app.py _LLM_MAX_BODY):
# a stock workload's own model calls, so a self-DoS class, but "captured cannot
# mean unbounded" is the rule and the proxy Pod has 1 GiB.
MAX_BODY_BYTES = int(os.environ.get("ANDYUR_LLM_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
_DOT_SEGMENTS = frozenset({".", ".."})
# Trace identity the WORKLOAD sends is not identity: the run's trace comes from
# the run record (the front's fixed parent), never from the caller.
_DROP_TRACE = frozenset({"traceparent", "tracestate", "baggage"})


def forward_path(raw_path: bytes) -> str | None:
    """The upstream path for one request, decided on the RAW path, or None to refuse.

    Starlette matched the route on the DECODED, normalised path, which is not
    what the upstream will see: it receives what is forwarded. So the decision
    is made on the bytes the client sent -- a literal `/llm` prefix (not a
    percent-encoded spelling of it), then segments of which none is empty and
    none decodes to `.` or `..` (one and two levels of percent-decoding, so
    `%2e%2e` and `%252e%252e` are both refused). The accepted remainder is
    returned verbatim, prefix stripped, so the upstream sees exactly the
    client's segments and never a resolved one.
    """
    try:
        raw = raw_path.decode("ascii")
    except UnicodeDecodeError:
        return None
    if raw == LLM_PREFIX:
        return "/"
    if not raw.startswith(LLM_PREFIX + "/"):
        return None
    rest = raw[len(LLM_PREFIX):]
    for segment in rest.split("/")[1:]:
        if not segment:
            return None
        for decoded in (unquote(segment), unquote(unquote(segment))):
            # A segment that decodes to a dot segment, or that CONTAINS a
            # separator or a dot-dot once decoded (`a%2Fb`, `..%5C`, `..;`),
            # is refused whole: what the upstream would make of it is not
            # this front's to guess (R LOW, PR #21 round 2).
            if decoded in _DOT_SEGMENTS or ".." in decoded or "/" in decoded or "\\" in decoded:
                return None
    return rest


def _route_of(raw_path: bytes) -> str:
    """The request's route from the CLOSED vocabulary, never the caller's text:
    an allow-listed model call by name, or one of the two ways it is not one."""
    path = forward_path(raw_path)
    if path is None:
        return "refused-path"
    clean = path.split("?", 1)[0]
    return clean if clean in modelpolicy.FRONT_LLM_PATHS else "not-a-model-call"


def _span():
    from opentelemetry import trace
    return trace.get_current_span()


def _observe(span, **attributes) -> None:
    """Attributes on the request's span; a telemetry failure changes nothing."""
    try:
        for key, value in attributes.items():
            if value is not None:
                span.set_attribute(key, value)
    except Exception:
        pass


def _decided(span, outcome: str, refusal: str = "none", *, request_bytes: int | None = None,
             extra: dict | None = None) -> None:
    """One decision, by name, on the span AND the counter."""
    _observe(span, **{"andyur.decision": outcome, "andyur.refusal": refusal, **(extra or {})})
    otel.try_record_metric(SERVICE_NAME, "andyur.execfront.decisions", 1,
                           andyur__outcome=("success" if outcome == "forwarded" else "denied"),
                           andyur__refusal=refusal)
    if request_bytes is not None:
        otel.try_record_metric(SERVICE_NAME, "andyur.execfront.request_bytes", request_bytes)


def _refuse(span, refusal: modelpolicy.Refusal, *, request_bytes: int | None = None,
            extra: dict | None = None) -> Response:
    _decided(span, "refused", refusal.code, request_bytes=request_bytes, extra=extra)
    return JSONResponse(refusal.body(), status_code=refusal.status)


def build_app(upstream: str | None, enforced_model: str | None = None, *,
              require_model: bool = False, run_id: str | None = None,
              agent: str | None = None) -> Starlette:
    client = (httpx.AsyncClient(base_url=upstream, timeout=600.0)
              if upstream else None)
    identity = {"andyur.run_id": run_id, "andyur.agent": agent,
                "andyur.model.granted": enforced_model or "",
                "andyur.external": True}

    async def ready(request: Request) -> Response:
        return JSONResponse({"ready": True, "model_proxy": upstream is not None})

    async def llm(request: Request) -> Response:
        span = _span()
        _observe(span, **identity)
        raw_path = request.scope.get("raw_path") or request.url.path.encode()
        # The workload's raw path is UNTRUSTED FREE TEXT and never becomes an
        # attribute (R on PR #25): scrubbing shapes out of it is a losing race,
        # so the span carries the closed ROUTE vocabulary and two numbers
        # instead -- which is what an operator reads anyway ("which model call,
        # how long a path"), and neither can carry a secret.
        _observe(span, **{"andyur.execfront.route": _route_of(raw_path),
                          "andyur.execfront.path_bytes": len(raw_path),
                          "andyur.execfront.path_segments": raw_path.count(b"/")})
        path = forward_path(raw_path)
        if path is None:
            return _refuse(span, modelpolicy.Refusal(
                "path_refused", 400,
                "path refused: only literal segments under /llm are forwarded "
                "(no dot segments, no empty segments)"))
        # THE POLICY, before anything reaches an upstream: only the model-call
        # endpoints, only POST -- the model leg's listing, management and fetch
        # surface (Ollama's /api/tags, /api/delete, /api/pull, ...) is not a
        # run's business (R HIGH-1, PR #22). Shared with the api-mode sidecar.
        refused = modelpolicy.path_refusal(request.method, path, modelpolicy.FRONT_LLM_PATHS)
        if refused is not None:
            return _refuse(span, refused)
        # h11 has already refused a non-numeric Content-Length (400), so the
        # only question left is the bound.
        declared = request.headers.get("content-length")
        if declared and int(declared) > MAX_BODY_BYTES:
            return _refuse(span, modelpolicy.Refusal(
                "body_too_large", 413, "request body exceeds the per-run model call limit"),
                request_bytes=int(declared))
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return _refuse(span, modelpolicy.Refusal(
                    "body_too_large", 413, "request body exceeds the per-run model call limit"),
                    request_bytes=size)
            chunks.append(chunk)
        body = b"".join(chunks)
        # The model pin: every request names the model this run was granted
        # (services.model.name), or it is refused by name, never rewritten.
        # Decided BEFORE the upstream is consulted, like the path policy: with
        # no model leg the refusal is still 403, not "no proxy" (the k3s gate
        # observes exactly that distinction).
        body, pinned = modelpolicy.validate_model_request(
            body, enforced_model, require_model=require_model)
        if pinned is not None:
            return _refuse(span, pinned, request_bytes=size,
                           extra={"andyur.model.requested": _requested_model(chunks)})
        if client is None:
            return _refuse(span, modelpolicy.Refusal(
                "no_model_proxy", 503, "this run has no model proxy to forward to"),
                request_bytes=size)
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in _DROP_REQ and k.lower() not in _DROP_TRACE}
        # The RUN's trace identity goes upstream, never the workload's.
        try:
            otel.inject_traceparent(headers, span)
        except Exception:
            pass
        upstream_req = client.build_request(
            request.method, path, headers=headers, content=body,
            params=request.query_params)
        try:
            resp = await client.send(upstream_req, stream=True)
        except httpx.HTTPError as exc:
            return _refuse(span, modelpolicy.Refusal(
                "upstream_unreachable", 502,
                f"model proxy unreachable ({type(exc).__name__})"), request_bytes=size)
        _decided(span, "forwarded", request_bytes=size,
                 extra={"gen_ai.request.model": enforced_model or "",
                        "http.upstream.status_code": resp.status_code})

        async def body_stream():
            try:
                async for chunk in resp.aiter_bytes():
                    yield chunk
            finally:
                await resp.aclose()

        return StreamingResponse(
            body_stream(), status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()
                     if k.lower() not in _DROP_RESP})

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    return Starlette(routes=[
        Route(READY_PATH, endpoint=ready, methods=["GET"]),
        Route(LLM_PREFIX, endpoint=llm, methods=methods),
        Route(LLM_PREFIX + "/{path:path}", endpoint=llm, methods=methods),
    ])


def _requested_model(chunks: list[bytes]) -> str | None:
    """The model a REFUSED request named, for the span only: redacted and
    bounded like every untrusted value; None when the body named none."""
    import json
    try:
        parsed = json.loads(b"".join(chunks) or b"null")
    except ValueError:
        return None
    if isinstance(parsed, dict):
        for key, value in parsed.items():
            if isinstance(key, str) and key.casefold() == "model":
                return otel.safe_attribute(value)
    return None


def observed_app(upstream: str | None, enforced_model: str | None = None, *,
                 require_model: bool = False, run_id: str | None = None,
                 agent: str | None = None, origin_trace: str | None = None):
    """The front's ASGI app inside the platform's server instrumentation."""
    return otel.ObservedASGI(
        build_app(upstream, enforced_model, require_model=require_model,
                  run_id=run_id, agent=agent),
        service_name=SERVICE_NAME, operation=OPERATION,
        parent_traceparent=origin_trace)


class ExecFront:
    """The serve-only sidecar's proxy-port listener, for the life of one run."""

    def __init__(self, upstream: str | None, host: str = "127.0.0.1",
                 port: int = 0, enforced_model: str | None = None, *,
                 require_model: bool = False, run_id: str | None = None,
                 agent: str | None = None, origin_trace: str | None = None):
        self._server = uvicorn.Server(uvicorn.Config(
            observed_app(upstream, enforced_model, require_model=require_model,
                         run_id=run_id, agent=agent, origin_trace=origin_trace),
            host=host, port=port, log_level="warning", loop="asyncio", timeout_graceful_shutdown=config.THREAD_SERVER_GRACEFUL_SHUTDOWN_SECONDS))
        self._thread: threading.Thread | None = None
        self._host = host

    def start(self) -> str:
        """Start serving and return the base URL the front answers on."""
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("the exec/v1 front failed to start")
            threading.Event().wait(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://{self._host}:{port}"

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)

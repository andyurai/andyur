"""The per-run sidecar's HTTP listener.

A thin Starlette app over async httpx. It does no HTTP parsing of its own: the
framework reads the agent's request, and httpx makes the upstream call. The
sidecar's job is only the three things a proxy product cannot do for us -- strip
the agent's credentials, mint the delegated token, and present the run's mTLS
cert -- and even those lean on `andyur.identity` and `asclient`.

    POST /tools/<name>/...  strip -> exchange (cached) -> Bearer -> tool, over
                            mTLS when the reach_url is https (PROD requires it)
    POST /llm/...           strip -> service key -> shared LLM gateway (LiteLLM)
    anything else           404, so the agent cannot reach an undeclared upstream

Everything external is INJECTED (the exchange callable, the tool client factory,
the gateway client) so the whole flow is testable without SPIRE, an AS, or a real
tool. The defaults wire the real ones.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import ssl
from typing import Callable, Mapping

import anyio
import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route as _StarletteRoute

from .. import mcpwire, otel
from . import sidecar

log = logging.getLogger(__name__)

# Hop-by-hop headers are per-connection and must not be forwarded (RFC 9110
# sec 7.6.1). httpx sets its own, and passing the agent's would corrupt framing.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})
_UNTRUSTED_TRACE = frozenset({"traceparent", "tracestate", "baggage"})
# ONE policy with the exec/v1 front (andyur/modelpolicy.py): the allowed
# endpoints and the model pin are shared, not copied.
from .. import modelpolicy as _modelpolicy  # noqa: E402
_LLM_PATHS = _modelpolicy.SIDECAR_LLM_PATHS
_LLM_MAX_BODY = int(os.environ.get("ANDYUR_LLM_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
_LLM_MAX_CALLS = int(os.environ.get("ANDYUR_LLM_MAX_CALLS_PER_RUN", "100"))
_LLM_MAX_CONCURRENT = int(os.environ.get("ANDYUR_LLM_MAX_CONCURRENT", "4"))
_TOOL_MAX_CALLS = int(os.environ.get("ANDYUR_TOOL_MAX_CALLS_PER_RUN", "500"))
_TOOL_MAX_CONCURRENT = int(os.environ.get("ANDYUR_TOOL_MAX_CONCURRENT", "8"))
# A tools/list response is BUFFERED, not streamed, because the whole catalog has
# to be read before it can be filtered. Every other tool response still streams
# per ADR-003; a bounded catalog is not a completion stream. The bound exists
# because buffering an unbounded upstream body is the denial-of-service the rest
# of this file is careful to avoid.
_TOOLS_LIST_MAX_BYTES = int(
    os.environ.get("ANDYUR_TOOLS_LIST_MAX_BYTES", str(4 * 1024 * 1024)))


def _clean(headers: Mapping[str, str]) -> dict[str, str]:
    """Strip the agent's credentials (S1/S2) AND the hop-by-hop headers."""
    stripped = sidecar.strip_inbound(headers)
    return {k: v for k, v in stripped.items()
            if k.lower() not in _HOP_BY_HOP | _UNTRUSTED_TRACE}


async def _bounded_body(request: Request, limit: int) -> bytes | None:
    """Read an untrusted request without allowing chunked input to exceed limit."""
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > limit:
                return None
        except ValueError:
            return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _default_exchange(**kw):
    # Imported lazily so the proxy package does not pull the server package at
    # import time, and so tests inject a fake without it being reached.
    from ..server import asclient
    return asclient.exchange(**kw)


# Sidecar-lifetime connection pools, NOT a client per request. Explicit timeouts
# so a slow or dribbling upstream cannot pin the run's event loop (the toolproxy
# per-operation-timeout bug class), and limits so a chatty agent cannot exhaust
# file descriptors. httpx keys its keep-alive pool BY HOST, so a single client
# already gives a per-target pool (many concurrent connections per tool), not one
# serialized physical connection. Created once in build_app and closed on sidecar
# teardown -- the tool client holds the run's X509-SVID, so its close is a
# credential teardown, not just cleanup.
_LIMITS = httpx.Limits(max_connections=64, max_keepalive_connections=16)
_TOOL_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0)
# The model leg tolerates a longer read: a completion can take a while. (Real SSE
# streaming, which bounds this per-chunk instead, is the follow-up on this leg.)
_LLM_TIMEOUT = httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=5.0)


def _default_tool_client(identity: sidecar.RunIdentity) -> httpx.AsyncClient:
    """An mTLS-capable client holding the run's X509-SVID. This is the S5 leg:
    on an https reach_url the run PRESENTS its own cert on the wire. Whether
    that stops cross-run replay depends on the tool VERIFYING it: sender-binding
    is a two-party property and no Andyur tool PEP checks the peer cert against
    the token yet (see docs/threat-model.md), so
    today the delegated token remains a bearer token bounded by audience and
    TTL. On an http reach_url (dev only; production refuses it at tool-partition
    time) no handshake happens and the cert is carried but never presented.
    Pooled and reused for the sidecar's lifetime.

    NB: check_hostname is off (SPIFFE identifies by URI SAN, not DNS) and the
    peer is trusted by trust-domain-bundle membership, not by a pinned tool
    SPIFFE ID -- the same posture as identity.client_tls. Pinning the tool's
    expected peer identity is the tracked hardening on this leg."""
    mat = identity.mtls_material()
    # An explicit SSLContext, not httpx's cert=/verify= shorthand: on current
    # httpx the (cert=tuple, verify=path) combination completes the handshake
    # WITHOUT presenting the client certificate, which silently turns mTLS
    # into one-way TLS -- the live-socket suite pins the presented-cert
    # property. check_hostname off for the same reason as identity.client_tls:
    # SPIFFE verifies by URI SAN, not hostname; the bundle is the boundary.
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=mat["bundle"])
    ctx.check_hostname = False
    ctx.load_cert_chain(certfile=mat["cert"], keyfile=mat["key"])
    return httpx.AsyncClient(verify=ctx, timeout=_TOOL_TIMEOUT, limits=_LIMITS)


def _default_gateway_client() -> httpx.AsyncClient:
    """Pooled client to the shared LLM gateway, sidecar-lifetime."""
    return httpx.AsyncClient(timeout=_LLM_TIMEOUT, limits=_LIMITS)


def build_app(
    *,
    router: sidecar.Router,
    identity: sidecar.RunIdentity,
    scope,
    pin,
    gateway_url: str,
    llm_master_key: str = "",
    enforced_model: str | None = None,
    trusted_traceparent: str | None = None,
    exchange_fn: Callable[..., Mapping] | None = None,
    tool_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    gateway_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    cache: sidecar.TokenCache | None = None,
    brokered_credential_fn: Callable[[str], Mapping[str, str]] | None = None,
    brokered_credential_close: Callable[[], None] | None = None,
    dpop_holder=None,
) -> Starlette:
    exchange_fn = exchange_fn or _default_exchange
    tool_client_factory = tool_client_factory or (lambda: _default_tool_client(identity))
    gateway_client_factory = gateway_client_factory or _default_gateway_client
    cache = cache or sidecar.TokenCache()
    # A streamed response is consumed by Starlette in a child task, so release
    # is deliberately not task-affine. CapacityLimiter is borrower/task-affine;
    # Semaphore represents the actual resource here: in-flight upstream streams.
    llm_limiter = anyio.Semaphore(_LLM_MAX_CONCURRENT)
    tool_limiter = anyio.Semaphore(_TOOL_MAX_CONCURRENT)
    llm_calls = 0
    tool_calls = 0
    sidecar_tracer = otel.setup_tracing("andyur-sidecar")

    # ONE pooled client per leg, built now and reused for every request, closed
    # on sidecar teardown. Not per request: opening/closing a client (and, for
    # tools, a fresh mTLS handshake) on every call is the lifecycle the operator and
    # the registry session flagged.
    tool_client = tool_client_factory() if router.has_tools else None
    gateway_client = gateway_client_factory()

    async def handle(request: Request) -> Response:
        nonlocal llm_calls, tool_calls
        route = router.classify(request.url.path)
        body = await _bounded_body(request, _LLM_MAX_BODY)
        if body is None:
            return Response("sidecar: request body exceeds the per-run limit",
                            status_code=413)
        clean_headers = _clean(request.headers)

        if route.kind == "tool":
            tool = route.tool
            prefix = f"/tools/{tool.name}"
            remainder = request.url.path[len(prefix):] or "/"
            if remainder != tool.path or request.method not in (
                    "POST", "GET", "DELETE"):
                return Response(
                    f"sidecar: {tool.name} is served only at its declared "
                    "MCP endpoint", status_code=404)

            # PER-TOOL AUTHORITY. Until this existed the sidecar leg authorized
            # by AUDIENCE alone, so an enumerated binding granted every tool its
            # upstream happened to expose -- while the runtime protocol promised
            # third-party agent authors that "the list is never wider than the
            # law".
            #
            # The decision is the SERVER'S, sealed into this run's tool
            # descriptor by registry.authority_for + mcpwire.permitted_tools --
            # the same computation the mint path and the dataplane use. The
            # sidecar enforces it and does not reconstruct it.
            mcp_method = None
            permitted: set[str] | None = None
            if tool.permitted_tools is not None:
                kind = mcpwire.mcp_body_kind(body)
                if kind in ("array", "invalid"):
                    # A BATCH can carry a tools/call that single-message parsing
                    # cannot surface, and an unparseable body names no method at
                    # all. Either would skip the per-tool check entirely, so an
                    # enumerated binding refuses both rather than authorize
                    # something it could not read. MCP 2025-06-18 removed
                    # batching, so refusing arrays is protocol-correct.
                    # No release() here: this refusal happens BEFORE the
                    # concurrency slot is taken, which is the right order --
                    # an unauthorized call should not consume one.
                    return Response(
                        f"sidecar: {tool.name} is enumerated per tool; a "
                        f"{kind} JSON-RPC body cannot be authorized",
                        status_code=403)
                # The server already intersected the binding's grants with THIS
                # run's narrowed authority (registry.authority_for), so there is
                # nothing left to decide here. Recomputing would be a second
                # source of truth for one fact, and the previous attempt at it
                # passed `{"actions": None}`, which discards the narrowing.
                permitted = set(tool.permitted_tools)
                if kind == "empty":
                    # A body-less leg is the standalone GET SSE stream or the
                    # DELETE that ends a session. GET can carry a REPLAYED
                    # tools/list result when the client resumes with
                    # Last-Event-ID, and that reply would reach the agent
                    # unfiltered because there is no request body to classify.
                    # An enumerated binding refuses the resumable read rather
                    # than serve a menu it cannot filter.
                    if request.method == "GET":
                        return Response(
                            f"sidecar: {tool.name} is enumerated per tool; the "
                            "resumable event stream cannot be filtered",
                            status_code=403)
                if kind == "object":
                    mcp_method, called = mcpwire.parse_mcp(body)
                    # `method is None` is a JSON-RPC RESPONSE from the client
                    # -- what a conforming MCP client sends back when the SERVER
                    # made a request of it (sampling/createMessage, roots/list).
                    # It names no method and invokes nothing, and the dataplane
                    # admits it. Refusing it here made two components disagree
                    # about the same protocol, which is worse than either answer.
                    if (mcp_method is not None
                            and mcp_method not in mcpwire.MCP_TOOL_SESSION_METHODS):
                        # Every other JSON-RPC method reaches the same upstream
                        # over the same credential, so an open vocabulary is a
                        # side door around the reviewed grant: resources/read
                        # and prompts/get read server state and run server-side
                        # templates no tool grant ever mentioned.
                        log.warning(
                            "tool %s: REFUSED method %r, outside the enumerated "
                            "binding's method vocabulary", tool.name, mcp_method)
                        return Response(
                            f"sidecar: {mcp_method!r} is not permitted on "
                            f"{tool.name}, which is enumerated per tool",
                            status_code=403)
                    if mcp_method == "tools/call" and called not in permitted:
                        log.warning(
                            "tool %s: REFUSED tools/call %r, not in the "
                            "binding's granted tools", tool.name, called)
                        return Response(
                            f"sidecar: {called!r} is not a granted tool on "
                            f"{tool.name}", status_code=403)
            if tool_calls >= _TOOL_MAX_CALLS:
                return Response("sidecar: per-run tool call budget exhausted",
                                status_code=429)
            try:
                tool_limiter.acquire_nowait()
            except anyio.WouldBlock:
                return Response("sidecar: too many concurrent tool calls",
                                status_code=429)
            tool_calls += 1
            release = _release_once(tool_limiter.release)
            use_dpop = False
            # The binding's declared credential header names, lowercased. Empty
            # for a managed/delegated leg, which injects only Authorization.
            declared_headers: set[str] = set()
            # The registry selects exactly one credential mode. There is no
            # runtime downgrade from failed delegation to a shared credential.
            # and bounded; run it off the event loop so a slow AS does not stall
            # every other in-flight call on this sidecar.
            try:
                if tool.credential_mode == "brokered":
                    if brokered_credential_fn is None or not tool.credential_ref:
                        raise RuntimeError("brokered credential source is unavailable")
                    credential_headers = await anyio.to_thread.run_sync(
                        lambda: brokered_credential_fn(tool.credential_ref))
                    # THE ENFORCEMENT POINT. The vault holds transport material;
                    # it does not decide what a binding may set. A secret that
                    # returns a header this binding never declared is refused,
                    # so compromising the credential store cannot widen which
                    # headers reach the vendor -- only which values do.
                    declared = {name.lower()
                                for name in (tool.credential_headers or ())}
                    declared_headers = declared
                    offered = {name.lower() for name in credential_headers}
                    if not declared:
                        raise RuntimeError(
                            "binding declares no credential headers, so its "
                            "brokered credential can set none")
                    if not offered <= declared:
                        raise RuntimeError(
                            "brokered credential returned header(s) this binding "
                            f"does not declare: {sorted(offered - declared)}")
                elif tool.credential_mode == "managed":
                    token = await anyio.to_thread.run_sync(
                        lambda: sidecar.delegated_token(
                            identity, tool, scope, pin, exchange_fn, cache,
                            binding=(dpop_holder.jkt if dpop_holder else ""),
                            exchange_extra=({"dpop_key": dpop_holder.token_endpoint_key()}
                                            if dpop_holder else None)))
                    if dpop_holder is None:
                        credential_headers = {"Authorization": f"Bearer {token}"}
                    else:
                        credential_headers = {"Authorization": f"DPoP {token}"}
                        use_dpop = True
                else:
                    raise RuntimeError("unknown credential mode")
            except BaseException as exc:
                release()
                if not isinstance(exc, Exception):
                    raise
                # Fail closed and name the control: no token means no call, never
                # a call without one.
                log.error("tool %s: exchange failed, WITHHELDING the call: %s: %s",
                          tool.name, type(exc).__name__, exc)
                return Response(
                    f"sidecar could not obtain an approved credential for {tool.name}",
                    status_code=502)
            # The upstream URL is the route's DECLARED path, never the agent's
            # remainder: splicing the remainder let a compromised agent present
            # the run's delegated token and mTLS cert to any path on the tool's
            # host (and misrouted every tool not served at exactly /mcp, since
            # the agent config used to hardcode that). The agent's config points
            # at /tools/<name><declared path>; anything else is refused, and the
            # methods are MCP's own (streamable HTTP: POST requests, GET for the
            # SSE channel, DELETE to end the session) -- confinement the
            # agentgateway path gets from its MCP-aware backend.
            url = f"{tool.scheme}://{tool.host}:{tool.port}{tool.path}"
            # clean_headers strips the agent's KNOWN credential headers, but a
            # binding may declare any name, so a header this binding brokers can
            # still be sitting in there under whatever casing the agent chose.
            # Merging on top would not replace it: dict keys are case-SENSITIVE
            # while HTTP header names are not, so `dd-api-key` from the agent and
            # `DD-API-KEY` from the vault are two entries, and both go on the
            # wire as one comma-joined value. The vendor then sees the agent's
            # forgery inside the credential it trusts.
            #
            # So drop every brokered name case-insensitively FIRST. A credential
            # replaces; it never appends to something the agent supplied.
            # DROP EVERY DECLARED NAME, not merely the ones the vault answered
            # with. `offered <= declared` deliberately admits a strict subset --
            # a smaller credential is a narrowing, not an escalation -- but a
            # declared header the vault did NOT return is one _clean does not
            # know about, so it would survive from the agent's request and reach
            # the vendor beside the real credential. Datadog would then see a
            # two-header credential half of which the agent chose.
            brokered = declared_headers | {n.lower() for n in credential_headers}
            out = {k: v for k, v in clean_headers.items()
                   if k.lower() not in brokered}
            out.update(credential_headers)
            if use_dpop:
                out["DPoP"] = dpop_holder.resource_proof(
                    request.method, url, token)
            # The agent's trace headers were stripped by _clean(). Start a
            # sidecar-owned CLIENT span under the authenticated run context and
            # forward only that generated identity to the enterprise service.
            # The span remains open until the streamed response is consumed.
            from opentelemetry.trace import SpanKind
            operation = {"POST": "tool.request", "GET": "tool.stream",
                         "DELETE": "tool.session"}[request.method]
            span = sidecar_tracer.start_span(
                f"{operation} {tool.name}",
                context=otel.context_from(trusted_traceparent),
                kind=SpanKind.CLIENT,
                attributes={
                    "andyur.egress.type": "tool",
                    "andyur.tool.name": tool.name,
                    "server.address": tool.host,
                    "server.port": tool.port,
                    "http.request.method": request.method,
                    "url.path": tool.path,
                    "peer.service": tool.name,
                    "andyur.external": True,
                },
            )
            otel.inject_traceparent(out, span)
            if mcp_method == "tools/list" and permitted is not None:
                return await _proxy_filtered_tools_list(
                    tool_client, request.method, url, out, body,
                    permitted=permitted, tool_name=tool.name,
                    span=span, on_close=release)
            return await _proxy_stream(
                tool_client, request.method, url, out, body, span=span,
                on_close=release)

        if route.kind == "llm":
            # The shared LLM gateway (LiteLLM) speaks native Anthropic Messages.
            # The sidecar holds the gateway's SERVICE credential (its master key)
            # and injects it as `x-api-key`; the agent never holds it, and the
            # run's user token (T0) is NOT the gateway's authority -- forwarding
            # T0 here would make a run credential a provider credential.
            prefix = "/llm"
            remainder = request.url.path[len(prefix):] or "/"
            path_refused = _modelpolicy.path_refusal(request.method, remainder, _LLM_PATHS)
            if path_refused is not None:
                _refused_on_span(path_refused)
                return Response(f"sidecar: {path_refused.code}: LLM endpoint is not allowed",
                                status_code=path_refused.status)
            if llm_calls >= _LLM_MAX_CALLS:
                return Response("sidecar: per-run LLM call budget exhausted",
                                status_code=429)
            body, refusal = _validated_model_body(body, enforced_model)
            if refusal is not None:
                return refusal
            url = gateway_url.rstrip("/") + remainder
            out = {**clean_headers, "x-api-key": llm_master_key}
            if trusted_traceparent:
                # Agent-provided trace identity was stripped by _clean(). Replace
                # it with the runner's authenticated run context so LiteLLM joins
                # the real trace instead of accepting an attacker-chosen trace.
                out["traceparent"] = trusted_traceparent
            try:
                llm_limiter.acquire_nowait()
            except anyio.WouldBlock:
                return Response("sidecar: too many concurrent LLM calls",
                                status_code=429)
            llm_calls += 1
            release = _release_once(llm_limiter.release)
            return await _proxy_stream(
                gateway_client, request.method, url, out, body,
                on_close=release)

        return Response("no such route on the sidecar", status_code=404)

    @contextlib.asynccontextmanager
    async def _lifespan(_app):
        # Close both pools on teardown. The tool client holds the run's X509-SVID
        # material, so this ends the run's ability to present it -- a credential
        # teardown, not just cleanup. Never raises: it runs in the sidecar's
        # fail-closed shutdown path.
        try:
            yield
        finally:
            for client in (tool_client, gateway_client):
                if client is None:
                    continue
                try:
                    await client.aclose()
                except Exception:                          # noqa: BLE001
                    pass
            if brokered_credential_close is not None:
                try:
                    brokered_credential_close()
                except Exception:                          # noqa: BLE001
                    pass
            if dpop_holder is not None:
                try:
                    dpop_holder.close()
                except Exception:                          # noqa: BLE001
                    pass
            try:
                cache.close()
            except Exception:                              # noqa: BLE001
                pass

    return Starlette(
        routes=[_StarletteRoute("/{path:path}", handle,
                                methods=["GET", "POST", "PUT", "DELETE", "PATCH"])],
        lifespan=_lifespan,
    )


def _validated_model_body(body: bytes, enforced_model: str | None
                          ) -> tuple[bytes, Response | None]:
    """The body to forward (the VALIDATED object, re-serialised) or a refusal.
    One policy with the exec/v1 front: modelpolicy.validate_model_request."""
    canonical, refusal = _modelpolicy.validate_model_request(body, enforced_model)
    if refusal is None:
        return canonical, None
    _refused_on_span(refusal)
    return body, Response(f"sidecar: {refusal.code}: {refusal.message}", status_code=refusal.status)


def _refused_on_span(refusal) -> None:
    """The refusal by name on the request's span (ObservedASGI's); the same
    code the body carries. Telemetry never changes the response."""
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        span.set_attribute("andyur.decision", "refused")
        span.set_attribute("andyur.refusal", refusal.code)
    except Exception:
        pass


def _enforce_model(body: bytes, enforced_model: str | None) -> Response | None:
    """Refuse a model the run is not entitled to. Returns a refusal Response, or
    None when the request may proceed.

    The manifest/registry model is immutable authority: a run may call ONLY the
    model its manifest selected. The agent's request body names a model, and a
    prompt-injected or tampered agent could name another (a more capable, more
    expensive, or unapproved one). So a body whose `model` is absent or different
    from the enforced one is REFUSED here, before the gateway is ever reached --
    not silently rewritten, because a rewrite hides that the run tried. When no
    model is enforced (a legacy/unbound run) the body passes through unchanged.
    """
    refusal = _modelpolicy.model_refusal(body, enforced_model)
    if refusal is None:
        return None
    _refused_on_span(refusal)
    return Response(f"sidecar: {refusal.code}: {refusal.message}", status_code=refusal.status)


async def _proxy_filtered_tools_list(
        client: httpx.AsyncClient, method: str, url: str,
        headers: Mapping[str, str], body: bytes, *,
        permitted: set[str], tool_name: str,
        span=None, on_close=None) -> Response:
    """Forward a tools/list and return only the tools this run may call.

    The one place the sidecar buffers a tool response. It has to: the catalog
    cannot be filtered until it has been read, and handing the agent a menu
    wider than its authority is the defect this closes.

    Fail closed twice over. An oversized catalog is refused rather than
    truncated, because a truncated JSON document is not a smaller menu, it is an
    unparseable one. An unreadable body riding a tools/list exchange is refused
    rather than passed through, because passing it through is exactly the
    unfiltered menu.
    """
    from opentelemetry.trace import Status, StatusCode
    try:
        # httpx merges its own `accept-encoding: gzip, deflate, br, zstd` into a
        # request we never set, and aiter_raw() yields UNDECODED bytes -- so any
        # MCP server behind nginx/CloudFront/GZipMiddleware answered a
        # permanent 502 here. The dataplane already learned this and pins
        # identity for the same reason; the fix had not been carried over.
        headers = {**headers, "accept-encoding": "identity"}
        req = client.build_request(method, url, headers=headers, content=body)
        upstream = await client.send(req, stream=True)
        try:
            raw = bytearray()
            async for chunk in upstream.aiter_raw():
                raw += chunk
                if len(raw) > _TOOLS_LIST_MAX_BYTES:
                    break
            if len(raw) > _TOOLS_LIST_MAX_BYTES:
                log.error("tool %s: tools/list response exceeds %d bytes; "
                          "REFUSING rather than serving a truncated menu",
                          tool_name, _TOOLS_LIST_MAX_BYTES)
                return Response(
                    f"sidecar: {tool_name} tools/list response is too large "
                    "to authorize", status_code=502)
        finally:
            await upstream.aclose()

        if span is not None:
            span.set_attribute("http.response.status_code", upstream.status_code)

        # A non-2xx upstream names no tools; pass its status through untouched
        # rather than trying to filter an error document.
        passthrough = {k: v for k, v in upstream.headers.items()
                       if k.lower() not in _HOP_BY_HOP
                       and k.lower() != "content-encoding"}
        if upstream.status_code >= 300:
            return Response(bytes(raw), status_code=upstream.status_code,
                            headers=passthrough)
        try:
            filtered = mcpwire.filter_tools_payload(bytes(raw), permitted)
        except (ValueError, RecursionError) as exc:
            # RecursionError, not just ValueError: 6 KB of nested arrays makes
            # the filter recurse past the limit, and it is not a ValueError, so
            # it escaped this handler and returned 500 instead of the designed
            # fail-closed 502. The MCP upstream is untrusted by the threat
            # model, so that was a 6 KB unhandled exception.
            log.error("tool %s: tools/list response is unreadable (%s); "
                      "WITHHOLDING it rather than serving it unfiltered",
                      tool_name, exc)
            return Response(
                f"sidecar: {tool_name} returned a tools/list body that cannot "
                "be authorized", status_code=502)
        # content-length is recomputed by Starlette from the FILTERED body, so
        # the upstream's is dropped above with the hop-by-hop set.
        return Response(filtered, status_code=upstream.status_code,
                        headers=passthrough)
    except BaseException as exc:
        if span is not None:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR))
        raise
    finally:
        if span is not None:
            span.end()
        if on_close is not None:
            on_close()


async def _proxy_stream(client: httpx.AsyncClient, method: str, url: str,
                        headers: Mapping[str, str], body: bytes, *,
                        span=None, on_close=None) -> StreamingResponse:
    """Forward the request and STREAM the response back as it arrives.

    ADR-003 requires tool and model responses to stream with backpressure and
    cancellation, not be buffered whole: an Anthropic SSE completion or a chunked
    MCP result must reach the agent as the upstream produces it. `send(stream=True)`
    keeps the POOLED client (it is not closed here); the upstream response is
    closed when the body is exhausted OR the agent disconnects (Starlette cancels
    the generator, and the `finally` releases the connection back to the pool).
    Hop-by-hop headers are dropped -- the sidecar's own connection sets its own.
    """
    from opentelemetry.trace import Status, StatusCode

    try:
        req = client.build_request(method, url, headers=headers, content=body)
        upstream = await client.send(req, stream=True)
        if span is not None:
            span.set_attribute("http.response.status_code", upstream.status_code)
            if upstream.status_code >= 500:
                span.set_status(Status(StatusCode.ERROR))
    except BaseException as exc:
        if span is not None:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR))
            span.end()
        if on_close is not None:
            on_close()
        raise

    async def _pump():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            try:
                try:
                    await upstream.aclose()
                finally:
                    if span is not None:
                        span.end()
            finally:
                if on_close is not None:
                    on_close()

    out_headers = {k: v for k, v in upstream.headers.items()
                   if k.lower() not in _HOP_BY_HOP}
    return StreamingResponse(
        _pump(), status_code=upstream.status_code, headers=out_headers,
        media_type=upstream.headers.get("content-type"))


def _release_once(release):
    """Return an idempotent permit release for competing cleanup paths."""
    released = False

    def done():
        nonlocal released
        if not released:
            released = True
            release()

    return done

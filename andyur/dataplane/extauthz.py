"""Andyur's ext_authz decision service for the composed data plane.

SPIKE (ADR-004). Envoy's ext_authz filter calls this per tool request. It is
the ONE thing Andyur owns on the request path: the authority decision, computed
in the SAME place the mint uses (`registry.authority_for`), never a second
copy. It does NOT terminate TLS, parse MCP, pool connections, or stream -- Envoy
does. On allow it returns the delegated token for Envoy to inject; on deny it
returns 403 and the tool is never reached.

Identity is PROVISIONED, not agent-supplied. A per-run Envoy knows which run it
is from its immutable launch and its per-run SVID; the untrusted agent must not
select that identity by presenting a bearer header (that both leaks the token
to the tool and lets the agent choose who it is). So this service is built for
ONE run (`run_agent`, `run_id`) and never reads a caller-supplied run token.

A managed decision REQUIRES an exchange coordinator: a managed call must never
proceed without a platform-obtained credential, so `exchange_fn` is mandatory
and `build_app` refuses to start without it.

Everything external is injected (the liveness check, the authority function,
the exchange callable) so the decision is testable without a database, SPIRE,
or an AS.
"""

from __future__ import annotations

import functools
import json
import logging
import math
import re
import threading
from dataclasses import dataclass

from typing import Any, Callable, Iterable

from ..mcpwire import (  # noqa: F401  (re-exported for existing callers)
    MCP_TOOL_SESSION_METHODS,
    filter_tools_payload,
    mcp_body_kind,
    parse_mcp,
    permitted_tools,
)

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from andyur import identity as workload_identity

log = logging.getLogger(__name__)

# The MCP methods a tool-enumerated binding admits: session lifecycle plus the
# tool surface itself. This is protocol vocabulary, not policy -- the POLICY
# (which tools, requiring which actions) is registry data. It exists because an
# `mcp_tools` grant is the operator's statement "this server is used for THESE
# tools"; letting resources/*, prompts/* or any future method family ride the
# same delegated credential would widen the reviewed grant through a side
# door. Bindings that do not enumerate tools keep the pre-existing
# audience-level posture and are not constrained by this set.# MCP_TOOL_SESSION_METHODS MOVED to andyur/mcpwire.py so the sidecar closes
# the same vocabulary. Re-exported above with the other shared decisions.

# The Lua filter's LAST-RESORT body when the decision service is unreachable
# (httpCall synthesizes a 5xx before /toolfilter runs). The normal fail-closed
# error is built by /toolfilter itself (`_unavailable`), which can carry the
# JSON-RPC id and SSE framing; this bare form is only for the case where that
# service could not be reached at all.
TOOLS_LIST_UNAVAILABLE = (
    b'{"jsonrpc":"2.0","id":null,"error":{"code":-32000,'
    b'"message":"tools/list filtering unavailable"}}')

# Upper bound on a tools/list body the decision service will parse and rewrite,
# matched to the Envoy listener's per_connection_buffer_limit_bytes. Above this
# the rewrite fails closed rather than buffering several copies of an
# adversarially large list.
MAX_TOOLS_LIST_BYTES = 4 * 1024 * 1024
MAX_BROKER_REQUEST_BYTES = 64 * 1024
MAX_BROKER_ACTIONS = 256
MAX_BROKER_ACTION_BYTES = 16 * 1024
MAX_BROKER_PIN_BYTES = 4096
MAX_BROKER_PIN_NODES = 256
MAX_BROKER_PIN_DEPTH = 8
DENY_ONLY_STATE_TIMEOUT_SECONDS = 0.25
DENY_ONLY_STATE_CONCURRENCY = 8
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class _DependencyCapacityExhausted(Exception):
    pass


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value} is forbidden")


def _utf8_len(value: str) -> int:
    try:
        return len(value.encode())
    except UnicodeEncodeError as exc:
        raise ValueError("authority pin contains invalid Unicode") from exc


def _validate_pin_structure(value: object) -> None:
    nodes = 0
    scalar_bytes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes, scalar_bytes
        nodes += 1
        if nodes > MAX_BROKER_PIN_NODES or depth > MAX_BROKER_PIN_DEPTH:
            raise ValueError("authority pin exceeds structural bounds")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > MAX_BROKER_PIN_BYTES:
                    raise ValueError("authority pin contains an invalid key")
                scalar_bytes += _utf8_len(key)
                if scalar_bytes > MAX_BROKER_PIN_BYTES:
                    raise ValueError("authority pin exceeds scalar bounds")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > MAX_BROKER_PIN_BYTES:
                raise ValueError("authority pin string exceeds scalar bounds")
            scalar_bytes += _utf8_len(item)
        elif item is None or isinstance(item, bool):
            pass
        elif isinstance(item, int):
            # Reject from bit length before decimal conversion can allocate a
            # representation larger than the whole pin budget.
            decimal_upper_bound = max(1, int(item.bit_length() * 0.30103) + 1)
            if decimal_upper_bound > MAX_BROKER_PIN_BYTES - scalar_bytes:
                raise ValueError("authority pin integer exceeds scalar bounds")
            scalar_bytes += len(str(item))
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("authority pin number must be finite")
            scalar_bytes += len(repr(item))
        else:
            raise ValueError("authority pin contains a non-JSON value")
        if scalar_bytes > MAX_BROKER_PIN_BYTES:
            raise ValueError("authority pin exceeds scalar bounds")

    visit(value, 0)


@dataclass(frozen=True)
class SealedAuthorityEnvelope:
    """Typed, previously verified broker input; never derived from a credential."""

    agent: str
    run_id: str
    expected_subject: str
    expected_actor: str
    audience: str
    actions: tuple[str, ...] | None
    resource_pin_json: str | None
    registry_sha256: str

    def __post_init__(self) -> None:
        for field in ("agent", "run_id", "expected_subject",
                      "expected_actor", "audience"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip() or len(value) > 2048:
                raise ValueError(f"sealed authority {field} must be non-empty and bounded")
        actor_agent, actor_run = workload_identity.parse_agent_run(
            self.expected_actor)
        if (actor_agent, actor_run) != (self.agent, self.run_id):
            raise ValueError(
                "sealed authority expected_actor must be the exact agent/run SPIFFE ID")
        if not isinstance(self.registry_sha256, str) \
                or not _SHA256.fullmatch(self.registry_sha256):
            raise ValueError("sealed authority registry_sha256 must be lowercase SHA-256")
        if self.actions is not None:
            if type(self.actions) is not tuple or any(
                    not isinstance(item, str) or not item.strip()
                    or item != item.strip() or len(item) > 256
                    for item in self.actions):
                raise ValueError("sealed authority actions must be unique bounded strings")
            if self.actions != tuple(sorted(set(self.actions))):
                raise ValueError("sealed authority actions must be unique bounded strings")
            if len(self.actions) > MAX_BROKER_ACTIONS or sum(
                    _utf8_len(item) for item in self.actions
            ) > MAX_BROKER_ACTION_BYTES:
                raise ValueError("sealed authority actions exceed the aggregate bound")
        if self.resource_pin_json is not None:
            if not isinstance(self.resource_pin_json, str) \
                    or _utf8_len(self.resource_pin_json) > MAX_BROKER_PIN_BYTES:
                raise ValueError("sealed authority resource pin must be bounded canonical JSON")
            try:
                value = json.loads(
                    self.resource_pin_json, parse_constant=_reject_json_constant)
                _validate_pin_structure(value)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError,
                    RecursionError) as exc:
                raise ValueError("sealed authority resource pin must be canonical JSON") from exc
            if not isinstance(value, dict) or json.dumps(
                    value, sort_keys=True, separators=(",", ":"),
                    allow_nan=False) != self.resource_pin_json:
                raise ValueError("sealed authority resource pin must be a canonical JSON object")


def _canonical_pin(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("current authority pin is not an object")
    _validate_pin_structure(value)
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if _utf8_len(encoded) > MAX_BROKER_PIN_BYTES:
        raise ValueError("current authority pin exceeds the encoded bound")
    return encoded


def _authority_matches(envelope: SealedAuthorityEnvelope, decision: dict[str, Any]) -> bool:
    actions = decision.get("actions")
    if actions is None:
        current_actions: object = None
    elif not isinstance(actions, list) or len(actions) > MAX_BROKER_ACTIONS \
            or any(not isinstance(item, str) or not item.strip()
                   or item != item.strip() or len(item) > 256 for item in actions) \
            or sum(_utf8_len(item) for item in actions) > MAX_BROKER_ACTION_BYTES:
        current_actions = object()
    else:
        current_actions = tuple(sorted(actions))
    return (decision.get("audience") == envelope.audience
            and current_actions == envelope.actions
            and _canonical_pin(decision.get("pin")) == envelope.resource_pin_json)


async def _bounded_request_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BROKER_REQUEST_BYTES:
            raise ValueError("broker request exceeds 64 KiB")
        body.extend(chunk)
    return bytes(body)


def build_deny_only_broker(
    *,
    envelope: SealedAuthorityEnvelope,
    authority_fn: Callable[..., dict[str, Any]] | None = None,
    liveness_fn: Callable[[str], bool] | None = None,
    identity_fn: Callable[[str], tuple[str, str]] | None = None,
    registry_digest_fn: Callable[[str, str], str] | None = None,
    state_fn: Callable[[], tuple[
        bool, tuple[str, str], str, dict[str, Any]]] | None = None,
    authz_path: str = "/authz",
) -> Starlette:
    """Construct the first production broker slice: verify state, always deny.

    There is deliberately no exchange callable and no credential output type.
    A request can prove that Envoy reached the per-run broker and that the
    broker still observes the sealed run/registry authority, but credential
    issuance remains structurally absent until the next reviewed slice.
    """
    if not isinstance(envelope, SealedAuthorityEnvelope):
        raise ValueError("deny-only broker requires a typed sealed authority envelope")
    split_dependencies = all(callable(item) for item in (
        authority_fn, liveness_fn, identity_fn, registry_digest_fn))
    if not callable(state_fn) and not split_dependencies:
        raise ValueError(
            "deny-only broker requires identity, liveness, registry and authority checks")
    if callable(state_fn) and any(item is not None for item in (
            authority_fn, liveness_fn, identity_fn, registry_digest_fn)):
        raise ValueError("atomic and split broker state sources cannot be combined")

    admission_limiter = anyio.CapacityLimiter(DENY_ONLY_STATE_CONCURRENCY)
    # AnyIO releases its thread limiter when an awaiter abandons a cancelled
    # worker, even though the underlying Python thread may still be running.
    # This separate lifetime semaphore is therefore released by the worker,
    # not the request, and caps residual abandoned calls as well as live ones.
    dependency_slots = threading.BoundedSemaphore(DENY_ONLY_STATE_CONCURRENCY)

    async def _dependency(callable_: Callable[..., Any], *args: object) -> Any:
        if not dependency_slots.acquire(blocking=False):
            raise _DependencyCapacityExhausted
        ownership_lock = threading.Lock()
        ownership = ["queued"]

        def run() -> Any:
            with ownership_lock:
                if ownership[0] == "cancelled":
                    return None
                ownership[0] = "worker"
            try:
                return callable_(*args)
            finally:
                dependency_slots.release()

        try:
            return await anyio.to_thread.run_sync(
                run, abandon_on_cancel=True)
        except BaseException:
            # Cancellation before the global AnyIO pool starts `run` leaves
            # release ownership with this coroutine. Once `run` claims it,
            # only the actual worker may release, including after abandonment.
            with ownership_lock:
                if ownership[0] == "queued":
                    ownership[0] = "cancelled"
                    dependency_slots.release()
            raise

    async def _state_problem() -> str | None:
        try:
            admission_limiter.acquire_nowait()
        except anyio.WouldBlock:
            return "broker state-check capacity exhausted"
        try:
            with anyio.fail_after(DENY_ONLY_STATE_TIMEOUT_SECONDS):
                return await _checked_state_problem()
        except TimeoutError:
            return "broker state check timed out"
        finally:
            admission_limiter.release()

    async def _checked_state_problem() -> str | None:
        if state_fn is not None:
            try:
                current = await _dependency(state_fn)
                if not isinstance(current, tuple) or len(current) != 4:
                    return "atomic broker state is malformed"
                live, current_identity, registry_digest, decision = current
                if type(live) is not bool:
                    return "atomic broker liveness is malformed"
                if not live:
                    return "run is not active"
                if current_identity != (
                        envelope.expected_subject, envelope.expected_actor):
                    return "sealed identity changed"
                if registry_digest != envelope.registry_sha256:
                    return "registry generation changed"
                if not isinstance(decision, dict) or not _authority_matches(
                        envelope, decision):
                    return "sealed authority changed"
                return None
            except _DependencyCapacityExhausted:
                return "broker dependency capacity exhausted"
            except Exception:                                  # noqa: BLE001
                log.warning("deny-only atomic state check raised for run %s",
                            envelope.run_id, exc_info=True)
                return "atomic broker state check failed"
        try:
            assert liveness_fn is not None
            live = await _dependency(
                liveness_fn, envelope.run_id)
        except _DependencyCapacityExhausted:
            return "broker dependency capacity exhausted"
        except Exception:                                      # noqa: BLE001
            log.warning("deny-only broker liveness check raised for run %s",
                        envelope.run_id, exc_info=True)
            return "run liveness check failed"
        if not live:
            return "run is not active"
        try:
            assert identity_fn is not None
            assert registry_digest_fn is not None
            assert authority_fn is not None
            identity = await _dependency(
                identity_fn, envelope.run_id)
            if identity != (envelope.expected_subject, envelope.expected_actor):
                return "sealed identity changed"
            registry_digest = await _dependency(
                registry_digest_fn, envelope.agent, envelope.run_id)
            if registry_digest != envelope.registry_sha256:
                return "registry generation changed"
            decision = await _dependency(
                authority_fn, envelope.agent, envelope.run_id,
                envelope.audience, None, None)
            if not isinstance(decision, dict) or not _authority_matches(
                    envelope, decision):
                return "sealed authority changed"
        except _DependencyCapacityExhausted:
            return "broker dependency capacity exhausted"
        except Exception:                                      # noqa: BLE001
            log.warning("deny-only broker authority check raised for run %s",
                        envelope.run_id, exc_info=True)
            return "authority check failed"
        return None

    async def ready(_: Request) -> Response:
        problem = await _state_problem()
        if problem:
            return Response(problem, status_code=503)
        return Response("deny-only broker ready", status_code=200)

    async def authz(request: Request) -> Response:
        try:
            await _bounded_request_body(request)
        except ValueError as exc:
            return Response(str(exc), status_code=413)
        problem = await _state_problem()
        if problem:
            return Response(problem, status_code=403)
        # This is the positive control for slice 3a: all prerequisites are live
        # and exact, yet issuance remains impossible and no Authorization header
        # exists. A later slice must replace this named denial under its own live
        # AS/resource proof rather than accidentally falling through.
        return Response("credential issuance is disabled", status_code=403)

    methods = ["GET", "POST", "DELETE"]
    return Starlette(routes=[
        Route("/ready", ready, methods=["GET"]),
        Route(authz_path, authz, methods=methods),
        Route(authz_path + "/{rest:path}", authz, methods=methods),
    ])


def _best_effort_id(body: bytes) -> Any:
    """The JSON-RPC id from a tools/list response body, so a fail-closed error
    can be correlated with the request (JSON-RPC 2.0 sec 5: the error id MUST
    equal the request id; null only when it cannot be determined). Best-effort:
    an unreadable body yields null, which is the honest answer."""
    import json
    try:
        msg = json.loads(body)
    except Exception:                                          # noqa: BLE001
        # Try the first SSE data payload.
        try:
            for raw in body.decode().split("\n"):
                line = raw.rstrip("\r")
                if line.startswith("data:"):
                    msg = json.loads(line[len("data:"):].strip() or "null")
                    break
            else:
                return None
        except Exception:                                     # noqa: BLE001
            return None
    return msg.get("id") if isinstance(msg, dict) else None


def _unavailable(req_id: Any, *, sse: bool) -> bytes:
    """A fail-closed JSON-RPC error carrying the request id, framed for the
    upstream content-type so an SSE client actually receives it (a bare JSON
    body on a text/event-stream response is invisible to an SSE parser)."""
    import json
    payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {
        "code": -32000, "message": "tools/list filtering unavailable"}})
    if sse:
        return ("event: message\ndata: " + payload + "\n\n").encode()
    return payload.encode()


def _default_liveness(run_id: str) -> bool:
    from ..server.auth import _run_liveness
    active, _ = _run_liveness(run_id)
    return active


def _default_authority(agent: str, run_id: str, audience: str,
                       method: str | None = None,
                       tool: str | None = None) -> dict[str, Any]:
    # Scope and pin come from the RUN RECORD (sealed at launch), never from the
    # request, then the ceiling-safe decision is the mint's own. The MCP
    # method/tool are available for finer per-tool policy; the registry ceiling
    # is the audience-level decision the mint already computes.
    from ..server import db, registry
    with db.connect() as conn:
        row = conn.execute(
            "SELECT scope, subject_context FROM runs WHERE id = ?",
            (run_id,)).fetchone()
    import json
    scope = json.loads(row["scope"]) if row and row["scope"] else None
    pin = json.loads(row["subject_context"]) if row and row["subject_context"] else None
    return registry.authority_for(agent, scope, pin, audience)


def is_allowed(decision: dict[str, Any]) -> bool:
    """DENY when the registry emptied the grant: no permitted audience, or an
    explicit empty action set. Mirrors the mint's own reading of
    `registry.authority_for` (actions == [] is deny, None is unrestricted)."""
    if decision.get("audience") is None:
        return False
    actions = decision.get("actions")
    if actions is not None and len(actions) == 0:
        return False
    return True


# permitted_tools, filter_tools_payload, mcp_body_kind and parse_mcp MOVED to
# andyur/mcpwire.py. The sidecar tool leg needs the same decisions, and a
# second implementation would break the one property permitted_tools exists to
# hold: that the menu an agent sees and the calls it may make cannot drift
# apart. Imported at module scope above; re-exported here so existing callers
# and tests that reach for extauthz.permitted_tools keep one meaning.


def build_app(
    *,
    run_agent: str,
    run_id: str,
    audience: str,
    exchange_fn: Callable[..., str],
    authority_fn: Callable[..., dict[str, Any]] | None = None,
    liveness_fn: Callable[[str], bool] | None = None,
    authz_path: str = "/authz",
    mcp_tools: Iterable[Any] | None = None,
    cnf_fn: Callable[[], str | None] | None = None,
    require_mcp_tools: bool = False,
) -> Starlette:
    """`run_agent`/`run_id` are this proxy's PROVISIONED identity (one Envoy per
    run). `audience` is its single tool resource_id. `exchange_fn(agent, run_id,
    scope, pin, audience) -> token` returns the delegated bearer to inject and
    is REQUIRED -- a managed call cannot proceed without a platform credential.

    `mcp_tools` is the tool binding's enumerated grants from the SEALED registry
    resolution this run launched with (`ToolBinding.mcp_tools`) -- provisioned
    at launch exactly like the run identity, never read from a request. None
    keeps the audience-level posture; enumerated grants close the method
    vocabulary to `MCP_TOOL_SESSION_METHODS`, gate every tools/call on the
    named tool's required action, and back the /toolfilter rewrite.

    `cnf_fn` returns the RFC 8705 `x5t#S256` thumbprint of the run's CURRENT
    X509-SVID leaf -- the certificate Envoy presents to the tool. It is read
    per request at mint time, not captured once. When set, every exchange is
    asked for a sender-bound token (`exchange_fn(..., cnf=thumb)`) and a
    thumbprint that cannot be read WITHHOLDS the token: with binding configured,
    an unbound token must never be minted as a fallback (F-02).

    ROTATION CAVEAT (open item, ADR-004): binding is per-request but the cert
    the tool sees is fixed per TLS connection at handshake, and Envoy applies an
    SDS rotation only to NEW upstream connections. Across an SVID rotation, a
    freshly bound token can ride a POOLED old-leaf connection and be refused by
    the tool ("not bound to this channel") until the pool cycles -- a
    fail-closed availability window, never a widening. Rotation-mid-session
    (drain-on-rotate, or an AS grace window over current+previous thumbprints)
    is tracked in ADR-004; and any future caching exchange coordinator MUST key
    its cache by the cnf thumbprint or it will serve stale-bound tokens."""
    if exchange_fn is None:
        raise ValueError(
            "a managed tool proxy requires an exchange coordinator; refusing "
            "to start a decision service that could allow a call with no "
            "platform-obtained credential")
    if require_mcp_tools and mcp_tools is None:
        # Production posture (sibling of require_identity): a managed MCP server
        # must EXPLICITLY enumerate its tools -- `[]` to permit none. `None` is
        # the audience-level, no-per-tool-filtering back-compat mode, which
        # silently retains server-wide authority and an unfiltered tools/list;
        # production must not fall into it by omission.
        raise ValueError(
            "a production managed MCP binding must declare mcp_tools (use [] to "
            "permit no invocation); refusing the audience-level default")
    authority_fn = authority_fn or _default_authority
    liveness_fn = liveness_fn or _default_liveness
    grants: dict[str, str] | None = None
    if mcp_tools is not None:
        grants = {g.name: g.requires for g in mcp_tools}

    async def authz(request: Request) -> Response:
        # The injected callables are SYNC and may block (a sqlite read, a
        # network token exchange). This service and the /toolfilter callback
        # share one event loop, so running them inline would let one slow
        # exchange stall every concurrent decision AND time out the Lua
        # response-filter round trip. Off-load each to a worker thread.
        # The run must still be ACTIVE: a terminated run's grant is dead even if
        # a token/SVID has not yet expired.
        try:
            if not await anyio.to_thread.run_sync(liveness_fn, run_id):
                return Response("run is not active", status_code=403)
        except Exception:                                      # noqa: BLE001
            log.warning("liveness check raised for run %s; denying",
                        run_id, exc_info=True)
            return Response("run liveness check failed", status_code=403)
        # MCP-aware: the decision authorizes the specific method + tool, not
        # just the server (audience). The JSON-RPC body rides the ext_authz
        # request (Envoy with_request_body).
        raw = await request.body()
        method, tool = parse_mcp(raw)
        if grants is not None:
            # An enumerated binding cannot per-tool-authorize a request shape it
            # cannot read into a single method+tool. A BATCH (top-level array)
            # or a garbage/scalar body yields method=None, which must NOT be
            # confused with the body-less transport leg -- a batched tools/call
            # would otherwise skip every per-tool check below and still be
            # minted a token. Fail closed on anything but an empty body or a
            # single JSON object. (MCP 2025-06-18 removed batching.)
            kind = mcp_body_kind(raw)
            if kind in ("array", "invalid"):
                log.warning("run %s: refusing unrecognized MCP request shape "
                            "%r on an enumerated binding", run_id, kind)
                return Response(
                    "not permitted: unrecognized MCP request shape (a single "
                    "JSON-RPC message is required; batching is not supported)",
                    status_code=403)
        try:
            decision = await anyio.to_thread.run_sync(
                authority_fn, run_agent, run_id, audience, method, tool)
        except Exception:                                      # noqa: BLE001
            # Unknown agent / registry read failure is fail-closed.
            log.warning("authority decision raised for run %s (method=%r "
                        "tool=%r); denying", run_id, method, tool, exc_info=True)
            return Response("authority decision failed", status_code=403)
        if not is_allowed(decision):
            return Response(
                f"not permitted: method={method!r} tool={tool!r}",
                status_code=403)
        if grants is not None:
            # An enumerated binding closes the method vocabulary (see
            # MCP_TOOL_SESSION_METHODS) and gates every tools/call on the
            # named tool's registry grant. A method-less single object (a
            # client RESPONSE to a server-initiated request) invokes nothing
            # and rides through; the batch/garbage shapes were already refused.
            if method is not None and method not in MCP_TOOL_SESSION_METHODS:
                return Response(
                    f"not permitted: method={method!r} is outside the "
                    "tool-enumerated MCP surface", status_code=403)
            if method == "tools/call":
                allowed = permitted_tools(decision, grants) or []
                if tool is None or tool not in allowed:
                    return Response(
                        f"not permitted: tool={tool!r} is not granted to "
                        "this run", status_code=403)
        try:
            if cnf_fn is None:
                bearer = await anyio.to_thread.run_sync(
                    exchange_fn, run_agent, run_id, decision.get("actions"),
                    decision.get("pin"), audience)
            else:
                thumb = await anyio.to_thread.run_sync(cnf_fn)
                if not thumb:
                    # With binding configured, an unbound token is never an
                    # acceptable fallback.
                    log.warning("run %s: run-cert thumbprint unreadable; "
                                "withholding the delegated token", run_id)
                    return Response(
                        "could not bind the delegated token to the run "
                        "certificate", status_code=403)
                bearer = await anyio.to_thread.run_sync(
                    functools.partial(
                        exchange_fn, run_agent, run_id, decision.get("actions"),
                        decision.get("pin"), audience, cnf=thumb))
                # NOTE (seam with ADR-006, B's lane): the coordinator REQUESTS
                # the binding but deliberately does NOT decode the issued token
                # to confirm the AS honored it -- ADR-006's broker states the
                # same ("does not decode the returned credential"), and the
                # AS/broker sender-binding topology is still an open blocker
                # there. The "AS stripped/altered cnf" case is caught at the
                # RESOURCE, where verify_cnf(require_cnf=True) refuses a token
                # not bound to the live certificate. Whether the coordinator
                # should ALSO verify is an A/B seam decision, not settled here.
        except Exception:                                      # noqa: BLE001
            # Allowed by policy but the token could not be minted: withhold.
            log.warning("token mint/exchange raised for run %s; withholding",
                        run_id, exc_info=True)
            return Response("could not mint delegated token", status_code=403)
        # Envoy forwards this Authorization upstream and OVERRIDES any the agent
        # sent, so the tool only ever sees the platform-issued token.
        headers = {"authorization": f"Bearer {bearer}"}
        if method is not None:
            # Surfaces the AUTHORIZED method to Envoy as dynamic metadata
            # (dynamic_metadata_from_headers), so the response-side Lua filter
            # knows a tools/list reply is in flight. Read from the authz
            # RESPONSE, never from agent headers -- the agent cannot forge it.
            headers["x-andyur-mcp"] = method
            if method == "tools/list":
                # Forwarded upstream (allowed_upstream_headers) so the tool
                # replies uncompressed; the response rewrite cannot verify a
                # body it cannot read, and would otherwise fail closed.
                headers["accept-encoding"] = "identity"
        return Response("ok", status_code=200, headers=headers)

    async def toolfilter(request: Request) -> Response:
        """Rewrite a tools/list RESPONSE body to the permitted tools. Called by
        the Envoy response filter, over the same private channel as /authz. It
        DISPENSES nothing (no token, no allow) -- it can only ever narrow.

        It ALWAYS returns 200 with the exact bytes Envoy should emit, because
        only here is the upstream content-type known (forwarded as
        `x-andyur-upstream-ct`), so the fail-closed error can be framed for JSON
        or SSE and carry the request id. On any failure the agent receives that
        error, never the unfiltered list."""
        body = await request.body()
        if grants is None:
            return Response(body, status_code=200)
        sse = "text/event-stream" in request.headers.get(
            "x-andyur-upstream-ct", "")
        # Re-check LIVENESS at response time, symmetric with /authz: a run that
        # terminated while a slow tools/list was in flight must not still be
        # handed its menu. Fail closed on terminated OR on a liveness error.
        try:
            if not await anyio.to_thread.run_sync(liveness_fn, run_id):
                log.info("run %s: terminated during tools/list; empty menu",
                         run_id)
                return Response(_unavailable(_best_effort_id(body), sse=sse),
                                status_code=200)
        except Exception:                                      # noqa: BLE001
            log.warning("run %s: liveness check raised during tools/list; "
                        "failing closed", run_id, exc_info=True)
            return Response(_unavailable(_best_effort_id(body), sse=sse),
                            status_code=200)
        if len(body) > MAX_TOOLS_LIST_BYTES:
            # Match the Envoy listener buffer ceiling: an oversized list is a
            # fail-closed error, not an unbounded parse+re-encode (3 copies).
            log.warning("run %s: tools/list body %d bytes exceeds the %d cap; "
                        "failing closed", run_id, len(body), MAX_TOOLS_LIST_BYTES)
            return Response(_unavailable(None, sse=sse), status_code=200)
        try:
            decision = await anyio.to_thread.run_sync(
                authority_fn, run_agent, run_id, audience, "tools/list", None)
            allowed = permitted_tools(decision, grants) if is_allowed(decision) \
                else []
            return Response(filter_tools_payload(body, set(allowed or [])),
                            status_code=200)
        except Exception:                                      # noqa: BLE001
            # Unreadable body or failed decision: emit a fail-closed JSON-RPC
            # error (correlated + framed), never the unverified list.
            log.warning("run %s: tools/list rewrite refused; emitting "
                        "fail-closed error", run_id, exc_info=True)
            return Response(_unavailable(_best_effort_id(body), sse=sse),
                            status_code=200)

    # The full MCP streamable-HTTP method set (POST call, GET SSE, DELETE
    # session), matching what Envoy's route admits -- otherwise Envoy would
    # admit a DELETE the decision service then 405s before the tool.
    methods = ["GET", "POST", "DELETE"]
    return Starlette(routes=[
        Route(authz_path, authz, methods=methods),
        Route("/toolfilter", toolfilter, methods=["POST"]),
        Route(authz_path + "/{rest:path}", authz, methods=methods),
    ])

"""Control plane API.

The server owns all state: the agent registry, coordination status, and run
records. Every other process (CLI, worker daemon, runners) talks to it over
HTTP and never touches the database directly, except runners appending to
their own workspace files.
"""

import asyncio
import contextlib
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from opentelemetry.trace import Status, StatusCode
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from .. import (actions, config, db, extensions, graph, identity,
                observability, orchestration, otel, runinput, workspace)
from . import (actionrequests, asproviders, auth, conversation, coordinator,
               delegation, messages, mind, oidc, pdp, registry, runtoken,
               schedules, tasks, tokenexchange)
# NOT `.registry` (which is andyur.server.registry, the mint-time ceiling store).
# This is andyur.registry, the agent-DEFINITION catalog whose read API the run
# harness consumes. The two are deliberately separate; the alias keeps them so.
from ..registry import api as registry_api
from ..registry.models import (AgentNotFound, RegistryUnavailable,
                              MalformedLifecycle, lifecycle_from_assignment)
from ..registry.service import configured_registry
from .. import mcpwire
from ..registry.models import LIFETIME_FLOOR_SECONDS, RUNTIME_PROTOCOL_EXEC_V1
from . import registry as registry_authority
from .heartbeat import heartbeat_loop

NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
# Names that mean something else in this system. A SPIFFE role is the last path
# segment of an id (identity.role_of), and agent identities are
# `/agent/<name>/run/<id>`, so today an agent called "operator" cannot be
# mistaken for the operator role. That safety is a property of one registrar
# layout, not of the name -- and an authorization check that depends on a URL
# shape staying the same is one refactor from admitting an agent that named
# itself after a privilege. Reserve them instead; the cost is four names.
RESERVED_NAMES = {"operator", "worker", "runner", "control-plane", "andyur",
                  "system", "admin", "temporal-execution-worker"}
_tracer = otel.setup_tracing("andyur-server")
log = logging.getLogger("andyur.server")


def _configure_andyur_logging() -> None:
    """Give the `andyur` package a handler, at INFO.

    Without this the package logs into a void: nothing anywhere calls
    basicConfig, so the effective level is WARNING with no handler, and logging's
    lastResort fallback is itself WARNING. Every `log.info` in the tree was
    therefore silently discarded -- which was only cosmetic until `mint ISSUED`
    became an AUDIT RECORD. An audit control that does not emit is not a control,
    and a review found exactly that: a live credential could exist for its whole
    lifetime with no issuance record on either side.

    Scoped to the `andyur` logger rather than the root, so this does not turn on
    every library's INFO chatter, and skipped if an operator has already
    configured handlers.
    """
    package = logging.getLogger("andyur")
    if package.handlers or logging.getLogger().handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"))
    package.addHandler(handler)
    package.setLevel(config.LOG_LEVEL)


_configure_andyur_logging()

# Fail safe #1 is GONE, because the configuration it refused cannot be expressed.
# It required agent-auth to be paired with identity or local trust, since with
# identity off the operator could not be proven and a run could mint cross-agent
# run tokens. Identity is unconditional now, so the operator is always proven by
# its SVID and there is nothing left to refuse.
# Fail safe #2: with agent-auth on and a SHARED database (multi-node), a per-process
# random run-token secret would make tokens minted on one replica 401 on another.
if config.AGENT_AUTH and config.DB_URL and not config.RUN_TOKEN_SECRET_SET:
    raise RuntimeError(
        "ANDYUR_RUN_TOKEN_SECRET must be set when ANDYUR_AGENT_AUTH is on with a "
        "shared DB (ANDYUR_DB_URL); a per-process random secret breaks run tokens "
        "across replicas."
    )


def _warn_ownerless_agents() -> None:
    """Turning user-auth ON strands every agent that predates it.

    Ownership is compared as a string, and an agent created before user-auth
    has `owner IS NULL`, which matches no user. The owner gate then answers 404
    to everyone -- correctly, since nobody owns it -- while the name stays
    globally taken, so creating a replacement answers 409 `already exists` for
    an agent the caller cannot see. That pair of answers is indistinguishable
    from a platform bug unless somebody says what happened, and only an admin
    can see the rows at all.

    A warning, not a refusal: an operator may have meant to retire them, and
    refusing to serve would turn an untidy migration into an outage.
    """
    if not config.USER_AUTH:
        return
    try:
        with db.connect() as conn:
            names = [r["name"] for r in conn.execute(
                "SELECT name FROM agents WHERE owner IS NULL ORDER BY name")]
    except Exception:            # a warning must never keep the server down
        return
    if not names:
        return
    shown = ", ".join(names[:10]) + (f", +{len(names) - 10} more" if len(names) > 10 else "")
    log.warning(
        "ANDYUR_USER_AUTH is on and %d agent(s) have no owner: %s. They predate "
        "user-auth, so no user can see or trigger them, while their names stay "
        "taken (create answers 409, delete answers 404). An admin can delete "
        "them, or set `agents.owner` to the user who should hold them.",
        len(names), shown)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Refuse to serve a production deployment that is not actually contained.
    # In lifespan rather than at import: importing Andyur (a test, a CLI, a
    # migration) must not require a full production environment, but SERVING
    # must.
    config.assert_profile()
    config.assert_user_auth()
    _assert_extensions()
    # Build the workflow provider HERE, so a misconfigured one refuses to serve
    # rather than failing per request. `registry.UnknownProvider` says it "must
    # stop the process rather than surface as a runtime error some caller might
    # handle" -- and lazily constructing it meant a typo in
    # ANDYUR_WORKFLOW_PROVIDER started a healthy-looking server whose every
    # trigger 500s, whose heartbeat raises each tick, and whose POST /tasks
    # fails AFTER committing the task row.
    orchestration.facade()
    db.init_db()
    _warn_ownerless_agents()
    graph.init()  # no-op unless ANDYUR_GRAPH=neo4j
    task = asyncio.create_task(heartbeat_loop())
    yield
    task.cancel()


def _assert_extensions() -> None:
    """Load the enabled extensions before serving, so one that cannot load stops
    the process instead of failing per request. An authorization policy with
    user-auth off is refused too: it is consulted only for user-authenticated
    requests, so under that configuration it would never be asked anything
    while the operator believed it was enforcing."""
    loaded = extensions.loaded()
    if loaded.authorization_policy is not None and not config.USER_AUTH:
        raise extensions.ExtensionError(
            f"extension {loaded.authorization_policy_from!r} installs an "
            "authorization policy, but ANDYUR_USER_AUTH is off; the policy "
            "governs user-authenticated requests and would never be consulted")


USER_TOKEN_HEADER = "x-andyur-user-token"


def _identify(authorization: str | None, run_token: str | None,
              user_token: str) -> tuple[str, bool, dict]:
    """The workload, then the user. Off the event loop: both may wait on
    something outside this process.

    The workload must be the OPERATOR. Only the operator's CLI and the console
    forward a user's token, and a run is the component this platform does not
    trust: it holds a runner SVID and can hold its user's token. Admitting any
    valid SVID here let a run read the policy's verdict on that user and hold
    every policy slot, which no handler would have let it do."""
    caller = auth.caller_spiffe_id(authorization)
    if run_token or identity.role_of(caller) != auth.OPERATOR:
        raise HTTPException(
            403, "a user token is accepted only from the operator workload")
    return _authenticate(user_token)


def _policy_text(value: object) -> str:
    """Somebody else's string, made safe to record: one line, redacted, bounded.

    Never raises. The value may be an object whose `__str__` does, and an
    exception here would be an unrecorded 500 in place of a decision."""
    try:
        return otel.safe_attribute(" ".join(str(value).split()))
    except Exception:
        return "(unprintable)"

# How a consultation is named in the bounded vocabulary the metric and the
# structured event share: (outcome, reason).
_POLICY_VOCABULARY = {
    extensions.ALLOW: ("success", "unknown"),
    extensions.REFUSE: ("denied", "refused"),
    extensions.ERROR: ("failure", "invalid"),
    extensions.TIMEOUT: ("timeout", "timeout"),
    extensions.SATURATED: ("failure", "exhausted"),
}


async def _govern_user_request(request: Request) -> None:
    """Put every request that presents a user token to the enabled policy.

    A dependency of the APPLICATION, so it runs for every route and before any
    of them: a route cannot forget it, and none of them has looked anything up
    yet. Both halves matter. Consulting the policy from inside the handlers
    governed only the handlers that authenticated a user, and it ran after
    their own lookups -- so a refusal answered 403 for a thing that existed and
    404 for one that did not, which told a refused caller what the ownership
    check exists to hide.

    The WORKLOAD is authenticated here first, and then the user. A user token
    means nothing to this server unless the operator forwarded it, so a caller
    with no SVID gets the 401 it always got, a caller that is not the operator
    gets a 403, and neither reaches the identity provider or the policy. Checking the user token first made both
    reachable by anyone who could open a connection: a forged token forced a
    key fetch per request, and a refusal told the holder of a stolen token
    which routes its user was barred from.

    The policy is never shown a caller the platform has not identified, and a
    user token that does not validate is a 401 on every route while a policy
    is enabled, including the routes that would otherwise ignore the header.
    Ownership and the admin role are still the handler's decisions, made after
    this, so a policy may be asked about a request the platform then refuses.
    It is never asked to allow one.

    A request with no user token is the host operator's SVID and is not
    governed: halting a workflow must not depend on a browser session, or on
    somebody else's code answering.
    """
    loaded = extensions.loaded()
    gate = loaded.authorization_gate
    if gate is None or not config.USER_AUTH:
        return
    token = request.headers.get(USER_TOKEN_HEADER)
    if not token:
        return
    subject, is_admin, claims = await run_in_threadpool(
        _identify, request.headers.get("authorization"),
        request.headers.get("x-andyur-run-token"), token)
    path = getattr(request.scope.get("route"), "path", None)
    action = f"{request.method} {path}"
    refusal: HTTPException | None = None
    # The span records nothing by itself. What a policy raises or returns reaches
    # the trace only through _policy_text, and the tracer's own exception
    # recording would put a message and a traceback there whole.
    with _tracer.start_as_current_span(
            "authz.policy", record_exception=False,
            set_status_on_exception=False) as span:
        span.set_attribute("andyur.authz.policy", loaded.authorization_policy_from or "")
        span.set_attribute("andyur.authz.action", action)
        span.set_attribute("andyur.user", _policy_text(subject))
        if path is None:
            # No declared route to name the action by. A policy asked about an
            # action it cannot identify has not agreed to it.
            decision = extensions.Decision(extensions.ERROR, 0.0, error=LookupError(
                "the request matched no declared route"))
        else:
            decision = await gate.consult(extensions.UserRequest.of(
                subject=subject, is_admin=is_admin, claims=claims, action=action,
                params=request.path_params))
        span.set_attribute("andyur.authz.decision", decision.outcome)
        outcome, reason = _POLICY_VOCABULARY[decision.outcome]
        otel.try_record_metric("andyur-server", "andyur.extension_policy.decisions",
                               1, andyur__outcome=outcome, andyur__reason=reason)
        otel.try_record_metric("andyur-server", "andyur.extension_policy.duration",
                               decision.seconds, andyur__outcome=outcome)
        observability.event(log, "extension_policy.decision", outcome=outcome,
                            reason=reason)
        if decision.outcome == extensions.REFUSE:
            # The policy's text is somebody else's string: redacted and bounded
            # before it reaches the span, the log or the caller.
            said = _policy_text(decision.reason)
            span.add_event("andyur.authz.refused", {"andyur.authz.reason": said})
            log.info("authorization policy %r refused %s for %r: %s",
                     loaded.authorization_policy_from, action, subject, said)
            refusal = HTTPException(
                403, f"refused by authorization policy: {said}" if said
                else "refused by authorization policy")
        elif decision.outcome == extensions.ERROR:
            # The exception's type and its message, both through the same
            # redactor as a reason -- a class name is the policy's text too.
            # Not record_exception and not exc_info: both carry the message
            # and the traceback whole.
            kind = _policy_text(type(decision.error).__name__)
            why = _policy_text(decision.error)
            span.add_event("exception", {"exception.type": kind,
                                         "exception.message": why})
            span.set_status(Status(StatusCode.ERROR, "the policy failed"))
            log.error("authorization policy %r failed on %s for %r (%s: %s); "
                      "refusing", loaded.authorization_policy_from, action,
                      subject, kind, why)
            refusal = HTTPException(
                403, "the authorization policy failed to evaluate this request")
        elif decision.outcome == extensions.TIMEOUT:
            span.set_status(Status(StatusCode.ERROR, "the policy did not answer"))
            log.error("authorization policy %r did not answer %s within %ss; refusing",
                      loaded.authorization_policy_from, action, gate.timeout)
            refusal = HTTPException(
                503, "the authorization policy did not answer in time",
                headers={"Retry-After": "1"})
        elif decision.outcome == extensions.SATURATED:
            span.set_status(Status(StatusCode.ERROR, "the policy is saturated"))
            log.error("authorization policy %r has all %d calls outstanding; "
                      "refusing %s", loaded.authorization_policy_from,
                      gate.concurrency, action)
            refusal = HTTPException(
                503, "the authorization policy has too many calls outstanding",
                headers={"Retry-After": "1"})
    # Raised outside the span: a refusal is a decision the span already
    # records, not an exception that happened to it.
    if refusal is not None:
        raise refusal


app = FastAPI(title="Andyur", version="0.1.0", lifespan=lifespan,
              dependencies=[Depends(_govern_user_request)])

# The control plane's write endpoints (messages/tasks/files/graph/...) read the
# whole body with `await request.json()`, and pydantic runs only AFTER Starlette
# has buffered it. Without a ceiling an agent-reachable tool write (send_message,
# create_task, file writes) could hand the SHARED server a multi-GB body and OOM
# it before any validation -- so bound it once, in front of every route, rather
# than per field. Content-Length is refused up front (the practical vector always
# sets it); the streamed body is also counted so a chunked/mislabeled body is cut
# off rather than buffered without limit (fail-closed: the read ends early).
#
# The cap is raised from a too-tight 4 MiB: the runner PUTs the whole run
# TRANSCRIPT here as one body (runs/<id>/transcript.jsonl), and 4 MiB 413'd real
# runs, dropping the audit record ADR-010's own-storage files:write exists to keep.
# 64 MiB matches the BYOA ingest budget (agentchannel._MAX_STREAM) and admits
# typical transcripts while still bounding a multi-GB OOM. It is a RAISED BOUND,
# NOT a guarantee every transcript fits: the in-process runner accumulates the
# transcript from SDK messages across many turns with no single-stream bound, so a
# pathological run can still exceed 64 MiB. That residual case now 413s and the
# runner logs a WARNING that the audit record was dropped (see _put_file's caller
# in runner.py phase 4/5) rather than losing it silently -- raise the env override
# if such runs are expected.
_MAX_REQUEST_BYTES = int(os.environ.get("ANDYUR_MAX_REQUEST_BYTES", str(64 * 1024 * 1024)))


class _BodySizeLimit:
    def __init__(self, asgi_app, limit: int):
        self._app = asgi_app
        self._limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self._app(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self._limit
            except ValueError:
                too_big = True
            if too_big:
                return await self._reject(send)
        seen = 0
        cut = False

        async def bounded_receive():
            nonlocal seen, cut
            message = await receive()
            if message["type"] == "http.request" and not cut:
                seen += len(message.get("body", b""))
                if seen > self._limit:
                    cut = True
                    return {"type": "http.disconnect"}
            return message

        await self._app(scope, bounded_receive, send)

    async def _reject(self, send):
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body",
                    "body": b'{"detail":"request body exceeds the server limit"}'})


app.add_middleware(_BodySizeLimit, limit=_MAX_REQUEST_BYTES)

# THE REQUEST SPAN AND THE andyur.http.server.* METRICS, around every route.
#
# The control plane had no request-level instrumentation at all, so most of its
# routes emitted NO SERVER SPAN: a 401 at the boundary, a 422 on a malformed
# cursor, a 403 from an owner gate were decisions the platform made and did not
# record -- which is the exit criteria's own test. Two routes had grown an
# explicit `_decision_span` as a stopgap, which was one helper on two routes out
# of forty (ROADMAP.md 33).
#
# trust_traceparent is FALSE, deliberately and by the operator's decision. The
# caller is authenticated, but trace identity is still the caller's ASSERTION:
# trusting it would let an authenticated caller graft the control plane's
# decisions onto a trace of their choosing, or join two unrelated callers'
# work into one. The cost is that a console-to-server hop is two traces rather
# than one, which is the status quo and is safe by default.
#
# health_spans is FALSE for the opposite reason to the console's: this process
# IS behind readiness probes, and a span per probe would be most of every trace.
app.add_middleware(otel.ObservedASGI, service_name="andyur-server",
                   operation="server.request")

# The agent-definition registry's read API (/v1/registry/...). Its routes carry
# their own auth.require(OPERATOR, CONTROL_PLANE), so mounting is all that is
# needed here; removing this line takes the endpoints away entirely (they 404),
# which is what test_registry_mount asserts against.
app.include_router(registry_api.router)


class Body(BaseModel):
    """Every request body on this API. Unknown fields are REFUSED, not ignored.

    Pydantic's default is to drop what it does not recognise, and on an API whose
    job is to bound what an agent may do that default fails OPEN. A caller that
    typos `subject_ctx` for `subject_context` gets HTTP 200 and a run with no pin;
    one that typos `scopes` for `scope` gets a run with no scope, which this
    platform reads as UNRESTRICTED. Both callers believe they constrained the run.
    Neither did, and nothing anywhere says so. That was reproduced against a
    running server, not reasoned about.

    So it is refused here, once, for every body -- rather than on the two models
    where the bug happened to be noticed first, which is how it survived on the
    other fifteen.
    """

    model_config = ConfigDict(extra="forbid")


# Free text a caller supplies that ends up in a RUN ROW, and therefore on every
# page of run history. Unbounded, one row was enough to break that page for
# good: POST /tasks accepts a RUN token, tasks.py builds the woken run's reason
# from the task title, and a 17 MiB title made GET /runs a 17 MiB response --
# past the console's 16 MiB cap, on every page, until someone deleted the row.
# A smaller limit is not a workaround, it is the field's real size: a reason is
# a sentence a human reads in a table cell.
MAX_REASON_CHARS = 512
MAX_TITLE_CHARS = 512
# A scope is a list of entity-type tokens intersected with the caller's
# entitlements. Bounded so the sealed run row cannot be grown through it.
MAX_SCOPE_ENTRIES = 64
MAX_SCOPE_CHARS = 256
# The pin is a map of canonical resource IDS. coordinator.canonical_pin already
# refuses anything that is not a flat map of non-empty strings; these bound how
# big those strings and that map may be, because the pin is sealed on the run
# and travels in the signed grant.
MAX_PIN_ENTRIES = 32
MAX_PIN_CHARS = 256
# A Kubernetes object name is at most 253 characters (RFC 1123 subdomain), so a
# longer one could not have named a real object. Bounded here as well as in
# `actions.canonical_target` because this is the boundary: the body is rejected
# before a 4 MiB "namespace" is ever copied into a decision, a row or a log.
MAX_K8S_NAME_CHARS = 253
# An approver is a person's name or login, written into the audit trail.
MAX_APPROVER_CHARS = 256
# The bound on a user identifier, wherever it enters: asserted on the trigger
# body, or read out of a validated IdP claim. One constant so a value that
# authenticates cannot fail to fit the column it is written to.
MAX_ACTING_USER_CHARS = 256


class AgentCreate(Body):
    name: str
    registry_agent_id: str | None = None
    description: str = ""
    personality: str = ""
    scope: str = ""


class TriggerBody(Body):
    reason: str = Field("manual trigger by operator", max_length=MAX_REASON_CHARS)
    run_type: str = "work"
    # U2: the scope this run needs (None = unrestricted)
    scope: list[Annotated[str, StringConstraints(max_length=MAX_SCOPE_CHARS)]] | None = \
        Field(None, max_length=MAX_SCOPE_ENTRIES)
    # THE PIN: what this run's work is ABOUT -- the canonical resource ids it may
    # touch, e.g. {"account": "447"}. Typed as str -> str because a pin is an
    # IDENTIFIER, not a filter: numbers, nulls and nested objects would each need
    # their own comparison rule downstream, and "the pin matched" must mean one
    # thing. Asserted here by the authenticated caller of this endpoint, which is
    # operator-gated (auth.require refuses a run token outright), so the agent has
    # no path to this field. None = unpinned.
    subject_context: dict[
        Annotated[str, StringConstraints(max_length=MAX_PIN_CHARS)],
        Annotated[str, StringConstraints(max_length=MAX_PIN_CHARS)],
    ] | None = Field(None, max_length=MAX_PIN_ENTRIES)
    # THE ACTOR: who this run acts FOR. The trigger contract is specified to
    # carry actor, entitlements, pinned context and intent; it carried every part
    # but this one, so the only way to launch a run on behalf of a user was to
    # have USER_AUTH on and an OIDC token in hand. That left anything else --
    # a service launching work for a user, a scheduled run, a demo -- writing
    # `acting_user` into the database by hand, which is not an interface.
    #
    # The design names three tiers of who may assert this: an IdP claim is
    # strongest, an authenticated APPLICATION is acceptable and gets logged, and
    # the agent must be structurally unable to. This field is the middle tier.
    # It is safe because the endpoint is operator-gated -- `auth.require` refuses
    # a run token outright -- so an agent has no path to it, exactly as with the
    # pin beside it. When USER_AUTH is on the IdP wins and this is REFUSED rather
    # than merged, because two sources for one fact is how they come to disagree.
    acting_user: str | None = None
    # THE INPUT: one JSON value this run is handed, in whatever shape the
    # agent's own task format is. Sealed onto the run row (canonical, bounded,
    # refused if credential-shaped; andyur/runinput.py owns those rules) and
    # delivered per interface: a fenced prompt section for a native agent,
    # `input.data` for runtime-v1, the process's stdin/file/argv for exec/v1.
    # Distinct from `reason` (why this run exists) and from the pin (what it
    # may touch): this is data, and nothing that decides authority reads it.
    input: Any = None


class ActionRequestBody(Body):
    """One consequential action a RUN asks Andyur to take on its behalf.

    Every field here arrives from the agent, so every field is bounded and then
    checked against something the agent could not set: `tool` against the one
    remediation this MVP admits, and namespace/deployment against the PIN in the
    run's signed grant. Nothing in this body decides anything.
    """

    tool: str = Field(max_length=MAX_K8S_NAME_CHARS)
    namespace: str = Field(max_length=MAX_K8S_NAME_CHARS)
    deployment: str = Field(max_length=MAX_K8S_NAME_CHARS)


class ApproveBody(Body):
    """The human consenting to an action, when there is no IdP to name them.

    Bounded exactly like `acting_user`, and for the same reason: it is written
    into the audit trail, and an audit record the audited party can write is
    worse than no record.
    """

    approver: str | None = Field(None, max_length=MAX_APPROVER_CHARS)


class TurnBody(Body):
    body: str   # one human message in a live conversation


class ReplyBody(Body):
    kind: str          # chunk | turn_end | session_end | error
    body: str = ""     # the reply text (redacted by the runner before it is sent)


# A run's own report of what it did. Stored raw and served on the row route,
# so this is the bound that makes "the bodies belong to the row route" true --
# the comment on the list projection said "captured stdout up to 1 MiB" and no
# code enforced it: the only limit was the 64 MiB request cap.
MAX_SUMMARY_CHARS = 1024 * 1024
MAX_ERROR_CHARS = 64 * 1024


class FinishBody(Body):
    summary: str | None = Field(None, max_length=MAX_SUMMARY_CHARS)
    error: str | None = Field(None, max_length=MAX_ERROR_CHARS)


class WorkerFinishBody(Body):
    # A worker reporting the completion of a run it owns. worker_id is the
    # ownership claim, checked against runs.worker; the summary/error are the
    # same fields /finish carries, on a DEDICATED endpoint rather than the
    # heartbeat body (a 1 MiB summary must never ride the 10 s heartbeat).
    worker_id: str
    summary: str | None = Field(None, max_length=MAX_SUMMARY_CHARS)
    error: str | None = Field(None, max_length=MAX_ERROR_CHARS)


class HeartbeatBody(Body):
    worker_id: str
    slots: int
    slots_free: int
    running: list[str] = []
    # The worker's containment posture. Declared here because pydantic drops
    # unknown fields by default: the daemon was already sending this and the
    # server was silently discarding it, so the "we would notice a dev worker"
    # assurance was worth exactly nothing.
    profile: str = "unknown"
    orchestrator: str = "unknown"


class ScheduleBody(Body):
    cron: str
    reason: str = "scheduled run"


class TaskCreateBody(Body):
    assignee: str
    # The assignee's woken run takes its reason from this title, so the bound
    # on a run's reason has to hold here too -- and this route accepts a RUN
    # token, so an agent reaches it without any operator credential.
    title: str = Field(..., max_length=MAX_TITLE_CHARS)
    detail: str = ""
    creator: str = "operator"
    # trace context of the creating agent's run, so the assignee's run joins
    # the same distributed trace (cross-agent tracing)
    trace_ctx: str | None = None
    # the creating agent's run id; the server copies THAT run's workflow (never a
    # client-supplied workflow id) so workflow identity stays authoritative
    parent_run_id: str | None = None
    # U4: the authority to hand the delegated run. Capped to the delegator's own
    # scope (never wider); omit to pass the delegator's scope down unchanged.
    scope: list[str] | None = None


class TaskUpdateBody(Body):
    state: str
    result: str | None = None


class MessageBody(Body):
    recipient: str
    body: str
    sender: str = "operator"
    trace_ctx: str | None = None
    parent_run_id: str | None = None


class FileWriteBody(Body):
    content: str
    actor: str = "agent"
    run_id: str | None = None


class RestoreBody(Body):
    version_id: str
    actor: str = "operator"


class EntityBody(Body):
    name: str
    type: str = "entity"
    summary: str | None = None
    run_id: str | None = None
    embedding: list[float] | None = None


class FactBody(Body):
    subject: str
    predicate: str
    object: str
    subject_type: str = "entity"
    object_type: str = "entity"
    valid_from: str | None = None
    run_id: str | None = None
    confidence: float = 1.0


class EpisodeBody(Body):
    text: str
    run_id: str | None = None


@app.get("/health")
def health() -> dict:
    """Shallow process liveness only; Kubernetes readiness uses /ready."""
    return {"ok": True, "service": "andyur-server"}


@app.get("/ready")
def ready() -> dict:
    """Bounded readiness for dependencies needed to authorize and persist runs."""
    problems: list[str] = []
    try:
        config.assert_profile()
        config.assert_user_auth()
    except Exception as exc:
        problems.append(f"configuration: {type(exc).__name__}")
    problems.extend(f"authorization-server: {problem}"
                    for problem in config.as_problems())
    try:
        with db.connect() as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception as exc:
        problems.append(f"database: {type(exc).__name__}")
    if config.PROD:
        try:
            identity.assert_live_x509_identity(
                f"spiffe://{identity.TRUST_DOMAIN}/control-plane")
        except Exception as exc:
            problems.append(f"identity: {type(exc).__name__}")
    if problems:
        raise HTTPException(503, detail={"ready": False, "problems": problems})
    return {"ready": True, "service": "andyur-server"}


@app.get("/identity/whoami")
def whoami(authorization: str | None = Header(default=None)) -> dict:
    """Validate the caller's JWT-SVID and report the identity it proves. This is
    where the per-run container-attestation round-trip lands: a runner in its own
    container presents its container-attested SVID, and the server (a SPIFFE
    workload on the same trust domain) validates it cryptographically and reads
    back which agent/run is calling -- no self-declared name is trusted."""
    token = identity.bearer_token(authorization)
    if token is None:
        raise HTTPException(401, "missing JWT-SVID bearer token")
    try:
        spiffe_id = identity.validate_token(token)
    except Exception as exc:
        log.warning("whoami: JWT-SVID validation failed: %s", exc)
        raise HTTPException(401, "invalid JWT-SVID")  # detail stays in the log
    agent, run_id = identity.parse_agent_run(spiffe_id)
    return {
        "spiffe_id": spiffe_id,
        "agent": agent,          # set when the caller is a per-run runner SVID
        "run_id": run_id,
        # a role name only for non-run identities (operator, worker, ...); for a
        # per-run SVID the last segment is the run id, not a role, so report none
        "role": None if agent else identity.role_of(spiffe_id),
    }


@app.get("/identity/verify-run")
def verify_run(ctx: auth.RunCtx = auth.require_run()) -> dict:
    """A run-scoped call that exercises the full R1 + Slice 4 auth path: the run
    token scopes the caller, and (identity on) the token is bound to the caller's
    container-attested SVID -- a token replayed from another container is rejected
    before this returns. Reports the scoped identity the server authorized."""
    return {
        "agent": ctx.agent,
        "run_id": ctx.run_id,
        "workflow_id": ctx.workflow_id,
        "is_operator": ctx.is_operator,
        "user": ctx.user,        # U1: the user this run acts for (the agent's owner)
        "scope": ctx.scope,      # U2: the narrowed authority granted to this run
    }


class TokenExchangeBody(Body):
    # Unknown fields are REJECTED, not ignored. The pin and the user are taken
    # from the run's signed grant, and a body carrying `pin` or `sub` is either a
    # confused client or a model trying to restate its own authority. Silently
    # dropping it tells neither of them anything; 422 tells both.

    audience: str                        # the target this downstream grant is for
    actor: str | None = None             # the delegatee: a REGISTERED AGENT, whose
                                         # registry ceiling bounds the grant. Not a
                                         # tool -- a tool is the `audience`.
    scope: list[str] | None = None       # requested narrowing; capped to the parent's scope
    subject_token: str | None = None     # a prior downstream JWT, to continue an act chain


@app.get("/.well-known/jwks.json")
def exchange_jwks() -> dict:
    """Andyur's downstream-delegation public key (U4). An external target fetches this
    once and validates every delegated JWT locally, with no callback to the server."""
    return tokenexchange.public_jwks()


TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
# The one token type this endpoint takes in and gives out (RFC 8693 sec 3). Named
# once so the request checks and the response cannot drift apart.
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


async def _exchange_request(request: Request) -> TokenExchangeBody:
    """Accept BOTH wire formats and normalise to one internal shape.

    FORM-ENCODED is the real RFC 8693 (sec 2.1) and the reason this exists: an
    off-the-shelf client -- agentgateway, in our case -- posts
    `grant_type`/`subject_token`/`subject_token_type`/`audience` as a form, and the
    JSON-with-a-custom-`actor`-field body this endpoint used to require meant no
    standard client could talk to it. Verified against agentgateway 1.4.1, which
    sends exactly those four plus `requested_token_type`.

    JSON is kept because the CLI and the existing tests use it, and because
    breaking them buys nothing: the two forms carry the same information.

    In the form-encoded case there is no `actor` parameter, because RFC 8693 has
    none -- the actor is the party presenting the subject token. So the actor is
    the CALLING AGENT, which is also the only value that was ever safe: the actor
    was previously caller-chosen, and the ceiling had to be applied twice to stop
    an agent naming a more capable delegatee to widen what it held.
    """
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip()
    if ctype != "application/x-www-form-urlencoded":
        try:
            return TokenExchangeBody(**(await request.json()))
        except ValidationError as exc:
            # Parsed here rather than by FastAPI's signature, so the 422 that a
            # forbidden extra field earns has to be raised by hand. Without this
            # a body carrying a `pin` became a 500, which reads as our bug rather
            # than the caller's.
            raise HTTPException(422, json.loads(exc.json()))

    form = await request.form()
    grant = form.get("grant_type")
    if grant != TOKEN_EXCHANGE_GRANT:
        # `unsupported_grant_type` is RFC 6749 sec 5.2's code for exactly this,
        # and saying which grant we do support turns a 400 into a fixable one.
        raise _oauth_error(
            400, "unsupported_grant_type",
            f"this endpoint implements only {TOKEN_EXCHANGE_GRANT}")
    if not form.get("subject_token"):
        raise _oauth_error(400, "invalid_request",
                           "subject_token is required for a token exchange")
    # RFC 8693 sec 2.1 makes `subject_token_type` REQUIRED, and a request that
    # omits it is malformed however well the rest reads. Refusing an unsupported
    # value matters more than the absent case: a client saying it presented a
    # SAML assertion or an id_token has a different intent from one presenting an
    # access token, and silently treating them alike is how a client believes it
    # got semantics it did not get.
    subject_type = form.get("subject_token_type")
    if not subject_type:
        raise _oauth_error(400, "invalid_request",
                           "subject_token_type is required (RFC 8693 sec 2.1)")
    if str(subject_type) != ACCESS_TOKEN_TYPE:
        raise _oauth_error(
            400, "invalid_request",
            f"subject_token_type {subject_type} is not supported; this endpoint "
            f"accepts only {ACCESS_TOKEN_TYPE}")
    # RFC 8693 sec 2.1: the AS chooses the issued type only when the request does
    # not specify one. Honouring a request for an id_token or a SAML assertion by
    # returning an access token, with a 200, tells the client it got something it
    # did not.
    requested = form.get("requested_token_type")
    if requested and str(requested) != ACCESS_TOKEN_TYPE:
        raise _oauth_error(
            400, "invalid_request",
            f"requested_token_type {requested} is not supported; this endpoint "
            f"issues only {ACCESS_TOKEN_TYPE}")
    # `audience` and `resource` both name the target (RFC 8693 sec 2.1, RFC 8707).
    # A client may send either. BOTH may legitimately repeat, and a token here
    # names exactly ONE target -- that is the whole point of the audience term in
    # the authority intersection. Silently taking the first of several would hand
    # back a token for a target the client did not think it was getting, so a
    # request naming more than one is refused.
    # getlist for EVERY parameter, not only the target. RFC 6749 sec 3.1: a
    # parameter MUST NOT appear more than once, and `form.get` silently takes the
    # last -- the same defect the target check below was written to close, left
    # in place on its neighbours.
    for repeated in ("grant_type", "subject_token", "subject_token_type",
                     "requested_token_type", "scope"):
        if len(form.getlist(repeated)) > 1:
            raise _oauth_error(
                400, "invalid_request",
                f"{repeated} appears more than once; RFC 6749 sec 3.1 permits "
                "each parameter at most once")
    targets = [*form.getlist("audience"), *form.getlist("resource")]
    if len(targets) > 1:
        raise _oauth_error(
            400, "invalid_target",
            "this endpoint issues a token for exactly one target; name one "
            "audience or one resource, not several")
    audience = targets[0] if targets else None
    if not audience:
        raise _oauth_error(400, "invalid_target",
                           "audience or resource is required: a token must name "
                           "the one target it may be spent at")
    scope = form.get("scope")
    return TokenExchangeBody(
        audience=str(audience),
        actor=None,                      # resolved from the caller, see above
        scope=scope.split() if scope else None,
        subject_token=None,              # the RUN's token already authenticated us
    )


@app.post("/oauth/token")
async def token_exchange(
    request: Request, ctx: auth.RunCtx = auth.require_run()
) -> dict:
    """RFC 8693 token exchange (U4). Accepts the standard form-encoded request and,
    for our own CLI and tests, an equivalent JSON body.

    This is Andyur's reference/development signer. The production profile
    refuses it unconditionally: production authority comes from the adopter's
    configured authorization server through `server.asclient`.

    The granted authority is `entitlement AND pin AND ceiling AND audience`, and
    BOTH the caller's and the actor's registry ceilings apply -- the token comes
    back to the caller, so naming a more capable delegatee must not widen what the
    caller ends up holding. Returns an asymmetric JWT the target validates against
    Andyur's JWKS, with the pin as an RFC 9396 `authorization_details` claim.

    Failure modes: 400 `invalid_target` (actor not in the registry, or the audience
    is above a ceiling), 400 `invalid_scope` (the terms intersect to nothing --
    refused rather than issuing a token that permits nothing), 400 `invalid_request`,
    401 `invalid_grant` (bad subject token), 403 (the delegation allow-list),
    422 (a body field that is not honoured here, e.g. a pin), 503 (the registry is
    unreadable). `scope` appears in the RESPONSE whenever it differs from what was
    requested.

    The pin comes from the RUN, never from the body. That is the whole point of it:
    the run's pin was sealed by an authenticated caller at creation and inherited
    across delegation, so by the time an agent reaches this endpoint the resource
    its authority is scoped to is already decided and there is no field here through
    which the model can restate it."""
    if config.PROD:
        raise _oauth_error(
            403, "access_denied",
            "Andyur's local token signer is disabled in production; use the "
            "configured enterprise authorization server")
    body = await _exchange_request(request)
    caller_agent = None if ctx.is_operator else ctx.agent
    # No `actor` in a form request: RFC 8693 has no such parameter, and the actor
    # is the party presenting the subject token -- this run.
    if body.actor is None:
        body = body.model_copy(update={"actor": caller_agent or "operator"})
    if not ctx.is_operator and ctx.user is None:
        # OAuth-shaped + no-store like every other response from this endpoint,
        # so a client branches on the code and no error body is cacheable.
        raise _oauth_error(400, "invalid_request",
                           "this run has no user (sub) to delegate for")
    # The same gate /tasks and /messages apply. Handing an agent a TOKEN for a
    # delegatee is delegation just as much as handing it a task is, and the
    # operator's allow-list meant nothing on the one path that mints credentials.
    caller = caller_agent
    if not delegation.may_delegate(caller, body.actor):
        raise _oauth_error(
            403, "access_denied",
            f"agent '{caller}' may not delegate to '{body.actor}'")
    try:
        token, detail = tokenexchange.mint(
            body.actor, body.audience, caller=caller,
            ctx_sub=ctx.user, ctx_scope=ctx.scope,
            ctx_sub_src=ctx.user_asserted_by,
            subject_token=body.subject_token, requested_scope=body.scope,
            pin=ctx.pin,
        )
    except (tokenexchange.AudienceRefused, tokenexchange.UnknownActor) as exc:
        # RFC 8693 sec 2.2.2: a target the AS is unwilling to issue for is
        # `invalid_target`, and sec 5.2 of RFC 6749 makes that a 400. An earlier
        # version used 403 to keep "policy said no" from reading as a client bug
        # in an audit trail -- the right instinct, the wrong lever. `invalid_target`
        # is a dedicated, machine-greppable code for exactly this answer, which
        # separates it from every other 400 on the endpoint better than a 403 that
        # collapses into every other 403 on the service.
        raise _oauth_error(400, "invalid_target", str(exc))
    except tokenexchange.AuthorityEmpty as exc:
        # RFC 6749 sec 5.2 `invalid_scope`: the request is well formed and the
        # granted authority is empty, which is a scope answer, not a target one.
        raise _oauth_error(400, "invalid_scope", str(exc))
    except tokenexchange.ExchangeError as exc:
        raise _oauth_error(400, "invalid_request", str(exc))
    except tokenexchange.InvalidDelegatedToken as exc:
        raise _oauth_error(401, "invalid_grant", f"invalid subject token: {exc}")
    except registry.StoreUnavailable as exc:
        # The ceiling lives in the database, so an unreachable store means the
        # mint cannot know what it is allowed to issue. Refusing is right; doing
        # it as a bare 500 is not, because that is indistinguishable from a code
        # bug on an endpoint where 400 already means "malformed".
        log.error("mint unavailable: the authorization store could not be read (%s)", exc)
        raise _oauth_error(
            503, "temporarily_unavailable",
            "the authorization store is unreachable, so no authority can be "
            "derived; no token was issued")
    granted = detail["granted"]
    claims = detail["claims"]
    out = {
        "access_token": token,
        # RFC 8693 sec 3: `:access_token` means an OAuth 2.0 access token, and
        # `:jwt` means a JWT that is not otherwise identified. This mints an
        # RFC 9068 `at+jwt`, which is BOTH, and a client that asked for an access
        # token and is told it received a bare JWT is entitled to treat that as
        # the wrong type. agentgateway does exactly that, and refused every call
        # with "token exchange returned issued_token_type ...:jwt, expected
        # ...:access_token" -- found by running the real broker, not by reading.
        "issued_token_type": ACCESS_TOKEN_TYPE,
        # A resource server validates it against our JWKS with no callback,
        # which is what Bearer means.
        "token_type": "Bearer",
        # Derived from the token that was ACTUALLY issued, not re-read from
        # config. RFC 8693 sec 2.2.1 defines expires_in as the lifetime of the
        # issued token, `mint` takes a ttl parameter that can differ from the
        # config default, and a credential broker caches on this value -- so an
        # over-reported lifetime becomes a caller reusing a dead token.
        "expires_in": claims["exp"] - claims["iat"],
    }
    # RFC 6749 sec 3.3: if the granted scope differs from the requested scope, the
    # response MUST say so. This is not a nicety -- the ceiling and the pin can both
    # shrink a grant silently, and an agent that cannot see it was narrowed calls
    # the tool, gets a 403 it has no way to explain, and retries. That is a loop.
    if granted is not None and (detail["asked"] is None
                                or set(detail["asked"]) != set(granted)):
        out["scope"] = " ".join(granted)
    # RFC 6749 sec 5.1: the token response MUST NOT be cached (see _NO_STORE_HEADERS).
    return JSONResponse(out, headers=_NO_STORE_HEADERS)


# RFC 6749 sec 5.1: a token endpoint's responses may carry a token or sensitive
# grant detail, so every one MUST forbid caching -- otherwise an intermediary or
# client cache is entitled to replay a 200 token response to a later request.
_NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _oauth_error(status: int, code: str, description: str) -> HTTPException:
    """An OAuth-shaped error body (RFC 6749 sec 5.2) rather than FastAPI's bare
    `detail` string, so a client can branch on the CODE instead of parsing prose.
    Both are carried: the code for machines, the description for the operator
    reading a log. Carries the no-store headers so error bodies (which name why a
    grant failed) are no more cacheable than the token itself."""
    return HTTPException(status, {"error": code, "error_description": description},
                         headers=_NO_STORE_HEADERS)


def _is_admin(claims: dict) -> bool:
    """Does this validated token carry the configured admin role?

    The roles claim MUST be a JSON array of strings -- the shape RFC 9068 sec
    2.2.3.1 defines for `roles`/`groups`/`entitlements` (per RFC 7643). A
    space-delimited string is the syntax of `scope` and nothing else, and scope
    is authorization the CLIENT asked for, not an assertion the IdP makes about
    the user -- so accepting it here would let a client-influenced value grant
    admin. Any non-array shape -- a string, an object, a number, a hostile token
    carrying junk where a list belongs -- reads as NOT admin rather than raising,
    because a parsing surprise must never widen authority. Unset ANDYUR_ADMIN_ROLE
    means nobody is admin."""
    if not config.ADMIN_ROLE:
        return False
    node: object = claims
    for part in config.ROLES_CLAIM.split("."):
        if not isinstance(node, dict):
            return False
        node = node.get(part)
    if not isinstance(node, list):
        return False
    return any(r == config.ADMIN_ROLE for r in node if isinstance(r, str))


def _authed_principal(user_token: str | None) -> tuple[str, bool]:
    """Validate the caller's OIDC token; return (subject, is_admin), or 401."""
    subject, is_admin, _claims = _authenticate(user_token)
    return subject, is_admin


def _authenticate(user_token: str | None) -> tuple[str, bool, dict]:
    """Validate the caller's OIDC token; return (subject, is_admin, claims), or 401.

    The subject is read from `config.OIDC_SUBJECT_CLAIM` (`sub` by default), so
    a deployment can trade the guaranteed-stable-but-opaque `sub` for a legible
    one like `preferred_username`. See the config note for what that trades
    away -- this function only enforces that the choice actually produced a
    usable identifier.
    """
    if not user_token:
        raise HTTPException(401, "user-auth is on: a user OIDC token is required")
    try:
        claims = oidc.validate_user_claims(user_token)
    except oidc.InvalidUserToken as exc:
        raise HTTPException(401, f"invalid user token: {exc}")
    subject = claims.get(config.OIDC_SUBJECT_CLAIM)
    # FAIL CLOSED, and do NOT quietly fall back to `sub`. A fallback would put
    # two identifier spaces -- UUIDs and usernames -- into the same ownership
    # column, where a comparison between them silently never matches: the user
    # would simply stop seeing their own agents, with no error to explain it.
    if not isinstance(subject, str) or not subject.strip():
        log.error("user token carries no usable %r claim (claims present: %s)",
                  config.OIDC_SUBJECT_CLAIM, sorted(claims))
        raise HTTPException(
            401,
            f"the user token carries no usable {config.OIDC_SUBJECT_CLAIM!r} "
            "claim, so this caller has no identity to own or act as. Either "
            "configure the IdP to emit that claim, or point "
            "ANDYUR_OIDC_SUBJECT_CLAIM at one it does emit.")
    subject = subject.strip()
    # Bounded like every other identifier that reaches a row or a token: the
    # same limit `acting_user` is validated against on the trigger path, so a
    # value that authenticates here cannot fail to fit there.
    if len(subject) > MAX_ACTING_USER_CHARS:
        raise HTTPException(
            401,
            f"the {config.OIDC_SUBJECT_CLAIM!r} claim is longer than "
            f"{MAX_ACTING_USER_CHARS} characters and cannot be used as an identity")
    return subject, _is_admin(claims), claims


def _authed_user(user_token: str | None) -> str:
    """Validate the caller's OIDC token and return the user (sub), or 401 (U3)."""
    return _authed_principal(user_token)[0]


def _owner_gate(name: str, user_token: str | None) -> None:
    """U3 cross-user isolation: when user-auth is on, the authenticated user must OWN
    the agent, else 404 -- a non-owner cannot even learn the agent exists (no
    existence oracle). An ADMIN passes: visibility and lifecycle over every
    owner's agents is what the role grants (it still cannot trigger, see
    trigger_agent). A no-op when user-auth is off."""
    if not config.USER_AUTH:
        return
    user, is_admin = _authed_principal(user_token)
    if is_admin:
        return
    with db.connect() as conn:
        row = conn.execute("SELECT owner FROM agents WHERE name = ?", (name,)).fetchone()
    if row is None or row["owner"] != user:
        raise HTTPException(404, f"no agent named '{name}'")


# ---- run views -----------------------------------------------------------------
# The runs table carries one secret (subject_token, the user's own login token,
# served only by GET /runs/{id}/subject-token to the run's SVID) beside the run
# facts. Every route that returns a run row goes through run_view, so the
# secret cannot leave by any of them: GET /runs/{id} was `SELECT *` and handed
# it to any operator caller.
#
# THE PROJECTION IS AN ALLOW-LIST, and that is the point of it. It was a
# deny-list naming the one secret, which meant every column added afterwards
# was published by DEFAULT. `parent_run_id` was added for the workflow graph
# and immediately handed one owner the run id of another owner's run, on the
# row of a run they legitimately own -- the very id the elided node beside it
# exists to withhold. Naming one more column in a deny-list would have fixed
# that instance and left the trap armed for the next column. So: nothing
# reaches a client unless it is listed here, and `_RUN_WITHHELD` says why for
# each one that is not. tests pin the two against the live table, so a new
# column cannot be added without deciding which side it is on.
_RUN_WITHHELD = {
    # The user's own login token, served only by GET /runs/{id}/subject-token
    # to the run's own SVID.
    "subject_token": "a credential",
    # The run that woke this one. It is another owner's run id whenever the
    # delegation crossed an owner boundary, and the flow graph computes edges
    # from it SERVER-SIDE, so no client needs it.
    "parent_run_id": "another owner's run id; the flow graph resolves it server-side",
    # The key the run fence adopts by (ADR-014 D11). It grants nothing alone --
    # adopting takes the execution worker's identity -- but no client needs
    # it, and an identifier that names a runtime generation is not a run fact.
    "execution_generation": "the runtime generation the engine's fence adopts by",
}
_RUN_VIEW_FIELDS = frozenset({
    "id", "agent", "run_type", "state", "reason", "summary", "error",
    "created_at", "started_at", "finished_at", "worker", "trace_ctx",
    "workflow_id", "depth", "assigned_at", "acting_user", "user_asserted_by",
    "scope", "subject_context", "registry_digest", "runtime_resolution",
    "ceiling_audiences", "pin_asserted_by", "revoked_at", "heartbeat_at",
    "conv_read_cursor", "input", "dispatch",
    # Which orchestration provider the run is bound to: a run fact, like its
    # dispatch mode, and what an operator reads to know which engine holds it.
    "orchestration_provider",
    # The kind it was admitted as, and when its provider acknowledged the
    # start: run facts an operator reads to see why a run is (or is not yet)
    # moving (provider draft R6.6).
    "workflow_kind", "provider_acked_at",
})
# Columns a JOIN adds for gating, never part of the run's own facts.
_RUN_JOIN_COLUMNS = frozenset({"agent_owner"})
# What a LIST row carries. Bodies (captured stdout, bounded at
# MAX_SUMMARY_CHARS; the sealed input; the runtime document) belong to the row
# route; fifty of them in one page exceeded the console's 16 MiB response cap.
#
# `scope` is here because no list shows it -- the console's Runs table and the
# CLI's `agents runs` both render id, agent, protocol, state, reason and time --
# and a scope is a caller-supplied list of strings, so leaving it in the page
# meant an unbounded field nothing read.
_RUN_LIST_OMIT = frozenset({"summary", "error", "input", "runtime_resolution",
                            "ceiling_audiences", "subject_context", "trace_ctx",
                            "scope"})
# `reason` IS rendered in the list, so it cannot simply be dropped -- and it is
# the one caller-supplied string left on the page. A page carries at most
# _RUNS_PAGE_MAX rows, so this bound is what keeps a page under the console's
# response cap no matter what any row holds: 200 x 512 chars is 100 KiB.
# The bound at the boundary (MAX_REASON_CHARS) stops a long reason being stored
# at all; this one is what protects a page from a row that is ALREADY stored,
# which no input validation can undo.
_LIST_REASON_CHARS = 512


def _trace_id(trace_ctx: str | None) -> str | None:
    """The 32-hex trace id out of a stored W3C traceparent, or None."""
    if not trace_ctx:
        return None
    parts = trace_ctx.split("-")
    return parts[1] if len(parts) == 4 and len(parts[1]) == 32 else None


def run_view(row) -> dict:
    """The ONE projection of a run row: the facts on `_RUN_VIEW_FIELDS` and
    nothing else, plus the trace id a console can link to and the interface a
    page shows as the protocol. Consumers that read their own run (the runner's
    trace_ctx, the CLI's state/summary/error) keep every field they use;
    anything not listed is withheld by default, with `_RUN_WITHHELD` naming
    why."""
    out = {k: v for k, v in dict(row).items() if k in _RUN_VIEW_FIELDS}
    out["trace_id"] = _trace_id(out.get("trace_ctx"))
    # Derived here, on EVERY run view, so the page has one reader of it. When
    # only the list carried it, the page fell back to parsing
    # runtime_resolution itself -- a second parser, on the one view that no
    # longer has the column, so every list row read as `native`.
    out["interface_version"] = _interface_version(out)
    return out


def run_list_view(row) -> dict:
    """A run as one row of a list: run_view without the bodies, and with the
    one rendered free-text field bounded, so a page's size depends on the page
    limit and nothing else."""
    full = run_view(row)
    out = {k: v for k, v in full.items() if k not in _RUN_LIST_OMIT}
    reason = out.get("reason")
    if isinstance(reason, str) and len(reason) > _LIST_REASON_CHARS:
        out["reason"] = reason[:_LIST_REASON_CHARS] + "…"
    return out


# The columns a LIST row is BUILT from: what it publishes, plus the two the
# projection derives from and then drops. Named in the query instead of
# `SELECT r.*`, because selecting everything and dropping it afterwards still
# materialises every summary, input and runtime document for limit+1 rows
# first: measured 1,887 MiB peak to serve 83 KB on `?limit=200`, which is the
# page the console loads by default and needs no adversary to reach -- 200
# finished runs with ordinary summaries is a working platform.
#
# Derived here from the projection so the two cannot drift: adding a field to
# the list view without adding it here would return it as NULL.
_RUN_LIST_COLUMNS = tuple(sorted(
    (_RUN_VIEW_FIELDS - _RUN_LIST_OMIT) | {"trace_ctx", "runtime_resolution"}))
# The GRAPH's columns: the same list row, plus the two the route needs to build
# edges and to decide visibility and which it never returns. It was `SELECT r.*`
# for up to 401 rows across the two owner buckets, which made this route's cost
# depend on a bound two modules away (FinishBody's max_length) rather than on
# its own projection -- the same shape as an edge's `reason` resting on
# TaskCreateBody.title.
_FLOW_RUN_COLUMNS = tuple(sorted(set(_RUN_LIST_COLUMNS) | {"parent_run_id"}))


def _interface_version(row: dict) -> str | None:
    """The protocol a run was launched under, read from its stored runtime
    resolution. Tolerant of anything in that column: it is TEXT, and SQLite
    will hand back whatever type was written. A row this cannot parse must not
    take out the page it appears on."""
    try:
        parsed = json.loads(row.get("runtime_resolution") or "{}")
    except (ValueError, TypeError):
        return None
    return parsed.get("interface_version") if isinstance(parsed, dict) else None


def _visible_owner(user_token: str | None) -> str | None:
    """The owner a caller may see: None for everyone (user-auth off, or an
    admin), else the caller's sub. Authenticates FIRST, so a bad token is a
    401 whether or not the thing exists. The one rule every run route and the
    agents list apply."""
    if not config.USER_AUTH:
        return None
    user, is_admin = _authed_principal(user_token)
    return None if is_admin else user


def _run_owner_gate(run_id: str, user_token: str | None) -> dict:
    """The run's row, if the caller may read it. Mirrors _owner_gate: the
    caller must own the run's AGENT (or be an admin), else 404 with no
    existence oracle. Returns the row so callers do not select it twice."""
    owner = _visible_owner(user_token)
    with db.connect() as conn:
        row = conn.execute(
            "SELECT r.*, a.owner AS agent_owner FROM runs r "
            "JOIN agents a ON a.name = r.agent WHERE r.id = ?", (run_id,)).fetchone()
    if row is None or (owner is not None and row["agent_owner"] != owner):
        raise HTTPException(404, f"no run '{run_id}'")
    return dict(row)


def _admin_gate(user_token: str | None, *, alternative: str = "") -> None:
    """Ops surfaces (workers, workflow halt) are admin-only under user-auth.
    403, not 404: these are fixed routes, not named resources, so there is no
    existence to hide, and auth.py already answers role refusals with 403.

    A caller presenting NO user token under user-auth is the RAW OPERATOR SEAM --
    the CLI / infra operator on the host, already proven operator by
    auth.require(OPERATOR) above this. It is allowed, because the operator SVID
    is host-level infrastructure identity and the emergency kill switch
    (halt/workers) must not become browser-only. This does NOT open a browser
    hole: the console BFF is the only path that bridges a browser to the operator
    SVID, and when it has a user session it ALWAYS attaches the user token, so a
    browser user's ops call carries a token and gets the role check. Owner-scoped
    routes are deliberately stricter (see _owner_gate): those need to know WHICH
    user, so a missing token there is 401, not an infra pass."""
    if not config.USER_AUTH or user_token is None:
        return
    sub, is_admin = _authed_principal(user_token)
    if not is_admin:
        # Name the role and claim so "why am I not admin" is debuggable without
        # decoding the token by hand.
        log.info("admin surface refused for user %r: no %r in claim %r",
                 sub, config.ADMIN_ROLE, config.ROLES_CLAIM)
        # A refusal that does not say what to do instead reads as a bug. The
        # owner-facing equivalent of an ops surface is a real control, not a
        # consolation: say which one, so the caller is not left believing the
        # platform has no answer for them.
        raise HTTPException(
            403, f"this surface requires the {config.ADMIN_ROLE!r} role "
                 f"(from the {config.ROLES_CLAIM!r} claim)"
                 + (f". {alternative}" if alternative else ""))


class CeilingBody(Body):
    # `None` clears the term (unrestricted); `[]` denies everything for it. The
    # two are deliberately distinct and both reachable, because "I never set a
    # limit" and "I set the limit to nothing" are different operator intents.
    actions: list[str] | None = None
    audiences: list[str] | None = None


@app.delete("/agents/{name}")
def delete_agent(name: str, force: bool = False,
                 _id: str = auth.require(auth.OPERATOR),
                 x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Delete an agent and everything in its namespace.

    Andyur could create agents and never remove them, which made every experiment
    permanent and every demo a reason to stand up a throwaway database instead of
    using the real one. That is the wrong trade: a product people cannot clean up
    is a product people stop testing.

    REFUSES WHILE A RUN IS LIVE, including when `force=true`. A run in flight has a runner
    process holding a token for this agent, and deleting the row underneath it
    turns a clean refusal into an untracked execution. `force` remains accepted
    for API compatibility but cannot bypass execution teardown; halt the run and
    wait for its terminal state before deleting its namespace.

    Deletion is DELIBERATELY CASCADING. An agent's runs, tasks, messages, turns,
    schedules, mind files, and memory graph are its namespace, not independent
    records that happen to mention it, and leaving them behind would let a
    recreated agent of the same name inherit a dead one's history."""
    # An admin may delete any owner's agent (cleanup is lifecycle, not
    # impersonation); a plain user only their own.
    deleting_user: str | None = None
    if config.USER_AUTH:
        user, is_admin = _authed_principal(x_andyur_user_token)
        deleting_user = None if is_admin else user
    removed = {}
    with db.connect() as conn:
        # Lock the agent row BEFORE checking liveness and retain that lock through
        # deletion. Postgres FK inserts take a conflicting key-share lock; SQLite
        # has no row locks, so a no-op write obtains its single writer lock. A
        # trigger can therefore happen before this transaction or after it, never
        # between the live-run decision and the delete it protects.
        if db.IS_POSTGRES:
            agent_row = conn.execute(
                "SELECT owner FROM agents WHERE name = ? FOR UPDATE", (name,)
            ).fetchone()
        else:
            locked = conn.execute(
                "UPDATE agents SET paused = paused WHERE name = ?", (name,)
            ).rowcount > 0
            agent_row = (conn.execute(
                "SELECT owner FROM agents WHERE name = ?", (name,)
            ).fetchone() if locked else None)
        if agent_row is None:
            raise HTTPException(404, f"no agent named '{name}'")
        if deleting_user is not None and agent_row["owner"] != deleting_user:
            # Same non-oracle answer as the other ownership gates. Crucially,
            # this comparison is against the row we locked and will delete.
            raise HTTPException(404, f"no agent named '{name}'")
        live = conn.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = ? "
            "AND state IN ('pending', 'running')", (name,),
        ).fetchone()["n"]
        if live:
            raise HTTPException(
                409, f"agent '{name}' has {live} live run(s); finish or halt them "
                "and wait for a terminal state before deleting")
        for table, where in (("runs", "agent = ?"), ("schedules", "agent = ?"),
                             ("mind_versions", "agent = ?"),
                             ("tasks", "assignee = ? OR creator = ?"),
                             ("messages", "sender = ? OR recipient = ?"),
                             ("conversation_turns", "sender = ?")):
            params = (name,) * where.count("?")
            cur = conn.execute(f"DELETE FROM {table} WHERE {where}", params)
            removed[table] = cur.rowcount
        removed["agents"] = conn.execute(
            "DELETE FROM agents WHERE name = ?", (name,)).rowcount
    # Outside the transaction on purpose. These are separate stores, so they
    # cannot join the database's atomicity; doing them after the commit means the
    # worst case is orphaned FILES, which an operator can find and remove. Doing
    # them before would mean a failed commit had already destroyed the mind of an
    # agent that still exists.
    try:
        removed["mind_files"] = workspace.delete_agent_files(name)
    except Exception as exc:                      # noqa: BLE001
        log.error("agent %s deleted, but its mind files did not: %s", name, exc)
        removed["mind_files"] = -1
    try:
        removed["graph_nodes"] = graph.forget_agent(name)
    except Exception as exc:                      # noqa: BLE001
        log.error("agent %s deleted, but its graph nodes did not: %s", name, exc)
        removed["graph_nodes"] = -1
    log.warning("operator DELETED agent %s (force=%s): %s", name, force, removed)
    return {"deleted": name, "removed": removed}


@app.put("/agents/{name}/ceiling")
def set_agent_ceiling(name: str, body: CeilingBody,
                      _id: str = auth.require(auth.OPERATOR),
                      x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Set the hard limit on what this agent may EVER hold, whatever its user is
    entitled to (see registry.py). No run-token path: a ceiling its holder can
    raise is not a ceiling. Owner-or-admin under user-auth (same gate as the
    read): rewriting another tenant's ceiling is the highest-authority
    cross-tenant action there is -- `{"actions": []}` bricks their agent,
    `{"actions": null}` widens its hard maximum -- so it must be gated at least
    as strongly as reading it, not left open while the read is closed.

    This exists because the ceiling became a term the token mint enforces on every
    call, and until now the only way to configure one was to hand-edit JSON into
    `agents.ceiling_actions` with no validation -- where a typo reads back as
    DENY_ALL and bricks the agent. A control that is enforced automatically and
    configured manually is a control that will be wrong."""
    _owner_gate(name, x_andyur_user_token)
    with db.connect() as conn:
        agent = conn.execute(
            "SELECT registry_agent_id FROM agents WHERE name = ?", (name,)
        ).fetchone()
    if agent is None:
        raise HTTPException(404, f"no agent named '{name}'")
    if agent["registry_agent_id"] is not None:
        raise HTTPException(
            409,
            f"agent '{name}' is registry-bound; its ceiling is controlled by "
            f"registry definition {agent['registry_agent_id']!r}",
        )
    try:
        registry.set_ceiling(name, actions=body.actions, audiences=body.audiences)
    except ValueError as exc:
        # Both the unknown-agent case and a malformed term land here; the message
        # from the registry says which.
        raise HTTPException(404 if "no such agent" in str(exc) else 400, str(exc))
    log.warning("operator set the ceiling for %s: actions=%s audiences=%s",
                name, body.actions, body.audiences)
    return {"agent": name, **registry.get_ceiling(name)}


@app.get("/agents/{name}/ceiling")
def get_agent_ceiling(name: str, _id: str = auth.require(auth.OPERATOR),
                      x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Read an agent's ceiling. Operator-only: it tells you exactly how far an
    agent can be pushed, which is not something an agent should be able to ask.
    Owner-or-admin under user-auth, for the same reason: another tenant's attack
    surface is not something a user should be able to ask either."""
    _owner_gate(name, x_andyur_user_token)
    with db.connect() as conn:
        if conn.execute("SELECT 1 FROM agents WHERE name = ?",
                        (name,)).fetchone() is None:
            raise HTTPException(404, f"no agent named '{name}'")
    return {"agent": name, **registry.get_ceiling(name)}


@app.post("/agents", status_code=201)
def create_agent(body: AgentCreate, _id: str = auth.require(auth.OPERATOR),
                 x_andyur_user_token: str | None = Header(default=None)) -> dict:
    if body.name in RESERVED_NAMES:
        raise HTTPException(
            400, f"'{body.name}' is reserved: it names a platform role, and an "
            "agent must never be able to answer to one")
    if not NAME_RE.match(body.name):
        raise HTTPException(
            422,
            "agent name must be lowercase alphanumeric with - or _, "
            "starting with a letter",
        )
    resolution = None
    if body.registry_agent_id is not None:
        try:
            resolution = configured_registry().resolve(body.registry_agent_id)
        except AgentNotFound:
            raise HTTPException(
                422, f"unknown registry agent id {body.registry_agent_id!r}")
        except RegistryUnavailable as exc:
            raise HTTPException(503, f"agent registry is unavailable: {exc}")

    # U1: with user-auth on, the agent is OWNED by the user proven by their OIDC
    # token; every run of it later inherits this owner as its `sub`. An admin
    # creating an agent owns it like anyone else -- ownership follows the
    # authenticated subject, never a claimed one.
    owner = _authed_user(x_andyur_user_token) if config.USER_AUTH else None
    now = db.utcnow()
    ceiling_actions = (None if resolution is None or resolution.ceiling.actions is None
                       else json.dumps(list(resolution.ceiling.actions)))
    ceiling_audiences = (
        None if resolution is None or resolution.ceiling.resources is None
        else json.dumps(list(resolution.ceiling.resources))
    )
    try:
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO agents (name, registry_agent_id, description, owner, "
                "created_at, ceiling_actions, ceiling_audiences) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (body.name, body.registry_agent_id, body.description, owner, now,
                 ceiling_actions, ceiling_audiences),
            )
    except db.integrity_errors():
        raise HTTPException(409, f"agent '{body.name}' already exists")

    try:
        workspace.create_agent_files(
            body.name, body.description, body.personality, body.scope
        )
    except FileExistsError:
        # The DB row is new but a mind for this name already exists in storage
        # (orphaned from a prior life, or a concurrent create). Roll the row
        # back so we do not leave a half-created agent, and report the conflict.
        with db.connect() as conn:
            # Only two tables now, and only one of them is written by anything
            # else. The cascade ordering hazard this used to guard against went
            # away with agent_status: there is no second table for a cascade to
            # lock in the wrong order.
            conn.execute("DELETE FROM runs WHERE agent = ?", (body.name,))
            conn.execute("DELETE FROM agents WHERE name = ?", (body.name,))
        raise HTTPException(
            409, f"a mind for agent '{body.name}' already exists in storage"
        )
    profile = workspace.load_profile(body.name)
    return {
        "name": body.name,
        "registry_agent_id": body.registry_agent_id,
        "created_at": now,
        "spiffe_id": profile.get("spiffe_id"),
    }


@app.get("/me")
def whoami_user(_id: str = auth.require(auth.OPERATOR),
                x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Who is this caller, and are they admin? The console UI renders its mode
    from THIS answer and nothing else -- the server still enforces every gate,
    so a client ignoring /me changes what it draws, not what it can do. With
    user-auth off there is no user axis and the single operator IS the admin."""
    if not config.USER_AUTH:
        return {"user_auth": False, "sub": None, "admin": True}
    sub, is_admin = _authed_principal(x_andyur_user_token)
    return {"user_auth": True, "sub": sub, "admin": is_admin}


@app.get("/agents")
def list_agents(_id: str = auth.require(auth.OPERATOR),
                x_andyur_user_token: str | None = Header(default=None)) -> list[dict]:
    # U3: with user-auth on, a user sees only the agents they own; an admin
    # sees every owner's (the `owner` column in the response is what makes an
    # all-owners list readable, and is NULL anyway when user-auth is off).
    owner = None
    if config.USER_AUTH:
        user, is_admin = _authed_principal(x_andyur_user_token)
        owner = None if is_admin else user
    sql = (
        "SELECT a.name, a.owner, a.registry_agent_id, a.description, a.paused, "
        "       a.created_at, "
        "       s.state, s.run_id, s.updated_at AS state_updated_at "
        "FROM agents a JOIN agent_status s ON s.agent = a.name "
    )
    params: tuple = ()
    if owner is not None:
        sql += "WHERE a.owner = ? "
        params = (owner,)
    sql += "ORDER BY a.name"
    with db.connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/agents/{name}")
def get_agent(name: str, _id: str = auth.require(auth.OPERATOR),
              x_andyur_user_token: str | None = Header(default=None)) -> dict:
    _owner_gate(name, x_andyur_user_token)   # U3: 404 for a non-owner
    with db.connect() as conn:
        row = conn.execute(
            """
            SELECT a.name, a.owner, a.registry_agent_id, a.description, a.paused,
                   a.created_at,
                   s.state, s.run_id, s.updated_at AS state_updated_at
            FROM agents a JOIN agent_status s ON s.agent = a.name
            WHERE a.name = ?
            """,
            (name,),
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"no agent named '{name}'")
        recent = conn.execute(
            "SELECT * FROM runs WHERE agent = ? ORDER BY created_at DESC, id DESC LIMIT 5",
            (name,),
        ).fetchall()
    out = dict(row)
    # A DB row can outlive its mind storage -- a half-deleted or storage-drifted
    # agent. Return the row with a null profile (same guard the run-detail
    # endpoint uses for agent_spiffe_id) instead of a 500, so the operator can
    # still see the agent in `show`/`status`/`watch` and delete it, and one
    # corrupt record does not break the whole fleet view.
    try:
        out["profile"] = workspace.load_profile(name)
    except FileNotFoundError:
        out["profile"] = None
    out["recent_runs"] = [run_view(r) for r in recent]
    return out


def _run_trace_ctx(run_id: str):
    """Rebuild the OTel context for a run from its stored traceparent so a
    handler's span nests under the run's distributed trace."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT trace_ctx FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
    return otel.context_from(row["trace_ctx"]) if row else None


@app.post("/agents/{name}/trigger", status_code=201)
def trigger_agent(name: str, body: TriggerBody, _id: str = auth.require(auth.OPERATOR),
                  x_andyur_user_token: str | None = Header(default=None)) -> dict:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT owner FROM agents WHERE name = ?", (name,)
        ).fetchone()
    if row is None:
        raise HTTPException(404, f"no agent named '{name}'")
    # U3: only the owning user may trigger their agent (404 to a non-owner).
    # DELIBERATELY no admin bypass: the run acts as the OWNER and presents the
    # caller's token as its RFC 8693 subject_token, so an admin-triggered run
    # would act as a user whose credential it does not hold. Admin authority is
    # lifecycle, never impersonation.
    if config.USER_AUTH and row["owner"] != _authed_user(x_andyur_user_token):
        raise HTTPException(404, f"no agent named '{name}'")
    # The trigger span is the root of the run's trace; its context is persisted
    # on the run so the runner and later server calls join the same trace.
    # U1: the run acts for the agent's owner. Pass it into wakeup so the run row
    # carries the user from insert AND the per-user conversation cap can be
    # enforced under the same admission lock as the global cap.
    if body.acting_user is not None:
        # Bounded exactly like `audience`, and for the same reason: this value is
        # written into a token's `sub` and into the audit trail, and an audit
        # record the audited party can write is worse than no record. Control
        # characters would let one forged log line become two.
        bad = body.acting_user.strip()
        if (not bad or len(bad) > MAX_ACTING_USER_CHARS
                or any(c in bad for c in "\r\n\t")):
            raise HTTPException(
                422, f"acting_user must be 1-{MAX_ACTING_USER_CHARS} characters "
                     "and contain no "
                     "control characters")
        body = body.model_copy(update={"acting_user": bad})
    if config.USER_AUTH and body.acting_user:
        # The stronger source is present, so the weaker one is an error rather
        # than something to silently ignore: a caller passing it believes it did
        # something.
        raise HTTPException(
            422, "acting_user cannot be asserted while user-auth is on: the run "
                 "acts for the authenticated owner of the agent, from the IdP")
    if body.acting_user and not config.USER_AUTH and not config.ASSERTED_USER:
        # Refused rather than ignored: a caller that passes this believes it set
        # who the run acts for, and silently dropping it would produce a run with
        # no user whose tokens are then refused for a reason that names the wrong
        # thing.
        raise HTTPException(
            422, "asserting acting_user without an IdP is off by default: it "
                 "makes this server sign a token whose subject nobody "
                 "authenticated. Set ANDYUR_ASSERTED_USER=on to allow it, or "
                 "ANDYUR_USER_AUTH=on to take the user from a real login")
    owner = row["owner"] if config.USER_AUTH else body.acting_user
    if owner and not config.USER_AUTH:
        # Logged, because the design says an application asserting this is
        # acceptable ONLY if it is on the record.
        log.info("run for '%s' will act for user %r, asserted by the "
                 "authenticated caller %r (no IdP in this deployment)",
                 name, owner, _id)
    with _tracer.start_as_current_span(f"run {name}") as span:
        span.set_attribute("andyur.agent", name)
        span.set_attribute("andyur.run_type", body.run_type)
        # U2: grant this run the intersection of the user's entitlements and the
        # scope its task declares, BEFORE the run exists.
        #
        # This used to insert the run and then UPDATE its scope. A worker
        # heartbeat landing in that window assigns the run and mints its token
        # from the columns as they stand -- scope NULL -- and the PDP reads a
        # null scope as UNRESTRICTED. So the endpoint whose purpose is to narrow
        # a run's authority could, under ordinary concurrency, hand out a token
        # with none of the narrowing applied. Computing the grant first and
        # passing it into the insert makes the run atomically born with its
        # scope, which is what delegation already did (tasks.create_task).
        granted = _grant_scope(body.scope)
        # THE INPUT, sealed before the run exists for the same reason as the
        # scope: a heartbeat must never assign a run whose input is still to
        # be written. Refusals are 422 -- the request is unusable as sent.
        try:
            sealed_input = runinput.seal(body.input)
        except runinput.InputRefused as exc:
            raise HTTPException(422, str(exc))
        # THE PIN, sealed into the same insert and for the same reason. The
        # asserter is recorded with it: this endpoint only ever runs for a caller
        # the server has already authenticated (operator role, plus the owning
        # user under user-auth), and auth.require rejects a caller presenting a
        # run token before this handler is reached -- so an agent can neither set
        # this nor be named as having set it.
        try:
            run_id, _refusal = orchestration.facade().request_agent_run(
                name, body.reason, body.run_type,
                trace_ctx=otel.current_traceparent(), user=owner, scope=granted,
                subject_context=body.subject_context,
                pin_asserted_by=_pin_asserter(owner, _id),
                run_input=sealed_input,
                # THE SUBJECT TOKEN. The run presents this at the adopter's
                # authorization server as the RFC 8693 `subject_token` -- you
                # cannot present a credential you did not keep, and until now
                # Andyur validated the user's token here and dropped it, which
                # is the whole reason `acting_user` existed as an assertion.
                #
                # Only stored when there is an external AS to present it to.
                # Keeping a user credential that nothing will ever use is a
                # credential at rest for no reason.
                subject_token=(x_andyur_user_token
                               if config.AS_TOKEN_ENDPOINT else None),
        # An IdP-authenticated user, or one an authenticated client merely
        # asserted -- carried onto the run so every grant it mints can say which.
        user_asserted_by=(runtoken.SUB_SRC_IDP if config.USER_AUTH
                          else runtoken.SUB_SRC_ASSERTED),
            )
        except (coordinator.PinRefused, coordinator.InputRefused) as exc:
            # 422, not 409: the request itself is unusable, and a caller retrying
            # it unchanged will be refused forever. A busy agent is the 409.
            raise HTTPException(422, str(exc))
        if run_id is None:
            raise HTTPException(409,
                                f"agent '{name}' is not idle, or a conversation cap was hit")
        span.set_attribute("andyur.run_id", run_id)
        if owner:
            span.set_attribute("andyur.user", owner)
        if granted is not None:
            span.set_attribute("andyur.scope", " ".join(granted))
        if body.subject_context:
            span.set_attribute(
                "andyur.pin",
                " ".join(f"{k}={v}" for k, v in sorted(body.subject_context.items())))
    return {"run_id": run_id, "agent": name}


def _pin_asserter(owner: str | None, caller_id: str) -> str:
    """WHO is on record as having asserted this run's pin.

    Prefixed by KIND, because "alice" and a SPIFFE id are not the same kind of
    claim and an audit that cannot tell them apart cannot answer the only
    question it is asked: was the target chosen by the user, or by the
    application acting on their behalf? An IdP-authenticated user is the stronger
    assertion, so it wins when present; otherwise the authenticated caller of
    this endpoint is named. Neither can ever be an agent -- this endpoint is
    operator-gated and refuses a run token.
    """
    return f"user:{owner}" if owner else f"caller:{caller_id}"


def _grant_scope(requested: list[str] | None) -> list[str] | None:
    """The scope granted to a run. None (no request) => unrestricted.

    Otherwise ask the PDP once per requested scope and keep what it permits. The
    intersection of entitlements and request is no longer an operation this
    module implements -- it is merely what the PDP answers today."""
    if requested is None:
        return None
    subject = pdp.Subject(type="user", entitlements=config.USER_ENTITLEMENTS.split())
    granted = pdp.evaluate_all(subject, requested)
    return [s for s, ok in zip(requested, granted) if ok]


@app.get("/runs/{run_id}/subject-token")
def run_subject_token(run_id: str,
                      ctx: auth.RunCtx = auth.require_run(require_svid=True)) -> dict:
    """The run's own subject token, for the RUNNER to hand to agentgateway.

    THE AGENT MUST NEVER REACH THIS. It is reachable only with a run token
    PLUS the run's own attested per-run SVID (require_svid), and only for the
    run that token names -- `require_run_id` refuses any other run, and the
    operator branch is excluded deliberately: an operator has no use for a
    user's credential and every reason not to hold one. The SVID requirement
    is what bounds a leaked run token: this endpoint returns the user's
    credential, so a bare token replayed from another container must not reach
    it. The runner already presents that SVID on this call, and a deployment
    that cannot present one has no external AS to spend the token at (the
    sidecar withholds every managed tool without an actor SVID), so nothing
    that could use the token is turned away.

    Why an endpoint rather than the environment: the runner already pops
    ANDYUR_RUN_TOKEN out of its env, but in the non-pod shape the agent shares a
    uid with the runner and can read /proc/<pid>/environ before that happens. A
    credential fetched over the run-scoped API is never in an environment at all.

    Returns null rather than 404 when there is none, because "this deployment
    has no external authorization server" is an ordinary state and not an error.
    """
    if ctx.is_operator:
        raise HTTPException(
            403, "a subject token is issued to the run that owns it, not to an "
                 "operator: nothing an operator does needs a user's credential")
    ctx.require_run_id(run_id)
    expected_subject = ctx.user
    if config.AS_PROVIDER == "entra" and ctx.subject_token:
        try:
            claims = oidc.validate_user_claims(ctx.subject_token)
            expected_subject = asproviders.subject_identity("entra", claims)
        except (oidc.InvalidUserToken,
                asproviders.ProviderConfigurationError) as exc:
            raise HTTPException(
                403, f"the run's subject token cannot establish Entra tenant/object "
                     f"continuity: {exc}") from exc
    return {
        "run_id": run_id,
        "subject_token": ctx.subject_token,
        # This value comes from the server-verified run grant / persisted run,
        # not by decoding the bearer below.  The exchange client uses it as the
        # trusted continuity anchor for the downstream token's subject.
        "expected_subject": expected_subject,
        # Derived from authenticated, exact-run state; credentials are only
        # transport and never the source of the expected actor identity.
        "expected_actor": f"{identity.agent_spiffe_id(ctx.agent)}/run/{run_id}",
    }


@app.get("/runs/{run_id}/live")
def run_is_live(
    run_id: str,
    x_andyur_run_token: str | None = Header(default=None),
) -> dict:
    """Is this run still executing? One boolean, for the broker.

    Answers only for the run whose own credential is presented. Left open, this
    is a live-run oracle: "is this run executing right now" for any id is target
    selection, which is precisely the reconnaissance the broker's own /usage
    endpoint refuses to provide. Run ids travel through tasks, messages and
    delegation, so "an attacker would need the id already" was too weak a
    defence to rest on.

    The broker has no identity of its own to present, and does not need one: it
    forwards the credential of the caller that just proved which run it is. So
    the question is only askable by something already holding the answer's
    subject.
    """
    if not x_andyur_run_token:
        raise HTTPException(401, "run liveness requires the run's own credential")
    try:
        ctx = runtoken.verify(x_andyur_run_token, purpose=runtoken.PURPOSE_BROKER)
    except runtoken.InvalidRunToken as exc:
        raise HTTPException(401, f"invalid credential: {exc}")
    if ctx.get("run_id") != run_id:
        # Same status as an invalid token: a distinct error here would confirm
        # that some OTHER run id exists, which is the oracle again by a side door.
        raise HTTPException(401, "credential is not for this run")
    return {"live": coordinator.run_is_live(run_id)}


def run_broker_state(
    run_id: str, ctx: auth.RunCtx,
) -> dict:
    """One atomic, authenticated authority snapshot for the deny-only broker.

    The initial response is frozen into ``SealedAuthorityEnvelope`` by the
    broker process.  Every readiness/authz decision fetches it again and
    compares the complete snapshot.  Request bytes and credentials authenticate
    transport only; they never supply an expected subject, actor, audience,
    registry digest, action, or pin.
    """
    ctx.require_run_id(run_id)
    with db.connect() as conn:
        row = conn.execute(
            "SELECT r.agent, r.state, r.acting_user, r.scope, "
            "r.subject_context, r.registry_digest, r.ceiling_audiences "
            "FROM runs r WHERE r.id = ?", (run_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(404, f"no run '{run_id}'")
    def closed_json(value):
        return json.loads(
            value,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {token}")),
        )

    try:
        actions = closed_json(row["scope"]) if row["scope"] is not None else None
        pin = (closed_json(row["subject_context"])
               if row["subject_context"] is not None else None)
        audiences = closed_json(row["ceiling_audiences"])
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HTTPException(503, "persisted broker authority is malformed") from exc
    digest = row["registry_digest"]
    if isinstance(digest, str) and digest.startswith("sha256:"):
        digest = digest.removeprefix("sha256:")
    actor = f"{identity.agent_spiffe_id(row['agent'])}/run/{run_id}"
    return {
        "schema": "andyur.deny-broker-state/v1",
        "run_id": run_id,
        "agent": row["agent"],
        "live": row["state"] in ("pending", "running"),
        # A system-owned run without a delegated user is still a concrete
        # principal for deny-only custody.  This value can never become an AS
        # subject unless a later issuance slice explicitly qualifies it.
        "expected_subject": row["acting_user"] or actor,
        "expected_actor": actor,
        "registry_sha256": digest,
        "audiences": audiences,
        "actions": actions,
        "pin": pin,
    }


@app.get("/runs/{run_id}")
def get_run(run_id: str, ctx: auth.RunCtx = auth.require_run(),
            x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """A run's facts. A run reads its own (run token); an operator reads any,
    owner-gated under user-auth. Through run_view, so the subject token never
    leaves by this route."""
    ctx.require_run_id(run_id)
    if ctx.is_operator:
        row = _run_owner_gate(run_id, x_andyur_user_token)
    else:
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise HTTPException(404, f"no run '{run_id}'")
    out = run_view(row)
    try:
        out["agent_spiffe_id"] = workspace.load_profile(out["agent"]).get("spiffe_id")
    except FileNotFoundError:
        out["agent_spiffe_id"] = None
    return out


_RUNS_PAGE_DEFAULT, _RUNS_PAGE_MAX = 50, 200


def _encode_cursor(created_at: str, run_id: str) -> str:
    """An OPAQUE page cursor: base64url over the keyset, no reserved URL
    characters, so a client that forgets to percent-encode it cannot turn
    "+00:00" into a space and get a silently empty page."""
    import base64
    raw = json.dumps([created_at, run_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(token: str) -> tuple[str, str]:
    import base64
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        parsed = json.loads(raw)
        # The SHAPE first. Unpacking any 2-length iterable admitted a 2-char
        # JSON string ("ab" -> "a", "b") and a 2-key object (its keys), both of
        # which then produced the silently empty page this cursor exists to
        # rule out.
        if not isinstance(parsed, list) or len(parsed) != 2:
            raise ValueError
        created_at, run_id = parsed
        if not isinstance(created_at, str) or not isinstance(run_id, str) \
                or not created_at or not run_id:
            raise ValueError
    except (ValueError, TypeError):
        raise HTTPException(422, "before must be the `next` cursor of a previous page") from None
    return created_at, run_id


@app.get("/runs")
def list_runs(agent: str | None = None, state: str | None = None,
              limit: int = Query(_RUNS_PAGE_DEFAULT, ge=1, le=_RUNS_PAGE_MAX),
              before: str | None = Query(None, max_length=512),
              _id: str = auth.require(auth.OPERATOR),
              x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Run history across agents, newest first, keyset-paginated on
    (created_at, id). Owner-filtered exactly as GET /agents is. Rows are the
    list projection (no bodies). `next` is an opaque cursor; pass it back as
    `before` for the page after it."""
    with _decision_span("server.list_runs") as span:
        return _list_runs(agent, state, limit, before, x_andyur_user_token, span)


def _list_runs(agent, state, limit, before, x_andyur_user_token, span) -> dict:
    owner = _visible_owner(x_andyur_user_token)
    where, params = [], []
    if owner is not None:
        where.append("a.owner = ?"); params.append(owner)
    if agent is not None:
        where.append("r.agent = ?"); params.append(agent)
    if state is not None:
        where.append("r.state = ?"); params.append(state)
    if before is not None:
        span.reason = "invalid"                 # if _decode_cursor refuses below
        created, rid = _decode_cursor(before)
        span.reason = None                      # ...it did not
        # A row-value comparison, so the walk is total and a page boundary can
        # never repeat or skip a row. Needs SQLite >= 3.15 (2016); see the
        # floor declared in pyproject.toml.
        where.append("(r.created_at, r.id) < (?, ?)")
        params += [created, rid]
    columns = ", ".join(f'r."{c}"' for c in _RUN_LIST_COLUMNS)
    sql = (f"SELECT {columns} FROM runs r JOIN agents a ON a.name = r.agent "
           + ("WHERE " + " AND ".join(where) + " " if where else "")
           + "ORDER BY r.created_at DESC, r.id DESC LIMIT ?")
    with db.connect() as conn:
        rows = conn.execute(sql, (*params, limit + 1)).fetchall()
    page = [run_list_view(r) for r in rows[:limit]]
    nxt = _encode_cursor(page[-1]["created_at"], page[-1]["id"]) if len(rows) > limit else None
    span.set_attribute("andyur.outcome", "allowed")
    span.set_attribute("andyur.runs.returned", len(page))
    span.set_attribute("andyur.runs.owner_scoped", owner is not None)
    return {"runs": page, "next": nxt}


def _transcript_text(run_id: str, user_token: str | None) -> str:
    """The run's transcript as the runner wrote it (redacted NDJSON), for a
    caller the owner gate admits. exec/v1 runs capture stdout into the run's
    summary instead and never have one; that 404 says so by name."""
    row = _run_owner_gate(run_id, user_token)
    text = workspace.read_text(row["agent"], workspace.transcript_path(run_id))
    if text is None:
        if _interface_version(row) == RUNTIME_PROTOCOL_EXEC_V1:
            raise HTTPException(404, "no transcript: exec/v1 runs capture stdout only")
        raise HTTPException(404, f"no transcript yet for run '{run_id}'")
    return text


@app.get("/runs/{run_id}/transcript")
def get_run_transcript(run_id: str, _id: str = auth.require(auth.OPERATOR),
                       x_andyur_user_token: str | None = Header(default=None)):
    from fastapi.responses import PlainTextResponse
    # application/x-ndjson is the de facto type for newline-delimited JSON;
    # it is not IANA-registered (application/jsonl is in registration).
    return PlainTextResponse(_transcript_text(run_id, x_andyur_user_token),
                             media_type="application/x-ndjson")


def _block_kind(block: dict) -> str:
    """dataclasses.asdict drops the class, so a block is known by its keys."""
    if "tool_use_id" in block:
        return "tool_result"
    if "input" in block and "name" in block:
        return "tool_use"
    if "thinking" in block:
        return "thinking"
    if "text" in block:
        return "text"
    return "other"


def exchanges_from_transcript(text: str) -> list[dict]:
    """Project transcript records into typed exchanges, in order: the human
    turns, each model reply (its blocks, model and usage), and each tool call
    paired with its result by tool_use_id. Content is exactly what the runner
    recorded (already redacted); nothing is read from telemetry."""
    out: list[dict] = []
    # unmatched tool calls by id, oldest first: a result binds to the first
    # call that has none (an id used twice is the runner's bug, not a crash)
    pending: dict[str, list[dict]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(rec, dict):
            continue                       # a corrupt line hides itself, not the record
        if "human" in rec:
            out.append({"kind": "turn", "seq": rec.get("turn"), "text": str(rec["human"])})
            continue
        kind, data = rec.get("type"), rec.get("data")
        if not isinstance(data, dict):
            data = {}
        content = data.get("content")
        blocks = [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []
        if kind == "AssistantMessage":
            shown = []
            for b in blocks:
                bk = _block_kind(b)
                if bk == "tool_use":
                    call = {"kind": "tool", "tool_use_id": b.get("id"),
                            "name": _tool_name(b.get("name")),
                            "input": b.get("input"), "result": None, "is_error": None}
                    pending.setdefault(str(b.get("id")), []).append(call)
                    out.append(call)
                    shown.append({"type": "tool_use", "id": b.get("id"), "name": b.get("name")})
                elif bk == "text":
                    shown.append({"type": "text", "text": b.get("text")})
                elif bk == "thinking":
                    shown.append({"type": "thinking"})
            out.append({"kind": "model", "model": data.get("model"), "blocks": shown,
                        "usage": data.get("usage"), "stop_reason": data.get("stop_reason")})
        elif kind == "UserMessage":
            for b in blocks:
                waiting = pending.get(str(b.get("tool_use_id"))) if _block_kind(b) == "tool_result" else None
                if waiting:
                    call = waiting.pop(0)
                    call["result"] = b.get("content")
                    call["is_error"] = b.get("is_error")
        elif kind == "ResultMessage":
            out.append({"kind": "result", "is_error": data.get("is_error"),
                        "num_turns": data.get("num_turns"), "duration_ms": data.get("duration_ms"),
                        "total_cost_usd": data.get("total_cost_usd")})
    return out


# A caller-supplied identifier echoed back in a refusal. Bounded so a
# multi-kilobyte path parameter cannot become a multi-kilobyte response, and so
# nothing downstream of that message is handed an unbounded string.
_ECHO_ID_CHARS = 64


class _Decision:
    """One route's decision: the span, plus the reason the handler chose."""

    __slots__ = ("span", "reason")

    def __init__(self, span) -> None:
        self.span = span
        self.reason: str | None = None

    def set_attribute(self, key: str, value) -> None:
        self.span.set_attribute(key, value)


@contextlib.contextmanager
def _decision_span(name: str):
    """A span for one route's decision, with the refusal recorded BY NAME and
    nothing the caller typed.

    record_exception is OFF for the same reason everywhere it is used here: an
    HTTPException raised inside a span is otherwise recorded with its message
    and a stack trace, and a refusal's message routinely echoes the caller's
    own input. The span says what was decided; the caller gets their string back
    and telemetry does not.

    The control plane has no ObservedASGI, so without this the routes this lane
    added -- their boundary refusals and their 422s -- produce no server span at
    all. Mounting request-level instrumentation across every control-plane route
    is a platform change and is `ROADMAP.md` gap 29.
    """
    with _tracer.start_as_current_span(
            name, record_exception=False, set_status_on_exception=False) as span:
        decision = _Decision(span)
        try:
            yield decision
        except HTTPException as refusal:
            span.set_attribute("andyur.outcome", "refused")
            span.set_attribute("http.response.status_code", refusal.status_code)
            # The reason the handler named, else one derived from the status.
            # Read from the handler and never back off the span: with telemetry
            # off a span is a NonRecordingSpan that exposes no attributes, so a
            # handler that HAD set the reason would look like one that had not,
            # in exactly the configuration nobody is watching.
            span.set_attribute("andyur.reason", decision.reason or (
                "invalid" if refusal.status_code < 500 else "unavailable"))
            span.set_status(Status(StatusCode.ERROR, f"refused {refusal.status_code}"))
            raise


def _short_id(value: str) -> str:
    return value if len(value) <= _ECHO_ID_CHARS else value[:_ECHO_ID_CHARS] + "\u2026"


def _flow_item(row, keys: tuple) -> dict:
    """One task or message as the graph shows it, with its free text bounded.

    `detail`, `result` and `body` are caller-supplied and unbounded, and a
    workflow may hold any number of FINISHED items -- which the delegation cap
    does not count. The graph shows them as context beside an edge; the whole
    of one belongs to its own route.
    """
    out = {}
    for key in keys:
        value = row[key]
        if isinstance(value, str):
            value = _clip_bytes(value, _FLOW_ITEM_BYTES)
        out[key] = value
    return out


def _clip_bytes(value: str, limit: int) -> str:
    """`value` truncated so its JSON ENCODING is at most about `limit` bytes.

    Measured on the encoding rather than on `len()`, because that is what the
    response is made of and what the console's own body cap counts. A string of
    control characters is one character each and six bytes each once escaped,
    so a character bound understates the wire cost sixfold.
    """
    if len(json.dumps(value)) - 2 <= limit:
        return value
    kept, size = [], 0
    for ch in value:
        size += len(json.dumps(ch)) - 2
        if size > limit:
            break
        kept.append(ch)
    return "".join(kept) + "\u2026"


def _tool_name(raw) -> str:
    """A tool's display name, normalised HERE and nowhere else.

    A transcript block only has to CARRY `name`; nothing requires it to be a
    string. The counts and the page were each coercing it their own way (`str`
    on one side, JavaScript string coercion on the other), so the same call
    became two different graph nodes.
    """
    return raw if isinstance(raw, str) and raw else "tool"


# A run may write its own transcript, so its size is agent-controlled. The flow
# graph reads EVERY visible run's transcript in one request, so an unbounded
# read there is one agent turning one page view into a multi-hundred-megabyte
# allocation. The row route (/runs/{id}/exchanges) reads one run for one reader
# and keeps the full text; this bound is the GRAPH's.
_FLOW_TRANSCRIPT_BYTES = 512 * 1024
# ...and a budget for the whole REQUEST, because the per-file cap alone still
# multiplies by the run count: 200 runs at the per-file cap is 100 MiB held at
# once, and one operator can ask for that as fast as the page will let them.
# When the budget runs out the remaining nodes are drawn WITHOUT their counts
# and the response says so, rather than the request growing to fit the data.
_FLOW_READ_BUDGET = 8 * 1024 * 1024
# Distinct model and tool names drawn for one run. Names come from the
# transcript, so their cardinality is agent-controlled too, and every one of
# them is a node in the response and a lane in the SVG.
_FLOW_MAX_KEYS = 32
# Runs drawn in one graph. A workflow is bounded by the delegation depth cap in
# DEPTH, not in breadth, so nothing else bounds this.
_FLOW_MAX_RUNS = 200
# Tasks and messages are the OTHER two tables this route reads whole, and the
# cheapest request that hurt was 112 bytes: one run plus 500 closed tasks and
# 500 read messages returned 1.05 GB and took the process to 3.6 GiB, because
# neither query had a LIMIT and `detail`, `result` and `body` had no bound.
# MAX_WORKFLOW_RUNS counts none of it -- it counts only NON-TERMINAL work -- so
# a workflow can hold any number of finished items.
_FLOW_MAX_ITEMS = 200
# ...and the payloads themselves, in the graph only. The panel shows a task's
# detail as context beside its edge; the whole of it belongs to the task route.
#
# BYTES, not characters, because the RESPONSE is bytes: a control character is
# one character in and six bytes out as a JSON escape, so a "4096-character"
# detail measured 24,581 bytes on the wire and the documented cap understated
# the real answer sixfold.
_FLOW_ITEM_BYTES = 2048
# A model or tool NAME comes out of a transcript the run wrote, so its LENGTH
# is agent-controlled too. _FLOW_MAX_KEYS bounds how many distinct names one
# node may carry and said nothing about how long each may be: thirty-two names
# at 16 KiB each was half a megabyte in a single node.
_FLOW_KEY_CHARS = 128
# A transcript of millions of tiny lines spends the byte budget on parse calls
# rather than on content: 4.2 million failed json.loads for a 121 KB response,
# 5.2 s of CPU. The byte budget bounds bytes; this bounds WORK PER BYTE.
_FLOW_MAX_LINES = 20000


def exchange_counts(text: str) -> dict:
    """The shape of a run's exchanges without their content: model calls by
    model and tool calls by tool name, for a graph that must not fetch every
    transcript's body to draw its nodes."""
    models: dict[str, int] = {}
    tools: dict[str, int] = {}
    truncated = False

    def tally(bucket: dict, key: str) -> None:
        nonlocal truncated
        # A model or tool NAME comes out of the transcript the run wrote, so
        # its LENGTH is agent-controlled as well as its cardinality.
        if len(key) > _FLOW_KEY_CHARS:
            key = key[:_FLOW_KEY_CHARS] + "\u2026"
            truncated = True
        if key not in bucket and len(bucket) >= _FLOW_MAX_KEYS:
            truncated = True                   # named, never silently dropped
            return
        bucket[key] = bucket.get(key, 0) + 1

    # Counted LINE BY LINE, never through exchanges_from_transcript. That
    # function builds the full exchange list -- every text block, every tool
    # input and every tool result body -- and this needs two small dicts of
    # integers from it. The graph reads many transcripts in one request, so the
    # peak was the sum of every run's fully-materialised exchanges to produce a
    # few hundred bytes of counts.
    for lineno, line in enumerate(text.splitlines()):
        if lineno >= _FLOW_MAX_LINES:
            truncated = True
            break
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(rec, dict) or rec.get("type") != "AssistantMessage":
            continue
        data = rec.get("data")
        if not isinstance(data, dict):
            data = {}
        tally(models, data.get("model") or "model")
        content = data.get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            if isinstance(b, dict) and _block_kind(b) == "tool_use":
                tally(tools, _tool_name(b.get("name")))
    return {"models": models, "tools": tools, "truncated": truncated}


@app.get("/runs/{run_id}/exchanges")
def get_run_exchanges(run_id: str, _id: str = auth.require(auth.OPERATOR),
                      x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """What the run exchanged with its model and its tools, from the run's own
    transcript and nothing else (tool payloads are kept out of spans by
    default, and the run event plane forbids content)."""
    return {"run_id": run_id,
            "exchanges": exchanges_from_transcript(_transcript_text(run_id, x_andyur_user_token))}


# --- consequential actions (board rows 9-12) --------------------------------
#
# THE THREE ROUTES THAT MAKE THE CLAIM DEMONSTRABLE. An agent asks (with its run
# token, from inside its own containment); an operator reads what Andyur decided
# (from the console, over HTTP, with no database); and an operator consents to
# an action that was held for a human. The contract is
# docs/lane-a-action-contract.md and the console renders exactly these fields.


def _approver(user_token: str | None, asserted: str | None) -> tuple[str, str]:
    """WHO approved, and HOW that identity was established -- always as a pair.

    An identity rendered without its provenance is an ASSERTED identity
    displayed as a PROVEN one, which is this week's recurring defect and would
    be the first instance visible in the artifact we show people. So the pair is
    built in one place and neither half can be produced without the other.

    Under user-auth the IdP names the approver and the body may not: two sources
    for one fact is how they come to disagree, and the weaker one would be the
    forgeable one. Without an IdP the caller of this operator-gated endpoint
    asserts it, and the record says so -- `operator_api`, which the console
    renders as a weak provenance rather than as a proven identity.
    """
    if config.USER_AUTH:
        if asserted is not None:
            raise HTTPException(
                422, "approver cannot be asserted while user-auth is on: the "
                     "approval is recorded for the authenticated operator")
        return _authed_user(user_token), runtoken.SUB_SRC_IDP
    if not asserted or len(asserted.strip()) > MAX_APPROVER_CHARS \
            or any(c in asserted for c in "\r\n\t") or not asserted.strip():
        raise HTTPException(
            422, "approver is required when there is no IdP: an approval with "
                 "nobody's name on it is not an approval")
    return asserted.strip(), "operator_api"


@app.post("/runs/{run_id}/actions", status_code=201)
def request_run_action(run_id: str, body: ActionRequestBody,
                       ctx: auth.RunCtx = auth.require_run()) -> dict:
    """A run REQUESTS a consequential action. Andyur decides, and may perform it.

    OPERATOR-REFUSED ON PURPOSE. This endpoint records that THE AGENT asked, and
    the whole MVP claim is about what happens to an agent's request. An operator
    posting here would produce a row saying the run requested something it never
    requested -- a forged audit record, written by the platform, in the one
    artifact we show people to prove the platform's records are trustworthy. An
    operator who wants a rollback has kubectl.

    The authority and the target come from `ctx` -- the SIGNED grant -- and never
    from the body. That is what makes the decision unforgeable by the thing being
    decided about: a prompt-injected agent can change what it asks for, and can
    change nothing about what it is allowed to have.
    """
    if ctx.is_operator:
        raise HTTPException(
            403, "a consequential action is requested BY A RUN: this endpoint "
                 "records what the agent asked for, and an operator asking on "
                 "its behalf would forge that record")
    ctx.require_run_id(run_id)
    with _decision_span("action.request") as decision:
        decision.set_attribute("andyur.run_id", run_id)
        try:
            held = actions.grant_in_effect(body.tool, ctx.scope)
        except ValueError as exc:
            decision.reason = "invalid"
            raise HTTPException(422, str(exc)) from exc
        # The PDP can only NARROW: it is asked whether this run may exercise the
        # authority IT HOLDS, and `actions.decide` still requires that authority
        # to be enumerated in the run's sealed scope. A policy engine answering
        # yes cannot supply a grant the run does not have; one that is
        # unreachable denies, because pdp fails closed. A run holding neither
        # grant is not asked about at all -- there is no authority to evaluate,
        # and `decide` denies it by name.
        permits = held is None or pdp.evaluate(
            pdp.Subject(type="run", id=run_id, is_operator=False, scope=ctx.scope),
            held)
        try:
            row = actionrequests.request(
                run_id, body.tool, body.namespace, body.deployment,
                granted_scope=ctx.scope, pin=ctx.pin, policy_permits=permits,
                grant_expires_at=ctx.expires_at)
        except actionrequests.ActionExhausted as exc:
            # 429, not 422: the request is well-formed and would have been
            # decided on its merits a moment earlier. A caller that retries
            # forever should be told it is the RATE that is refused.
            decision.reason = "exhausted"
            raise HTTPException(429, str(exc)) from exc
        except actionrequests.ActionRefused as exc:
            decision.reason = "invalid"
            raise HTTPException(422, str(exc)) from exc
    return row


@app.get("/runs/{run_id}/actions")
def get_run_actions(run_id: str, _id: str = auth.require(auth.OPERATOR),
                    x_andyur_user_token: str | None = Header(default=None)) -> list:
    """What this run requested and what Andyur decided, for the console.

    A LIST, including the empty one. "Nothing was requested" and "the evidence is
    unavailable" are different claims, and a console that cannot tell them apart
    renders the second as the first -- so this route answers 404 for a run that
    does not exist (owner-gated, no existence oracle) and `[]` for a run that
    requested nothing, and never the other way round.
    """
    _run_owner_gate(run_id, x_andyur_user_token)
    return actionrequests.list_for_run(run_id)


@app.post("/runs/{run_id}/actions/{action_id}/approve")
def approve_run_action(run_id: str, action_id: str, body: ApproveBody,
                       _id: str = auth.require(auth.OPERATOR),
                       x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """A human consents to an action the run was already entitled to perform.

    Operator-gated, so an agent cannot reach it in any configuration:
    `auth.require` refuses a run token outright. Approval consents to the USE of
    an authority and never grants one -- an action only reaches this state if the
    run's sealed grant already named the rollback authority, which is why a
    read-only run is DENIED at request time rather than queued for an approval
    that could never make it legitimate.
    """
    _run_owner_gate(run_id, x_andyur_user_token)
    approver, asserted_by = _approver(x_andyur_user_token, body.approver)
    with _decision_span("action.approval") as decision:
        decision.set_attribute("andyur.run_id", run_id)
        existing = actionrequests.get(action_id)
        if existing is None or existing["run_id"] != run_id:
            decision.reason = "invalid"
            raise HTTPException(404, f"no action '{action_id}' on run '{run_id}'")
        row = actionrequests.approve(action_id, approver, asserted_by)
        if row is None:
            # The compare-and-swap lost: the row was not (or is no longer) in
            # approval_required. 409 rather than a second execution -- two
            # operators approving concurrently must produce one rollback.
            decision.reason = "conflict"
            raise HTTPException(
                409, f"action '{action_id}' is not awaiting approval "
                     f"(decision: {existing['decision']})")
    return row


@app.get("/workflows/{workflow_id}/flow")
def get_workflow_flow(workflow_id: str, _id: str = auth.require(auth.OPERATOR),
                      x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """The run graph of one workflow from the platform's own records. Nodes
    are run_view rows the caller may read; a run of another owner is an ELIDED
    node (agent, state, depth only) so the chain's shape stays visible without
    leaking it: an edge into an elided run carries no cause or reason either
    (a reason embeds task titles and sender names).

    EDGES COME FROM `parent_run_id`, recorded by every run woken by a task or a
    message at the moment it is woken. A row written before that column existed
    (parent_run_id NULL, depth > 0) falls back to the nearest preceding run one
    level up -- a guess, kept only for those rows. A row that HAS a parent id
    which does not resolve inside this workflow gets NO EDGE: the fallback used
    to catch that case too and attributed the run to an unrelated one, carrying
    its cause and reason, indistinguishable from a real edge. Deleting an agent
    cascades its runs away and leaves exactly that dangling pointer.

    A run woken by the heartbeat's drain joins the right workflow but records no
    parent -- the task and message rows do not carry the creating run's id, so
    there is nothing to record. It draws as a second root, which is what the
    record actually says.

    Each visible run also carries the counts of its model and tool calls, so the
    graph is drawn from one call and a run's exchanges are fetched only when a
    node is chosen."""
    # record_exception / set_status_on_exception OFF, deliberately. An
    # HTTPException raised inside a span is otherwise recorded with its message
    # AND a stack trace, and this route's 404 echoes the caller's own path
    # parameter -- so an 8 KB workflow id came back out of the collector on
    # otel.status_description, in a module where redact() is applied nowhere.
    # The span says what was DECIDED, by name; the caller gets their own string
    # back and telemetry does not.
    # The two 404s below are byte-identical to the CALLER, which is what closes
    # the existence oracle. A span is not caller-visible, so it may say which
    # one it was -- otherwise an authorization denial and a miss are the same
    # event to whoever reads the trace.
    with _decision_span("server.workflow_flow") as span:
        return _workflow_flow(workflow_id, x_andyur_user_token, span)


def _workflow_flow(workflow_id: str, x_andyur_user_token: str | None, span) -> dict:
    owner = _visible_owner(x_andyur_user_token)
    # EACH OWNER'S SET IS CAPPED SEPARATELY, so a workflow one owner fills
    # cannot push another owner's runs past the cap. Applying the cap to the
    # mixed set before the owner filter let alice seed 250 runs into a shared
    # workflow and erase bob's own run, task and message from bob's console --
    # with the route answering 404 "no workflow" for work he owns. The admin's
    # graph was silently wrong the same way.
    flow_columns = ", ".join(f'r."{c}"' for c in _FLOW_RUN_COLUMNS)
    RUNS_SQL = ("SELECT " + flow_columns + ", a.owner AS agent_owner FROM runs r "
                "JOIN agents a ON a.name = r.agent WHERE r.workflow_id = ?{extra} "
                "ORDER BY r.created_at, r.id LIMIT ?")
    TASKS_SQL = ("SELECT t.id, t.assignee, t.creator, t.title, t.detail, t.state, "
                 "t.result, t.created_at, a.owner AS agent_owner FROM tasks t "
                 "JOIN agents a ON a.name = t.assignee WHERE t.workflow_id = ?{extra} "
                 "ORDER BY t.created_at LIMIT ?")
    MSGS_SQL = ("SELECT m.id, m.recipient, m.sender, m.body, m.state, m.created_at, "
                "a.owner AS agent_owner FROM messages m JOIN agents a ON a.name = m.recipient "
                "WHERE m.workflow_id = ?{extra} ORDER BY m.created_at LIMIT ?")
    with db.connect() as conn:
        if owner is None:
            rows = conn.execute(RUNS_SQL.format(extra=""),
                                (workflow_id, _FLOW_MAX_RUNS + 1)).fetchall()
            over_run_cap = len(rows) > _FLOW_MAX_RUNS
            rows = rows[:_FLOW_MAX_RUNS]
        else:
            mine = conn.execute(RUNS_SQL.format(extra=" AND a.owner = ?"),
                                (workflow_id, owner, _FLOW_MAX_RUNS + 1)).fetchall()
            # The rest only fills in the chain's SHAPE (elided nodes), so it
            # gets its own budget and cannot displace the caller's own runs.
            others = conn.execute(RUNS_SQL.format(extra=" AND a.owner != ?"),
                                  (workflow_id, owner, _FLOW_MAX_RUNS + 1)).fetchall()
            over_run_cap = len(mine) > _FLOW_MAX_RUNS or len(others) > _FLOW_MAX_RUNS
            rows = sorted(list(mine[:_FLOW_MAX_RUNS]) + list(others[:_FLOW_MAX_RUNS]),
                          key=lambda r: (r["created_at"], r["id"]))
        # Tasks and messages are returned only to their owner, so the owner
        # predicate belongs in the query: it is both the bound and the fix.
        item_extra = "" if owner is None else " AND a.owner = ?"
        item_args = (workflow_id,) if owner is None else (workflow_id, owner)
        tasks = conn.execute(TASKS_SQL.format(extra=item_extra),
                             (*item_args, _FLOW_MAX_ITEMS + 1)).fetchall()
        messages = conn.execute(MSGS_SQL.format(extra=item_extra),
                                (*item_args, _FLOW_MAX_ITEMS + 1)).fetchall()
    if not rows:
        span.reason = "no_such_workflow"
        raise HTTPException(404, f"no workflow '{_short_id(workflow_id)}'")
    over_item_cap = len(tasks) > _FLOW_MAX_ITEMS or len(messages) > _FLOW_MAX_ITEMS
    tasks = tasks[:_FLOW_MAX_ITEMS]
    messages = messages[:_FLOW_MAX_ITEMS]
    budget = _FLOW_READ_BUDGET
    over_read_budget = False
    visible = [r for r in rows if owner is None or r["agent_owner"] == owner]
    if not visible:
        span.reason = "not_visible_to_owner"
        raise HTTPException(404, f"no workflow '{_short_id(workflow_id)}'")
    nodes, edges = [], []
    index_of = {r["id"]: i for i, r in enumerate(rows)}
    by_depth: dict[int, list[int]] = {}
    for i, r in enumerate(rows):
        d = r["depth"] or 0
        mine = owner is None or r["agent_owner"] == owner
        if mine:
            # The LIST projection, not run_view: a node needs a run's facts,
            # not its bodies. With the full view, 200 nodes carrying summaries
            # at the platform's 1 MiB retention cap plus their inputs was a
            # 1.89 GB response. The run page fetches the bodies for the one run
            # a reader opens.
            node = {**run_list_view(r), "elided": False, "index": i}
            # BOUNDED AT THE READ, not after it. Slicing what a whole-file
            # read returned bounds the response and nothing else: the graph
            # reads every visible run's transcript in one request, and each of
            # those files is written by the run itself.
            allowance = min(_FLOW_TRANSCRIPT_BYTES, budget)
            read = workspace.read_text_bounded(
                r["agent"], workspace.transcript_path(r["id"]), allowance) if allowance else None
            if read is not None:
                # CHARGED ON BYTES READ, not on decoded content, and charged
                # BEFORE the branch. Content that decodes to nothing still cost
                # a read: 8 MiB of b"\xff" decodes under errors="ignore" to the
                # empty string, so charging the decoded length charged zero and
                # the loop kept going -- 12.5x over budget with the response
                # reporting that nothing had been truncated.
                budget -= read[2]
            if not read or not read[0]:
                node["exchanges"] = None
                if not allowance:
                    # NOT the same as having no transcript, and the page draws
                    # them differently. Without this the graph labelled 184
                    # nodes "no transcript, trace only" while every one of them
                    # had a 5 MiB transcript the budget had run out before.
                    node["exchanges_omitted"] = "budget"
                    over_read_budget = True
            else:
                text, more, _raw = read
                counts = exchange_counts(text)
                counts["truncated"] = counts["truncated"] or more
                node["exchanges"] = counts
        else:
            node = {"agent": r["agent"], "state": r["state"], "depth": d, "elided": True, "index": i}
        nodes.append(node)
        recorded = r["parent_run_id"]
        if recorded:
            # A recorded parent that does not resolve here is a DANGLING
            # pointer (its run was deleted, or it names another workflow).
            # Drawing no edge is the truthful answer; the fallback below would
            # invent one from whichever run happens to sit one level up.
            parent = index_of.get(recorded)
        elif d > 0 and by_depth.get(d - 1):
            parent = by_depth[d - 1][-1]       # pre-column rows: nearest preceding, one level up
        else:
            parent = None
        if parent is not None:
            edges.append({"from": parent, "to": i,
                          "cause": r["run_type"] if mine else None,
                          "reason": r["reason"] if mine else None})
        by_depth.setdefault(d, []).append(i)
    # This route reads N agent-written files per request, so how much it read
    # and what it left out are the two things an operator asks about a slow one.
    # Without them a multi-second, multi-hundred-megabyte request is invisible.
    span.set_attribute("andyur.flow.runs_drawn", len(nodes))
    span.set_attribute("andyur.flow.bytes_read", _FLOW_READ_BUDGET - budget)
    span.set_attribute("andyur.flow.truncated_runs", over_run_cap)
    span.set_attribute("andyur.flow.truncated_reads", over_read_budget)
    span.set_attribute("andyur.flow.truncated_items", over_item_cap)
    # Per-file truncation and the per-run key cap are set on the NODE and were
    # nowhere on the span, so two of the three ways this route can return a
    # partial answer were dark to an operator reading the trace.
    span.set_attribute("andyur.flow.partial_transcripts", sum(
        1 for nd in nodes if nd.get("exchanges") and nd["exchanges"].get("truncated")))
    return {
        "workflow_id": workflow_id,
        "state": coordinator.workflow_state(workflow_id) or "unknown",
        "truncated_runs": over_run_cap,
        "truncated_items": over_item_cap,
        # Say what was left out. A graph that silently is not the whole
        # workflow reads as a complete one.
        "truncated_reads": over_read_budget,
        "nodes": nodes,
        "edges": edges,
        "tasks": [_flow_item(t, ("id", "assignee", "creator", "title", "detail",
                                "state", "result", "created_at"))
                  for t in tasks if owner is None or t["agent_owner"] == owner],
        "messages": [_flow_item(m, ("id", "recipient", "sender", "body", "state", "created_at"))
                     for m in messages if owner is None or m["agent_owner"] == owner],
    }


@app.get("/runs/{run_id}/registry-tools")
def get_run_registry_tools(
    run_id: str, ctx: auth.RunCtx = auth.require_run(require_svid=True)
) -> dict:
    """The bound tool descriptor for this run's credential-holding sidecar.

    The registry ID is derived from the authenticated run's runtime agent; it is
    never caller-selected. This keeps one run from enumerating another agent's
    internal routing and keeps the full authority ceiling out of this response.
    The untrusted agent process does not receive the sealed run token/SVID used
    here; the runner fetches this before configuring its sidecar.
    """
    ctx.require_run_id(run_id)
    with db.connect() as conn:
        row = conn.execute(
            "SELECT r.agent, a.registry_agent_id FROM runs r "
            "JOIN agents a ON a.name = r.agent WHERE r.id = ?", (run_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(404, f"no run '{run_id}'")
    registry_agent_id = row["registry_agent_id"]
    if registry_agent_id is None:
        return {"registry_agent_id": None, "tools": []}
    try:
        resolution = configured_registry().resolve(registry_agent_id)
    except (AgentNotFound, RegistryUnavailable) as exc:
        raise HTTPException(
            503, f"bound registry agent {registry_agent_id!r} is unavailable: {exc}"
        ) from exc
    # THE PER-TOOL DECISION IS MADE HERE, not in the sidecar.
    #
    # The sidecar used to be handed the binding's static grants and compute
    # `permitted_tools({"actions": None}, ...)`, whose literal None short-
    # circuits to "every enumerated tool" -- so the run's narrowed authority
    # never entered the decision. For a brokered binding the sidecar is the only
    # Andyur enforcement point, so that was a real widening.
    #
    # `authority_for` is the function a mint path is supposed to call: it reads
    # the ceiling from the registry itself, so "the run supplied a wider
    # ceiling" is not a request that can be expressed. The sidecar receives the
    # RESULT and decides nothing.
    tools = []
    for tool in resolution.tools:
        permitted = None
        if tool.mcp_tools is not None:
            try:
                decision = registry_authority.authority_for(
                    ctx.agent, ctx.scope, ctx.pin, tool.resource_id)
            except Exception:                                  # noqa: BLE001
                # No readable ceiling means no derivable authority. Withhold the
                # binding rather than offer it under an authority we could not
                # compute.
                log.warning("run %s: withholding tool %s, authority for "
                            "audience %s could not be derived",
                            run_id, tool.name, tool.resource_id, exc_info=True)
                continue
            permitted = sorted(mcpwire.permitted_tools(
                decision, {g.name: g.requires for g in tool.mcp_tools}) or [])
        entry = {key: value for key, value in {
            "name": tool.name,
            "reach_url": tool.reach_url,
            "resource_id": tool.resource_id,
            "authority": tool.authority,
            "credential_ref": tool.credential_ref,
            "credential_headers": (list(tool.credential_headers)
                                   if tool.credential_headers else None),
        }.items() if value is not None}
        # ALWAYS present, and null is a meaningful value: null means the binding
        # enumerates nothing and stays audience-level, [] means it enumerates and
        # this run may call none of them. Emitted outside the `is not None`
        # filter above precisely so the two cannot be confused with absence --
        # a missing key would silently disable per-tool authority.
        entry["permitted_tools"] = permitted
        tools.append(entry)
    return {"registry_agent_id": registry_agent_id, "tools": tools}


@app.post("/runs/{run_id}/start")
def start_run(run_id: str, ctx: auth.RunCtx = auth.require_run()) -> dict:
    ctx.require_run_id(run_id)
    with _tracer.start_as_current_span(
        "server.start_run", context=_run_trace_ctx(run_id)
    ):
        if not coordinator.start_run(run_id):
            raise HTTPException(409, f"run '{run_id}' is not pending")
    return {"run_id": run_id, "state": "running"}


def _credential_launch(a: dict) -> dict:
    """Mint the credentials one claimed run is launched with, in place.

    ONE place, used by both dispatchers -- the native heartbeat and the
    engine's execution claim -- so a run is credentialed identically whichever
    of them hands it out: the same token claims, the same lifetime, the same
    purpose-bound broker token.
    """
    ttl = _run_token_ttl(a.get("run_type"), a.get("runtime_resolution"))
    a["run_token"] = runtoken.mint(
        a["agent"], a["id"], a.get("workflow_id"), sub=a.get("user"),
        sub_src=a.get("user_asserted_by"),
        scope=json.loads(a["scope"]) if a.get("scope") else None, ttl=ttl,
        audiences=(json.loads(a["ceiling_audiences"])
                   if a.get("ceiling_audiences") else None),
        # the pin travels in the grant, like sub and scope, so the run's
        # target is a signed claim rather than a line in its prompt
        pin=json.loads(a["pin"]) if a.get("pin") else None)
    # A second, purpose-bound credential for model calls. Since S4 the
    # AGENT never holds it: the runner's loopback proxy attaches it from
    # the runner's own memory, and the runner scrubs it from the agent
    # subprocess env. It is still not the run token: audience binding is
    # what keeps a stolen model credential from becoming control-plane
    # authority, whoever stole it.
    a["broker_token"] = runtoken.mint(
        a["agent"], a["id"], a.get("workflow_id"), ttl=ttl,
        purpose=runtoken.PURPOSE_BROKER)
    # The deadline the RUNNER will arm, resolved here rather than in the
    # daemon so the number the runner enforces, the number the token covers
    # and the number the reaper collects by all come from one computation.
    # Absent for an agent with no grant, so the worker keeps using the
    # platform default it already has.
    granted = _granted_run_seconds(a.get("runtime_resolution"))
    if granted is not None:
        a["run_ttl"] = granted
    return a


@app.post("/worker/heartbeat")
def worker_heartbeat(body: HeartbeatBody, _id: str = auth.require(auth.WORKER)) -> dict:
    # A dev-profile worker runs every agent unsandboxed with the open internet.
    # If this control plane is production, that is a hole opened by a worker the
    # operator may not know is attached, so say so on every beat rather than
    # once at startup in a log nobody is tailing.
    if config.PROD and body.profile != "prod":
        log.error(
            "worker '%s' reports profile '%s' while this control plane is prod: "
            "its runs are NOT sandboxed and NOT egress-confined",
            body.worker_id, body.profile)
    if body.worker_id == coordinator.ENGINE_WORKER:
        # THE ENGINE'S CLAIM MARKER IS NOT A WORKER ID (B+ adversarial review).
        # A daemon beating as "engine" had native runs assigned under it, and
        # the execution worker -- whose finishes are stamped with that marker --
        # could then finalize them.
        raise HTTPException(403, "the engine's claim marker is not a worker id")
    coordinator.record_heartbeat(body.worker_id, body.slots)
    assignments = coordinator.assign_runs(
        body.worker_id, body.slots_free,
        require_registry=body.orchestrator == "kubernetes",
    )
    # mint a per-run token (R1) so the runner can prove WHICH agent/run it is on
    # every run-scoped call; the daemon carries it into the runner's environment.
    # A conversation token is minted to outlive the whole session (which can run
    # far longer than a headless run) so the session never needs a mid-flight
    # refresh -- there is no token-rotation endpoint to attack, and the session
    # can never outlive its own credential (both bounded by CONVERSATION_MAX_SECONDS).
    for a in assignments:
        _credential_launch(a)
    # The other direction of the heartbeat: which of the runs this worker says it
    # is executing must be destroyed now. The runner's own halt poll stops a run
    # BETWEEN tool calls; this stops one that is inside a tool call, wedged, or
    # no longer accountable to any run record. The decision is the server's,
    # because the process being killed is exactly the wrong thing to ask.
    from .heartbeat import RUN_TTL_SECONDS
    return {
        "assignments": assignments,
        "kill": coordinator.runs_to_kill(body.running or []),
        "heartbeat_interval": 10,
        # The TTL the SERVER reaps by, so a run is bounded by one number rather
        # than two. When the worker used its own, a larger value meant healthy
        # long runs were reaped as hung -- and since a terminal record now marks
        # a run for destruction, a configuration mismatch that used to produce a
        # wrong status line would produce a SIGKILL mid-execution.
        "run_ttl": RUN_TTL_SECONDS,
    }


class ExecuteBody(Body):
    # Which launcher will run it: a Kubernetes launch requires a registry-bound
    # agent whose sealed resolution still matches, exactly as for the daemon.
    orchestrator: str
    # The orchestration provider this executor serves. The claim refuses a run
    # bound to any other (run execution draft, step 2).
    provider: str


def _refused(exc: "coordinator.ExecutionRefused"):
    # 409 with the refusal's NAME: the execution worker maps every one of these
    # to a non-retryable failure, so the engine does not retry Andyur's "no".
    return JSONResponse(status_code=409,
                        content={"refusal": exc.code, "detail": str(exc)})


@app.post("/runs/{run_id}/execute")
def execute_run_claim(run_id: str, body: ExecuteBody,
                      _id: str = auth.require(auth.EXECUTION_WORKER)):
    """The engine's execution worker claims ONE admitted run by id
    (Architecture B+, ADR-014 D11).

    Everything returned comes from Andyur's record; the engine supplied only
    the id. `launch` carries the launch payload and freshly minted credentials
    while the run has not started, and is null for a run that is already
    running -- that one is adopted by its generation, never re-credentialed.
    """
    with _tracer.start_as_current_span(
        "server.execute_run_claim", context=_run_trace_ctx(run_id)
    ) as span:
        span.set_attribute("andyur.run_id", run_id)
        try:
            # THE SEAL IS THE SERVER'S TO REQUIRE. Taking it from the caller's
            # `orchestrator` let an execution worker saying "host" skip the
            # re-check that the registry still resolves to what was sealed
            # (B+ adversarial review); under the production profile it is
            # required whatever the caller says.
            claim = coordinator.claim_for_execution(
                run_id, require_registry=config.PROD or body.orchestrator == "kubernetes",
                provider=body.provider)
        except coordinator.ExecutionRefused as exc:
            span.set_attribute("andyur.outcome", "refused")
            span.set_attribute("andyur.reason", exc.code)
            return _refused(exc)
        span.set_attribute("andyur.outcome", "launch" if claim["launch"] else "adopt")
        if claim["launch"] is not None:
            _credential_launch(claim["launch"])
    return claim


@app.get("/runs/{run_id}/execution")
def execution_status(run_id: str, _id: str = auth.require(auth.EXECUTION_WORKER)):
    """Whether an engine-dispatched run must be destroyed now, as the daemon's
    heartbeat answers for its own runs: halted workflow or terminal record.
    The decision is the server's, never the executing process's."""
    with db.connect() as conn:
        row = conn.execute("SELECT state, dispatch FROM runs WHERE id = ?",
                           (run_id,)).fetchone()
    if row is None:
        return {"run_id": run_id, "state": None, "kill": True}
    if row["dispatch"] != "engine":
        return _refused(coordinator.ExecutionRefused(
            "not_engine", f"run {run_id!r} is not dispatched by the engine"))
    kill = run_id in coordinator.runs_to_kill([run_id])
    with db.connect() as conn:
        state = conn.execute("SELECT state FROM runs WHERE id = ?",
                             (run_id,)).fetchone()["state"]
    return {"run_id": run_id, "state": state, "kill": kill}


class BundleInstall(Body):
    """The agents a bundle contains, as `andyur.agent-resolution/v1` documents.

    Sent whole rather than file by file: a bundle is installed or it is not, and
    a per-file endpoint would make a half-installed bundle reachable by giving
    up halfway through.
    """

    agents: list[dict]
    # Replacing is a different act from installing, and saying so is the caller's
    # job. An install that silently overwrote a bundle would let a typo'd name
    # take out somebody else's agents.
    replace: bool = False


@app.get("/v1/registry/bundles")
def list_bundles(_id: str = auth.require(auth.OPERATOR),
                 x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """What is installed. Readable by any operator: it is catalogue
    information, the same as `registry list`."""
    from ..registry import bundles as bundle_ops
    try:
        directory = bundle_ops.registry_directory()
    except bundle_ops.BundleRefused as exc:
        raise HTTPException(409, str(exc))
    return {"bundles": bundle_ops.list_bundles(directory)}


@app.put("/v1/registry/bundles/{name}")
def install_bundle(name: str, body: BundleInstall,
                   _id: str = auth.require(auth.OPERATOR),
                   x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Install a bundle of agents.

    ADMIN-ONLY, and not because bundles are infrastructure. Installing one
    decides which agents may exist and what authority each may ever hold, so it
    is the most consequential write on this API -- an owner who could install a
    bundle could grant themselves an agent holding any action the platform
    knows."""
    from ..registry import bundles as bundle_ops
    _admin_gate(x_andyur_user_token)
    try:
        directory = bundle_ops.registry_directory()
        return bundle_ops.install_bundle(directory, name, body.agents,
                                         replace=body.replace)
    except bundle_ops.BundleRefused as exc:
        raise HTTPException(409, str(exc))
    except RegistryUnavailable as exc:
        raise HTTPException(422, f"the bundle did not load: {exc}")


@app.delete("/v1/registry/bundles/{name}")
def uninstall_bundle(name: str, _id: str = auth.require(auth.OPERATOR),
                     x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Remove an installed bundle from the catalogue.

    Agents already created from it KEEP RUNNING. The registry says what may be
    launched, not what is; using uninstall to stop an agent would be an
    instrument that looks like it worked and did not."""
    from ..registry import bundles as bundle_ops
    _admin_gate(x_andyur_user_token)
    try:
        directory = bundle_ops.registry_directory()
        return bundle_ops.uninstall_bundle(directory, name)
    except bundle_ops.BundleRefused as exc:
        raise HTTPException(409, str(exc))


@app.get("/workers")
def list_workers(_id: str = auth.require(auth.OPERATOR),
                 x_andyur_user_token: str | None = Header(default=None)) -> list[dict]:
    _admin_gate(x_andyur_user_token)   # infrastructure view, not tenant data
    from datetime import datetime, timedelta, timezone

    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, slots, last_heartbeat FROM workers ORDER BY last_heartbeat DESC"
        ).fetchall()
    # ISO strings in the same zone compare lexicographically
    alive_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat(
        timespec="seconds"
    )
    return [dict(r) | {"alive": r["last_heartbeat"] >= alive_cutoff} for r in rows]


@app.post("/runs/{run_id}/finish")
def finish_run(run_id: str, body: FinishBody, ctx: auth.RunCtx = auth.require_run()) -> dict:
    ctx.require_run_id(run_id)
    with _tracer.start_as_current_span(
        "server.finish_run", context=_run_trace_ctx(run_id)
    ) as span:
        span.set_attribute("andyur.result", "failed" if body.error else "done")
        if not coordinator.finish_run(run_id, body.summary, body.error):
            raise HTTPException(409, f"run '{run_id}' already finalized or unknown")
    return {"run_id": run_id, "state": "failed" if body.error else "done"}


@app.post("/runs/{run_id}/worker-finish")
def worker_finish_run(
    run_id: str, body: WorkerFinishBody,
    _id: str = auth.require(auth.WORKER, auth.EXECUTION_WORKER),
) -> dict:
    """A worker reports the completion of a run it owns whose workload reports
    nothing of its own -- a stock exec/v1 process, which starts, works, writes
    to stdout and exits. The runner posts its own /finish with a run token; a
    stock process holds none, so its owning worker reports for it here.

    Worker-authenticated (the same role the heartbeat uses), and a THIN wrapper
    over the SAME coordinator.finish_run: failed-vs-done is derived in exactly
    one place, and the state guard and its 409 are unchanged.

    The ownership check is runs.worker == body.worker_id. It is honest about its
    strength: the WORKER role is proven by SVID, but individual workers are NOT
    -- the whole pool shares one role identity (identity.role_of collapses
    spiffe://.../worker to "worker"), and /worker/heartbeat already trusts
    body.worker_id to claim and condemn runs. So this check catches a bug, a
    stale worker or a misrouted assignment; it does NOT resist a malicious
    worker, and nothing on this trust boundary does. Proven per-worker identity
    (runs.worker as a cryptographic fact) is a pre-existing product-level gap,
    tracked open in ROADMAP.md, not closed here.
    """
    with _tracer.start_as_current_span(
        "server.worker_finish_run", context=_run_trace_ctx(run_id)
    ) as span:
        span.set_attribute("andyur.result", "failed" if body.error else "done")
        # Ownership is enforced INSIDE the finalizing UPDATE (worker = ?), so a
        # run reassigned to another worker between any read and here cannot be
        # finalized by the wrong one. The outcome only maps to a status code.
        # The engine's execution worker finishes ENGINE runs only: its claim
        # marker is fixed here rather than taken from the body, and the daemon
        # may not present that marker as its own worker id.
        if identity.role_of(_id) == auth.EXECUTION_WORKER:
            worker_id = coordinator.ENGINE_WORKER
        elif body.worker_id == coordinator.ENGINE_WORKER:
            raise HTTPException(
                403, "the engine's claim marker is not a worker id")
        else:
            worker_id = body.worker_id
        outcome = coordinator.worker_finish_run(
            run_id, worker_id, body.summary, body.error)
        if outcome == "unknown":
            raise HTTPException(404, f"run '{run_id}' unknown")
        if outcome == "not_owner":
            raise HTTPException(
                403, f"run '{run_id}' is not owned by worker '{body.worker_id}'")
        if outcome == "not_active":
            raise HTTPException(409, f"run '{run_id}' already finalized")
    return {"run_id": run_id, "state": outcome}


@app.post("/runs/{run_id}/token")
def issue_run_token(run_id: str, _id: str = auth.require(auth.OPERATOR)) -> dict:
    """Mint a run token for an operator-launched local run. The daemon mints at
    assign time; the CLI's no-daemon local fallback needs one too (so the runner
    it spawns can make run-scoped calls when agent-auth is on)."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT agent, run_type, workflow_id, state, acting_user, scope, "
            "subject_context, user_asserted_by, ceiling_audiences, "
            "runtime_resolution, dispatch FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(404, f"no run '{run_id}'")
    if row["state"] not in ("pending", "running"):
        raise HTTPException(409, f"run '{run_id}' is not active")
    if row["dispatch"] == "engine":
        # ONE DISPATCHER PER RUN. The CLI's no-daemon fallback runs the runner
        # itself with this token; for a run the engine dispatches, that was a
        # second launch of the same run beside the execution worker's.
        raise HTTPException(409, f"run '{run_id}' is dispatched by the engine")
    return {"run_token": runtoken.mint(
        row["agent"], run_id, row["workflow_id"], sub=row["acting_user"],
        sub_src=row["user_asserted_by"],
        scope=json.loads(row["scope"]) if row["scope"] else None,
        audiences=(json.loads(row["ceiling_audiences"])
                   if row["ceiling_audiences"] else None),
        # the local no-daemon path must hand out the SAME grant the daemon would,
        # pin included -- a run whose token happens to be minted here is not a
        # run that gets to be unpinned
        pin=json.loads(row["subject_context"]) if row["subject_context"] else None,
        ttl=_run_token_ttl(row["run_type"], row["runtime_resolution"]))}


# A run's credential must outlive the run itself, including the window the
# reaper waits before collecting it -- otherwise a run being reaped cannot make
# the call that reports its own failure. Wider than heartbeat.RUN_GRACE_SECONDS
# on purpose, and the same margin conversations have always used.
_RUN_TOKEN_GRACE = 300


def _granted_run_seconds(runtime_resolution: str | None) -> int | None:
    """This run's own wall clock, or None to mean the platform default."""
    if not runtime_resolution:
        return None
    try:
        lifecycle = lifecycle_from_assignment(json.loads(runtime_resolution))
    except MalformedLifecycle:
        # A grant existed and cannot be read. The floor is the shortest
        # defensible bound; the platform default would be WIDER than what may
        # have been granted, and a lost grant must not buy a run more time.
        return LIFETIME_FLOOR_SECONDS
    except (TypeError, ValueError):
        return None
    return None if lifecycle is None else lifecycle.max_seconds


def _run_token_ttl(run_type: str | None,
                   runtime_resolution: str | None = None) -> int | None:
    """How long this run's token must live.

    A credential is minted to cover its run and is never refreshed: there is no
    token-rotation endpoint to attack, and a run can never outlive the token it
    was issued. That property is why this returns a LIFETIME rather than a
    rotation policy.

    Three cases. A conversation is bounded by CONVERSATION_MAX_SECONDS. A run
    whose agent was granted a lifetime is bounded by that grant, read from the
    runtime resolution sealed onto the run -- the same value the reaper judges
    it by. Anything else gets the platform default (None).
    """
    if run_type == "conversation":
        return config.CONVERSATION_MAX_SECONDS + _RUN_TOKEN_GRACE
    lifecycle = None
    if runtime_resolution:
        try:
            lifecycle = lifecycle_from_assignment(json.loads(runtime_resolution))
        except MalformedLifecycle:
            return LIFETIME_FLOOR_SECONDS + _RUN_TOKEN_GRACE
        except (TypeError, ValueError):
            lifecycle = None
    if lifecycle is None:
        return None
    return lifecycle.max_seconds + _RUN_TOKEN_GRACE


# --- Conversational agents -------------------------------------------------
# Two authorization surfaces, kept strictly separate:
#   * operator side (turn / close / events): the human driving the chat. Gated by
#     the OPERATOR role, and under user-auth by OWNERSHIP of the run, so only the
#     agent's owner can speak into or read a session.
#   * session side (next-turn / reply): the runner, proven by its per-run token,
#     scoped by require_run_id to ITS run only. The agent can never post a human
#     turn (that needs the operator role it does not hold) nor read another run.

def _conv_run_for_operator(run_id: str, user_token: str | None) -> dict:
    """Load a conversation run for an operator-side call, enforcing ownership
    under user-auth. 404 (not 403) to a non-owner: no existence oracle."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT id, agent, run_type, state, acting_user FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
    if row is None or row["run_type"] != "conversation":
        raise HTTPException(404, f"no conversation '{run_id}'")
    if config.USER_AUTH and row["acting_user"] != _authed_user(user_token):
        raise HTTPException(404, f"no conversation '{run_id}'")
    return dict(row)


@app.post("/runs/{run_id}/turn", status_code=201)
def conversation_turn(
    run_id: str, body: TurnBody, _id: str = auth.require(auth.OPERATOR),
    x_andyur_user_token: str | None = Header(default=None),
) -> dict:
    """Operator/owner speaks one turn into a live session."""
    _conv_run_for_operator(run_id, x_andyur_user_token)
    try:
        seq = conversation.enqueue_turn(run_id, "operator", body.body)
    except conversation.TurnTooLarge:
        raise HTTPException(413, "turn body too large")
    except conversation.Backlogged:
        raise HTTPException(429, "conversation backlog full; the session is being closed")
    except conversation.ConversationClosed:
        raise HTTPException(409, "conversation is closed")
    return {"seq": seq}


@app.post("/runs/{run_id}/close")
def conversation_close(
    run_id: str, _id: str = auth.require(auth.OPERATOR),
    x_andyur_user_token: str | None = Header(default=None),
) -> dict:
    """Operator/owner ends the session; the runner sees the close sentinel and
    shuts down cleanly. Idempotent: closing a closed conversation is a no-op."""
    _conv_run_for_operator(run_id, x_andyur_user_token)
    try:
        conversation.enqueue_turn(run_id, "operator", "", kind=conversation.KIND_CLOSE)
    except conversation.ConversationClosed:
        pass  # already terminal
    except conversation.Backlogged:
        pass  # close must always be accepted; it is what drains the backlog
    return {"closed": True}


@app.get("/runs/{run_id}/events")
def conversation_events(
    run_id: str, after: int = 0, _id: str = auth.require(auth.OPERATOR),
    x_andyur_user_token: str | None = Header(default=None),
) -> dict:
    """Operator/owner reads reply events with seq greater than its cursor."""
    row = _conv_run_for_operator(run_id, x_andyur_user_token)
    events = conversation.read_events(run_id, after)
    return {"events": events, "state": row["state"]}


@app.get("/runs/{run_id}/next-turn")
def conversation_next_turn(run_id: str, ctx: auth.RunCtx = auth.require_run()) -> dict:
    """Session side: the runner claims the next pending turn for ITS run. Scoped
    by the run token to this run only; the agent cannot enqueue or read peers."""
    ctx.require_run_id(run_id)
    turn = conversation.claim_next_turn(run_id)
    if turn is None:
        conversation.beat(run_id)
        return {"turn": None}
    return {"turn": turn}


@app.post("/runs/{run_id}/reply", status_code=201)
def conversation_reply(
    run_id: str, body: ReplyBody, ctx: auth.RunCtx = auth.require_run()
) -> dict:
    """Session side: the runner appends one reply event for ITS run."""
    ctx.require_run_id(run_id)
    if body.kind not in (conversation.EV_CHUNK, conversation.EV_TURN_END,
                         conversation.EV_SESSION_END, conversation.EV_ERROR):
        raise HTTPException(422, f"unknown event kind '{body.kind}'")
    try:
        seq = conversation.append_event(run_id, body.kind, body.body)
    except conversation.ConversationClosed:
        raise HTTPException(409, "conversation is closed")
    return {"seq": seq}


# --- Scheduling -----------------------------------------------------------

@app.post("/agents/{name}/schedules", status_code=201)
def create_schedule(
    name: str, body: ScheduleBody, _id: str = auth.require(auth.OPERATOR)
) -> dict:
    # NOTE: the halted-run write guard was once pasted in here by mistake.
    # This endpoint is operator-only and has neither `ctx` nor `relpath`, so it
    # raised NameError on EVERY call: cron scheduling was dead, and 494 tests
    # never touched the endpoint to notice.
    with db.connect() as conn:
        if conn.execute("SELECT 1 FROM agents WHERE name = ?", (name,)).fetchone() is None:
            raise HTTPException(404, f"no agent named '{name}'")
    try:
        return schedules.create_schedule(name, body.cron, body.reason)
    except (ValueError, KeyError) as exc:
        raise HTTPException(422, f"invalid cron expression: {exc}")


@app.get("/schedules")
def list_schedules(
    agent: str | None = None, _id: str = auth.require(auth.OPERATOR)
) -> list[dict]:
    return schedules.list_schedules(agent)


@app.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str, _id: str = auth.require(auth.OPERATOR)) -> dict:
    try:
        deleted = schedules.delete_schedule(schedule_id)
    except schedules.EngineScheduleUnreachable as exc:
        raise HTTPException(409, str(exc))
    if not deleted:
        raise HTTPException(404, f"no schedule '{schedule_id}'")
    return {"deleted": schedule_id}


# --- Tasks ----------------------------------------------------------------

@app.post("/tasks", status_code=201)
def create_task(
    body: TaskCreateBody, ctx: auth.RunCtx = auth.require_run()
) -> dict:
    auth.require_scope(ctx, "tasks:write")   # U2
    # server-authoritative provenance: a run creates tasks AS its own agent,
    # parented to its own run; only the operator may set these from the body.
    creator = body.creator if ctx.is_operator else ctx.agent
    parent = body.parent_run_id if ctx.is_operator else ctx.run_id
    if not ctx.is_operator and not delegation.may_delegate(ctx.agent, body.assignee):
        raise HTTPException(
            403, f"agent '{ctx.agent}' may not delegate to '{body.assignee}'"
        )
    # U4 downstream delegation: the assignee's run acts for the SAME user as the
    # delegator, with a scope capped to the delegator's own (never wider). The
    # operator is not a delegated user, so it hands no user/scope down.
    deleg_user = None if ctx.is_operator else ctx.user
    deleg_scope = None if ctx.is_operator else tokenexchange.narrow_scope(ctx.scope, body.scope)
    try:
        return tasks.create_task(
            body.assignee, creator, body.title, body.detail,
            trace_ctx=body.trace_ctx, parent_run_id=parent,
            deleg_user=deleg_user, deleg_scope=deleg_scope,
        )
    except coordinator.DelegationRefused as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@app.get("/tasks")
def list_tasks(
    assignee: str | None = None,
    state: str | None = None,
    ctx: auth.RunCtx = auth.require_run(),
) -> list[dict]:
    if not ctx.is_operator:
        assignee = ctx.agent  # a run sees only its own agent's tasks
    return tasks.list_tasks(assignee, state)


@app.post("/tasks/{task_id}")
def update_task(
    task_id: str,
    body: TaskUpdateBody,
    ctx: auth.RunCtx = auth.require_run(),
) -> dict:
    auth.require_scope(ctx, "tasks:write")   # U2
    if not ctx.is_operator:
        with db.connect() as conn:
            row = conn.execute(
                "SELECT assignee FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
        if row is None:
            raise HTTPException(404, f"no task '{task_id}'")
        if row["assignee"] != ctx.agent:
            raise HTTPException(403, f"task '{task_id}' is not assigned to '{ctx.agent}'")
    try:
        updated = tasks.update_task(task_id, body.state, body.result)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if updated is None:
        raise HTTPException(404, f"no task '{task_id}'")
    return updated


# --- Messaging ------------------------------------------------------------

@app.post("/messages", status_code=201)
def send_message(
    body: MessageBody, ctx: auth.RunCtx = auth.require_run()
) -> dict:
    auth.require_scope(ctx, "messages:write")   # U2
    sender = body.sender if ctx.is_operator else ctx.agent
    parent = body.parent_run_id if ctx.is_operator else ctx.run_id
    # delegation gates only waking another AGENT; the operator inbox is the human
    # channel and is never gated
    if (not ctx.is_operator and body.recipient != auth.OPERATOR
            and not delegation.may_delegate(ctx.agent, body.recipient)):
        raise HTTPException(
            403, f"agent '{ctx.agent}' may not message '{body.recipient}'"
        )
    try:
        return messages.send_message(
            body.recipient, sender, body.body,
            trace_ctx=body.trace_ctx, parent_run_id=parent,
            deleg_user=None if ctx.is_operator else ctx.user,
            deleg_scope=None if ctx.is_operator else ctx.scope,
        )
    except coordinator.DelegationRefused as exc:
        raise HTTPException(409, str(exc))


@app.get("/messages")
def list_messages(
    recipient: str,
    state: str | None = None,
    ctx: auth.RunCtx = auth.require_run(),
) -> list[dict]:
    if not ctx.is_operator:
        recipient = ctx.agent  # a run sees only its own agent's messages
    return messages.list_messages(recipient, state)


@app.post("/messages/{message_id}/handle")
def handle_message(
    message_id: str, ctx: auth.RunCtx = auth.require_run()
) -> dict:
    auth.require_scope(ctx, "messages:write")   # U2
    if not ctx.is_operator:
        with db.connect() as conn:
            row = conn.execute(
                "SELECT recipient FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
        if row is None:
            raise HTTPException(404, f"no message '{message_id}'")
        if row["recipient"] != ctx.agent:
            raise HTTPException(403, f"message '{message_id}' is not addressed to '{ctx.agent}'")
    if not messages.handle_message(message_id):
        raise HTTPException(404, f"no message '{message_id}'")
    return {"handled": message_id}


# --- Workflows (kill-switch) -----------------------------------------------

@app.post("/workflows/{workflow_id}/halt")
def halt_workflow(
    workflow_id: str, _id: str = auth.require(auth.OPERATOR),
    x_andyur_user_token: str | None = Header(default=None),
) -> dict:
    """Halt a workflow: no further runs, tasks, or messages spawn under it, and
    its already-queued runs and open tasks are stopped/hidden (kill-switch).
    Stops a poisoned or runaway fan-out across the whole unit of work.

    Admin-only under user-auth: workflows are not owner-scoped rows, so an
    owner-or-admin gate has nothing to compare against; a user's own kill
    switch is pausing their agent."""
    _admin_gate(x_andyur_user_token,
                alternative="A workflow is not owner-scoped, so there is no "
                            "owner to check against. To stop your OWN agent, "
                            "pause it: `andyur agents pause <name>` -- a paused "
                            "agent cannot be woken by a trigger, task, message "
                            "or schedule.")
    orchestration.facade().halt_workflow(workflow_id)
    return {"workflow_id": workflow_id, "state": "halted"}


@app.post("/workflows/{workflow_id}/unhalt")
def unhalt_workflow(
    workflow_id: str, _id: str = auth.require(auth.OPERATOR),
    x_andyur_user_token: str | None = Header(default=None),
) -> dict:
    """Reverse a halt (operator recoverability)."""
    _admin_gate(x_andyur_user_token)   # same boundary as halt
    orchestration.facade().unhalt_workflow(workflow_id)
    return {"workflow_id": workflow_id, "state": "active"}


@app.get("/workflows/{workflow_id}")
def get_workflow(
    workflow_id: str,
    ctx: auth.RunCtx = auth.require_run(),
) -> dict:
    """Workflow state, so a running agent can poll whether it has been halted
    mid-run and abort (in-flight kill-switch). Scoped to the run's own workflow
    so it is not an existence oracle for arbitrary workflow ids."""
    ctx.require_workflow(workflow_id)
    state = coordinator.workflow_state(workflow_id)
    return {"workflow_id": workflow_id, "state": state or "unknown"}


# --- Agent kill-switch (pause the source, across all workflows) ------------

@app.post("/agents/{name}/pause")
def pause_agent(name: str, _id: str = auth.require(auth.OPERATOR),
                x_andyur_user_token: str | None = Header(default=None)) -> dict:
    """Pause an agent so it is never woken (by trigger, schedule, task, or
    message) until resumed. Halting a workflow stops a unit of work; pausing an
    agent stops a runaway source that keeps starting new workflows.

    Owner-or-admin under user-auth: pausing is the user's own kill switch for
    their agent, and without the gate any authenticated user could freeze (or
    covertly un-freeze) another tenant's agent by name -- set_paused's 404 would
    also confirm which names exist."""
    _owner_gate(name, x_andyur_user_token)
    if not coordinator.set_paused(name, True):
        raise HTTPException(404, f"no agent named '{name}'")
    return {"agent": name, "paused": True}


@app.post("/agents/{name}/resume")
def resume_agent(name: str, _id: str = auth.require(auth.OPERATOR),
                 x_andyur_user_token: str | None = Header(default=None)) -> dict:
    _owner_gate(name, x_andyur_user_token)   # same isolation as pause
    if not coordinator.set_paused(name, False):
        raise HTTPException(404, f"no agent named '{name}'")
    return {"agent": name, "paused": False}


# --- The mind (agent files) and mind history (versioning) ------------------

def run_for_agent(name: str, ctx: auth.RunCtx = auth.require_run()) -> auth.RunCtx:
    """Dependency for /agents/{name}/... endpoints (R1): authorize the run and
    confine it to its OWN agent's namespace. The operator (or agent-auth off) may
    act on any agent."""
    ctx.require_agent(name)
    return ctx


@app.get("/agents/{name}/context")
def get_context(
    name: str, ctx: auth.RunCtx = Depends(run_for_agent)
) -> dict:
    """The agent's mind a run needs in its prompt, in one call. This is how a
    runner loads context: over HTTP, so it needs no storage access.

    Requires files:read, like the per-file endpoint. It did not, and it returns
    knowledge, instructions and both memories in a single call -- so the U2 read
    scope was bypassable through the very endpoint every run already uses,
    while the narrower `GET /files/{path}` enforced it."""
    auth.require_scope(ctx, "files:read")   # U2, same as reading the files
    try:
        mind = workspace.load_context(name)
    except FileNotFoundError:
        raise HTTPException(404, f"no agent named '{name}'")
    with db.connect() as conn:
        row = conn.execute(
            "SELECT registry_agent_id FROM agents WHERE name = ?", (name,)
        ).fetchone()
    if row is None:
        raise HTTPException(404, f"no agent named '{name}'")
    registry_agent_id = row["registry_agent_id"]
    mind["registry_agent_id"] = registry_agent_id
    mind["registry_model"] = None
    if registry_agent_id is not None:
        try:
            resolution = configured_registry().resolve(registry_agent_id)
        except (AgentNotFound, RegistryUnavailable) as exc:
            # A bound agent must never silently fall back to its mutable legacy
            # mind when its authoritative definition cannot be established.
            raise HTTPException(
                503, f"bound registry agent {registry_agent_id!r} is unavailable: {exc}"
            ) from exc
        mind["instructions"] = resolution.instructions
        mind["registry_model"] = resolution.model
    mind["graph_enabled"] = graph.enabled()  # so the runner knows to capture
    return mind


@app.get("/agents/{name}/files/{relpath:path}")
def read_file(
    name: str, relpath: str,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> dict:
    auth.require_scope(ctx, "files:read")   # U2
    try:
        content = workspace.read_text(name, relpath)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if content is None:
        raise HTTPException(404, f"no file '{relpath}' for agent '{name}'")
    return {"path": relpath, "content": content}


def _refuse_if_halted(ctx, relpath: str | None = None) -> None:
    """A run whose workflow has been HALTED may record what happened, never what
    to believe.

    Halting cancels pending runs and leaves a running one alive until the next
    heartbeat condemns it, so for up to one beat a run the operator explicitly
    stopped can still write. What it must not do in that window is influence the
    runs that follow. Its own episodic record (runs/<id>/**) is allowed, because
    destroying the evidence along with the run would be worse.

    Named and shared because the first version was inline in write_file only,
    and the memory GRAPH went straight past it: entities, facts and episodes are
    recalled into the next run's prompt, so a halted run could poison every
    later run through a door the rule was never applied to. `relpath=None` means
    "no own-record exemption applies here", which is right for the graph -- a
    graph write is never episodic evidence.
    """
    if ctx.is_operator or not ctx.workflow_id:
        return
    with db.connect() as conn:
        halted = coordinator.is_halted(conn, ctx.workflow_id)
    if not halted:
        return
    if relpath is not None and workspace.is_own_record(relpath, ctx.run_id):
        return
    raise HTTPException(
        403,
        "this run's workflow is halted: it may record what happened "
        "(runs/<id>/**) but may no longer write memory, artifacts or the graph",
    )


@app.put("/agents/{name}/files/{relpath:path}")
def write_file(
    name: str, relpath: str, body: FileWriteBody,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> dict:
    auth.require_scope(ctx, "files:write")   # U2
    # Shape first, authority second: a traversal is a malformed request (400),
    # an unpermitted write is a refusal (403). Keeping them distinct keeps both
    # debuggable, and means the authority check below always sees a sane path.
    try:
        workspace.assert_valid_path(name, relpath)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    # A run may write what it LEARNED (memory/**) and its own episodic record
    # (runs/<its own id>/**), never what it IS: tool grants, instructions,
    # knowledge and profile are operator-provisioned. Without this a compromised
    # run cannot reach another agent, but it can rewrite ITSELF for every run
    # that follows -- escalation with a delay. See workspace.run_may_write.
    if not ctx.is_operator and not workspace.run_may_write(relpath, ctx.run_id):
        raise HTTPException(
            403,
            f"a run may not write '{relpath}': agent configuration is "
            "operator-provisioned (runs write memory/** and their own runs/<id>/**)",
        )
    # A run whose workflow has been HALTED is being destroyed. Until this, the
    # operator's kill landed on the process but not on its authority: halting
    # cancels pending runs and leaves a running one alive until the next
    # heartbeat condemns it, so for up to one beat a run the operator had
    # explicitly stopped could still write memory -- which is influence over
    # every future run of that agent, persisted after the kill. Verified: the
    # poison landed and stayed.
    #
    # It may still write its own record, because that is the evidence of what it
    # did and destroying the evidence with the run would be worse.
    _refuse_if_halted(ctx, relpath)
    with db.connect() as conn:
        if conn.execute("SELECT 1 FROM agents WHERE name = ?", (name,)).fetchone() is None:
            raise HTTPException(404, f"no agent named '{name}'")
    # server-stamp provenance from the run identity (a run can't forge actor/run_id)
    actor = body.actor if ctx.is_operator else ctx.agent
    run_id = body.run_id if ctx.is_operator else ctx.run_id
    try:
        mind.write_file(name, relpath, body.content, actor, run_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"path": relpath, "written": True}


@app.get("/agents/{name}/versions")
def list_versions(
    name: str, path: str | None = None,
    _id: str = auth.require(auth.OPERATOR),
) -> list[dict]:
    return mind.history(name, path)


@app.get("/versions/{version_id}")
def get_version(version_id: str, _id: str = auth.require(auth.OPERATOR)) -> dict:
    v = mind.get_version(version_id)
    if v is None:
        raise HTTPException(404, f"no version '{version_id}'")
    return v


@app.post("/agents/{name}/restore")
def restore_version(
    name: str, body: RestoreBody, _id: str = auth.require(auth.OPERATOR)
) -> dict:
    result = mind.restore(name, body.version_id, body.actor)
    if result is None:
        raise HTTPException(404, f"no version '{body.version_id}' for '{name}'")
    return result


# --- Associative memory graph (Phase 6) ------------------------------------

def _graph_on() -> None:
    if not graph.enabled():
        raise HTTPException(503, "memory graph is disabled (set ANDYUR_GRAPH=neo4j)")


def _agent_or_404(name: str) -> None:
    with db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM agents WHERE name = ?", (name,)
        ).fetchone() is None:
            raise HTTPException(404, f"no agent named '{name}'")


@app.post("/agents/{name}/graph/entities")
def graph_add_entity(
    name: str, body: EntityBody,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> dict:
    _refuse_if_halted(ctx)
    _graph_on()
    _agent_or_404(name)
    rid = body.run_id if ctx.is_operator else ctx.run_id
    return graph.upsert_entity(
        name, body.name, body.type, body.summary, rid, body.embedding
    )


@app.post("/agents/{name}/graph/facts")
def graph_add_fact(
    name: str, body: FactBody,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> dict:
    _refuse_if_halted(ctx)
    _graph_on()
    _agent_or_404(name)
    rid = body.run_id if ctx.is_operator else ctx.run_id
    return graph.add_fact(
        name, body.subject, body.predicate, body.object,
        body.subject_type, body.object_type, body.valid_from,
        rid, body.confidence,
    )


@app.post("/agents/{name}/graph/episodes")
def graph_add_episode(
    name: str, body: EpisodeBody,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> dict:
    _refuse_if_halted(ctx)
    _graph_on()
    _agent_or_404(name)
    rid = body.run_id if ctx.is_operator else ctx.run_id
    return graph.add_episode(name, rid, body.text)


@app.get("/agents/{name}/graph/search")
def graph_search(
    name: str, q: str, limit: int = 10,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> list[dict]:
    _graph_on()
    return graph.search(name, q, limit)


@app.get("/agents/{name}/graph/recall")
def graph_recall(
    name: str, q: str, limit: int = 5,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> list[dict]:
    """The subgraph relevant to a wakeup context, for prompt injection."""
    _graph_on()
    return graph.recall(name, q, limit)


@app.get("/agents/{name}/graph/types")
def graph_types(
    name: str, _ctx: auth.RunCtx = Depends(run_for_agent),
) -> list[str]:
    _graph_on()
    return graph.known_types(name)


@app.get("/agents/{name}/graph/neighbors")
def graph_neighbors(
    name: str, entity: str, limit: int = 25,
    ctx: auth.RunCtx = Depends(run_for_agent),
) -> dict:
    _graph_on()
    return graph.neighbors(name, entity, limit)


@app.get("/agents/{name}/graph/counts")
def graph_counts(
    name: str, _ctx: auth.RunCtx = Depends(run_for_agent),
) -> dict:
    _graph_on()
    return graph.counts(name)


@app.post("/agents/{name}/graph/consolidate")
def graph_consolidate(
    name: str, threshold: float | None = None,
    _id: str = auth.require(auth.OPERATOR),
) -> dict:
    """Consolidation A on demand: mechanical merge + prune, no LLM."""
    _graph_on()
    _agent_or_404(name)
    return graph.consolidate(name, threshold)

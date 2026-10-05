"""Request authentication and authorization for the control plane.

Every protected endpoint declares which SPIFFE roles may call it. When
identity is on, an inbound request must carry a valid JWT-SVID whose role is
in the allowed set; otherwise it is rejected before any handler runs. When
identity is off (no SPIRE agent), the dependency is a no-op so the platform
still runs locally.
"""

import contextlib
import dataclasses
import os

from fastapi import Depends, Header, HTTPException

from .. import identity, otel
from . import pdp

# Traces the per-run authorization decision so the identity flow -- token verify,
# SVID validate, token<->SVID bind -- renders alongside the agent's tool calls in
# one Jaeger trace per run. Gated on its OWN flag (not just ANDYUR_OTEL): the
# authorization runs on hot paths too (the kill-switch poll hits require_run every
# few seconds), so tracing it by default would drown a run's trace. Turn it on to
# debug the identity flow. Also a no-op when ANDYUR_OTEL is off.
_tracer = otel.setup_tracing("andyur-server")
_TRACE_AUTH = os.environ.get("ANDYUR_TRACE_AUTH", "off").lower() in ("1", "on", "true")


class _NoSpan:
    def set_attribute(self, *a):  # spans are optional; attributes vanish when off
        pass


_NOSPAN = _NoSpan()


def _auth_span(name: str, trace_ctx: str | None = None):
    """An auth-decision span when ANDYUR_TRACE_AUTH is on (anchored on the run's
    own trace via trace_ctx), else a no-op context. Either way the with-block runs
    its logic and any HTTPException propagates unchanged."""
    if not _TRACE_AUTH:
        return contextlib.nullcontext(_NOSPAN)
    return _tracer.start_as_current_span(name, context=otel.context_from(trace_ctx))


def caller_spiffe_id(authorization: str | None) -> str:
    """The SPIFFE ID the caller proved with its JWT-SVID, or 401.

    Which workload is calling, and nothing about what it may do: `require`
    decides that from the role."""
    token = identity.bearer_token(authorization)
    if token is None:
        raise HTTPException(401, "missing JWT-SVID bearer token")
    try:
        return identity.validate_token(token)
    except Exception as exc:
        raise HTTPException(401, f"invalid JWT-SVID: {exc}")


def require(*roles: str):
    """Build a FastAPI dependency that admits only the given SPIFFE roles."""
    allowed = set(roles)

    def dependency(
        authorization: str | None = Header(default=None),
        x_andyur_run_token: str | None = Header(default=None),
    ) -> str:
        # A caller presenting a run token has declared itself a RUN, and a run is
        # never an operator. Checked before the identity mode, so the answer is
        # the same in dev as in production: an endpoint that is operator-only
        # cannot be reached by a run in ANY configuration.
        #
        # This used to read "with identity off, a caller can simply omit the
        # header", and returned "identity-disabled" -- an unauthenticated pass on
        # an operator-only endpoint. Identity is no longer optional, so the pass
        # is gone and the honest-scope caveat with it.
        if x_andyur_run_token:
            raise HTTPException(
                403, "operator-only endpoint: a run token is not an operator credential"
            )
        spiffe_id = caller_spiffe_id(authorization)
        role = identity.role_of(spiffe_id)
        if role not in allowed:
            raise HTTPException(
                403,
                f"caller '{spiffe_id}' (role {role}) not permitted; "
                f"requires one of {sorted(allowed)}",
            )
        return spiffe_id

    return Depends(dependency)


# Role names as registered in SPIRE (spiffe://andyur.local/<role>).
OPERATOR = "operator"
WORKER = "worker"
RUNNER = "runner"
CONTROL_PLANE = "control-plane"
# The durable engine's execution worker (Architecture B+): claims and launches
# engine-dispatched runs by id. Not the worker daemon, and not interchangeable
# with it.
EXECUTION_WORKER = "temporal-execution-worker"


# --- Agent-scoped authorization (R1) ---------------------------------------

@dataclasses.dataclass
class RunCtx:
    """Who is making a run-scoped call. `is_operator` = full access (the operator,
    or agent-auth disabled). Otherwise the call is scoped to `agent`/`run_id`."""

    agent: str | None
    run_id: str | None
    workflow_id: str | None
    is_operator: bool
    user: str | None = None      # U1: the user this run acts for (the agent's owner)
    # HOW that user was established: "idp" or "asserted". Travels with the user
    # so a downstream grant can state it, and a resource server can refuse a
    # subject nobody authenticated.
    user_asserted_by: str | None = None
    scope: list | None = None    # U2: the narrowed authority granted to this run
    # The PIN: what this run's work is ABOUT, e.g. {"account": "447"}. Read from
    # the SIGNED grant, never from a header, a body, or the prompt -- so an
    # authorization check downstream can compare the resource being touched
    # against a target the agent had no way to choose. None = unpinned, which is
    # the pre-pin behaviour and grants no narrowing (it does not deny either;
    # denying on absence would break every existing run).
    pin: dict | None = None
    # The run's subject token for the outbound RFC 8693 exchange. Read from the
    # run record, never from a header or body: it is a credential, and a caller
    # that could supply one could delegate for a user it never authenticated.
    subject_token: str | None = None
    # Verified signed expiry; persisted with queued consequential actions so
    # an operator's later approval cannot extend the run's original grant.
    expires_at: int | None = None

    def require_agent(self, agent_name: str) -> None:
        """A run may act only on its own agent's namespace (operator: any)."""
        if not (self.is_operator or self.agent == agent_name):
            raise HTTPException(
                403,
                f"run for '{self.agent}' may not act on agent '{agent_name}'",
            )

    def require_run_id(self, run_id: str) -> None:
        """A run may drive only its own run's lifecycle (operator: any)."""
        if not (self.is_operator or self.run_id == run_id):
            raise HTTPException(403, f"run token is not for run '{run_id}'")

    def require_workflow(self, workflow_id: str) -> None:
        """A run may query only its own workflow (operator: any)."""
        if not (self.is_operator or self.workflow_id == workflow_id):
            raise HTTPException(403, "run token is not for this workflow")


def _subject_token_for(run_id: str | None) -> str | None:
    """The run's stored subject token, or None.

    Only read when an external authorization server is configured: with no AS
    there is nothing to present it to, and reading a credential nothing will use
    is a needless query on a hot path.
    """
    from .. import config, db
    if not run_id or not config.AS_TOKEN_ENDPOINT:
        return None
    try:
        with db.connect() as conn:
            row = conn.execute(
                "SELECT subject_token FROM runs WHERE id = ?", (run_id,)).fetchone()
    except Exception:                                          # noqa: BLE001
        # The mint fails closed on a missing subject token, so a store that is
        # briefly unreachable denies rather than proceeding without a credential.
        return None
    return (row["subject_token"] if row else None) or None


def require_scope(ctx: "RunCtx", needed: str) -> None:
    """U2: refuse a run-scoped action the run was not granted -- so even acting as
    the entitled user, a run cannot exceed its task's scope.

    This is the enforcement point (PEP): it builds the subject, asks the PDP, and
    obeys. It deliberately does not know how the decision is reached; that rule
    lives in server/pdp.py and, with ANDYUR_PDP=authzen, outside the process."""
    subject = pdp.Subject(
        type="run", id=ctx.run_id, is_operator=ctx.is_operator, scope=ctx.scope
    )
    if not pdp.evaluate(subject, needed):
        raise HTTPException(
            403, f"insufficient_scope: this run is not granted '{needed}'")


def require_run(*, require_svid: bool = False):
    """Authorize a run-scoped call and return a RunCtx. With agent-auth on, a
    valid run token scopes the caller to its agent; a call without one must be
    the operator, proven by JWT-SVID. With agent-auth off, any known infra role
    (operator/runner/worker) is treated as the operator -- but always proven by
    SVID: there is no unauthenticated caller in any configuration."""

    def dependency(
        authorization: str | None = Header(default=None),
        x_andyur_run_token: str | None = Header(default=None),
    ) -> RunCtx:
        from ..config import AGENT_AUTH

        # 1) A valid run token always scopes the caller to its agent (agent-auth on).
        if AGENT_AUTH and x_andyur_run_token:
            from . import runtoken

            try:
                ctx = runtoken.verify(x_andyur_run_token)
            except runtoken.InvalidRunToken as exc:
                raise HTTPException(401, f"invalid run token: {exc}")
            active, trace_ctx = _run_liveness(ctx["run_id"])
            if not active:
                raise HTTPException(401, "run token is for a finished/unknown run")
            # trace this authorization INTO the run's own trace, so the identity
            # flow is visible next to the agent's work (ANDYUR_TRACE_AUTH on)
            with _auth_span("auth.require_run", trace_ctx) as span:
                span.set_attribute("andyur.agent", ctx["agent"] or "")
                span.set_attribute("andyur.run_id", ctx["run_id"] or "")
                span.set_attribute("andyur.workflow_id", ctx["workflow_id"] or "")
                span.set_attribute("andyur.auth.mode", "run_token")
                # Slice 4 enforcement: the token is a portable bearer secret; bind
                # it to the caller's container-attested SVID so a stolen token
                # replayed from a different container is rejected (SVID won't match)
                _bind_run_token_to_svid(
                    ctx, authorization, required=require_svid
                )
                span.set_attribute("andyur.auth.decision", "authorized")
                if ctx.get("sub"):
                    span.set_attribute("andyur.user", ctx["sub"])
                if ctx.get("scope") is not None:
                    span.set_attribute("andyur.scope", " ".join(ctx["scope"]))
                if ctx.get("pin") is not None:
                    span.set_attribute(
                        "andyur.pin",
                        " ".join(f"{k}={v}" for k, v in sorted(ctx["pin"].items())))
            # The subject token is read from the RUN RECORD, not from the run
            # token. It is a credential and it is large; a token claim would put
            # it in every log line that prints a decoded grant, and would let a
            # caller who obtained one grant keep presenting it after the run
            # record was cleared.
            return RunCtx(ctx["agent"], ctx["run_id"], ctx["workflow_id"],
                          is_operator=False, user=ctx.get("sub"),
                          user_asserted_by=ctx.get("sub_src"),
                          scope=ctx.get("scope"), pin=ctx.get("pin"),
                          subject_token=_subject_token_for(ctx["run_id"]),
                          expires_at=ctx["expires_at"])

        # 2) No run token -> fall back to ROLE auth (as before R1). This must NOT
        #    be a blanket passthrough, or turning identity on no longer protects
        #    these endpoints, and a compromised run could drop its token to escalate.
        #
        #    The identity-off branch that used to sit here returned an OPERATOR
        #    context to an unauthenticated caller whenever agent-auth was off or
        #    ANDYUR_TRUST_LOCAL was set. It is deleted rather than tightened: a
        #    caller who cannot be identified is not an operator in any
        #    configuration.
        token = identity.bearer_token(authorization)
        if token is None:
            raise HTTPException(401, "missing JWT-SVID bearer token")
        try:
            role = identity.role_of(identity.validate_token(token))
        except Exception as exc:
            raise HTTPException(401, f"invalid JWT-SVID: {exc}")
        # With agent-auth on, only the operator may make a run-scoped call without
        # a token; with it off, any known infra role may (role-only, as before).
        if AGENT_AUTH:
            if role != OPERATOR:
                raise HTTPException(
                    403,
                    f"role '{role}' cannot make run-scoped calls without a run token",
                )
        elif role not in (OPERATOR, RUNNER, WORKER):
            raise HTTPException(403, f"role '{role}' not permitted")
        return RunCtx(None, None, None, is_operator=True)

    return Depends(dependency)


def require_broker_run():
    """Authorize the private per-run broker with its purpose-bound token + SVID.

    The broker credential cannot call ordinary run APIs, and an ordinary run
    token cannot call this boundary.  Strict per-run SVID binding additionally
    prevents a copied broker token from defining state for another workload.
    """
    def dependency(
        authorization: str | None = Header(default=None),
        x_andyur_run_token: str | None = Header(default=None),
    ) -> RunCtx:
        from . import runtoken

        if not x_andyur_run_token:
            raise HTTPException(401, "broker state requires the broker credential")
        try:
            ctx = runtoken.verify(
                x_andyur_run_token, purpose=runtoken.PURPOSE_BROKER)
        except runtoken.InvalidRunToken as exc:
            raise HTTPException(401, f"invalid broker credential: {exc}") from exc
        active, _ = _run_liveness(ctx["run_id"])
        if not active:
            raise HTTPException(401, "broker credential is for a finished/unknown run")
        _bind_run_token_to_svid(ctx, authorization, required=True)
        return RunCtx(
            ctx["agent"], ctx["run_id"], ctx["workflow_id"], is_operator=False)

    return Depends(dependency)


def _bind_run_token_to_svid(
    ctx: dict, authorization: str | None, *, required: bool = False
) -> None:
    """Enforce that a run token is presented from the container it belongs to.

    When the caller presents a per-run JWT-SVID (the container attestation from
    Slice 3/4), it MUST name the same agent/run as the token, or the call is a
    stolen-token replay from a different container -> 403. In strict mode
    (ANDYUR_REQUIRE_RUN_SVID) a matching per-run SVID is required on every
    token-scoped call; otherwise it is enforced only when present, so the
    existing role paths keep working."""
    from ..config import REQUIRE_RUN_SVID

    strict = REQUIRE_RUN_SVID or required

    with _auth_span("auth.bind") as span:
        token = identity.bearer_token(authorization)
        has_bearer = token is not None
        if not has_bearer:
            span.set_attribute(
                "andyur.auth.bind", "absent-strict" if strict else "absent-lax"
            )
            if strict:
                raise HTTPException(401, "run-scoped call requires a JWT-SVID (strict mode)")
            return
        try:
            spiffe_id = identity.validate_token(token)
        except Exception as exc:
            span.set_attribute("andyur.auth.bind", "invalid-svid")
            raise HTTPException(401, f"invalid JWT-SVID: {exc}")
        span.set_attribute("andyur.auth.svid", spiffe_id)
        svid_agent, svid_run = identity.parse_agent_run(spiffe_id)
        if svid_agent is None:  # a role SVID (e.g. operator), not a per-run identity
            span.set_attribute("andyur.auth.bind", "role-svid")
            if strict:
                raise HTTPException(403, "run-scoped call requires a per-run SVID (strict mode)")
            return
        span.set_attribute("andyur.auth.svid_agent", svid_agent)
        span.set_attribute("andyur.auth.svid_run", svid_run)
        if svid_agent != ctx["agent"] or svid_run != ctx["run_id"]:
            span.set_attribute("andyur.auth.bind", "mismatch")
            raise HTTPException(
                403,
                "run token does not match the caller's attested SVID identity "
                "(token/container mismatch)",
            )
        span.set_attribute("andyur.auth.bind", "match")


def _run_liveness(run_id: str | None) -> tuple[bool, str | None]:
    """(is the run still pending/running, its stored trace context) in one query.
    Liveness stops a run token being replayed after its run terminates; the trace
    context lets the authorization span join the run's own trace."""
    if not run_id:
        return (False, None)
    from .. import db

    with db.connect() as conn:
        row = conn.execute(
            "SELECT state, trace_ctx FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
    if row is None:
        return (False, None)
    return (row["state"] in ("pending", "running"), row["trace_ctx"])


def _run_active(run_id: str | None) -> bool:
    """Whether a run is still pending/running -- so a run token cannot be replayed
    against an agent's namespace after its run has terminated (persistence)."""
    return _run_liveness(run_id)[0]

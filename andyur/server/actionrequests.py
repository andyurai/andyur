"""The consequential-action request: one row per production change an agent asks for.

Lane A, board rows 9-12. `andyur.actions` decides and `andyur.rollback` performs;
this is where a request becomes a DURABLE, QUERYABLE FACT and where the two are
joined in the right order.

WHY A TABLE AND AN API AND NOT A SPAN. The MVP exit criterion is that an
operator can follow the whole story "without opening a database, kubectl, Jaeger
or source code". A decision that exists only in a span or in stdout fails that
criterion by definition, so the decision is a row the console reads over HTTP.

WHAT THE AGENT CANNOT REACH FROM HERE. Everything that decides. The run's
authority (`scope`) and its target (`pin`) are read from the SIGNED GRANT the
run token carries; the request body contributes the tool name and the target,
both of which are then checked against those two. The Kubernetes credential is
the server's, is never handed to the run, and is used only after a decision.
"""

from __future__ import annotations

import logging
import json
import os
import re
import time
import uuid

from .. import actions, db, observability, otel, rollback
from . import pdp

log = logging.getLogger(__name__)

_tracer = otel.setup_tracing("andyur-server")
SERVICE_NAME = "andyur-server"

# `result_detail` is rendered by the console and is the one field here that can
# carry cluster observations. Remote exception bodies/headers are never copied:
# the requesting run may read this field but cannot read cluster credentials.
MAX_DETAIL_CHARS = 300
# HOW MANY CONSEQUENTIAL ACTIONS ONE RUN MAY REQUEST.
#
# There was no bound, and the agent is what drives this endpoint. Two costs
# followed: a run could write unbounded rows into a server-owned table, and --
# worse -- an ALLOWED action EXECUTES, so an authorised run could ask for the
# same rollback in a loop and be obeyed every time, each one holding a request
# thread for as long as the read-back watches the cluster. Neither is exotic;
# a stuck agent retrying a tool call produces both.
#
# The cap counts EVERY row, denials included, because the row is the cost. The
# platform bounds the same class elsewhere the same way
# (coordinator.MAX_WORKFLOW_RUNS), and one rollback of one pinned deployment
# does not legitimately need many attempts.
MAX_ACTIONS_PER_RUN = int(os.environ.get("ANDYUR_MAX_ACTIONS_PER_RUN", "8"))
# How long `_perform` watches the cluster for the consequence of its write. The
# module constant (rather than a literal at the call site) is what a test sets
# to zero and an operator raises for a slow cluster.
OBSERVE_SECONDS = float(os.environ.get("ANDYUR_ACTION_OBSERVE_SECONDS",
                                       rollback.OBSERVE_SECONDS))
# A revision as Kubernetes writes it. Anything else is not put on a span: the
# annotation is a cluster value, but "it came from the cluster" is not the same
# statement as "it is bounded".
_REVISION = re.compile(r"^[0-9]{1,10}$")

_VIEW_FIELDS = (
    "id", "run_id", "tool", "target", "requested_at", "decision",
    "decision_reason", "decided_at", "approved_by", "approved_by_asserted_by",
    "approved_at", "result", "result_detail", "finished_at",
)
_WITHHELD_FIELDS = frozenset({"authorization_snapshot", "grant_expires_at"})


class ActionExhausted(ValueError):
    """The run has spent its consequential-action budget.

    Distinct from a refusal and from a denial, because it is neither the
    request's fault nor a decision about its legitimacy: the same request would
    have been decided on its merits a moment earlier. The caller gets 429, and
    an operator reading the rows sees a run that kept asking.
    """


class ActionRefused(ValueError):
    """The request is unusable as sent -- an unknown tool, an unusable target.

    DISTINCT FROM A DENIAL, and the distinction is the point: a denial is a
    decision Andyur made about a legitimate request and gets a row an operator
    can read. This is a malformed request, which gets a 422 and no row, because
    recording it as a decision would put "denied" beside a question nobody asked.
    """


def _client_factory():
    """The Kubernetes adapter, resolved late so importing this module (and thus
    the whole server) never requires the kubernetes client library or a
    reachable cluster. Tests substitute this name."""
    from .kubernetes_deployments import DeploymentsApi
    return DeploymentsApi()


def action_view(row) -> dict:
    """The one projection. An explicit field list rather than `dict(row)`, so a
    column added later is a decision about what a client may see, not an
    accident (`app._RUN_WITHHELD` settled that argument for runs)."""
    return {field: row[field] for field in _VIEW_FIELDS}


def list_for_run(run_id: str) -> list[dict]:
    """Every consequential action this run requested, oldest first."""
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM action_requests WHERE run_id = ? "
            "ORDER BY requested_at, id", (run_id,)).fetchall()
    return [action_view(row) for row in rows]


def get(action_id: str) -> dict | None:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM action_requests WHERE id = ?", (action_id,)).fetchone()
    return action_view(row) if row is not None else None


def _record_decision(span, decision: actions.Decision) -> None:
    """The decision on ITS OWN span, the counter and the log, BY NAME.

    Per the operator's 2026-08-26 rule every decision is observable; per this
    lane's own rule it is observable as a NAME from a closed set, so a decision
    invented at a call site is a ValueError here rather than a new dimension
    nobody declared.

    THE SPAN IS PASSED IN, not taken from the ambient context. Reading
    `get_current_span()` decorated whatever the caller happened to have open --
    a gate's root span, a request span, or a no-op -- so three decisions in one
    process overwrote each other on one unrelated span and a reader could not
    tell which decision belonged to which action. Found by the live gate, which
    asked the trace what had been decided and got nothing back.
    """
    try:
        span.set_attribute("andyur.action_decision", decision.decision)
        span.set_attribute("andyur.action_reason", decision.reason)
    except Exception:                                          # noqa: BLE001
        pass
    otel.try_record_metric(SERVICE_NAME, "andyur.action.decisions", 1,
                           andyur__action_decision=decision.decision,
                           andyur__action_reason=decision.reason)
    observability.event(log, "action.decided", action_decision=decision.decision,
                        action_reason=decision.reason)


def _record_identity(span, run_id: str) -> None:
    """Correlate each decision with its sealed run, never authority inputs."""
    try:
        span.set_attribute("andyur.run_id", otel.safe_attribute(run_id))
        span.set_attribute("andyur.component", "action-requests")
        with db.connect() as conn:
            row = conn.execute("SELECT agent FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row:
            span.set_attribute("andyur.agent_id", otel.safe_attribute(row["agent"]))
    except Exception:
        # Observability cannot grant or refuse an action.
        pass


def _record_result(span, result: str) -> None:
    try:
        span.set_attribute("andyur.action_result", result)
    except Exception:                                          # noqa: BLE001
        pass
    otel.try_record_metric(SERVICE_NAME, "andyur.action.results", 1,
                           andyur__action_result=result)
    observability.event(log, "action.performed", action_result=result)


def _run_id_of(action_id: str) -> str:
    """Which run an action row belongs to. Only for finding that run's trace
    context; the authority for a decision never comes from here."""
    try:
        with db.connect() as conn:
            row = conn.execute("SELECT run_id FROM action_requests WHERE id = ?",
                               (action_id,)).fetchone()
        return row["run_id"] if row else ""
    except Exception:                                     # noqa: BLE001
        return ""


def _run_traceparent(run_id: str) -> str | None:
    """The run's own trace context, as the control plane recorded it.

    Absent for a run anchored before telemetry was on, and for any run whose
    row is gone -- both of which give None, and a None parent is simply a root
    span, which is what this was before. It never raises: a decision must not
    fail because its telemetry could not find a parent.
    """
    try:
        with db.connect() as conn:
            row = conn.execute("SELECT trace_ctx FROM runs WHERE id = ?",
                               (run_id,)).fetchone()
        return row["trace_ctx"] if row else None
    except Exception:                                     # noqa: BLE001
        return None


def _locked_run(conn, run_id: str):
    """Lock lifecycle before spending authority, using the existing DB engine.

    Workflow then run matches halt_workflow's lock order. Creating a missing
    workflow row prevents a concurrent first halt from racing a missing-row
    SELECT. SQLite's writer reservation precedes every read in this transaction;
    PostgreSQL uses its row locks. No network call occurs under these locks.
    """
    if not db.IS_POSTGRES:
        conn.execute("BEGIN IMMEDIATE")
    initial = conn.execute("SELECT workflow_id FROM runs WHERE id = ?",
                           (run_id,)).fetchone()
    if initial is None:
        return None, False
    halted = False
    workflow_id = initial["workflow_id"]
    if workflow_id:
        conn.execute("INSERT INTO workflows (id, state, created_at) "
                     "VALUES (?, 'active', ?) ON CONFLICT(id) DO NOTHING",
                     (workflow_id, db.utcnow()))
        suffix = " FOR UPDATE" if db.IS_POSTGRES else ""
        workflow = conn.execute("SELECT state FROM workflows WHERE id = ?" + suffix,
                                (workflow_id,)).fetchone()
        halted = workflow["state"] == "halted"
    suffix = " FOR UPDATE" if db.IS_POSTGRES else ""
    row = conn.execute("SELECT state, revoked_at FROM runs WHERE id = ?" + suffix,
                       (run_id,)).fetchone()
    return row, halted


def _lifecycle_denial(run, halted: bool, grant_expires_at) -> actions.Decision | None:
    if run is None or run["state"] not in ("pending", "running") or run["revoked_at"]:
        return actions.Decision(actions.DENIED, actions.REASON_RUN_INACTIVE)
    if halted:
        return actions.Decision(actions.DENIED, actions.REASON_WORKFLOW_HALTED)
    if not isinstance(grant_expires_at, int) or isinstance(grant_expires_at, bool):
        return actions.Decision(actions.DENIED, actions.REASON_AUTHORITY_MISSING)
    if grant_expires_at <= int(time.time()):
        return actions.Decision(actions.DENIED, actions.REASON_GRANT_EXPIRED)
    return None


def request(run_id: str, tool: str, namespace: str, deployment: str, *,
            granted_scope, pin, grant_expires_at: int | None,
            policy_permits: bool = True) -> dict:
    """Record one requested consequential action, decide it, and -- only if the
    decision is `allowed` -- perform it.

    `granted_scope` and `pin` come from the run's signed grant. They are
    parameters rather than lookups so that the ONE place they may come from is
    visible at the call site, and so this function cannot be handed a run id and
    quietly re-derive an authority from a row an attacker might have influenced.
    """
    if tool not in actions.TOOLS:
        # Refused, not decided: see ActionRefused. `tool` is echoed back to the
        # caller that sent it and never reaches a span or a log.
        raise ActionRefused(
            f"{tool!r} is not a consequential action this deployment admits")
    try:
        target = actions.canonical_target(namespace, deployment)
    except ValueError as exc:
        raise ActionRefused(str(exc)) from exc

    # ONE RUN IS ONE TRACE, INCLUDING WHAT THE PLATFORM DECIDED BECAUSE OF IT.
    #
    # `action.decide` used to be a root span of its own, so an operator reading
    # a run's trace saw the agent's `mcp.tool request_rollback` call and then
    # nothing: the request and the decision it caused, in two traces,
    # correlated by nobody. The one artifact that is supposed to show a
    # consequential action end to end showed half of it.
    #
    # The parent is the RUN's stored traceparent -- written by the control plane
    # when it anchored the run, read here from the row. NOT a `traceparent`
    # header off the request: `ObservedASGI` refuses those everywhere in this
    # codebase, because a span parent taken from a caller is a parent the caller
    # chose, and the caller here is a process running an agent's instructions.
    # A stored value the requester cannot influence is a different thing.
    parent = otel.context_from(_run_traceparent(run_id))
    with _tracer.start_as_current_span("action.decide", context=parent,
                                       record_exception=False) as span:
        _record_identity(span, run_id)
        decision = actions.decide(tool, granted_scope, policy_permits=policy_permits)
        if decision.decision != actions.DENIED and not actions.target_is_pinned(
                pin, namespace, deployment):
            # Authority first, then target: a run with no rollback grant is
            # denied for THAT reason whatever it aimed at, and only a run that
            # could legitimately roll something back is told it aimed at the
            # wrong thing.
            decision = actions.Decision(actions.DENIED,
                                        actions.REASON_TARGET_NOT_PINNED)
        action_id = uuid.uuid4().hex[:12]
        now = db.utcnow()
        with db.connect() as conn:
            run, halted = _locked_run(conn, run_id)
            if run is None:
                raise ActionRefused(f"no run '{run_id}'")
            # Authorization, budget and insertion are one serialized admission.
            # Sharing a connection alone does not serialize COUNT with INSERT.
            used = conn.execute(
                "SELECT COUNT(*) AS n FROM action_requests WHERE run_id = ?",
                (run_id,)).fetchone()["n"]
            if used >= MAX_ACTIONS_PER_RUN:
                raise ActionExhausted(
                    f"this run has already requested {used} consequential actions, "
                    f"which is its cap")
            if decision.decision != actions.DENIED:
                decision = _lifecycle_denial(run, halted, grant_expires_at) or decision
            conn.execute(
                "INSERT INTO action_requests (id, run_id, tool, target, requested_at, "
                "decision, decision_reason, decided_at, result, authorization_snapshot, "
                "grant_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (action_id, run_id, tool, target, now, decision.decision,
                 decision.reason, now,
                 actions.NOT_ATTEMPTED if decision.decision == actions.DENIED else None,
                 json.dumps({"scope": granted_scope, "pin": pin}, sort_keys=True),
                 grant_expires_at),
            )
        _record_decision(span, decision)
    if decision.decision == actions.ALLOWED:
        return _perform(action_id, target)
    return get(action_id)


def approve(action_id: str, approver: str, asserted_by: str) -> dict:
    """One human consents to an action the run was already entitled to perform.

    `approver` and `asserted_by` are a PAIR, always. An identity rendered
    without how it was established is an asserted identity displayed as a proven
    one -- this week's recurring defect, and the first instance visible in the
    artifact we show people.

    Re-evaluate current policy against the verified snapshot, then atomically
    check lifecycle and consume the pending approval. Human consent cannot
    resurrect a finished run, extend an expired grant, or override the PDP.

    The admission commit is the in-flight boundary: a later halt prevents NEW
    admissions, but cannot undo a Kubernetes mutation already admitted here.
    This is not a distributed transaction with Kubernetes. Approval consents
    to rollback of the pinned resource at execution time, not a historical
    revision/diff that the request never captured.
    """
    with db.connect() as conn:
        original = conn.execute("SELECT * FROM action_requests WHERE id = ?",
                                (action_id,)).fetchone()
    if original is None or original["decision"] != actions.APPROVAL_REQUIRED:
        return None
    # The external PDP may block; lifecycle locks are acquired only AFTER its
    # response, so a halt during that wait is observed instead of delayed.
    with _tracer.start_as_current_span("action.approve",
                                       context=otel.context_from(_run_traceparent(
                                           original["run_id"])),
                                       record_exception=False) as span:
        span.set_attribute("andyur.action_id", action_id)
        _record_identity(span, original["run_id"])
        decision = _approval_policy(original)
        with db.connect() as conn:
            run, halted = _locked_run(conn, original["run_id"])
            row = conn.execute("SELECT * FROM action_requests WHERE id = ?",
                               (action_id,)).fetchone()
            if row is None or row["decision"] != actions.APPROVAL_REQUIRED:
                return None
            # Bind the policy answer to exactly the stored authority it saw.
            if any(row[key] != original[key] for key in (
                    "authorization_snapshot", "grant_expires_at", "tool", "target", "run_id")):
                decision = actions.Decision(actions.DENIED, actions.REASON_AUTHORITY_MISSING)
            elif decision.decision != actions.DENIED:
                decision = (_lifecycle_denial(run, halted, row["grant_expires_at"])
                            or decision)
            now = db.utcnow()
            denied = decision.decision == actions.DENIED
            changed = conn.execute(
                "UPDATE action_requests SET decision = ?, decision_reason = ?, "
                "decided_at = ?, approved_by = ?, approved_by_asserted_by = ?, "
                "approved_at = ?, result = ?, finished_at = ? "
                "WHERE id = ? AND decision = ?",
                (decision.decision, decision.reason, now,
                 None if denied else approver, None if denied else asserted_by,
                 None if denied else now, actions.NOT_ATTEMPTED if denied else None,
                 now if denied else None, action_id, actions.APPROVAL_REQUIRED)).rowcount
        if not changed:
            return None
        _record_decision(span, decision)
        if denied:
            _record_result(span, actions.NOT_ATTEMPTED)
    row = get(action_id)
    return row if denied else _perform(action_id, row["target"])


def _approval_policy(row) -> actions.Decision:
    """Use only the verified request snapshot; an absent legacy grant denies."""
    try:
        snapshot = json.loads(row["authorization_snapshot"])
        scope, pin = snapshot["scope"], snapshot["pin"]
        if not isinstance(scope, list) or not all(isinstance(s, str) for s in scope):
            raise ValueError("invalid scope")
        namespace, deployment = actions.split_target(row["target"])
        held = actions.grant_in_effect(row["tool"], scope)
    except (TypeError, ValueError, KeyError):
        return actions.Decision(actions.DENIED, actions.REASON_AUTHORITY_MISSING)
    if held is None:
        return actions.Decision(actions.DENIED, actions.REASON_NO_WRITE_AUTHORITY)
    if not actions.target_is_pinned(pin, namespace, deployment):
        return actions.Decision(actions.DENIED, actions.REASON_TARGET_NOT_PINNED)
    if not pdp.evaluate(pdp.Subject(type="run", id=row["run_id"], scope=scope), held):
        return actions.Decision(actions.DENIED, actions.REASON_POLICY_DENIED)
    return actions.Decision(actions.ALLOWED, actions.REASON_APPROVED)


def _perform(action_id: str, target: str) -> dict:
    """Execute an ALLOWED action and record what the CLUSTER says happened.

    The result written here is an OBSERVATION. `succeeded` requires that the
    original deployment has the intended template and controller-observed
    generation, as well as a changed revision;
    everything short of that is `failed` with the observed state named. A
    `succeeded` derived from our own dispatch returning 200 would be a green
    carrying no information, which is the failure family this repository has
    found three times in a week.
    """
    namespace, deployment = actions.split_target(target)
    # The run's trace again, for the same reason: `_perform` runs after the
    # decide span has closed, so without a parent it is a third orphan root --
    # and it is the span that says whether the cluster ACTUALLY moved, which is
    # the one an operator most needs to find from the run.
    run_id = _run_id_of(action_id)
    parent = otel.context_from(_run_traceparent(run_id))
    with _tracer.start_as_current_span("action.perform", context=parent,
                                       record_exception=False) as span:
        span.set_attribute("andyur.action_id", action_id)
        _record_identity(span, run_id)
        span.set_attribute("andyur.operation", "rollback")
        started = time.monotonic()
        try:
            outcome = rollback.rollback(_client_factory(), namespace, deployment,
                                        observe_seconds=OBSERVE_SECONDS)
            result = actions.SUCCEEDED if outcome.changed else actions.FAILED
            detail = outcome.detail
            reason = outcome.reason
            if outcome.observed_revision and _REVISION.fullmatch(
                    outcome.observed_revision):
                span.set_attribute("andyur.observed_revision",
                                   outcome.observed_revision)
        except rollback.NoPreviousRevision as exc:
            # A legitimate cluster state, not a platform fault: reporting it as
            # an error would tell an operator the rollback was refused when in
            # fact there was nowhere to roll back to.
            result, detail = actions.FAILED, str(exc)
            reason = "no_previous_revision"
        except Exception:                                      # noqa: BLE001
            # The run reads this row. Even bounded vendor diagnostics may
            # contain privileged template values, credentials or headers.
            # Keep a closed cause, not a stringified backend exception.
            result = actions.FAILED
            detail = "cluster_error: rollback execution failed"
            reason = "cluster_error"
        detail = detail[:MAX_DETAIL_CHARS]
        duration = time.monotonic() - started
        span.set_attribute("andyur.rollback_reason", reason)
        span.add_event("rollback.observed", {"andyur.rollback_reason": reason,
                                              "andyur.duration_ms": duration * 1000})
        otel.try_record_metric(SERVICE_NAME, "andyur.action.observation_seconds",
                               duration, andyur__rollback_reason=reason)
        observability.event(log, "action.observed", rollback_reason=reason,
                            duration_ms=duration * 1000)
        _record_result(span, result)
    with db.connect() as conn:
        conn.execute(
            "UPDATE action_requests SET result = ?, result_detail = ?, "
            "finished_at = ? WHERE id = ?",
            (result, detail, db.utcnow(), action_id))
    return get(action_id)

"""Messaging: the coordination channel between agents (and the operator).

Sending a message to an agent best-effort wakes it, so a message is delivered
promptly rather than waiting for the agent's next scheduled run. The recipient
sees its unread messages in every run's context and marks them handled. The
special recipient/sender 'operator' is how the operator chat REPL talks to an
agent: the operator's message wakes the agent, and the agent replies by
sending a message back to 'operator'.
"""

import logging
import uuid
import json

from .. import db, orchestration, otel
from . import coordinator


_tracer = otel.setup_tracing("andyur-server")


def _anchored(trace_ctx, agent: str, why: str):
    """The trace the woken run will belong to.

    A DELEGATING RUN'S CONTEXT ALWAYS WINS: it is what links the assignee's run
    into the chain that caused it, which is the whole point of `parent_run_id`
    beside it.

    But when nobody supplied one -- an OPERATOR creating a task or sending a
    message -- the woken run got `trace_ctx=None` and was anchored to NOTHING.
    `agents trigger` opens a span for exactly this reason (app.trigger_agent);
    these two paths never did, and the control plane has no ASGI
    instrumentation to fall back on, so `current_traceparent()` here returns
    None too. The result: the most common way work reaches an agent produced
    runs with no trace at all, while "one run is one trace" is an exit
    criterion (observability-exit-criteria.md 7).

    So a root span is opened for the wakeup, named as the trigger names its
    own, and its context becomes the run's. It closes immediately: this span
    marks the CAUSE, and everything the run does hangs off the traceparent
    stored on the run row.
    """
    if trace_ctx:
        return trace_ctx
    with _tracer.start_as_current_span(f"run {agent}") as span:
        try:
            span.set_attribute("andyur.agent", agent)
            span.set_attribute("andyur.wakeup", why)
        except Exception:                                      # noqa: BLE001
            pass
        return otel.current_traceparent()


log = logging.getLogger(__name__)


def send_message(
    recipient: str,
    sender: str,
    body: str,
    trace_ctx: str | None = None,
    parent_run_id: str | None = None,
    deleg_user: str | None = None,
    deleg_scope: list | None = None,
) -> dict:
    mid = uuid.uuid4().hex[:12]
    now = db.utcnow()
    with db.connect() as conn:
        is_agent = conn.execute(
            "SELECT 1 FROM agents WHERE name = ?", (recipient,)
        ).fetchone()
        # Only a message that would WAKE AN AGENT is gated + stamped: it is
        # refused (under the workflow lock) if the workflow is halted/at cap or the
        # parent is unknown, and stamped so a halt hides it. Messages to the
        # OPERATOR are the human control + audit channel and are deliberately NOT
        # gated, capped, or hidden -- halting a run must never silence its report
        # to the operator, and a deep chain must still be able to escalate.
        workflow_id = None
        if is_agent and parent_run_id:
            workflow_id, _ = coordinator.guard_new_work(conn, parent_run_id, now)
        conn.execute(
            "INSERT INTO messages (id, recipient, sender, body, state, created_at, "
            "workflow_id, subject_context, parent_run_id) "
            "VALUES (?, ?, ?, ?, 'unread', ?, ?, ?, ?)",
            (mid, recipient, sender, body, now, workflow_id,
             coordinator.pin_of_run(conn, parent_run_id), parent_run_id),
        )
        conn.execute(
            "UPDATE messages SET delegated_user = ?, delegated_scope = ? WHERE id = ?",
            (deleg_user, json.dumps(deleg_scope) if deleg_scope is not None else None, mid),
        )
    # wake the recipient if it is an agent (the operator is not woken). trace_ctx
    # links the recipient's run into the sender's trace; parent_run_id lets the
    # coordinator inherit the sender run's workflow (server-authoritative), so a
    # messaged agent's run stays in the same unit of work without the sender
    # asserting a workflow id.
    if is_agent:
        # A refused wakeup (recipient busy) leaves notified_at NULL so the
        # heartbeat drain comes back for it once the recipient is free, and the
        # stamp is written when a run actually STARTS and renders the message
        # (coordinator.start_run). See heartbeat.drain_pending_work.
        try:
            orchestration.facade().request_agent_run(
                recipient, f"new message from {sender}", run_type="message",
                trace_ctx=_anchored(trace_ctx, recipient, "message"),
                parent_run_id=parent_run_id,
                user=deleg_user, scope=deleg_scope,
            )
        except coordinator.InputRefused as exc:
            # Same as tasks.create_task: the row is durable, the wakeup was
            # best effort, and this refusal is permanent rather than busy.
            log.warning("message %s sent to '%s' but no run can be woken for "
                        "it: %s", mid, recipient, exc)
        except orchestration.OrchestrationError as exc:
            # As in tasks.create_task: the message row is committed, the drain
            # comes back for unwoken work, and a best-effort wakeup must not
            # turn a delivered message into a 500.
            log.warning("message %s sent to '%s'; the wakeup was refused by "
                        "orchestration and the drain will re-drive it: %s",
                        mid, recipient, exc)
    return {"id": mid, "recipient": recipient, "sender": sender}


# What a caller of list_messages is told. See TASK_VIEW_FIELDS in tasks.py for
# why this is an allow-list and not a `SELECT *`.
MESSAGE_VIEW_FIELDS = (
    "id", "recipient", "sender", "body", "state", "created_at",
    "workflow_id", "subject_context", "delegated_user", "delegated_scope",
)
MESSAGE_WITHHELD = {
    "parent_run_id",   # the run that sent it; drain bookkeeping, see tasks.py
    "notified_at",     # when it was first offered to a run
}


def message_view(row) -> dict:
    return {k: v for k, v in dict(row).items() if k in MESSAGE_VIEW_FIELDS}


def list_messages(recipient: str, state: str | None = None) -> list[dict]:
    # messages belonging to a halted workflow are never surfaced, so a kill-switch
    # closes the message propagation channel too (mirrors list_tasks)
    clauses = [
        "recipient = ?",
        "(workflow_id IS NULL OR workflow_id NOT IN "
        "(SELECT id FROM workflows WHERE state = 'halted'))",
    ]
    params: list = [recipient]
    if state:
        clauses.append("state = ?")
        params.append(state)
    where = " WHERE " + " AND ".join(clauses)
    with db.connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM messages{where} ORDER BY created_at", params
        ).fetchall()
    return [message_view(r) for r in rows]


def handle_message(message_id: str) -> bool:
    with db.connect() as conn:
        cur = conn.execute(
            "UPDATE messages SET state = 'handled' WHERE id = ?", (message_id,)
        )
    return cur.rowcount > 0

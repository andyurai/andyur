"""Task service: the unit of delegated work.

An agent (or the operator) creates a task for an assignee. The assignee sees
its open tasks in every run's context, claims them (open -> in_progress), and
closes them (-> closed) with a result. Creating a task best-effort wakes the
assignee so delegation is immediate rather than waiting for the next run.

State transitions are guarded so an agent cannot, for example, close a task it
never claimed out from under another worker.
"""

import json
import logging
import uuid

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

VALID_STATES = ("open", "in_progress", "closed")


def create_task(
    assignee: str,
    creator: str,
    title: str,
    detail: str = "",
    trace_ctx: str | None = None,
    parent_run_id: str | None = None,
    deleg_user: str | None = None,
    deleg_scope: list | None = None,
) -> dict:
    tid = uuid.uuid4().hex[:12]
    now = db.utcnow()
    with db.connect() as conn:
        exists = conn.execute(
            "SELECT 1 FROM agents WHERE name = ?", (assignee,)
        ).fetchone()
        if exists is None:
            raise ValueError(f"no agent named '{assignee}' to assign the task to")
        # Workflow is SERVER-AUTHORITATIVE (copied from the creating run, unknown
        # parent refused), and the kill-switch + caps are enforced HERE, where the
        # durable work is created -- under the same workflow-row lock the wakeup
        # uses, so a halted/capped workflow refuses the task row itself, race-free.
        workflow_id, depth = coordinator.guard_new_work(conn, parent_run_id, now)
        # Carry the creating run's PIN onto the row. The immediate wakeup below
        # inherits it through parent_run_id, but that wakeup is best-effort: a
        # BUSY assignee is refused and the work is re-driven later by
        # heartbeat.drain_pending_work, which has no parent to inherit from.
        # Without this the deferred path produced an UNPINNED run, and a
        # compromised agent could force it just by delegating to a busy peer.
        pin = coordinator.pin_of_run(conn, parent_run_id)
        conn.execute(
            "INSERT INTO tasks (id, assignee, creator, title, detail, state, "
            "created_at, updated_at, workflow_id, subject_context, parent_run_id) "
            "VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)",
            (tid, assignee, creator, title, detail, now, now, workflow_id, pin,
             parent_run_id),
        )
        conn.execute(
            "UPDATE tasks SET delegated_user = ?, delegated_scope = ? WHERE id = ?",
            (deleg_user, json.dumps(deleg_scope) if deleg_scope is not None else None, tid),
        )
    # delegation: try to wake the assignee to work it now (best effort). trace_ctx
    # links the assignee's run into the creating run's trace; parent_run_id lets
    # the coordinator inherit workflow + depth; the resolved workflow_id is passed
    # so the woken run and this task row match even if the parent later finishes.
    # U4: the delegated run inherits the delegator's user and a scope no wider than
    # the delegator's own, so authority narrows across the hop and never widens.
    # Best effort means the assignee is often BUSY, which is normal and used to
    # be the end of it: the row was durable, so the work was deferred rather
    # than lost, but nothing ever came back for it. An agent whose only source
    # of work is delegation could sit idle beside an open task indefinitely.
    # The heartbeat drain now re-drives it; this task counts as offered only
    # when a run actually STARTS and renders it (coordinator.start_run).
    try:
        orchestration.facade().request_agent_run(
            assignee, f"new task from {creator}: {title}", run_type="task",
            trace_ctx=_anchored(trace_ctx, assignee, "task"),
            parent_run_id=parent_run_id, workflow_id=workflow_id,
            user=deleg_user, scope=deleg_scope,
        )
    except coordinator.InputRefused as exc:
        # The task row is durable and already committed; only the best-effort
        # wakeup failed, and it failed PERMANENTLY: the assignee's manifest
        # declares a process that needs an input, and delegated work carries
        # none. Treated as the busy case is treated (the work stays open and
        # visible), but said out loud, because the drain will report it on
        # every tick until someone reads this.
        log.warning("task %s created for '%s' but no run can be woken for it: %s",
                    tid, assignee, exc)
    except orchestration.OrchestrationError as exc:
        # BEST EFFORT MEANS BEST EFFORT. The task row is committed before this
        # runs, and the drain re-drives work nobody woke for, so a wakeup that
        # fails costs latency and nothing else.
        #
        # Routing through the facade widened what can be raised here --
        # provider unreachable, capability missing, workflow bound to another
        # engine -- and only InputRefused was caught, so an engine having a bad
        # minute turned a SUCCESSFUL, durable POST /tasks into a 500 for the
        # caller. Delegation is exactly the path that must survive an
        # orchestration hiccup.
        log.warning("task %s created for '%s'; the wakeup was refused by "
                    "orchestration and the drain will re-drive it: %s",
                    tid, assignee, exc)
    return {"id": tid, "assignee": assignee, "title": title, "state": "open"}


# WHAT A CALLER OF list_tasks IS TOLD, named one column at a time.
#
# `SELECT *` published whatever the schema happened to hold, so a column added
# for the server's own bookkeeping became API the moment it was created -- and
# the caller here is a RUN, the least-trusted component on the platform. Adding
# `parent_run_id` for the drain is what demonstrated it: an internal handle
# reached every agent without anyone deciding it should. Same finding, and the
# same fix, as the run projection in app.py.
TASK_VIEW_FIELDS = (
    "id", "assignee", "creator", "title", "detail", "state",
    "created_at", "updated_at", "workflow_id", "subject_context",
    "delegated_user", "delegated_scope", "result",
)
TASK_WITHHELD = {
    # the run that created the work. Server bookkeeping: it is how the drain
    # attributes a deferred run, and the assignee has no use for it. A run id
    # is also what `parent_run_id` accepts on delegation -- the route takes
    # that from the caller's context and never from the body, so this is
    # defence in depth rather than the control itself.
    "parent_run_id",
    # when the work was first offered to a run. Drain bookkeeping; an agent
    # reading it would learn only whether it had been woken before.
    "notified_at",
}


def task_view(row) -> dict:
    return {k: v for k, v in dict(row).items() if k in TASK_VIEW_FIELDS}


def list_tasks(assignee: str | None = None, state: str | None = None) -> list[dict]:
    # tasks belonging to a halted workflow are never surfaced, so a kill-switch
    # also stops already-created delegated work from being drained later
    clauses = [
        "(workflow_id IS NULL OR workflow_id NOT IN "
        "(SELECT id FROM workflows WHERE state = 'halted'))"
    ]
    params: list = []
    if assignee:
        clauses.append("assignee = ?")
        params.append(assignee)
    if state:
        clauses.append("state = ?")
        params.append(state)
    where = " WHERE " + " AND ".join(clauses)
    with db.connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM tasks{where} ORDER BY created_at", params
        ).fetchall()
    return [task_view(r) for r in rows]


def update_task(task_id: str, state: str, result: str | None = None) -> dict | None:
    if state not in VALID_STATES:
        raise ValueError(f"state must be one of {VALID_STATES}")
    now = db.utcnow()
    with db.connect() as conn:
        cur = conn.execute(
            "UPDATE tasks SET state = ?, result = COALESCE(?, result), updated_at = ? "
            "WHERE id = ?",
            (state, result, now, task_id),
        )
        if cur.rowcount == 0:
            return None
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    return dict(row)

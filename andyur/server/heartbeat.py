"""Server heartbeat loop.

A background task that ticks every 30 seconds and keeps the platform
self-healing:

- reaps runs stuck in 'running' past the TTL (runner crashed or hung
  without reporting), returning the agent to idle
- requeues pending runs assigned to a worker whose heartbeat went stale,
  so a surviving worker can pick them up

Phase 4 adds scheduled-task evaluation to this loop.
"""

import asyncio
import json
import logging
import os
import time
import typing
from datetime import datetime, timedelta, timezone

from .. import config, db, graph, observability, orchestration, otel
from ..registry.models import LIFETIME_FLOOR_SECONDS
from ..registry.models import (LIFETIME_CEILING_SECONDS, MalformedLifecycle,
                               granted_lifetime_seconds,
                               lifecycle_from_assignment)
from . import coordinator, engine_breaker

log = logging.getLogger(__name__)
_tracer = otel.get_tracer("andyur-server")

class WaitingWork(typing.NamedTuple):
    """One agent's waiting work, as the drain needs to see it.

    NAMED because this grew to eleven columns and was unpacked positionally.
    Reordering the SELECT would then have shifted every field silently -- the
    pin would arrive as the user, the workflow as the scope -- and each of
    those decides a security control. A rename is a loud error; a shift is not.
    """
    agent: str
    pin: str | None
    distinct_pins: int
    user: str | None
    scope: str | None
    distinct_authorities: int
    workflow_id: str | None
    distinct_workflows: int
    parent_run_id: str | None
    distinct_parents: int
    parent_depth: int | None


TICK_SECONDS = 30
_last_consolidate = 0.0
# Bounded by the platform's lifetime ceiling, like every declared grant: the
# engine's execution bound is derived from that ceiling (ADR-014 D11), and this
# is the number the worker, the token and the reaper all take for a run that
# declared nothing.
RUN_TTL_SECONDS = min(int(os.environ.get("ANDYUR_RUN_TTL_SECONDS", "900")),
                      LIFETIME_CEILING_SECONDS)
RUN_GRACE_SECONDS = 120
WORKER_STALE_SECONDS = 45
# How long a run may sit unclaimed before the platform gives up on scheduling it.
# Not a TTL: this is the backstop on a queue nobody is draining, so it is far
# longer than any run's own deadline. See the note in recover_stuck_runs.
QUEUE_MAX_WAIT_SECONDS = int(
    os.environ.get("ANDYUR_QUEUE_MAX_WAIT_SECONDS", str(24 * 3600))
)


def _cutoff(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat(
        timespec="seconds"
    )


def _past_deadline(row) -> bool:
    """Has this run outlived the lifetime its own resolution granted?

    Unparseable state fails CLOSED, onto the platform default, because the
    alternative is a run that no reaper will ever collect. A row that has not
    started yet is not this reaper's business; the unclaimed-queue backstop
    handles those.
    """
    started_at = row["started_at"]
    if not started_at:
        # Genuinely not started yet. Not this reaper's business; the
        # unclaimed-queue backstop owns that case.
        return False
    try:
        started = datetime.fromisoformat(started_at)
    except (TypeError, ValueError):
        # PRESENT but unreadable. Returning False here let a row with a corrupt
        # timestamp evade the reaper forever, which is the opposite of what this
        # function's own docstring promises. A run whose start time cannot be
        # read cannot be shown to be within its deadline, so it is reaped.
        log.warning("run %s has an unreadable started_at (%r); reaping rather "
                    "than leaving it uncollectable", row["id"], started_at)
        return True
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)

    lifecycle = None
    raw = row["runtime_resolution"]
    if raw:
        try:
            lifecycle = lifecycle_from_assignment(json.loads(raw))
        except MalformedLifecycle:
            # A grant EXISTED and we cannot read it. Falling back to the
            # platform default would WIDEN a run granted 120s to 900s, so the
            # shortest defensible bound is used instead: a lost grant must never
            # buy a run more time than it was given.
            log.warning("run %s has an unreadable lifecycle; reaping at the "
                        "floor rather than widening to the default", row["id"])
            allowed = LIFETIME_FLOOR_SECONDS
            deadline = started + timedelta(seconds=allowed + RUN_GRACE_SECONDS)
            return datetime.now(timezone.utc) >= deadline
        except (TypeError, ValueError):
            lifecycle = None
    allowed = granted_lifetime_seconds(lifecycle, RUN_TTL_SECONDS)
    deadline = started + timedelta(seconds=allowed + RUN_GRACE_SECONDS)
    return datetime.now(timezone.utc) >= deadline


def recover_stuck_runs() -> list[str]:
    actions = []
    with db.connect() as conn:
        # Headless runs are reaped by age: a run past its own deadline whose
        # runner never reported is hung. Conversation runs legitimately run far
        # longer, so they are EXCLUDED here and reaped by liveness below instead.
        #
        # Each run is judged against ITS OWN granted lifetime, read from the
        # runtime resolution sealed onto the row when the run was created. A
        # single global cutoff would reap a legitimately long agent at the
        # platform default, which is the whole defect this replaces.
        #
        # The comparison happens in Python rather than SQL because the interval
        # is per row, and date arithmetic with a per-row operand is spelled
        # differently in SQLite and Postgres. The candidate set is bounded by
        # one live run per agent, so this reads a small number of rows.
        # NO started_at predicate. It is a TEXT column compared as a string, so
        # a row whose timestamp is unreadable ("garbage") sorts outside any
        # cutoff and is never selected -- which made the malformed-timestamp
        # branch below unreachable for exactly the rows it exists to collect.
        # The candidate set is bounded by one live run per agent, so this reads
        # a small number of rows and decides in Python, where the value can
        # actually be parsed.
        candidates = conn.execute(
            "SELECT id, started_at, runtime_resolution FROM runs "
            "WHERE state = 'running' AND run_type != 'conversation'",
        ).fetchall()
    hung = [row for row in candidates if _past_deadline(row)]
    for row in hung:
        if coordinator.finish_run(
            row["id"], None, "reaped by server: runner exceeded TTL without reporting"
        ):
            actions.append(f"reaped hung run {row['id']}")

    # A conversation is reaped only when its liveness beat goes stale: the session
    # process actually died (it beats on every turn poll AND on every reply chunk).
    # A never-beaten session (started but its runner died before the first poll) is
    # caught by started_at via COALESCE. The window is the LARGER of the idle and
    # per-turn windows plus grace, so a session mid-way through a long (up to
    # TURN_TTL) turn -- which does not poll for turns during that turn -- is never
    # reaped as dead even if idle is configured shorter than the per-turn TTL.
    conv_window = max(config.CONVERSATION_IDLE_SECONDS,
                      config.CONVERSATION_TURN_TTL_SECONDS) + RUN_GRACE_SECONDS
    with db.connect() as conn:
        dead = conn.execute(
            "SELECT id FROM runs WHERE state = 'running' AND run_type = 'conversation' "
            "AND COALESCE(heartbeat_at, started_at) < ?",
            (_cutoff(conv_window),),
        ).fetchall()
    for row in dead:
        if coordinator.finish_run(
            row["id"], None, "reaped by server: conversation session died"
        ):
            actions.append(f"reaped dead conversation {row['id']}")

    # ...and a conversation that is very much ALIVE still has a ceiling.
    #
    # Liveness was the ONLY server-side bound on a session, so a beating session
    # was exempt from every wall-clock limit: CONVERSATION_MAX_SECONDS is checked
    # between turns INSIDE THE RUNNER, which is the process we assume can wedge
    # or be subverted. A session stuck in its turn loop beats on every reply
    # chunk, so it looked healthy forever while holding one of the scarce global
    # conversation slots, its agent's only claim, and a live credential minted to
    # expire with the session.
    #
    # The server enforces the same number the runner does, plus a grace window so
    # a session closing itself cleanly is never racing this. Belt and braces on
    # purpose: a bound only the bounded process enforces is not a bound.
    conv_ceiling = config.CONVERSATION_MAX_SECONDS + RUN_GRACE_SECONDS
    with db.connect() as conn:
        overrun = conn.execute(
            "SELECT id FROM runs WHERE state = 'running' AND run_type = 'conversation' "
            "AND started_at < ?",
            (_cutoff(conv_ceiling),),
        ).fetchall()
    for row in overrun:
        if coordinator.finish_run(
            row["id"], None,
            "reaped by server: conversation exceeded its session time limit"
        ):
            actions.append(f"reaped overrunning conversation {row['id']}")

    with db.connect() as conn:
        requeued = conn.execute(
            # Engine-dispatched runs are EXCLUDED by name, not by the accident
            # that their claim marker is never a registered worker: their
            # retry is the engine's, and a requeue here would hand one run to
            # both dispatchers.
            "UPDATE runs SET worker = NULL WHERE state = 'pending' "
            "AND dispatch IS NULL "
            "AND worker IS NOT NULL AND worker IN "
            "(SELECT id FROM workers WHERE last_heartbeat < ?)",
            (_cutoff(WORKER_STALE_SECONDS),),
        )
        if requeued.rowcount:
            actions.append(f"requeued {requeued.rowcount} run(s) from dead workers")

    # Reap runs stranded in 'pending': a runner that was launched but died before
    # it could POST /start (crash in prepare, container start failure, SIGKILL)
    # leaves the run pending forever -- no runner-side timeout ever applies (those
    # live inside the runner, which never started), the single-runner death does
    # not trip the dead-worker requeue above (the worker is still alive), and the
    # agent stays 'queued'. For a conversation this also permanently leaks one of
    # the scarce global MAX_CONVERSATIONS slots.
    #
    # CLAIMED IS NOT THE SAME AS QUEUED, and treating them alike failed healthy
    # work. A pending run with a worker was handed to one and the runner died: it
    # is stranded, and TTL+grace is the right deadline. A pending run with NO
    # worker has simply not been picked up, because every slot on the platform is
    # busy -- exactly the state a queue exists to represent. Reaping it recorded
    # a failure against an agent that did nothing wrong, and did it hardest under
    # load, when the queue is longest and the retry storm least welcome.
    #
    # Unclaimed work still cannot wait forever: while it is pending it holds the
    # agent's only live-run slot (the partial unique index), so the agent can
    # never run again. The backstop is deliberately far out -- a queue that is
    # still full a day later is a capacity problem, not a stuck run -- and it
    # says which of the two happened.
    #
    # MEASURED FROM THE CLAIM, NOT FROM CREATION, which is the whole point of
    # separating the two populations. Using created_at here handed the queued
    # run a deadline it had already blown while waiting: the instant a worker
    # picked up a run older than TTL+grace, the next tick failed it as "never
    # started" while a healthy runner was preparing it. That made the 24h
    # backstop illusory (the deadline snapped back to TTL the moment anything
    # claimed the run) and it bit hardest under sustained load, when queue
    # latency exceeds the TTL -- exactly the case the split was written for.
    # COALESCE for rows assigned before this column existed.
    #
    # A QUEUED CONVERSATION IS NOT LIKE QUEUED HEADLESS WORK, either. Both wait
    # for capacity, but a conversation holds one of the scarce global
    # MAX_CONVERSATIONS slots while a human sits waiting, and a session that
    # finally starts twenty hours later is worth nothing to anybody. Given the
    # far-out backstop, one worker outage could hold every slot for a day and
    # refuse every new conversation platform-wide. So an unclaimed conversation
    # keeps the short interactive deadline; only headless work, which is still
    # worth doing late, gets the long one.
    with db.connect() as conn:
        conv_dead = conn.execute(
            "SELECT id FROM runs WHERE state = 'pending' AND run_type = 'conversation' "
            "AND worker IS NOT NULL AND COALESCE(assigned_at, created_at) < ?",
            (_cutoff(config.CONVERSATION_IDLE_SECONDS + RUN_GRACE_SECONDS),),
        ).fetchall()
        headless_dead = conn.execute(
            "SELECT id FROM runs WHERE state = 'pending' AND run_type != 'conversation' "
            "AND worker IS NOT NULL AND COALESCE(assigned_at, created_at) < ?",
            (_cutoff(RUN_TTL_SECONDS + RUN_GRACE_SECONDS),),
        ).fetchall()
        conv_queued = conn.execute(
            "SELECT id FROM runs WHERE state = 'pending' AND run_type = 'conversation' "
            "AND worker IS NULL AND created_at < ?",
            (_cutoff(config.CONVERSATION_IDLE_SECONDS + RUN_GRACE_SECONDS),),
        ).fetchall()
        never_scheduled = conn.execute(
            "SELECT id FROM runs WHERE state = 'pending' AND run_type != 'conversation' "
            "AND worker IS NULL AND created_at < ?",
            (_cutoff(QUEUE_MAX_WAIT_SECONDS),),
        ).fetchall()
    for row in conv_dead + headless_dead:
        if coordinator.finish_run(
            row["id"], None, "reaped by server: run never started"
        ):
            actions.append(f"reaped stranded pending run {row['id']}")
    for row in conv_queued:
        if coordinator.finish_run(
            row["id"], None,
            "reaped by server: no worker picked up the session in time"
        ):
            actions.append(f"reaped unstarted conversation {row['id']} (no capacity)")
    for row in never_scheduled:
        if coordinator.finish_run(
            row["id"], None,
            "reaped by server: no worker had capacity within the queue window"
        ):
            actions.append(f"reaped never-scheduled run {row['id']} (platform saturated)")
    return actions


# How long an admitted engine run may wait for its provider's acknowledgement
# before it is offered again. Longer than one start's RPC bound, so a start
# still in flight is not raced; a race would be harmless anyway (starting is
# idempotent on the run), only noisy.
REOFFER_GRACE_SECONDS = 60


def reoffer_unacknowledged() -> list[str]:
    """EVENTUAL DELIVERY (provider draft R6.6): offer again the engine runs
    whose admission committed but whose provider start never acknowledged.
    Paused while the engine breaker is open, like every phase that reaches the
    engine; one failure stops the tick and trips the breaker."""
    from .. import orchestration
    wait = engine_breaker.ENGINE.open_for()
    if wait:
        return [f"re-offer paused: the workflow engine was unreachable; next "
                f"attempt in {wait:.0f}s"]
    try:
        return orchestration.facade().reoffer_unacknowledged(REOFFER_GRACE_SECONDS)
    except orchestration.ProviderUnavailable as exc:
        wait = engine_breaker.ENGINE.trip()
        return [f"re-offer stopped: the workflow engine is unreachable ({exc}); "
                f"next attempt in {wait:.0f}s"]


def drain_pending_work() -> list[str]:
    """Wake idle agents that have work waiting and no run since it arrived.

    WHY THIS EXISTS. Delegation and messaging both wake their target
    BEST-EFFORT: create_task and send_message call maybe_wakeup and ignore the
    refusal. Handing work to a BUSY agent is therefore normal and expected --
    and nothing ever came back for it. The task row was durable, so the work was
    deferred rather than lost (the agent's next run renders open tasks in its
    prompt), but "next run" could be a cron tick hours away, or never, for an
    agent with no schedule. An agent that only ever runs when delegated to could
    be handed work and sit idle beside it indefinitely.

    THE RE-DRIVE MUST NOT BECOME A TREADMILL, which is the part worth getting
    right. Waking on "has an open task" alone would re-wake every tick for as
    long as the task stays open -- and an agent that cannot complete a task is
    exactly the agent that would be woken forever, burning a slot and a model
    budget each time.

    So each piece of work carries `notified_at`: the moment it was OFFERED to a
    run. create_task and send_message stamp it when their own wakeup succeeds;
    this drain stamps it when it wakes an agent. Work is re-driven only while
    that stamp is NULL, which makes the offer exactly-once per item regardless
    of what the agent then does with it.

    Deliberately NOT a timestamp comparison ("work newer than the agent's last
    run"), which is the obvious implementation and is wrong: utcnow() has
    one-second granularity, so a task and the run woken for it carry the same
    stamp almost always, and every tie has to be resolved as either dropping the
    work or waking forever. Recording the fact beats inferring it from a clock
    that cannot represent the difference.

    Halted workflows are excluded, matching list_tasks/list_messages: the kill
    switch must not be undone by the drain.
    """
    wait = engine_breaker.ENGINE.open_for()
    if wait:
        return [f"drain paused: the workflow engine was unreachable; next "
                f"attempt in {wait:.0f}s"]

    actions = []
    for w in agents_with_waiting_work():
        agent, pin = w.agent, w.pin
        # CARRY THE PIN OF THE WAITING WORK. This path had no parent run to
        # inherit from, so it minted an UNPINNED run and the work executed with
        # its target stripped off -- reachable on demand by delegating to a busy
        # assignee. The pin now travels on the task/message row, so the deferred
        # wakeup constrains the run exactly as the immediate one would have.
        #
        # MIXED PINS ARE REFUSED RATHER THAN MERGED. If an agent is holding work
        # for two different targets, no single run can be correct for both, and
        # picking one would silently execute the other's work under the wrong
        # pin. Leave it for a per-item drive rather than guess; the work stays
        # open and un-stamped, so nothing is lost.
        if w.distinct_pins > 1:
            actions.append(
                f"'{agent}' holds waiting work under {w.distinct_pins} different "
                "pins; not drained (no single run can be correct for all)")
            continue
        if w.distinct_authorities > 1:
            actions.append(
                f"'{agent}' holds waiting work under {w.distinct_authorities} "
                "different delegated authorities; not drained")
            continue
        # THE DRAINED RUN JOINS THE WORKFLOW OF THE WORK IT DRAINS and records
        # the run that created that work as its parent, so the graph is READ
        # from the record instead of inferred. Neither was possible until the
        # task and message rows kept `parent_run_id`: the drain had nothing to
        # record, so a run that performed a delegated task drew as a second
        # root, and GET /workflows/{id}/flow showed the originating workflow's
        # task with no run against it.
        #
        # ONLY WHEN THE WAITING WORK AGREES. A drained run renders ALL of an
        # agent's open work, so work spanning several workflows belongs to none
        # of them, and several parents have no single answer either. A fresh
        # workflow is then the honest attribution, not a defect -- refusing
        # instead would strand ordinary fan-in, since two parentless tasks are
        # already two workflows.
        #
        # `converting_agent` is what makes joining SAFE rather than a liveness
        # bug. admit() counts open tasks and unread messages AND non-terminal
        # runs against MAX_WORKFLOW_RUNS, so without it a task waiting on a
        # workflow already at its cap is refused by the very wakeup meant to
        # re-drive it and never drains at all (reproduced: cap 3, one open
        # task, the task stranded forever). These items are already inside the
        # budget; this run executes them rather than adding to them, and
        # anything it CREATES still counts in full. The AGENT is passed rather
        # than the count read here, so the credit is recounted under the same
        # lock as the totals it corrects -- see admit().
        single_workflow = w.distinct_workflows == 1 and w.workflow_id is not None
        single_parent = w.distinct_parents == 1 and w.parent_run_id is not None
        # DEPTH BINDS ON BOTH PATHS. Joining a workflow without a single parent
        # left the run at depth 0 INSIDE that workflow, which an agent triggers
        # on demand: delegate twice, from two runs, to an assignee it keeps
        # busy, and the drained run restarts the delegation chain at the top of
        # a workflow it is already in. The floor is the deepest waiting
        # parent's depth + 1, so the bound holds whether or not the work agrees
        # on one parent. No parents at all is a genuine root, and floors at 0.
        depth_floor = (w.parent_depth or 0) + 1 if w.parent_depth is not None else 0
        # WHICH attribution this drain reached, by name. Three outcomes shared
        # one log line: joined with a parent, joined as a root because the
        # waiting work disagreed on one, and a fresh workflow because it
        # disagreed on the workflow. "Why is this run drawn as a root?" was
        # answerable only by reading the code and guessing at the data.
        decision = ("joined" if single_workflow and single_parent
                    else "joined_rootless" if single_workflow
                    else "fresh_workflow")
        # CONTINUE THE CREATING RUN'S TRACE. This is the hop the change adds:
        # the graph now draws parent-run -> drained-run, and without this the
        # drained node's trace id is null, so the edge the console shows cannot
        # be followed in the trace. `schedules.fire_due` roots its own trace
        # because a schedule has no parent; this one does.
        with _tracer.start_as_current_span(
            "heartbeat.drain", context=_trace_ctx_of(w.parent_run_id if single_parent else None)
        ) as span:
            span.set_attribute("andyur.agent", agent)
            span.set_attribute("andyur.decision", decision)
            if single_workflow:
                span.set_attribute("andyur.workflow_id", w.workflow_id)
            if decision != "joined":
                # the two degradations, named where they happen rather than
                # inferred from the absence of an attribute
                span.add_event(
                    "drain.attribution_degraded",
                    {"andyur.reason": ("conflict" if w.distinct_workflows > 1
                                       or w.distinct_parents > 1 else "unavailable"),
                     "andyur.count": w.distinct_workflows if w.distinct_workflows > 1
                                     else w.distinct_parents})
            try:
                actions.extend(_drain_one(
                    span, decision, agent, pin, w.user, w.scope, w.workflow_id,
                    w.parent_run_id, single_workflow, single_parent, depth_floor))
            except _EngineDown as exc:
                # STOP, AND WAIT LONGER EACH TIME. Every agent left in this
                # tick would fail the same way; the work stays open, so the
                # drain resumes where it was once the engine answers.
                wait = engine_breaker.ENGINE.trip()
                actions.append(
                    f"drain stopped: the workflow engine is unreachable ({exc}); "
                    f"remaining agents keep their work open and the drain "
                    f"resumes in {wait:.0f}s")
                return actions
    return actions


def _trace_ctx_of(run_id):
    """The OTel context stored on a run, so a later wakeup joins its trace."""
    if not run_id:
        return None
    with db.connect() as conn:
        row = conn.execute(
            "SELECT trace_ctx FROM runs WHERE id = ?", (run_id,)).fetchone()
    return otel.context_from(row["trace_ctx"]) if row else None


def _outcome(span, decision: str, outcome: str, reason: str = "unknown") -> None:
    """ONE place that stamps a drain's result on the span, the counter and the
    log, so the three cannot drift.

    `andyur.run.outcomes` was declared in observability.py and recorded by
    nothing, and the drain's only record was a `print` -- no level, no trace
    id, outside the redaction boundary. The agent name and run id stay on the
    span; the log event carries only bounded vocabulary, because a log
    dimension has to be groupable to be worth having.
    """
    span.set_attribute("andyur.outcome", outcome)
    span.set_attribute("andyur.reason", reason)
    otel.try_record_metric(
        "andyur-server", "andyur.run.outcomes", 1,
        **{"andyur.outcome": outcome, "andyur.operation": "claim"})
    observability.event(
        log, "heartbeat.drain", outcome=outcome, reason=reason,
        decision=decision,
        level=logging.INFO if outcome == "success" else logging.WARNING)


class _EngineDown(Exception):
    """The workflow engine could not be reached. Raised past `_drain_one` so the
    DRAIN stops, rather than being reported per agent like the other refusals."""


# THE DRAIN BACKS OFF WHILE THE ENGINE IS DOWN (engine_breaker.ENGINE), and it
# did not. Every tick, for every agent with waiting work, admission committed a
# pending run, `start` could not reach the engine, and the run was abandoned as
# failed -- the work
# stayed open, so the next tick did it all again. That is up to one failed run
# per agent per tick (~2,880 a day each) for as long as an outage lasts, plus a
# worker possibly launching a Pod for a run that is then refused its start.
#
# Distinct from the per-agent refusals, and that is the point. "One agent's bad
# luck must not cost the rest their turn" is right for a capability missing or a
# workflow bound elsewhere -- those are about THAT agent. An unreachable engine
# is not one agent's bad luck: every remaining agent fails identically, so
# carrying on only manufactures failed runs.


def _drain_one(span, decision, agent, pin, user, scope, workflow_id,
               parent_run_id, single_workflow, single_parent,
               depth_floor) -> list[str]:
    """One agent's drain, inside its span. Returns the operator-visible lines."""
    actions: list[str] = []
    try:
        run_id, reason = orchestration.facade().request_agent_run(
            agent, "work was waiting: open tasks or unread messages",
            run_type="task",
            workflow_kind=orchestration.DEFERRED_WORK,
            subject_context=json.loads(pin) if pin else None,
            pin_asserted_by="drain:inherited-from-work" if pin else None,
            user=user, scope=json.loads(scope) if scope else None,
            workflow_id=workflow_id if single_workflow else None,
            parent_run_id=parent_run_id if single_parent else None,
            # UNCONDITIONAL, and safe because the recount is workflow-scoped:
            # when the work spans workflows this run mints a fresh one, and no
            # waiting item references it, so the credit is zero by
            # construction. A `if single_workflow` guard here would be a second
            # statement of a fact admit() already enforces, and two places
            # stating one fact eventually disagree.
            converting_agent=agent,
            depth_floor=depth_floor,
            trace_ctx=otel.current_traceparent(),
        )
        if run_id:
            # A run admitted and started: the engine answered.
            engine_breaker.ENGINE.answered()
    except coordinator.PinRefused as exc:
        # FIRST, and separately from the two below. resolve_pin's own docstring
        # says a retarget attempt "must not look like backpressure and
        # disappear" -- and the generic clause below is exactly that, because
        # PinRefused subclasses DelegationRefused too. No reachable path from
        # the drain today (an item's pin comes from its parent, so a pin
        # divergence implies a parent divergence, which turns the claim off),
        # but the guard has to be capable of firing to be a guard.
        _outcome(span, "none", "denied", "refused")
        span.record_exception(exc)
        return [f"'{agent}' holds waiting work whose target was REFUSED: {exc}"]
    except coordinator.InputRefused as exc:
        # Same treatment as mixed pins: the work stays open and un-stamped,
        # and the line names why. This one is permanent -- delegated work
        # carries no input and the agent's manifest requires one -- so it
        # repeats every tick until the work is closed or reassigned.
        _outcome(span, "none", "denied", "invalid")
        return [f"'{agent}' holds waiting work but cannot be woken "
                f"for it: {exc}"]
    except coordinator.DelegationRefused as exc:
        # AFTER InputRefused, which subclasses it. Ordered the other way
        # round, the generic handler swallowed the permanent refusal and
        # reported it as a race with retention -- the right outcome for
        # the wrong reason, which is worse than no line at all because an
        # operator would wait for a race that is never going to resolve.
        # Reachable only by a race: the parent run was proved alive by the
        # query above and pruned before the wakeup opened its transaction.
        # The tick must survive it -- this loop drains every agent on the
        # platform, so one unlucky row must not cost the other agents their
        # turn.
        _outcome(span, "none", "failure", "conflict")
        span.record_exception(exc)
        return [f"'{agent}' holds waiting work but the run that "
                f"created it went away first: {exc}"]
    except orchestration.ProviderUnavailable as exc:
        # NOT this agent's bad luck -- see `_EngineDown`. Recorded on this
        # agent's span, then raised so the drain stops for the tick.
        _outcome(span, "none", "failure", "unavailable")
        span.record_exception(exc)
        raise _EngineDown(str(exc)) from exc
    except orchestration.OrchestrationError as exc:
        # ONE AGENT'S BAD LUCK MUST NOT COST THE REST THEIR TURN, which is the
        # requirement the handler above already states and which routing
        # through the facade quietly broke: the facade can raise a provider
        # being unreachable, a capability missing, or a workflow bound to
        # another engine, and none of those were caught -- so one failure
        # aborted `drain_pending_work` for every remaining agent, on every
        # tick, for as long as the condition lasted.
        #
        # The work stays open and unstamped, so the next tick re-drives it.
        # Nothing is lost; the cost is one tick of latency for this agent.
        _outcome(span, "none", "failure", "unavailable")
        span.record_exception(exc)
        return [f"'{agent}' holds waiting work but orchestration refused the "
                f"wakeup; it stays open and will be re-driven: {exc}"]
    if run_id:
        # NOT stamped here. The stamp belongs to the moment a run STARTS and
        # renders the prompt (coordinator.start_run), because that is when
        # the work is actually shown to the agent. Stamping the wakeup
        # recorded an intention, and anything that cancelled the pending run
        # before it started left the work open, stamped, and invisible to
        # this drain forever.
        span.set_attribute("andyur.run_id", run_id)
        _outcome(span, decision, "success")
        actions.append(f"drained waiting work for '{agent}' as run {run_id}")
    else:
        # A REFUSAL IS A DECISION AND GETS WRITTEN DOWN. maybe_wakeup
        # returns None for a workflow at its cap or past its depth, for an
        # agent paused since the query, and for a lost race -- all of which
        # left this loop appending nothing at all, so the tick reported
        # "drained 0" whether the platform was idle or a workflow was
        # wedged against a cap. Now that the drained run inherits the
        # work's depth, the cap can refuse it for real, which is the same
        # answer an idle agent would have got at delegation time.
        # THE REASON, BY NAME. `wakeup_or_reason` is the same call as
        # `maybe_wakeup` with the refusal kept, because a bare None meant an
        # operator could not tell a kill switch from a spent work budget
        # from a depth ceiling from a lost race -- four different responses.
        _outcome(span, decision, "denied", reason)
        actions.append(f"'{agent}' holds waiting work but was not woken: "
                       f"{reason}")
    return actions


def agents_with_waiting_work() -> list[WaitingWork]:
    """Idle, unpaused agents holding work that has never been offered to a run.

    SEPARATE FROM THE DRAIN THAT USES IT, so its guards can be observed. Inline,
    they could not be: every one of them is ALSO enforced by maybe_wakeup or by
    halt_workflow, so deleting the halted filter, the paused join, or the
    live-run exclusion left every end-to-end test passing. The system was right
    and the tests were measuring a different layer -- which fails the same way an
    assertion that cannot fail does: it would not report the guard's removal.

    These are not redundant despite that. Selecting an agent here means waking
    it, and a wakeup that is going to be refused is a wasted transaction on a
    path that runs every 30 seconds for every agent on the platform. The
    downstream refusals are the correctness boundary; these are the reason the
    heartbeat does not spend its tick discovering that.
    """
    live = "SELECT agent FROM runs WHERE state IN ('pending', 'running')"
    # ONLY A PARENT THAT STILL EXISTS. resolve_workflow REFUSES an unknown
    # parent run rather than silently rooting the work at depth 0 -- correctly,
    # since a forged parent id would otherwise reset the depth cap. But a work
    # row can outlive the run that created it (retention prunes runs), so a
    # drain that named a pruned parent would raise DelegationRefused every tick
    # and strand the work. Report a parent only when it can still be proved;
    # otherwise this is work with no provable origin, which reads as no parent.
    # EVERY REFERENCE TO THE OUTER TABLE IS QUALIFIED, and `runs` is aliased.
    # `runs` has a `parent_run_id` column of its own, so an unqualified
    # `parent_run_id` inside a subquery over `runs` binds to the INNER table --
    # `WHERE runs.id = runs.parent_run_id`, which matches nothing and returns
    # NULL for every row. Silent: the depth floor read as "no parent" and the
    # bypass it exists to close stayed open, with the query looking correct.
    def live_parent(t):
        return (f"CASE WHEN {t}.parent_run_id IN (SELECT r.id FROM runs r) "
                f"THEN {t}.parent_run_id END AS parent_run_id")
    # THE DEEPEST PARENT the waiting work has, which is what bounds the drained
    # run when the work has parents but no single one. Read here rather than in
    # the drain so it comes from the same snapshot as `parents` -- computed
    # separately, the count and the depth could disagree about which rows they
    # describe. A pruned parent yields NULL and MAX ignores it, which agrees
    # with live_parent: an unprovable parent is no parent.
    def parent_depth(t):
        return (f"(SELECT r.depth FROM runs r WHERE r.id = {t}.parent_run_id) "
                f"AS parent_depth")
    not_halted = ("(workflow_id IS NULL OR workflow_id NOT IN "
                  "(SELECT id FROM workflows WHERE state = 'halted'))")
    with db.connect() as conn:
        rows = conn.execute(
            f"""
            SELECT w.agent AS agent, MIN(w.pin) AS pin,
                   -- COALESCE because SQL COUNT(DISTINCT) IGNORES NULL: one
                   -- unpinned item beside one pinned item counted as a single
                   -- pin, so the mixed-pin guard did not fire and MIN picked
                   -- the pinned value. The direction was safe (the unpinned
                   -- item ran pinned, which is a narrowing) but the guard was
                   -- not measuring what it claims. The three counts added for
                   -- gap 28 got this right; this was the odd one out.
                   COUNT(DISTINCT COALESCE(w.pin, '')) AS pins,
                   MIN(w.delegated_user) AS delegated_user,
                   MIN(w.delegated_scope) AS delegated_scope,
                   COUNT(DISTINCT COALESCE(w.delegated_user, '') || ':' ||
                         COALESCE(w.delegated_scope, 'null')) AS authorities,
                   MIN(w.workflow_id) AS workflow_id,
                   COUNT(DISTINCT COALESCE(w.workflow_id, '')) AS workflows,
                   MIN(w.parent_run_id) AS parent_run_id,
                   COUNT(DISTINCT COALESCE(w.parent_run_id, '')) AS parents,
                   MAX(w.parent_depth) AS parent_depth
            FROM (
                -- UNION ALL, not UNION: every column out of this subquery is
                -- an aggregate that ignores duplicates (COUNT(DISTINCT), MIN,
                -- MAX), so deduplicating would buy nothing and cost a sort.
                SELECT assignee AS agent, subject_context AS pin,
                       delegated_user, delegated_scope,
                       workflow_id, {live_parent('tasks')},
                       {parent_depth('tasks')} FROM tasks
                WHERE state = 'open' AND notified_at IS NULL AND {not_halted}
                UNION ALL
                SELECT recipient AS agent, subject_context AS pin,
                       delegated_user, delegated_scope,
                       workflow_id, {live_parent('messages')},
                       {parent_depth('messages')} FROM messages
                WHERE state = 'unread' AND notified_at IS NULL AND {not_halted}
            ) w
            JOIN agents a ON a.name = w.agent AND a.paused = 0
            WHERE w.agent NOT IN ({live})
            GROUP BY w.agent
            """
        ).fetchall()
    return [WaitingWork(
        agent=r["agent"], pin=r["pin"], distinct_pins=r["pins"],
        user=r["delegated_user"], scope=r["delegated_scope"],
        distinct_authorities=r["authorities"], workflow_id=r["workflow_id"],
        distinct_workflows=r["workflows"], parent_run_id=r["parent_run_id"],
        distinct_parents=r["parents"], parent_depth=r["parent_depth"],
    ) for r in rows]


def consolidate_graphs() -> list[str]:
    """Consolidation A across all agents: mechanical merge + prune, no LLM.
    Runs in the control plane precisely because it needs no model, only vector
    math over embeddings the runs already computed."""
    actions = []
    with db.connect() as conn:
        agents = [r["name"] for r in conn.execute("SELECT name FROM agents").fetchall()]
    for a in agents:
        try:
            r = graph.consolidate(a)
            if r["merged"] or r["pruned"]:
                actions.append(
                    f"graph consolidate {a}: merged {r['merged']}, pruned {r['pruned']}"
                )
        except Exception as exc:
            actions.append(f"graph consolidate {a} failed: {exc}")
    return actions


def _say(phase: str, action: str) -> None:
    """What the tick did, through the logger rather than `print`.

    These lines were the ONLY record of a self-healing decision -- a requeued
    run, a fired schedule, a refused drain -- and `print` is not the redaction
    boundary, carries no level, no trace id and no JSON envelope, so nothing
    could alert on them and nothing could correlate them with the trace the
    same decision wrote. `otel.setup_tracing` installs the JSON formatter with
    trace fields on the `andyur` logger; this is what reaches it.
    """
    # A plain message, NOT a declared event: these lines are free text (agent
    # names, run ids, an exception's words), so they go through `message`,
    # which the JSON formatter redacts. Declared event fields are validated but
    # NOT redacted, which is why the drain's bounded facts are a separate
    # `heartbeat.drain` event and this is not one.
    log.info("[%s] %s", phase, action)


async def heartbeat_loop() -> None:
    from . import schedules

    global _last_consolidate
    while True:
        try:
            # OFF THE EVENT LOOP, EVERY PHASE. This coroutine runs on uvicorn's
            # MAIN loop -- the one that serves every HTTP request -- and the
            # phases are synchronous. They used to be local database work and
            # a synchronous call cost milliseconds. Once the facade routed
            # admission through a workflow provider, `fire_due` and the drain
            # reach `provider.start`, which blocks on a network call for up to
            # the RPC bound: with the engine slow or unreachable, each agent
            # with waiting work froze the loop for ~10s per tick, and NOTHING
            # was served meanwhile -- not `/ready`, not a worker's heartbeat,
            # and not the halt endpoint, which is the one request that must
            # never wait on the engine.
            #
            # A worker thread is safe here because these functions were
            # already written to run concurrently with the threadpool
            # endpoints: every claim they make is a guarded UPDATE, which is
            # what lets N server replicas run this same loop.
            for phase, run in (("recover", recover_stuck_runs),
                               ("reoffer", reoffer_unacknowledged),
                               ("schedule", schedules.fire_due),
                               ("drain", drain_pending_work)):
                for action in await asyncio.to_thread(run):
                    _say(phase, action)
            now = time.monotonic()
            if (config.GRAPH_CONSOLIDATE and graph.enabled()
                    and now - _last_consolidate >= config.GRAPH_CONSOLIDATE_INTERVAL):
                _last_consolidate = now
                for action in await asyncio.to_thread(consolidate_graphs):
                    _say("consolidate", action)
        except Exception as exc:
            log.exception("heartbeat tick failed", extra={"andyur.operation": "heartbeat"})
            del exc
        await asyncio.sleep(TICK_SECONDS)

"""Cron scheduling.

A schedule fires an agent unattended on a cron cadence. The server heartbeat
loop calls due_schedules() each tick; for each schedule whose next_run_at has
passed it triggers a run (through the same maybe_wakeup CAS as any other
trigger) and advances next_run_at to the next cron occurrence.

If the agent is busy when a schedule fires, the tick is RETRIED SHORTLY rather
than queued or dropped. No backlog accumulates (a retry is one pending attempt,
not N stacked runs), but neither is the tick silently lost: the schedule fires
as soon as the agent is free.

This used to say the tick was skipped, and described it as keeping a slow agent
from accumulating a backlog. What it actually did was let one long-running
conversation swallow every scheduled run for its whole duration -- around sixty
of them for a `* * * * *` schedule -- because next_run_at was advanced to the
next slot before the wakeup was even attempted. Unattended operation is the
platform's premise, so "the agent was busy" must not mean "the schedule stopped".
"""

import os
import uuid
from datetime import datetime, timedelta, timezone

from croniter import croniter

from .. import db, orchestration, otel
from . import coordinator, engine_breaker

_tracer = otel.get_tracer("andyur-server")

# How soon to retry a schedule whose agent was busy. Roughly one heartbeat, so a
# freed agent is picked up on the next tick rather than at the next cron slot.
RETRY_SECONDS = int(os.environ.get("ANDYUR_SCHEDULE_RETRY_SECONDS", "30"))


def _next(cron: str, after: datetime | None = None) -> str:
    base = after or datetime.now(timezone.utc)
    return croniter(cron, base).get_next(datetime).isoformat(timespec="seconds")


def _iso_in(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(
        timespec="seconds"
    )


def create_schedule(agent: str, cron: str, reason: str, *,
                    schedule_id: str | None = None,
                    paused: bool = False) -> dict:
    """Create a schedule. `schedule_id` lets a caller supply the id instead of
    minting one.

    That option exists because a caller that must be able to REPLACE a schedule
    needs its id to survive the replacement. Without it, "update" became
    delete-then-create under a fresh id: the delete matched nothing on the
    second attempt and each update left another live schedule behind, so an
    agent fired once more per tick every time and no id could stop any of them.
    """
    croniter(cron)  # validates the expression, raises on bad input
    sid = schedule_id or uuid.uuid4().hex[:12]
    now = db.utcnow()
    facade = orchestration.facade()
    # WHICH TRIGGER, decided once: a provider that dispatches runs itself also
    # fires this schedule itself (Architecture B+, ADR-014 D11). The native
    # poller then never fires it, so one schedule never fires twice.
    engine = facade.dispatches_runs
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO schedules (id, agent, cron, reason, enabled, next_run_at, "
            "created_at, trigger) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sid, agent, cron, reason, 0 if paused else 1, _next(cron), now,
             "engine" if engine else None),
        )
    if engine:
        # The row FIRST, the engine's schedule second: if the engine refuses,
        # the row is removed and the caller told -- a schedule that fires must
        # never be one Andyur cannot see, and one Andyur shows must not
        # silently never fire.
        #
        # A FAILURE IS AMBIGUOUS. A timeout can arrive after the engine created
        # the schedule, and dropping the row then left a schedule firing that
        # Andyur could neither show nor stop (B+ adversarial review). So the
        # engine's copy is removed first; only if that succeeds does the row
        # go. If it cannot be removed either, the row STAYS -- visible, and
        # deletable once the engine is back -- and the caller is still told.
        try:
            facade.create_schedule(orchestration.ScheduleSpec(
                schedule_id=sid, agent=agent, cron=cron, reason=reason,
                paused=paused))
        except Exception:
            try:
                facade.delete_schedule(sid)
            except Exception:                              # noqa: BLE001
                pass                                       # the row stays
            else:
                with db.connect() as conn:
                    conn.execute("DELETE FROM schedules WHERE id = ?", (sid,))
            raise
    return {"id": sid, "agent": agent, "cron": cron, "reason": reason,
            "trigger": "engine" if engine else "native"}


def list_schedules(agent: str | None = None) -> list[dict]:
    with db.connect() as conn:
        if agent:
            rows = conn.execute(
                "SELECT * FROM schedules WHERE agent = ? ORDER BY created_at", (agent,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM schedules ORDER BY created_at"
            ).fetchall()
    return [dict(r) for r in rows]


def delete_schedule(schedule_id: str) -> bool:
    with db.connect() as conn:
        row = conn.execute("SELECT trigger FROM schedules WHERE id = ?",
                           (schedule_id,)).fetchone()
    if row is not None and row["trigger"] == "engine":
        # The ENGINE's schedule first: if it cannot be removed, the row stays --
        # still visible, still deletable -- rather than leaving a schedule
        # that keeps firing with nothing in Andyur to show it or stop it.
        orchestration.facade().delete_schedule(schedule_id)
    return _delete_row(schedule_id)


class TickRefused(ValueError):
    """A provider's schedule tick names no enabled engine schedule Andyur
    holds for that agent. Permanent: the tick is given up."""


def admit_engine_tick(schedule_id: str | None, agent: str):
    """Admit the run for one tick of a provider-owned schedule, or refuse it.

    THE CHECK IS ANDYUR'S, done here once for every provider that owns
    schedules (provider draft R10.3). A tick must name an enabled engine
    schedule Andyur holds for that agent; anything a provider can start --
    and any identity the provider admits can start one -- that names no such
    schedule admits nothing. The ROW supplies the reason, so nothing the
    provider carries reaches the run's record.

    Returns the facade's `(run_id, refusal)`; raises `TickRefused`, and lets
    `coordinator.InputRefused` through for the caller to treat as permanent.
    """
    with db.connect() as conn:
        row = conn.execute(
            "SELECT reason FROM schedules WHERE id = ? AND agent = ? AND enabled = 1 "
            "AND trigger = 'engine'", (schedule_id, agent)).fetchone()
    if row is None:
        raise TickRefused(
            f"no enabled engine schedule {schedule_id!r} for agent {agent!r}")
    return orchestration.facade().request_agent_run(
        agent, row["reason"], "scheduled",
        workflow_kind=orchestration.SCHEDULED_AGENT)


class EngineScheduleUnreachable(RuntimeError):
    """The schedule lives in the engine and the bound provider cannot reach it."""


def delete_native_schedule(schedule_id: str) -> bool:
    """The native provider's delete: the row, for a schedule the native poller
    fires. A schedule the ENGINE fires is refused, not dropped -- the provider
    bound now cannot reach the engine, and removing the row would leave the
    engine's copy firing with nothing in Andyur to show or stop it. Its first
    version went back through `delete_schedule`, which sent it straight back
    here: a RecursionError, and a schedule no one could delete."""
    with db.connect() as conn:
        row = conn.execute("SELECT trigger FROM schedules WHERE id = ?",
                           (schedule_id,)).fetchone()
    if row is not None and row["trigger"] == "engine":
        raise EngineScheduleUnreachable(
            f"schedule '{schedule_id}' is fired by the workflow engine; delete it "
            "with the engine's provider configured")
    return _delete_row(schedule_id)


def _delete_row(schedule_id: str) -> bool:
    with db.connect() as conn:
        cur = conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
    return cur.rowcount > 0


def fire_due() -> list[str]:
    """Fire every enabled schedule whose time has come. Returns human-readable
    action strings for logging. Called from the server heartbeat loop.

    Safe under server replication: each due schedule is claimed with a guarded
    UPDATE that advances next_run_at only if it is still due, so of N replicas
    running this loop, exactly one wins each tick and the schedule fires once.
    The other replicas' UPDATE matches no row (next_run_at already advanced)
    and they skip it. No leader election needed, same CAS idea as everywhere."""
    # WHILE THE ENGINE IS DOWN, NOTHING IS CLAIMED. A claim advances the
    # schedule, and a start that then cannot reach the engine abandons the run
    # as failed: every due schedule did both, every tick, for the length of an
    # outage. Left unclaimed, a due schedule fires on the first tick after the
    # breaker closes, which is what a schedule deferred by an outage should do.
    wait = engine_breaker.ENGINE.open_for()
    if wait:
        return [f"schedules paused: the workflow engine was unreachable; next "
                f"attempt in {wait:.0f}s"]
    now_iso = db.utcnow()
    actions = []
    with db.connect() as conn:
        due = conn.execute(
            "SELECT id, agent, cron, reason FROM schedules "
            # NATIVE schedules only: an engine schedule is fired by the engine.
            "WHERE enabled = 1 AND next_run_at <= ? AND trigger IS NULL",
            (now_iso,),
        ).fetchall()
    for s in due:
        if engine_breaker.ENGINE.open_for():
            break  # tripped by an earlier schedule this tick; the rest stay due
        # atomic claim: advance next_run_at only if this row is still due
        with db.connect() as conn:
            claimed = conn.execute(
                "UPDATE schedules SET next_run_at = ?, last_run_at = ? "
                "WHERE id = ? AND next_run_at <= ?",
                (_next(s["cron"]), now_iso, s["id"], now_iso),
            )
            won = claimed.rowcount == 1
        if not won:
            continue  # another replica claimed this tick
        # a scheduled fire roots its own trace, like a manual trigger does
        with _tracer.start_as_current_span("scheduled_run") as span:
            span.set_attribute("andyur.agent", s["agent"])
            try:
                run_id, _refusal = orchestration.facade().request_agent_run(
                    s["agent"], s["reason"], run_type="scheduled",
                    trace_ctx=otel.current_traceparent(),
                    workflow_kind=orchestration.SCHEDULED_AGENT,
                )
            except coordinator.InputRefused as exc:
                # This schedule can NEVER fire for this agent: a schedule
                # carries no input and the agent's manifest requires one. Not
                # the busy case below, so no 30s re-arm -- that would retry a
                # permanent refusal ~2,880 times a day. The tick stays burned,
                # the next slot reports it again, and the line names the fix.
                actions.append(
                    f"schedule {s['id']} cannot fire for '{s['agent']}': {exc}")
                continue
            except orchestration.ProviderUnavailable as exc:
                # The ENGINE is down, not this schedule's agent: trip the
                # breaker so the schedules after this one stay due and unclaimed,
                # and re-arm this one below like any other deferral.
                wait = engine_breaker.ENGINE.trip()
                actions.append(
                    f"schedule {s['id']} deferred for '{s['agent']}': the workflow "
                    f"engine is unreachable ({exc}); schedules resume in {wait:.0f}s")
                run_id = None
            except orchestration.OrchestrationError as exc:
                # TRANSIENT, SO RE-ARM RATHER THAN BURN THE TICK. Unlike the
                # refusal above, an engine being unreachable says nothing about
                # whether this schedule can ever fire -- it will almost
                # certainly fire on the next attempt.
                #
                # Falling through with no run_id takes the deferral path below,
                # which pulls next_run_at back to a short retry. Letting it
                # propagate instead would abort the loop over every REMAINING
                # due schedule, and each of those has already had its
                # next_run_at advanced by the atomic claim above -- so one
                # engine hiccup would silently burn a whole tick's worth of
                # unattended work.
                actions.append(
                    f"schedule {s['id']} deferred for '{s['agent']}': "
                    f"orchestration refused the wakeup: {exc}")
                run_id = None
        if run_id:
            engine_breaker.ENGINE.answered()
            actions.append(f"schedule {s['id']} fired run {run_id} for '{s['agent']}'")
        else:
            # THE TICK WAS BURNED, NOT DEFERRED. The claim above advances
            # next_run_at to the next cron slot BEFORE the wakeup is attempted
            # -- correct for the replication race, wrong for a refusal. A
            # refused wakeup (agent busy) therefore consumed the tick and the
            # schedule waited for its next slot, so a conversation lasting an
            # hour silently ate ~60 runs of a `* * * * *` schedule and the only
            # trace was a log line.
            #
            # Re-arm SOON instead: retry shortly rather than at the next slot,
            # so the schedule resumes as soon as the agent is free. The CAS
            # keeps replication safe -- it only pulls the time back in if no
            # other replica has since moved it further -- and never pushes it
            # PAST the natural next slot, so a retry can only make the schedule
            # more punctual, never less.
            retry_at = _iso_in(RETRY_SECONDS)
            with db.connect() as conn:
                conn.execute(
                    "UPDATE schedules SET next_run_at = ? "
                    "WHERE id = ? AND next_run_at > ?",
                    (retry_at, s["id"], retry_at),
                )
            actions.append(
                f"schedule {s['id']} deferred for '{s['agent']}' (busy or paused); "
                f"retrying at {retry_at}"
            )
    return actions

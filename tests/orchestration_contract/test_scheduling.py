"""Schedules: unattended firing, and what happens when the agent is busy.

Durable timers are the single clearest thing a durable-execution engine offers
Andyur, so this module is written to be exactly the specification such an engine
must satisfy -- and no more. Nothing here asserts cron parsing, tick cadence, or
that a loop polls at all; a provider with native scheduling does none of those
and is still correct.

Two properties are contract. A due schedule fires exactly once however many
schedulers are running, and a tick refused because the agent was busy is
RE-ARMED rather than consumed. The second one is written from a real defect: the
tick used to be burned, so one long conversation silently swallowed about sixty
runs of a per-minute schedule and the only evidence was a log line.
"""

from datetime import datetime, timedelta, timezone

from andyur import db
from andyur.server import coordinator, schedules

from .conftest import is_free, live_run_of


def _make_due(schedule_id: str) -> None:
    """Bring a schedule's next firing into the past."""
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    with db.connect() as c:
        c.execute("UPDATE schedules SET next_run_at = ? WHERE id = ?", (past, schedule_id))


def _next_firing(schedule_id: str) -> datetime:
    with db.connect() as c:
        raw = c.execute(
            "SELECT next_run_at FROM schedules WHERE id = ?", (schedule_id,)
        ).fetchone()["next_run_at"]
    when = datetime.fromisoformat(raw)
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


# --- a due schedule fires ---------------------------------------------------

def test_a_due_schedule_admits_a_run(agent):
    s = schedules.create_schedule(agent, "* * * * *", "the scheduled reason")
    _make_due(s["id"])

    schedules.fire_due()

    assert live_run_of(agent) is not None, "a due schedule admitted nothing"


def test_a_schedule_that_is_not_due_fires_nothing(agent):
    schedules.create_schedule(agent, "0 3 * * *", "nightly")

    schedules.fire_due()

    assert is_free(agent)


def test_a_fired_schedule_moves_on(agent):
    """The firing must advance, or the same tick fires forever."""
    s = schedules.create_schedule(agent, "* * * * *", "work")
    _make_due(s["id"])

    schedules.fire_due()

    assert _next_firing(s["id"]) > datetime.now(timezone.utc)


def test_one_due_tick_produces_one_run_however_often_it_is_evaluated(agent):
    """EXACTLY ONCE, stated without reference to how it is achieved.

    The native provider gets this from a guarded update that advances the
    schedule only if it is still due, so among N replicas exactly one wins.
    A provider with native scheduling gets it some other way. What neither may
    do is fire twice.
    """
    s = schedules.create_schedule(agent, "* * * * *", "work")
    _make_due(s["id"])

    # THE AGENT IS FREED BETWEEN EVALUATIONS, or this could not fail. It used
    # to fire three times in a row with the first run still live, so the second
    # and third were refused because the AGENT WAS BUSY -- the one-live-run rule
    # answered the question, not the schedule's claim. A claim that never
    # advanced the tick produced one run here and passed. Freed, a correct
    # claim has already moved the tick into the future and nothing more fires;
    # a claim that left it due fires again.
    for _ in range(3):
        schedules.fire_due()
        live = live_run_of(agent)
        if live:
            coordinator.finish_run(live, "done", None)

    with db.connect() as c:
        runs = c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = ?", (agent,)).fetchone()["n"]
    assert runs == 1, (
        f"one due tick produced {runs} runs: the schedule's claim did not move "
        "the tick on, so it fired again as soon as the agent was free")


# --- a busy agent defers the tick, it does not lose it ----------------------

def test_a_tick_refused_because_the_agent_is_busy_is_re_armed(agent):
    """THE DEFECT THIS ENCODES: the tick used to be consumed. next_run_at was
    advanced to the next slot before the wakeup was even attempted, so a
    refusal meant the schedule waited a full cron period -- and an agent busy
    for an hour lost every tick in that hour.

    Unattended operation is the platform's premise, so 'the agent was busy'
    must never mean 'the schedule stopped'.
    """
    coordinator.maybe_wakeup(agent, "something already running")
    s = schedules.create_schedule(agent, "0 3 * * *", "nightly")
    _make_due(s["id"])

    schedules.fire_due()

    soon = datetime.now(timezone.utc) + timedelta(seconds=schedules.RETRY_SECONDS + 30)
    assert _next_firing(s["id"]) <= soon, (
        "a refused tick was pushed to the next cron slot instead of re-armed")


def test_the_re_armed_tick_fires_once_the_agent_is_free(agent):
    """The re-arm has to actually produce the run, or it is just a delay."""
    busy = coordinator.maybe_wakeup(agent, "occupying the agent")
    s = schedules.create_schedule(agent, "0 3 * * *", "nightly")
    _make_due(s["id"])
    schedules.fire_due()

    coordinator.finish_run(busy, "done", None)
    _make_due(s["id"])
    schedules.fire_due()

    assert live_run_of(agent) is not None, "the re-armed tick never fired"


def test_a_deferral_does_not_stack_up_a_backlog(agent):
    """Re-armed, not queued. A provider that enqueued every refused tick would
    release a burst the moment the agent frees up -- which is how unattended
    scheduling turns into an incident."""
    busy = coordinator.maybe_wakeup(agent, "occupying the agent")
    s = schedules.create_schedule(agent, "* * * * *", "frequent")

    for _ in range(10):
        _make_due(s["id"])
        schedules.fire_due()

    coordinator.finish_run(busy, "done", None)
    _make_due(s["id"])
    schedules.fire_due()

    with db.connect() as c:
        scheduled = c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = ? AND run_type = 'scheduled'",
            (agent,)).fetchone()["n"]
    assert scheduled == 1, f"ten refused ticks released {scheduled} runs"


def test_a_re_arm_never_delays_a_schedule_past_its_natural_slot(agent):
    """The re-arm may only make a schedule MORE punctual. A provider that
    re-armed by pushing the time forward could delay a sparse schedule past a
    slot it would otherwise have hit."""
    coordinator.maybe_wakeup(agent, "occupying the agent")
    s = schedules.create_schedule(agent, "* * * * *", "frequent")
    natural = _next_firing(s["id"])
    _make_due(s["id"])

    schedules.fire_due()

    assert _next_firing(s["id"]) <= natural + timedelta(seconds=1), (
        "the re-arm pushed the schedule later than plain cron would have")


def test_a_paused_agent_defers_rather_than_loses_its_schedule(agent):
    """Pause is temporary, so a schedule must survive it."""
    coordinator.set_paused(agent, True)
    s = schedules.create_schedule(agent, "0 3 * * *", "nightly")
    _make_due(s["id"])

    schedules.fire_due()
    assert is_free(agent)

    coordinator.set_paused(agent, False)
    _make_due(s["id"])
    schedules.fire_due()

    assert live_run_of(agent) is not None, "unpausing did not restore the schedule"

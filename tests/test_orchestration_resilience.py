"""What an orchestration failure is allowed to cost.

Routing every wakeup through the facade widened what those call sites can
raise: a provider unreachable, a capability missing, a workflow bound to another
engine. The call sites still caught only `InputRefused`, so failures that used
to be a quiet `None` became exceptions on paths whose own comments describe them
as best effort.

The rule these defend: **a wakeup that fails costs latency, never durable work.**
The task row, the message row and the schedule row are all committed before the
wakeup is attempted, and the drain comes back for work nobody woke for. Turning
that into a 500, or into a burned cron tick, spends something real to report
something transient.
"""

import pytest

from andyur import db, orchestration
from andyur.orchestration.local import LocalWorkflowProvider
from andyur.server import coordinator, heartbeat, messages, schedules, tasks

from orchestration_contract.conftest import is_free, live_run_of


class Unreachable(LocalWorkflowProvider):
    """A provider whose engine is down, in the way a real one goes down: it
    admits nothing and raises the error the SPI says is transient."""

    def start(self, request):
        raise orchestration.ProviderUnavailable("the engine is down")


@pytest.fixture
def broken(monkeypatch):
    """Point the shared facade at an unreachable engine for one test."""
    orchestration.reset_facade()
    f = orchestration.OrchestrationFacade(provider=Unreachable())
    monkeypatch.setattr(orchestration, "facade", lambda: f)
    yield f
    orchestration.reset_facade()


# --- delegation survives an engine outage ------------------------------------

def test_a_task_is_still_created_when_the_engine_is_down(env, broken):
    """The task row is committed before the wakeup. A failure there must not
    turn a successful, durable POST /tasks into a 500 for the caller --
    delegation is exactly the path that has to survive an orchestration
    hiccup."""
    env.agent("boss")
    env.agent("worker")

    created = tasks.create_task(assignee="worker", creator="boss", title="do it")

    assert created["state"] == "open"
    assert is_free("worker"), "no run should have been admitted"


def test_the_undelivered_task_is_re_driven_once_the_engine_returns(env, broken,
                                                                   monkeypatch):
    """Nothing is lost. The work stays open and unstamped, so the drain picks
    it up on a later tick."""
    env.agent("boss")
    env.agent("worker")
    tasks.create_task(assignee="worker", creator="boss", title="do it")

    orchestration.reset_facade()
    monkeypatch.setattr(orchestration, "facade",
                        lambda: orchestration.OrchestrationFacade(
                            provider=LocalWorkflowProvider()))
    heartbeat.drain_pending_work()

    assert live_run_of("worker") is not None, "the deferred task was never re-driven"


def test_a_message_is_still_delivered_when_the_engine_is_down(env, broken):
    env.agent("sender")
    env.agent("recipient")

    sent = messages.send_message(recipient="recipient", sender="sender", body="hi")

    assert sent["id"]
    assert is_free("recipient")


# --- the drain keeps going ---------------------------------------------------

def test_one_agents_failure_does_not_cost_the_others_their_drain(env, monkeypatch):
    """`_drain_one`'s own comment states the requirement -- "one unlucky row
    must not cost the other agents their turn" -- and routing through the
    facade quietly broke it: an unhandled error aborted the loop over every
    remaining agent, on every tick, for as long as the condition lasted."""
    env.agent("boss")
    for name in ("first", "second", "third"):
        env.agent(name)
        tasks.create_task(assignee=name, creator="boss", title=f"for {name}")
        coordinator.set_paused(name, True)     # leave the work undelivered
    for name in ("first", "second", "third"):
        coordinator.set_paused(name, False)

    failed_for = {"first"}

    class SelectivelyBroken(LocalWorkflowProvider):
        def start(self, request):
            with db.connect() as c:
                agent = c.execute("SELECT agent FROM runs WHERE id = ?",
                                  (request.root_run_id,)).fetchone()["agent"]
            if agent in failed_for:
                # A REFUSAL OF THIS WORKFLOW, not an outage. This raised
                # `ProviderUnavailable` for one agent, which is not a thing an
                # engine does: unreachable is unreachable for everyone. The
                # drain now stops on a real outage rather than manufacturing a
                # failed run per agent (see the backoff test below), and that
                # exposed that this test had been exercising its property with
                # the wrong error. The property -- one agent's bad luck does
                # not cost the rest their turn -- is about per-workflow
                # refusals, so it is tested with one.
                raise orchestration.WorkflowRejected("refused for this one")
            return super().start(request)

    f = orchestration.OrchestrationFacade(provider=SelectivelyBroken())
    monkeypatch.setattr(orchestration, "facade", lambda: f)

    actions = heartbeat.drain_pending_work()

    assert live_run_of("second") is not None, "the drain stopped at the first failure"
    assert live_run_of("third") is not None
    assert any("orchestration refused" in a for a in actions), actions
    orchestration.reset_facade()


# --- a cron tick is deferred, not burned -------------------------------------

def test_an_engine_outage_defers_a_schedule_rather_than_burning_its_tick(env, broken):
    """Unlike a permanent input refusal, an unreachable engine says nothing
    about whether this schedule can ever fire. Burning the tick would silently
    lose a slot of unattended work -- the same defect the re-arm was written
    for, arriving by a different route."""
    agent = env.agent("alice")
    s = schedules.create_schedule(agent, "0 3 * * *", "nightly")
    with db.connect() as c:
        c.execute("UPDATE schedules SET next_run_at = ? WHERE id = ?",
                  ("2000-01-01T00:00:00+00:00", s["id"]))

    actions = schedules.fire_due()

    assert any("deferred" in a for a in actions), actions
    with db.connect() as c:
        nxt = c.execute("SELECT next_run_at FROM schedules WHERE id = ?",
                        (s["id"],)).fetchone()["next_run_at"]
    # HOW SOON, not whether it is in the future. This asserted `nxt < "2100"`,
    # which any date this century satisfies -- including the next 03:00 slot a
    # BURNED tick advances to. A re-arm lands within the retry window of now; a
    # burned tick lands hours away. Only the window tells them apart.
    from datetime import datetime, timezone

    delay = (datetime.fromisoformat(nxt) - datetime.now(timezone.utc)).total_seconds()
    assert delay <= schedules.RETRY_SECONDS + 30, (
        f"the tick was pushed {delay:.0f}s out -- to the next cron slot rather "
        f"than re-armed within {schedules.RETRY_SECONDS}s, so this slot of "
        "unattended work is lost")


# --- compensation only touches a run that never began ------------------------

def test_compensation_does_not_bury_a_run_a_worker_already_started(env, monkeypatch):
    """The race the facade opens: a worker can claim and start the run between
    its admission and the dispatch call returning. Marking THAT run failed
    would write an obituary for a container still doing work, and drop its
    credential mid-flight."""
    agent = env.agent("alice")
    started = {}

    class SlowAndBroken(LocalWorkflowProvider):
        def start(self, request):
            # a worker gets there first, exactly as one could over a network
            coordinator.start_run(request.root_run_id)
            started["run"] = request.root_run_id
            raise orchestration.ProviderUnavailable("the engine is down")

    f = orchestration.OrchestrationFacade(provider=SlowAndBroken())

    with pytest.raises(orchestration.ProviderUnavailable):
        f.request_agent_run(agent, "work")

    with db.connect() as c:
        row = c.execute("SELECT state, subject_token FROM runs WHERE id = ?",
                        (started["run"],)).fetchone()
    assert row["state"] == "running", (
        "compensation buried a run that was already executing")


def test_compensation_does_free_an_agent_whose_run_never_began(env):
    """The case it exists for is unaffected."""
    agent = env.agent("alice")
    f = orchestration.OrchestrationFacade(provider=Unreachable())

    with pytest.raises(orchestration.ProviderUnavailable):
        f.request_agent_run(agent, "work")

    assert is_free(agent)


# --- configuration is checked before serving ---------------------------------

def test_a_misconfigured_provider_refuses_to_serve_rather_than_failing_per_request(
        env, monkeypatch):
    """`UnknownProvider` says it must stop the process rather than surface as a
    runtime error. Built lazily, a typo started a healthy-looking server whose
    every trigger 500s and whose POST /tasks fails AFTER committing its row."""
    from andyur.orchestration import registry

    orchestration.reset_facade()
    monkeypatch.setenv(registry.ENV_VAR, "temporel")
    try:
        with pytest.raises(registry.UnknownProvider):
            orchestration.facade()
    finally:
        orchestration.reset_facade()


def test_the_server_builds_its_provider_before_accepting_traffic():
    """Asserted against the lifespan itself, because the failure mode is that
    nobody notices until the first request."""
    import inspect

    from andyur.server import app as app_module

    source = inspect.getsource(app_module.lifespan)
    assert "orchestration.facade()" in source, (
        "the server no longer validates its workflow provider at startup")


@pytest.mark.parametrize("phase", ["recover", "schedule", "drain", "consolidate"])
def test_a_blocking_heartbeat_phase_does_not_freeze_the_event_loop(monkeypatch, phase):
    """The heartbeat runs on uvicorn's MAIN loop, which serves every request.

    Once admission reached the workflow provider, a phase could block on the
    network for the whole RPC bound, and with the engine slow the server stopped
    answering anything -- including the halt endpoint, the one request that must
    never wait on the engine.

    THE ASSERTION IS ABOUT THE WINDOW, not the total. Counting how often another
    coroutine ran over the whole test would pass without the fix too, because
    the loop resumes as soon as the block ends. What matters is that something
    else ran WHILE the phase was blocked.

    EVERY PHASE, one at a time. Only the drain was tested, so a schedule phase
    left on the loop -- the one that reaches the provider on every due
    schedule -- passed.
    """
    import asyncio
    import time

    from andyur.server import heartbeat, schedules

    window = {}

    def blocking():
        window["start"] = time.monotonic()
        time.sleep(0.5)                       # a provider call that is slow
        window["end"] = time.monotonic()
        return []

    from andyur import config, graph

    targets = {"recover": (heartbeat, "recover_stuck_runs"),
               "schedule": (schedules, "fire_due"),
               "drain": (heartbeat, "drain_pending_work"),
               "consolidate": (heartbeat, "consolidate_graphs")}
    for name, (module, attr) in targets.items():
        monkeypatch.setattr(module, attr, blocking if name == phase else (lambda: []))
    monkeypatch.setattr(config, "GRAPH_CONSOLIDATE", phase == "consolidate")
    monkeypatch.setattr(config, "GRAPH_CONSOLIDATE_INTERVAL", 0)
    monkeypatch.setattr(graph, "enabled", lambda: True)
    monkeypatch.setattr(heartbeat, "_last_consolidate", float("-inf"))

    async def main():
        marks = []

        async def monitor():
            while True:
                marks.append(time.monotonic())
                await asyncio.sleep(0.02)

        mon = asyncio.create_task(monitor())
        beat = asyncio.create_task(heartbeat.heartbeat_loop())
        while "end" not in window:
            await asyncio.sleep(0.05)
        beat.cancel()
        mon.cancel()
        return marks

    marks = asyncio.run(main())
    during = [m for m in marks if window["start"] < m < window["end"]]

    assert during, (
        "nothing else ran on the event loop while a heartbeat phase was "
        "blocked -- the server was not serving requests, halt included")



# --- an unreachable engine pauses the drain ----------------------------------

def _agents_with_open_work(env, names):
    env.agent("boss")
    for name in names:
        env.agent(name)
        tasks.create_task(assignee=name, creator="boss", title=f"for {name}")
        coordinator.set_paused(name, True)     # leave the work undelivered
    for name in names:
        coordinator.set_paused(name, False)


def _failed_runs():
    with db.connect() as c:
        return c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE state = 'failed'").fetchone()["n"]


@pytest.fixture
def fresh_backoff(monkeypatch):
    from andyur.server import engine_breaker
    engine_breaker.ENGINE.reset()


def test_an_unreachable_engine_stops_the_drain_instead_of_failing_every_agent(
        env, broken, fresh_backoff):
    """IT FAILED A RUN PER AGENT PER TICK. Admission committed a pending run,
    `start` could not reach the engine, the run was abandoned as failed, and the
    work stayed open -- so the next tick did it again, for every agent, for as
    long as the outage lasted: up to ~2,880 failed runs a day each.

    An unreachable engine is not one agent's bad luck; every remaining agent
    fails the same way. So the first one stops the tick.
    """
    _agents_with_open_work(env, ("first", "second", "third", "fourth"))
    # MEASURED FROM HERE, NOT FROM ZERO. Creating each task makes a best-effort
    # wakeup, and with the engine down each of those is abandoned too -- the
    # first version of this counted those four, saw five, and failed a drain
    # that had in fact stopped after one.
    before = _failed_runs()

    actions = heartbeat.drain_pending_work()

    abandoned = _failed_runs() - before
    assert abandoned <= 1, (
        f"the drain admitted and abandoned {abandoned} runs in one tick of an "
        "outage -- one per agent, which repeats every tick")
    assert any("drain stopped" in a for a in actions), actions


def test_while_backing_off_the_drain_admits_nothing(env, broken, fresh_backoff):
    """The tick after an outage must not try again at once, or the backoff is
    only a label on the same churn."""
    _agents_with_open_work(env, ("first", "second"))
    heartbeat.drain_pending_work()
    before = _failed_runs()

    actions = heartbeat.drain_pending_work()

    assert _failed_runs() == before, "the drain retried inside its backoff window"
    assert any("drain paused" in a for a in actions), actions


def test_positive_control_a_reachable_engine_drains_every_agent(env, fresh_backoff):
    """Without this, a drain that stops unconditionally passes both tests above."""
    orchestration.reset_facade()
    _agents_with_open_work(env, ("first", "second", "third"))

    heartbeat.drain_pending_work()

    for name in ("first", "second", "third"):
        assert live_run_of(name) is not None, f"{name}'s work was not drained"


# --- one breaker, shared by the drain and the schedules -----------------------

def _due_schedules(env, names):
    ids = []
    for name in names:
        s = schedules.create_schedule(env.agent(name), "0 3 * * *", "nightly")
        with db.connect() as c:
            c.execute("UPDATE schedules SET next_run_at = ? WHERE id = ?",
                      ("2000-01-01T00:00:00+00:00", s["id"]))
        ids.append(s["id"])
    return ids


def _next_run_at(schedule_id):
    with db.connect() as c:
        return c.execute("SELECT next_run_at FROM schedules WHERE id = ?",
                         (schedule_id,)).fetchone()["next_run_at"]


def test_an_engine_outage_stops_the_schedule_phase_after_one_attempt(env, broken):
    """THE SCHEDULES HAD NO BACKOFF while the drain did. Every due schedule was
    claimed, its run admitted, its start refused and the run abandoned as
    failed -- every tick, for every schedule, for the length of the outage.

    The first unreachable start trips the breaker; the schedules after it stay
    due and UNCLAIMED, so they fire once the engine answers rather than being
    advanced and failed."""
    ids = _due_schedules(env, ("alpha", "beta", "gamma"))
    before = _failed_runs()

    actions = schedules.fire_due()

    assert _failed_runs() - before <= 1, (
        f"{_failed_runs() - before} scheduled runs were admitted and abandoned "
        "in one tick of an outage")
    untouched = [i for i in ids if _next_run_at(i) == "2000-01-01T00:00:00+00:00"]
    assert len(untouched) >= 2, (
        "the schedules after the first failure were claimed anyway; they should "
        f"stay due until the engine answers ({actions})")


def test_while_the_engine_is_down_no_schedule_is_claimed(env, broken):
    ids = _due_schedules(env, ("alpha",))
    from andyur.server import engine_breaker
    engine_breaker.ENGINE.trip()
    before = _failed_runs()

    actions = schedules.fire_due()

    assert _failed_runs() == before, "a schedule fired inside the outage window"
    assert _next_run_at(ids[0]) == "2000-01-01T00:00:00+00:00", (
        "a due schedule was claimed while the breaker was open")
    assert any("schedules paused" in a for a in actions), actions


def test_the_drain_resumes_once_the_window_has_passed(env, broken, monkeypatch):
    """A backoff that never ends is an outage of its own. After the window, the
    drain tries the engine again -- here, a reachable one, which drains."""
    _agents_with_open_work(env, ("first", "second"))
    heartbeat.drain_pending_work()                     # trips the breaker
    from andyur.server import engine_breaker
    assert engine_breaker.ENGINE.open_for() > 0, "the outage did not trip the breaker"

    # The engine comes back, and the window runs out.
    import sys
    facade_module = sys.modules["andyur.orchestration.facade"]   # the attribute is patched
    orchestration.reset_facade()
    monkeypatch.setattr(orchestration, "facade", facade_module.facade)
    real_monotonic = engine_breaker.time.monotonic
    monkeypatch.setattr(engine_breaker.time, "monotonic",
                        lambda: real_monotonic() + engine_breaker.MAX_SECONDS + 1)

    actions = heartbeat.drain_pending_work()

    assert not any("drain paused" in a for a in actions), (
        f"the drain stayed paused after its window ({actions})")
    for name in ("first", "second"):
        assert live_run_of(name) is not None, f"{name}'s work was not drained on recovery"


def test_an_idle_tick_does_not_reset_the_backoff(env, broken):
    """Only an engine that ANSWERED closes the breaker. A tick with nothing to
    do reached nothing, and resetting on it kept a long outage at the minimum
    wait: every window ended, the next attempt failed, and the wait never grew."""
    from andyur.server import engine_breaker
    first = engine_breaker.ENGINE.trip()
    engine_breaker.ENGINE._until = 0.0            # the window ends, idle

    heartbeat.drain_pending_work()                 # nothing is waiting
    second = engine_breaker.ENGINE.trip()

    assert second > first, (
        f"the wait did not grow ({first:.0f}s then {second:.0f}s): something "
        "reset the backoff without the engine having answered")

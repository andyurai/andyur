"""Stage 9: what survives a worker dying, a service going away, and a step
delivered twice.

These run the REAL provider against a REAL Temporal service. Everything else in
`test_temporal_provider.py` is assertable with the SDK absent; none of it can
tell you whether the thing actually works, and a mock here would be the more
dangerous kind of green.

    ANDYUR_TEMPORAL_ADDRESS=localhost:7233   (a `temporal server start-dev`)

Marked `integration`, so the fast lane skips them and CI runs them in a lane
that has a service.

## The invariant everything below serves

    one Andyur run_id  ->  at most one logical external effect

Durable execution protects against a worker dying. It does NOT protect against
an ambiguous completion: a step whose effect landed before its acknowledgement
was lost is retried, and retried means done twice unless something refuses. On
this platform that something is Andyur's own guards -- `start_run` and
`finish_run` refuse a repeat -- which is why these tests assert the EFFECT
count, not the call count.
"""

import os
import threading
import time
import uuid

import pytest

pytestmark = pytest.mark.integration

temporalio = pytest.importorskip("temporalio", reason="the Temporal SDK is an extra")

from andyur import db                                            # noqa: E402
from andyur.orchestration import errors, models                  # noqa: E402
from andyur.orchestration.temporal import TemporalConfig         # noqa: E402
from andyur.orchestration.temporal.provider import (             # noqa: E402
    HALT_SIGNAL, TemporalWorkflowProvider)
from andyur.server import coordinator                            # noqa: E402

ADDRESS = os.environ.get("ANDYUR_TEMPORAL_ADDRESS", "localhost:7233")


def _service_is_up() -> bool:
    import socket

    host, _, port = ADDRESS.partition(":")
    try:
        with socket.create_connection((host, int(port or 7233)), timeout=1):
            return True
    except OSError:
        return False


if not _service_is_up():
    # A SKIP IS NOT A PASS in the lane that exists to run this: CI sets the
    # variable, so a runner whose service never came up fails instead.
    if os.environ.get("ANDYUR_REQUIRE_TEMPORAL") == "1":
        raise RuntimeError(f"ANDYUR_REQUIRE_TEMPORAL=1 and no Temporal service at {ADDRESS}")
    pytest.skip(f"no Temporal service at {ADDRESS}", allow_module_level=True)


class WorkerThread:
    """A Temporal worker in a thread, so a test can kill it mid-flight.

    Its own event loop, because the worker is async and these tests are not --
    the same shape the provider itself uses, for the same reason.
    """

    def __init__(self, queue: str):
        self.queue = queue
        self._loop = None
        self._stop = None
        self._thread = None

    def start(self):
        import asyncio

        ready = threading.Event()

        def run():
            import asyncio as aio

            from temporalio.client import Client

            from andyur.orchestration.temporal.config import TemporalConfig as Cfg
            from andyur.orchestration.temporal.worker import build_worker

            loop = aio.new_event_loop()
            aio.set_event_loop(loop)
            self._loop = loop
            self._stop = aio.Event()

            async def serve():
                client = await Client.connect(ADDRESS)
                # THE SHIPPED WORKER, not one the test built: a harness with
                # its own worker configuration proves nothing about the one
                # that runs in production.
                async with build_worker(client, Cfg(address=ADDRESS,
                                                    task_queue=self.queue)):
                    ready.set()
                    await self._stop.wait()

            loop.run_until_complete(serve())

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(30), "the worker never became ready"
        return self

    def kill(self):
        """Stop serving. The workflow's state stays in the service, which is
        the property under test."""
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(timeout=20)
        self._thread = None


@pytest.fixture
def queue():
    return f"andyur-test-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def provider(queue):
    p = TemporalWorkflowProvider(
        TemporalConfig(address=ADDRESS, task_queue=queue, rpc_timeout_seconds=15))
    yield p
    p._conn.close()


@pytest.fixture
def worker(queue):
    w = WorkerThread(queue)
    yield w
    w.kill()


def _admitted(env, name="alice"):
    """An agent with a real admitted run, as the facade would leave it."""
    agent = env.agent(name)
    run_id = coordinator.maybe_wakeup(agent, "campaign")
    with db.connect() as c:
        wf = c.execute("SELECT workflow_id FROM runs WHERE id = ?",
                       (run_id,)).fetchone()["workflow_id"]
    return agent, run_id, wf


def _state(run_id):
    with db.connect() as c:
        row = c.execute("SELECT state FROM runs WHERE id = ?", (run_id,)).fetchone()
    return row["state"] if row else None


def _wait(predicate, timeout=30, interval=0.4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _announce_started(run_id):
    """Stand in for the RUN announcing its own start.

    `POST /runs/{id}/start` is authenticated by the run's own SVID, so in a
    real deployment the agent says this and nothing else may say it on its
    behalf. There is no run process in this campaign, so the test does.

    THE WORKFLOW MUST NOT DO THIS, and an earlier version did: it marked the
    run `running`, which took it out of the `pending` state the worker daemon
    claims, so the run was never assigned and never launched. Every test below
    used to wait for `running` after starting a workflow -- which asserted the
    defect rather than the contract, and passed because a campaign has no
    daemon that needed the run to stay pending.
    """
    assert coordinator.start_run(run_id), f"run {run_id} was not pending"


def _activity_completions(provider, workflow_id):
    """How many activities this workflow has actually completed.

    The signal that a workflow is MAKING PROGRESS, now that it no longer
    mutates the run. A workflow with no worker is RUNNING too; the difference
    is whether anything executed.
    """
    return _history_kinds(provider, workflow_id).get(
        "EVENT_TYPE_ACTIVITY_TASK_COMPLETED", 0)


def _ex(run_id):
    """The engine execution that observes one run.

    Executions are keyed by RUN now, not by Andyur's workflow id: a workflow
    holds many runs, and keying by the workflow meant only the first was ever
    observed. Anything that addresses THE ENGINE'S EXECUTION -- describe, signal,
    history -- uses this; anything that addresses ANDYUR'S WORKFLOW keeps `wf`.
    """
    from andyur.orchestration.temporal.provider import run_execution_id

    return run_execution_id(run_id)


def _start(provider, wf, run_id):
    return provider.start(models.WorkflowStart(
        workflow_id=wf, root_run_id=run_id, workflow_kind="single_agent"))


# --- the invariant -----------------------------------------------------------

def test_one_run_id_yields_one_execution_however_often_it_is_started(
        env, provider, worker):
    """THE PRIMARY INVARIANT. Andyur retries, and a durable engine delivers at
    least once; neither may produce a second execution for one admitted run."""
    worker.start()
    _agent, run_id, wf = _admitted(env)

    handles = [_start(provider, wf, run_id) for _ in range(4)]

    assert len({h.provider_ref for h in handles}) == 1, (
        f"one run id produced {len({h.provider_ref for h in handles})} executions")


def test_starting_the_same_workflow_does_not_disturb_a_run_already_going(
        env, provider, worker):
    """A duplicate start reaches an execution that is already RUNNING, and must
    return it rather than replace it.

    WHAT THIS USED TO ASSERT COULD NOT FAIL. It checked that the run's
    `started_at` was unchanged -- but the workflow no longer writes it (a run
    announces its own start), so no bug in the engine path could change it. An
    adversarial review restored the old start activity and even made it
    overwrite `started_at` unconditionally; this stayed green both times.

    What the engine path DOES control is the conflict policy. `USE_EXISTING`
    returns the live execution; a policy such as `TERMINATE_EXISTING` would
    kill it and start another under the same id, silently restarting the
    observation of a run that is mid-flight. That is visible as a different
    engine run id, so that is what is asserted.
    """
    worker.start()
    _agent, run_id, wf = _admitted(env)
    first = _start(provider, wf, run_id)
    _announce_started(run_id)
    assert _wait(lambda: _activity_completions(provider, _ex(run_id)) > 0), (
        "setup: the execution must be running before the duplicate arrives")

    second = _start(provider, wf, run_id)

    assert second.provider_ref == first.provider_ref, (
        f"a duplicate start replaced a RUNNING execution ({first.provider_ref} "
        f"-> {second.provider_ref}); its observation was restarted mid-flight")
    assert not provider.describe(_ex(run_id)).state.is_terminal()


def _started_at(run_id):
    with db.connect() as c:
        return c.execute("SELECT started_at FROM runs WHERE id = ?",
                         (run_id,)).fetchone()["started_at"]


# --- the worker dying --------------------------------------------------------

def test_work_survives_a_worker_that_never_existed(env, provider, worker):
    """Scenario 1: started with no worker at all. The service holds the task;
    the workflow makes progress the moment one appears."""
    _agent, run_id, wf = _admitted(env)

    _start(provider, wf, run_id)                    # no worker running yet
    time.sleep(2)
    assert _activity_completions(provider, _ex(run_id)) == 0, (
        "something executed without a worker")
    assert _state(run_id) == "pending", "the run was moved out of pending"

    worker.start()

    assert _wait(lambda: _activity_completions(provider, _ex(run_id)) > 0), (
        "the workflow did not resume when a worker appeared")
    # STILL PENDING, and that is the contract. The workflow observes the run;
    # the daemon is what claims and launches it, and a workflow that had moved
    # it out of `pending` would have taken that away.
    assert _state(run_id) == "pending"


def test_work_survives_the_worker_being_killed_mid_flight(env, provider, worker):
    """Scenarios 2 and 3: the worker dies after claiming the task, and after
    the run has been started but before the workflow finished with it."""
    worker.start()
    _agent, run_id, wf = _admitted(env)
    _start(provider, wf, run_id)
    _announce_started(run_id)
    assert _wait(lambda: _activity_completions(provider, _ex(run_id)) > 0)

    worker.kill()
    described = provider.describe(_ex(run_id))
    assert described.state is models.WorkflowState.RUNNING, (
        "the service forgot the workflow when its worker died")

    second = WorkerThread(worker.queue).start()
    try:
        coordinator.finish_run(run_id, "done", None)
        assert _wait(lambda: provider.describe(_ex(run_id)).state.is_terminal(), timeout=40), (
            "the workflow never noticed the run had finished")
    finally:
        second.kill()


def test_a_completed_step_is_not_repeated_after_a_restart(env, provider, worker):
    """Replay, which is the reason to adopt this at all: the worker dies, another
    picks the execution up by replaying its history, and it carries on.

    WHAT THIS USED TO ASSERT COULD NOT FAIL. It checked the run's `started_at`
    was unchanged after the restart, and nothing in the engine path writes it
    any more. A review restored the old start activity, then made it overwrite
    `started_at` unconditionally; this stayed green both times, because a
    completed activity is replayed from history rather than re-run.

    What our code controls in a replay is DETERMINISM, and most of that is now
    caught EARLIER than replay: the sandbox, switched back on for Andyur's
    workflows by the same review, refuses a non-deterministic call on the first
    execution (see the named wait below). What is left for this test is the
    resume path itself -- the execution survives its worker, completes, and
    reports the run's result with no failed workflow task in its history.
    """
    worker.start()
    _agent, run_id, wf = _admitted(env)
    _start(provider, wf, run_id)
    _announce_started(run_id)
    # NAMED, because this is where non-deterministic workflow code now fails.
    # Checked with a mutant that called `random.random()` in the workflow: the
    # sandbox refused it on the FIRST execution, so no activity ever completed
    # and this wait timed out with a bare `assert False` -- caught, and
    # undiagnosable. Non-determinism is stopped before a replay can happen,
    # which is the determinism checks doing their job; the failure just has to
    # say that is what happened.
    assert _wait(lambda: _activity_completions(provider, _ex(run_id)) > 0), (
        "the execution never completed an activity: its workflow task is "
        "failing, most likely because the workflow code is not deterministic "
        "and the sandbox refused it")

    worker.kill()
    second = WorkerThread(worker.queue).start()
    try:
        coordinator.finish_run(run_id, "done", None)
        assert _wait(lambda: provider.describe(_ex(run_id)).state.is_terminal(),
                     timeout=40), "the execution never resumed after the worker died"
        assert provider.describe(_ex(run_id)).state is models.WorkflowState.SUCCEEDED, (
            "the replayed execution did not report the run's outcome")
        assert _history_kinds(provider, _ex(run_id)).get(
            "EVENT_TYPE_WORKFLOW_TASK_FAILED", 0) == 0, (
            "a workflow task failed on replay -- the workflow code is not "
            "deterministic, so a restart takes a different path than the original")
    finally:
        second.kill()


# --- the service going away ---------------------------------------------------

def test_an_unreachable_service_is_reported_not_raised_as_itself(env):
    """Scenario 5. Andyur's own record is untouched by the engine being down,
    and the error that comes back is Andyur's vocabulary, not the SDK's."""
    dead = TemporalWorkflowProvider(
        TemporalConfig(address="127.0.0.1:1", rpc_timeout_seconds=3))
    try:
        health = dead.health()
        assert health.reachable is False

        _agent, run_id, wf = _admitted(env)
        with pytest.raises(errors.ProviderUnavailable):
            _start(dead, wf, run_id)

        assert _state(run_id) == "pending", (
            "an unreachable engine changed Andyur's record")
    finally:
        dead._conn.close()


def test_andyurs_record_is_authoritative_while_the_engine_is_unreachable(env):
    """Scenario 4, in the form that matters: the platform keeps working. A run
    can still be finished, and an audit still reads the truth, with no engine
    in the picture at all."""
    _agent, run_id, _wf = _admitted(env)
    coordinator.start_run(run_id)

    coordinator.finish_run(run_id, "done", None)

    assert _state(run_id) == "done"


# --- halt, and why not cancel -------------------------------------------------

def test_halting_stops_the_workflow_without_destroying_anything(env, provider, worker):
    """Scenario 7. The signal reaches the workflow, it stops waiting, and the
    run is untouched -- because containment is Andyur's condemnation path and
    does not run through the provider."""
    worker.start()
    _agent, run_id, wf = _admitted(env)
    _start(provider, wf, run_id)
    _announce_started(run_id)

    outcome = provider.halt(models.HaltRequest(workflow_id=wf, reason="operator", run_ids=(run_id,)))

    assert outcome.accepted is True
    assert _wait(lambda: provider.describe(_ex(run_id)).state.is_terminal(), timeout=40)
    assert _state(run_id) == "running", (
        "the provider ended a run; only Andyur may do that")


def test_halting_a_workflow_the_service_never_had_is_accepted(env, provider):
    """There is no durable progress to stop, so the request is satisfied --
    and refusing would break the kill switch exactly when an operator is racing
    a workflow that is starting."""
    outcome = provider.halt(models.HaltRequest(
        workflow_id=f"wf-never-{uuid.uuid4().hex[:8]}", reason="operator"))

    assert outcome.accepted is True


def test_cancelling_does_not_run_the_workflows_own_cleanup(env, provider, worker):
    """Scenario 6, and the measurement that decided the interface.

    This is the behaviour the design avoids rather than relies on: cancelling
    the workflow cancels its own execution, so anything it would do afterwards
    does not happen. The test exists so that if a future SDK changes this, we
    find out deliberately rather than by trusting a comment.
    """
    worker.start()
    _agent, run_id, wf = _admitted(env)
    _start(provider, wf, run_id)
    _announce_started(run_id)

    client = provider._conn.client()
    provider._conn.run(client.get_workflow_handle(_ex(run_id)).cancel())

    assert _wait(lambda: provider.describe(_ex(run_id)).state.is_terminal(), timeout=40)
    assert _state(run_id) == "running", (
        "cancellation reached into Andyur's record, which it must never do")


# --- duplicate delivery and timeouts ------------------------------------------

def test_a_duplicated_step_is_refused_by_the_platform_not_the_engine(env):
    """Scenario 8, at the boundary that actually protects the effect.

    Temporal will deliver an activity more than once; nothing it offers stops
    that. What stops a SECOND START is Andyur's own guard, so this asserts the
    guard directly -- the engine is not the thing being tested here.
    """
    _agent, run_id, _wf = _admitted(env)

    first = coordinator.start_run(run_id)
    second = coordinator.start_run(run_id)

    assert (first, second) == (True, False)


def test_a_duplicated_finish_cannot_overwrite_the_recorded_outcome(env):
    _agent, run_id, _wf = _admitted(env)
    coordinator.start_run(run_id)

    assert coordinator.finish_run(run_id, "the real outcome", None) is True
    assert coordinator.finish_run(run_id, None, "a retry's opinion") is False
    assert _state(run_id) == "done"


def test_a_bounded_call_fails_rather_than_hanging(env):
    """Scenario 9 in the shape Andyur cares about: these are called on request
    paths, so a call that cannot complete must fail, not hang -- a caller
    cannot tell a hang from slow work."""
    slow = TemporalWorkflowProvider(
        TemporalConfig(address="10.255.255.1:7233", rpc_timeout_seconds=2))
    try:
        start = time.monotonic()
        with pytest.raises(errors.ProviderUnavailable):
            slow.start(models.WorkflowStart(
                workflow_id="wf-x", root_run_id="r-x", workflow_kind="single_agent"))
        assert time.monotonic() - start < 20, "the call was not bounded"
    finally:
        slow._conn.close()


# --- Stage 10: schedules ------------------------------------------------------

@pytest.fixture
def schedule_id(provider):
    sid = f"andyur-test-sched-{uuid.uuid4().hex[:8]}"
    yield sid
    try:
        provider.delete_schedule(sid)
    except Exception:                       # noqa: BLE001 - cleanup is best effort
        pass


def _spec(schedule_id, agent="alice", cron="0 3 * * *", **kw):
    return models.ScheduleSpec(schedule_id=schedule_id, agent=agent, cron=cron,
                               reason="nightly", **kw)


def test_a_schedule_is_created_under_the_id_the_caller_asked_for(
        env, provider, schedule_id):
    handle = provider.create_schedule(_spec(schedule_id))

    assert handle.schedule_id == schedule_id
    assert handle.provider == "temporal"


def test_creating_the_same_schedule_twice_is_not_an_error(env, provider, schedule_id):
    """The caller's intent is that this trigger exists; saying so twice does
    not make it two triggers."""
    provider.create_schedule(_spec(schedule_id))
    again = provider.create_schedule(_spec(schedule_id))

    assert again.schedule_id == schedule_id


def test_updating_a_schedule_replaces_it_rather_than_adding_another(
        env, provider, schedule_id):
    """The defect this encodes cost the native provider a duplicate per update:
    delete-then-create under a FRESH id left the old one firing forever."""
    provider.create_schedule(_spec(schedule_id, cron="0 3 * * *"))
    provider.update_schedule(_spec(schedule_id, cron="0 4 * * *"))
    provider.update_schedule(_spec(schedule_id, cron="0 5 * * *"))

    provider.delete_schedule(schedule_id)

    client = provider._conn.client()
    with pytest.raises(Exception):
        provider._conn.run(client.get_schedule_handle(schedule_id).describe())


def test_deleting_an_absent_schedule_is_not_an_error(env, provider):
    provider.delete_schedule(f"never-existed-{uuid.uuid4().hex[:6]}")


def test_an_overlap_rule_the_engine_cannot_express_is_refused(
        env, provider, schedule_id):
    """REFUSED, NOT SUBSTITUTED. None of the engine's native overlap policies
    is Andyur's skip-and-retry-soon, so a caller asking for buffering is told
    no rather than quietly given SKIP."""
    with pytest.raises(errors.ProviderCapabilityMissing):
        provider.create_schedule(_spec(schedule_id, on_overlap="buffer_all"))


def test_a_schedule_created_paused_is_paused(env, provider, schedule_id):
    provider.create_schedule(_spec(schedule_id, paused=True))

    client = provider._conn.client()
    desc = provider._conn.run(client.get_schedule_handle(schedule_id).describe())

    assert desc.schedule.state.paused is True


def test_a_busy_agent_does_not_lose_its_tick(env, provider, worker, schedule_id):
    """ANDYUR'S OVERLAP RULE, end to end on the engine.

    The agent is busy when the schedule fires, so admission refuses. The tick
    must not be dropped and must not be buffered: the workflow waits on a
    DURABLE timer and asks again, which is what the native engine does with a
    re-armed row -- except this survives the worker dying mid-wait.
    """
    worker.start()
    agent = env.agent("alice")
    busy = coordinator.maybe_wakeup(agent, "occupying the agent")
    assert busy is not None

    client = provider._conn.client()
    from andyur.orchestration.temporal.workflows import ScheduledAgentRun

    wf_id = f"sched-run-{uuid.uuid4().hex[:8]}"
    handle = provider._conn.run(client.start_workflow(
        ScheduledAgentRun.run,
        args=[agent, "nightly", 2.0, 60.0, _engine_schedule(agent)],
        id=wf_id, task_queue=provider._config.task_queue))

    time.sleep(4)
    with db.connect() as c:
        scheduled = c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = ? AND run_type = 'scheduled'",
            (agent,)).fetchone()["n"]
    assert scheduled == 0, "a tick was admitted while the agent was busy"

    coordinator.finish_run(busy, "done", None)

    assert _wait(lambda: _scheduled_runs(agent) == 1, timeout=40), (
        "the deferred tick never fired once the agent was free")
    assert _scheduled_runs(agent) == 1, "the tick was admitted more than once"


def _engine_schedule(agent, reason="nightly"):
    """The Andyur row a tick must name: admission refuses a tick for a schedule
    Andyur does not hold (B+ adversarial review)."""
    sid = uuid.uuid4().hex[:12]
    with db.connect() as c:
        c.execute(
            "INSERT INTO schedules (id, agent, cron, reason, enabled, next_run_at, "
            "created_at, trigger) VALUES (?, ?, '0 3 * * *', ?, 1, ?, ?, 'engine')",
            (sid, agent, reason, db.utcnow(), db.utcnow()))
    return sid


def _scheduled_runs(agent):
    with db.connect() as c:
        return c.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE agent = ? AND run_type = 'scheduled'",
            (agent,)).fetchone()["n"]


def test_a_tick_is_given_up_rather_than_carried_into_the_next_slot(
        env, provider, worker):
    """Bounded on purpose. Carrying a tick past its own window is the backlog
    the rule forbids, so the workflow gives up and the next firing is a fresh
    decision."""
    worker.start()
    agent = env.agent("alice")
    coordinator.maybe_wakeup(agent, "busy for the whole window")

    client = provider._conn.client()
    from andyur.orchestration.temporal.workflows import ScheduledAgentRun

    handle = provider._conn.run(client.start_workflow(
        ScheduledAgentRun.run,
        args=[agent, "nightly", 1.0, 3.0,           # retry 1s, window 3s
              _engine_schedule(agent)],
        id=f"sched-run-{uuid.uuid4().hex[:8]}",
        task_queue=provider._config.task_queue))
    result = provider._conn.run(handle.result())

    assert result is None, "the tick was carried beyond its window"
    assert _scheduled_runs(agent) == 0


# --- Stage 11: durable approvals ---------------------------------------------

def _action_row(env, action_id, decision, agent="approver-agent"):
    """An action request in a given decision state, on a REAL run.

    The real `actionrequests.request` needs a live grant and a PDP; these tests
    are about what the WORKFLOW does with the row, so the row is what they set
    up -- but the run has to exist, because `action_requests.run_id` is a
    foreign key and a test that invented one would be testing nothing.
    """
    env.agent(agent)
    run_id = coordinator.maybe_wakeup(agent, "for an action")
    with db.connect() as c:
        c.execute(
            "INSERT INTO action_requests (id, run_id, tool, target, requested_at, "
            "decision) VALUES (?, ?, 't', 'tgt', ?, ?)",
            (action_id, run_id, db.utcnow(), decision))
    return run_id


def _approval(provider, action_id, wait_seconds=30.0):
    from andyur.orchestration.temporal.workflows import DurableApproval

    client = provider._conn.client()
    return provider._conn.run(client.start_workflow(
        DurableApproval.run, args=[action_id, wait_seconds],
        id=f"appr-{uuid.uuid4().hex[:8]}",
        task_queue=provider._config.task_queue))


def test_a_signal_saying_approved_does_not_make_it_approved(env, provider, worker):
    """THE PROPERTY THE WHOLE DESIGN RESTS ON.

    Anyone who can reach the engine can send a signal. If the signal decided,
    the authorization decision would have moved into the engine -- replayed
    from history rather than re-evaluated, which is the opposite of what
    revocation needs. The row says approval is still required; the workflow
    must say so too, no matter who rang the bell.
    """
    worker.start()
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    _action_row(env, action_id, "approval_required")

    handle = _approval(provider, action_id)
    provider._conn.run(handle.signal("decided"))
    decision = provider._conn.run(handle.result())

    assert decision == "approval_required", (
        "a signal decided an authorization question; the row must")


def test_the_recorded_decision_is_what_comes_back(env, provider, worker):
    worker.start()
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    _action_row(env, action_id, "approved")

    handle = _approval(provider, action_id)
    provider._conn.run(handle.signal("decided"))

    assert provider._conn.run(handle.result()) == "approved"


def test_a_decision_recorded_without_a_signal_is_still_found(env, provider, worker):
    """The wait can end without anyone ringing the bell -- a decision may be
    recorded by an operator who never touched the engine. The row is read after
    the wake-up either way, so the timeout path reaches the same answer."""
    worker.start()
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    _action_row(env, action_id, "approved")

    handle = _approval(provider, action_id, wait_seconds=2.0)

    assert provider._conn.run(handle.result()) == "approved"


def test_an_action_that_does_not_exist_is_named_not_guessed(env, provider, worker):
    worker.start()

    handle = _approval(provider, f"act-never-{uuid.uuid4().hex[:6]}", wait_seconds=2.0)

    assert provider._conn.run(handle.result()) == "absent"


def test_the_wait_survives_the_worker_being_killed(env, provider, worker):
    """WHAT THE ENGINE ACTUALLY ADDS. An approval that does not survive a
    restart silently becomes a refusal, and an operator who approved something
    is entitled to expect it happened."""
    worker.start()
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    _action_row(env, action_id, "approval_required")
    handle = _approval(provider, action_id, wait_seconds=120.0)
    time.sleep(2)

    worker.kill()
    with db.connect() as c:                       # the human decides meanwhile
        c.execute("UPDATE action_requests SET decision = 'approved' WHERE id = ?",
                  (action_id,))

    second = WorkerThread(worker.queue).start()
    try:
        provider._conn.run(handle.signal("decided"))
        assert provider._conn.run(handle.result()) == "approved", (
            "the approval did not survive the worker being replaced")
    finally:
        second.kill()


def test_approval_semantics_are_not_temporal_only(env):
    """The local provider must be able to exercise the same security
    semantics, or the security story is only testable where the engine is.

    What it cannot offer is the DURABLE multi-day wait, and the capability
    model says so rather than pretending otherwise.
    """
    from andyur.orchestration import capabilities
    from andyur.orchestration.local import LocalWorkflowProvider

    local = LocalWorkflowProvider().capabilities()

    # the recording and revalidation live in andyur.server.actionrequests,
    # which is provider-independent and has no capability gate at all
    assert "approval" not in " ".join(capabilities.ALL_CAPABILITIES)
    with pytest.raises(errors.ProviderCapabilityMissing):
        capabilities.check("durable_approval", local)


# --- Stage 12: delegation is the platform's, whichever engine is running ------

def _delegate(env, provider, parent_agent="boss", child_agent="worker"):
    """A delegated run admitted through the facade, with a provider bound."""
    from andyur import orchestration

    env.agent(parent_agent)
    env.agent(child_agent)
    f = orchestration.OrchestrationFacade(provider=provider)
    parent, _ = f.request_agent_run(parent_agent, "root", user="u1",
                                    user_asserted_by="idp",
                                    subject_token="PARENT-CREDENTIAL")
    return f, parent


def test_delegation_security_does_not_move_when_the_engine_does(env, provider, worker):
    """THE STAGE 12 REQUIREMENT, stated as a test.

    Parent validation, never-widening inheritance, the depth cap and the
    work-item cap are Andyur's and happen BEFORE any provider is asked to
    schedule anything. Running on a durable engine must not change one of them.

    The same assertions hold in `tests/orchestration_contract/` against the
    native engine; this runs them with a Temporal provider bound, so the claim
    is measured on both rather than assumed on one.
    """
    worker.start()
    f, parent = _delegate(env, provider)

    # a forged parent is refused, not rooted -- it would reset depth and budget
    forged, reason = f.request_agent_run(
        "worker", "child", parent_run_id="de" * 16)
    assert forged is None and reason is not None

    # the subject's credential does not follow a different subject
    other, _ = f.request_agent_run(
        "worker", "child", parent_run_id=parent, user="someone-else")
    with db.connect() as c:
        tok = c.execute("SELECT subject_token FROM runs WHERE id = ?",
                        (other,)).fetchone()["subject_token"]
    assert tok is None, "a run acting for a different subject got the credential"


def test_the_depth_cap_holds_with_a_durable_engine_bound(env, provider, worker):
    """The cap is enforced at admission, which is upstream of every provider."""
    from andyur import orchestration

    worker.start()
    agents = [env.agent(f"d{i}") for i in range(coordinator.MAX_DELEGATION_DEPTH + 2)]
    f = orchestration.OrchestrationFacade(provider=provider)

    chain = [f.request_agent_run(agents[0], "root")[0]]
    for i in range(1, coordinator.MAX_DELEGATION_DEPTH + 1):
        nxt, _ = f.request_agent_run(agents[i], f"hop {i}", parent_run_id=chain[-1])
        assert nxt is not None, f"the chain was refused early at hop {i}"
        chain.append(nxt)

    over, reason = f.request_agent_run(
        agents[coordinator.MAX_DELEGATION_DEPTH + 1], "one too far",
        parent_run_id=chain[-1])

    assert over is None and reason is not None, "the depth cap moved"


def test_child_workflows_are_not_claimed_because_nothing_uses_them(provider):
    """CHARACTERIZATION, and a deliberate non-implementation.

    The plan says Temporal MAY model delegation as child workflows. Andyur's
    delegation does not go through a run's workflow -- it goes through tasks and
    messages, each admitted by the facade, and each admitted run gets its own
    workflow already. Binding those lifetimes into a parent would add a
    relationship the platform does not have.

    So the capability stays False, because a capability is a promise something
    will be built on and nothing here is built on this one. The security
    semantics above hold either way, which is what the stage actually requires.
    """
    assert provider.capabilities().child_workflows is False

    from andyur.orchestration import capabilities
    with pytest.raises(errors.ProviderCapabilityMissing):
        capabilities.check("delegated_fanout", provider.capabilities())


# --- review regressions -------------------------------------------------------

def _history_kinds(provider, workflow_id):
    from temporalio.api.enums.v1 import EventType

    async def collect():
        h = provider._conn.client().get_workflow_handle(workflow_id)
        kinds = {}
        async for e in h.fetch_history_events():
            n = EventType.Name(e.event_type)
            kinds[n] = kinds.get(n, 0) + 1
        return kinds

    return provider._conn.run(collect())


def test_the_poll_loop_does_not_advance_by_failing_its_own_task(
        env, provider, worker):
    """THE TEST THAT PASSED FOR THE WRONG REASON, now asserting the mechanism.

    `wait_condition` throws on timeout, which is the ORDINARY case on every
    poll of a run that is still going. Uncaught, it escaped the workflow; and
    because `asyncio.TimeoutError` is not a `FailureError`, Temporal treated it
    as a workflow task failure and retried forever. The loop did advance --
    replay re-ran the observation and eventually saw a terminal state -- so the
    campaign went green with a task timeout in the history of every run.

    Green is not the assertion. The history is.
    """
    worker.start()
    _agent, run_id, wf = _admitted(env)
    _start(provider, wf, run_id)
    _announce_started(run_id)

    time.sleep(12)                              # at least two polls at POLL=5s
    coordinator.finish_run(run_id, "done", None)
    assert _wait(lambda: provider.describe(_ex(run_id)).state.is_terminal(), timeout=40)

    # TERMINAL IS NOT THE ASSERTION, and checking only that is how this passed
    # while broken: an uncaught TimeoutError FAILS the workflow, and a failed
    # workflow is terminal too. The property is that the loop polled and the
    # workflow COMPLETED, reporting the run's own outcome.
    kinds = _history_kinds(provider, _ex(run_id))
    assert kinds.get("EVENT_TYPE_WORKFLOW_EXECUTION_FAILED", 0) == 0, (
        f"the workflow failed rather than polling: {kinds}")
    assert kinds.get("EVENT_TYPE_WORKFLOW_EXECUTION_COMPLETED", 0) == 1, kinds
    assert kinds.get("EVENT_TYPE_WORKFLOW_TASK_FAILED", 0) == 0, kinds
    assert provider.describe(_ex(run_id)).state is models.WorkflowState.SUCCEEDED, (
        "the workflow did not report the run's outcome")


def test_a_signal_with_no_payload_can_be_rung_through_the_interface(
        env, provider, worker):
    """`WorkflowSignal.payload` defaults to `{}`, which is falsy -- so
    `payload or None` passed an explicit None ARGUMENT, and the SDK delivers one
    value per payload whatever the handler's signature. Every handler here takes
    no parameters, so the doorbell could not be rung through the provider
    interface at all."""
    worker.start()
    _agent, run_id, wf = _admitted(env)
    _start(provider, wf, run_id)
    _announce_started(run_id)

    provider.signal(_ex(run_id), models.WorkflowSignal(name="halt"))

    assert _wait(lambda: provider.describe(_ex(run_id)).state.is_terminal(), timeout=40), (
        "the signal did not reach the workflow")
    assert _history_kinds(provider, _ex(run_id)).get(
        "EVENT_TYPE_WORKFLOW_TASK_FAILED", 0) == 0


def test_a_refused_update_leaves_the_schedule_alone(env, provider, schedule_id):
    """A REFUSAL MUST COST NOTHING. Validating inside `create_schedule` meant an
    update carrying an unsupported overlap deleted the existing schedule and
    then refused -- the agent's cron stopped firing and nothing was put back."""
    provider.create_schedule(_spec(schedule_id))

    with pytest.raises(errors.ProviderCapabilityMissing):
        provider.update_schedule(_spec(schedule_id, on_overlap="buffer_all"))

    client = provider._conn.client()
    desc = provider._conn.run(client.get_schedule_handle(schedule_id).describe())
    assert desc is not None, "a refused update destroyed the schedule"


# --- the history bound -------------------------------------------------------

def _kinds_of_execution(provider, workflow_id, run_id):
    """History of ONE execution, named by run id.

    `_history_kinds` asks for the workflow id alone, which resolves to the
    LATEST execution -- and a handoff is recorded in the one it left, so
    looking there finds nothing however well the handoff worked.
    """
    from temporalio.api.enums.v1 import EventType

    client = provider._conn.client()

    async def collect():
        h = client.get_workflow_handle(workflow_id, run_id=run_id)
        kinds = {}
        async for e in h.fetch_history_events():
            n = EventType.Name(e.event_type)
            kinds[n] = kinds.get(n, 0) + 1
        return kinds

    return provider._conn.run(collect())


def _continued_as_new_input(provider, workflow_id, run_id):
    """The arguments the first execution handed to its continuation.

    Read from the FIRST execution deliberately: a handle with no run id follows
    the chain to the latest one, which is not where the handoff was recorded.
    """
    from temporalio.api.enums.v1 import EventType

    # RESOLVED OFF THE LOOP. `_conn.client()` blocks on the private loop to
    # connect, so calling it from inside a coroutine already running there
    # deadlocks until the RPC bound expires. It only appears to work once the
    # client is cached, which makes it a trap rather than an error.
    client = provider._conn.client()

    async def collect():
        h = client.get_workflow_handle(workflow_id, run_id=run_id)
        async for e in h.fetch_history_events():
            if (e.event_type
                    == EventType.EVENT_TYPE_WORKFLOW_EXECUTION_CONTINUED_AS_NEW):
                attrs = e.workflow_execution_continued_as_new_event_attributes
                return await client.data_converter.decode(list(attrs.input.payloads))
        return None

    return provider._conn.run(collect())


def test_a_long_run_hands_off_rather_than_filling_its_own_history(
        env, provider, worker):
    """HISTORY IS DURABLE AND ONLY GROWS, and this platform is for long-lived
    agents.

    Every poll writes an activity's three events, a timer's two, and the
    workflow tasks that drive them. Temporal warns around 10,240 events and
    REFUSES around 51,200, so an unbounded loop at a five-second poll has a
    lifetime measured in hours -- a run whose observation dies after an
    afternoon is not a limit, it is the product failing.

    ## Why the bound is an argument and not a constant

    The bound is recorded in the history it bounds, so a replay sees the number
    the run was actually started with. Read from the environment instead, a
    worker started with a different setting would replay someone else's run
    against a number that run never used.

    THE ACCOUNT THIS DOCSTRING USED TO GIVE WAS WRONG, and it is corrected
    rather than quietly removed because the mistake is the useful part. It said
    an earlier monkeypatching version of this test was "MEASURED to be wrong"
    because "the sandbox re-imports the workflow's own module". The sandbox did
    no such thing -- `andyur` was passed through wholesale, so the module was
    the host's own object, and a later adversarial review proved it by running
    `time.time()` inside an `andyur` workflow and getting a value back. That
    test was failing for a different reason, found only afterwards: it read the
    LATEST execution's history, and a handoff is recorded in the execution it
    left. A real symptom was explained with a false mechanism, and the false
    mechanism was then written down as a finding.
    """
    from andyur.orchestration.temporal.workflows import AndyurRun

    worker.start()
    _agent, run_id, wf = _admitted(env)
    client = provider._conn.client()          # off the loop; see above

    async def start_with_a_small_bound():
        return await client.start_workflow(
            AndyurRun.run, args=[run_id, False, 2],
            id=wf, task_queue=provider._config.task_queue)

    handle = provider._conn.run(start_with_a_small_bound())
    first_execution = handle.first_execution_run_id
    _announce_started(run_id)

    assert _wait(lambda: _kinds_of_execution(provider, wf, first_execution).get(
        "EVENT_TYPE_WORKFLOW_EXECUTION_CONTINUED_AS_NEW", 0) == 1, timeout=60), (
        "the run never handed off; its history grows without bound")

    # STILL OBSERVING, which is the point of handing off rather than stopping.
    assert not provider.describe(wf).state.is_terminal()

    # THE HANDOFF'S ARGUMENTS. A continuation is a NEW execution with a new
    # instance, so `_halted` starts False again unless it is passed: a halt
    # signalled during the observation activity -- after the check at the top
    # of the loop, before the handoff -- would otherwise be dropped, and the
    # record of it with it. The bound rides along for the same reason, or the
    # continuation would quietly observe under a different one.
    carried = _continued_as_new_input(provider, wf, first_execution)
    assert carried == [run_id, False, 2], (
        f"the handoff carried {carried!r}; it must carry the run id, the halt "
        "flag and the bound it was started with")

    coordinator.finish_run(run_id, "done", None)
    assert _wait(lambda: provider.describe(wf).state.is_terminal(), timeout=60)
    assert provider.describe(wf).state is models.WorkflowState.SUCCEEDED, (
        "the continuation did not report the run's outcome")
    assert _history_kinds(provider, wf).get("EVENT_TYPE_WORKFLOW_TASK_FAILED", 0) == 0


def test_a_continuation_told_it_was_halted_does_not_forget(
        env, provider, worker):
    """The other half of the wiring: the argument is HONOURED, not just sent.

    Started the way a continuation is started, with the flag already set. It
    must note the halt and stop, rather than poll on as though nothing had
    happened.
    """
    from andyur.orchestration.temporal.workflows import AndyurRun

    worker.start()
    _agent, run_id, wf = _admitted(env)

    client = provider._conn.client()          # off the loop; see above

    async def start_as_a_continuation_would():
        return await client.start_workflow(
            AndyurRun.run, args=[run_id, True],
            id=f"{wf}-as-continuation", task_queue=provider._config.task_queue)

    h = provider._conn.run(start_as_a_continuation_would())

    # BOUNDED, AND THE BOUND IS THE ASSERTION. Waiting on the result directly
    # means a continuation that ignored the flag polls on until the RPC bound
    # expires, and the test then reports that the service did not answer --
    # true, useless, and about the wrong thing.
    wf_as_continuation = f"{wf}-as-continuation"
    assert _wait(lambda: provider.describe(wf_as_continuation).state.is_terminal(),
                 timeout=30), (
        "a continuation told it was halted kept polling instead of stopping")

    assert provider._conn.run(h.result()) == "halted"




def test_a_halt_delivered_with_the_start_is_not_lost(env, provider, worker):
    """THE KILL SWITCH PRESSED THE MOMENT A RUN BEGINS.

    The SDK applies a first task's signals before `run` starts, and `run`
    reset the halt flag from its argument, so a halt that arrived with the
    start was silently dropped and the workflow polled on. It surfaced only on
    a 2-CPU CI runner, where the signal usually lands before the first task.
    Signal-with-start puts the halt in the first task EVERY time, so this is
    deterministic on any machine.
    """
    from andyur.orchestration.temporal.provider import HALT_SIGNAL
    from andyur.orchestration.temporal.workflows import AndyurRun

    worker.start()
    _agent, run_id, wf = _admitted(env)
    client = provider._conn.client()          # off the loop; see above
    wf_id = f"{wf}-halted-at-start"

    async def start_with_the_halt():
        return await client.start_workflow(
            AndyurRun.run, args=[run_id], id=wf_id,
            task_queue=provider._config.task_queue, start_signal=HALT_SIGNAL)

    h = provider._conn.run(start_with_the_halt())
    assert _wait(lambda: provider.describe(wf_id).state.is_terminal(), timeout=30), (
        "a halt delivered with the start was lost: the workflow kept polling")
    assert provider._conn.run(h.result()) == "halted"


def test_a_missing_namespace_is_not_healthy():
    """A misspelled or unregistered namespace used to report HEALTHY.

    `GetSystemInfo` is not scoped to a namespace, and the service answers a
    missing namespace with NOT_FOUND -- the code halt reads as "no such
    workflow, so already halted". Probed: every halt returned "accepted,
    HALTED" against an engine that had never heard of the workflow, with health
    green throughout. Starts failed loudly; the kill switch did not.
    """
    bad = TemporalWorkflowProvider(TemporalConfig(
        address=ADDRESS, namespace=f"no-such-ns-{uuid.uuid4().hex[:6]}",
        rpc_timeout_seconds=10))
    try:
        health = bad.health()
    finally:
        bad._conn.close()

    assert health.reachable is False, (
        "a namespace the service does not have was reported healthy, so a "
        "misconfigured kill switch would look fine")
    assert "namespace" in health.detail, (
        f"unhealthy for an unstated reason: {health.detail!r}")


def test_positive_control_a_real_namespace_is_healthy():
    """Without this, a health check that reports everything unhealthy passes
    the test above."""
    good = TemporalWorkflowProvider(TemporalConfig(
        address=ADDRESS, namespace="default", rpc_timeout_seconds=10))
    try:
        assert good.health().reachable is True
    finally:
        good._conn.close()


# --- one execution per run ---------------------------------------------------

def _state_of(provider, execution):
    """The execution's state, or None if the engine has no such execution."""
    try:
        return provider.describe(execution).state
    except errors.WorkflowNotFound:
        return None


def test_a_delegated_run_is_observed_by_its_own_execution(env, provider, worker):
    """ONLY THE FIRST RUN IN A WORKFLOW WAS EVER OBSERVED.

    Executions were keyed by Andyur's WORKFLOW id, and a workflow holds many
    runs -- every delegated task or message joins its parent's. A second run's
    start got the first run's execution back, so it had no durable observation
    and nothing a halt signal could reach, while the provider reported it
    started. Three reviewers found it independently; a live probe confirmed it.

    Proved through the real delegation path, and by the property that
    distinguishes it: finishing ONLY the child must complete the child's
    execution while the root's keeps running. With one execution per workflow
    there is no child execution to complete.
    """
    from andyur.orchestration.facade import OrchestrationFacade

    worker.start()
    facade = OrchestrationFacade(provider)
    alice, bob = env.agent("alice"), env.agent("bob")

    root, _ = facade.request_agent_run(alice, "root")
    child, _ = facade.request_agent_run(bob, "child", parent_run_id=root)
    assert child, "the delegated run was not admitted"
    with db.connect() as c:
        wf_root, wf_child = (c.execute("SELECT workflow_id FROM runs WHERE id = ?",
                                       (r,)).fetchone()["workflow_id"]
                             for r in (root, child))
    assert wf_root == wf_child, "the child did not join its parent's workflow"

    _announce_started(root)
    _announce_started(child)
    assert _wait(lambda: _state_of(provider, _ex(child))
                 is models.WorkflowState.RUNNING), (
        "a run that joined an existing workflow has no execution of its own -- "
        "it is not observed, and a halt signal has nothing to reach")
    assert _state_of(provider, _ex(root)) is models.WorkflowState.RUNNING

    coordinator.finish_run(child, "done", None)

    assert _wait(lambda: _state_of(provider, _ex(child))
                 is models.WorkflowState.SUCCEEDED, timeout=40), (
        "finishing the child did not complete the child's execution, so that "
        "execution is not observing the child")
    assert _state_of(provider, _ex(root)) is models.WorkflowState.RUNNING, (
        "finishing the child stopped the ROOT's execution too -- they are one")


def test_halting_a_workflow_reaches_every_live_run(env, provider, worker):
    """With one execution per run, a halt must signal each of them -- named by
    Andyur's record, not discovered from the engine's eventually consistent
    listing, which could miss a run that started a moment ago."""
    from andyur.orchestration.facade import OrchestrationFacade

    worker.start()
    facade = OrchestrationFacade(provider)
    alice, bob = env.agent("alice"), env.agent("bob")
    root, _ = facade.request_agent_run(alice, "root")
    child, _ = facade.request_agent_run(bob, "child", parent_run_id=root)
    with db.connect() as c:
        wf = c.execute("SELECT workflow_id FROM runs WHERE id = ?",
                       (root,)).fetchone()["workflow_id"]
    _announce_started(root)
    _announce_started(child)
    for r in (root, child):
        assert _wait(lambda r=r: _state_of(provider, _ex(r))
                     is models.WorkflowState.RUNNING)

    outcome = facade.halt_workflow(wf)

    assert outcome.accepted
    for r, name in ((root, "root"), (child, "child")):
        assert _wait(lambda r=r: (_state_of(provider, _ex(r)) or
                                  models.WorkflowState.RUNNING).is_terminal(),
                     timeout=40), (
            f"the halt did not reach the {name} run's execution")


def test_a_rotated_client_can_be_swapped_into_a_real_running_worker():
    """THE ROTATION PATH, against the real SDK and a real service. The worker
    hands a freshly connected client to the running Worker instead of
    rebuilding it; the SDK checks the two clients share a runtime, and a
    client connected without naming one was refused -- live, on the first
    rotation, while every fake-client test passed."""
    import asyncio

    from andyur.orchestration.temporal import worker as worker_mod
    from andyur.orchestration.temporal.client import TemporalConnection

    config = TemporalConfig(address=ADDRESS, task_queue=f"swap-{uuid.uuid4().hex[:8]}",
                            rpc_timeout_seconds=15)
    settings = TemporalConnection(config)

    async def main():
        first = await worker_mod._connect(settings, config)
        worker = worker_mod.build_worker(first, config)
        running = asyncio.create_task(worker.run())
        try:
            await asyncio.sleep(1)
            assert not running.done(), f"the worker stopped: {running.exception()}"
            second = await worker_mod._connect(settings, config)
            worker.client = second                      # what a rotation does
            assert worker.client is second
            await asyncio.sleep(1)
            assert not running.done(), "the worker stopped after the client swap"
        finally:
            await worker.shutdown()
            running.cancel()

    asyncio.run(main())


def test_architecture_a_the_native_assignment_loop_is_what_dispatches(env, provider, worker):
    """CHARACTERIZATION, pinned before Architecture B+ changes it.

    Under Architecture A the engine OBSERVES a run and the native loop
    DISPATCHES it: with the durable provider selected and its workflow making
    progress, the run stays `pending` and unassigned until `assign_runs()`
    hands it to a worker. B+ moves dispatch into the engine; when it does, this
    test is the one that has to change, on purpose and in the same commit that
    changes the dispatcher -- not a behaviour that shifts without a trace.
    """
    worker.start()
    _agent, run_id, wf = _admitted(env)
    _start(provider, wf, run_id)
    assert _wait(lambda: _activity_completions(provider, _ex(run_id)) > 0), (
        "the workflow made no progress")

    with db.connect() as c:
        row = c.execute("SELECT state, worker FROM runs WHERE id = ?",
                        (run_id,)).fetchone()
    assert (row["state"], row["worker"]) == ("pending", None), (
        "the engine dispatched the run itself; Architecture A leaves that to "
        f"the native assignment loop (state={row['state']!r}, worker={row['worker']!r})")

    assigned = coordinator.assign_runs("characterization-worker", 1)
    assert [a["id"] for a in assigned] == [run_id], (
        "the native assignment loop did not hand out the run the engine is observing")

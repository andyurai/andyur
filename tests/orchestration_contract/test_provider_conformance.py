"""The provider contract, run against every provider.

The modules beside this one assert Andyur's orchestration semantics, which hold
whoever is running the work -- admission, the drain, the caps, the reaper. None
of that is a provider's to implement, so none of it is here.

THIS module is the other half: the part of the contract a provider actually
answers for. Every test below runs unchanged against each provider, which is the
only way the interface means anything. An SPI nobody has run two implementations
against is a guess.

Two providers today: the native engine wrapped as `local`, and a test double
with no engine at all. The double is not a reference implementation -- it proves
the contract is satisfiable without an engine, which is a weaker claim than it
looks and is why the Stage 2 spike was run against a real durable engine before
the interface was fixed.

## What is deliberately NOT asserted here

`local` refuses to start a workflow whose run was never admitted, because it can
see Andyur's own tables and a provider must not create work. A durable engine
cannot check that -- it has no view of the runs table -- so requiring it would
be requiring something unimplementable. It is pinned in the local-specific tests
instead. Telling those two apart is most of the value of writing a conformance
suite at all.
"""

import uuid

import pytest

from andyur.orchestration import errors, models
from andyur.orchestration.local import LocalWorkflowProvider
from andyur.server import coordinator

from .fakes import FakeProvider


class _Local:
    """The native engine, plus the admission it requires before a start."""

    name = "local"

    def __init__(self, env):
        self._env = env
        self._n = 0

    def make(self):
        self._n += 1
        agent = self._env.agent(f"agent{self._n}")
        run = coordinator.maybe_wakeup(agent, "conformance")
        from andyur import db
        with db.connect() as c:
            workflow = c.execute(
                "SELECT workflow_id FROM runs WHERE id = ?", (run,)
            ).fetchone()["workflow_id"]
        return workflow, run

    def an_agent(self):
        """An agent that exists. The schedules table has a foreign key to
        `agents`, so a name alone is not enough on this provider."""
        self._n += 1
        return self._env.agent(f"sched{self._n}")

    def live_schedules(self, agent):
        from andyur.server import schedules as svc
        return len(svc.list_schedules(agent))

    def schedule_is_paused(self, schedule_id):
        from andyur import db
        with db.connect() as c:
            row = c.execute("SELECT enabled FROM schedules WHERE id = ?",
                            (schedule_id,)).fetchone()
        return row is not None and not row["enabled"]

    @property
    def provider(self):
        return LocalWorkflowProvider()


class _Fake:
    """No engine at all. Admission is not its business, so `make` only invents
    the identifiers Andyur would have produced."""

    name = "fake"

    def __init__(self, env):
        self._provider = FakeProvider(schedules=True)

    def make(self):
        return f"wf-{uuid.uuid4().hex[:8]}", f"run-{uuid.uuid4().hex[:8]}"

    def an_agent(self):
        return "any-name"

    def live_schedules(self, agent):
        return len(self._provider._schedules)

    def schedule_is_paused(self, schedule_id):
        return self._provider._schedules[schedule_id].paused

    @property
    def provider(self):
        return self._provider


class _Temporal:
    """The durable engine, against a live service. The ONLY durable provider,
    and until an adversarial review it was the one this suite never ran.

    The module docstring says these bodies run "against every provider", and
    the fixture listed two: the native engine and a fake. A suite that asks
    nothing of the one provider whose behaviour differs most proves nothing
    about it -- and the Temporal provider shipped with only a partial
    restatement of these properties in the campaign, weaker in exactly the
    places mutation had already shown mattered.

    Needs a service at ANDYUR_TEMPORAL_ADDRESS (default localhost:7233) and is
    marked `integration`, so the fast suite deselects it.
    """

    name = "temporal"

    @property
    def halt_bound_seconds(self) -> float:
        """How long this provider may legitimately take to stop reporting a
        halted workflow as running -- DERIVED from its mechanism, not guessed.

        The halt signal is acted on at the top of the observation loop, so the
        worst case is an `observe_state` call already in flight (bounded by
        CALL_TIMEOUT), then `note_halt` (CALL_TIMEOUT again), plus one POLL
        and a margin for task scheduling on a contended runner. The fixed 30 s
        this test used was shorter than the first term alone. (The CI failures
        that prompted this were NOT that: a halt delivered with the start was
        being dropped by the workflow -- see
        `test_a_halt_delivered_with_the_start_is_not_lost`.)
        """
        from andyur.orchestration.temporal.workflows import CALL_TIMEOUT, POLL
        return (2 * CALL_TIMEOUT + POLL).total_seconds() + 30

    def __init__(self, env):
        import os
        import socket

        address = os.environ.get("ANDYUR_TEMPORAL_ADDRESS", "localhost:7233")
        host, _, port = address.partition(":")
        try:
            socket.create_connection((host, int(port or 7233)), timeout=1).close()
        except OSError:
            if os.environ.get("ANDYUR_REQUIRE_TEMPORAL") == "1":
                raise RuntimeError(
                    f"ANDYUR_REQUIRE_TEMPORAL=1 and no Temporal service at {address}")
            pytest.skip(f"no Temporal service at {address}")

        from andyur.orchestration.temporal import TemporalConfig, TemporalWorkflowProvider

        self._env = env
        self._n = 0
        self._queue = f"conformance-{uuid.uuid4().hex[:8]}"
        self._config = TemporalConfig(address=address, task_queue=self._queue,
                                      rpc_timeout_seconds=15)
        self._provider = TemporalWorkflowProvider(self._config)
        self._schedules = []
        # EVERY SCHEDULE THE PROVIDER CREATES IS TRACKED, by wrapping the
        # provider rather than asking each test to remember. Nothing called
        # `track_schedule`, so `live_schedules` counted an empty list -- the
        # update test could not fail against this engine -- and teardown
        # deleted nothing, leaving every schedule these tests made running on
        # the service.
        create = self._provider.create_schedule

        def create_and_track(spec):
            handle = create(spec)
            self.track_schedule(spec.schedule_id)
            return handle

        self._provider.create_schedule = create_and_track
        self._worker = _TemporalWorker(address, self._queue).start()

    def make(self):
        """A real admitted run: the workflow observes the run's state, so an
        invented id would be observed as absent and complete at once."""
        self._n += 1
        agent = self._env.agent(f"tagent{self._n}")
        run = coordinator.maybe_wakeup(agent, "conformance")
        from andyur import db
        with db.connect() as c:
            workflow = c.execute(
                "SELECT workflow_id FROM runs WHERE id = ?", (run,)
            ).fetchone()["workflow_id"]
        return workflow, run

    def an_agent(self):
        self._n += 1
        return self._env.agent(f"tsched{self._n}")

    # EVERY `client()` BELOW IS RESOLVED OFF THE LOOP, before the coroutine. It
    # blocks on the connection's private loop to connect, so calling it from a
    # coroutine already running on that loop deadlocks until the RPC bound.
    # The first version of this class did exactly that in teardown and five
    # tests errored -- the ones that never used the provider, so nothing had
    # cached the client first.

    def _schedule_ids_for(self, agent):
        client = self._provider._conn.client()

        async def collect():
            return [entry.id async for entry in await client.list_schedules()]

        ids = self._provider._conn.run(collect())
        return [i for i in ids if i in self._schedules]

    def live_schedules(self, agent):
        return len(self._schedule_ids_for(agent))

    def schedule_is_paused(self, schedule_id):
        client = self._provider._conn.client()

        async def paused():
            desc = await client.get_schedule_handle(schedule_id).describe()
            return desc.schedule.state.paused

        return self._provider._conn.run(paused())

    def track_schedule(self, schedule_id):
        if schedule_id not in self._schedules:
            self._schedules.append(schedule_id)

    @property
    def provider(self):
        return self._provider

    def close(self):
        try:
            if self._schedules:                   # nothing to clean -> no connect
                client = self._provider._conn.client()

                async def drop():
                    for sid in self._schedules:
                        try:
                            await client.get_schedule_handle(sid).delete()
                        except Exception:          # noqa: BLE001 - cleanup
                            pass

                self._provider._conn.run(drop())
        finally:
            self._worker.kill()
            self._provider._conn.close()


class _TemporalWorker:
    """The SHIPPED worker in a thread, so a harness does not prove things about
    a worker configuration that does not run in production."""

    def __init__(self, address, queue):
        self.address, self.queue = address, queue
        self._loop = self._stop = self._thread = None

    def start(self):
        import asyncio
        import threading

        ready = threading.Event()

        def run():
            from temporalio.client import Client

            from andyur.orchestration.temporal.config import TemporalConfig as Cfg
            from andyur.orchestration.temporal.worker import build_worker

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop, self._stop = loop, asyncio.Event()

            async def serve():
                client = await Client.connect(self.address)
                async with build_worker(client, Cfg(address=self.address,
                                                    task_queue=self.queue)):
                    ready.set()
                    await self._stop.wait()

            loop.run_until_complete(serve())

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(30), "the conformance worker never became ready"
        return self

    def kill(self):
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(timeout=20)


@pytest.fixture(params=[
    _Local, _Fake,
    pytest.param(_Temporal, marks=pytest.mark.integration),
], ids=["local", "fake", "temporal"])
def subject(request, env):
    made = request.param(env)
    yield made
    if hasattr(made, "close"):
        made.close()


def _start(workflow_id, root_run_id, kind="single_agent"):
    return models.WorkflowStart(
        workflow_id=workflow_id, root_run_id=root_run_id, workflow_kind=kind)


# --- identity and capabilities ----------------------------------------------

def test_a_provider_has_a_stable_name(subject):
    """The name is stored against work and shown to operators, so it does not
    change between calls."""
    p = subject.provider

    assert p.name
    assert p.name == p.name
    assert p.name == subject.provider.name, "the name changed between instances"


def test_every_provider_offers_the_mandatory_guarantees(subject):
    """`halt`, `at_most_once` and `replay_safe` are preconditions of being a
    provider. They are asserted here rather than trusted from what a provider
    advertises, because advertising them proves nothing."""
    from andyur.orchestration import capabilities

    assert capabilities.MANDATORY <= subject.provider.capabilities().offered()


def test_capabilities_name_the_provider_they_describe(subject):
    p = subject.provider
    assert p.capabilities().provider == p.name


def test_health_reports_rather_than_raising(subject):
    """A provider that is unwell must say so, so the control plane can refuse
    new durable work while still serving reads of Andyur's own record."""
    health = subject.provider.health()

    assert isinstance(health, models.ProviderHealth)
    assert health.provider == subject.provider.name
    assert isinstance(health.reachable, bool)


# --- starting ---------------------------------------------------------------

def test_the_handle_a_start_returns_addresses_the_execution_it_started(subject):
    """The id on the handle is the one that reaches the execution.

    RENAMED AND NARROWED, deliberately, and the reason is not convenience. This
    asserted `handle.workflow_id == workflow` -- that the handle carries
    Andyur's WORKFLOW id. That held while every provider had one execution per
    workflow. The durable provider now runs one execution per RUN, because a
    workflow holds many runs and keying by the workflow left every run after
    the first unobserved; for such a provider there is no single execution
    called "the workflow", and the old assertion demanded one.

    What every provider still owes, and what this asserts, is that the handle
    is usable: describing the id it returned finds that execution and names
    this provider. That is the property callers actually rely on.
    """
    workflow, run = subject.make()

    handle = subject.provider.start(_start(workflow, run))

    assert handle.provider == subject.provider.name
    described = subject.provider.describe(handle.workflow_id)
    assert described.workflow_id == handle.workflow_id
    assert described.provider == subject.provider.name


def test_starting_the_same_workflow_twice_is_one_execution(subject):
    """THE PROPERTY THAT MAKES AN AT-LEAST-ONCE CALLER SAFE. The Stage 2 spike
    measured its absence: a step whose effect landed before its acknowledgement
    was lost ran three times under a three-attempt retry, which for a launch
    would be three containers for one admitted run."""
    p = subject.provider
    workflow, run = subject.make()
    request = _start(workflow, run)

    first = p.start(request)
    second = p.start(request)

    # THE WHOLE HANDLE, not just the workflow id. Comparing only the id passed
    # a provider that started a second execution and handed back a different
    # reference to it -- found by mutation, because the weaker assertion looked
    # entirely reasonable until something violated the contract and it did not
    # notice.
    assert first == second, (
        f"{p.name} produced two executions for one workflow id: "
        f"{first.provider_ref!r} then {second.provider_ref!r}")


# --- halting ----------------------------------------------------------------

def test_halting_is_accepted_and_reports_a_terminal_state(subject):
    p = subject.provider
    workflow, run = subject.make()
    p.start(_start(workflow, run))

    outcome = p.halt(models.HaltRequest(workflow_id=workflow, reason="operator"))

    assert outcome.accepted is True
    # HALTED **or** HALTING. Requiring HALTED would force a provider that needs
    # a moment to wind down to claim it had already finished, and the honest
    # answer to "have you stopped yet" is sometimes "I am stopping".
    assert outcome.state in {models.WorkflowState.HALTED,
                             models.WorkflowState.HALTING}


def test_halting_twice_is_not_an_error(subject):
    """An operator pulling the kill switch twice, or a retry delivering it
    twice, must not produce a failure that looks like the halt not working."""
    p = subject.provider
    workflow, run = subject.make()
    p.start(_start(workflow, run))
    request = models.HaltRequest(workflow_id=workflow, reason="operator")

    p.halt(request)
    again = p.halt(request)

    assert again.accepted is True


def test_halting_never_reports_a_workflow_as_progressing(subject):
    """What a provider must NOT say after being halted.

    Whether `describe` reports HALTED is NOT a provider-level guarantee and was
    asserted as one here in the first draft. Andyur's governance record is what
    makes a workflow halted, and the facade writes it -- a provider that reads
    Andyur's state (as the native one does) can only report what it was told.

    What every provider owes is narrower and still worth pinning: having
    accepted a halt, it must not go on claiming the workflow is running.
    `test_orchestration_facade.py` covers the platform-level property, which is
    the one an operator actually cares about.
    """
    p = subject.provider
    workflow, run = subject.make()
    handle = p.start(_start(workflow, run))
    # THE LIVE RUNS ARE NAMED, as the facade names them from Andyur's record.
    # Run against the durable provider for the first time, this halted with no
    # runs named -- and correctly signalled nothing, so the execution kept
    # running and the assertion failed. A halt that names nothing reaches
    # nothing; what the provider owes is that the runs it IS told about stop.
    p.halt(models.HaltRequest(workflow_id=workflow, reason="operator",
                              run_ids=(run,)))

    import time
    deadline = time.monotonic() + getattr(subject, "halt_bound_seconds", 30)
    while (p.describe(handle.workflow_id).state is models.WorkflowState.RUNNING
           and time.monotonic() < deadline):
        time.sleep(0.3)
    assert p.describe(handle.workflow_id).state is not models.WorkflowState.RUNNING


def test_halting_a_workflow_the_provider_never_had_is_still_accepted(subject):
    """THIS ASSERTED THE OPPOSITE IN ITS FIRST DRAFT, and both the contract and
    the provider were wrong together -- written in one sitting, agreeing with
    each other, disagreeing with the platform.

    `POST /workflows/{id}/halt` answers 200 for an id with no rows, and tests
    pin it. That is deliberate: `coordinator.halt_workflow` inserts the row
    already halted, so work that later tries to join that workflow is refused.
    Halting AHEAD of the work is a real operator action.

    A provider refusing here would break the kill switch precisely when an
    operator is racing a workflow that is starting. There is no durable progress
    to stop, so the request is already satisfied.

    Contrast `describe`, which DOES refuse an unknown workflow -- inventing a
    state for a read is the harm there, and the asymmetry is the point.
    """
    outcome = subject.provider.halt(
        models.HaltRequest(workflow_id="wf-never-existed", reason="operator"))

    assert outcome.accepted is True


# --- describing -------------------------------------------------------------

def test_describe_returns_a_normalized_state(subject):
    """The provider's vocabulary does not escape. Whatever the engine calls
    this, it arrives as one of Andyur's states."""
    p = subject.provider
    workflow, run = subject.make()
    handle = p.start(_start(workflow, run))

    described = p.describe(handle.workflow_id)

    assert isinstance(described.state, models.WorkflowState)
    assert described.workflow_id == handle.workflow_id
    assert described.provider == p.name


def test_describing_an_unknown_workflow_is_not_found(subject):
    """Rather than inventing a terminal state. A provider that has forgotten a
    workflow -- retention expired, history dropped -- must say it does not know,
    because a fabricated terminal state would free an agent whose work may still
    be running."""
    with pytest.raises(errors.WorkflowNotFound):
        subject.provider.describe("wf-never-existed")


# --- schedules --------------------------------------------------------------

def test_a_provider_offering_schedules_creates_one(subject):
    p = subject.provider
    if not p.capabilities().schedules:
        pytest.skip(f"{p.name} does not offer schedules")
    spec = models.ScheduleSpec(
        schedule_id=f"s-{uuid.uuid4().hex[:6]}", agent=subject.an_agent(),
        cron="0 3 * * *", reason="nightly")

    handle = p.create_schedule(spec)

    assert handle.provider == p.name


def test_deleting_an_absent_schedule_is_not_an_error(subject):
    """Idempotent, because the caller's intent -- that it must not fire -- is
    already satisfied by its absence."""
    p = subject.provider
    if not p.capabilities().schedules:
        pytest.skip(f"{p.name} does not offer schedules")

    p.delete_schedule("s-never-existed")


def test_an_overlap_rule_the_provider_does_not_implement_is_refused(
        subject):
    """REFUSED, NOT SUBSTITUTED. Andyur's rule is skip-and-retry-soon: a tick
    finding its agent busy is retried shortly, never buffered. A provider whose
    scheduler buffers must say so -- quietly giving the caller the behaviour it
    has instead of the one asked for is how a backlog appears where someone
    expected a drop."""
    p = subject.provider
    if not p.capabilities().schedules:
        pytest.skip(f"{p.name} does not offer schedules")
    spec = models.ScheduleSpec(
        schedule_id=f"s-{uuid.uuid4().hex[:6]}", agent="agent1",
        cron="0 3 * * *", reason="nightly", on_overlap="buffer_all")

    with pytest.raises(errors.ProviderCapabilityMissing):
        p.create_schedule(spec)


def test_a_schedule_keeps_the_id_it_was_created_with(subject):
    """THE HANDLE MUST NAME WHAT THE CALLER ASKED FOR. The first draft asserted
    only `handle.provider`, which is exactly the assertion that cannot catch a
    provider minting its own id and handing back something else -- and one of
    them did."""
    p = subject.provider
    if not p.capabilities().schedules:
        pytest.skip(f"{p.name} does not offer schedules")
    spec = models.ScheduleSpec(
        schedule_id=f"s-{uuid.uuid4().hex[:6]}", agent=subject.an_agent(),
        cron="0 3 * * *", reason="nightly")

    handle = p.create_schedule(spec)

    assert handle.schedule_id == spec.schedule_id


def test_updating_a_schedule_replaces_it_rather_than_adding_another(subject):
    """THE BUG THIS ENCODES: update was delete-then-create under a FRESH id, so
    the delete matched nothing the second time and each update left another live
    schedule behind. After N updates the agent fired N+1 times per tick, and no
    id could stop any of them.

    Counted through the provider's own surface, so it holds for any engine.
    """
    p = subject.provider
    if not p.capabilities().schedules:
        pytest.skip(f"{p.name} does not offer schedules")
    sid = f"s-{uuid.uuid4().hex[:6]}"
    agent = subject.an_agent()

    def spec(cron):
        return models.ScheduleSpec(schedule_id=sid, agent=agent,
                                   cron=cron, reason="nightly")

    p.create_schedule(spec("0 3 * * *"))
    p.update_schedule(spec("0 4 * * *"))
    p.update_schedule(spec("0 5 * * *"))

    p.delete_schedule(sid)
    assert subject.live_schedules(agent) == 0, (
        "updating left extra schedules behind; deleting the id could not stop them")


def test_a_schedule_created_paused_does_not_fire(subject):
    """`paused` was silently dropped, so a spec created paused fired at its
    next slot -- the opposite of what the caller asked for."""
    p = subject.provider
    if not p.capabilities().schedules:
        pytest.skip(f"{p.name} does not offer schedules")
    sid = f"s-{uuid.uuid4().hex[:6]}"

    p.create_schedule(models.ScheduleSpec(
        schedule_id=sid, agent=subject.an_agent(), cron="* * * * *",
        reason="frequent", paused=True))

    assert subject.schedule_is_paused(sid) is True

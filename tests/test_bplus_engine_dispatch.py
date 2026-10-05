"""Architecture B+ against a REAL engine: an admitted run is dispatched by the
engine, executed by the execution worker, and never touched by the native
assignment loop (ADR-014 D11, Gate B locally).

What is real: the Temporal service, the shipped `AndyurExecution` workflow,
`execute_run` Activity and `build_execution_worker`, the facade and provider in
engine-dispatch mode, and the control plane itself -- in-process, over its ASGI
app, authenticated as the execution worker. What stands in: the Kubernetes
launcher, as an in-memory fence with the same create-only semantics (the real
fence is proved against the live API server by infra/bplus-spike/gate_a.py).

The native loop is not merely unused here: `assign_runs` RAISES if anything
calls it, so a pass means the engine path does not depend on it at all.
"""

import os
import socket
import threading
import time
import uuid

import httpx
import pytest

from andyur import db, identity, orchestration
from andyur.orchestration.temporal import TemporalConfig
from andyur.orchestration.temporal.provider import TemporalWorkflowProvider
from andyur.server import coordinator
from conftest import svid_header

pytestmark = pytest.mark.integration

ADDRESS = os.environ.get("ANDYUR_TEMPORAL_ADDRESS", "localhost:7233")


def _up():
    host, _, port = ADDRESS.partition(":")
    try:
        with socket.create_connection((host, int(port or 7233)), timeout=1):
            return True
    except OSError:
        return False


if not _up():
    if os.environ.get("ANDYUR_REQUIRE_TEMPORAL") == "1":
        raise RuntimeError(f"ANDYUR_REQUIRE_TEMPORAL=1 and no Temporal service at {ADDRESS}")
    pytest.skip(f"no Temporal service at {ADDRESS}", allow_module_level=True)

EXEC = svid_header(f"spiffe://{identity.TRUST_DOMAIN}/temporal-execution-worker")


class _Runtime:
    def __init__(self):
        self.code = None

    def poll(self):
        return self.code


class FencedLauncher:
    """The daemon in execution mode, over an in-memory run fence: one runtime
    per run, create-only, held by the run's generation."""

    execution = True
    worker_id = "execution-test"

    def __init__(self):
        self.fence = {}          # run_id -> generation
        self.runtimes = {}       # run_id -> _Runtime
        self.procs = {}
        self.launched = []
        self.killed = []

    class _Orch:
        # Not "kubernetes": a Kubernetes claim requires a sealed registry
        # binding, which is refused for an unbound agent (covered in
        # test_bplus_dispatch.py) and exercised for real in the cluster gates.
        name = "synthetic"

        def __init__(self, outer):
            self.outer = outer

        def adopt_governed(self, run_id, generation, runtime):
            if self.outer.fence.get(run_id) != generation:
                raise RuntimeError("fence held by another generation")
            return self.outer.runtimes[run_id]

    @property
    def orch(self):
        return FencedLauncher._Orch(self)

    def launch(self, run_id, *args, generation=None):
        if run_id in self.fence:
            raise RuntimeError(f"Kubernetes run {run_id!r} is already owned")
        self.fence[run_id] = generation
        self.runtimes[run_id] = _Runtime()
        self.procs[run_id] = self.runtimes[run_id]
        self.launched.append((run_id, generation))

    def kill(self, run_ids):
        for r in run_ids:
            self.killed.append(r)
            if r in self.runtimes:
                self.runtimes[r].code = 137

    async def reap_one(self, api, run_id):
        proc = self.procs.get(run_id)
        if proc is None or proc.code is None:
            return None
        del self.procs[run_id]
        return proc.code


class ExecutionWorkerThread:
    def __init__(self, config, launcher):
        self.config, self.launcher = config, launcher
        self._loop = self._stop = self._thread = None

    def start(self):
        ready = threading.Event()

        def run():
            import asyncio

            from temporalio.client import Client

            from andyur.daemon.engine_executor import EngineExecutor
            from andyur.orchestration.temporal import execution
            from andyur.orchestration.temporal.execution_worker import (
                build_execution_worker)
            from andyur.server.app import app

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop, self._stop = loop, asyncio.Event()

            async def serve():
                api = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        base_url="http://cp", headers=EXEC)
                execution.bind(EngineExecutor(self.launcher, api, provider="temporal"))
                client = await Client.connect(ADDRESS)
                async with build_execution_worker(client, self.config):
                    ready.set()
                    await self._stop.wait()
                await api.aclose()

            loop.run_until_complete(serve())

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(30), "the execution worker never became ready"
        return self

    def stop(self):
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(timeout=30)


@pytest.fixture
def engine(env, monkeypatch):
    def forbidden(*_a, **_k):
        raise AssertionError("the native assignment loop was called for an engine run")
    monkeypatch.setattr(coordinator, "assign_runs", forbidden)
    from andyur.daemon.engine_executor import EngineExecutor
    monkeypatch.setattr(EngineExecutor, "POLL_SECONDS", 0.2)

    q = f"andyur-exec-{uuid.uuid4().hex[:8]}"
    config = TemporalConfig(address=ADDRESS, dispatch="engine", execution_queue=q,
                            task_queue=f"{q}-cp", rpc_timeout_seconds=15)
    provider = TemporalWorkflowProvider(config)
    facade = orchestration.OrchestrationFacade(provider=provider)
    launcher = FencedLauncher()
    worker = ExecutionWorkerThread(config, launcher).start()
    yield env, facade, provider, launcher
    worker.stop()
    provider._conn.close()


def _wait(pred, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.2)
    return False


def _row(run_id):
    with db.connect() as c:
        return dict(c.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone())


def _result(provider, run_id, timeout=40):
    from andyur.orchestration.temporal.provider import run_execution_id

    client = provider._conn.client()
    return provider._conn._loop.call(
        client.get_workflow_handle(run_execution_id(run_id)).result(), timeout)


def test_an_engine_run_executes_with_the_native_assignment_loop_absent(engine):
    """GATE B, LOCALLY. Admission marks the run for the engine; the engine
    dispatches `execute_run(run_id)`; the execution worker claims it from Andyur
    and launches it under the run's own generation; the run finishes and the
    execution completes -- and `assign_runs` was never called."""
    env, facade, provider, launcher = engine
    run_id, refusal = facade.request_agent_run(env.agent("alice"), "work")
    assert run_id and refusal is None
    assert _row(run_id)["dispatch"] == "engine"

    assert _wait(lambda: launcher.launched), "the engine never dispatched the run"
    assert launcher.launched == [(run_id, _row(run_id)["execution_generation"])], (
        "the launch did not run under the generation Andyur recorded for the run")

    # The run does its work and reports, as a real run would over its own SVID.
    assert coordinator.start_run(run_id)
    assert coordinator.finish_run(run_id, "did the work", None)
    launcher.runtimes[run_id].code = 0

    outcome = _result(provider, run_id)
    assert outcome["outcome"] == "exited" and outcome["how"] == "launched", outcome
    assert _row(run_id)["state"] == "done"


class _Crash(BaseException):
    """The server dying between the admission commit and the provider start:
    a BaseException, so the facade's compensation does not run -- exactly as
    it would not in a process that had died."""


def test_a_run_whose_start_was_lost_is_offered_again_and_executes_once(engine):
    """EVENTUAL DELIVERY (provider draft R6.6, F-18), against a real engine.
    The admission committed; the start never happened. Nothing re-offered the
    run: it held its agent until the 24 h queue backstop. The re-offer starts
    it -- once -- and the engine dispatches it like any other."""
    env, facade, provider, launcher = engine
    real_start = provider.start

    def crash(request):
        raise _Crash()
    provider.start = crash
    with pytest.raises(_Crash):
        facade.request_agent_run(env.agent("alice"), "work")
    provider.start = real_start
    [row] = coordinator.unacknowledged_engine_runs("temporal", "9999")
    run_id = row["id"]
    assert _row(run_id)["state"] == "pending" and not launcher.launched

    actions = facade.reoffer_unacknowledged(grace_seconds=0)
    assert len(actions) == 1 and run_id in actions[0]
    assert _wait(lambda: launcher.launched), "the re-offered run was never dispatched"
    assert launcher.launched == [(run_id, _row(run_id)["execution_generation"])]
    assert _row(run_id)["provider_acked_at"] is not None
    assert facade.reoffer_unacknowledged(grace_seconds=0) == [], "offered twice"


def test_halting_an_engine_run_destroys_its_runtime(engine):
    """The kill switch reaches an engine-dispatched run: governance first, then
    the engine's cancellation and the server's condemnation both converge on
    Andyur's containment, and the runtime is destroyed."""
    env, facade, provider, launcher = engine
    run_id, _ = facade.request_agent_run(env.agent("alice"), "work")
    assert _wait(lambda: launcher.launched), "the engine never dispatched the run"
    assert coordinator.start_run(run_id)

    facade.halt_workflow(_row(run_id)["workflow_id"])

    outcome = _result(provider, run_id)
    assert run_id in launcher.killed, "the halted run's runtime was not destroyed"
    assert outcome["outcome"] in {"killed", "halted"}, outcome
    assert launcher.runtimes[run_id].code == 137


def _halt_and_time(facade, run_id, launcher, bound):
    started = time.monotonic()
    try:
        facade.halt_workflow(_row(run_id)["workflow_id"])
    except orchestration.HaltNotAcknowledged:
        pass    # the engine did not hear it; Andyur's governance halt was written first
    destroyed = _wait(lambda: launcher.runtimes[run_id].code == 137, timeout=bound)
    return destroyed, time.monotonic() - started


def test_the_engines_cancellation_alone_destroys_a_halted_run(engine, monkeypatch):
    """HALF ONE of the dual path. With Andyur's condemnation poll silenced, the
    engine's cancellation of the execution must still destroy the runtime --
    and promptly. It did not inside 40 s until the worker's heartbeat throttle
    was capped: an Activity learns of its cancellation only when a heartbeat
    is actually sent, and the SDK throttled sends to 48 s."""
    from andyur.daemon.engine_executor import EngineExecutor

    async def silent(self, run_id):
        return {}
    monkeypatch.setattr(EngineExecutor, "_status", silent)
    env, facade, provider, launcher = engine
    run_id, _ = facade.request_agent_run(env.agent("alice"), "work")
    assert _wait(lambda: launcher.launched)
    assert coordinator.start_run(run_id)

    destroyed, took = _halt_and_time(facade, run_id, launcher, bound=15)

    assert destroyed, "the engine's cancellation alone did not destroy the halted run"
    assert took < 15


def test_andyurs_condemnation_alone_destroys_a_halted_run(engine, monkeypatch):
    """HALF TWO, and the one Gate C rests on: the engine never hears about the
    halt at all -- its signal is dropped -- and Andyur's own condemnation, polled
    by the executor from the control plane, still destroys the runtime."""
    env, facade, provider, launcher = engine
    def unheard(self, request):
        raise orchestration.HaltNotAcknowledged("the engine is unreachable")
    monkeypatch.setattr(type(provider), "halt", unheard)
    run_id, _ = facade.request_agent_run(env.agent("alice"), "work")
    assert _wait(lambda: launcher.launched)
    assert coordinator.start_run(run_id)

    destroyed, took = _halt_and_time(facade, run_id, launcher, bound=15)

    assert destroyed, "Andyur's condemnation alone did not destroy the halted run"
    assert took < 15


class ControlPlaneWorkerThread:
    """The control plane's own workflow worker (its queue, the shipped
    build_worker), which runs ScheduledAgentRun and its admission activity."""

    def __init__(self, config):
        self.config = config
        self._loop = self._stop = self._thread = None

    def start(self):
        ready = threading.Event()

        def run():
            import asyncio

            from temporalio.client import Client

            from andyur.orchestration.temporal.worker import build_worker

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop, self._stop = loop, asyncio.Event()

            async def serve():
                client = await Client.connect(ADDRESS)
                async with build_worker(client, self.config):
                    ready.set()
                    await self._stop.wait()

            loop.run_until_complete(serve())

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(30), "the control plane's worker never became ready"
        return self

    def stop(self):
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(timeout=30)


def test_an_engine_schedule_fires_through_the_engine_and_dispatches_through_it(engine, monkeypatch):
    """STEP 12. The schedule is a Temporal Schedule under Andyur's id; when it
    fires, ScheduledAgentRun admits the run through the facade -- Andyur
    decides -- and the admitted run is dispatched by the engine to the
    execution worker. The native poller never sees it; the native assignment
    loop is never called; deleting the schedule removes it from the engine."""
    from andyur.server import schedules

    env, facade, provider, launcher = engine
    monkeypatch.setattr(orchestration, "facade", lambda: facade)
    config = provider._config
    control = ControlPlaneWorkerThread(
        TemporalConfig(address=ADDRESS, task_queue=config.task_queue)).start()
    try:
        agent = env.agent("alice")
        s = schedules.create_schedule(agent, "0 3 * * *", "nightly")
        assert s["trigger"] == "engine"

        client = provider._conn.client()
        provider._conn.run(client.get_schedule_handle(s["id"]).trigger())

        assert _wait(lambda: launcher.launched), "the schedule's run was never dispatched"
        (run_id, generation), = launcher.launched
        row = _row(run_id)
        assert row["dispatch"] == "engine" and row["run_type"] == "scheduled"
        assert generation == row["execution_generation"]

        assert schedules.delete_schedule(s["id"])
        from temporalio.service import RPCError
        with pytest.raises(RPCError):
            provider._conn.run(client.get_schedule_handle(s["id"]).describe())
    finally:
        control.stop()

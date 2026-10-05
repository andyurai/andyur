"""Architecture B+: the engine dispatches admitted runs (ADR-014 D11).

The server half -- who may claim a run, what a claim returns, and that the
native loop and the engine can never both dispatch one run -- and the
executor half, against stand-ins for the daemon and the control plane. The
real engine and the real run fence are exercised in test_temporal_campaign.py
and infra/bplus-spike/.
"""

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from andyur import db, identity, orchestration
from andyur.server import coordinator, heartbeat
from andyur.server.app import app
from conftest import svid_header
from orchestration_contract.fakes import FakeProvider

EXEC = svid_header(f"spiffe://{identity.TRUST_DOMAIN}/temporal-execution-worker")
WORKER = svid_header(f"spiffe://{identity.TRUST_DOMAIN}/worker")
client = TestClient(app)


def _engine_run(env, name="alice"):
    agent = env.agent(name)
    return coordinator.wakeup_or_reason(agent, "work", dispatch="engine")[0]


def _native_run(env, name="bob"):
    agent = env.agent(name)
    return coordinator.wakeup_or_reason(agent, "work")[0]


def _row(run_id):
    with db.connect() as c:
        return dict(c.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone())


def _claim(run_id, headers=EXEC, orchestrator="host", provider="temporal"):
    return client.post(f"/runs/{run_id}/execute",
                       json={"orchestrator": orchestrator, "provider": provider},
                       headers=headers)


# --- one run, one dispatcher --------------------------------------------------

def test_the_native_loop_never_hands_out_an_engine_run(env):
    """An engine run is the execution worker's; if the native loop could also
    select it, one run could be launched by both dispatchers."""
    engine = _engine_run(env)
    native = _native_run(env)

    handed = [a["id"] for a in coordinator.assign_runs("w1", 10)]

    assert engine not in handed, "the native assignment loop handed out an engine run"
    assert native in handed, "positive control: a native run is still handed out"


def test_the_facade_marks_a_run_for_the_engine_only_when_the_provider_dispatches(env):
    """The marker is written at admission, in the run's INSERT -- from the
    provider, not from any caller -- so there is no instant in which the native
    loop could see an engine run unmarked."""
    class Dispatching(FakeProvider):
        @property
        def dispatches_runs(self):
            return True

    engine_run, _ = orchestration.OrchestrationFacade(
        provider=Dispatching()).request_agent_run(env.agent("alice"), "x")
    native_run, _ = orchestration.OrchestrationFacade(
        provider=FakeProvider()).request_agent_run(env.agent("bob"), "x")

    assert _row(engine_run)["dispatch"] == "engine"
    assert _row(native_run)["dispatch"] is None


def test_a_dead_workers_requeue_never_touches_an_engine_run(env):
    """The requeue hands a dead worker's pending runs back to the native loop.
    An engine run's retry is the engine's; requeuing it would give it to both."""
    engine = _engine_run(env)
    native = _native_run(env)
    stale = "2000-01-01T00:00:00+00:00"
    with db.connect() as c:
        for w in ("engine", "dead-worker"):
            c.execute("INSERT INTO workers (id, slots, last_heartbeat) VALUES (?, 1, ?)",
                      (w, stale))
        c.execute("UPDATE runs SET worker = 'engine' WHERE id = ?", (engine,))
        c.execute("UPDATE runs SET worker = 'dead-worker' WHERE id = ?", (native,))

    heartbeat.recover_stuck_runs()

    assert _row(engine)["worker"] == "engine", "an engine run was requeued to the native loop"
    assert _row(native)["worker"] is None, "positive control: a dead worker's run is requeued"


# --- the claim: Andyur decides, the engine only names the run -------------------

def test_the_first_claim_records_the_runs_one_generation_and_retries_get_it_back(env):
    run_id = _engine_run(env)

    first = _claim(run_id).json()
    second = _claim(run_id).json()

    assert first["generation"] and first["generation"] == second["generation"], (
        "a retry got a different generation; the fence would refuse its adoption")
    assert _row(run_id)["execution_generation"] == first["generation"]
    assert _row(run_id)["worker"] == coordinator.ENGINE_WORKER
    assert first["launch"]["run_token"], "a pending run was not credentialed for launch"


def test_a_started_run_is_adopted_never_recredentialed(env):
    """Once the run has started, a retry adopts what is running; minting it
    fresh credentials would hand out authority nothing will use."""
    run_id = _engine_run(env)
    generation = _claim(run_id).json()["generation"]
    assert coordinator.start_run(run_id)

    claim = _claim(run_id).json()

    assert claim["generation"] == generation
    assert claim["launch"] is None, "a running run was handed launch credentials again"


@pytest.mark.parametrize("case", ["unknown", "native", "terminal", "halted"])
def test_andyur_refuses_what_it_did_not_admit_for_the_engine(env, case):
    """The engine can name a run id; it cannot make one executable."""
    if case == "unknown":
        run_id = "f" * 32
    elif case == "native":
        run_id = _native_run(env)
    else:
        run_id = _engine_run(env)
        with db.connect() as c:
            if case == "terminal":
                c.execute("UPDATE runs SET state = 'done' WHERE id = ?", (run_id,))
            else:
                c.execute("UPDATE workflows SET state = 'halted' WHERE id = "
                          "(SELECT workflow_id FROM runs WHERE id = ?)", (run_id,))

    resp = _claim(run_id)

    assert resp.status_code == 409, resp.text
    expected = {"unknown": "unknown", "native": "not_engine",
                "terminal": "terminal", "halted": "halted"}[case]
    assert resp.json()["refusal"] == expected
    if case != "unknown":
        assert _row(run_id)["execution_generation"] is None, "a refused claim was recorded"


def test_a_kubernetes_claim_refuses_an_agent_with_no_sealed_registry_binding(env):
    run_id = _engine_run(env)
    resp = _claim(run_id, orchestrator="kubernetes")
    assert resp.status_code == 409 and resp.json()["refusal"] == "unsealed"


def test_in_production_the_seal_is_required_whatever_the_caller_says(env, monkeypatch):
    """ADVERSARIAL REVIEW (B+ identity, H7): the claim took `require_registry`
    from the caller's own `orchestrator`, so an execution worker saying "host"
    skipped the re-check that the registry still resolves to the sealed run."""
    from andyur import config
    run_id = _engine_run(env)
    monkeypatch.setattr(config, "PROD", True)
    resp = _claim(run_id, orchestrator="host")
    assert resp.status_code == 409 and resp.json()["refusal"] == "unsealed"


def test_a_daemon_may_not_beat_as_the_engine(env):
    """ADVERSARIAL REVIEW (B+ engine authority, H8): a daemon beating as
    "engine" had native runs assigned under the engine's marker, and the
    execution worker could then finalize them with any summary."""
    native = _native_run(env)
    resp = TestClient(app).post("/worker/heartbeat", headers=WORKER, json={
        "worker_id": coordinator.ENGINE_WORKER, "slots": 1, "slots_free": 1,
        "running": []})
    assert resp.status_code == 403
    assert _row(native)["worker"] is None


def test_the_execution_worker_cannot_finish_a_native_run_even_under_its_marker(env):
    """Defence in depth: the finish also matches the dispatcher, so a native
    run that somehow carries the engine's marker is still not the engine's."""
    native = _native_run(env)
    with db.connect() as c:
        c.execute("UPDATE runs SET worker = ? WHERE id = ?",
                  (coordinator.ENGINE_WORKER, native))
    resp = TestClient(app).post(f"/runs/{native}/worker-finish", headers=EXEC,
                                json={"worker_id": "x", "summary": "forged"})
    assert resp.status_code == 403, resp.text
    assert _row(native)["state"] == "pending"


def test_the_no_daemon_cli_path_cannot_launch_an_engine_run(env):
    """ADVERSARIAL REVIEW (B+ mode separation, H5): the CLI's no-daemon
    fallback mints a run token and runs the runner itself -- for an engine
    run, a second launch beside the execution worker's."""
    run_id = _engine_run(env)
    resp = TestClient(app).post(f"/runs/{run_id}/token")
    assert resp.status_code == 409 and "engine" in resp.text


def test_no_agent_may_take_the_execution_workers_name(env):
    """Roles come from the last segment of a SPIFFE id; an agent named after
    a privileged role is one identity-layout change from holding it."""
    resp = TestClient(app).post("/agents", json={"name": "temporal-execution-worker"})
    assert resp.status_code == 400, resp.text


@pytest.mark.parametrize("who", ["worker", "operator"])
def test_only_the_execution_worker_may_claim(env, who):
    run_id = _engine_run(env)
    headers = WORKER if who == "worker" else {}
    assert _claim(run_id, headers=headers).status_code == 403
    assert _row(run_id)["execution_generation"] is None


def test_the_daemon_cannot_finish_a_run_as_the_engine(env):
    run_id = _engine_run(env)
    _claim(run_id)

    forged = client.post(f"/runs/{run_id}/worker-finish", headers=WORKER,
                         json={"worker_id": coordinator.ENGINE_WORKER, "summary": "x"})
    real = client.post(f"/runs/{run_id}/worker-finish", headers=EXEC,
                       json={"worker_id": "anything", "summary": "ok"})

    assert forged.status_code == 403, "the daemon finished a run as the engine"
    assert real.status_code == 200 and _row(run_id)["state"] == "done", real.text


def test_a_halted_engine_run_is_condemned_to_its_executor(env):
    run_id = _engine_run(env)
    _claim(run_id)
    assert client.get(f"/runs/{run_id}/execution", headers=EXEC).json()["kill"] is False
    with db.connect() as c:
        c.execute("UPDATE workflows SET state = 'halted' WHERE id = "
                  "(SELECT workflow_id FROM runs WHERE id = ?)", (run_id,))
    assert client.get(f"/runs/{run_id}/execution", headers=EXEC).json()["kill"] is True


# --- the executor ----------------------------------------------------------------

class _Proc:
    def __init__(self):
        self.code = None

    def poll(self):
        return self.code


class _Orch:
    name = "kubernetes"

    def __init__(self):
        self.adopted = []

    def release_after_outcome(self, run_id, generation):
        self.released = getattr(self, "released", []) + [(run_id, generation)]

    def adopt_governed(self, run_id, generation, runtime):
        self.adopted.append((run_id, generation))
        p = _Proc()
        p.code = 0
        return p


class _Daemon:
    execution = True
    worker_id = "execution-test"

    def __init__(self, launch_error=None):
        self.orch = _Orch()
        self.procs = {}
        self.launched = []
        self.killed = []
        self._launch_error = launch_error

    def launch(self, run_id, *args, generation=None):
        if self._launch_error:
            raise self._launch_error
        self.launched.append((run_id, generation))
        p = _Proc()
        p.code = 0
        self.procs[run_id] = p

    def kill(self, run_ids):
        self.killed.extend(run_ids)
        for r in run_ids:
            if r in self.procs:
                self.procs[r].code = 137

    async def reap_one(self, api, run_id):
        proc = self.procs.get(run_id)
        if proc is None or proc.code is None:
            return None
        return self.procs.pop(run_id).code


def _api(claim_status=200, claim=None, kill=False, finished=None):
    def handler(request):
        if request.url.path.endswith("/execute"):
            return httpx.Response(claim_status, json=claim or {})
        if request.url.path.endswith("/execution"):
            return httpx.Response(200, json={"kill": kill, "state": "running"})
        if request.url.path.endswith("/worker-finish"):
            if finished is not None:
                finished.append(request.url.path)
            return httpx.Response(200, json={"state": "failed"})
        return httpx.Response(404)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://cp")


def _execute(daemon, api, run_id="r" * 32):
    from andyur.daemon.engine_executor import EngineExecutor

    EngineExecutor.POLL_SECONDS = 0.01
    beats = []

    async def go():
        async with api:
            return await EngineExecutor(daemon, api, provider="temporal").execute(run_id, beats.append)
    return asyncio.run(go()), beats


def _launch_claim(run_id="r" * 32):
    return {"id": run_id, "generation": "exec-abc",
            "launch": {"id": run_id, "agent": "alice", "run_token": "t"}}


def test_the_executor_launches_under_the_runs_generation():
    daemon = _Daemon()
    out, beats = _execute(daemon, _api(claim=_launch_claim()))
    assert daemon.launched == [("r" * 32, "exec-abc")], (
        "the launch did not carry the run's own generation")
    assert out["outcome"] == "exited" and out["how"] == "launched"
    assert all(b.get("generation") == "exec-abc" for b in beats)
    assert not any(k for b in beats for k in b if "token" in k), (
        "a heartbeat -- durable engine state -- carried a credential")


def test_the_executor_adopts_when_the_fence_says_the_run_is_already_owned():
    """A retry after the acknowledgement was lost: the fence refuses a second
    launch, and the executor adopts the run instead of failing it."""
    daemon = _Daemon(launch_error=RuntimeError("Kubernetes run 'x' is already owned"))
    out, _ = _execute(daemon, _api(claim=_launch_claim()))
    assert daemon.orch.adopted == [("r" * 32, "exec-abc")]
    assert out["how"] == "adopted" and out["outcome"] == "exited"


def test_an_andyur_refusal_is_permanent():
    from andyur.daemon.engine_executor import ExecutionRefused

    with pytest.raises(ExecutionRefused) as info:
        _execute(_Daemon(), _api(claim_status=409,
                                 claim={"refusal": "halted", "detail": "no"}))
    assert info.value.code == "halted"


def test_a_condemned_run_is_contained_by_its_executor():
    daemon = _Daemon()

    class Hanging(_Daemon):
        pass
    daemon.launch = lambda run_id, *a, generation=None: daemon.procs.__setitem__(
        run_id, _Proc())                                     # never exits by itself
    out, _ = _execute(daemon, _api(claim=_launch_claim(), kill=True))
    assert daemon.killed == ["r" * 32], "the condemned run was not destroyed"
    assert out["outcome"] == "killed"


def test_a_failed_launch_is_recorded_as_the_runs_outcome(monkeypatch):
    finished = []
    daemon = _Daemon(launch_error=ValueError("rbac refused"))
    out, _ = _execute(daemon, _api(claim=_launch_claim(), finished=finished))
    assert out["outcome"] == "launch_failed"
    assert finished == [f"/runs/{'r' * 32}/worker-finish"]


# --- the runtime reconciler reaches engine runs (Gate C) -------------------------

from test_kubernetes_orphan_sweep import FakeApi, _pod  # noqa: E402


class _FencedApi(FakeApi):
    def __init__(self, pods):
        super().__init__(pods)
        self.deleted = []

    def read_run_singleton(self, namespace, name, labels, owner, timeout):
        from andyur.daemon.kubernetes_api import LeaseClaim
        return LeaseClaim(name, "uid", "1", owner)

    def delete_run_group(self, namespace, selector, timeout):
        self.deleted.append(dict(selector))

    def release_run_singleton(self, namespace, claim, timeout):
        self.released = getattr(self, "released", []) + [(claim.name, claim.holder)]

    def assert_isolation_ready(self, namespace):
        pass


def _k8s(pods, *, run_scoped=False):
    from andyur.daemon.kubernetes_controller import KubernetesRunController
    from andyur.daemon.orchestrator import KubernetesOrchestrator

    api = _FencedApi(pods)
    controller = KubernetesRunController(api, "andyur-runs", None if run_scoped else "worker-a")
    return KubernetesOrchestrator(controller=controller,
                                  run_scoped_generations=run_scoped), api


A, B, C = "a" * 32, "b" * 32, "c" * 32


def _pods():
    return [_pod(A, "worker-a", "proxy"), _pod(A, "worker-a", "agent"),
            _pod(B, "exec-1234", "proxy"), _pod(B, "exec-1234", "agent"),
            _pod(C, "worker-b", "proxy"), _pod(C, "worker-b", "agent")]


def test_the_reconciler_finds_engine_runs_it_did_not_launch():
    """A halted run must die when the execution worker that launched it is
    dead, so the daemon -- which watches the runtime, not the engine -- must be
    able to see it. Only ENGINE generations: another worker's runs stay that
    worker's, as before."""
    orch, _ = _k8s(_pods())
    assert orch.engine_runs() == [(B, "exec-1234")]


def test_the_reconciler_destroys_a_condemned_engine_run_by_its_exact_generation():
    from andyur.daemon.kubernetes_manifests import _digest

    orch, api = _k8s(_pods())
    orch.kill([B])
    assert api.deleted and all(d.get("andyur.run/generation") == _digest("exec-1234")
                               for d in api.deleted), api.deleted
    assert not any(d.get("andyur.run/id") == _digest(C) for d in api.deleted), (
        "another worker's run was destroyed")


def test_one_ambiguous_pod_elsewhere_does_not_hide_engine_runs_from_the_kill():
    """ADVERSARIAL REVIEW (B+ identity/containment, H5). The engine view spans
    the whole namespace, and it reused the adoption listing, which refuses the
    entire set on one ambiguous Pod: another daemon's proxy in `Unknown` on a
    lost node made `engine_runs` and `kill` raise, so with the engine and the
    execution worker gone a halted engine run was never destroyed."""
    lost = _pod("d" * 32, "worker-b", "proxy")
    lost.phase = "Unknown"
    orch, api = _k8s(_pods() + [lost])
    assert orch.engine_runs() == [(B, "exec-1234")]
    orch.kill([B])
    from andyur.daemon.kubernetes_manifests import _digest
    assert [d["andyur.run/generation"] for d in api.deleted] == [_digest("exec-1234")]


def test_the_engine_view_is_not_bounded_by_one_daemons_adoption_cap():
    """64 runs of OTHER launchers exceeded the adoption bound and blinded the
    engine view -- 16 execution-worker replicas at concurrency 4 would do it."""
    orch, _ = _k8s(_pods() + [_pod(f"{i:032x}", "worker-b", "proxy") for i in range(64)])
    assert orch.engine_runs() == [(B, "exec-1234")]


def test_an_engine_pod_that_fails_verification_is_skipped_not_destroyed():
    rewritten = _pod("e" * 32, "exec-5678", "proxy")
    rewritten.labels["andyur.run/generation"] = "rewritten"
    orch, api = _k8s(_pods() + [rewritten])
    assert orch.engine_runs() == [(B, "exec-1234")]
    orch.kill(["e" * 32])
    assert api.deleted == [], "a Pod that failed verification was destroyed"


def test_the_reconcilers_kill_never_releases_a_fence_it_did_not_claim():
    """Reviewed and KEPT (B+ adversarial review, H3): the reconciler observed
    this run, it never claimed it, and observation grants no release authority
    (`test_restart_observes_exact_singleton_but_cannot_release_it`). The Lease
    that stays behind can only refuse a relaunch of a run Andyur condemned."""
    orch, api = _k8s(_pods())
    orch.kill([B])
    assert getattr(api, "released", []) == []


def test_the_execution_worker_itself_does_not_reconcile():
    orch, _ = _k8s(_pods(), run_scoped=True)
    assert orch.engine_runs() == []


def test_the_claims_generation_is_what_the_reconciler_looks_for(env):
    from andyur.daemon.orchestrator import ENGINE_GENERATION_PREFIX

    generation = _claim(_engine_run(env)).json()["generation"]
    assert generation.startswith(ENGINE_GENERATION_PREFIX), (
        "the reconciler would never find a run claimed under this generation")


# --- schedules: one trigger per schedule (Step 12) -------------------------------

from andyur.server import schedules  # noqa: E402


class _Dispatching(FakeProvider):
    @property
    def dispatches_runs(self):
        return True


def _bind(monkeypatch, provider):
    f = orchestration.OrchestrationFacade(provider=provider)
    monkeypatch.setattr(orchestration, "facade", lambda: f)
    return provider


def _due(sid):
    with db.connect() as c:
        c.execute("UPDATE schedules SET next_run_at = '2000-01-01T00:00:00+00:00' "
                  "WHERE id = ?", (sid,))


def test_an_engine_dispatched_deployment_fires_schedules_in_the_engine_only(env, monkeypatch):
    """The schedule exists in the engine under ANDYUR's id, and the native
    poller never fires it -- not even when the row says it is due -- so one
    schedule cannot fire twice."""
    provider = _bind(monkeypatch, _Dispatching())
    s = schedules.create_schedule(env.agent("alice"), "0 3 * * *", "nightly")
    _due(s["id"])

    fired = schedules.fire_due()

    assert s["trigger"] == "engine" and s["id"] in provider._schedules
    assert fired == [], f"the native poller fired an engine schedule: {fired}"
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"] == 0


def test_positive_control_a_native_deployment_still_fires_through_the_poller(env, monkeypatch):
    from andyur.orchestration.local import LocalWorkflowProvider

    _bind(monkeypatch, LocalWorkflowProvider())
    s = schedules.create_schedule(env.agent("alice"), "0 3 * * *", "nightly")
    _due(s["id"])

    fired = schedules.fire_due()

    assert s["trigger"] == "native"
    assert any("fired run" in a for a in fired), fired


def test_deleting_an_engine_schedule_removes_it_from_the_engine(env, monkeypatch):
    provider = _bind(monkeypatch, _Dispatching())
    s = schedules.create_schedule(env.agent("alice"), "0 3 * * *", "nightly")

    assert schedules.delete_schedule(s["id"])
    assert s["id"] not in provider._schedules, "the engine's schedule outlived Andyur's row"


def test_an_engine_that_refuses_the_schedule_leaves_no_row_behind(env, monkeypatch):
    """A row Andyur shows must be a schedule that fires."""
    class Refusing(_Dispatching):
        def create_schedule(self, spec):
            raise orchestration.ProviderUnavailable("engine down")
    _bind(monkeypatch, Refusing())

    with pytest.raises(orchestration.ProviderUnavailable):
        schedules.create_schedule(env.agent("alice"), "0 3 * * *", "nightly")
    assert schedules.list_schedules() == []


# --- delegated and deferred work reach the engine, not the native loop ------------

from andyur.server import tasks  # noqa: E402


def test_delegated_work_is_dispatched_by_the_engine(env, monkeypatch):
    """Delegation wakes its target through the facade, so under engine dispatch
    the child run is the engine's. A run created around the facade would be the
    native loop's -- and in a deployment where the native loop does not
    dispatch, it would never launch at all."""
    _bind(monkeypatch, _Dispatching())
    boss, worker = env.agent("boss"), env.agent("helper")
    tasks.create_task(assignee=worker, creator=boss, title="look into it")

    with db.connect() as c:
        rows = c.execute("SELECT dispatch FROM runs WHERE agent = ?", (worker,)).fetchall()
    assert rows and all(r["dispatch"] == "engine" for r in rows), [dict(r) for r in rows]


def test_deferred_work_picked_up_by_the_drain_is_dispatched_by_the_engine(env, monkeypatch):
    """The drain DECIDES admission (Andyur's job); the admitted run is then the
    engine's to dispatch, not the native loop's."""
    _bind(monkeypatch, _Dispatching())
    helper = env.agent("helper")
    coordinator.set_paused(helper, True)          # the wakeup is refused: work waits
    tasks.create_task(assignee=helper, creator="boss", title="later")
    coordinator.set_paused(helper, False)

    heartbeat.drain_pending_work()

    with db.connect() as c:
        rows = c.execute("SELECT dispatch FROM runs WHERE agent = ?", (helper,)).fetchall()
    assert rows, "the drain admitted nothing"
    assert all(r["dispatch"] == "engine" for r in rows), [dict(r) for r in rows]


# --- adversarial review: a cancellation is not a halt; a launch keeps its beat ---

def _cancelled(api, *, requested, run_id="r" * 32):
    from andyur.daemon.engine_executor import EngineExecutor

    daemon = _Daemon()
    daemon.procs[run_id] = _Proc()                  # a live, healthy runtime

    async def go():
        async with api:
            return await EngineExecutor(daemon, api, provider="temporal").cancelled(run_id, requested=requested)
    return asyncio.run(go()), daemon


def _unreachable():
    def handler(request):
        raise httpx.ConnectError("control plane down")
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://cp")


@pytest.mark.parametrize("requested", [True, False])
def test_a_cancellation_andyur_does_not_condemn_never_destroys_the_run(requested):
    """ADVERSARIAL REVIEW (B+ launch idempotency, H2/H8; engine authority, H6).
    Every cancellation used to destroy the runtime and record it failed: a
    rolling restart of the execution worker (worker_shutdown), an attempt the
    engine had already replaced (timed_out / not_found) killing the run its
    successor adopted, and a workflow cancel Andyur never asked for. The engine
    cannot condemn a run; Andyur, reachable and saying no, is final."""
    contained, daemon = _cancelled(_api(kill=False), requested=requested)
    assert contained is False and daemon.killed == []


def test_a_cancellation_andyur_condemns_destroys_the_run():
    contained, daemon = _cancelled(_api(kill=True), requested=False)
    assert contained is True and daemon.killed == ["r" * 32]


def test_with_andyur_unreachable_only_a_requested_cancel_contains():
    """The halt path's own cancellation must still work with the control plane
    down (Gate C's engine half); a shutdown or superseded attempt must not."""
    contained, daemon = _cancelled(_unreachable(), requested=True)
    assert contained is True and daemon.killed == ["r" * 32]
    contained, daemon = _cancelled(_unreachable(), requested=False)
    assert contained is False and daemon.killed == []


def test_the_activity_passes_the_engines_cancel_reason_to_the_executor():
    from temporalio.testing import ActivityEnvironment
    from andyur.orchestration.temporal import execution

    seen = []

    class Executor:
        async def execute(self, run_id, heartbeat):
            await asyncio.sleep(30)

        async def cancelled(self, run_id, *, requested):
            seen.append(requested)
            return False

    execution.bind(Executor())
    env = ActivityEnvironment()

    async def go():
        task = asyncio.ensure_future(env.run(execution.execute_run, "r" * 32))
        await asyncio.sleep(0.05)
        env.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    try:
        asyncio.run(go())
    finally:
        execution.bind(None)
    assert seen == [True]


def test_a_slow_launch_keeps_heartbeating():
    """A launch blocks for up to two minutes (proxy readiness, then input) and
    the engine's heartbeat timeout is 60s: one quiet launch let the engine hand
    the run to another worker while this one was still creating it."""
    import time as _time
    from andyur.daemon.engine_executor import EngineExecutor

    daemon = _Daemon()
    original = daemon.launch

    def slow(run_id, *args, generation=None):
        _time.sleep(0.3)
        original(run_id, *args, generation=generation)
    daemon.launch = slow
    EngineExecutor.LAUNCH_BEAT_SECONDS = 0.05
    try:
        _, beats = _execute(daemon, _api(claim=_launch_claim()))
    finally:
        EngineExecutor.LAUNCH_BEAT_SECONDS = 10.0
    assert sum(b["phase"] == "launching" for b in beats) >= 3, beats


def test_an_adopted_run_whose_agent_is_not_created_yet_has_not_exited(monkeypatch):
    """The fence is taken first and the agent created last, so a retry that
    adopts mid-launch finds no agent Pod. That read as exit 1: the half-built
    group was reaped and a run that would have succeeded recorded failed."""
    from andyur.daemon import kubernetes_controller as kc

    class Api:
        def pod_phase(self, namespace, name):
            return None
    now = [1000.0]
    monkeypatch.setattr(kc.time, "monotonic", lambda: now[0])
    handle = kc.KubernetesRunHandle(Api(), "andyur-runs", "agent",
                                    absent_grace_until=now[0] + 150)
    assert handle.poll() is None
    now[0] += 151
    assert handle.poll() == 1, "absence after a whole launch is still an exit"
    assert kc.KubernetesRunHandle(Api(), "andyur-runs", "agent").poll() == 1, (
        "a handle this process launched must keep reading absence as exited")


# --- adversarial review: schedules Andyur can always see and stop ------------

def test_an_engine_schedule_under_the_local_provider_is_refused_not_recursed(env, monkeypatch):
    """ADVERSARIAL REVIEW (B+ mode separation, H1). After a switch to Local, the
    delete went Local -> schedule service -> facade -> Local ... RecursionError,
    and the schedule could never be removed. It is refused by name, and kept."""
    from andyur.orchestration.local.provider import LocalWorkflowProvider

    _bind(monkeypatch, _Dispatching())
    sid = schedules.create_schedule(env.agent("alice"), "0 3 * * *", "nightly")["id"]
    _bind(monkeypatch, LocalWorkflowProvider())
    resp = TestClient(app).delete(f"/schedules/{sid}")
    assert resp.status_code == 409 and "engine" in resp.text
    assert [s["id"] for s in schedules.list_schedules()] == [sid]


class _Ambiguous(_Dispatching):
    """The engine created the schedule, and the call still failed."""

    def __init__(self, delete_fails=False):
        super().__init__()
        self._delete_fails = delete_fails

    def create_schedule(self, spec):
        super().create_schedule(spec)
        raise orchestration.ProviderUnavailable("rpc deadline exceeded")

    def delete_schedule(self, schedule_id):
        if self._delete_fails:
            raise orchestration.ProviderUnavailable("engine down")
        super().delete_schedule(schedule_id)


def test_an_ambiguous_create_leaves_no_schedule_andyur_cannot_see(env, monkeypatch):
    """A create that failed after the engine made the schedule dropped the row
    and left the engine's copy firing, invisible and undeletable."""
    p = _bind(monkeypatch, _Ambiguous())
    with pytest.raises(orchestration.ProviderUnavailable):
        schedules.create_schedule(env.agent("alice"), "0 3 * * *", "nightly")
    assert schedules.list_schedules() == [] and p._schedules == {}


def test_if_the_engine_copy_cannot_be_removed_the_row_stays_visible(env, monkeypatch):
    p = _bind(monkeypatch, _Ambiguous(delete_fails=True))
    with pytest.raises(orchestration.ProviderUnavailable):
        schedules.create_schedule(env.agent("alice"), "0 3 * * *", "nightly")
    assert [s["id"] for s in schedules.list_schedules()] == list(p._schedules)


def _admit(trigger):
    from andyur.orchestration.temporal.activities import admit_scheduled_run
    from temporalio.testing import ActivityEnvironment
    return asyncio.run(ActivityEnvironment().run(admit_scheduled_run, trigger))


def test_a_tick_that_names_no_andyur_schedule_admits_nothing(env, monkeypatch):
    """ADVERSARIAL REVIEW (B+ identity, H6). The engine admits the execution
    worker's identity, which could start ScheduledAgentRun for any agent with
    any reason -- and the tick was admitted. A tick must name an enabled engine
    schedule of that agent, and the ROW supplies the reason."""
    from andyur.orchestration.temporal.activities import ScheduledTrigger

    _bind(monkeypatch, _Dispatching(schedules=True))
    agent = env.agent("alice")
    assert _admit(ScheduledTrigger(agent, "forged")) is None
    assert _admit(ScheduledTrigger(agent, "forged", schedule_id="nope")) is None
    sid = schedules.create_schedule(agent, "0 3 * * *", "nightly")["id"]
    assert _admit(ScheduledTrigger(env.agent("bob"), "forged", schedule_id=sid)) is None
    run_id = _admit(ScheduledTrigger(agent, "forged reason", schedule_id=sid))
    assert run_id is not None
    with db.connect() as c:
        reason = c.execute("SELECT reason FROM runs WHERE id = ?", (run_id,)).fetchone()[0]
    assert "forged" not in (reason or ""), reason


# --- adversarial review: no silent Architecture A in production ----------------

@pytest.mark.parametrize("dispatch,refused", [(None, True), ("native", True),
                                              ("engine", False)])
def test_production_temporal_must_say_engine_dispatch(monkeypatch, dispatch, refused):
    """ADVERSARIAL REVIEW (B+ mode separation, H4). Unset meant `native`, and
    the native worker daemon is still deployed: a manifest that lost the line
    silently ran every Temporal-backed run through the native loop."""
    from andyur import config
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setenv("ANDYUR_WORKFLOW_PROVIDER", "temporal")
    if dispatch is None:
        monkeypatch.delenv("ANDYUR_TEMPORAL_DISPATCH", raising=False)
    else:
        monkeypatch.setenv("ANDYUR_TEMPORAL_DISPATCH", dispatch)
    assert (config.temporal_dispatch_problem() is not None) is refused


def test_the_dispatch_rule_leaves_local_and_dev_alone(monkeypatch):
    """The package default stays Local and is never keyed to the profile."""
    from andyur import config
    monkeypatch.delenv("ANDYUR_TEMPORAL_DISPATCH", raising=False)
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.delenv("ANDYUR_WORKFLOW_PROVIDER", raising=False)
    assert config.temporal_dispatch_problem() is None
    monkeypatch.setenv("ANDYUR_WORKFLOW_PROVIDER", "temporal")
    monkeypatch.setattr(config, "PROD", False)
    assert config.temporal_dispatch_problem() is None


def test_the_workflow_worker_refuses_the_same_way(monkeypatch):
    from andyur import config
    from andyur.orchestration.temporal import worker
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setenv("ANDYUR_WORKFLOW_PROVIDER", "temporal")
    monkeypatch.delenv("ANDYUR_TEMPORAL_DISPATCH", raising=False)
    monkeypatch.setattr(worker.asyncio, "run", lambda *a: pytest.fail("it started"))
    with pytest.raises(config.InsecureProfile, match="TEMPORAL_DISPATCH"):
        worker.main()


# --- the engine's execution bound covers every lifetime Andyur can grant -------

def test_the_engine_execution_bound_outlasts_the_longest_grant_and_its_teardown():
    """The Activity bound was a fixed 26 hours while the registry already
    permitted grants of up to seven days: a longer run's execution would have
    been timed out by the ENGINE mid-run. It is now derived from the ceiling,
    and the margin must cover everything that follows a deadline -- the
    reaper's grace, one launch, the condemnation poll and the group's delete."""
    from datetime import timedelta
    from andyur.daemon.engine_executor import EngineExecutor
    from andyur.daemon.kubernetes_controller import KubernetesRunController as K
    from andyur.orchestration.temporal import workflows
    from andyur.registry.models import LIFETIME_CEILING_SECONDS
    from andyur.server.heartbeat import RUN_GRACE_SECONDS

    after_deadline = (RUN_GRACE_SECONDS + K.ADOPTION_LAUNCH_GRACE
                      + EngineExecutor.POLL_SECONDS + K.DELETE_TIMEOUT)
    assert workflows.EXECUTION_START_TO_CLOSE >= timedelta(
        seconds=LIFETIME_CEILING_SECONDS + after_deadline)
    assert workflows.EXECUTION_START_TO_CLOSE - timedelta(
        seconds=LIFETIME_CEILING_SECONDS) == workflows.EXECUTION_MARGIN


def test_no_lifetime_andyur_can_grant_exceeds_the_ceiling():
    """Every source of a run's wall clock is bounded by the ceiling the engine
    bound is derived from: a declared grant, the platform default for a run
    that declared nothing, and a conversation's maximum."""
    from andyur import config
    from andyur.registry.models import (
        LIFETIME_CEILING_SECONDS, MalformedLifecycle, granted_lifetime_seconds,
        lifecycle_from_assignment)

    with pytest.raises(MalformedLifecycle, match="outside the permitted bounds"):
        lifecycle_from_assignment({"lifecycle": {
            "mode": "task", "max_seconds": LIFETIME_CEILING_SECONDS + 1}})
    assert lifecycle_from_assignment({"lifecycle": {
        "mode": "task", "max_seconds": LIFETIME_CEILING_SECONDS}}) is not None
    assert granted_lifetime_seconds(None, 48 * 3600) == 48 * 3600
    assert granted_lifetime_seconds(None, 30 * 24 * 3600) == LIFETIME_CEILING_SECONDS
    assert config.CONVERSATION_MAX_SECONDS <= 6 * 3600 <= LIFETIME_CEILING_SECONDS


def test_the_servers_platform_default_is_clamped_at_the_ceiling():
    """The number the server sends workers and reaps by, read in a fresh
    process so the environment is what the module actually saw at import."""
    import subprocess
    import sys
    code = ("from andyur.server.heartbeat import RUN_TTL_SECONDS as t;"
            "from andyur.registry.models import LIFETIME_CEILING_SECONDS as c;"
            "print(t, c)")
    env = {**__import__("os").environ, "ANDYUR_RUN_TTL_SECONDS": str(30 * 24 * 3600)}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                         text=True, check=True).stdout.split()
    assert out[0] == out[1], out


# --- pre-DBOS-spike changes (provider drafts, F-1 / F-2 / F-4 / F-5) -----------

def test_a_failed_launch_releases_the_fence_only_after_the_failure_is_recorded():
    """F-2, the executor's half: recorded -> the fence is released; not
    recorded -> nothing is released and the invocation fails, so the retry
    finds the run fenced and adopts instead of launching again."""
    daemon = _Daemon(launch_error=ValueError("rbac refused"))
    out, _ = _execute(daemon, _api(claim=_launch_claim(), finished=[]))
    assert out["outcome"] == "launch_failed"
    assert daemon.orch.released == [("r" * 32, "exec-abc")]

    def unconfirmed(request):
        if request.url.path.endswith("/execute"):
            return httpx.Response(200, json=_launch_claim())
        return httpx.Response(503)
    daemon = _Daemon(launch_error=ValueError("rbac refused"))
    api = httpx.AsyncClient(transport=httpx.MockTransport(unconfirmed), base_url="http://cp")
    with pytest.raises(RuntimeError, match="not recorded"):
        _execute(daemon, api)
    assert getattr(daemon.orch, "released", []) == [], (
        "the fence was released although the failure was never recorded")


def test_a_run_is_claimable_only_through_the_provider_it_was_admitted_under(env, monkeypatch):
    """F-1 (run execution draft, step 2). With two dispatching providers
    deployed, an executor serving one could claim -- and launch -- a run the
    other admitted. The binding is written in the admission INSERT, so there
    is no window before the provider's start returns."""
    provider = _bind(monkeypatch, _Dispatching("temporal"))
    run_id, _ = orchestration.facade().request_agent_run(env.agent("alice"), "work", "work")
    assert _row(run_id)["orchestration_provider"] == provider.name

    refused = _claim(run_id, provider="dbos")
    assert refused.status_code == 409 and refused.json()["refusal"] == "not_bound"
    assert _row(run_id)["execution_generation"] is None, "a refused claim was recorded"
    assert _claim(run_id, provider="temporal").status_code == 200


def test_an_engine_run_admitted_before_the_binding_existed_is_temporals(env):
    """Rows admitted before the column carry no binding; Temporal was the only
    dispatching provider then, and no other provider may claim them."""
    run_id = _engine_run(env)
    assert _row(run_id)["orchestration_provider"] is None
    assert _claim(run_id, provider="dbos").json()["refusal"] == "not_bound"
    assert _claim(run_id, provider="temporal").status_code == 200


def test_the_controller_is_hosted_the_same_way_for_every_provider(monkeypatch):
    """F-4: the bootstrap -- containment checks, execution-mode daemon, the
    executor's identity-bound client -- is provider-neutral; a provider only
    names itself."""
    from andyur import config, identity
    from andyur.daemon import daemon as daemon_mod, engine_executor

    checks = []
    monkeypatch.setattr(config, "assert_profile",
                        lambda **kw: checks.append(("profile", kw)))
    monkeypatch.setattr(daemon_mod, "assert_egress_locked", lambda: checks.append("egress"))
    monkeypatch.setattr(identity, "assert_agent_isolation", lambda: checks.append("isolation"))
    monkeypatch.setattr(identity, "client_tls",
                        lambda who: checks.append(("tls", who)) or (None, True))
    monkeypatch.setattr(identity, "httpx_auth", lambda: None)
    monkeypatch.setattr(engine_executor, "Daemon", lambda execution: _Daemon())

    async def host(provider):
        async with engine_executor.hosted(provider) as executor:
            return executor.provider, type(executor).__name__
    assert asyncio.run(host("dbos")) == ("dbos", "EngineExecutor")
    assert checks == [("profile", {"signs_run_tokens": False}), "egress", "isolation",
                      ("tls", engine_executor.EXECUTOR_IDENTITY)]


def test_temporal_hosts_the_neutral_controller_under_its_own_name(monkeypatch):
    import contextlib
    from andyur.daemon import engine_executor
    from andyur.orchestration.temporal import execution, execution_worker
    from andyur.orchestration.temporal.config import TemporalConfig

    seen = {}

    @contextlib.asynccontextmanager
    async def hosted(provider):
        seen["provider"] = provider
        yield type("E", (), {"daemon": _Daemon(), "provider": provider})()
    monkeypatch.setattr(engine_executor, "hosted", hosted)
    monkeypatch.setattr(execution, "bind", lambda executor: seen.setdefault("bound", executor))

    async def no_run(config, build=None):
        seen["build"] = build
    monkeypatch.setattr(execution_worker, "_run", no_run)
    asyncio.run(execution_worker.serve(TemporalConfig(dispatch="engine")))
    assert seen["provider"] == "temporal" and seen["bound"].provider == "temporal"
    assert seen["build"] is execution_worker.build_execution_worker


def test_the_tick_check_is_andyurs_and_the_same_for_every_provider(env, monkeypatch):
    """F-5: the schedule check lives in the schedule service, not in any
    provider's code; a provider only forwards the tick."""
    _bind(monkeypatch, _Dispatching(schedules=True))
    agent = env.agent("alice")
    with pytest.raises(schedules.TickRefused):
        schedules.admit_engine_tick("nope", agent)
    sid = schedules.create_schedule(agent, "0 3 * * *", "nightly")["id"]
    with pytest.raises(schedules.TickRefused):
        schedules.admit_engine_tick(sid, env.agent("bob"))
    run_id, _ = schedules.admit_engine_tick(sid, agent)
    assert run_id is not None


# --- F-18: eventual delivery of an admitted run to its provider ---------------

class _Counting(_Dispatching):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.starts = []

    def start(self, request):
        self.starts.append(request.root_run_id)
        return super().start(request)


def _stranded(env, agent="alice", provider="fake"):
    """Committed and bound, never started: the crash between commit and start."""
    run_id = coordinator.wakeup_or_reason(
        env.agent(agent), "work", dispatch="engine",
        orchestration_provider=provider, workflow_kind="single_agent")[0]
    with db.connect() as c:
        c.execute("UPDATE runs SET created_at = '2000-01-01T00:00:00+00:00' WHERE id = ?",
                  (run_id,))
    return run_id


def test_a_committed_but_unstarted_engine_run_is_offered_again_once(env, monkeypatch):
    provider = _bind(monkeypatch, _Counting())
    run_id = _stranded(env)
    actions = orchestration.facade().reoffer_unacknowledged(60)
    assert provider.starts == [run_id] and len(actions) == 1
    assert _row(run_id)["provider_acked_at"] is not None
    assert orchestration.facade().reoffer_unacknowledged(60) == []
    assert provider.starts == [run_id], "offered again after it was acknowledged"


def test_a_normal_admission_is_acknowledged_and_never_re_offered(env, monkeypatch):
    provider = _bind(monkeypatch, _Counting())
    run_id, _ = orchestration.facade().request_agent_run(env.agent("alice"), "work")
    assert _row(run_id)["provider_acked_at"] is not None
    with db.connect() as c:
        c.execute("UPDATE runs SET created_at = '2000-01-01T00:00:00+00:00'")
    orchestration.facade().reoffer_unacknowledged(60)
    assert provider.starts == [run_id]


@pytest.mark.parametrize("case", ["in_grace", "other_provider", "legacy", "claimed",
                                  "terminal", "native"])
def test_what_is_never_re_offered(env, monkeypatch, case):
    """In flight (inside the grace), bound elsewhere (never re-homed), from
    before the binding existed, already claimed (the provider evidently started
    it), ended, or dispatched natively."""
    provider = _bind(monkeypatch, _Counting())
    run_id = _stranded(env, provider="other" if case == "other_provider" else "fake")
    with db.connect() as c:
        if case == "in_grace":
            c.execute("UPDATE runs SET created_at = ? WHERE id = ?", (db.utcnow(), run_id))
        elif case == "legacy":
            c.execute("UPDATE runs SET orchestration_provider = NULL WHERE id = ?", (run_id,))
        elif case == "claimed":
            c.execute("UPDATE runs SET execution_generation = 'exec-1' WHERE id = ?", (run_id,))
        elif case == "terminal":
            c.execute("UPDATE runs SET state = 'failed' WHERE id = ?", (run_id,))
        elif case == "native":
            c.execute("UPDATE runs SET dispatch = NULL WHERE id = ?", (run_id,))
    assert orchestration.facade().reoffer_unacknowledged(60) == []
    assert provider.starts == []


def test_the_re_offer_waits_out_an_engine_outage(env, monkeypatch):
    from andyur.server import engine_breaker

    class Down(_Counting):
        def start(self, request):
            raise orchestration.ProviderUnavailable("down")
    _bind(monkeypatch, Down())
    run_id = _stranded(env)
    monkeypatch.setattr(engine_breaker, "ENGINE", engine_breaker.EngineBreaker())
    [action] = heartbeat.reoffer_unacknowledged()
    assert "unreachable" in action
    assert engine_breaker.ENGINE.open_for() > 0, "the outage did not trip the breaker"
    assert "paused" in heartbeat.reoffer_unacknowledged()[0]
    assert _row(run_id)["state"] == "pending", "an outage must not end an admitted run"

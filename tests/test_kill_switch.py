"""The kill switch as a boundary, not a request.

Andyur stops a halted run two ways, and the difference matters:

  cooperative   the runner polls the halt flag and stops itself. Fast and tidy,
                but it lands only BETWEEN tool calls and needs the run to still
                be cooperating.
  enforced      the server condemns the run and the daemon destroys it. Needs
                nothing from the run at all.

These tests cover the enforced path: who gets condemned, who writes the record,
and whether destroying a run actually destroys the work it started -- the part
that is easy to get wrong, because killing the supervising process leaves the
agent's own shell commands running as orphans.
"""

import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import time

import pytest

import conftest
from fastapi.testclient import TestClient

from andyur.daemon.daemon import Daemon
from andyur.server import app as app_module
from andyur.server import coordinator

client = TestClient(app_module.app)


@pytest.fixture
def running_run(env):
    """An agent with a run the worker is actively executing."""
    env.agent("alice")
    run = coordinator.maybe_wakeup("alice", "root")
    wf = env.run_workflow(run)
    coordinator.assign_runs("w1", 1)
    coordinator.start_run(run)
    return {"run": run, "wf": wf}


# --- who gets condemned -----------------------------------------------------

def test_a_healthy_run_is_left_alone(running_run):
    assert coordinator.runs_to_kill([running_run["run"]]) == []


def test_a_halted_workflow_condemns_its_running_run(running_run):
    coordinator.halt_workflow(running_run["wf"])
    assert coordinator.runs_to_kill([running_run["run"]]) == [running_run["run"]]


def test_an_unknown_run_is_condemned(env):
    """A process executing with no run record answers to nobody: nothing will
    record what it does, and no policy check names it. Unaccountable execution
    is stopped on sight."""
    assert coordinator.runs_to_kill(["ghost-run"]) == ["ghost-run"]


def test_an_already_finished_run_still_executing_is_condemned(running_run):
    """The reaper finalized it (TTL exceeded) but the process is alive. The
    record says the run is over; the truth must be made to match."""
    coordinator.finish_run(running_run["run"], None, "reaped")
    assert coordinator.runs_to_kill([running_run["run"]]) == [running_run["run"]]


def test_nothing_running_asks_nothing(env):
    assert coordinator.runs_to_kill([]) == []


# --- who writes the record --------------------------------------------------

def test_the_server_writes_the_obituary_not_the_dying_run(running_run, env):
    """Never ask a process you are destroying to report its own death: it may
    not live long enough, and if it has been subverted the report is a lie."""
    coordinator.halt_workflow(running_run["wf"])
    coordinator.runs_to_kill([running_run["run"]])
    assert env.run_state(running_run["run"]) == "failed"


def test_condemning_a_run_frees_its_agent(running_run):
    """Otherwise the agent stays 'busy' forever on a run that no longer exists,
    and the kill switch quietly becomes a denial of service on that agent."""
    coordinator.halt_workflow(running_run["wf"])
    coordinator.runs_to_kill([running_run["run"]])
    from andyur import db
    with db.connect() as c:
        row = c.execute(
            "SELECT state FROM agent_status WHERE agent = 'alice'").fetchone()
    assert row["state"] == "idle"


def test_condemning_is_idempotent(running_run, env):
    """The worker keeps reporting the run until the process is really gone, so
    the same run is condemned on several beats. Re-issuing must not rewrite a
    record that is already terminal."""
    coordinator.halt_workflow(running_run["wf"])
    coordinator.runs_to_kill([running_run["run"]])
    first = client.get(f"/runs/{running_run['run']}").json()
    coordinator.runs_to_kill([running_run["run"]])
    assert client.get(f"/runs/{running_run['run']}").json()["finished_at"] == first["finished_at"]


# --- the worker is told, over the channel it already uses -------------------

def test_the_heartbeat_carries_the_kill_list(running_run):
    coordinator.halt_workflow(running_run["wf"])
    r = client.post("/worker/heartbeat", headers=conftest.svid_header(
        conftest.WORKER_SVID), json={
        "worker_id": "w1", "slots": 2, "slots_free": 1,
        "running": [running_run["run"]],
    })
    assert r.status_code == 200
    assert running_run["run"] in r.json()["kill"]


def test_the_heartbeat_kill_list_is_empty_when_nothing_is_condemned(running_run):
    r = client.post("/worker/heartbeat", headers=conftest.svid_header(
        conftest.WORKER_SVID), json={
        "worker_id": "w1", "slots": 2, "slots_free": 1,
        "running": [running_run["run"]],
    })
    assert r.json()["kill"] == []


# --- destroying a run destroys the work it started --------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_kill_takes_the_whole_process_tree_not_just_the_runner():
    """The bug this pins: an agent's real work happens in processes the runner
    SPAWNED (the model CLI, and every shell command it runs). Killing only the
    runner's pid leaves those alive with no supervisor, no TTL and no halt poll
    -- a kill switch that stops the accounting and not the agent.

    Stand up that exact shape: a parent that spawns a long-lived child, then
    kill through the daemon and require both to be gone.
    """
    parent = subprocess.Popen(
        ["/bin/sh", "-c", "sleep 300 & echo $! ; wait"],
        stdout=subprocess.PIPE, text=True,
        start_new_session=True,   # the same isolation the daemon gives a run
    )
    child_pid = int(parent.stdout.readline().strip())
    assert _alive(child_pid), "the spawned child should be running"

    daemon = Daemon()
    daemon.procs["run-x"] = parent
    daemon.kill(["run-x"])

    _wait_gone(parent.pid)
    _wait_gone(child_pid)
    assert not _alive(child_pid), "the agent's own child process survived the kill"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _wait_gone(pid: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and _alive(pid):
        time.sleep(0.05)
        try:
            os.waitpid(pid, os.WNOHANG)   # reap ours so it is not left a zombie
        except ChildProcessError:
            pass


@pytest.mark.parametrize("shape", ["host", "container", "pod"])
def test_every_launch_path_gives_the_run_its_own_process_group(monkeypatch, shape):
    """The property the kill depends on, asserted at the REAL launch site.

    The tree test below injects its own Popen, so it proves killpg works given a
    new session -- not that launch() creates one. That gap let a live bug
    through: the sandbox branch had no start_new_session, so the docker client
    inherited the DAEMON's process group, and killing 'the run' would have
    signalled the daemon and every other run on the worker. Under the production
    profile, which requires the sandbox, that was the only path that ran.

    Every shape is covered, including the pod's SECOND container: an agent
    container launched into the daemon's own group would put the same footgun
    back, one container along from where it was found.
    """
    import andyur.daemon.daemon as mod
    from andyur.daemon import orchestrator
    monkeypatch.setattr(orchestrator, "_sandbox_argv",
                        lambda *a, **kw: ["/bin/sh", "-c", "sleep 30"])
    monkeypatch.setattr(orchestrator, "_agent_argv",
                        lambda *a, **kw: ["/bin/sh", "-c", "sleep 30"])
    monkeypatch.setattr(orchestrator.identity, "runner_launch_env",
                        lambda *a, **kw: dict(os.environ))
    monkeypatch.setattr(orchestrator.identity, "role_python", lambda role: "/bin/sh")
    monkeypatch.setattr(orchestrator, "PROJECT_ROOT", "/tmp")
    monkeypatch.setattr(mod, "RUNLOG_DIR", pathlib.Path(tempfile.mkdtemp()))
    if shape == "host":
        monkeypatch.setattr(orchestrator.subprocess, "Popen",
                            _recording_popen(orchestrator))
    d = mod.Daemon()
    d.orch = {"host": orchestrator.HostOrchestrator,
              "container": orchestrator.ContainerOrchestrator,
              "pod": orchestrator.PodOrchestrator}[shape]()
    if shape == "pod":
        # the fake sidecar is a `sleep`, not a container docker can inspect
        monkeypatch.setattr(orchestrator.PodOrchestrator, "_wait_until_running",
                            lambda self, name, deadline, proc=None: True)
        # O1 per-run network ops would hit real docker against the fake sidecar;
        # this test is about process groups, not networking, so stub them.
        monkeypatch.setattr(orchestrator, "_net_create", lambda name: True)
        monkeypatch.setattr(orchestrator, "_net_connect",
                            lambda name, container, alias: True)
        monkeypatch.setattr(orchestrator, "_net_rm", lambda name: None)
    extra = []
    try:
        d.launch("run-pg", "alice")
        proc = d.procs["run-pg"]
        assert os.getpgid(proc.pid) != os.getpgid(0), (
            "the run shares the daemon's process group; killing it would kill "
            "the daemon and every other run on this worker")
        if shape == "pod":
            agent_proc = d.orch._agent_procs["run-pg"]
            extra.append(agent_proc)
            assert os.getpgid(agent_proc.pid) != os.getpgid(0), (
                "the pod's AGENT container shares the daemon's process group")
    finally:
        for p in extra:
            try:
                if os.getpgid(p.pid) != os.getpgid(0):
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                else:
                    p.kill()
            except (ProcessLookupError, PermissionError):
                pass
        # Never group-kill our own group. If the property under test is broken,
        # the child IS in pytest's group, and cleaning up with killpg would kill
        # the test runner -- the same mistake this test exists to catch, made by
        # the test. A broken property must fail an assertion, not the process.
        for p in d.procs.values():
            try:
                if os.getpgid(p.pid) != os.getpgid(0):
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                else:
                    p.kill()
            except (ProcessLookupError, PermissionError):
                pass


def _recording_popen(mod):
    real = mod.subprocess.Popen

    def popen(argv, **kw):
        return real(["/bin/sh", "-c", "sleep 30"], **kw)

    return popen


def test_a_run_that_shares_the_daemons_group_is_never_group_killed(monkeypatch):
    """Defence in depth for the bug above. If a launch path ever forgets the new
    session again, the kill must refuse rather than take the platform down: a
    containment mechanism that can kill the daemon is worse than the gap it
    closes."""
    proc = subprocess.Popen(["/bin/sh", "-c", "sleep 30"])   # NO new session
    daemon = Daemon()
    daemon.procs["run-shared"] = proc
    try:
        assert os.getpgid(proc.pid) == os.getpgid(0)
        daemon.kill(["run-shared"])
        assert os.getpgid(0)          # we are still alive
        proc.wait(timeout=5)          # and the run itself was still stopped
    finally:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def test_killing_a_run_the_daemon_does_not_own_is_not_an_error():
    """A container can outlive the daemon that launched it (daemon restart, or a
    second worker on the same host). The kill must still be attempted and must
    not take the daemon down with an exception."""
    Daemon().kill(["run-not-here"])


def test_kill_survives_a_process_that_already_exited():
    proc = subprocess.Popen(["/bin/sh", "-c", "exit 0"], start_new_session=True)
    proc.wait()
    daemon = Daemon()
    daemon.procs["run-y"] = proc
    daemon.kill(["run-y"])   # must not raise ProcessLookupError


# --- one number, not two ----------------------------------------------------

def test_the_heartbeat_carries_the_servers_run_ttl(running_run):
    """The server reaps a run by ITS ttl while the worker used to hand the
    container its own. A worker configured higher meant healthy long runs were
    reaped as hung -- and now that a terminal record marks a run for
    destruction, that mismatch would escalate from a wrong status line to a
    SIGKILL mid-execution. So the server's number is the number."""
    r = client.post("/worker/heartbeat", headers=conftest.svid_header(
        conftest.WORKER_SVID), json={
        "worker_id": "w1", "slots": 2, "slots_free": 1, "running": [],
    })
    from andyur.server.heartbeat import RUN_TTL_SECONDS
    assert r.json()["run_ttl"] == RUN_TTL_SECONDS


def test_the_daemon_adopts_the_servers_ttl_over_its_own(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setenv("ANDYUR_RUN_TTL_SECONDS", "60")
    argv = orchestrator._sandbox_argv("alice", "run-1", server_run_ttl=4242)
    env = [argv[i + 1] for i, v in enumerate(argv) if v == "-e"]
    assert "ANDYUR_RUN_TTL_SECONDS=4242" in env
    assert env.index("ANDYUR_RUN_TTL_SECONDS=4242") > env.index("ANDYUR_RUN_TTL_SECONDS=60"), \
        "the server's value must be set last so it wins"


def test_the_daemon_hands_the_servers_ttl_to_the_orchestrator(monkeypatch, tmp_path):
    """The half the argv test cannot see. The TTL is no longer read from a module
    global by the argv builder, it is passed in -- so a daemon that stopped
    forwarding it would leave the argv test green while every container ran on
    its own idea of when the run is over."""
    import andyur.daemon.daemon as mod
    from andyur.daemon import orchestrator
    monkeypatch.setattr(mod, "SERVER_RUN_TTL", 4242)
    monkeypatch.setattr(mod, "RUNLOG_DIR", tmp_path)
    seen = {}

    class _Spy(orchestrator.Orchestrator):
        name = "spy"

        def launch(self, spec, logfile):
            seen["spec"] = spec
            return subprocess.Popen(["/bin/sh", "-c", "exit 0"])

        def kill(self, run_ids):
            pass

    d = mod.Daemon()
    d.orch = _Spy()
    d.launch("run-1", "alice")
    assert seen["spec"].server_run_ttl == 4242


def test_the_worker_reports_its_profile(running_run):
    """A dev-profile worker attached to a prod control plane runs every agent
    unsandboxed with the open internet, and nothing else would say so."""
    from andyur.daemon.daemon import Daemon
    import asyncio

    sent = {}

    class _Api:
        async def post(self, path, json=None):
            sent.update(json)

            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return {"assignments": [], "kill": [], "heartbeat_interval": 10}
            return _R()

    asyncio.run(Daemon().heartbeat(_Api()))
    assert "profile" in sent


# --- the liveness endpoint is not an oracle ---------------------------------

def test_run_liveness_needs_the_runs_own_credential(running_run):
    """'Is this run executing right now' for any id is target selection. Run ids
    travel through tasks, messages and delegation, so 'you would need the id'
    was too weak a defence to rest on."""
    from andyur.server import runtoken as rt
    assert client.get(f"/runs/{running_run['run']}/live").status_code == 401

    good = rt.mint("alice", running_run["run"], running_run["wf"],
                   purpose=rt.PURPOSE_BROKER)
    r = client.get(f"/runs/{running_run['run']}/live",
                   headers={"X-Andyur-Run-Token": good})
    assert r.status_code == 200 and r.json()["live"] is True

    other = rt.mint("alice", "some-other-run", running_run["wf"],
                    purpose=rt.PURPOSE_BROKER)
    assert client.get(f"/runs/{running_run['run']}/live",
                      headers={"X-Andyur-Run-Token": other}).status_code == 401


def test_a_control_plane_run_token_cannot_ask_about_liveness(running_run):
    """The credential kept out of the agent's reach is not the one used here."""
    from andyur.server import runtoken as rt
    cp = rt.mint("alice", running_run["run"], running_run["wf"])   # PURPOSE_RUN
    assert client.get(f"/runs/{running_run['run']}/live",
                      headers={"X-Andyur-Run-Token": cp}).status_code == 401


# --- the fixes that were claimed but not delivered --------------------------

def test_a_condemned_run_is_never_dropped_by_the_report_cap(running_run):
    """A cap alone turned a resource limit into a silent kill-switch failure: a
    condemned run past the cutoff was never killed AND never logged, and the
    list is influenceable by what a worker reports."""
    coordinator.halt_workflow(running_run["wf"])
    padded = [f"junk-{i}" for i in range(1200)] + [running_run["run"]]
    doomed = coordinator.runs_to_kill(padded)
    assert running_run["run"] in doomed


def test_the_worker_profile_actually_reaches_the_server():
    """It was being sent and silently dropped, because pydantic ignores unknown
    fields. The assurance in the docs was worth nothing until this existed."""
    body = app_module.HeartbeatBody(
        worker_id="w1", slots=1, slots_free=1, running=[], profile="dev")
    assert body.profile == "dev"


@pytest.mark.parametrize("body", [
    "not json at all",
    "",
    "[1, 2, 3]",
])
def test_a_broken_control_plane_does_not_kill_the_worker(monkeypatch, body):
    """These reached `resp.json()` outside the try and took the daemon down. A
    control plane answering nonsense is a broken control plane, not a reason for
    every worker on the fleet to exit."""
    import asyncio
    import json as _json

    class _Api:
        async def post(self, path, json=None):
            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return _json.loads(body)   # raises for the first two
            return _R()

    asyncio.run(Daemon().heartbeat(_Api()))   # must simply return


def test_a_malformed_assignment_costs_one_run_not_the_worker(monkeypatch):
    import asyncio

    class _Api:
        async def post(self, path, json=None):
            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return {"assignments": [{"agent": "alice"}],   # no 'id'
                            "kill": [], "heartbeat_interval": 10}
            return _R()

    asyncio.run(Daemon().heartbeat(_Api()))


def test_nan_does_not_win_the_heartbeat_clamp():
    """NaN survives float() and loses every comparison, so a naive clamp returns
    the MAXIMUM: the worst kill latency, reachable by sending nonsense."""
    from andyur.daemon.daemon import _clamp_interval, HEARTBEAT_INTERVAL, HEARTBEAT_MAX
    assert _clamp_interval(float("nan")) == HEARTBEAT_INTERVAL
    assert _clamp_interval(float("nan")) != HEARTBEAT_MAX
    assert _clamp_interval(86400) == HEARTBEAT_MAX
    assert _clamp_interval(-5) >= 1.0
    assert _clamp_interval("soon") == HEARTBEAT_INTERVAL


def test_adopted_run_ids_must_look_like_run_ids(monkeypatch):
    """A container name is attacker-influenceable on a shared host, and these ids
    become SQL bind parameters, kill targets and a regex. One carrying a newline
    injected extra run ids into the worker's report, which the server then
    finalized as if they were real runs."""
    import andyur.daemon.daemon as mod
    from andyur.daemon import orchestrator

    class _Res:
        returncode = 0
        stdout = ("andyur-run-good-1\n"
                  "andyur-run-bad id with spaces\n"
                  "andyur-run-\n"
                  "totally-unrelated-container\n"
                  "andyur-run-also-good_2\n")

    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *a, **kw: _Res())
    d = Daemon()
    d.orch = orchestrator.ContainerOrchestrator()
    assert d.adopted_runs() == ["also-good_2", "good-1"]


def test_adopted_runs_occupy_capacity(monkeypatch):
    """Reporting an adopted run as executing while not counting it as busy told
    the server this worker was free for work it was already doing, so every
    daemon restart overcommitted the host."""
    import asyncio
    import andyur.daemon.daemon as mod
    monkeypatch.setattr(mod, "SLOTS", 2)
    d = Daemon()
    monkeypatch.setattr(d, "adopted_runs", lambda: ["a1", "a2", "a3"])
    sent = {}

    class _Api:
        async def post(self, path, json=None):
            sent.update(json)

            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return {"assignments": [], "kill": []}
            return _R()

    asyncio.run(d.heartbeat(_Api()))
    assert sent["slots_free"] == 0
    assert len(sent["running"]) == 3


# --- round 3: the fixes to the fixes ----------------------------------------

def test_a_stopped_container_is_not_adopted(monkeypatch):
    """`docker ps -a` listed EXITED and CREATED containers too. They are not
    executing, but they were adopted, reported in flight, subtracted from free
    slots, and condemned forever -- docker kill cannot kill a stopped container,
    so nothing removed them and a worker with two leftovers had zero capacity for
    good. A Docker restart is enough to produce them."""
    import andyur.daemon.daemon as mod
    from andyur.daemon import orchestrator
    seen = {}

    class _Res:
        returncode = 0
        stdout = "andyur-run-alive\n"

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return _Res()

    monkeypatch.setattr(orchestrator.subprocess, "run", fake_run)
    d = Daemon()
    d.orch = orchestrator.ContainerOrchestrator()
    assert d.adopted_runs() == ["alive"]
    assert "-a" not in seen["argv"], "adoption must list running containers only"


@pytest.mark.parametrize("assignments", [5, True, 1.5])
def test_a_non_iterable_assignments_field_does_not_kill_the_worker(assignments):
    """The previous round guarded the kill list and the body, and left the
    iteration itself unprotected: a scalar raises before the per-item try is
    ever reached, and the exception walks out of heartbeat() to daemon exit."""
    import asyncio

    class _Api:
        async def post(self, path, json=None):
            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return {"assignments": assignments, "kill": []}
            return _R()

    asyncio.run(Daemon().heartbeat(_Api()))


def test_condemning_a_large_batch_is_one_connection(running_run, monkeypatch):
    """finish_run per run opened a connection each, putting seconds of
    synchronous database work inside a heartbeat every worker makes every ten
    seconds. On Postgres it is N sequential un-pooled connects in one request."""
    from andyur import db
    coordinator.halt_workflow(running_run["wf"])
    connects = {"n": 0}
    real = db.connect

    def counting_connect(*a, **kw):
        connects["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(db, "connect", counting_connect)
    monkeypatch.setattr(coordinator.db, "connect", counting_connect)
    coordinator.runs_to_kill([running_run["run"]] + [f"ghost-{i}" for i in range(50)])
    assert connects["n"] <= 3, f"{connects['n']} connections for one batch"


def test_the_whole_batch_is_one_kill_call(monkeypatch):
    """The beat's cost must not scale with the number of condemned runs.

    It used to spawn one `docker kill` per run, so twenty condemned runs took
    the sum of twenty subprocess timeouts -- past the 45s worker-stale window,
    at which point the server declares the worker dead and requeues runs whose
    containers are still executing. Batching is what removes the cap, the
    dedicated thread pool, and the per-run error handling that grew around it.
    """
    import asyncio

    calls = []
    d = Daemon()
    monkeypatch.setattr(d, "kill", calls.append)

    class _Api:
        async def post(self, path, json=None):
            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return {"assignments": [], "kill": [f"r{i}" for i in range(50)]}
            return _R()

    asyncio.run(d.heartbeat(_Api()))
    assert len(calls) == 1, f"{len(calls)} kill calls for one beat"
    assert len(calls[0]) == 50, "the batch lost runs"


def test_the_beat_survives_a_kill_that_raises(monkeypatch):
    """docker missing from PATH raises FileNotFoundError, which is not a signal
    error. One broken batch must not take the worker down."""
    import asyncio

    d = Daemon()

    def boom(run_ids):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(d, "kill", boom)

    class _Api:
        async def post(self, path, json=None):
            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return {"assignments": [], "kill": ["r1"]}
            return _R()

    asyncio.run(d.heartbeat(_Api()))    # must simply return

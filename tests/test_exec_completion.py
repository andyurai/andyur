"""Daemon-owned completion of a stock exec/v1 run (ADR-011 D3), tested against
the REAL server auth.

A runtime-v1 agent reports its own completion from inside the run. A stock
exec/v1 workload reports nothing -- it starts, works, writes to stdout and
exits -- so the daemon reads the container's exit at the one boundary it owns
and reports the finish on the run's behalf. The finish is worker-authenticated
(the workload holds no run token), so these tests drive it through the actual
POST /runs/{id}/worker-finish route and require(WORKER), not a faked client --
the gap that let an earlier version ship a finish that could never land.
"""

import asyncio
import time
from types import SimpleNamespace

import httpx

from andyur import config, db
from andyur.daemon import daemon as daemon_module
from andyur.daemon.daemon import Daemon
from andyur.daemon.kubernetes_api import OfficialKubernetesApi
from andyur.daemon.orchestrator import KubernetesOrchestrator, _ExecRun
from andyur.redact import redact
from andyur.execlifecycle import capture_output, TRUNCATION_MARKER
from andyur.server.app import app
from starlette.testclient import TestClient

import conftest

client = TestClient(app)


def _make_run(env, run_id="run-1", worker="worker-A", state="running",
              agent="stock", summary=None, error=None):
    env.agent(agent)
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, run_type, state, reason, created_at, "
            "worker, summary, error) VALUES (?, ?, 'work', ?, '', ?, ?, ?, ?)",
            (run_id, agent, state, db.utcnow(), worker, summary, error))
    return run_id


def _run_row(run_id):
    with db.connect() as c:
        return c.execute(
            "SELECT state, summary, error FROM runs WHERE id = ?",
            (run_id,)).fetchone()


# --- H1: the worker-finish route, through require(WORKER) and finish_run ------

def test_owning_worker_finishes_the_run_done_with_the_summary_stored(env):
    _make_run(env, "r", worker="w-A", state="running")
    resp = client.post("/runs/r/worker-finish",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w-A", "summary": "root cause: disk",
                             "error": None})
    assert resp.status_code == 200 and resp.json()["state"] == "done"
    row = _run_row("r")
    assert row["state"] == "done" and row["summary"] == "root cause: disk"


def test_a_nonzero_exit_error_finishes_the_run_failed(env):
    _make_run(env, "r", worker="w-A", state="running")
    resp = client.post("/runs/r/worker-finish",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w-A", "summary": "boom",
                             "error": "the workload process exited with code 3"})
    assert resp.status_code == 200 and resp.json()["state"] == "failed"
    assert _run_row("r")["state"] == "failed"


def test_a_body_naming_a_non_owner_worker_is_403(env):
    # (b1): the worker_id in the body is NOT the run's owner -> 403 naming the
    # owner, and the run row is untouched.
    _make_run(env, "r", worker="w-A", state="running")
    resp = client.post("/runs/r/worker-finish",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w-B", "summary": "x", "error": None})
    # 403 names the refused CALLER (w-B), not the owner -- a non-owner is not
    # told which worker holds the run. The run row is untouched.
    assert resp.status_code == 403 and "w-B" in resp.json()["detail"]
    assert _run_row("r")["state"] == "running"


def test_a_different_worker_naming_the_owner_still_finishes_the_run(env):
    # (b2): the shared-role model's documented limit. Any authenticated worker
    # that names the OWNER's id in the body succeeds, because worker identity is
    # self-asserted (identity.role_of collapses the whole pool to "worker"; the
    # heartbeat already trusts body.worker_id). This is NOT resistance to a
    # malicious worker -- nothing on this boundary is -- and it is tracked open
    # in ROADMAP.md. This test goes RED the day per-worker SVIDs
    # land and the route binds ownership to a proven identity, which is exactly
    # when someone must revisit it.
    _make_run(env, "r", worker="w-A", state="running")
    resp = client.post("/runs/r/worker-finish",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w-A", "summary": "s", "error": None})
    assert resp.status_code == 200
    assert _run_row("r")["state"] == "done"


def test_an_already_finalized_run_is_409(env):
    # (c): finish_run's state guard is the one decider; a second finish is 409,
    # which the daemon's post_finish treats as CONFIRMED.
    _make_run(env, "r", worker="w-A", state="done", summary="already")
    resp = client.post("/runs/r/worker-finish",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w-A", "summary": "again", "error": None})
    assert resp.status_code == 409
    assert _run_row("r")["summary"] == "already"   # untouched


def test_worker_finish_requires_the_worker_role(env):
    # (d): the route is worker-role-gated. A missing bearer is 401 and a
    # non-worker identity (here the operator) is 403 -- both refused, and the run
    # is untouched. (The suite's TestClient injects the operator SVID unless a
    # request opts out, so NO_AUTH surfaces as the wrong-role 403 rather than the
    # bare-missing-bearer 401; either way it is not the worker, so it cannot
    # finish.)
    _make_run(env, "r", worker="w-A", state="running")
    resp = client.post("/runs/r/worker-finish", headers=conftest.NO_AUTH,
                       json={"worker_id": "w-A", "summary": "x", "error": None})
    assert resp.status_code in (401, 403)
    assert _run_row("r")["state"] == "running"
    op = client.post("/runs/r/worker-finish",
                     headers=conftest.svid_header(conftest.OPERATOR_SVID),
                     json={"worker_id": "w-A", "summary": "x", "error": None})
    assert op.status_code == 403
    assert _run_row("r")["state"] == "running"


def test_worker_finish_on_an_unknown_run_is_404(env):
    resp = client.post("/runs/nope/worker-finish",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w-A", "summary": "x", "error": None})
    assert resp.status_code == 404


# --- H1 end to end: the daemon reaper drives the real route -------------------

class FakeProc:
    pid = 0

    def __init__(self, code=0):
        self._code = code

    def poll(self):
        return self._code


class RecordingOrch:
    """The orchestrator seam the reaper uses, recording call ORDER so a test can
    prove the finish is reported before the Pod is deleted."""

    name = "kubernetes"

    def __init__(self, completion):
        self._completion = completion
        self.calls = []

    def read_exec_completion(self, run_id):
        self.calls.append(("read", run_id))
        if isinstance(self._completion, Exception):
            raise self._completion
        return self._completion

    def cleanup(self, run_id):
        self.calls.append(("cleanup", run_id))


def _daemon(orch, worker_id="w-A"):
    d = Daemon.__new__(Daemon)
    d.procs = {}
    d.orch = orch
    d.worker_id = worker_id
    d.stopping = False
    return d


def test_reaper_finalizes_a_stock_run_end_to_end_over_the_real_route(env):
    _make_run(env, "r", worker="w-A", state="running")
    orch = RecordingOrch((0, "opensre: unable to determine root cause\n", None,
                          1 << 20))
    d = _daemon(orch, worker_id="w-A")
    d.procs["r"] = FakeProc(0)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
                transport=transport, base_url="http://test",
                headers=conftest.svid_header(conftest.WORKER_SVID)) as api:
            await d.reap(api)

    asyncio.run(go())

    row = _run_row("r")
    assert row["state"] == "done"            # exit 0 -> completed (D3)
    assert "unable to determine root cause" in row["summary"]
    # reported BEFORE the Pod was deleted, and the run reaped afterwards
    assert orch.calls == [("read", "r"), ("cleanup", "r")]
    assert d.procs == {}


def test_reaper_treats_a_real_403_as_terminal_and_reaps_the_pod(env):
    """R LOW (#20): the 403-terminal rule driven by the REAL route, not a faked
    post_finish. The run was reassigned to w-B; w-A's reaper reads the exit and
    posts worker-finish, the server refuses it 403 by name, post_finish treats
    that as terminal (not ours to finish), and the reaper still deletes the
    Pod -- it must not keep retrying a decision. The row is untouched: w-B
    reports that run."""
    _make_run(env, "r", worker="w-B", state="running")
    orch = RecordingOrch((0, "output of a run that is no longer ours\n", None,
                          1 << 20))
    d = _daemon(orch, worker_id="w-A")
    d.procs["r"] = FakeProc(0)
    posted = []

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
                transport=transport, base_url="http://test",
                headers=conftest.svid_header(conftest.WORKER_SVID)) as api:
            real_post = api.post

            async def spy(path, **kw):
                resp = await real_post(path, **kw)
                posted.append((path, resp.status_code))
                return resp
            api.post = spy
            await d.reap(api)

    asyncio.run(go())
    assert posted == [("/runs/r/worker-finish", 403)]       # ONE call, a real 403
    row = _run_row("r")
    assert row["state"] == "running" and row["summary"] is None
    assert orch.calls == [("read", "r"), ("cleanup", "r")]  # reaped anyway
    assert d.procs == {}


def test_reaper_records_a_worker_svid_workload_failure(env):
    _make_run(env, "r", worker="w-A", state="running")
    d = _daemon(RecordingOrch((137, "", None, 1 << 20)), worker_id="w-A")
    d.procs["r"] = FakeProc(1)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
                transport=transport, base_url="http://test",
                headers=conftest.svid_header(conftest.WORKER_SVID)) as api:
            await d.reap(api)

    asyncio.run(go())
    row = _run_row("r")
    assert row["state"] == "failed"
    assert "137" in (row["error"] or "")


# --- daemon reap logic (fake finish; exercises the reaper, not the auth) ------

def _fake_finish(monkeypatch, result=(True, "")):
    posted = []

    async def fake_post_finish(api, run_id, *, summary, error, path=None,
                               extra=None, **kw):
        posted.append({"run_id": run_id, "summary": summary, "error": error,
                       "path": path, "extra": extra})
        return result

    monkeypatch.setattr(daemon_module, "post_finish", fake_post_finish)
    return posted


def test_reaper_posts_to_worker_finish_with_the_worker_id(monkeypatch):
    posted = _fake_finish(monkeypatch)
    d = _daemon(RecordingOrch((0, "out\n", None, 1 << 20)), worker_id="w-A")
    d.procs["r"] = FakeProc(0)
    asyncio.run(d.reap(object()))
    assert posted[0]["path"] == "/runs/r/worker-finish"
    assert posted[0]["extra"] == {"worker_id": "w-A"}
    assert posted[0]["error"] is None


def test_an_unconfirmed_finish_keeps_the_pod_for_a_retry(monkeypatch):
    _fake_finish(monkeypatch, result=(False, "server 503"))
    orch = RecordingOrch((0, "out\n", None, 1 << 20))
    d = _daemon(orch, worker_id="w-A")
    d.procs["r"] = FakeProc(0)
    asyncio.run(d.reap(object()))
    # NOT reaped: the outcome never landed, so the Pod (its evidence) stays.
    assert "r" in d.procs
    assert ("cleanup", "r") not in orch.calls


def test_a_run_that_reports_itself_is_reaped_without_a_worker_finish(monkeypatch):
    posted = _fake_finish(monkeypatch)
    orch = RecordingOrch(None)               # runtime-v1: self-reports
    d = _daemon(orch, worker_id="w-A")
    d.procs["r"] = FakeProc(0)
    asyncio.run(d.reap(object()))
    assert posted == []                      # daemon posts nothing
    assert orch.calls == [("read", "r"), ("cleanup", "r")]
    assert d.procs == {}


def test_a_raising_read_does_not_crash_the_loop_and_keeps_the_pod(monkeypatch):
    posted = _fake_finish(monkeypatch)
    orch = RecordingOrch(RuntimeError("kube API 503"))
    d = _daemon(orch, worker_id="w-A")
    d.procs["r"] = FakeProc(0)
    asyncio.run(d.reap(object()))            # must NOT raise
    assert posted == []
    assert "r" in d.procs                    # left for a retry
    assert ("cleanup", "r") not in orch.calls


def test_the_retention_ceiling_reaches_the_daemon(monkeypatch):
    monkeypatch.setattr(config, "OUTPUT_RETENTION_MAX_BYTES", 64)
    posted = _fake_finish(monkeypatch)
    # emission cap is huge, so retention (64) is the effective bound.
    d = _daemon(RecordingOrch((0, "x" * 5000, None, 1 << 20)), worker_id="w-A")
    d.procs["r"] = FakeProc(0)
    asyncio.run(d.reap(object()))
    assert len(posted[0]["summary"].encode("utf-8")) <= 64


# --- orchestrator.read_exec_completion ----------------------------------------

class FakeApi:
    def __init__(self, exit_code=0, logs="all clear\n"):
        self.exit_code = exit_code
        self.logs = logs
        self.log_reads = []

    def read_container_exit(self, namespace, name, container):
        return self.exit_code

    def pod_logs(self, namespace, name, tail_lines=80, limit_bytes=None):
        self.log_reads.append({"pod": name, "limit_bytes": limit_bytes,
                               "tail_lines": tail_lines})
        return self.logs


class FakeController:
    namespace = "andyur-runs"

    def __init__(self, api):
        self.api = api

    def list_running_generations(self):
        return []

    def delete_generation(self, run_id, generation):
        pass


def _orch(api):
    return KubernetesOrchestrator(FakeController(api))


def _track(orch, run_id="r", **kw):
    orch._exec_runs[run_id] = _ExecRun(
        pod="pod-agent", container="agent",
        output_max_bytes=kw.get("output_max_bytes", 1 << 20),
        capture_stdout=kw.get("capture_stdout", "capture"),
        capture_stderr=kw.get("capture_stderr", "capture"))
    orch._generations[run_id] = "gen-1"


def test_read_exec_completion_bounds_the_log_read_at_the_api(monkeypatch):
    monkeypatch.setattr(config, "OUTPUT_RETENTION_MAX_BYTES", 1000)
    api = FakeApi(exit_code=0, logs="hello\n")
    orch = _orch(api)
    _track(orch, "r", output_max_bytes=500)      # emission 500 < retention 1000
    exit_code, stdout, stderr, out_max = orch.read_exec_completion("r")
    assert exit_code == 0 and stdout == "hello\n" and stderr is None
    assert out_max == 500
    # the READ was bounded to min(500, 1000) + margin, not unbounded
    assert api.log_reads[0]["limit_bytes"] == 500 + 8192
    # ... and asked for the HEAD window: tail_lines=None reaches the read at
    # THIS layer (H6; pinned at the pod_logs layer alone before -- R LOW, #20)
    assert api.log_reads[0]["tail_lines"] is None
    assert "tail_lines" in api.log_reads[0]          # recorded, not defaulted away


def test_an_unreadable_log_is_named_in_the_daemon_log_not_swallowed(monkeypatch):
    """H5's log-the-exception, pinned (R LOW, #20): a pods/log 403 (or any read
    failure) yields an EMPTY capture, and the daemon log names the failure and
    its consequence. The run itself still completes (exit code is returned)."""
    from andyur.daemon import orchestrator as orchestrator_module
    lines = []
    monkeypatch.setattr(orchestrator_module, "log", lines.append)

    class Forbidden(FakeApi):
        def pod_logs(self, namespace, name, tail_lines=80, limit_bytes=None):
            raise PermissionError("(403) Forbidden: pods/log")

    orch = _orch(Forbidden(exit_code=0, logs="never read\n"))
    _track(orch, "r")
    exit_code, stdout, stderr, _ = orch.read_exec_completion("r")
    assert (exit_code, stdout, stderr) == (0, "", None)
    [line] = lines
    assert line == ("run r: reading exec/v1 output failed "
                    "(PermissionError: (403) Forbidden: pods/log); summary will be empty")


def test_read_exec_completion_is_none_for_a_run_not_owned():
    assert _orch(FakeApi()).read_exec_completion("nope") is None


def test_a_discarded_stdout_is_never_read():
    api = FakeApi(logs="dropped diagnostics")
    orch = _orch(api)
    _track(orch, "r", capture_stdout="discard")
    _, stdout, _, _ = orch.read_exec_completion("r")
    assert stdout is None and api.log_reads == []


def test_cleanup_forgets_the_exec_run():
    orch = _orch(FakeApi())
    _track(orch, "r")
    orch.cleanup("r")
    assert orch.read_exec_completion("r") is None


def test_base_orchestrator_owns_no_completion():
    from andyur.daemon.orchestrator import HostOrchestrator
    assert HostOrchestrator().read_exec_completion("r") is None


# --- read_container_exit: the container the exit is read from -----------------

def _api_with_pod(pod):
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    api._core = SimpleNamespace(
        read_namespaced_pod=lambda name, ns, **kw: pod)
    api._api_exception = _NeverRaised
    return api


class _NeverRaised(Exception):
    status = 0


def _status(name, terminated_code=None, running=False):
    if running:
        state = SimpleNamespace(terminated=None)
    else:
        state = SimpleNamespace(
            terminated=SimpleNamespace(exit_code=terminated_code))
    return SimpleNamespace(name=name, state=state)


def test_read_container_exit_reads_the_named_container_not_an_init_container():
    # init container terminated 0, the AGENT still running -> None (not 0).
    pod = SimpleNamespace(status=SimpleNamespace(
        init_container_statuses=[_status("init", terminated_code=0)],
        container_statuses=[_status("agent", running=True)]))
    assert _api_with_pod(pod).read_container_exit("ns", "p", "agent") is None


def test_read_container_exit_returns_the_agent_containers_code():
    pod = SimpleNamespace(status=SimpleNamespace(
        init_container_statuses=[_status("init", terminated_code=0)],
        container_statuses=[_status("agent", terminated_code=3)]))
    assert _api_with_pod(pod).read_container_exit("ns", "p", "agent") == 3


def test_read_container_exit_maps_oomkilled_to_137_not_none():
    pod = SimpleNamespace(status=SimpleNamespace(
        init_container_statuses=[],
        container_statuses=[_status("agent", terminated_code=137)]))
    assert _api_with_pod(pod).read_container_exit("ns", "p", "agent") == 137


# --- pod_logs: real bytes, not the client's bytes-repr quirk ------------------

def _api_with_log(body_bytes):
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    seen = {}

    def read_log(name, ns, **kw):
        seen.update(kw)
        return SimpleNamespace(data=body_bytes)

    api._core = SimpleNamespace(read_namespaced_pod_log=read_log)
    api._api_exception = _NeverRaised
    api._seen = seen
    return api


def test_pod_logs_returns_plain_text_not_a_bytes_repr():
    api = _api_with_log(b"plain\nline two\n")
    assert api.pod_logs("ns", "p") == "plain\nline two\n"
    assert api._seen.get("_preload_content") is False   # the load-bearing flag


def test_pod_logs_returns_a_json_line_verbatim_not_a_python_literal():
    api = _api_with_log(b'{"a":1}\n')
    assert api.pod_logs("ns", "p") == '{"a":1}\n'


def test_pod_logs_byte_bounds_locally_too():
    api = _api_with_log(b"abcdefghij")
    assert api.pod_logs("ns", "p", limit_bytes=4) == "abcd"


# --- H3/H4: redact stays linear, and the byte cut runs AFTER redaction --------

def test_capture_output_on_a_large_body_is_fast():
    # 200k letters, no secret. The old quadratic URL branch took ~7s at 80k;
    # linear must stay well under a second.
    start = time.monotonic()
    out = capture_output("a" * 200_000, None,
                         emission_max_bytes=1 << 20, retention_max_bytes=1 << 20)
    assert time.monotonic() - start < 1.0
    assert out == "a" * 200_000


def test_a_secret_straddling_the_byte_cut_cannot_survive_by_being_half_included():
    # The secret spans the truncation boundary: the part BEFORE the cut ("sk-ant-"
    # + 2 chars) is too short to match on its own, but the full 30-char token
    # does. Only redact-BEFORE-truncate removes it; truncate-then-redact leaves
    # the "sk-ant-.." head in place. bound 100 -> keep 49 cuts inside the token.
    body = "x" * 40 + "sk-ant-" + "S" * 30 + "y" * 40      # >100 bytes, straddles
    out = capture_output(body, None, emission_max_bytes=100, retention_max_bytes=100)
    assert "sk-ant-" not in out
    assert "<redacted>" in out


def test_the_final_cut_never_splits_a_multibyte_character():
    # bound 54 -> keep = 54 - marker(51) = 3 bytes on the MAIN truncate branch:
    # one 'é' (2 bytes) fits, the 3rd byte would split the next 'é'. The char-
    # boundary back-off must drop the lone continuation byte, or both
    # surrogateescape and errors='replace' die decoding the result.
    out = capture_output("é" * 100, None,
                         emission_max_bytes=54, retention_max_bytes=54)
    encoded = out.encode("utf-8")
    assert len(encoded) <= 54
    out.encode("utf-8").decode("utf-8")          # no partial char -> no error
    assert out.endswith(TRUNCATION_MARKER)


def test_pod_logs_sends_limit_bytes_and_no_tail_lines_on_the_exec_read():
    # H6: the exec read must send ONLY limitBytes (head window), never the
    # client's default tail_lines=80 (which would read the last 80 LINES).
    api = _api_with_log(b"whatever")
    api.pod_logs("ns", "p", tail_lines=None, limit_bytes=500)
    assert api._seen.get("limit_bytes") == 500
    assert "tail_lines" not in api._seen
    assert api._seen.get("_preload_content") is False


def test_pod_logs_replaces_invalid_utf8_rather_than_raising():
    api = _api_with_log(b"ok\xff\xfebad")
    out = api.pod_logs("ns", "p")
    assert out.startswith("ok") and out.endswith("bad") and "�" in out


# --- MED3: ownership is atomic (no TOCTOU), 403 is terminal --------------------

def test_worker_finish_run_will_not_finalize_a_run_owned_by_another_worker(env):
    from andyur.server import coordinator
    _make_run(env, "r", worker="w-A", state="running")
    # A run the server has (re)assigned to w-A cannot be finalized by w-B, even
    # though w-B is an authenticated worker: ownership is in the UPDATE's WHERE.
    assert coordinator.worker_finish_run("r", "w-B", "x", None) == "not_owner"
    assert _run_row("r")["state"] == "running"          # untouched
    assert coordinator.worker_finish_run("r", "w-A", "done", None) == "done"
    assert _run_row("r")["state"] == "done"


def test_the_reaper_treats_a_403_as_terminal_and_does_not_retry(monkeypatch):
    # A run reassigned to another worker 403s worker-finish. That is a decision,
    # not a transient blip: the reaper must stop (clean up), not hold the Pod.
    calls = {"n": 0}

    async def fake_post_finish(api, run_id, *, summary, error, attempts=3,
                               path=None, extra=None):
        calls["n"] += 1
        # post_finish itself decides 403 is terminal; emulate its contract.
        return True, ""

    monkeypatch.setattr(daemon_module, "post_finish", fake_post_finish)
    orch = RecordingOrch((0, "out\n", None, 1 << 20))
    d = _daemon(orch, worker_id="w-A")
    d.procs["r"] = FakeProc(0)
    asyncio.run(d.reap(object()))
    assert calls["n"] == 1                       # one attempt, then cleanup
    assert ("cleanup", "r") in orch.calls and d.procs == {}


# --- MED4: the finish does not block the heartbeat ----------------------------

def test_two_unconfirmed_finishes_do_not_stack_blocking_ahead_of_heartbeat(monkeypatch):
    # With attempts=1 the reaper makes ONE post per run per tick (the tick-level
    # retry keeps the Pod), so N unconfirmed runs cost N single attempts, not
    # N x (3 x 10s + 2s) -- which for two runs (64s) would exceed WORKER_STALE.
    attempts_seen = []

    async def fake_post_finish(api, run_id, *, summary, error, attempts=3,
                               path=None, extra=None):
        attempts_seen.append(attempts)
        return False, "server down"

    monkeypatch.setattr(daemon_module, "post_finish", fake_post_finish)
    d = _daemon(RecordingOrch((0, "o\n", None, 1 << 20)), worker_id="w-A")
    d.procs["r1"] = FakeProc(0)
    d.procs["r2"] = FakeProc(0)
    asyncio.run(d.reap(object()))
    assert attempts_seen == [1, 1]               # one attempt each, no 3x loop
    assert "r1" in d.procs and "r2" in d.procs    # kept for the next tick


# --- R MED-0 (PR #21): cleanup off the loop, and never out of reap ------------

class _CleanupOrch(RecordingOrch):
    def __init__(self, delay=0.0, raise_exc=None):
        super().__init__(None)              # not an exec/v1 run: no finish to post
        self.delay, self.raise_exc = delay, raise_exc

    def cleanup(self, run_id):
        super().cleanup(run_id)
        if self.delay:
            import time as _t
            _t.sleep(self.delay)
        if self.raise_exc:
            raise self.raise_exc


def test_reap_cleanup_runs_off_the_loop_so_the_heartbeat_keeps_cadence():
    """Test B: a 0.5s Pod delete inside cleanup must not stall a sibling
    coroutine on the same loop (it used to run inline and stalled the heartbeat
    for the whole DELETE_TIMEOUT per reaped run)."""
    d = _daemon(_CleanupOrch(delay=0.5))
    d.procs["r"] = FakeProc(0)
    gaps = []

    async def ticker(stop):
        import time as _t
        last = _t.monotonic()
        while not stop.is_set():
            await asyncio.sleep(0.01)
            now = _t.monotonic()
            gaps.append(now - last)
            last = now

    async def go():
        stop = asyncio.Event()
        t = asyncio.create_task(ticker(stop))
        await d.reap(None)
        stop.set()
        await t

    asyncio.run(go())
    assert d.procs == {} and ("cleanup", "r") in d.orch.calls
    assert max(gaps) < 0.1, f"loop stalled {max(gaps):.3f}s during cleanup"


def test_a_cleanup_timeout_never_escapes_reap():
    """Test C: delete_run_group past DELETE_TIMEOUT raises TimeoutError; it must
    be logged and the loop continue (it escaped reap and run() with the run
    already popped, its Lease claim unreleased)."""
    from unittest.mock import patch
    lines = []
    d = _daemon(_CleanupOrch(raise_exc=TimeoutError("Kubernetes run-group delete timed out")))
    d.procs["r"] = FakeProc(0)
    with patch("andyur.daemon.daemon.log", lines.append):
        asyncio.run(d.reap(None))
    assert d.procs == {}
    assert any("cleanup failed (TimeoutError" in l for l in lines), lines
    assert any(l == "run r exited with code 0" for l in lines)


def test_the_daemon_hands_the_assignments_model_to_the_governed_launcher(monkeypatch, tmp_path):
    """The one-line plumbing that makes services.model.name real: the
    assignment's `model` reaches RunSpec.model, which launch_governed turns
    into the exec/v1 facts. Pinned at the daemon, not only at the launcher."""
    from andyur.daemon import daemon as daemon_module
    monkeypatch.setattr(daemon_module, "RUNLOG_DIR", tmp_path)
    seen = {}

    class Orch:
        name = "kubernetes"
        def describe(self, run_id):
            return "fake placement"
        def launch_governed(self, spec, runtime, logfile):
            seen["spec"] = spec
            seen["runtime"] = runtime
            return FakeProc(None)

    d = _daemon(Orch(), worker_id="w-A")
    d.launch("r-model", "opensre-sre", None, "run-token", None, "headless",
             "agt_opensre", {"runtime_type": "container"}, None, '{"alert": 1}',
             "qwen3-andyur:latest")
    assert seen["spec"].model == "qwen3-andyur:latest"
    assert seen["spec"].run_input == '{"alert": 1}'
    assert seen["runtime"] == {"runtime_type": "container"}
    assert "r-model" in d.procs


def test_a_failed_launch_finishes_the_run_failed_by_name(monkeypatch):
    """A launch that raises never reaches procs, so nothing would ever reap it
    and no halt could reach it: the run sat `running` forever and its agent
    stayed non-idle (found live, 2026-08-26). The daemon now reports the
    failure through worker-finish, with the cause, as the run's outcome."""
    posted = _fake_finish(monkeypatch)
    d = _daemon(RecordingOrch(None), worker_id="w-A")

    def failing_launch(*a, **k):
        raise RuntimeError("run-group launch failed (attach 403); rollback also failed (403)")

    d.launch = failing_launch
    asyncio.run(d._launch_assignment(None, {"id": "r-fail", "agent": "opensre-sre"}))
    [p] = posted
    assert p["path"] == "/runs/r-fail/worker-finish"
    assert p["extra"] == {"worker_id": "w-A"}
    assert p["summary"] is None
    assert p["error"].startswith("launch failed: RuntimeError: run-group launch failed")


def test_a_failed_launch_is_logged_and_reported_redacted(monkeypatch):
    """The exception text of a failed launch can quote what the launcher was
    holding (a Secret's stringData, a token); the log line and the reported
    error are both redacted (R LOW)."""
    from andyur.daemon import daemon as daemon_module
    posted = _fake_finish(monkeypatch)
    lines = []
    monkeypatch.setattr(daemon_module, "log", lines.append)
    d = _daemon(RecordingOrch(None), worker_id="w-A")
    secret = "sk-ant-api03-" + "A" * 40

    def failing_launch(*a, **k):
        raise RuntimeError(f"apply failed for Secret with token {secret}")

    d.launch = failing_launch
    asyncio.run(d._launch_assignment(None, {"id": "r-leak", "agent": "opensre-sre"}))
    assert secret not in "\n".join(lines) and any("launch failed" in l for l in lines)
    assert secret not in posted[0]["error"] and posted[0]["error"].startswith("launch failed")



def test_the_heartbeat_returns_before_slow_launches_finish_and_still_completes_them(monkeypatch):
    """R LOW: launches are TRACKED tasks. Awaiting each inline serialised two
    slow image pulls behind each other and ahead of the next beat (past the
    45 s stale window). The beat returns while both launches are still running
    off the loop; both then complete under the daemon's tracking set."""
    import time as _t
    from andyur.daemon.daemon import Daemon
    d = Daemon()
    monkeypatch.setattr(d, "adopted_runs", lambda: [])
    done = []

    def slow_launch(run_id, *a, **k):
        _t.sleep(0.3)
        done.append(run_id)

    d.launch = slow_launch

    class _Api:
        async def post(self, path, json=None):
            class _R:
                status_code = 200
                def raise_for_status(self): pass
                def json(self): return {"assignments": [{"id": "r1", "agent": "a"},
                                                        {"id": "r2", "agent": "a"}], "kill": []}
            return _R()

    async def go():
        t0 = _t.monotonic()
        await d.heartbeat(_Api())
        beat = _t.monotonic() - t0
        pending = list(d._launches)
        assert len(pending) == 2 and done == []          # both in flight, neither awaited
        await asyncio.gather(*pending)
        return beat

    beat = asyncio.run(go())
    assert beat < 0.25, f"the beat waited on the launches ({beat:.2f}s)"
    assert sorted(done) == ["r1", "r2"] and d._launches == set()

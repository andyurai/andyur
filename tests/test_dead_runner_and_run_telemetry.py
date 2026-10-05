"""Two defects a real run surfaced, and a CLI crash that hid a third.

Both platform defects share a shape: something the daemon KNOWS is never said,
and the consequence appears somewhere else, later, looking like a different
problem.

  * A runner that dies before reporting leaves its run `pending` FOREVER. The
    agent is then pinned -- every later trigger answers 409 "agent is not idle"
    -- and no endpoint cancels a pending run, so the only way out is halting the
    workflow. The daemon holds the one fact nobody else has: the container
    exited, and with what code.
  * A run handed a collector it cannot reach retries forever. In production the
    endpoint is deliberately NOT rewritten to the host gateway (the run has no
    route there), so the default `localhost:4318` resolves to the run's own
    loopback and every run's log fills with connection-refused noise.
"""

import asyncio

import pytest

from andyur.daemon import daemon as daemon_mod
from andyur.daemon import orchestrator


# --- the run whose runner died without reporting ------------------------------

class _Proc:
    def __init__(self, code):
        self._code = code

    def poll(self):
        return self._code


class _Daemon:
    """The two reap collaborators, and nothing else."""

    def __init__(self, code, reported):
        self.procs = {"run-1": _Proc(code)}
        self.worker_id = "worker-a"
        self.orch = type("O", (), {"cleanup": staticmethod(lambda run_id: None)})()
        self._reported = reported
        self.finished = []

    async def _report_exec_completion(self, api, run_id):
        return self._reported

    def _cleanup_traced(self, run_id):
        self.cleaned = getattr(self, "cleaned", []) + [run_id]

    def _trace_contexts(self):
        return {}

    _report_dead_runner = daemon_mod.Daemon._report_dead_runner
    reap = daemon_mod.Daemon.reap
    reap_one = daemon_mod.Daemon.reap_one


def _reap(monkeypatch, *, code, reported, finish=(True, "ok")):
    posted = []

    async def fake_post_finish(api, run_id, **kwargs):
        posted.append({"run_id": run_id, **kwargs})
        return finish

    monkeypatch.setattr(daemon_mod, "post_finish", fake_post_finish)
    d = _Daemon(code, reported)
    asyncio.run(d.reap(api=object()))
    return posted


def test_a_runner_that_died_without_reporting_is_finished_by_the_worker(monkeypatch):
    """The fix. Without it the row stays pending and the agent is unusable."""
    posted = _reap(monkeypatch, code=1, reported=None)

    assert len(posted) == 1
    assert posted[0]["run_id"] == "run-1"
    assert posted[0]["path"] == "/runs/run-1/worker-finish"
    assert posted[0]["extra"] == {"worker_id": "worker-a"}
    assert posted[0]["error"], "a non-zero exit must carry an error"


def test_a_clean_exit_is_not_reported_as_a_failure(monkeypatch):
    """Exit 0 means the runner finished and said so. Reporting again would be
    the worker inventing an outcome it did not observe."""
    assert _reap(monkeypatch, code=0, reported=None) == []


def test_an_exec_run_is_left_to_its_own_reporter(monkeypatch):
    """`_report_exec_completion` returning True means the completion is already
    reported; a second report would be redundant at best."""
    assert _reap(monkeypatch, code=1, reported=True) == []


def test_the_report_is_best_effort_and_does_not_break_the_reap(monkeypatch):
    """A 409 -- the runner DID report and then exited non-zero -- is confirmed,
    and an unconfirmed report must not raise out of reap and stall the loop."""
    posted = _reap(monkeypatch, code=1, reported=None, finish=(False, "boom"))
    assert len(posted) == 1  # attempted, and reap completed anyway


def test_an_unconfirmed_report_keeps_the_runtime_and_is_retried(monkeypatch):
    """B+ ADVERSARIAL REVIEW (launch idempotency, H1/H4). The report followed
    cleanup, and cleanup releases the run's fence: a failed report -- or a
    worker dying between the two -- left a pending record with no fence, and
    the engine's retry was handed launch material and launched the run again.
    The outcome now lands BEFORE anything is released."""
    results = iter([(False, "503"), (True, "ok")])

    async def fake_post_finish(api, run_id, **kwargs):
        return next(results)

    monkeypatch.setattr(daemon_mod, "post_finish", fake_post_finish)
    d = _Daemon(1, None)
    assert asyncio.run(d.reap_one(object(), "run-1")) is None
    assert "run-1" in d.procs and getattr(d, "cleaned", []) == [], (
        "the runtime was released before its outcome was recorded")
    assert asyncio.run(d.reap_one(object(), "run-1")) == 1
    assert d.cleaned == ["run-1"] and "run-1" not in d.procs


# --- the collector a run cannot reach -----------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("http://localhost:4318", True),
    ("http://127.0.0.1:4318", True),
    ("http://0.0.0.0:4318", True),
    ("http://jaeger:4318", False),
    ("http://host.docker.internal:4318", False),
    ("http://otel-collector.observability:4318", False),
])
def test_host_local_recognises_the_run_s_own_loopback(url, expected):
    """host.docker.internal is NOT host-local for this purpose: it is what a dev
    rewrite produces, and it resolves from inside a container."""
    assert orchestrator._host_local(url) is expected


def _otel_argv(monkeypatch, *, prod, endpoint):
    """Build the REAL launcher argv and read the EFFECTIVE telemetry env.

    An earlier version of this helper re-implemented the branch and asserted
    against its own copy, so disabling the real one left every test green --
    the exact failure mode these tests exist to catch, committed inside the
    tests themselves. `_sandbox_argv` is what actually runs.

    `ANDYUR_OTEL` appears TWICE: once forwarded from the daemon's own
    environment (_FORWARD) and once appended by the branch under test. Docker
    takes the last `-e` for a name, so the effective value is the last one --
    which is why this reads the last rather than asserting on membership.
    """
    monkeypatch.setattr(orchestrator.config, "PROD", prod)
    monkeypatch.setattr(orchestrator.otel, "OTEL_ON", True)
    monkeypatch.setenv("ANDYUR_OTEL", "on")
    monkeypatch.setenv("ANDYUR_OTEL_ENDPOINT", endpoint)
    logged = []
    monkeypatch.setattr(orchestrator, "log", logged.append)

    argv = orchestrator._sandbox_argv("agent-a", "run-1")
    env = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-e"]
    otel_values = [v.split("=", 1)[1] for v in env if v.startswith("ANDYUR_OTEL=")]
    endpoints = [v.split("=", 1)[1] for v in env
                 if v.startswith("ANDYUR_OTEL_ENDPOINT=")]
    return (otel_values[-1] if otel_values else None,
            endpoints[-1] if endpoints else None, logged)


def test_in_production_an_unreachable_collector_turns_run_telemetry_off(monkeypatch):
    """Prod does not rewrite to the host gateway, so localhost stays localhost --
    the run's own loopback, where nothing listens."""
    effective, endpoint, logged = _otel_argv(
        monkeypatch, prod=True, endpoint="http://localhost:4318")

    assert effective == "off"
    assert endpoint is None, "no collector should be configured at all"
    assert logged, "turning telemetry off must be said once, not implied"


def test_in_production_a_collector_on_the_run_network_is_passed_through(monkeypatch):
    """Addressed by name, which is the documented way to get traces from a
    confined run."""
    effective, endpoint, _ = _otel_argv(
        monkeypatch, prod=True, endpoint="http://jaeger:4318")

    assert effective == "on"
    assert endpoint == "http://jaeger:4318"


def test_in_dev_the_host_collector_is_rewritten_and_kept(monkeypatch):
    """Dev rewrites to the host gateway, which a container CAN reach -- so
    telemetry stays on and the endpoint is the rewritten one."""
    effective, endpoint, _ = _otel_argv(
        monkeypatch, prod=False, endpoint="http://localhost:4318")

    assert effective == "on"
    assert endpoint == "http://host.docker.internal:4318"

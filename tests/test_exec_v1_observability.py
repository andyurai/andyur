"""The exec/v1 path is observed (production-gaps row 21, PR B), held to
docs/observability-exit-criteria.md: every decision a span with the reason BY
NAME, in the run's trace; identity on the span, secrets never; failures with
duration and cause; metrics for the countables; telemetry off is safe and
telemetry on changes no outcome; and each test here reddens when the
instrumentation it names is removed (mutation-checked).

The spans are read through an in-memory exporter installed on the real OTel
SDK -- the platform's own ObservedASGI, ExecFront, ToolService, daemon and
controller code runs unchanged.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import uvicorn
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from andyur import modelpolicy, otel
from andyur.runner import execfront, runner, toolservice
from andyur.runner.execfront import ExecFront

ROOT = Path(__file__).resolve().parents[1]
GRANTED = "granted-model"


# --- fixtures ---------------------------------------------------------------

@pytest.fixture()
def spans(monkeypatch):
    """The real SDK behind an in-memory exporter: every setup_tracing() in the
    platform returns a tracer on this provider; metrics are a no-op meter."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    monkeypatch.setattr(otel, "OTEL_ON", True)
    monkeypatch.setattr(otel, "setup_tracing", lambda service_name: tracer)
    monkeypatch.setattr(otel, "setup_metrics", lambda service_name, readers=None: None)
    monkeypatch.setattr(runner, "_tracer", tracer)

    class _Spans:
        def all(self):
            return list(exporter.get_finished_spans())

        def named(self, name):
            return [s for s in self.all() if s.name == name]

        def clear(self):
            exporter.clear()

    handle = _Spans()
    handle.tracer = tracer
    return handle


def _attrs(span):
    return dict(span.attributes)


class _Upstream:
    """A real model-leg stand-in recording what the front forwards."""

    def __init__(self):
        self.seen: list[dict] = []

        async def any_path(request: Request) -> Response:
            self.seen.append({"path": request.url.path, "body": await request.body(),
                              "headers": {k.lower(): v for k, v in request.headers.items()}})
            return Response(b'{"model":"answered"}', status_code=200, media_type="application/json")

        self._server = uvicorn.Server(uvicorn.Config(
            Starlette(routes=[Route("/{path:path}", endpoint=any_path, methods=["GET", "POST", "DELETE"])]),
            host="127.0.0.1", port=0, log_level="warning", loop="asyncio"))

    def start(self) -> str:
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        while not self._server.started:
            threading.Event().wait(0.02)
        return f"http://127.0.0.1:{self._server.servers[0].sockets[0].getsockname()[1]}"

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture()
def run_trace(spans):
    """A 'run' root span, as the server anchors one: its traceparent is what
    the sidecar's listeners get as their trusted fixed parent."""
    with spans.tracer.start_as_current_span("run test-agent") as root:
        yield root, otel.current_traceparent()


@pytest.fixture()
def front(spans, run_trace):
    up = _Upstream()
    url = up.start()
    _, parent = run_trace
    f = ExecFront(url, enforced_model=GRANTED, require_model=True,
                  run_id="r1", agent="test-agent", origin_trace=parent)
    base = f.start()
    yield up, base
    f.stop()
    up.stop()


# --- the front: every decision a span in the run's trace -------------------

def test_every_front_decision_is_a_span_in_the_runs_trace_with_the_reason_by_name(spans, run_trace, front, monkeypatch):
    """Criteria 1-3: forwarded and each refusal, by the code the body carries,
    parented to the run's trace; identity (run, agent, granted model) on the
    span; the workload's own traceparent never becomes the trace."""
    root, _ = run_trace
    up, base = front
    monkeypatch.setattr(execfront, "MAX_BODY_BYTES", 256)
    forwarded = httpx.post(base + "/llm/api/chat", json={"model": GRANTED, "messages": []},
                           headers={"traceparent": "00-" + "f" * 32 + "-" + "a" * 16 + "-01",
                                    "tracestate": "vendor=attacker", "baggage": "k=v"})
    assert forwarded.status_code == 200
    expected = {
        "path_not_model_call": httpx.get(base + "/llm/api/tags"),
        "model_not_granted": httpx.post(base + "/llm/api/chat", json={"model": "other"}),
        "model_key_variant": httpx.post(base + "/llm/api/chat",
                                        content=b'{"model": "granted-model", "MODEL": "other"}',
                                        headers={"content-type": "application/json"}),
        "duplicate_model_key": httpx.post(base + "/llm/api/chat",
                                          content=b'{"model": "granted-model", "model": "other"}',
                                          headers={"content-type": "application/json"}),
        "model_missing": httpx.post(base + "/llm/api/chat", json={"messages": []}),
        "body_not_json": httpx.post(base + "/llm/api/chat", content=b"not json"),
        "path_refused": httpx.post(base + "/llm//api/chat", json={"model": GRANTED}),
        "body_too_large": httpx.post(base + "/llm/api/chat",
                                     json={"model": GRANTED, "messages": ["x" * 400]}),
    }
    for code, response in expected.items():
        assert response.json()["error"] == code, code
    decisions = [s for s in spans.all() if s.name.startswith("execfront")]
    by_code = {_attrs(s).get("andyur.refusal") for s in decisions}
    assert by_code == set(expected) | {"none"}
    for span in decisions:
        a = _attrs(span)
        assert span.context.trace_id == root.context.trace_id, "not in the run's trace"
        assert span.context.trace_id != int("f" * 32, 16), "the workload's traceparent was trusted"
        assert a["andyur.run_id"] == "r1" and a["andyur.agent"] == "test-agent"
        assert a["andyur.model.granted"] == GRANTED
        assert a["andyur.decision"] in ("forwarded", "refused")
        assert a["http.response.status_code"] in (200, 400, 403, 404, 413)
    [ok] = [s for s in decisions if _attrs(s)["andyur.decision"] == "forwarded"]
    assert _attrs(ok)["gen_ai.request.model"] == GRANTED and _attrs(ok)["andyur.refusal"] == "none"
    wrong = next(s for s in decisions if _attrs(s)["andyur.refusal"] == "model_not_granted")
    assert _attrs(wrong)["andyur.model.requested"] == "other"
    # the upstream saw the RUN's trace identity, not the workload's
    [seen] = [s for s in up.seen if s["path"] == "/api/chat"]
    assert seen["headers"]["traceparent"].split("-")[1] == format(root.context.trace_id, "032x")
    assert "tracestate" not in seen["headers"] and "baggage" not in seen["headers"]


def test_readiness_probes_are_metrics_only_never_a_span(spans, front):
    """A kubelet probes /ready every few seconds for the life of the Pod; a
    span each would be most of a run's trace (criterion 5's cardinality)."""
    _, base = front
    for _ in range(3):
        assert httpx.get(base + "/ready").status_code == 200
    assert not [s for s in spans.all() if s.name.startswith("execfront")]
    httpx.get(base + "/llm/api/tags")
    assert len([s for s in spans.all() if s.name.startswith("execfront")]) == 1


def test_secrets_in_a_request_never_reach_a_span_attribute_or_event(spans, run_trace, front):
    """Criterion 3 / R must-have 1: a bearer, a run-token-shaped JWT and an API
    key placed in a request are absent from every span attribute and event;
    untrusted values are bounded. The mutant that records the raw value
    (bypasses otel.safe_attribute) reddens here."""
    _, base = front
    key = "sk-ant-api03-" + "A" * 40
    jwt = "eyJ" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20
    bearer = "Bearer " + "t" * 40
    httpx.post(base + "/llm/api/chat", json={"model": key, "messages": []},
               headers={"authorization": bearer, "x-run": jwt})
    httpx.post(base + "/llm/api/chat", json={"model": "m" * 5000})
    httpx.get(base + "/llm/api/" + "p" * 3000)
    everything = []
    for span in spans.all():
        everything.extend(str(v) for v in _attrs(span).values())
        for event in span.events:
            everything.extend(str(v) for v in dict(event.attributes).values())
    joined = "\n".join(everything)
    for secret in (key, jwt, bearer, "t" * 40):
        assert secret not in joined, "a secret reached a span"
    assert "<redacted>" in joined                                     # the key was seen, redacted
    assert all(len(v) <= otel.ATTRIBUTE_MAX_CHARS for v in everything), "an unbounded attribute"


def test_telemetry_pointed_at_a_closed_port_changes_no_outcome(monkeypatch):
    """Criterion 7 / R must-have 2: with the REAL exporter aimed at a closed
    port, the front's decisions are byte-identical and no request is slowed
    by the export. The mutant that lets the exporter's error propagate (or
    awaits the export inline) reddens here."""
    monkeypatch.setattr(otel, "OTEL_ON", True)
    monkeypatch.setattr(otel, "ENDPOINT", "http://127.0.0.1:1")
    monkeypatch.setattr(execfront, "SERVICE_NAME", "andyur-runner-closedport")
    # this test drives the REAL provider registry and shuts it down: give it
    # its own, so the rest of the suite keeps its providers (pollution found
    # by the full run)
    monkeypatch.setattr(otel, "_closed", False)

    class _Sentinel:                       # "a first service already won the global provider":
        def force_flush(self, *a): pass    # this test must not set the process-wide tracer
        def shutdown(self): pass           # provider (suite-order pollution found by the full run)
    monkeypatch.setattr(otel, "_providers", {"sentinel": _Sentinel()})
    monkeypatch.setattr(otel, "_meter_providers", {})
    monkeypatch.setattr(otel, "_instruments", {})
    up = _Upstream()
    url = up.start()
    f = ExecFront(url, enforced_model=GRANTED, require_model=True, run_id="r1", agent="a",
                  origin_trace="00-" + "1" * 32 + "-" + "2" * 16 + "-01")
    base = f.start()
    try:
        started = time.monotonic()
        outcomes = [
            httpx.post(base + "/llm/api/chat", json={"model": GRANTED}).status_code,
            httpx.post(base + "/llm/api/chat", json={"model": "other"}).status_code,
            httpx.get(base + "/llm/api/tags").status_code,
            httpx.post(base + "/llm/api/chat", content=b"x").status_code,
            httpx.get(base + "/ready").status_code,
        ]
        elapsed = time.monotonic() - started
    finally:
        f.stop()
        up.stop()
    assert outcomes == [200, 403, 404, 400, 200]
    assert elapsed < 3.0, f"requests waited on the exporter ({elapsed:.1f}s)"
    t0 = time.monotonic()
    drained = otel.shutdown_bounded(1.0)
    assert time.monotonic() - t0 < 2.5
    assert drained in (True, False)


# --- bounded shutdown ---------------------------------------------------------

def test_shutdown_bounded_returns_within_the_bound_when_the_exporter_hangs(monkeypatch):
    """Criterion 7, second half (R on the plan): the serve-only exit must not
    wait on a collector. A processor whose flush blocks 30 s is cut at the
    bound; the mutant that joins without a timeout reddens here."""
    class Hanging:
        def force_flush(self, timeout_millis=None):
            time.sleep(30)

        def shutdown(self):
            pass

    monkeypatch.setattr(otel, "_closed", False)
    monkeypatch.setattr(otel, "_providers", {"hang": Hanging()})
    monkeypatch.setattr(otel, "_meter_providers", {})
    t0 = time.monotonic()
    drained = otel.shutdown_bounded(0.5)
    assert drained is False
    assert time.monotonic() - t0 < 1.5
    assert otel._closed is True and otel._providers == {}


def test_the_serve_only_park_exits_within_the_bound_with_the_collector_unreachable():
    """The whole exit path, as PID 1 would run it: telemetry ON, the endpoint a
    closed port, a span open across the park; SIGTERM -> exit 0 within 2.5 s.
    Drop the bounded shutdown (main() flushing unbounded) and this pays the
    exporter's retries."""
    script = (
        "import asyncio, os, sys, time\n"
        "os.environ['ANDYUR_OTEL'] = 'on'\n"
        "os.environ['ANDYUR_OTEL_ENDPOINT'] = 'http://127.0.0.1:1'\n"
        "from andyur import otel\n"
        "from andyur.runner import runner\n"
        "t = otel.setup_tracing('andyur-runner')\n"
        "with t.start_as_current_span('runner test'):\n"
        "    why = asyncio.run(runner._serve_only_park(120))\n"
        "t0 = time.monotonic()\n"
        "drained = otel.shutdown_bounded(runner.SERVE_ONLY_FLUSH_SECONDS)\n"
        "print('EXIT', why, drained, round(time.monotonic() - t0, 2), flush=True)\n"
    )
    env = {**os.environ, "ANDYUR_OTEL": "on", "ANDYUR_OTEL_ENDPOINT": "http://127.0.0.1:1"}
    proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env,
                            preexec_fn=lambda: signal.signal(signal.SIGTERM, signal.SIG_IGN))
    try:
        deadline = time.monotonic() + 30
        while "parked" not in (line := proc.stdout.readline()):
            assert time.monotonic() < deadline and line != "", proc.stderr.read()
        sent = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=2.5 + runner.SERVE_ONLY_FLUSH_SECONDS) == 0, proc.stderr.read()
        exited = time.monotonic() - sent
        out = proc.stdout.read()
        assert "EXIT sigterm" in out, out
        assert exited < runner.SERVE_ONLY_FLUSH_SECONDS + 1.5, f"exit took {exited:.1f}s"
    finally:
        proc.kill()


def test_thread_hosted_servers_leave_the_interpreter_exit_clean():
    """The SIGSEGV reports (uvloop's timer callback on a torn-down interpreter):
    thread-hosted uvicorn servers run the stdlib loop and are joined on stop,
    so a process that started and stopped each exits 0. Restore uvloop on a
    thread left alive and this exits -11."""
    script = (
        "import os\n"
        "os.environ['ANDYUR_MCP_TOKEN'] = 'declared'\n"
        "from unittest.mock import patch\n"
        "from andyur.runner import runner\n"
        "with patch('andyur.runner.driver._server_call'):\n"
        "    front, svc, url = runner._start_serve_only_services('a', 'r', None, None, enforced_model='m')\n"
        "    front.stop(); svc.stop()\n"
        "print('CLEAN', flush=True)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "ANDYUR_OTEL": "off"})
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-800:])
    assert "CLEAN" in proc.stdout
    for path in ("execfront", "toolservice", "toolsidecar", "modelproxy", "agentchannel"):
        assert 'loop="asyncio"' in (ROOT / "andyur" / "runner" / f"{path}.py").read_text(), path


# --- the MCP boundary and the park ----------------------------------------------

def test_the_mcp_boundary_refusal_is_a_span_with_bearer_rejected(spans, run_trace, monkeypatch):
    """Criteria 1-3: /mcp without the declared bearer is a SERVER span in the
    run's trace carrying bearer_rejected -- the same code the body carries --
    and never the bearer; with it, the request is admitted by name."""
    root, parent = run_trace
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer-value")
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    with patch("andyur.runner.driver._server_call"):
        front, svc, mcp_url = runner._start_serve_only_services("alice", "r1", parent, None,
                                                                enforced_model=GRANTED)
        try:
            init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"}}})
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
            refused = httpx.post(mcp_url, content=init, headers={**headers, "Authorization": "Bearer nope"}, timeout=5)
            assert refused.status_code == 401
            assert refused.json() == {"error": "bearer_rejected", "detail": "unauthorized"}
            admitted = httpx.post(mcp_url, content=init, headers={**headers, "Authorization": "Bearer declared-bearer-value"}, timeout=5)
            assert admitted.status_code == 200
        finally:
            front.stop()
            svc.stop()
    mcp = [s for s in spans.all() if s.name.startswith("mcp ")]
    assert {_attrs(s)["andyur.refusal"] for s in mcp} == {"bearer_rejected", "none"}
    assert {_attrs(s)["andyur.decision"] for s in mcp} == {"refused", "admitted"}
    assert all(s.context.trace_id == root.context.trace_id for s in mcp)
    joined = "\n".join(str(v) for s in mcp for v in _attrs(s).values())
    assert "declared-bearer-value" not in joined and "nope" not in joined


def test_runner_serve_records_the_ttl_and_the_exit_by_name(spans):
    """Criteria 1, 4: the park is a span with its TTL and why it ended --
    ttl_expired or sigterm -- the same words the log line carries."""
    assert asyncio.run(runner._serve_only_park(0.05)) == "ttl_expired"

    async def stopped():
        loop = asyncio.get_running_loop()
        event = runner._install_stop_handler(loop)
        loop.call_later(0.05, event.set)
        return await runner._serve_only_park(30)

    assert asyncio.run(stopped()) == "sigterm"
    serve = spans.named("runner.serve")
    assert [(_attrs(s)["andyur.serve.exit"], _attrs(s)["andyur.serve.ttl_seconds"]) for s in serve] == [
        ("ttl_expired", 0.05), ("sigterm", 30.0)]


def test_a_serve_start_failure_is_an_event_by_name(spans, run_trace, monkeypatch):
    monkeypatch.delenv("ANDYUR_MCP_TOKEN", raising=False)
    _, parent = run_trace
    with spans.tracer.start_as_current_span("runner.execute") as span:
        with pytest.raises(RuntimeError):
            runner._start_serve_only_services("alice", "r1", parent, None, enforced_model=GRANTED)
    [execute] = spans.named("runner.execute")
    [event] = execute.events
    assert event.name == "serve.start_failed"
    assert dict(event.attributes)["andyur.reason"] == "no_declared_bearer"


# --- the daemon ---------------------------------------------------------------

def _bare_daemon(orch, worker_id="w-A"):
    from andyur.daemon.daemon import Daemon
    d = Daemon.__new__(Daemon)
    d.procs, d.orch, d.worker_id, d.stopping = {}, orch, worker_id, False
    return d


class _Orch:
    name = "kubernetes"

    def __init__(self, completion, launch_error=None):
        self.completion, self.launch_error = completion, launch_error

    def read_exec_completion(self, run_id):
        return self.completion

    def launch_governed(self, spec, runtime, log):
        raise self.launch_error

    def describe(self, run_id):
        return "in a pod"


def test_the_exec_completion_is_a_span_with_the_finish_by_name(spans, monkeypatch):
    """Criteria 1, 4, 5: the daemon's reading of a stock run's exit is a span in
    the run's trace with the exit code, the captured bytes, and whether the
    finish confirmed -- with the server's reason by name when it did not --
    plus the finish latency/attempt metrics."""
    from andyur.daemon import daemon as daemon_module
    monkeypatch.setattr(daemon_module, "_tracer", spans.tracer)
    recorded = []
    monkeypatch.setattr(otel, "try_record_metric", lambda *a, **k: recorded.append((a[1], k)) or True)
    answers = iter([(True, None), (False, "server down")])

    async def fake_finish(api, run_id, *, summary, error, attempts=3, path=None, extra=None):
        return next(answers)

    monkeypatch.setattr(daemon_module, "post_finish", fake_finish)
    d = _bare_daemon(_Orch((0, "opensre: root_cause found\n", None, 1 << 20)))
    with spans.tracer.start_as_current_span("run x") as root:
        d._trace_contexts()["r1"] = otel.current_traceparent()
    assert asyncio.run(d._report_exec_completion(None, "r1")) is True
    d._trace_contexts()["r1"] = "00-" + format(root.context.trace_id, "032x") + "-" + "a" * 16 + "-01"
    assert asyncio.run(d._report_exec_completion(None, "r1")) is False
    confirmed, unconfirmed = spans.named("daemon.exec_completion")
    a, b = _attrs(confirmed), _attrs(unconfirmed)
    assert a["andyur.run_id"] == "r1" and a["andyur.exit_code"] == 0 and a["andyur.result"] == "done"
    assert a["andyur.finish"] == "confirmed" and a["andyur.captured_bytes"] > 0
    assert b["andyur.finish"] == "unconfirmed:server down"
    assert confirmed.context.trace_id == root.context.trace_id == unconfirmed.context.trace_id
    names = [n for n, _ in recorded]
    assert names.count("andyur.daemon.finish_seconds") == 2 and names.count("andyur.daemon.finish_attempts") == 2
    assert {k["andyur__outcome"] for n, k in recorded if n == "andyur.daemon.finish_attempts"} == {"success", "failure"}


def test_a_failed_launch_is_an_event_by_name_on_the_launch_span(spans, monkeypatch, tmp_path):
    from andyur.daemon import daemon as daemon_module
    monkeypatch.setattr(daemon_module, "_tracer", spans.tracer)
    monkeypatch.setattr(daemon_module, "RUNLOG_DIR", tmp_path)
    d = _bare_daemon(_Orch(None, launch_error=RuntimeError("run-group launch failed (attach 403)")))
    with pytest.raises(RuntimeError):
        d.launch("r-fail", "opensre-sre", "00-" + "3" * 32 + "-" + "4" * 16 + "-01")
    launches = spans.named("daemon.launch")
    assert [s.name for s in spans.all()] == ["daemon.launch"], [s.name for s in spans.all()]
    [launch] = launches
    assert _attrs(launch)["andyur.outcome"] == "failure"
    [event] = [e for e in launch.events if e.name == "launch_failed"]   # beside the SDK's `exception`
    assert dict(event.attributes) == {"andyur.reason": "RuntimeError", "andyur.finish": "worker-finish"}
    assert launch.context.trace_id == int("3" * 32, 16)


def test_daemon_log_lines_carry_the_trace_id_through_the_json_envelope(spans, capsys):
    """Criterion 6: the daemon's log line, inside a span, is the andyur.log.v1
    envelope with the active trace id, redacted."""
    import logging
    from andyur import observability
    from andyur.daemon import daemon as daemon_module
    logger = logging.getLogger("andyur")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(observability.JsonFormatter("andyur-daemon"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        with spans.tracer.start_as_current_span("daemon.launch") as span:
            daemon_module.log("launched run r1 with token sk-ant-api03-" + "Z" * 40)
    finally:
        logger.removeHandler(handler)
    line = json.loads([l for l in capsys.readouterr().out.splitlines() if l.startswith("{")][-1])
    assert line["schema"] == "andyur.log.v1" and line["trace_id"] == format(span.context.trace_id, "032x")
    assert "[daemon] launched run r1" in line["message"] and "sk-ant" not in line["message"]


# --- the controller -----------------------------------------------------------

def _controller_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_kubernetes_controller",
                                                  ROOT / "tests" / "test_kubernetes_controller.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_controller_waits_are_spans_with_duration_and_outcome_by_name(spans, monkeypatch):
    """Criteria 4-5: readiness, rollback and delete as spans with their outcome
    by name and duration, and the wait histogram per operation/outcome."""
    from andyur.daemon.kubernetes_controller import KubernetesRunController
    recorded = []
    monkeypatch.setattr(otel, "try_record_metric", lambda *a, **k: recorded.append((a[1], k)) or True)
    mod = _controller_module()
    api = mod.FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = mod._spec()
    with spans.tracer.start_as_current_span("daemon.launch") as launch:
        controller.launch(spec, mod.CREDENTIALS)
    controller.delete(spec)
    api.ready = False
    with pytest.raises(RuntimeError, match="not ready"):
        controller.launch(mod._spec(run_id="run-two"), mod.CREDENTIALS)
    by_name = {}
    for s in spans.all():
        by_name.setdefault(s.name, []).append(s)
    [ready], [deleted] = by_name["controller.wait_ready"][:1], by_name["controller.delete"]
    assert _attrs(ready)["andyur.outcome"] == "ready" and _attrs(ready)["andyur.run_id"] == "run-one"
    assert _attrs(ready)["andyur.timeout_seconds"] == float(controller.READY_TIMEOUT)
    assert ready.context.trace_id == launch.context.trace_id            # under the launch span
    assert _attrs(deleted)["andyur.outcome"] == "deleted" and _attrs(deleted)["andyur.seconds"] >= 0
    timed_out = by_name["controller.wait_ready"][1]
    assert _attrs(timed_out)["andyur.outcome"] == "timeout"
    [rollback] = by_name["controller.rollback"]
    assert _attrs(rollback)["andyur.outcome"] == "rolled_back" and _attrs(rollback)["andyur.cause"] == "RuntimeError"
    waits = [(k["andyur__operation"], k["andyur__outcome"]) for n, k in recorded if n == "andyur.controller.wait_seconds"]
    # the metric operation is the VOCABULARY word ("readiness"), not the span suffix (R MED-4)
    assert waits == [("readiness", "success"), ("delete", "success"), ("readiness", "timeout"), ("rollback", "success")]
    # the daemon's cleanup path deletes by generation, without a spec: the same
    # span (found missing by the OpenSRE read-back)
    api.ready = True
    controller.launch(mod._spec(run_id="run-three"), mod.CREDENTIALS)
    controller.delete_generation("run-three", mod._spec().generation)
    by_gen = [s for s in spans.named("controller.delete") if _attrs(s).get("andyur.generation")]
    assert len(by_gen) == 1 and _attrs(by_gen[0])["andyur.outcome"] == "deleted"


# --- the publisher -------------------------------------------------------------

def test_publisher_evidence_decisions_are_spans_by_name(spans, tmp_path):
    from andyur.agentspec import publisher
    not_green = tmp_path / "red.json"
    not_green.write_text(json.dumps({"gate": "exec-v1-conformance", "ok": False, "checks": [],
                                     "inputs": {"selected_image": "i", "selected_command": ["c"]}}))
    with pytest.raises(publisher.InvalidManifest):
        publisher.load_conformance_evidence(not_green)
    [span] = spans.named("publisher.evidence")
    a = _attrs(span)
    assert a["andyur.outcome"] == "refused" and a["andyur.refusal"] == "evidence_not_green"
    assert a["andyur.evidence"] == "red.json" and "not completely green" in a["andyur.detail"]


# --- the vocabulary is one ---------------------------------------------------

def test_the_front_and_the_sidecar_proxy_share_one_refusal_vocabulary():
    """The sidecar proxy's text body and the front's JSON body carry the same
    code for the same decision; the metric bound mirrors the set."""
    from andyur.proxy import app as proxy_app
    body, response = proxy_app._validated_model_body(b'{"model": "other"}', "granted")
    assert response.status_code == 403 and response.body.startswith(b"sidecar: model_not_granted: ")
    refusal = modelpolicy.model_refusal(b'{"model": "other"}', "granted")
    assert refusal.code == "model_not_granted" and refusal.body()["error"] == "model_not_granted"


def test_with_telemetry_off_the_workloads_trace_headers_still_never_reach_the_upstream(monkeypatch):
    """Criterion 7 (off is safe) meets criterion 2: with ANDYUR_OTEL=off there
    is no run context to inject, so the drop of the workload's traceparent/
    tracestate/baggage is the ONLY thing between an attacker-chosen trace
    identity and the model leg. The mutant that forwards them reddens here."""
    monkeypatch.setattr(otel, "OTEL_ON", False)
    up = _Upstream()
    url = up.start()
    f = ExecFront(url, enforced_model=GRANTED, require_model=True, run_id="r1", agent="a")
    base = f.start()
    try:
        r = httpx.post(base + "/llm/api/chat", json={"model": GRANTED},
                       headers={"traceparent": "00-" + "f" * 32 + "-" + "a" * 16 + "-01",
                                "tracestate": "vendor=attacker", "baggage": "k=v", "x-keep": "1"})
        assert r.status_code == 200
    finally:
        f.stop()
        up.stop()
    [seen] = up.seen
    assert seen["headers"]["x-keep"] == "1"
    assert not {"traceparent", "tracestate", "baggage"} & set(seen["headers"])


def test_the_daemons_cleanup_runs_in_the_runs_trace_from_the_executor_thread(spans, monkeypatch):
    """Found by the OpenSRE gate's read-back: run_in_executor inherits no OTel
    context, so the controller's delete span landed in its own trace. The
    daemon opens `daemon.cleanup` under the run's context on that thread; the
    orchestrator's delete becomes its child. The mutant that calls
    orch.cleanup directly reddens here."""
    from andyur.daemon import daemon as daemon_module
    monkeypatch.setattr(daemon_module, "_tracer", spans.tracer)
    monkeypatch.setattr(daemon_module, "post_finish", None)

    class _CleanupOrch:
        name = "kubernetes"

        def read_exec_completion(self, run_id):
            return None                                    # not a stock run: no finish to post

        def cleanup(self, run_id):
            with spans.tracer.start_as_current_span("controller.delete"):
                pass

    class _Proc:
        def poll(self):
            return 0

    d = _bare_daemon(_CleanupOrch())
    d.procs["r1"] = _Proc()
    with spans.tracer.start_as_current_span("run x") as root:
        d._trace_contexts()["r1"] = otel.current_traceparent()
    asyncio.run(d.reap(None))
    [cleanup] = spans.named("daemon.cleanup")
    [delete] = spans.named("controller.delete")
    assert cleanup.context.trace_id == root.context.trace_id == delete.context.trace_id
    assert delete.parent.span_id == cleanup.context.span_id
    assert _attrs(cleanup)["andyur.outcome"] == "success" and d._trace_contexts() == {}


# --- R's PR #25 round 1 -----------------------------------------------------------

@pytest.fixture()
def metrics(monkeypatch):
    """The REAL metric pipeline behind an in-memory reader: record_metric runs
    its vocabulary checks and the instruments really record (R MED-4: a stub
    that always returned True hid an operation outside the vocabulary)."""
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    monkeypatch.setattr(otel, "_closed", False)
    monkeypatch.setattr(otel, "_meter_providers", {})
    monkeypatch.setattr(otel, "_instruments", {})
    monkeypatch.setattr(otel, "setup_metrics", lambda service_name, readers=None: provider.get_meter("test"))

    def points():
        out = []
        data = reader.get_metrics_data()
        for rm in (data.resource_metrics if data else []):
            for sm in rm.scope_metrics:
                for m in sm.metrics:
                    for dp in m.data.data_points:
                        out.append((m.name, dict(dp.attributes), getattr(dp, "value", getattr(dp, "sum", None))))
        return out
    return points


def test_token_shaped_values_and_encoded_bearers_never_reach_a_span(spans, run_trace, front):
    """R MED-1: the run's OWN bearer shape (token_urlsafe(32)) is not a prefix
    the redactor knows; percent-encoding defeated the shapes it does know; and
    a secret straddling the 256 bound must not survive as a prefix. Mutant:
    bound before scrub, or skip the decode -> red."""
    import secrets as _secrets
    _, base = front
    bearer = _secrets.token_urlsafe(32)
    hexkey = "9f" * 20
    long_prefix = "p" * 250
    httpx.get(base + f"/llm/api/{bearer}")                 # a secret in the PATH: never recorded at all
    httpx.get(base + "/llm/api/Bearer%20" + "t" * 40)
    httpx.post(base + "/llm/api/chat", json={"model": "sk-proj-" + "A1" * 24})
    httpx.post(base + "/llm/api/chat", json={"model": hexkey})
    httpx.post(base + "/llm/api/chat", json={"model": long_prefix + bearer})
    values = [str(v) for s in spans.all() for v in _attrs(s).values()]
    joined = "\n".join(values)
    for secret in (bearer, "t" * 40, "A1" * 24, hexkey, bearer[:12], bearer[:6]):
        assert secret not in joined, f"{secret[:8]}... reached a span"
    # scrub BEFORE bound: a token that starts just inside the bound is scrubbed
    # whole; bounding first would leave its head as a "short word" (mutant)
    inside = ("p " * 124 + "x") + bearer                                 # the token starts at char 249
    out = otel.safe_attribute(inside)
    assert bearer[:6] not in out and "<redac" in out                  # scrubbed, then bounded
    assert all(len(v) <= otel.ATTRIBUTE_MAX_CHARS for v in values)
    assert otel.safe_attribute("Bearer%20" + "x1" * 20) == "<redacted>"
    # the route vocabulary is CLOSED: the caller's path text is never an attribute
    routes = {_attrs(s).get("andyur.execfront.route") for s in spans.all() if s.name.startswith("execfront")}
    assert routes <= {"/api/chat", "/api/generate", "/v1/chat/completions", "not-a-model-call", "refused-path"}
    assert not any(k.endswith("execfront.path") for s in spans.all() for k in _attrs(s))
    assert all(isinstance(_attrs(s).get("andyur.execfront.path_bytes"), int)
               for s in spans.all() if s.name.startswith("execfront"))
    assert otel.safe_attribute(long_prefix + bearer).endswith("<redacted>") or bearer[:10] not in otel.safe_attribute(long_prefix + bearer)


def test_the_root_logger_envelope_redacts_every_library_line(capsys):
    """R MED-2: with root=True, a third-party logger (the MCP SDK's warning
    with a caller-chosen name) leaves through the same redacting envelope --
    never Python's lastResort stderr, never verbatim."""
    import logging
    from andyur import observability
    root = logging.getLogger()
    saved = list(root.handlers); saved_andyur = list(logging.getLogger("andyur").handlers)
    for h in saved: root.removeHandler(h)
    for h in saved_andyur: logging.getLogger("andyur").removeHandler(h)
    try:
        observability.configure_logging("andyur-runner", stream=sys.stdout, root=True)
        import secrets as _secrets
        urlsafe, hexkey, proj = _secrets.token_urlsafe(32), "9f1e" * 10, "sk-proj-" + "A1" * 24
        logging.getLogger("mcp.server.lowlevel.server").warning(
            "Tool 'ANDYUR_RUN_TOKEN=eyJ%s.%s.%s bearer=%s' not listed" % ("a" * 20, "b" * 20, "c" * 20, urlsafe))
        runner._serve_log(f"[runner] token sk-ant-api03-{'Z' * 40} hex={hexkey} key={proj} run=" + "d" * 32
                          + " image=sha256:" + "e" * 64)
    finally:
        for h in list(root.handlers): root.removeHandler(h)
        for h in list(logging.getLogger("andyur").handlers): logging.getLogger("andyur").removeHandler(h)
        for h in saved: root.addHandler(h)
        for h in saved_andyur: logging.getLogger("andyur").addHandler(h)
    captured = capsys.readouterr()
    lines = [json.loads(l) for l in captured.out.splitlines() if l.startswith("{")]
    assert len(lines) == 2 and all(l["schema"] == "andyur.log.v1" for l in lines)
    assert "eyJ" not in captured.out and "sk-ant" not in captured.out and "ANDYUR_RUN_TOKEN=" not in captured.out
    # token SHAPES (the run's own bearer, a hex key, sk-proj-) are scrubbed by
    # the same redactor on the LOG path (R on 2755f36) ...
    for secret in (urlsafe, hexkey, "A1" * 24):
        assert secret not in captured.out, secret[:8]
    # ... while the platform's own identifiers stay readable: a 32-hex run id
    # and a sha256: image digest are not secrets
    assert "run=" + "d" * 32 in captured.out and "sha256:" + "e" * 64 in captured.out
    assert captured.err == ""                                         # nothing via lastResort


def test_mcp_bodies_are_bounded_by_name(spans, run_trace, monkeypatch):
    _, parent = run_trace
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer-value")
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    import socket
    with patch("andyur.runner.driver._server_call"):
        front, svc, mcp_url = runner._start_serve_only_services("alice", "r1", parent, None, enforced_model=GRANTED)
        try:
            host, port = mcp_url.split("//")[1].split("/")[0].split(":")
            raw = socket.create_connection((host, int(port)), timeout=5)
            raw.sendall(("POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer declared-bearer-value\r\n"
                         "Content-Type: application/json\r\n"
                         f"Content-Length: {toolservice.MAX_BODY_BYTES + 1}\r\n\r\n").encode())
            head = b""
            while b"body_too_large" not in head and len(head) < 8192:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                head += chunk
            raw.close()
        finally:
            front.stop(); svc.stop()
    assert head.startswith(b"HTTP/1.1 413") and b"body_too_large" in head
    refused = [s for s in spans.all() if s.name.startswith("mcp ") and _attrs(s).get("andyur.refusal") == "body_too_large"]
    assert refused, "an over-bound /mcp body was not refused by name"


def test_stop_returns_within_the_bound_with_an_open_stream_and_a_stalled_post(spans, run_trace, monkeypatch):
    """R MED-3: timeout_graceful_shutdown bounds each server's drain; an open
    GET /mcp stream and a stalled POST no longer hold stop() for 5 s each."""
    _, parent = run_trace
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer-value")
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    with patch("andyur.runner.driver._server_call"):
        front, svc, mcp_url = runner._start_serve_only_services("alice", "r1", parent, None, enforced_model=GRANTED)
        front_url = f"http://127.0.0.1:{front._server.servers[0].sockets[0].getsockname()[1]}"
        import socket
        # a raw client that opens a POST with a declared body it never sends (stalled)
        host, port = mcp_url.split("//")[1].split("/")[0].split(":")
        stalled = socket.create_connection((host, int(port)))
        stalled.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer declared-bearer-value\r\n"
                        b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
        init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        opened = httpx.post(mcp_url, content=init, headers={"Authorization": "Bearer declared-bearer-value",
                                                              "Content-Type": "application/json",
                                                              "Accept": "application/json, text/event-stream"}, timeout=5)
        session = opened.headers.get("mcp-session-id", "")
        assert opened.status_code == 200 and session
        streaming = socket.create_connection((host, int(port)))
        streaming.sendall((f"GET /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer declared-bearer-value\r\n"
                           f"Mcp-Session-Id: {session}\r\nAccept: text/event-stream\r\n\r\n").encode())
        streaming.settimeout(2)
        try:
            first = streaming.recv(512)                       # the stream is open: headers arrived
        except socket.timeout:
            first = b""
        assert first.startswith(b"HTTP/1.1 200"), first[:80]
        time.sleep(0.3)
        t0 = time.monotonic()
        svc.stop(); front.stop()
        elapsed = time.monotonic() - t0
        stalled.close(); streaming.close()
    assert elapsed < 3.0, f"stop() took {elapsed:.1f}s with open connections"


def test_the_countables_are_recorded_through_the_real_metric_pipeline(spans, run_trace, metrics, monkeypatch):
    """R MED-4/5: execfront decisions and request bytes, mcp decisions and the
    controller's readiness wait reach real instruments with vocabulary-checked
    attributes (a name outside the vocabulary records nothing)."""
    up = _Upstream(); url = up.start()
    _, parent = run_trace
    f = ExecFront(url, enforced_model=GRANTED, require_model=True, run_id="r1", agent="a", origin_trace=parent)
    base = f.start()
    try:
        httpx.post(base + "/llm/api/chat", json={"model": GRANTED})
        httpx.post(base + "/llm/api/chat", json={"model": "other"})
    finally:
        f.stop(); up.stop()
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer-value")
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    with patch("andyur.runner.driver._server_call"):
        front, svc, mcp_url = runner._start_serve_only_services("alice", "r1", parent, None, enforced_model=GRANTED)
        try:
            httpx.post(mcp_url, content=b"{}", headers={"Authorization": "Bearer nope", "Content-Type": "application/json"})
        finally:
            front.stop(); svc.stop()
    from andyur.daemon.kubernetes_controller import KubernetesRunController
    mod = _controller_module()
    api = mod.FakeApi()
    KubernetesRunController(api, "andyur-runs").launch(mod._spec(), mod.CREDENTIALS)
    pts = metrics()
    decisions = {(a.get("andyur.outcome"), a.get("andyur.refusal")): v for n, a, v in pts if n == "andyur.execfront.decisions"}
    assert decisions[("success", "none")] == 1 and decisions[("denied", "model_not_granted")] == 1
    assert any(n == "andyur.execfront.request_bytes" for n, _, _ in pts)
    assert {(a.get("andyur.outcome"), a.get("andyur.refusal")) for n, a, _ in pts if n == "andyur.mcp.decisions"} == {("denied", "bearer_rejected")}
    waits = {(a.get("andyur.operation"), a.get("andyur.outcome")) for n, a, _ in pts if n == "andyur.controller.wait_seconds"}
    assert ("readiness", "success") in waits


def test_a_platform_tool_call_is_a_child_span_with_its_outcome(spans, run_trace):
    from andyur.runner import driver

    async def fine(args):
        return {"content": [{"type": "text", "text": "ok"}]}

    async def broken(args):
        raise RuntimeError("boom")

    with spans.tracer.start_as_current_span("mcp POST") as request:
        asyncio.run(driver._traced_tool("send_message", "r1")(fine)({}))
        with pytest.raises(RuntimeError):
            asyncio.run(driver._traced_tool("create_task", "r1")(broken)({}))
    ok, failed = spans.named("mcp.tool send_message"), spans.named("mcp.tool create_task")
    assert len(ok) == 1 and _attrs(ok[0])["andyur.outcome"] == "success" and _attrs(ok[0])["andyur.run_id"] == "r1"
    assert len(failed) == 1 and _attrs(failed[0])["andyur.outcome"] == "failure" and _attrs(failed[0])["andyur.reason"] == "RuntimeError"
    assert ok[0].parent.span_id == request.context.span_id


def test_main_bounds_the_serve_only_exit_and_a_failed_start(monkeypatch):
    """R MED-5/6: main() shuts telemetry down BOUNDED for a serve-only process
    (not flush()), and the failed-start branch does the same before exit 1."""
    calls = []
    monkeypatch.setattr(otel, "shutdown_bounded", lambda seconds: calls.append(("bounded", seconds)) or True)
    monkeypatch.setattr(otel, "flush", lambda: calls.append(("flush", None)))
    monkeypatch.setattr(sys, "argv", ["andyur-runner", "--agent", "a", "--run-id", "r", "--serve-only"])
    monkeypatch.setattr(runner.identity, "seal_run_token", lambda: None)

    async def fake_execute(agent, run_id, serve_only=False):
        return 0

    monkeypatch.setattr(runner, "execute", fake_execute)
    with pytest.raises(SystemExit) as exit_:
        runner.main()
    assert exit_.value.code == 0
    assert calls == [("bounded", runner.SERVE_ONLY_FLUSH_SECONDS)]


def test_a_front_that_fails_to_start_is_an_event_by_name(spans, run_trace, monkeypatch):
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer-value")
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)

    class _Broken:
        def __init__(self, *a, **k): pass
        def start(self): raise RuntimeError("port busy")
        def stop(self): pass

    monkeypatch.setattr(runner, "ExecFront", _Broken)
    with spans.tracer.start_as_current_span("runner.execute") as span:
        with patch("andyur.runner.driver._server_call"), pytest.raises(RuntimeError, match="port busy"):
            runner._start_serve_only_services("alice", "r1", run_trace[1], None, enforced_model=GRANTED)
    [event] = [e for e in span.events if e.name == "serve.start_failed"]
    assert dict(event.attributes) == {"andyur.reason": "front_failed_to_start", "andyur.error": "RuntimeError"}


def test_the_attach_wait_is_a_span_with_its_outcome(spans):
    """controller.attach: the exec/v1 input delivery, with mode and bytes."""
    import dataclasses
    from andyur.daemon.kubernetes_controller import KubernetesRunController
    mod = _controller_module()

    class _Api(mod.FakeApi):
        def wait_container_running(self, namespace, name, container, timeout):
            return True

        def attach_stdin(self, namespace, name, *args, **kwargs):
            self.attached = (name, args, kwargs)

    api = _Api()
    spec = dataclasses.replace(mod._exec_launch_spec(), exec_input_mode="stdin",
                               exec_input=b'{"task": "hello"}', exec_input_max_bytes=4096)
    KubernetesRunController(api, "andyur-runs").launch(spec, mod.EXEC_CREDENTIALS)
    [attach] = spans.named("controller.attach")
    a = _attrs(attach)
    assert a["andyur.outcome"] == "delivered" and a["andyur.input_mode"] == spec.exec_input_mode
    assert a["andyur.input_bytes"] == len(spec.exec_input or b"")


def test_publisher_records_an_accepted_artifact_by_gate(spans, tmp_path):
    from andyur.agentspec import publisher
    gate = ROOT / "infra" / "byoa-spike" / "exec_v1_gate.py"
    import hashlib
    green = tmp_path / "green.json"
    green.write_text(json.dumps({"gate": "exec-v1-conformance", "ok": True,
                                 "checks": [{"check": "E1", "ok": True}],
                                 "inputs": {"selected_image": "img@sha256:" + "a" * 64, "selected_command": ["c"],
                                            "exec_gate_sha256": hashlib.sha256(gate.read_bytes()).hexdigest(),
                                            "interface": "exec/v1", "input_mode": "stdin", "granted_model": "m"}}))
    proven = publisher.load_conformance_evidence(green)
    [span] = spans.named("publisher.evidence")
    assert _attrs(span)["andyur.outcome"] == "accepted" and _attrs(span)["andyur.gate"] == "exec-v1-conformance"
    assert proven.model == "m"


def test_a_server_thread_left_alive_still_exits_the_interpreter_cleanly():
    """R MED-5: the crash claim is asserted on a process, not grepped from
    source -- a thread-hosted server deliberately NOT stopped, interpreter
    exit 0 (uvloop on that thread segfaulted at exit)."""
    script = (
        "import os\n"
        "os.environ['ANDYUR_MCP_TOKEN'] = 'declared'\n"
        "from unittest.mock import patch\n"
        "from andyur.runner import runner\n"
        "with patch('andyur.runner.driver._server_call'):\n"
        "    front, svc, url = runner._start_serve_only_services('a', 'r', None, None, enforced_model='m')\n"
        "print('LEFT ALIVE', front._server.config.loop, svc._server.config.loop, flush=True)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "ANDYUR_OTEL": "off"})
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert "LEFT ALIVE asyncio asyncio" in proc.stdout           # the stdlib loop, asserted on the live servers


def test_a_failed_serve_only_start_exits_within_the_bound(spans, monkeypatch):
    """R MED-6: the failed-start branch of the serve-only run (no bearer, a port
    collision) shuts telemetry down BOUNDED before exit 1 -- not flush()."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_agent_split", ROOT / "tests" / "test_agent_split.py")
    split = importlib.util.module_from_spec(spec); spec.loader.exec_module(split)
    split._serve_only_env(monkeypatch)
    monkeypatch.delenv("ANDYUR_MCP_TOKEN", raising=False)         # the bearer refusal
    calls = []
    monkeypatch.setattr(otel, "shutdown_bounded", lambda seconds: calls.append(("bounded", seconds)) or True)
    monkeypatch.setattr(otel, "flush", lambda: calls.append(("flush", None)))
    api = split._RecordingApi()
    rc = asyncio.run(runner._run_split(api, "alice", "r1", split.RUN, None, serve_only=True))
    assert rc == 1
    assert ("bounded", runner.SERVE_ONLY_FLUSH_SECONDS) in calls and ("flush", None) not in calls


def test_every_registered_platform_tool_emits_its_span_when_called_through_the_real_server(spans, run_trace):
    """R (PR #25): the decorator must be on the REAL registered tools, not a
    stand-in. Every tool the platform MCP server lists is called through the
    server's own tools/call handler (control-plane calls patched) and must
    emit `mcp.tool <name>`. Deleting one decorator reddens here."""
    from mcp import types
    from andyur.runner import driver
    with patch("andyur.runner.driver._server_call", return_value={"content": "", "id": "t1"}), \
         patch("andyur.runner.driver.embed_text", return_value=None):
        server = driver.build_platform_server("alice", run_trace[1], "r1")["instance"]
        listed = asyncio.run(server.request_handlers[types.ListToolsRequest](
            types.ListToolsRequest(method="tools/list"))).root.tools
        names = sorted(t.name for t in listed)
        assert names == ["append_long_term_memory", "create_task", "handle_message", "request_rollback",
                         "search_memory_graph", "send_message", "update_short_term_memory", "update_task"]
        args = {"append_long_term_memory": {"entry": "x"}, "create_task": {"assignee": "bob", "title": "t", "detail": "d"},
                "handle_message": {"message_id": "m1"}, "search_memory_graph": {"query": "q"},
                "request_rollback": {"namespace": "prod", "deployment": "checkout-service"},
                "send_message": {"to": "bob", "body": "hi"}, "update_short_term_memory": {"content": "c"},
                "update_task": {"task_id": "t1", "state": "closed", "result": "n"}}
        with spans.tracer.start_as_current_span("mcp POST"):
            for name in names:
                try:
                    asyncio.run(server.request_handlers[types.CallToolRequest](types.CallToolRequest(
                        method="tools/call", params=types.CallToolRequestParams(name=name, arguments=args[name]))))
                except Exception:
                    pass                                   # a tool body may refuse the stub; the span must exist
    emitted = sorted({s.name for s in spans.all() if s.name.startswith("mcp.tool ")})
    assert emitted == [f"mcp.tool {n}" for n in names], emitted


def test_redaction_never_swallows_a_url_path_a_run_id_or_an_image_digest():
    """Found in the cluster (PR #25 round 1): with `/` inside the token-shape
    alphabet, `…:8642/runs/<32-hex run id>/worker-finish` read as ONE 56-char
    token and the daemon's HTTP log line came out as `svc:<redacted>` -- the
    live gates grep the worker log BY RUN ID. Path separators (and `=`, `+`)
    are outside the alphabet; the platform's own mints (token_urlsafe) carry
    neither, so nothing of ours escapes. Mutant: put `/` back -> red."""
    import secrets as _secrets
    from andyur.redact import redact
    run_id = "4f869e56a3784a218c6dcd6170cc90cc"
    kept = [
        f"POST http://andyur-server.andyur-system.svc:8642/runs/{run_id}/worker-finish 200 OK",
        f"[daemon] run {run_id}: exec/v1 completion reported (done)",
        "localhost:5000/andyur-runner@sha256:" + "e" * 64,
        "id=123e4567-e89b-12d3-a456-426614174000 generation=worker-a-generation-one",
    ]
    for line in kept:
        assert redact(line) == line, line
    for secret in (_secrets.token_urlsafe(32), "9f1e" * 10, "sk-proj-" + "A1" * 24,
                   "eyJ" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20):
        assert "<redacted>" in redact(f"value={secret} tail"), secret[:10]
    # the whole worker-log line the gate greps survives verbatim
    assert run_id in redact(f"POST /runs/{run_id}/worker-finish")

"""Read the authorization hop from its actual HTTP peer and exported spans."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from andyur import actions, config, db, otel
from andyur.server import actionrequests
from test_lane_a_action_api import _run, _request, client, cluster, _no_waiting


@pytest.fixture
def peer():
    seen = []
    answer = {"status": 200, "body": {"decision": True}}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append({"traceparent": self.headers.get("traceparent"), "payload": payload})
            body = json.dumps(answer["body"]).encode()
            self.send_response(answer["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen, answer
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("case,expected", [
    ("permit", actions.ALLOWED), ("deny", actions.DENIED),
    ("malformed", actions.DENIED), ("unavailable", actions.DENIED),
])
def test_approval_pdp_wire_is_a_child_of_the_stored_run_trace(
        env, cluster, monkeypatch, peer, case, expected):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("review")
    monkeypatch.setattr(actionrequests, "_tracer", tracer)
    monkeypatch.setattr(otel, "setup_tracing", lambda *a, **k: tracer)
    monkeypatch.setattr(otel, "OTEL_ON", True)
    # The HTTP middleware's unrelated metrics must not create an OTLP exporter
    # while this test deliberately turns tracing on with an in-memory provider.
    monkeypatch.setattr(otel.ObservedASGI, "_metric_call", lambda *a, **k: None)
    recorded_metrics = []
    monkeypatch.setattr(otel, "try_record_metric", lambda *a, **k: recorded_metrics.append((a, k)))
    headers = _run(env, "sre", "r", [actions.SCOPE_ROLLBACK_WITH_APPROVAL])
    with tracer.start_as_current_span("trusted-run") as root:
        stored = otel.current_traceparent()
    with db.connect() as conn:
        conn.execute("UPDATE runs SET trace_ctx = ? WHERE id = 'r'", (stored,))
    queued = _request(headers, "r").json()
    base, seen, answer = peer
    if case == "deny":
        answer["body"] = {"decision": False}
    elif case == "malformed":
        answer["body"] = {"decision": "true"}
    elif case == "unavailable":
        answer["status"] = 503
    monkeypatch.setattr(config, "PDP", "authzen")
    monkeypatch.setattr(config, "PDP_URL", base)
    response = client.post(f"/runs/r/actions/{queued['id']}/approve",
                           json={"approver": "alice"},
                           headers={"traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01"})
    assert response.json()["decision"] == expected
    assert len(cluster.writes) == (1 if expected == actions.ALLOWED else 0)
    exported = exporter.get_finished_spans()
    (approval,) = [s for s in exported if s.name == "action.approve"]
    (dependency,) = [s for s in exported if s.name == "pdp.authorize"]
    assert dependency.kind == SpanKind.CLIENT
    assert dependency.parent.span_id == approval.context.span_id
    assert dependency.context.trace_id == approval.context.trace_id == root.context.trace_id
    assert seen[0]["traceparent"].split("-")[1:3] == [
        f"{dependency.context.trace_id:032x}", f"{dependency.context.span_id:016x}"]
    assert dependency.attributes["andyur.run_id"] == "r"
    assert dependency.end_time >= dependency.start_time
    assert any(args[1] == "andyur.dependency.duration" for args, attrs in recorded_metrics)
    if case in ("malformed", "unavailable"):
        assert dependency.status.status_code == StatusCode.ERROR
        (failure,) = [event for event in dependency.events if event.name == "dependency.failure"]
        assert failure.attributes["andyur.reason"] == ("invalid" if case == "malformed" else "unavailable")
    else:
        (decision,) = [event for event in dependency.events if event.name == "pdp.decision"]
        assert decision.attributes["andyur.outcome"] == ("success" if case == "permit" else "denied")

"""The per-run authorization decision is traced, so the identity flow (verify ->
validate SVID -> bind) shows up in the run's Jaeger trace next to the agent's tool
calls. These drive the real OTel SDK through an in-memory exporter and assert the
`auth.bind` span + its attributes."""

import pytest
from fastapi import HTTPException
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from andyur import identity, otel
from andyur.server import auth

CTX = {"agent": "scout", "run_id": "run-1", "workflow_id": "wf-1"}


@pytest.fixture
def spans(monkeypatch):
    """Point auth._tracer at an in-memory exporter; return a getter for the spans."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(auth, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(auth, "_TRACE_AUTH", True)   # opt-in auth tracing (off by default)
    monkeypatch.setattr(otel, "OTEL_ON", True)   # so context_from rebuilds the run's trace
    from andyur import config
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    return exporter.get_finished_spans


def _attrs(span):
    return dict(span.attributes)


def test_matching_svid_emits_a_match_bind_span(spans, monkeypatch):
    monkeypatch.setattr(identity, "validate_token",
                        lambda t: "spiffe://andyur.local/agent/scout/run/run-1")
    auth._bind_run_token_to_svid(CTX, "Bearer x")
    (span,) = spans()
    assert span.name == "auth.bind"
    a = _attrs(span)
    assert a["andyur.auth.bind"] == "match"
    assert a["andyur.auth.svid"] == "spiffe://andyur.local/agent/scout/run/run-1"
    assert a["andyur.auth.svid_agent"] == "scout" and a["andyur.auth.svid_run"] == "run-1"
    assert span.status.status_code != StatusCode.ERROR


def test_mismatched_svid_emits_a_mismatch_span_marked_error(spans, monkeypatch):
    monkeypatch.setattr(identity, "validate_token",
                        lambda t: "spiffe://andyur.local/agent/scout/run/OTHER")
    with pytest.raises(HTTPException):
        auth._bind_run_token_to_svid(CTX, "Bearer x")
    (span,) = spans()
    assert _attrs(span)["andyur.auth.bind"] == "mismatch"
    assert span.status.status_code == StatusCode.ERROR   # the 403 is recorded on the span


def test_role_svid_is_labelled_on_the_span(spans, monkeypatch):
    monkeypatch.setattr(identity, "validate_token",
                        lambda t: "spiffe://andyur.local/operator")
    auth._bind_run_token_to_svid(CTX, "Bearer x")   # lax: allowed
    assert _attrs(spans()[0])["andyur.auth.bind"] == "role-svid"


def test_absent_svid_is_labelled_lax(spans):
    auth._bind_run_token_to_svid(CTX, None)
    assert _attrs(spans()[0])["andyur.auth.bind"] == "absent-lax"


# `test_no_span_when_identity_off` was here. Deleted, not adapted: it asserted
# that attestation emits no span when identity is off, and there is no longer a
# configuration in which identity is off.


# -- the headline: the auth span JOINS the run's own trace ---------------------

def test_require_run_span_joins_the_runs_trace(spans, monkeypatch):
    """A real run-scoped call: assert the auth.require_run span lands in the SAME
    trace as the run (its trace_id equals the one stored on the run record), so in
    Jaeger the identity decision renders next to the agent's tool calls."""
    import datetime
    from fastapi.testclient import TestClient
    from andyur import db
    from andyur.server import runtoken
    from andyur.server.app import app

    # a known trace id the run was 'triggered' under (W3C traceparent)
    trace_id_hex = "0af7651916cd43dd8448eb211c80319c"
    trace_ctx = f"00-{trace_id_hex}-b7ad6b7169203331-01"
    monkeypatch.setattr(identity, "validate_token",
                        lambda t: "spiffe://andyur.local/agent/scout/run/run-x")

    with TestClient(app) as client:   # lifespan runs db.init_db()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with db.connect() as conn:
            conn.execute("INSERT INTO agents (name, created_at) VALUES ('scout', ?)", (now,))
            conn.execute("INSERT INTO runs (id, agent, state, created_at, trace_ctx) "
                         "VALUES ('run-x', 'scout', 'running', ?, ?)", (now, trace_ctx))
        token = runtoken.mint("scout", "run-x", "wf-1")
        r = client.get("/identity/verify-run", headers={
            "X-Andyur-Run-Token": token, "Authorization": "Bearer svid"})

    assert r.status_code == 200 and r.json()["run_id"] == "run-x"
    by_name = {s.name: s for s in spans()}
    assert "auth.require_run" in by_name and "auth.bind" in by_name
    # the decision span shares the run's trace id -> one trace per run
    assert by_name["auth.require_run"].context.trace_id == int(trace_id_hex, 16)
    assert by_name["auth.require_run"].attributes["andyur.auth.decision"] == "authorized"
    assert by_name["auth.bind"].attributes["andyur.auth.bind"] == "match"

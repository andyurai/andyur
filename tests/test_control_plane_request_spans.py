"""Every control-plane route records that it was called, and no caller decides
what trace it belongs to.

production-gaps 33. The control plane mounted no request-level instrumentation,
so most of its routes emitted NO span at all: a 401 at the boundary, a 422 on a
malformed cursor, a 403 from an owner gate were decisions the platform made and
did not write down -- which is the observability exit criteria's own test. Two
routes had grown an explicit `_decision_span` as a stopgap, one helper on two
routes out of forty.

`trust_traceparent` is FALSE by the operator's decision (2026-08-26). The caller
is authenticated, but trace identity is still the caller's ASSERTION: trusting
it would let an authenticated caller graft the control plane's decisions onto a
trace of their choosing, or join two unrelated callers' work into one. The cost
is that a console-to-server hop is two traces rather than one.
"""
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from fastapi.testclient import TestClient

from andyur import otel
from andyur.server import app as app_module
from conftest import NO_AUTH

client = TestClient(app_module.app)

FORGED_TRACE = "1" * 32
FORGED = f"00-{FORGED_TRACE}-2222222222222222-01"


@pytest.fixture
def spans(monkeypatch):
    """One in-memory provider for every tracer the request path reaches.

    `ObservedASGI` captures its tracer at construction, and the app is built at
    import, so the exporter is attached by patching the provider the SDK hands
    out rather than by rebuilding the app.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    monkeypatch.setattr(app_module, "_tracer", tracer)
    monkeypatch.setattr(otel, "setup_tracing", lambda name: tracer)
    monkeypatch.setattr(otel, "OTEL_ON", True)
    monkeypatch.setattr(otel, "setup_metrics", lambda name, **k: None)
    # the app's middleware already holds a tracer from import time; give the
    # instance the test's one so what it records is visible here
    for mw in getattr(app_module.app, "user_middleware", []):
        if getattr(mw.cls, "__name__", "") == "ObservedASGI":
            mw.kwargs.setdefault("service_name", "andyur-server")
    app_module.app.middleware_stack = None      # force a rebuild with the patch
    app_module.app.build_middleware_stack()
    return exporter


def _request_spans(exporter):
    return [s for s in exporter.get_finished_spans() if s.name.startswith("server.request")]


def test_a_refusal_at_the_boundary_is_recorded(env, spans):
    """The case that had no span at all: refused before any handler ran."""
    r = client.get("/runs", headers=NO_AUTH)
    assert r.status_code == 401
    got = _request_spans(spans)
    assert got, "an unauthenticated refusal produced no server span"
    assert got[0].attributes["http.response.status_code"] == 401


def test_an_ordinary_call_is_recorded_too(env, spans):
    # positive control: the span is not something only refusals get
    assert client.get("/agents").status_code == 200
    got = _request_spans(spans)
    assert got and got[0].attributes["http.response.status_code"] == 200


def test_a_caller_cannot_choose_the_trace_its_decisions_land_in(env, spans):
    """The operator's decision, as a property.

    An authenticated caller sending a traceparent must not become the parent of
    the control plane's own span, and must not decide its trace id.
    """
    r = client.get("/agents", headers={"traceparent": FORGED})
    assert r.status_code == 200
    [span] = _request_spans(spans)
    assert span.parent is None, "a caller's traceparent became the parent"
    assert format(span.context.trace_id, "032x") != FORGED_TRACE


def test_a_readiness_probe_does_not_get_a_span_of_its_own(env, spans):
    """Health is metrics-only here, and that is the opposite of the console's
    choice for a reason: this process sits behind readiness probes that arrive
    every few seconds, and a span each would be most of every trace."""
    assert client.get("/health").status_code == 200
    assert _request_spans(spans) == []


def test_the_route_level_decision_spans_still_nest_under_the_request_span(env, spans):
    """The two routes that grew their own span keep it, and it becomes a CHILD.

    Otherwise the reason a refusal was refused (`andyur.reason`) and the fact
    that a request happened would be two unrelated spans.
    """
    assert client.get("/runs").status_code == 200
    named = {s.name: s for s in spans.get_finished_spans()}
    assert "server.list_runs" in named
    request = _request_spans(spans)
    assert request, "no request span to nest under"
    assert named["server.list_runs"].parent is not None
    assert named["server.list_runs"].parent.span_id == request[0].context.span_id

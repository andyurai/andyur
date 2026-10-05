"""The console's telemetry, judged the way the exit criteria say: every
decision is a span carrying the reason BY NAME (the same word as the response
body and the log line), the request span wraps every path including static
and /healthz, the identity fetch is a dependency span in the platform's
vocabulary, the upstream call carries trace context, and a console-started
run's id lands on the span. Spans are captured with an in-memory exporter;
each test reddens when its instrumentation is removed (mutation suite).
"""
import asyncio
import logging

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from starlette.testclient import TestClient

from andyur import identity, otel
from andyur.console import server

SECRET = "test-console-secret"
LAUNCH = "test-launch-token"
ORIGIN = "http://127.0.0.1:9999"
H = server.SESSION_HEADER


@pytest.fixture
def spans(monkeypatch):
    """Every tracer the console reaches (its own, ObservedASGI's, and the
    dependency span's) resolves to one in-memory provider."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    monkeypatch.setattr(server, "_tracer", tracer)
    monkeypatch.setattr(otel, "setup_tracing", lambda name: tracer)
    # the conftest turns telemetry off for the suite; these tests are about
    # what happens with it ON, the deployed default
    monkeypatch.setattr(otel, "OTEL_ON", True)
    # ...but metrics would then try a real OTLP exporter; there is no collector here
    monkeypatch.setattr(otel, "setup_metrics", lambda name, **k: None)
    monkeypatch.setattr(otel, "try_record_metric", lambda *a, **k: True)
    return exporter


def _client(upstream=None, **kw):
    if upstream is None:
        upstream = httpx.AsyncClient(
            base_url="http://cp",
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": True})))
    app = server.build_app(SECRET, origin=ORIGIN, launch=server.LaunchToken(LAUNCH),
                           upstream=upstream, **kw)
    return TestClient(app, base_url=ORIGIN)


def _by_name(spans, name):
    return [s for s in spans.get_finished_spans() if s.name == name]


def test_a_refusal_is_a_span_with_the_reason_by_name(spans, caplog):
    c = _client()
    with caplog.at_level(logging.INFO, logger="andyur.console"):
        r = c.get("/api/agents", headers={H: SECRET, "origin": "http://evil.example"})
    assert r.json()["reason"] == "cross_origin"
    [span] = _by_name(spans, "console.proxy")
    a = span.attributes
    assert a["andyur.console.outcome"] == "refused"
    assert a["andyur.console.reason"] == "cross_origin"      # the same word
    assert a["andyur.console.route"] == "agents.list"        # the NAME, never the path
    assert a["http.response.status_code"] == 403
    assert "/agents" not in str(dict(a))
    # the log line is correlated to that span
    rec = [x for x in caplog.records if getattr(x, "event_name", "") == "console.refuse"][0]
    assert rec.event_fields["console_reason"] == "cross_origin"   # the same word
    assert rec.event_fields["reason"] == "refused"                # the platform bucket
    # and the request span (ObservedASGI) is the parent
    [req] = _by_name(spans, "console.request GET")
    assert span.parent is not None and span.parent.span_id == req.context.span_id
    assert req.attributes["http.response.status_code"] == 403


def test_every_reason_has_a_metric_bucket_AND_the_right_one():
    assert set(server._REASON_BUCKET) == set(server.Reason)
    # KEYS ARE NOT ENOUGH. Mapping bad_host to "timeout" kept every key present
    # and survived the suite: 16 of 19 reasons could be mis-bucketed silently,
    # and a bucket is what an operator groups refusals by. The mapping is a
    # decision per reason, so it is asserted per reason.
    assert {r.value: b for r, b in server._REASON_BUCKET.items()} == {
        # the caller asked for something it is not allowed to have
        "cross_origin": "refused", "bad_host": "refused", "bad_session": "refused",
        "launch_spent": "refused", "launch_unknown": "refused",
        # the caller's request is malformed or not a console call at all
        "missing_host": "invalid", "method_not_allowed": "invalid",
        "bad_path": "invalid", "not_a_console_route": "invalid",
        "client_disconnected": "invalid", "upstream_protocol_error": "invalid",
        # something the console depends on is not answering
        "session_expired": "unavailable", "idp_error": "unavailable",
        "identity_unavailable": "unavailable", "upstream_unreachable": "unavailable",
        # a limit was reached
        "body_too_large": "exhausted", "upstream_too_large": "exhausted",
        # a deadline passed
        "body_timeout": "timeout", "upstream_timeout": "timeout",
    }


def test_a_forwarded_call_records_outcome_and_upstream_status(spans):
    c = _client(httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(
        lambda r: httpx.Response(404, json={"detail": "no"}))))
    assert c.get("/api/agents/x", headers={H: SECRET}).status_code == 404
    [span] = _by_name(spans, "console.proxy")
    assert span.attributes["andyur.console.outcome"] == "forwarded"
    assert span.attributes["andyur.console.upstream_status"] == 404
    assert span.attributes["andyur.console.route"] == "agents.show"
    assert "andyur.console.reason" not in span.attributes


def test_a_console_started_run_puts_its_id_on_the_span(spans):
    c = _client(httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(
        lambda r: httpx.Response(201, json={"run_id": "3f9c1e7a4b0d4e2a"}))))
    c.post("/api/agents/x/trigger", headers={H: SECRET}, json={"reason": "r"})
    [span] = _by_name(spans, "console.proxy")
    assert span.attributes["andyur.run_id"] == "3f9c1e7a4b0d4e2a"


def test_trace_context_crosses_to_the_control_plane(spans):
    seen = {}
    def handler(r):
        seen["tp"] = r.headers.get("traceparent")
        return httpx.Response(200, json={})
    c = _client(httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler)))
    c.get("/api/agents", headers={H: SECRET})
    [span] = _by_name(spans, "console.proxy")
    assert seen["tp"] and format(span.context.trace_id, "032x") in seen["tp"]


def test_the_session_exchange_is_a_span(spans):
    c = _client()
    c.post("/session", json={"launch": LAUNCH})
    c.post("/session", json={"launch": LAUNCH})
    issued, spent = _by_name(spans, "console.session.issue")
    assert issued.attributes["andyur.console.outcome"] == "issued"
    assert spent.attributes["andyur.console.outcome"] == "refused"
    assert spent.attributes["andyur.console.reason"] == "launch_spent"


def test_static_and_healthz_requests_have_a_request_span(spans):
    # The platform suppresses health-endpoint spans by default (a readiness
    # probe every few seconds would be most of a Pod's trace). The console opts
    # back in, because it has no prober and /healthz is the single call the page
    # makes at boot to learn its control plane and its trace link. This pins
    # that opt-in: without it a failing boot is invisible in the trace.
    c = _client()
    c.get("/healthz")
    c.get("/nope.js")
    names = [s.name for s in spans.get_finished_spans()]
    assert names.count("console.request GET") == 2
    statuses = sorted(s.attributes["http.response.status_code"]
                      for s in _by_name(spans, "console.request GET"))
    assert statuses == [200, 404]


def test_the_identity_fetch_is_a_dependency_span_with_a_bounded_reason(spans, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError('SPIFFE socket file "/x/api.sock" does not exist')
    monkeypatch.setattr(identity, "fetch_token", broken)
    async def go():
        async with httpx.AsyncClient(auth=server.OperatorSvidAuth(),
                                     transport=httpx.MockTransport(lambda r: httpx.Response(200)),
                                     base_url="http://cp") as c:
            with pytest.raises(server.IdentityUnavailable):
                await c.get("/x")
    asyncio.run(go())
    [span] = _by_name(spans, "identity.fetch")
    assert span.attributes["andyur.dependency"] == "identity"
    assert span.attributes["andyur.operation"] == "fetch"


def test_a_session_refresh_is_a_span_with_its_outcome(spans):
    def idp(request):
        return httpx.Response(400, json={"error": "invalid_grant"})
    session = server.UserSession(
        {"access_token": "stale", "refresh_token": "rt1", "expires_in": 1},
        token_endpoint="http://idp/token", client_id="andyur-console")
    session._expires_at = 0
    c = _client(user_session=session,
                idp=httpx.AsyncClient(transport=httpx.MockTransport(idp)))
    assert c.get("/api/agents", headers={H: SECRET}).status_code == 401
    [span] = _by_name(spans, "console.session.refresh")
    assert span.attributes["andyur.console.outcome"] == "expired"


def test_telemetry_never_changes_a_response(monkeypatch):
    # a metric vocabulary error must not turn a refusal into a 500
    monkeypatch.setattr(otel, "try_record_metric", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    c = _client()
    with pytest.raises(RuntimeError):
        c.get("/api/agents")       # proves the patch is live
    monkeypatch.setattr(otel, "record_metric", lambda *a, **k: (_ for _ in ()).throw(ValueError("vocab")))
    monkeypatch.undo()
    monkeypatch.setattr(otel, "record_metric", lambda *a, **k: (_ for _ in ()).throw(ValueError("vocab")))
    r = _client().get("/api/agents")
    assert r.status_code == 401 and r.json()["reason"] == "bad_session"


# --- metrics, through a real reader ------------------------------------------
# The `spans` fixture stubs try_record_metric, which swallows every failure by
# design. A reason outside the platform's bounded vocabulary therefore meant the
# metric SILENTLY DID NOT EXIST and every test stayed green -- the exact shape
# of an assertion that cannot fail. These drive the real MeterProvider.

@pytest.fixture
def metrics(spans, monkeypatch):
    """A real MeterProvider behind an in-memory reader.

    Built ON TOP of `spans`, which stubs setup_metrics and try_record_metric so
    the trace tests need no collector -- those stubs are exactly what hid a bad
    metric, so this fixture puts the real functions back. The instrument cache
    is cleared too: it is keyed by (service, name) and would otherwise hand
    back an instrument built against a provider from an earlier test.
    """
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    reader = InMemoryMetricReader()
    otel._meter_providers.clear()
    otel._instruments.clear()
    monkeypatch.setattr(otel, "setup_metrics",
                        lambda name, **kw: _REAL_SETUP_METRICS(name, readers=(reader,)))
    monkeypatch.setattr(otel, "try_record_metric", _REAL_TRY_RECORD)
    yield reader
    otel._meter_providers.clear()
    otel._instruments.clear()


_REAL_SETUP_METRICS = otel.setup_metrics
_REAL_TRY_RECORD = otel.try_record_metric


def _points(reader, name):
    out = []
    data = reader.get_metrics_data()
    for rm in (data.resource_metrics if data else []):
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                if metric.name == name:
                    out.extend(metric.data.data_points)
    return out


def test_a_refusal_actually_records_its_decision_metric(spans, metrics):
    c = _client()
    assert c.get("/api/agents", headers={H: SECRET, "origin": "http://evil"}
                 ).status_code == 403
    points = _points(metrics, "andyur.authorization.decisions")
    assert points, "no decision metric was recorded at all"
    attrs = [dict(p.attributes) for p in points]
    assert {"andyur.outcome": "denied", "andyur.reason": "refused"} in attrs


def test_an_upstream_failure_counts_against_the_control_plane_dependency(spans, metrics):
    def dead(request):
        raise httpx.ConnectError("connection refused")
    c = _client(httpx.AsyncClient(base_url="http://cp",
                                  transport=httpx.MockTransport(dead)))
    assert c.get("/api/agents", headers={H: SECRET}).status_code == 502
    attrs = [dict(p.attributes) for p in _points(metrics, "andyur.dependency.failures")]
    assert {"andyur.dependency": "control-plane", "andyur.reason": "unavailable",
            "andyur.operation": "fetch"} in attrs, attrs
    # a CALLER's own mistake is not the dependency's failure
    assert c.get("/api/nope", headers={H: SECRET}).status_code == 403
    after = [dict(p.attributes) for p in _points(metrics, "andyur.dependency.failures")]
    assert len([a for a in after if a.get("andyur.dependency") == "control-plane"]) == 1


@pytest.mark.parametrize("reason", list(server.Reason))
def test_every_reason_records_a_metric_the_vocabulary_accepts(metrics, reason):
    # try_record_metric returns False rather than raising, so this asserts the
    # RETURN VALUE: a bucket outside observability._REASONS is a silent no-op
    # in production and would otherwise be invisible here too.
    assert otel.try_record_metric(
        server.SERVICE, "andyur.authorization.decisions",
        andyur__outcome="denied",
        andyur__reason=server._REASON_BUCKET[reason]) is True, reason


# --- trace context from a browser is never a parent ---------------------------

def test_a_browser_supplied_traceparent_is_not_a_parent(spans):
    # The page is untrusted input. If ObservedASGI trusted its traceparent, any
    # visitor could graft the operator's decisions onto a trace of their
    # choosing -- or join two unrelated operators' sessions into one.
    forged = "00-11111111111111111111111111111111-2222222222222222-01"
    c = _client()
    c.get("/api/agents", headers={H: SECRET, "traceparent": forged})
    [req] = _by_name(spans, "console.request GET")
    assert req.parent is None, "the request span took a browser header as its parent"
    assert format(req.context.trace_id, "032x") != "1" * 32
    # positive control: the console's OWN span is a child of the request span,
    # so "no parent" above is the header being ignored and not tracing being off
    [proxy] = _by_name(spans, "console.proxy")
    assert proxy.parent is not None and proxy.parent.span_id == req.context.span_id


# --- who made the decision ----------------------------------------------------

def test_the_decision_span_names_the_human_under_user_auth(spans):
    # A trace that says an agent was deleted but not by whom cannot answer the
    # question it is read for after an incident.
    import base64 as _b64
    import json as _json

    def _jwt(sub):
        payload = _b64.urlsafe_b64encode(_json.dumps({"sub": sub}).encode()).decode().rstrip("=")
        return f"aGRy.{payload}.c2ln"

    session = server.UserSession({"access_token": _jwt("alice@example.com"),
                                  "expires_in": 3600},
                                 token_endpoint="http://idp/token", client_id="c")
    c = _client(user_session=session)
    assert c.get("/api/agents", headers={H: SECRET}).status_code == 200
    [span] = _by_name(spans, "console.proxy")
    assert span.attributes["enduser.id"] == "alice@example.com"
    # the token itself never reaches telemetry
    assert _jwt("alice@example.com") not in str(dict(span.attributes))


def test_a_malformed_or_oversized_subject_never_reaches_a_span():
    # A span attribute is not a place to put whatever a forged token holds.
    assert server.unverified_subject("not.a.jwt") is None
    assert server.unverified_subject("") is None
    import base64 as _b64
    import json as _json
    big = _b64.urlsafe_b64encode(_json.dumps({"sub": "x" * 200}).encode()).decode().rstrip("=")
    assert server.unverified_subject(f"h.{big}.s") is None
    ok = _b64.urlsafe_b64encode(_json.dumps({"sub": "bob"}).encode()).decode().rstrip("=")
    assert server.unverified_subject(f"h.{ok}.s") == "bob"     # positive control


def test_a_console_failure_is_an_error_span_not_a_quiet_one(spans):
    # A 5xx is the console FAILING, not the console refusing. Left as OK, every
    # "errors in the last hour" query over the trace store reads zero while the
    # operator's page is down.
    from opentelemetry.trace import StatusCode

    def dead(request):
        raise httpx.ConnectError("connection refused")
    c = _client(httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(dead)))
    assert c.get("/api/agents", headers={H: SECRET}).status_code == 502
    [span] = _by_name(spans, "console.proxy")
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description == "upstream_unreachable"

    # POSITIVE CONTROL: a 4xx is a REFUSAL, and a refusal is not an error.
    spans.clear()
    c2 = _client()
    assert c2.get("/api/agents", headers={H: SECRET, "origin": "http://evil"}).status_code == 403
    [refused] = _by_name(spans, "console.proxy")
    assert refused.status.status_code != StatusCode.ERROR
    assert refused.attributes["andyur.console.outcome"] == "refused"


def test_the_decision_span_names_the_operator_identity_it_acted_as(spans, monkeypatch):
    # With the console as a single-operator tool there is no signed-in human, so
    # the SPIFFE id this process holds is the only principal there is. Without it
    # a trace says an agent was deleted and cannot say by what.
    import base64 as _b64
    import json as _json

    def _svid(sub):
        payload = _b64.urlsafe_b64encode(_json.dumps({"sub": sub}).encode()).decode().rstrip("=")
        return f"aGRy.{payload}.c2ln"

    monkeypatch.setattr(identity, "fetch_token",
                        lambda *a, **k: _svid("spiffe://andyur.local/operator"))
    monkeypatch.setattr(identity, "client_tls", lambda role: (None, False))
    c = _client(upstream=None)
    # the real auth adapter has to run, so drive the console's OWN upstream
    auth = server.OperatorSvidAuth()
    upstream = httpx.AsyncClient(base_url="http://cp", auth=auth,
                                 transport=httpx.MockTransport(
                                     lambda r: httpx.Response(200, json={})))
    upstream.andyur_operator_auth = auth
    c = _client(upstream)
    assert c.get("/api/agents", headers={H: SECRET}).status_code == 200
    [span] = _by_name(spans, "console.proxy")
    assert span.attributes["andyur.operator.id"] == "spiffe://andyur.local/operator"
    # the SVID itself is never on the span
    assert _svid("spiffe://andyur.local/operator") not in str(dict(span.attributes))

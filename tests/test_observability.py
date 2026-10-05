import io
import json
import logging
import math
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import anyio
import pytest
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from andyur import observability, otel


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_telemetry(monkeypatch):
    monkeypatch.setattr(otel, "OTEL_ON", False)
    monkeypatch.setattr(otel, "_meter_providers", {})
    monkeypatch.setattr(otel, "_instruments", {})
    monkeypatch.setattr(otel, "_closed", False)
    package = logging.getLogger("andyur")
    old_handlers, old_level = package.handlers[:], package.level
    root = logging.getLogger()
    old_root_handlers = root.handlers[:]
    package.handlers.clear()
    root.handlers.clear()
    yield
    otel.shutdown()
    package.handlers[:] = old_handlers
    package.setLevel(old_level)
    root.handlers[:] = old_root_handlers


def test_json_log_has_stable_envelope_and_no_arbitrary_record_fields():
    stream = io.StringIO()
    logger = logging.getLogger("andyur.test.envelope")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(observability.JsonFormatter("andyur-test"))
    logger.addHandler(handler)
    observability.event(logger, "run.completed", outcome="success", duration_ms=12)
    value = json.loads(stream.getvalue())
    assert value == {
        "event": "run.completed",
        "fields": {"duration_ms": 12, "outcome": "success"},
        "logger": "andyur.test.envelope",
        "message": "run.completed",
        "schema": "andyur.log.v1",
        "service": "andyur-test",
        "severity": "INFO",
        "timestamp": value["timestamp"],
    }


@pytest.mark.parametrize("field", [
    "token", "authorization", "api_key", "request_body", "transcript",
])
def test_structured_log_refuses_secret_and_content_fields(field):
    logger = logging.getLogger("andyur.test")
    with pytest.raises(ValueError):
        observability.event(logger, "dependency.failed", **{field: "leak"})


def test_structured_log_refuses_secret_disguised_in_allowed_field():
    with pytest.raises(ValueError, match="invalid event outcome"):
        observability.event(logging.getLogger("andyur.test"),
                            "run.completed", outcome="Bearer TOP-SECRET",
                            duration_ms=1)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, True])
def test_structured_log_refuses_non_finite_or_boolean_duration(value):
    with pytest.raises(ValueError, match="invalid event duration"):
        observability.event(logging.getLogger("andyur.test"),
                            "run.completed", outcome="success", duration_ms=value)


def test_metrics_refuse_identifiers_unknown_dimensions_and_unbounded_values():
    with pytest.raises(ValueError, match="bounded vocabulary"):
        observability.metric_attributes(run_id="run-123")
    with pytest.raises(ValueError, match="low-cardinality"):
        observability.metric_attributes(andyur__reason="Run 123 failed: arbitrary text")
    with pytest.raises(ValueError, match="stable vocabulary"):
        observability.instrument_kind("andyur.dynamic.metric")


def test_record_metric_refuses_service_label_spoof(monkeypatch):
    monkeypatch.setattr(otel, "metric", lambda *args: None)
    with pytest.raises(ValueError, match="must match"):
        otel.record_metric("andyur-server", "andyur.run.outcomes",
                           service__name="attacker-service", andyur__outcome="success")


def test_traced_asgi_records_bounded_request_metrics(monkeypatch):
    reader = InMemoryMetricReader()
    original = otel.setup_metrics

    def setup(service_name, *, readers=None):
        return original(service_name, readers=(reader,))

    monkeypatch.setattr(otel, "setup_metrics", setup)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    wrapped = otel.ObservedASGI(app, service_name="andyur-test", operation="http.request")
    sent = []
    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    anyio.run(wrapped, {"type": "http", "method": "GET", "path": "/runs/private-id",
                        "headers": []}, receive, send)

    data = reader.get_metrics_data()
    metrics = {metric.name: metric for resource in data.resource_metrics
               for scope in resource.scope_metrics for metric in scope.metrics}
    assert set(metrics) == {
        "andyur.http.server.requests",
        "andyur.http.server.duration",
        "andyur.http.server.in_flight",
    }
    request_point = metrics["andyur.http.server.requests"].data.data_points[0]
    assert request_point.value == 1
    assert dict(request_point.attributes) == {
        "http.request.method": "GET",
        "andyur.endpoint.class": "api",
        "http.response.status_code_class": "2xx",
    }
    assert "private-id" not in json.dumps(dict(request_point.attributes))


def test_domain_metrics_require_actionable_dimensions_and_nonnegative_values():
    with pytest.raises(ValueError, match="requires attributes"):
        otel.record_metric("andyur-test", "andyur.run.outcomes")
    with pytest.raises(ValueError, match="non-negative"):
        otel.record_metric("andyur-test", "andyur.run.outcomes", -1,
                           andyur__outcome="failure", andyur__operation="finish")
    for value in (math.nan, math.inf, -math.inf, True):
        with pytest.raises(ValueError, match="finite real"):
            otel.record_metric("andyur-test", "andyur.run.outcomes", value,
                               andyur__outcome="failure",
                               andyur__operation="finish")


def test_traced_asgi_preserves_existing_trusted_parent_default(monkeypatch):
    parent = object()
    seen = []

    class Span:
        def set_attribute(self, *args): pass
        def set_status(self, *args): pass
        def record_exception(self, *args): pass

    class SpanContext:
        def __enter__(self): return Span()
        def __exit__(self, *args): pass

    class Tracer:
        def start_as_current_span(self, *args, **kwargs):
            seen.append(kwargs["context"])
            return SpanContext()

    monkeypatch.setattr(otel, "context_from",
                        lambda value: parent if value == "00-trusted" else None)
    monkeypatch.setattr(otel, "setup_tracing", lambda service: Tracer())
    monkeypatch.setattr(otel, "setup_metrics", lambda service: None)
    monkeypatch.setattr(otel, "metric", lambda *args: type("Instrument", (), {
        "add": lambda *args, **kwargs: None,
        "record": lambda *args, **kwargs: None,
    })())

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive(): return {"type": "http.disconnect"}
    async def send(message): pass

    wrapper = otel.TracedASGI(app, service_name="andyur-test")
    assert wrapper.trust_traceparent is True
    anyio.run(wrapper, {"type": "http", "method": "POST", "path": "/mcp",
                        "headers": [(b"traceparent", b"00-trusted")]}, receive, send)
    assert seen == [parent]


def test_traced_asgi_metric_failure_does_not_change_response(monkeypatch):
    class BrokenInstrument:
        def add(self, *args, **kwargs):
            raise RuntimeError("metrics backend failed")
        record = add

    monkeypatch.setattr(otel, "metric", lambda *args: BrokenInstrument())
    called, sent = [], []

    async def app(scope, receive, send):
        called.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    wrapper = otel.ObservedASGI(app, service_name="andyur-test")
    anyio.run(wrapper, {"type": "http", "method": "GET", "path": "/",
                        "headers": []}, receive, send)
    assert called == [True]
    assert sent[0]["status"] == 200


def test_traced_asgi_metric_failure_does_not_mask_application_error(monkeypatch):
    class PrimaryError(RuntimeError): pass
    class BrokenInstrument:
        def add(self, *args, **kwargs): raise RuntimeError("metrics failed")
        record = add

    monkeypatch.setattr(otel, "metric", lambda *args: BrokenInstrument())

    async def app(scope, receive, send): raise PrimaryError("application failed")
    async def receive(): return {"type": "http.disconnect"}
    async def send(message): pass

    wrapper = otel.ObservedASGI(app, service_name="andyur-test")
    with pytest.raises(PrimaryError, match="application failed"):
        anyio.run(wrapper, {"type": "http", "method": "GET", "path": "/",
                            "headers": []}, receive, send)


def test_flush_isolates_exporter_failure(monkeypatch):
    class BrokenProvider:
        def force_flush(self):
            raise RuntimeError("collector unavailable")

    monkeypatch.setattr(otel, "_providers", {"trace": BrokenProvider()})
    monkeypatch.setattr(otel, "_meter_providers", {"metrics": BrokenProvider()})
    monkeypatch.setattr(otel, "OTEL_ON", True)
    otel.flush()


def test_metric_provider_initialization_is_singleton_under_concurrency():
    readers = [InMemoryMetricReader() for _ in range(16)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        meters = list(pool.map(
            lambda reader: otel.setup_metrics("andyur-concurrent", readers=(reader,)),
            readers,
        ))
    assert len(otel._meter_providers) == 1
    assert len({id(meter) for meter in meters}) == 1


def test_shutdown_is_idempotent_and_clears_provider_caches(monkeypatch):
    calls = []

    class Provider:
        def force_flush(self):
            calls.append("flush")
        def shutdown(self):
            calls.append("shutdown")

    monkeypatch.setattr(otel, "OTEL_ON", True)
    monkeypatch.setattr(otel, "_providers", {"trace": Provider()})
    monkeypatch.setattr(otel, "_meter_providers", {"metric": Provider()})
    monkeypatch.setattr(otel, "_instruments", {("service", "metric"): object()})
    monkeypatch.setattr(otel, "_closed", False)
    otel.shutdown()
    otel.shutdown()
    assert calls == ["flush", "flush", "shutdown", "shutdown"]
    assert otel._providers == otel._meter_providers == otel._instruments == {}
    assert otel._closed is True


def test_setup_racing_shutdown_cannot_leak_provider(monkeypatch):
    monkeypatch.setattr(otel, "OTEL_ON", True)
    reader = InMemoryMetricReader()

    def setup():
        try:
            otel.setup_metrics("andyur-race", readers=(reader,))
        except RuntimeError as exc:
            assert "shut down" in str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda fn: fn(), (setup, otel.shutdown)))
    assert otel._closed is True
    assert otel._meter_providers == {}


def test_instrument_creation_racing_shutdown_cannot_repopulate_cache(monkeypatch):
    entered, release = threading.Event(), threading.Event()

    class Meter:
        def create_counter(self, *args, **kwargs):
            entered.set()
            assert release.wait(2)
            return object()
        create_histogram = create_counter
        create_up_down_counter = create_counter

    monkeypatch.setattr(otel, "setup_metrics", lambda service: Meter())
    with ThreadPoolExecutor(max_workers=2) as pool:
        creating = pool.submit(
            otel.metric, "andyur-race", "andyur.run.outcomes")
        assert entered.wait(2)
        closing = pool.submit(otel.shutdown)
        release.set()
        creating.result()
        closing.result()
    assert otel._closed is True
    assert otel._instruments == {}


def test_dependency_observation_emits_success_red_metrics(monkeypatch):
    recorded = []
    monkeypatch.setattr(otel, "setup_tracing",
                        lambda service: (_ for _ in ()).throw(RuntimeError("offline")))
    monkeypatch.setattr(otel, "try_record_metric",
                        lambda *args, **kwargs: recorded.append((args, kwargs)) or True)
    with otel.observe_dependency(
            "andyur-credential-service", "vault", "fetch", lambda exc: "unknown"):
        result = "TOP-SECRET-RESULT"
    assert result == "TOP-SECRET-RESULT"
    assert [item[0][1] for item in recorded] == [
        "andyur.dependency.calls", "andyur.dependency.duration"]
    assert all(item[1]["andyur__outcome"] == "success" for item in recorded)
    assert "TOP-SECRET-RESULT" not in repr(recorded)


def test_dependency_observation_preserves_primary_failure_and_bounds_reason(monkeypatch):
    recorded, events = [], []
    monkeypatch.setattr(otel, "setup_tracing",
                        lambda service: (_ for _ in ()).throw(RuntimeError("offline")))
    monkeypatch.setattr(otel, "try_record_metric",
                        lambda *args, **kwargs: recorded.append((args, kwargs)) or True)
    monkeypatch.setattr(observability, "event",
                        lambda *args, **kwargs: events.append((args, kwargs)))

    class Primary(RuntimeError): pass
    with pytest.raises(Primary, match="vault failed"):
        with otel.observe_dependency(
                "andyur-credential-service", "vault", "fetch",
                lambda exc: "unbounded attacker text"):
            raise Primary("vault failed")
    assert [item[0][1] for item in recorded] == [
        "andyur.dependency.calls", "andyur.dependency.failures",
        "andyur.dependency.duration"]
    assert recorded[1][1]["andyur__reason"] == "unknown"
    assert events[0][1] == {
        "dependency": "vault", "reason": "unknown", "operation": "fetch"}


def test_dependency_telemetry_failure_cannot_change_operation(monkeypatch):
    monkeypatch.setattr(otel, "setup_tracing",
                        lambda service: (_ for _ in ()).throw(RuntimeError("trace failed")))
    monkeypatch.setattr(otel, "record_metric",
                        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("metric failed")))
    with otel.observe_dependency(
            "andyur-credential-service", "vault", "fetch", lambda exc: "unknown"):
        result = 42
    assert result == 42


def test_dependency_span_exit_failure_cannot_change_operation(monkeypatch):
    class Manager:
        def __enter__(self): return object()
        def __exit__(self, *args): raise RuntimeError("span exit failed")
    class Tracer:
        def start_as_current_span(self, *args, **kwargs): return Manager()
    monkeypatch.setattr(otel, "setup_tracing", lambda service: Tracer())
    monkeypatch.setattr(otel, "try_record_metric", lambda *args, **kwargs: True)
    with otel.observe_dependency(
            "andyur-credential-service", "vault", "fetch", lambda exc: "unknown"):
        result = 43
    assert result == 43


def test_dependency_failure_span_never_records_exception_message(monkeypatch):
    events = []
    class Span:
        def add_event(self, name, attributes): events.append((name, attributes))
        def set_status(self, status): pass
    class Manager:
        def __enter__(self): return Span()
        def __exit__(self, *args): pass
    class Tracer:
        def start_as_current_span(self, *args, **kwargs): return Manager()
    monkeypatch.setattr(otel, "setup_tracing", lambda service: Tracer())
    monkeypatch.setattr(otel, "try_record_metric", lambda *args, **kwargs: True)
    primary = RuntimeError("Bearer TOP-SECRET")
    with pytest.raises(RuntimeError) as caught:
        with otel.observe_dependency(
                "andyur-credential-service", "vault", "fetch",
                lambda exc: "unavailable"):
            raise primary
    assert caught.value is primary
    assert events == [("dependency.failure", {"andyur.reason": "unavailable"})]
    assert "TOP-SECRET" not in repr(events)


def test_dependency_span_canonicalizes_untrusted_signal_names(monkeypatch):
    seen, loggers = [], []
    class Span:
        def add_event(self, name, attributes): seen.append((name, attributes))
        def set_status(self, status): pass
    class Manager:
        def __enter__(self): return Span()
        def __exit__(self, *args): pass
    class Tracer:
        def start_as_current_span(self, name, **kwargs):
            seen.append((name, kwargs["attributes"]))
            return Manager()
    monkeypatch.setattr(otel, "setup_tracing", lambda service: Tracer())
    monkeypatch.setattr(otel, "try_record_metric", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        observability, "event",
        lambda logger, *args, **kwargs: loggers.append(logger.name))
    SecretError = type("BearerTOPSECRET", (RuntimeError,), {})
    primary = SecretError("TOP-SECRET")
    with pytest.raises(SecretError) as caught:
        with otel.observe_dependency(
                "Service Bearer TOP-SECRET", "Bearer TOP-SECRET", "secret/value",
                lambda exc: "unavailable"):
            raise primary
    assert caught.value is primary
    assert seen[0] == ("unknown.unknown", {
        "andyur.dependency": "unknown", "andyur.operation": "unknown"})
    assert "TOP-SECRET" not in repr(seen)
    assert "BearerTOPSECRET" not in repr(seen)
    assert loggers == ["andyur.andyur-unknown"]


def test_live_alert_gate_pins_rules_states_and_teardown():
    source = (ROOT / "infra/observability/verify-alerts.sh").read_text()
    assert "prom/prometheus@sha256:" in source
    assert "prometheus-alerts.yaml" in source
    assert source.count('assert_state ') == 4
    assert "wait_scraped" in source
    assert "--connect-timeout 2 --max-time 3" in source
    assert "subprocess.run(sys.argv[1:], timeout=60)" in source
    assert "if actual != expected:" in source
    assert "assert_state inactive\n" in source
    assert "assert_state pending" in source
    assert "assert_state firing" in source
    assert "container_absent" in source
    assert "Docker daemon unavailable while verifying teardown" in source
    assert "--filter \"name=^/${CONTAINER}$\"" in source
    for alert in (
            "AndyurHttpServerErrorRate", "AndyurDependencyFailures",
            "AndyurRunFailures"):
        assert alert in source

"""OpenTelemetry tracing for Andyur.

A run crosses three processes (server, daemon, runner), so a single agent run
should read as one distributed trace. We achieve that by anchoring every span
to a trace context created when the run is triggered and persisted on the run
record; each process starts its spans under that same context, so they share
one trace id and render as one trace in Jaeger.

Tracing is a framework invariant and is on by default. `ANDYUR_OTEL=off` is the
explicit development/test escape hatch; with it off, every function here is a
cheap no-op and Andyur needs no collector.
"""

import os
import re
import uuid
import atexit
import contextlib
import logging
import threading
import time
from collections.abc import Awaitable, Callable

from . import observability

_LOG = logging.getLogger("andyur.otel")

def _enabled() -> bool:
    raw = os.environ.get("ANDYUR_OTEL", "on").lower()
    if raw in ("1", "on", "true"):
        return True
    if raw in ("0", "off", "false"):
        return False
    raise RuntimeError(
        f"ANDYUR_OTEL={raw!r} is invalid; use on or off. Refusing to silently "
        "disable framework telemetry because of a configuration typo.")


OTEL_ON = _enabled()
# OTLP/HTTP endpoint of the collector (Jaeger all-in-one). /v1/traces is added
# by the exporter.
ENDPOINT = os.environ.get("ANDYUR_OTEL_ENDPOINT", "http://localhost:4318")

_providers: dict[str, object] = {}
_meter_providers: dict[str, object] = {}
_instruments: dict[tuple[str, str], object] = {}
_provider_lock = threading.RLock()
_closed = False
# Extra span processors every provider gets (existing and future ones): the
# conformance gate attaches an in-memory exporter here so it can record the
# span names a run produced without a collector. Never used in production.
_extra_span_processors: list = []
# THIS PROCESS, distinct from every other process of the same service. Without
# it `service.name` is all a reader has, and every console on a machine shares
# it -- so a gate reading its own refusals back out of the collector cannot
# tell them from another worktree's, and a time window is the only bound
# available. With it, a read-back can be bound to the run that produced it.
INSTANCE_ID = uuid.uuid4().hex


# How often one signal may report that its exports are failing. An exporter
# that cannot reach its backend fails EVERY batch, so an unthrottled report is
# a log flood; one line a minute per signal is enough to notice and cheap
# enough to leave on.
_EXPORT_COMPLAINT_SECONDS = 60.0
_last_complaint: dict[str, float] = {}


class _Audible:
    """An OTLP exporter that says so when its exports fail.

    `telemetry.export.failed` has been a declared event with a field schema
    since observability.py was written and NOTHING has ever emitted it. That is
    why the dev stack pointed metrics at a trace backend for as long as it did:
    every batch 404'd, forever, and the only visible difference between a
    working exporter and one shouting into a wall was that a metric assertion
    quietly stopped meaning anything.

    Failures are swallowed exactly as before -- telemetry never changes the
    operation it observes -- but they are no longer SILENT.
    """

    def __init__(self, inner, signal: str) -> None:
        self._inner = inner
        self._signal = signal

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def export(self, *args, **kwargs):
        try:
            result = self._inner.export(*args, **kwargs)
        except Exception as exc:                                   # noqa: BLE001
            self._complain(type(exc).__name__)
            raise
        if getattr(result, "name", "") == "FAILURE" or result is False:
            self._complain("export rejected by the backend")
        return result

    def _complain(self, detail: str) -> None:
        now = time.monotonic()
        last = _last_complaint.get(self._signal, 0.0)
        if now - last < _EXPORT_COMPLAINT_SECONDS:
            return
        _last_complaint[self._signal] = now
        try:
            observability.event(
                _LOG, "telemetry.export.failed", level=logging.WARNING,
                signal=self._signal, reason="unavailable")
            _LOG.warning("telemetry export failing for %s -> %s (%s)",
                         self._signal, ENDPOINT, detail)
        except Exception:                                          # noqa: BLE001
            pass          # a failure to report a failure changes nothing


def _resource(service_name: str):
    from opentelemetry.sdk.resources import Resource

    return Resource.create({"service.name": service_name,
                            "service.instance.id": INSTANCE_ID})
# A span attribute carrying a value an untrusted party chose (a request path,
# a model name) is bounded: the body cap is 2 MiB, an attribute is not.
ATTRIBUTE_MAX_CHARS = 256


def safe_attribute(value) -> str:
    """An untrusted string as a span attribute: decoded, redacted, bounded.

    Percent-DECODED first, so `Bearer%20...` cannot slip past the shapes the
    redactor knows; then the ONE redactor the run's logs and captured output
    use (prefix shapes AND token-shaped runs -- R MED-1 on PR #25); the bound
    LAST, so a secret cut at the bound cannot escape as a prefix.
    """
    from urllib.parse import unquote
    from .redact import redact
    text = str(value if value is not None else "")
    try:
        text = unquote(text)
    except Exception:
        pass
    text = redact(text)
    return text if len(text) <= ATTRIBUTE_MAX_CHARS else text[:ATTRIBUTE_MAX_CHARS - 1] + "\u2026"


def attach_span_processor(processor) -> None:
    """Add a span processor to every provider, now and later (gate/test seam)."""
    with _provider_lock:
        _extra_span_processors.append(processor)
        for provider in _providers.values():
            provider.add_span_processor(processor)


def setup_tracing(service_name: str):
    """Configure a TracerProvider that exports to the collector and return a
    tracer. Idempotent per service name; a no-op tracer when tracing is off."""
    # This existing cross-component seam now configures all three signals.
    # Operators may install their own handlers first; configure_logging respects
    # that and never replaces an existing logging pipeline.
    observability.configure_logging(service_name)
    setup_metrics(service_name)
    if not OTEL_ON:
        from opentelemetry import trace

        return trace.get_tracer(service_name)

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    with _provider_lock:
        if _closed:
            raise RuntimeError("telemetry providers are shut down")
        if service_name not in _providers:
            provider = TracerProvider(
                resource=_resource(service_name),
                shutdown_on_exit=False,
            )
            provider.add_span_processor(
                BatchSpanProcessor(
                    _Audible(OTLPSpanExporter(endpoint=f"{ENDPOINT}/v1/traces"),
                             "traces")
                )
            )
            for extra in _extra_span_processors:
                provider.add_span_processor(extra)
            # The first service in a process wins the global provider; later
            # services still get a working tracer from their own provider.
            if not _providers:
                trace.set_tracer_provider(provider)
            _providers[service_name] = provider

    return _providers[service_name].get_tracer("andyur")


def get_tracer(service_name: str = "andyur"):
    from opentelemetry import trace

    return trace.get_tracer(service_name)


def setup_metrics(service_name: str, *, readers=None):
    """Configure a per-service OTLP MeterProvider and return its meter.

    ``readers`` is an explicit test/embedding seam. Production uses the OTLP
    HTTP exporter and a periodic reader, keeping backend choice out of callers.
    """
    if not OTEL_ON and readers is None:
        from opentelemetry import metrics
        return metrics.get_meter(service_name)

    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.resources import Resource

    with _provider_lock:
        if _closed:
            raise RuntimeError("telemetry providers are shut down")
        if service_name not in _meter_providers:
            if readers is None:
                from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                    OTLPMetricExporter,
                )
                from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
                readers = (PeriodicExportingMetricReader(_Audible(
                    OTLPMetricExporter(endpoint=f"{ENDPOINT}/v1/metrics"),
                    "metrics")),)
            _meter_providers[service_name] = MeterProvider(
                resource=_resource(service_name),
                metric_readers=readers,
                shutdown_on_exit=False,
            )
    return _meter_providers[service_name].get_meter("andyur")


def metric(service_name: str, name: str):
    """Return a cached instrument from Andyur's fixed metric vocabulary."""
    key = (service_name, name)
    with _provider_lock:
        if _closed:
            raise RuntimeError("telemetry providers are shut down")
        if key not in _instruments:
            meter = setup_metrics(service_name)
            kind = observability.instrument_kind(name)
            factory = {
                "counter": meter.create_counter,
                "histogram": meter.create_histogram,
                "up_down_counter": meter.create_up_down_counter,
            }[kind]
            unit = "s" if name.endswith("duration") else "1"
            _instruments[key] = factory(name, unit=unit)
        return _instruments[key]


def record_metric(service_name: str, name: str, value: int | float = 1,
                  **attributes: str) -> None:
    """Record one stable metric after enforcing Andyur's cardinality policy."""
    supplied_service = attributes.pop("service__name", service_name)
    if supplied_service != service_name:
        raise ValueError("metric service.name must match the configured service")
    observability.metric_attributes(service__name=service_name)
    clean = observability.metric_attributes(**attributes)
    observability.validate_record(name, value, clean)
    instrument = metric(service_name, name)
    if observability.instrument_kind(name) == "histogram":
        instrument.record(value, clean)
    else:
        instrument.add(value, clean)


def try_record_metric(service_name: str, name: str, value: int | float = 1,
                      **attributes: str) -> bool:
    """Record telemetry without ever changing the observed operation."""
    try:
        record_metric(service_name, name, value, **attributes)
        return True
    except Exception:
        return False


@contextlib.contextmanager
def _client_span(service_name: str, dependency: str, operation: str):
    """Yield an optional span while isolating SDK enter and exit failures."""
    manager = None
    span = None
    try:
        from opentelemetry.trace import SpanKind
        manager = setup_tracing(service_name).start_as_current_span(
            f"{dependency}.{operation}", kind=SpanKind.CLIENT,
            attributes={"andyur.dependency": dependency,
                        "andyur.operation": operation})
        span = manager.__enter__()
    except Exception:
        manager = None
        span = None
    try:
        yield span
    finally:
        if manager is not None:
            try:
                manager.__exit__(None, None, None)
            except Exception:
                pass


@contextlib.contextmanager
def observe_dependency(service_name: str, dependency: str, operation: str,
                       classify_failure: Callable[[Exception], str]):
    """One safe CLIENT span plus RED metrics around a dependency operation.

    The classifier returns one of Andyur's bounded reason codes. Telemetry
    initialization, recording, formatting, and export are all subordinate to
    the wrapped operation: none may replace its return value or exception.
    """
    try:
        service_name = observability.metric_attributes(**{
            "service__name": service_name})["service.name"]
    except Exception:
        service_name = "andyur-unknown"
    try:
        bounded = observability.metric_attributes(**{
            "andyur__dependency": dependency,
            "andyur__operation": operation,
            "andyur__outcome": "success",
        })
        dependency = bounded["andyur.dependency"]
        operation = bounded["andyur.operation"]
    except Exception:
        dependency = "unknown"
        operation = "unknown"
    started = time.monotonic()
    with _client_span(service_name, dependency, operation) as span:
        try:
            yield
        except Exception as exc:
            try:
                reason = classify_failure(exc)
                bounded = observability.metric_attributes(**{
                    "andyur__dependency": dependency,
                    "andyur__operation": operation,
                    "andyur__reason": reason,
                })
                reason = bounded["andyur.reason"]
            except Exception:
                reason = "unknown"
            try_record_metric(
                service_name, "andyur.dependency.calls",
                andyur__dependency=dependency, andyur__operation=operation,
                andyur__outcome="failure")
            try_record_metric(
                service_name, "andyur.dependency.failures",
                andyur__dependency=dependency, andyur__operation=operation,
                andyur__reason=reason)
            try_record_metric(
                service_name, "andyur.dependency.duration",
                time.monotonic() - started, andyur__dependency=dependency,
                andyur__operation=operation, andyur__outcome="failure")
            try:
                observability.event(
                    logging.getLogger(f"andyur.{service_name}"),
                    "dependency.failed", dependency=dependency,
                    reason=reason, operation=operation)
            except Exception:
                pass
            if span is not None:
                try:
                    from opentelemetry.trace import Status, StatusCode
                    span.add_event(
                        "dependency.failure",
                        {"andyur.reason": reason})
                    span.set_status(Status(StatusCode.ERROR))
                except Exception:
                    pass
            raise
        else:
            try_record_metric(
                service_name, "andyur.dependency.calls",
                andyur__dependency=dependency, andyur__operation=operation,
                andyur__outcome="success")
            try_record_metric(
                service_name, "andyur.dependency.duration",
                time.monotonic() - started, andyur__dependency=dependency,
                andyur__operation=operation, andyur__outcome="success")


def current_traceparent() -> str | None:
    """W3C traceparent for the active span, to persist on a run record."""
    if not OTEL_ON:
        return None
    from opentelemetry.propagate import inject

    carrier: dict[str, str] = {}
    inject(carrier)
    return carrier.get("traceparent")


def context_from(traceparent: str | None):
    """Rebuild an OTel context from a stored traceparent so a different
    process can start spans inside the same trace. Returns None if absent."""
    if not OTEL_ON or not traceparent:
        return None
    from opentelemetry.propagate import extract

    return extract({"traceparent": traceparent})


def inject_traceparent(carrier: dict[str, str], span, *, baggage: bool = False) -> None:
    """Put one trusted span context on an outbound carrier.

    The sidecar deliberately does not propagate arbitrary baggage. Agent input
    is untrusted and operational correlation needs only W3C trace identity.
    """
    if not OTEL_ON:
        return
    from opentelemetry import trace
    from opentelemetry.propagate import inject

    context = trace.set_span_in_context(span)
    inject(carrier, context=context)
    if not baggage:
        carrier.pop("baggage", None)
        carrier.pop("tracestate", None)


class ObservedASGI:
    """Minimal inbound HTTP server instrumentation without a framework plugin.

    This is intentionally small: optionally extract a trusted W3C parent, time
    the full streaming response, and attribute method/status. It does not capture
    request or response bodies.
    """

    def __init__(self, app, *, service_name: str,
                 operation: str = "mcp.request",
                 trust_traceparent: bool = False,
                 parent_traceparent: str | None = None,
                 health_spans: bool = False) -> None:
        self.app = app
        self.service_name = service_name
        self.tracer = setup_tracing(service_name)
        setup_metrics(service_name)
        self.operation = operation
        self.trust_traceparent = trust_traceparent
        # A TRUSTED, FIXED parent for a listener that serves an untrusted
        # caller (the exec/v1 front and tool service): every request joins the
        # run's trace -- the traceparent the server stored on the run record --
        # without the caller's headers ever being read as trace identity.
        self.parent_traceparent = parent_traceparent
        # Readiness probes arrive every few seconds for the life of a Pod; a
        # span each would be most of a run's trace. The health class is
        # metrics-only unless a caller asks otherwise.
        self.health_spans = health_spans

    async def __call__(self, scope: dict, receive: Callable[[], Awaitable[dict]],
                       send: Callable[[dict], Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        from opentelemetry.trace import SpanKind, Status, StatusCode

        parent = context_from(self.parent_traceparent) if self.parent_traceparent else None
        if self.trust_traceparent:
            headers = {key.decode("latin-1").lower(): value.decode("latin-1")
                       for key, value in scope.get("headers", [])}
            parent = context_from(headers.get("traceparent"))
        metric_method = scope.get("method", "").upper()
        if metric_method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
            metric_method = "OTHER"
        path = scope.get("path", "")
        endpoint_class = "health" if path in {"/health", "/healthz", "/ready", "/readyz"} \
            else "metrics" if path == "/metrics" else "api"
        base_metrics = observability.metric_attributes(**{
            "http__request__method": metric_method,
            "andyur__endpoint__class": endpoint_class,
        })
        attributes = {
            "http.request.method": scope.get("method", ""),
            "andyur.external": True,
        }
        method = scope.get("method", "")
        started = time.monotonic()
        status = 500
        self._metric_call("andyur.http.server.in_flight", "add", 1, base_metrics)
        if endpoint_class == "health" and not self.health_spans:
            from opentelemetry.trace import INVALID_SPAN_CONTEXT, NonRecordingSpan
            span_manager = contextlib.nullcontext(NonRecordingSpan(INVALID_SPAN_CONTEXT))
        else:
            span_manager = self.tracer.start_as_current_span(
                f"{self.operation} {method}".rstrip(),
                context=parent, kind=SpanKind.SERVER,
                attributes=attributes)
        with span_manager as span:
            async def traced_send(message: dict) -> None:
                if message.get("type") == "http.response.start":
                    nonlocal status
                    status = int(message.get("status", 0))
                    span.set_attribute("http.response.status_code", status)
                    if status >= 500:
                        span.set_status(Status(StatusCode.ERROR))
                await send(message)

            try:
                await self.app(scope, receive, traced_send)
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                raise
            finally:
                result_metrics = {**base_metrics,
                    "http.response.status_code_class":
                        f"{status // 100}xx" if 100 <= status <= 599 else "unknown"}
                self._metric_call("andyur.http.server.requests", "add", 1,
                                  result_metrics)
                self._metric_call("andyur.http.server.duration", "record",
                                  time.monotonic() - started, result_metrics)
                self._metric_call("andyur.http.server.in_flight", "add", -1,
                                  base_metrics)

    def _metric_call(self, name: str, method: str, value: int | float,
                     attributes: dict[str, str]) -> None:
        """Telemetry is never allowed to alter an application response."""
        try:
            getattr(metric(self.service_name, name), method)(value, attributes)
        except Exception:
            pass


class TracedASGI(ObservedASGI):
    """Legacy trusted-boundary wrapper used by the SRE resource fixtures.

    New components must use :class:`ObservedASGI`, whose trace parent is safe by
    default. This compatibility class preserves the already-proven sidecar
    composition until those independently owned fixtures migrate explicitly.
    """

    def __init__(self, app, *, service_name: str,
                 operation: str = "mcp.request") -> None:
        super().__init__(app, service_name=service_name, operation=operation,
                         trust_traceparent=True)


def flush() -> None:
    """Force-export buffered spans. Call before a short-lived process exits
    (the runner) so its spans are not lost when the process ends."""
    if not OTEL_ON:
        return
    with _provider_lock:
        for provider in _providers.values():
            try:
                provider.force_flush()
            except Exception:
                pass
        for provider in _meter_providers.values():
            try:
                provider.force_flush()
            except Exception:
                pass


def shutdown() -> None:
    """Bound exporter lifetime and release worker threads at process exit."""
    global _closed
    with _provider_lock:
        if _closed:
            return
        flush()
        for providers in (_providers, _meter_providers):
            for provider in list(providers.values()):
                try:
                    provider.shutdown()
                except Exception:
                    pass
            providers.clear()
        _instruments.clear()
        _closed = True


def shutdown_bounded(seconds: float) -> bool:
    """Flush and shut telemetry down, waiting at most `seconds`.

    The serve-only sidecar is PID 1 and its SIGTERM exit is what a Pod delete
    pays for (R MED-0). With the collector unreachable, BatchSpanProcessor's
    flush and the OTLP exporter's retries block for their own timeouts (10 s
    and more) -- which would silently re-open that finding. So the export runs
    on a daemon thread and this returns when it finishes or when the bound
    expires; providers are marked closed FIRST so the atexit shutdown cannot
    block a second time. Telemetry fails open: True when everything exported,
    False when the bound cut it short (spans are dropped, the exit is not).
    """
    global _closed
    with _provider_lock:
        if _closed:
            return True
        _closed = True
        providers = list(_providers.values()) + list(_meter_providers.values())
        _providers.clear()
        _meter_providers.clear()
        _instruments.clear()

    def _drain():
        for provider in providers:
            try:
                provider.force_flush(int(seconds * 1000))
            except Exception:
                pass
            try:
                provider.shutdown()
            except Exception:
                pass

    worker = threading.Thread(target=_drain, name="andyur-otel-shutdown", daemon=True)
    worker.start()
    worker.join(seconds)
    return not worker.is_alive()


atexit.register(shutdown)

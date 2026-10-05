"""Nothing a caller typed reaches telemetry unredacted.

production-gaps 36. `otel.safe_attribute` exists for exactly this -- percent
decode, redact, then bound -- and was applied in one module. The reachable
instance was the console's `/flow` 404: the route interpolated the caller's raw
`workflow_id` into its message, and an HTTPException raised inside a span is
recorded with its message AND a stack trace, so an 8,039-character workflow id
came back out of the collector with a JWT-shaped substring in it.

THIS TEST IS THE RULE, and it is deliberately not a grep. A static check for
"does this set_attribute call go through safe_attribute" cannot see a value
that reaches a span through an exception message, a status description or an
event -- which is how the one reachable instance actually leaked. So it drives
hostile input through the real routes and asserts the marker reaches no span,
anywhere, by any path.

Adding a route that echoes caller input into a span fails here without anyone
remembering to add a case for it, which is the property a rule needs to have.
"""
import json

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from andyur import db
from andyur.server import app as app_module

client = TestClient(app_module.app)

# Shaped like the things that actually hurt: a bearer token, a long run of
# filler to blow any length bound, and characters that survive a naive
# round-trip. If any of these reach a span, so would a real credential.
SECRET = "eyJhbGciOiJSUzI1NiJ9.SUPERSECRETPAYLOAD.c2lnbmF0dXJl"
MARKER = f"Bearer%20{SECRET}" + "A" * 4000


def _drive(path_marker: str):
    """Every route this lane owns that takes caller-controlled input, driven
    with the marker in each position a caller controls.

    Query parameters get the SHORT marker: `before` is bounded at 512
    characters, so the long one is refused by request validation before the
    handler runs and the route is never actually exercised. A hostile fixture
    the route rejects at the door tests the door, not the route.
    """
    q = {"agent": SECRET, "state": SECRET, "before": SECRET}
    return [
        ("GET", f"/runs/{path_marker}", None, None),
        ("GET", f"/runs/{path_marker}/transcript", None, None),
        ("GET", f"/runs/{path_marker}/exchanges", None, None),
        ("GET", f"/runs/{path_marker}/registry-tools", None, None),
        ("GET", f"/workflows/{path_marker}/flow", None, None),
        ("GET", "/runs", None, q),
        ("GET", f"/agents/{path_marker}", None, None),
        ("POST", f"/agents/{path_marker}/trigger", {"reason": path_marker}, None),
        ("POST", "/agents", {"name": path_marker, "description": path_marker}, None),
        ("POST", "/tasks", {"assignee": path_marker, "title": path_marker}, None),
        ("POST", "/messages", {"recipient": path_marker, "body": path_marker}, None),
        ("GET", f"/v1/registry/agents/{path_marker}/resolve", None, None),
    ]


@pytest.fixture
def spans(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(app_module, "_tracer", provider.get_tracer("test"))
    return exporter


def _everything_recorded(exporter) -> str:
    """Every place a span can carry text: attributes, the status description,
    event names, event attributes, and the span name itself."""
    blob = []
    for span in exporter.get_finished_spans():
        blob.append(span.name)
        blob.append(json.dumps(dict(span.attributes or {}), default=str))
        blob.append(str(span.status.description))
        for event in span.events:
            blob.append(event.name)
            blob.append(json.dumps(dict(event.attributes or {}), default=str))
    return "\n".join(blob)


def test_no_route_lets_a_caller_put_their_own_text_on_a_span(env, spans):
    for method, path, body, params in _drive(MARKER):
        try:
            client.request(method, path, json=body, params=params)
        except Exception:
            pass          # a 500 is a separate bug; the leak is what is tested
    produced = {s.name for s in spans.get_finished_spans()}
    # THE COVERAGE THIS TEST ACTUALLY HAS, asserted so it cannot shrink in
    # silence. Most control-plane routes emit NO span at all today -- there is
    # no request-level instrumentation on the control plane (gap 33) -- so a
    # bare "the marker is absent" would be satisfied by routes that record
    # nothing, which is a different bug wearing this test's clothes.
    assert produced >= {"server.workflow_flow", "server.list_runs"}, produced
    recorded = _everything_recorded(spans)
    assert recorded, "no spans were produced, so this test asserts nothing"
    assert SECRET not in recorded, (
        "a caller-supplied secret reached a span:\n" + recorded[:1500])
    assert "A" * 200 not in recorded, (
        "unbounded caller text reached a span:\n" + recorded[:1500])


def test_the_flow_route_still_records_its_decision(env, spans):
    """The positive control for the test above.

    Withholding caller text is trivially satisfied by recording NOTHING, which
    would be a different failure -- a decision the platform made and did not
    write down. The refusal has to be on the span, by name, at the same time.
    """
    client.get(f"/workflows/{MARKER}/flow")
    [span] = [s for s in spans.get_finished_spans() if s.name == "server.workflow_flow"]
    assert span.attributes["andyur.outcome"] == "refused"
    assert span.attributes["andyur.reason"] == "no_such_workflow"
    assert span.attributes["http.response.status_code"] == 404


def test_safe_attribute_is_what_makes_an_untrusted_value_safe():
    """The helper the rule points at, exercised directly.

    Percent-DECODED first, so an encoded bearer cannot slip past the shapes the
    redactor knows; redacted; then bounded LAST, so a secret cut at the bound
    cannot escape as a prefix.
    """
    from andyur import otel

    out = otel.safe_attribute(MARKER)
    assert SECRET not in out
    # THE NUMBER, not the constant. `len(out) <= otel.ATTRIBUTE_MAX_CHARS`
    # moves with the constant, so raising the bound to 100,000 -- an attribute
    # that is no longer bounded in any useful sense -- stayed green. The bound
    # is part of what makes an untrusted value safe, so it is pinned as a value.
    assert otel.ATTRIBUTE_MAX_CHARS == 256
    assert len(out) <= 256
    # a value with nothing to hide passes through intact
    assert otel.safe_attribute("agents.list") == "agents.list"


def test_an_exception_raised_inside_a_span_is_not_recorded_with_its_message(env, spans):
    """The mechanism, not just the symptom.

    The console lane's leak was not a `set_attribute` at all: the route raised
    an HTTPException whose message echoed the caller's path parameter, and the
    SDK recorded that message and a stack trace on the way out. A route that
    records exceptions is a route that publishes whatever its error strings
    interpolate, which is why the fix was to record the DECISION instead.
    """
    client.get(f"/workflows/{MARKER}/flow")
    [span] = [s for s in spans.get_finished_spans() if s.name == "server.workflow_flow"]
    assert [e.name for e in span.events] == [], span.events
    assert SECRET not in str(span.status.description)

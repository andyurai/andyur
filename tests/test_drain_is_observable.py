"""The heartbeat's drain writes down every decision it makes.

The drain is the platform's self-healing path: work handed to a busy agent is
re-driven from here, so a drain that quietly stops is work that silently never
runs. It had NO instrumentation -- its only record was a `print` with no level,
no trace id and outside the redaction boundary, and its refusals were a bare
`None` that could equally mean a kill switch, a spent work budget, a depth
ceiling or a lost race.

Gap 28 made this worse before it made it better: joining the work's workflow
means the console now draws parent-run -> drained-run, and without the parent's
trace context the drained node's trace id is null, so the edge the operator can
SEE is an edge they cannot follow.
"""
import json
import logging

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from andyur import db, observability, otel
from andyur.server import coordinator, heartbeat, tasks


@pytest.fixture
def spans(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(heartbeat, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(otel, "OTEL_ON", True)
    return exporter


def _drain_spans(exporter):
    return [s for s in exporter.get_finished_spans() if s.name == "heartbeat.drain"]


def _delegated(env, *, parent_trace=None):
    """A task waiting on a busy agent, exactly as delegation leaves it."""
    env.agent("planner")
    env.agent("helper")
    parent = coordinator.maybe_wakeup("planner", "root run", trace_ctx=parent_trace)
    assert coordinator.start_run(parent)
    busy = coordinator.maybe_wakeup("helper", "already working")
    tasks.create_task("helper", "planner", "t", "d", parent_run_id=parent)
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    return parent


TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"


def test_the_drained_run_continues_the_creating_runs_trace(env, spans):
    """The hop gap 28 introduces. The graph draws the edge; the trace must
    carry it, or the operator can see the edge and not follow it."""
    _delegated(env, parent_trace=PARENT_TRACEPARENT)
    heartbeat.drain_pending_work()
    [span] = _drain_spans(spans)
    assert format(span.context.trace_id, "032x") == TRACE_ID, (
        "the drained run rooted its own trace, so the workflow edge the "
        "console draws cannot be followed")
    # and the run it created carries the trace forward to the runner
    with db.connect() as c:
        stored = c.execute(
            "SELECT trace_ctx FROM runs WHERE agent='helper' AND state='pending'"
        ).fetchone()[0]
    assert stored and TRACE_ID in stored


def test_the_attribution_reached_is_on_the_span_by_name(env, spans):
    _delegated(env, parent_trace=PARENT_TRACEPARENT)
    heartbeat.drain_pending_work()
    [span] = _drain_spans(spans)
    assert span.attributes["andyur.decision"] == "joined"
    assert span.attributes["andyur.outcome"] == "success"
    assert span.attributes["andyur.agent"] == "helper"
    assert span.attributes["andyur.run_id"]


def test_a_fresh_workflow_says_why_it_is_a_fresh_workflow(env, spans):
    """"Why is this run drawn as a root?" must be answerable from the trace,
    not from reading the code and guessing at the data."""
    env.agent("a")
    env.agent("b")
    env.agent("helper")
    busy = coordinator.maybe_wakeup("helper", "already working")
    for creator in ("a", "b"):
        p = coordinator.maybe_wakeup(creator, "root")
        assert coordinator.start_run(p)
        tasks.create_task("helper", creator, f"from {creator}", "d", parent_run_id=p)
    with db.connect() as c:
        c.execute("UPDATE runs SET state='done' WHERE id=?", (busy,))
    heartbeat.drain_pending_work()
    [span] = _drain_spans(spans)
    assert span.attributes["andyur.decision"] == "fresh_workflow"
    [event] = [e for e in span.events if e.name == "drain.attribution_degraded"]
    assert event.attributes["andyur.reason"] == "conflict"
    assert event.attributes["andyur.count"] == 2


def test_a_refusal_names_which_control_refused_it(env, spans, monkeypatch):
    """Four controls returned the same bare None. The operator response to each
    is different: resume the workflow, raise the depth, wait for the fan-out."""
    _delegated(env)
    monkeypatch.setattr(coordinator, "MAX_DELEGATION_DEPTH", 0)
    heartbeat.drain_pending_work()
    [span] = _drain_spans(spans)
    assert span.attributes["andyur.outcome"] == "denied"
    assert span.attributes["andyur.reason"] == "invalid", (
        "a depth refusal is indistinguishable from a spent work budget")


def test_a_spent_work_budget_is_a_different_reason_from_a_depth_ceiling(env, spans, monkeypatch):
    """The positive control for the test above: a DIFFERENT control must
    produce a DIFFERENT reason, or asserting on the reason proves nothing."""
    _delegated(env)
    monkeypatch.setattr(coordinator, "MAX_WORKFLOW_RUNS", 0)
    heartbeat.drain_pending_work()
    [span] = _drain_spans(spans)
    assert span.attributes["andyur.reason"] == "exhausted"


def test_the_decision_reaches_the_log_as_a_declared_event(env, spans, caplog):
    """`print` is not the redaction boundary, carries no level and no trace id.
    The bounded facts go through the declared-event schema instead, so a typo
    is a ValueError rather than a field that quietly stops appearing."""
    _delegated(env, parent_trace=PARENT_TRACEPARENT)
    with caplog.at_level(logging.INFO, logger="andyur.server.heartbeat"):
        heartbeat.drain_pending_work()
    [rec] = [r for r in caplog.records if getattr(r, "event_name", "") == "heartbeat.drain"]
    assert rec.event_fields == {"outcome": "success", "reason": "unknown",
                                "decision": "joined"}
    # the envelope really is JSON with the trace on it, not just an extra= dict
    envelope = json.loads(observability.JsonFormatter("andyur-server").format(rec))
    assert envelope["event"] == "heartbeat.drain"
    assert envelope["fields"]["decision"] == "joined"


def test_an_undeclared_drain_decision_is_a_ValueError(env):
    """The vocabulary is bounded on purpose: a decision invented at a call site
    must not become a new log dimension nobody declared."""
    with pytest.raises(ValueError):
        observability.event(logging.getLogger("andyur.test"), "heartbeat.drain",
                            outcome="success", reason="unknown",
                            decision="something-new")

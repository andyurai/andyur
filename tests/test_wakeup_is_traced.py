"""Every way work reaches an agent anchors that run to a trace.

`agents trigger` always did -- `app.trigger_agent` opens a `run <name>` span
and stores its context on the run. Tasks and messages did not: they took
`trace_ctx` from the caller, which is right for DELEGATION (an agent's run must
land in the chain that caused it) and left it None for everyone else. So an
operator creating a task got a run with `trace_ctx: None` -- anchored to
nothing, invisible in Jaeger -- and that is the most common way work reaches an
agent.

"One run is one trace" is an exit criterion, not a nicety.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from andyur import otel
from andyur.server import messages, tasks


@pytest.fixture(autouse=True)
def tracing(monkeypatch):
    """Real tracing, in memory. The unit environment runs with telemetry OFF,
    where `_anchored` correctly returns None -- so a test of what it anchors
    has to turn it on, exactly as the deployed default does."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    for module in (tasks, messages):
        monkeypatch.setattr(module, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(otel, "OTEL_ON", True)
    return exporter.get_finished_spans


def test_a_delegating_runs_context_always_wins():
    """The chain is the point: an assignee's run must land in the trace of the
    run that delegated to it, never in a fresh one."""
    parent = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
    assert tasks._anchored(parent, "assignee", "task") == parent
    assert messages._anchored(parent, "recipient", "message") == parent


def test_an_operator_created_task_still_gets_a_trace():
    """Nobody supplied a context, so one is opened here rather than leaving the
    run anchored to nothing."""
    anchored = tasks._anchored(None, "some-agent", "task")
    assert anchored, "an operator-created task wakes a run with no trace"
    assert anchored.startswith("00-")
    # a real, non-zero trace id
    assert set(anchored.split("-")[1]) != {"0"}


def test_an_operator_sent_message_still_gets_a_trace():
    anchored = messages._anchored(None, "some-agent", "message")
    assert anchored and anchored.startswith("00-")
    assert set(anchored.split("-")[1]) != {"0"}


def test_two_wakeups_are_two_traces():
    """Each is its own unit of work; sharing one trace would merge unrelated
    runs into a single timeline."""
    first = tasks._anchored(None, "a", "task")
    second = tasks._anchored(None, "a", "task")
    assert first.split("-")[1] != second.split("-")[1]


def test_telemetry_never_breaks_the_wakeup():
    """A decision about tracing must not decide whether work happens. With
    telemetry off there is no context to take, and the wakeup goes ahead
    unanchored rather than raising -- which is what the whole unit suite runs
    as, and why this file turns tracing on for the other tests."""
    with patch.object(tasks.otel, "current_traceparent", return_value=None):
        assert tasks._anchored(None, "a", "task") is None


def test_the_wakeup_span_says_what_woke_the_run(tracing):
    """A root span called `run <agent>` and nothing else would leave a reader
    unable to tell an operator's task from a schedule firing."""
    tasks._anchored(None, "some-agent", "task")
    span = [s for s in tracing() if s.name == "run some-agent"][-1]
    assert dict(span.attributes)["andyur.wakeup"] == "task"
    assert dict(span.attributes)["andyur.agent"] == "some-agent"


def test_both_wakeup_paths_route_through_the_anchor():
    """The property, in the call sites: neither may pass a raw `trace_ctx`
    straight to the wakeup again.

    The callee is now `orchestration.facade().request_agent_run`, which both
    modules reach instead of the coordinator directly. The PROPERTY is
    untouched -- a raw `trace_ctx` would still lose the anchor span -- so this
    follows the call site rather than being relaxed. It is matched by the
    argument rather than by the callee's name so that the next time the call
    moves, this asserts the same thing without being edited again.
    """
    import inspect

    for module in (tasks, messages):
        source = inspect.getsource(module)
        wakeup = source[source.index("request_agent_run("):]
        wakeup = wakeup[:wakeup.index(")")]
        assert "_anchored(" in wakeup, f"{module.__name__} wakes a run unanchored"

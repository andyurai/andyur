import json
from pathlib import Path

import pytest

from infra.validate_sre_trace import validate, wait_for_trace


TRACE_ID = "a" * 32


def _write(tmp_path, data):
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(data))
    return path


def _with_enterprise_egress(trace):
    """Attach the independently owned sidecar and demo-resource spans that the
    production validator requires in the same trace."""
    trace["processes"].update({
        "p-sidecar": {"serviceName": "andyur-sidecar"},
        "p-obs": {"serviceName": "sre-observability"},
        "p-tickets": {"serviceName": "sre-tickets"},
    })
    trace["spans"].extend([
        {"operationName": "tool.request obs", "processID": "p-sidecar",
         "spanID": "sidecar-obs"},
        {"operationName": "tool.request tickets", "processID": "p-sidecar",
         "spanID": "sidecar-tickets"},
        {"operationName": "mcp.request POST", "processID": "p-obs",
         "spanID": "resource-obs",
         "references": [{"refType": "CHILD_OF", "spanID": "sidecar-obs"}]},
        {"operationName": "mcp.request POST", "processID": "p-tickets",
         "spanID": "resource-tickets",
         "references": [{"refType": "CHILD_OF", "spanID": "sidecar-tickets"}]},
    ])
    return trace


def test_empty_jaeger_envelope_is_not_a_trace(tmp_path):
    with pytest.raises(ValueError, match="contains no trace"):
        validate(_write(tmp_path, {"data": []}), TRACE_ID)


def test_trace_requires_both_services_all_phases_and_real_tool_spans(tmp_path):
    operations = [
        "run sre-oncall", "runner sre-oncall", "runner.prepare", "runner.prompt",
        "runner.execute", "llm.request", "llm.response", "runner.process",
        "runner.finalize",
        "tool:obs/error_rate", "tool:tickets/comment",
    ]
    trace = {"traceID": TRACE_ID,
             "processes": {"p1": {"serviceName": "andyur-server"},
                           "p2": {"serviceName": "andyur-runner"}},
             "spans": ([{"operationName": name, "processID": "p1"}
                         for name in ("run sre-oncall", "server.start_run",
                                      "server.finish_run")] +
                       [{"operationName": name, "processID": "p2"}
                        for name in operations if name != "run sre-oncall"])}
    _with_enterprise_egress(trace)
    validate(_write(tmp_path, {"data": [trace]}), TRACE_ID)
    without_llm = dict(trace, spans=[
        s for s in trace["spans"] if s["operationName"] != "llm.response"])
    with pytest.raises(ValueError, match="llm.response"):
        validate(_write(tmp_path, {"data": [without_llm]}), TRACE_ID)
    trace["spans"] = [s for s in trace["spans"]
                      if s["operationName"] != "runner.execute"]
    with pytest.raises(ValueError, match="omits phases"):
        validate(_write(tmp_path, {"data": [trace]}), TRACE_ID)


def test_trace_rejects_an_orphan_server_process_record(tmp_path):
    operations = [
        "run sre-oncall", "runner sre-oncall", "runner.prepare", "runner.prompt",
        "runner.execute", "llm.request", "llm.response", "runner.process",
        "runner.finalize",
        "server.start_run", "server.finish_run", "tool:obs/error_rate",
        "tool:tickets/comment",
    ]
    trace = {
        "traceID": TRACE_ID,
        "processes": {"p1": {"serviceName": "andyur-server"},
                      "p2": {"serviceName": "andyur-runner"}},
        "spans": [{"operationName": name, "processID": "p2"}
                  for name in operations],
    }
    _with_enterprise_egress(trace)
    with pytest.raises(ValueError, match="server process does not own"):
        validate(_write(tmp_path, {"data": [trace]}), TRACE_ID)


def test_enterprise_service_nodes_must_be_children_of_sidecar_calls(tmp_path):
    operations = [
        "run sre-oncall", "runner sre-oncall", "runner.prepare", "runner.prompt",
        "runner.execute", "llm.request", "llm.response", "runner.process",
        "runner.finalize", "tool:obs/error_rate", "tool:tickets/comment",
    ]
    trace = {
        "traceID": TRACE_ID,
        "processes": {"p1": {"serviceName": "andyur-server"},
                      "p2": {"serviceName": "andyur-runner"}},
        "spans": ([{"operationName": name, "processID": "p1"}
                   for name in ("run sre-oncall", "server.start_run",
                                "server.finish_run")] +
                  [{"operationName": name, "processID": "p2"}
                   for name in operations if name != "run sre-oncall"]),
    }
    _with_enterprise_egress(trace)
    resource = next(span for span in trace["spans"]
                    if span.get("spanID") == "resource-obs")
    resource["references"] = [{"refType": "CHILD_OF", "spanID": "unknown"}]
    with pytest.raises(ValueError, match="not children of the sidecar"):
        validate(_write(tmp_path, {"data": [trace]}), TRACE_ID)


def test_trace_model_must_match_the_manifest_selection(tmp_path):
    operations = [
        "run sre-oncall", "runner sre-oncall", "runner.prepare", "runner.prompt",
        "runner.execute", "llm.request", "llm.response", "runner.process",
        "runner.finalize",
        "tool:obs/error_rate", "tool:tickets/comment",
    ]
    spans = ([{"operationName": name, "processID": "p1"}
              for name in ("run sre-oncall", "server.start_run",
                           "server.finish_run")] +
             [{"operationName": name, "processID": "p2"}
              for name in operations if name != "run sre-oncall"])
    execute = next(span for span in spans
                   if span["operationName"] == "runner.execute")
    execute["tags"] = [{"key": "andyur.model", "value": "manifest-model"}]
    trace = {"traceID": TRACE_ID,
             "processes": {"p1": {"serviceName": "andyur-server"},
                           "p2": {"serviceName": "andyur-runner"}},
             "spans": spans}
    _with_enterprise_egress(trace)
    path = _write(tmp_path, {"data": [trace]})
    validate(path, TRACE_ID, "manifest-model")
    with pytest.raises(ValueError, match="does not match manifest"):
        validate(path, TRACE_ID, "environment-override")


def test_api_trace_requires_litellm_in_the_same_trace(tmp_path):
    operations = [
        "run sre-oncall", "runner sre-oncall", "runner.prepare", "runner.prompt",
        "runner.execute", "llm.request", "llm.response", "runner.process",
        "runner.finalize", "tool:obs/error_rate", "tool:tickets/comment",
    ]
    trace = {
        "traceID": TRACE_ID,
        "processes": {"p1": {"serviceName": "andyur-server"},
                      "p2": {"serviceName": "andyur-runner"}},
        "spans": ([{"operationName": name, "processID": "p1"}
                   for name in ("run sre-oncall", "server.start_run",
                                "server.finish_run")] +
                  [{"operationName": name, "processID": "p2"}
                  for name in operations if name != "run sre-oncall"]),
    }
    _with_enterprise_egress(trace)
    path = _write(tmp_path, {"data": [trace]})
    with pytest.raises(ValueError, match="no andyur-litellm"):
        validate(path, TRACE_ID, require_litellm=True)
    trace["processes"]["p3"] = {"serviceName": "andyur-litellm"}
    trace["spans"].append({"operationName": "litellm_request", "processID": "p3"})
    validate(_write(tmp_path, {"data": [trace]}), TRACE_ID,
             require_litellm=True)


def test_wait_retries_empty_and_partial_jaeger_responses_until_complete(tmp_path):
    operations = [
        "run sre-oncall", "runner sre-oncall", "runner.prepare",
        "runner.prompt", "runner.execute", "llm.request", "llm.response",
        "runner.process",
        "runner.finalize", "tool:obs/error_rate", "tool:tickets/comment",
    ]
    complete_trace = {
        "traceID": TRACE_ID,
        "processes": {
            "p1": {"serviceName": "andyur-server"},
            "p2": {"serviceName": "andyur-runner"},
        },
        "spans": ([{"operationName": name, "processID": "p1"}
                    for name in ("run sre-oncall", "server.start_run",
                                 "server.finish_run")] +
                  [{"operationName": name, "processID": "p2"}
                   for name in operations if name != "run sre-oncall"]),
    }
    _with_enterprise_egress(complete_trace)
    complete = {"data": [complete_trace]}
    replies = iter(({"data": []}, {"data": [dict(complete["data"][0], spans=[])]},
                    complete))
    calls = []

    def fetch(url):
        calls.append(url)
        return json.dumps(next(replies)).encode()

    output = tmp_path / "retained.json"
    wait_for_trace("http://jaeger/trace", output, TRACE_ID,
                   attempts=3, pause=0, fetch=fetch)
    assert len(calls) == 3
    validate(output, TRACE_ID)

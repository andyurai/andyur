"""The two checks production-gaps row 24 added, tested at their edges.

Neither certified subject exercises the interesting cases: goose and OpenSRE
both declare no `tool_requests`, so E3b's fail-closed path never fires in a real
run, and a bounded network that works never produces a leak. A check that cannot
fail in the runs we actually make is the defect row 24 was about, one level up,
so the verdicts are pure functions and their edges are tested here.
"""

import importlib.util
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _gate():
    spec = importlib.util.spec_from_file_location(
        "exec_v1_gate", ROOT / "infra/byoa-spike/exec_v1_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = _gate()


def _probe(reached=(), denied=(), served=None, unserved=()):
    """The probe's lines. `served` defaults to everything that MUST serve, so a
    test about leaks does not have to restate the positive control."""
    if served is None:
        served = GATE.MUST_SERVE
    return "\n".join([*(f"REACHED {n}" for n in reached),
                      *(f"DENIED {n}" for n in denied),
                      *(f"SERVED {n}" for n in served),
                      *(f"UNSERVED {n}" for n in unserved)])


ALL_REACH = GATE.MUST_REACH
ALL_DENY = GATE.MUST_DENY
ALL_SERVE = GATE.MUST_SERVE


def test_a_bounded_network_passes():
    v = GATE.containment_verdict(_probe(reached=ALL_REACH, denied=ALL_DENY))
    assert v["ok"] and v["measured"] and v["positive_control"]
    assert v["leaked"] == [] and v["unprobed"] == []


@pytest.mark.parametrize("leak", ALL_DENY)
def test_any_single_leak_fails_and_is_named(leak):
    """One reachable destination that should not be is the whole finding, so
    each is checked separately rather than as a set."""
    denied = [d for d in ALL_DENY if d != leak]
    v = GATE.containment_verdict(_probe(reached=[*ALL_REACH, leak], denied=denied))
    assert not v["ok"], leak
    assert v["leaked"] == [leak]


def test_denials_without_the_positive_control_are_not_evidence():
    """Everything denied INCLUDING the allowed destinations is what a broken
    relay looks like. A gate that called that 'bounded' would report the
    strongest possible containment at the exact moment it measured nothing."""
    v = GATE.containment_verdict(_probe(denied=[*ALL_DENY, *ALL_REACH]))
    assert not v["positive_control"]
    assert not v["ok"]
    assert not v["measured"]


def test_a_destination_the_probe_never_reported_is_not_measured():
    """Silence is not a denial. If the probe dies after two lines, the missing
    destinations are `unprobed`, and the run is NOT measured -- which is the
    five-state vocabulary's NOT MEASURED rather than a quiet pass."""
    v = GATE.containment_verdict(_probe(reached=ALL_REACH, denied=["internet-ip"]))
    assert v["positive_control"]
    assert v["unprobed"] == sorted(set(ALL_DENY) - {"internet-ip"})
    assert not v["measured"] and not v["ok"]


# ---------------------------------------------------------------------------
# E3b: the "if any" hole.
# ---------------------------------------------------------------------------

def _req(method, auth=True):
    return {"rpc_method": method, "authorization": "Bearer x" if auth else None}


def _grant(server="observability"):
    return types.SimpleNamespace(server=server, tools=("read_logs",))


def test_a_workload_that_declared_tool_grants_and_never_called_fails_closed():
    """THE row-24 case. Under the old wording this passed identically to a
    workload that authenticated correctly on every call."""
    v = GATE.tool_traffic_verdict([], [], (_grant(),))
    assert not v["ok"]
    assert v["silent_despite_grants"] is True
    assert v["declared_tool_servers"] == ["observability"]


def test_a_workload_that_declared_nothing_and_called_nothing_still_passes():
    """OpenSRE. Declaring no tools and using none is not a defect, and turning
    it into one would fail an honest manifest."""
    v = GATE.tool_traffic_verdict([], [], ())
    assert v["ok"] and v["silent_despite_grants"] is False


def test_declared_grants_that_were_used_pass_and_are_counted_by_method():
    v = GATE.tool_traffic_verdict(
        [_req("initialize"), _req("tools/list"), _req("tools/call"), _req("tools/call")],
        [], (_grant(),))
    assert v["ok"]
    assert v["per_method"] == {"initialize": 1, "tools/list": 1, "tools/call": 2}


def test_zero_is_reported_as_a_measurement_not_an_absence():
    """The presentation half of the same finding: an empty refusal list read
    the same as never-measured, so the counts have to be positive facts."""
    v = GATE.tool_traffic_verdict([_req("initialize"), _req("tools/list")], [], ())
    assert v["per_method"] == {"initialize": 1, "tools/list": 1}
    assert "tools/call" not in v["per_method"]
    assert v["requests"] == 2


def test_an_unauthenticated_request_still_fails_whatever_was_declared():
    """The original property must survive the new one."""
    for declared in ((), (_grant(),)):
        v = GATE.tool_traffic_verdict([_req("initialize")], [_req("initialize", auth=False)],
                                      declared)
        assert not v["ok"], declared


def test_a_request_with_no_json_rpc_method_is_counted_not_dropped():
    v = GATE.tool_traffic_verdict([_req(None)], [], ())
    assert v["per_method"] == {"(none)": 1}
    assert v["requests"] == 1


def test_a_relay_that_accepts_but_does_not_answer_is_not_a_route():
    """THE FALSE GREEN THIS EXISTS FOR. The allowed destinations are probed with
    `nc -z` against the relay, and socat ACCEPTS before it dials upstream -- so a
    relay whose forward to the front is broken produces exactly the same REACHED
    line as a working one.

    Observed, not imagined: E8 reported "allowed destinations reachable,
    positive_control=ok" for a conformance run in which the workload could not
    reach the front at all, died with "Ollama API failed: Connection error", and
    recorded front_forwarded=0. Reachability is not a route, so one allowed
    destination must ANSWER.
    """
    v = GATE.containment_verdict(
        _probe(reached=ALL_REACH, denied=ALL_DENY, served=(), unserved=ALL_SERVE))
    assert not v["positive_control"], "accepting is not answering"
    assert not v["ok"]
    assert v["unserved"] == sorted(ALL_SERVE)


def test_an_unanswered_destination_the_probe_never_reported_is_not_measured():
    """Silence about serving is not a pass either: if wget never ran, the front is
    `unprobed` and the run is NOT measured, the same vocabulary reachability uses."""
    v = GATE.containment_verdict(
        _probe(reached=ALL_REACH, denied=ALL_DENY, served=(), unserved=()))
    assert not v["ok"]
    assert not v["measured"]
    assert set(ALL_SERVE) <= set(v["unprobed"])

"""infra/observability/trace_readback.py -- the gates' shared trace read-back.

Delivery is batched three times over, so a read at first sight is incomplete
(PR #24: a run read back as 5 spans that was 8 minutes later). The helper
waits for the EXPECTED span set and reports what is missing; the v3 envelope
is unwrapped; a traceparent is reduced to its trace id."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def rb():
    spec = importlib.util.spec_from_file_location(
        "trace_readback", ROOT / "infra" / "observability" / "trace_readback.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["trace_readback"] = module
    spec.loader.exec_module(module)
    return module


def _trace(*names, service="andyur-runner"):
    return {"resourceSpans": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": service}}]},
        "scopeSpans": [{"spans": [{"name": n, "spanId": f"s{i}", "attributes": [
            {"key": "andyur.run_id", "value": {"stringValue": "r1"}}]} for i, n in enumerate(names)]}]}]}


def test_the_wait_continues_until_every_expected_span_is_present(rb, monkeypatch):
    """The first read holds the early spans only; the helper must keep reading
    until the late ones land, and must NOT return at first sight (the mutant
    that returns on `trace is not None` alone reddens here)."""
    reads = iter([_trace("run a", "runner.prepare"), _trace("run a", "runner.prepare"),
                  _trace("run a", "runner.prepare", "runner.execute", "server.worker_finish_run")])
    seen = []
    monkeypatch.setattr(rb, "fetch_trace", lambda base, tid, **kw: (seen.append(1), next(reads))[1])
    monkeypatch.setattr(rb.time, "sleep", lambda s: None)
    trace = rb.wait_for_trace("http://j", "t" * 32, wait=30,
                              expected=["run a", "runner.execute", "server.worker_finish_run"])
    assert len(seen) == 3
    assert rb.missing_names(trace, ["run a", "runner.execute", "server.worker_finish_run"]) == []


def test_an_expired_wait_returns_the_last_read_and_names_what_is_missing(rb, monkeypatch, capsys):
    monkeypatch.setattr(rb, "fetch_trace", lambda base, tid, **kw: _trace("run a"))
    monkeypatch.setattr(rb.time, "sleep", lambda s: None)
    clock = iter([0.0, 0.0, 100.0, 100.0, 100.0, 100.0, 100.0])
    monkeypatch.setattr(rb.time, "monotonic", lambda: next(clock))
    rc = rb.main(["http://j", "00-" + "a" * 32 + "-" + "b" * 16 + "-01", "--wait", "10",
                  "--expect", "run a,runner.execute"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 0                                   # the CALLER decides; the facts are in the summary
    assert out["trace_id"] == "a" * 32
    assert out["expected_present"] is False and out["expected_missing"] == ["runner.execute"]
    assert out["span_names"] == ["run a"] and out["services"] == ["andyur-runner"]


def test_a_trace_that_never_appears_is_a_failure_by_name(rb, monkeypatch, capsys):
    monkeypatch.setattr(rb, "fetch_trace", lambda base, tid, **kw: None)
    monkeypatch.setattr(rb.time, "sleep", lambda s: None)
    clock = iter([0.0, 0.0, 100.0, 100.0])
    monkeypatch.setattr(rb.time, "monotonic", lambda: next(clock))
    assert rb.main(["http://j", "c" * 32, "--wait", "5"]) == 2
    assert json.loads(capsys.readouterr().out.strip())["error"] == "trace_not_found"


def test_the_v3_result_envelope_is_unwrapped_and_the_legacy_path_is_never_used(rb, monkeypatch):
    calls = []

    class _Resp:
        def __init__(self, body): self._b = body
        def read(self): return json.dumps(self._b).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(rb.urllib.request, "urlopen",
                        lambda req, timeout=0: (calls.append(req.full_url), _Resp({"result": _trace("x")}))[1])
    trace = rb.fetch_trace("http://j/", "d" * 32)
    assert calls == ["http://j/api/v3/traces/" + "d" * 32]
    assert [s["name"] for s in rb.spans(trace)] == ["x"]
    assert rb.trace_id_from_traceparent("00-" + "e" * 32 + "-" + "f" * 16 + "-01") == "e" * 32
    with pytest.raises(ValueError):
        rb.trace_id_from_traceparent("not-a-traceparent")

"""Run the gate's refusals without allowing any real kubectl execution."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "infra/kubernetes/verify-agent-requested-action.sh"
spec = importlib.util.spec_from_file_location(
    "action_gate_resources", ROOT / "infra/kubernetes/action_gate_resources.py")
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)


def run_gate(tmp_path, *, context="rancher-desktop", opted_in=True):
    calls = tmp_path / "calls.jsonl"
    kubectl = tmp_path / "kubectl"
    kubectl.write_text(f"#!{sys.executable}\n" + '''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["PROBE_CALLS"], "a") as out:
    out.write(json.dumps(args) + "\\n")
if args[:2] == ["config", "current-context"]:
    print(os.environ["PROBE_CONTEXT"])
    raise SystemExit(0)
assert args[:2] == ["--context", "rancher-desktop"], args
args = args[2:]
if args[:2] == ["get", "deployment"]:
    print("existing-image")
elif args[:2] == ["get", "statefulset"]:
    if any("automountServiceAccountToken" in a for a in args):
        print(os.environ["PROBE_OPT_IN"])
elif args[:2] == ["create", "namespace"]:
    assert args[2].startswith("andyur-action-") and args[2] != "prod"
    print("namespace already exists", file=sys.stderr)
    raise SystemExit(1)
''')
    kubectl.chmod(0o755)
    result = subprocess.run(
        ["bash", str(GATE)], capture_output=True, text=True, timeout=20,
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}",
             "ANDYUR_PY": sys.executable, "PROBE_CALLS": str(calls),
             "PROBE_CONTEXT": context,
             "PROBE_OPT_IN": "true" if opted_in else "false",
             "ANDYUR_GATE_USER_TOKEN": "test-only-operator-token"},
    )
    return result, [json.loads(line) for line in calls.read_text().splitlines()]


def test_wrong_context_refuses_without_any_cleanup_or_other_cluster_calls(tmp_path):
    result, calls = run_gate(tmp_path, context="production-context")
    assert result.returncode != 0
    assert "expected the rancher-desktop context" in result.stderr
    assert not any(op in call for call in calls
                   for op in ("delete", "patch", "apply", "create")), calls
    assert calls == [["config", "current-context"]]


def test_missing_credential_opt_in_never_patches_shared_resources(tmp_path):
    result, calls = run_gate(tmp_path, opted_in=False)
    assert result.returncode != 0
    assert "has not opted into consequential actions" in result.stderr
    assert not any(op in call for call in calls
                   for op in ("delete", "patch", "apply", "create"))


def test_failed_create_does_not_adopt_or_delete_existing_namespace(tmp_path):
    result, calls = run_gate(tmp_path)
    assert result.returncode != 0
    assert "existing namespaces are never adopted" in result.stderr
    assert any("create" in call for call in calls), "positive setup reached create"
    assert not any(op in call for call in calls
                   for op in ("delete", "patch", "apply"))


class Core:
    def __init__(self, uid="owned", *, stuck=False):
        self.uid = uid
        self.deleted = False
        self.stuck = stuck

    def delete_namespace(self, namespace, *, body, _request_timeout):
        # Model the API server's precondition at the actual destructive seam.
        assert body.preconditions is not None
        if body.preconditions.uid != self.uid:
            raise ApiException(status=409, reason="UID precondition failed")
        self.deleted = True

    def read_namespace(self, namespace, *, _request_timeout):
        if self.stuck:
            return SimpleNamespace(metadata=SimpleNamespace(uid=self.uid))
        raise ApiException(status=404)


NAMESPACE = "andyur-action-0123456789abcdef"


def test_owned_namespace_has_working_cleanup_positive_control():
    core = Core()
    resources.delete_owned(core, NAMESPACE, "owned")
    assert core.deleted


def test_same_name_replacement_is_rejected_at_delete_precondition():
    core = Core(uid="replacement")
    with pytest.raises(ApiException) as error:
        resources.delete_owned(core, NAMESPACE, "owned")
    assert error.value.status == 409
    assert not core.deleted


@pytest.mark.parametrize("name,uid", [("prod", "owned"), (NAMESPACE, "")])
def test_unowned_names_or_missing_identity_never_reach_delete(name, uid):
    core = Core()
    with pytest.raises(ValueError, match="unowned_namespace"):
        resources.delete_owned(core, name, uid)
    assert not core.deleted


def test_cleanup_not_observed_is_a_failure_not_a_green_artifact():
    with pytest.raises(TimeoutError, match="cleanup_timeout"):
        resources.delete_owned(Core(stuck=True), NAMESPACE, "owned", timeout=0)


@pytest.fixture
def telemetry(monkeypatch):
    from andyur import otel
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(otel, "OTEL_ON", True)
    monkeypatch.setattr(otel, "_meter_providers", {})
    monkeypatch.setattr(otel, "_instruments", {})
    monkeypatch.setattr(otel, "setup_tracing", lambda _: provider.get_tracer("gate-test"))
    reader = InMemoryMetricReader()
    otel.setup_metrics(resources.SERVICE, readers=[reader])
    yield exporter, reader, provider
    for meter in otel._meter_providers.values():
        meter.shutdown()
    provider.shutdown()


@pytest.mark.parametrize("core,uid,reason,error", [
    (Core(), "owned", "deleted", None),
    (Core(uid="replacement"), "owned", "conflict", ApiException),
    (Core(stuck=True), "owned", "timeout", TimeoutError),
    (Core(), "", "invalid", ValueError),
])
def test_cleanup_decision_is_traced_and_counted(telemetry, core, uid, reason, error):
    from contextlib import nullcontext

    exporter, reader, provider = telemetry
    with provider.get_tracer("parent").start_as_current_span("gate-run") as parent:
        with pytest.raises(error) if error else nullcontext():
            resources.delete_owned(core, NAMESPACE, uid, timeout=0)
    cleanup = [s for s in exporter.get_finished_spans() if s.name == "kubernetes.cleanup"]
    assert len(cleanup) == 1
    span = cleanup[0]
    assert span.parent.span_id == parent.get_span_context().span_id
    assert any(e.name == "action_gate.cleanup.decided" and
               e.attributes["andyur.cleanup_reason"] == reason for e in span.events)
    assert span.end_time >= span.start_time
    names = {m.name for r in reader.get_metrics_data().resource_metrics
             for s in r.scope_metrics for m in s.metrics}
    assert {"andyur.dependency.calls", "andyur.dependency.duration"} <= names
    if error:
        assert "andyur.dependency.failures" in names


def test_telemetry_failure_cannot_prevent_owned_cleanup(monkeypatch):
    from andyur import otel

    def broken(*args, **kwargs):
        raise RuntimeError("exporter unavailable")
    monkeypatch.setattr(otel, "setup_tracing", broken)
    monkeypatch.setattr(otel, "record_metric", broken)
    core = Core()
    resources.delete_owned(core, NAMESPACE, "owned")
    assert core.deleted


def test_vendor_secret_is_never_recorded_in_cleanup_span(telemetry):
    class Broken(Core):
        def delete_namespace(self, *args, **kwargs):
            raise ApiException(status=500, reason="Bearer probe-secret-never-export")

    exporter, _, _ = telemetry
    with pytest.raises(ApiException):
        resources.delete_owned(Broken(), NAMESPACE, "owned")
    for span in exporter.get_finished_spans():
        assert "probe-secret" not in span.to_json()


def test_cli_cleanup_joins_the_stored_run_trace(telemetry, monkeypatch):
    from andyur import otel

    exporter, _, _ = telemetry
    parent = "00-11111111111111111111111111111111-2222222222222222-01"
    monkeypatch.setenv("ANDYUR_GATE_TRACEPARENT", parent)
    monkeypatch.setenv("ANDYUR_GATE_RUN_ID", "run-gate-probe")
    monkeypatch.setenv("ANDYUR_GATE_AGENT_ID", "goose-agent")
    monkeypatch.setattr(sys, "argv", ["cleanup", "rancher-desktop", NAMESPACE, "owned"])
    monkeypatch.setattr(resources.config, "load_kube_config", lambda **kwargs: None)
    monkeypatch.setattr(resources.client, "CoreV1Api", lambda api: Core())
    monkeypatch.setattr(otel, "shutdown_bounded", lambda seconds: True)
    assert resources.main() == 0
    spans = exporter.get_finished_spans()
    assert {span.name for span in spans} == {"kubernetes.readiness", "kubernetes.cleanup"}
    assert all(span.context.trace_id == int("1" * 32, 16) for span in spans)
    assert all(span.parent.span_id == int("2" * 16, 16) for span in spans)
    [cleanup] = [span for span in spans if span.name == "kubernetes.cleanup"]
    assert cleanup.attributes["andyur.run_id"] == "run-gate-probe"
    assert cleanup.attributes["andyur.agent_id"] == "goose-agent"
    assert cleanup.attributes["andyur.component"] == "action-gate"
    text = GATE.read_text()
    assert 'ANDYUR_OTEL=on ANDYUR_GATE_TRACEPARENT="${trace_ctx:-}"' in text

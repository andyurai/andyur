"""The exec/v1 conformance gate's own machinery (ADR-011 D8), without docker:
the harness over real HTTP, the launch resolution through the real execconfig
resolver, and the credential-scan exemptions. The gate's live run against the
OpenSRE image is recorded in demos/opensre/evidence/."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _gate():
    spec = importlib.util.spec_from_file_location(
        "exec_v1_gate", ROOT / "infra" / "byoa-spike" / "exec_v1_gate.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["exec_v1_gate"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _gate()


@pytest.fixture()
def harness(gate):
    h = gate.Harness("qwen3-andyur:latest")
    try:
        yield h, f"http://127.0.0.1:{h.port}", f"http://127.0.0.1:{h.front_port}"
    finally:
        h.stop()


def test_the_model_path_is_the_real_front_pinned_to_the_granted_model(harness):
    """The harness puts the platform's own ExecFront in the model path (R
    MED-2): allowed endpoints with the granted model reach the recording stub;
    listing, another model, a case-variant key and /v1/messages are refused by
    the front and never reach it."""
    h, stub, front = harness
    for path in ("/llm/api/chat", "/llm/api/generate", "/llm/v1/chat/completions"):
        r = httpx.post(front + path, json={"model": "qwen3-andyur:latest", "messages": []})
        assert r.status_code == 200 and "ROOT CAUSE" in r.text, path
    assert httpx.post(front + "/llm/v1/messages", json={"model": "qwen3-andyur:latest"}).status_code == 404
    assert httpx.get(front + "/llm/api/tags").status_code == 404
    assert httpx.post(front + "/llm/api/chat", json={"model": "other"}).status_code == 403
    assert httpx.post(front + "/llm/api/chat", content=b'{"model": "qwen3-andyur:latest", "MODEL": "other"}',
                      headers={"content-type": "application/json"}).status_code == 403
    seen = [r for r in h.snapshot() if r["path"] != "/mcp"]
    assert [r["path"] for r in seen] == ["/api/chat", "/api/generate", "/v1/chat/completions"]
    assert all(r["model"] == "qwen3-andyur:latest" for r in seen)


def test_a_streaming_client_gets_sse_through_the_front_not_one_json_body(harness):
    """A client that asks for `stream: true` reads SSE. Answering it with a
    single JSON completion made Hermes Agent -- which streams by default --
    report "an empty stream with no finish_reason", retry, and exit 1, so E1
    failed for a workload whose only difference was streaming. Through the
    REAL front, a streamed call must arrive as chunks, finish with `stop`,
    and end with [DONE]; a non-streamed call must still be one JSON body."""
    h, stub, front = harness
    body = {"model": "qwen3-andyur:latest", "messages": [], "stream": True}
    r = httpx.post(front + "/llm/v1/chat/completions", json=body)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    events = [line[len("data: "):] for line in r.text.splitlines() if line.startswith("data: ")]
    assert events[-1] == "[DONE]"
    chunks = [json.loads(e) for e in events[:-1]]
    assert all(c["object"] == "chat.completion.chunk" and c["model"] == "qwen3-andyur:latest" for c in chunks)
    assert "ROOT CAUSE" in "".join(c["choices"][0]["delta"].get("content", "") for c in chunks)
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    plain = httpx.post(front + "/llm/v1/chat/completions", json={**body, "stream": False})
    assert plain.headers["content-type"].startswith("application/json")
    assert plain.json()["choices"][0]["message"]["content"].startswith("ROOT CAUSE")


def test_a_harness_with_no_granted_model_refuses_every_model_call(gate):
    h = gate.Harness(None)
    try:
        front = f"http://127.0.0.1:{h.front_port}"
        r = httpx.post(front + "/llm/api/chat", json={"model": "qwen3:8b"})
        assert r.status_code == 403 and r.json()["error"] == "no_model_granted"
        assert "granted no model" in r.json()["detail"]
        assert [r for r in h.snapshot() if r["path"] != "/mcp"] == []
    finally:
        h.stop()


def test_the_harness_mcp_boundary_needs_the_declared_bearer_and_refuses_an_ungranted_tool(harness):
    h, base, _ = harness
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    assert httpx.post(base + "/mcp", json=init).status_code == 401
    assert httpx.post(base + "/mcp", json=init, headers={"Authorization": "Bearer nope"}).status_code == 401
    ok = httpx.post(base + "/mcp", json=init, headers={"Authorization": f"Bearer {h.bearer}"})
    assert ok.status_code == 200 and ok.json()["result"]["serverInfo"]["name"] == "andyur-gate"
    call = lambda name: httpx.post(base + "/mcp", headers={"Authorization": f"Bearer {h.bearer}"},
                                   json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                         "params": {"name": name, "arguments": {}}}).json()["result"]
    assert call("granted_tool")["isError"] is False
    assert call("other_tool")["isError"] is True


def test_launch_resolves_the_manifest_configuration_through_execconfig(gate):
    from andyur.registry.models import ConfigFile, ConfigurationSpec, EnvVar, ProcessSpec
    h = gate.Harness("granted-model")
    try:
        facts = gate.facts_for(h, "gate1", "granted-model", "stdin", 600)
        assert facts.mcp_bearer == f"Bearer {h.bearer}"           # the header VALUE (PR #21)
        assert facts.model_base_url == f"{h.front_base}/llm"       # the REAL front, not the stub
        configuration = ConfigurationSpec(
            env=(EnvVar(name="LLM_PROVIDER", literal="ollama"),
                 EnvVar(name="OLLAMA_HOST", reference="services.model.base_url"),
                 EnvVar(name="OLLAMA_MODEL", reference="services.model.name"),
                 EnvVar(name="MCP_AUTH", reference="services.tools.mcp_headers.Authorization")),
            files=(ConfigFile(path="${workspace.home}/cfg.yaml",
                              template="mcp: ${services.tools.mcp_url}\nauth: ${services.tools.mcp_headers.Authorization}\n"),))
        process = ProcessSpec(input_mode="stdin", input_max_bytes=4096)
        launch = gate.Launch("img@sha256:" + "a" * 64, ("tool", "-i", "-"), process,
                             configuration, facts, {"alert": "x"})
        env = dict(launch.env)
        assert env["LLM_PROVIDER"] == "ollama"
        assert env["OLLAMA_HOST"] == f"{h.front_base}/llm"
        assert env["OLLAMA_MODEL"] == "granted-model"
        assert env["MCP_AUTH"] == f"Bearer {h.bearer}"             # the Secret's value, where declared
        assert launch.secret_env_names == ("MCP_AUTH",)
        assert launch.bearer_in_files is True
        assert launch.stdin == b'{"alert":"x"}' or launch.stdin.startswith(b"{")
        assert launch.command == ("tool", "-i", "-")
        [(path, content)] = launch.files
        assert path == "/home/agent/cfg.yaml" and f"auth: Bearer {h.bearer}" in content
        # argv mode appends the sealed input as ONE last argument
        argv_launch = gate.Launch("img@sha256:" + "a" * 64, ("tool",),
                                  ProcessSpec(input_mode="argv", input_max_bytes=4096),
                                  None, facts, {"alert": "x"})
        assert argv_launch.command[:1] == ("tool",) and len(argv_launch.command) == 2
        assert argv_launch.stdin is None and argv_launch.bearer_in_files is False
    finally:
        h.stop()


def test_the_recorded_opensre_evidence_is_green_gate_bound_and_names_the_audited_workload():
    """The committed artifact: every check green, produced by THIS exec gate
    source, for the audited digest under the manifest command, the model leg
    observed at the proxy path, the workload's output captured."""
    import hashlib
    from andyur.agentspec.publisher import load_conformance_evidence
    [path] = sorted((ROOT / "demos" / "opensre" / "evidence").glob("result-exec-v1-*.json"))
    doc = json.loads(path.read_text())
    assert doc["gate"] == "exec-v1-conformance" and doc["ok"] is True
    assert all(c["ok"] for c in doc["checks"]) and len(doc["checks"]) == 12
    # E8 is the check that closed the unmeasured-absence gap, so the artifact is
    # pinned on its PRESENCE and its measurement, not only on a count: a count
    # is satisfied by any twelfth check, including one that measures nothing.
    [e8] = [c for c in doc["checks"] if c["check"].startswith("E8 ")]
    assert e8["ok"] and "leaked=[]" in e8["detail"] and "positive_control=ok" in e8["detail"]
    assert doc["containment"]["measured"] is True
    assert doc["containment"]["positive_control"] is True
    assert doc["containment"]["leaked"] == [] and doc["containment"]["unprobed"] == []
    assert set(doc["containment"]["denied"]) >= {"internet-ip", "external-dns",
                                                 "host-gateway-direct", "public-dns"}
    # And E3b now reports positive per-method counts, so zero is a measurement.
    [e3b] = [c for c in doc["checks"] if c["check"].startswith("E3b ")]
    assert "per_method=" in e3b["detail"] and "silent_despite_grants=False" in e3b["detail"]
    assert (doc["inputs"]["interface"], doc["inputs"]["input_mode"], doc["inputs"]["granted_model"]) == (
        "exec/v1", "stdin", "qwen3-andyur:latest")
    proven = load_conformance_evidence(path)                  # the publisher's own acceptance
    assert proven.image == "ghcr.io/tracer-cloud/opensre@sha256:80e530dd06128d8b63016fbd371ac683c8744f1e187d14fbcfb5298ed4567cd2"
    assert proven.command == ("opensre", "investigate", "-i", "-")
    assert (proven.gate, proven.interface, proven.input_mode, proven.model) == (
        "exec-v1-conformance", "exec/v1", "stdin", "qwen3-andyur:latest")
    assert doc["inputs"]["manifest_sha256"] == hashlib.sha256(
        (ROOT / "demos" / "opensre" / "agent.json").read_bytes()).hexdigest()
    e2 = next(c for c in doc["checks"] if c["check"].startswith("E2 "))
    assert "/v1/chat/completions" in e2["detail"] and "off_policy=[]" in e2["detail"]
    assert next(c for c in doc["checks"] if c["check"].startswith("E3 "))["ok"]
    assert next(c for c in doc["checks"] if c["check"].startswith("E5b"))["ok"]
    assert "Unable to determine root cause" in doc["workload_stdout_excerpt"]
    # PR B: the conformance run is itself observable -- its trace id, the front's
    # spans it produced and the refusals it exercised, by name
    trace = doc["trace"]
    assert re.fullmatch(r"[0-9a-f]{32}", trace["trace_id"]) and trace["span_count"] >= 10
    assert set(trace["span_names"]) >= {"execfront POST", "execfront GET"}
    assert set(trace["front_refusals_by_name"]) >= {"model_not_granted", "model_key_variant", "path_not_model_call"}
    assert trace["front_forwarded"] >= 4                                # the workload's real model calls


def test_credential_scan_exempts_the_bearer_only_where_the_manifest_declared_it(gate, monkeypatch):
    """E4's exemptions, off docker (R LOW: the docstring promised them, no test
    drove them): the MCP bearer may sit in a DECLARED bearer-backed env and in
    a file whose template named the reference -- and nowhere else: never an
    undeclared env, never argv, never the output. The platform's own tokens are
    never exempt, and any ANDYUR_* variable on the workload fails the check
    (delivering ANDYUR_EXEC_MODEL to the workload would be caught here)."""
    from types import SimpleNamespace
    canaries = {"mcp_bearer": "Bearer tok-1", "run_token": "RUN-TOK", "channel_token": "CH-TOK"}

    def scan(env, argv, launch, stdout=""):
        inspect = SimpleNamespace(returncode=0, stdout=json.dumps(
            [{"Config": {"Env": env}, "Path": argv[0], "Args": argv[1:]}]))
        monkeypatch.setattr(gate, "sh", lambda *a, **k: inspect)
        gate.CHECKS.clear()
        gate.credential_scan(launch, canaries, stdout, "")
        [check] = gate.CHECKS
        assert check["check"].startswith("E4 ")
        return check

    declared = SimpleNamespace(files=(("cfg.yaml", "auth: Bearer tok-1\n"),),
                               secret_env_names=("MCP_AUTH",), bearer_in_files=True)
    undeclared = SimpleNamespace(files=(), secret_env_names=(), bearer_in_files=False)
    # the declared shape passes: bearer in the declared env and the templated file
    assert scan(["MCP_AUTH=Bearer tok-1", "OLLAMA_MODEL=m"], ["opensre"], declared)["ok"] is True
    # the same bearer where the manifest declared nothing
    r = scan(["LEAK=Bearer tok-1"], ["opensre"], undeclared)
    assert r["ok"] is False and "mcp_bearer in env" in r["detail"]
    r = scan([], ["opensre"], SimpleNamespace(files=(("f", "Bearer tok-1"),),
                                              secret_env_names=(), bearer_in_files=False))
    assert r["ok"] is False and "mcp_bearer in files" in r["detail"]
    # argv and the output are never exempt, declared or not
    assert "mcp_bearer in argv" in scan([], ["opensre", "Bearer tok-1"], declared)["detail"]
    assert "mcp_bearer in stdout" in scan([], ["opensre"], declared, stdout="Bearer tok-1")["detail"]
    # the platform's tokens are never exempt, wherever the manifest put the bearer
    assert "run_token in env" in scan(["MCP_AUTH=RUN-TOK"], ["opensre"], declared)["detail"]
    assert "channel_token in files" in scan([], ["opensre"], SimpleNamespace(
        files=(("f", "CH-TOK"),), secret_env_names=("MCP_AUTH",), bearer_in_files=True))["detail"]
    # any platform variable on the workload, credential-bearing or not
    r = scan(["ANDYUR_EXEC_MODEL=m"], ["opensre"], declared)
    assert r["ok"] is False and "andyur_env=[\'ANDYUR_EXEC_MODEL\']" in r["detail"]


def test_the_gate_records_its_own_trace_with_the_fronts_decisions_by_name(gate):
    """Criterion 7: the conformance run's evidence carries the trace id, where
    it went, and the span names -- the REAL front's decisions among them by
    refusal code -- so a conformance artifact is itself observable."""
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.trace import TracerProvider
    recorder = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(recorder))
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("exec-v1-conformance") as gate_span:
        with tracer.start_as_current_span("execfront POST") as s:
            s.set_attribute("andyur.decision", "refused"); s.set_attribute("andyur.refusal", "model_not_granted")
        with tracer.start_as_current_span("execfront POST") as s:
            s.set_attribute("andyur.decision", "forwarded"); s.set_attribute("andyur.refusal", "none")
        record = gate.trace_record(gate_span, recorder, None)
    assert record["trace_id"] == format(gate_span.context.trace_id, "032x")
    assert record["exported_to"] == "in-memory only" and record["span_count"] == 2
    assert record["front_refusals_by_name"] == ["model_not_granted"] and record["front_forwarded"] == 1

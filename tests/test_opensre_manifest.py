"""The OpenSRE demo manifest is a real exec/v1 manifest: it parses, compiles
against a policy that grants its model, and packages through the real
package_agents into the snapshot layout the governed registry loads -- with the
audited runtime shape (ADR-011 D5) and the configuration a stock OpenSRE
needs (Ollama provider, host and model from the closed vocabulary, HOME in the
writable scratch)."""
from __future__ import annotations

import json
from pathlib import Path

from andyur.agentspec import parse_manifest
from andyur.agentspec.compiler import compile_resolution
from andyur.agentspec.models import PlatformPolicy
from andyur.agentspec.publisher import package_agents
from andyur.registry.models import RUNTIME_PROTOCOL_EXEC_V1, AuthorityCeiling
from andyur.registry.runtime_overlay import load_runtime_overlay

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "demos" / "opensre" / "agent.json"
AUDITED_DIGEST = "sha256:80e530dd06128d8b63016fbd371ac683c8744f1e187d14fbcfb5298ed4567cd2"


def _policy(**kw) -> PlatformPolicy:
    base = dict(tool_catalog={}, ceiling=AuthorityCeiling(actions=(), resources=()),
                approved_models=("qwen3-andyur:latest",), revision="opensre-1",
                max_lifetime_seconds=3600)
    base.update(kw)
    return PlatformPolicy(**base)


def test_the_opensre_manifest_compiles_to_the_audited_exec_v1_runtime():
    manifest = parse_manifest(json.loads(MANIFEST.read_text()), source=str(MANIFEST),
                              governed=True)
    resolution = compile_resolution(manifest, _policy()).resolution
    runtime = resolution.runtime
    assert resolution.agent_id == "agt_opensre"
    assert resolution.model == "qwen3-andyur:latest"
    assert runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1
    assert runtime.image_ref == "ghcr.io/tracer-cloud/opensre"
    assert runtime.image_digest == AUDITED_DIGEST
    assert runtime.command == ("opensre", "investigate", "-i", "-")
    assert runtime.process.input_mode == "stdin"
    assert runtime.process.stdout == "capture"
    env = {var.name: var for var in runtime.configuration.env}
    assert env["LLM_PROVIDER"].literal == "ollama"
    assert env["OLLAMA_HOST"].reference == "services.model.base_url"
    assert env["OLLAMA_MODEL"].reference == "services.model.name"
    assert env["HOME"].reference == "workspace.home"
    # no bearer, no channel, no provider key: a stock OpenSRE holds nothing
    assert not any(var.reference and var.reference.startswith("services.tools.mcp_headers")
                   for var in runtime.configuration.env)


def test_the_opensre_manifest_packages_into_a_loadable_snapshot(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": "agt_platform_policy", "name": "platform-policy",
        "instructions": "Platform-owned policy input.", "model": None, "tools": [],
        "ceiling": {"actions": [], "resources": []}}))
    output = package_agents([MANIFEST], policy, tmp_path / "snapshot",
                            approved_models=("qwen3-andyur:latest",),
                            policy_revision="opensre-1", max_lifetime_seconds=3600)
    assert {p.name for p in output.iterdir()} == {"agt_opensre.json", "runtime-resolutions.json"}
    runtime = load_runtime_overlay(output)["agt_opensre"]
    assert runtime.interface_version == RUNTIME_PROTOCOL_EXEC_V1
    assert runtime.image_digest == AUDITED_DIGEST
    authority = json.loads((output / "agt_opensre.json").read_text())
    assert authority["model"] == "qwen3-andyur:latest"


def test_a_policy_that_does_not_approve_the_model_refuses_opensre():
    import pytest
    manifest = parse_manifest(json.loads(MANIFEST.read_text()), source=str(MANIFEST),
                              governed=True)
    with pytest.raises(PermissionError, match="qwen3-andyur"):
        compile_resolution(manifest, _policy(approved_models=("other-model",)))

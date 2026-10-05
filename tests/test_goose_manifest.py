"""Goose (Block's open-source agent) on exec/v1 with zero platform change --
the durable half of that proof (docs/goose-wiring-plan.md, deliverable 6): the
manifest in demos/goose/ parses through the REAL parser, resolves through the
REAL execconfig planner against real run facts, names nothing of the
platform's own configuration, and hands goose exactly the two services the
contract publishes -- the model leg by URL and name, the tool service by URL
and declared bearer -- through the closed vocabulary. The other half ("the
lane's diff under andyur/ is empty") is a reviewer-verified fact on the PR.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from andyur import execconfig
from andyur.agentspec import parser
from andyur.registry.models import RUNTIME_PROTOCOL_EXEC_V1

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "demos" / "goose" / "agent.json"
GOOSE_DIGEST = "sha256:d85a724ee487425f38ce015323adf2003591268ee515d9018ac89450ed7d3a5a"


@pytest.fixture(scope="module")
def manifest():
    return parser.parse_manifest(json.loads(MANIFEST.read_text()), source=str(MANIFEST))


def _facts(bearer="Bearer gate-mcp-token-value"):
    return execconfig.RunFacts(
        run_id="run-goose", deadline_epoch=2_000_000_000,
        model_base_url="http://10.42.0.5:8765/llm", model_openai_base_url="http://10.42.0.5:8765/llm/v1",
        model_name="qwen3-andyur:latest", mcp_url="http://10.42.0.5:8766/mcp",
        workspace_home=execconfig.WORKSPACE_HOME, workspace_tmp=execconfig.WORKSPACE_TMP,
        input_path="", mcp_bearer=bearer)


def test_goose_is_a_stock_exec_v1_workload_by_manifest_alone(manifest):
    runtime = manifest.runtime
    assert manifest.metadata.id == "agt_goose"
    assert runtime.interface_protocol == RUNTIME_PROTOCOL_EXEC_V1
    assert runtime.image.ref == "ghcr.io/block/goose" and runtime.image.digest == GOOSE_DIGEST
    # headless, instructions from stdin, one run, bounded turns, structured output
    assert list(runtime.command) == ["goose", "run", "-i", "-", "--no-session", "--max-turns", "8",
                                     "--output-format", "json"]
    assert runtime.process.input_mode == "stdin"
    assert manifest.model_requested == "qwen3-andyur:latest"


def test_the_configuration_resolves_through_the_real_planner_and_names_no_platform_internals(manifest):
    """plan_environment and render_files are the platform's own resolution;
    what they produce is what the Pod carries. Nothing goose gets is a
    platform variable, and the bearer lands only where the manifest declared
    it: in the rendered config file's Authorization header."""
    facts = _facts()
    configuration = manifest.runtime.configuration
    plain, secret_names = execconfig.plan_environment(configuration, facts)
    env = dict(plain)
    assert env["OPENAI_HOST"] == "http://10.42.0.5:8765/llm"          # the run's front, not a model host
    assert env["GOOSE_MODEL"] == "qwen3-andyur:latest"                  # the granted model, by name
    assert env["HOME"] == execconfig.WORKSPACE_HOME
    assert env["GOOSE_PROVIDER"] == "openai" and env["GOOSE_MODE"] == "auto"
    assert env["OPENAI_API_KEY"] == "andyur-front"                      # a placeholder, not a credential
    assert secret_names == () or list(secret_names) == []              # no bearer-backed ENV: the file carries it
    assert not [k for k in env if k.startswith("ANDYUR_")]
    [(path, content)] = execconfig.render_files(configuration, facts)
    assert path == f"{execconfig.WORKSPACE_HOME}/.config/goose/config.yaml"   # where goose reads it
    assert "uri: http://10.42.0.5:8766/mcp" in content
    assert 'Authorization: "Bearer gate-mcp-token-value"' in content
    assert "type: streamable_http" in content
    assert "${" not in content                                          # fully substituted


def test_every_reference_is_in_the_closed_vocabulary(manifest):
    """The manifest can only ask for what the contract publishes; a reference
    outside it is refused by the parser, so a platform secret cannot be named."""
    refs = {e.reference for e in manifest.runtime.configuration.env if e.reference}
    assert refs == {"services.model.name", "services.model.base_url", "workspace.home"}
    text = json.dumps(json.loads(MANIFEST.read_text()))
    assert "ANDYUR_" not in text and "channel" not in text.lower() and "run_token" not in text
    raw = json.loads(MANIFEST.read_text())
    raw["runtime"]["configuration"]["env"]["LEAK"] = {"from": "services.tools.mcp_bearer_secret"}
    with pytest.raises(parser.InvalidManifest):
        parser.parse_manifest(raw, source="mutant")

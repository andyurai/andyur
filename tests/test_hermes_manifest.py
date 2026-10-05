"""Hermes Agent (Nous Research) on exec/v1 with zero platform change -- the
third stock workload, and the durable half of that proof, as for Goose: the
manifest in demos/hermes/ parses through the REAL parser, resolves through the
REAL execconfig planner against real run facts, names nothing of the platform's
own configuration, and hands hermes exactly the two services the contract
publishes. The other half ("the diff under andyur/ is empty") is a
reviewer-verified fact on the PR.

Four things about this image are load-bearing, and each is pinned below
because the obvious future edit to each one is wrong:

  * the command names the venv binary by absolute path. The image's own
    entrypoint starts as root under s6-overlay and refuses every uid but 0 and
    its own 10000; the agent Pod runs as 1001 on a read-only root filesystem.
    `hermes` on PATH is a shim that tries to drop privileges the same way.
  * HERMES_HOME is the run's scratch home. The image sets it to /opt/data,
    which is on the read-only root filesystem under the Pod.
  * the granted model is gemma4-andyur, not the qwen3-andyur the other two
    stock workloads get. Hermes refuses a context window below 64K tokens, and
    qwen3-andyur is served at 32768.
  * `chat --query-file -`, not `-z`. One-shot `-z` forces HERMES_YOLO_MODE=1
    and bypasses command approval; the single-query path (implied on a non-TTY
    stdin) keeps approvals.single_query_mode, which defaults to deny. Not `-Q`
    either: quiet mode prints the bare final answer, which with the gate's
    canned reply is under E5b's 256 bytes, so truncation could never be shown.
    Without it hermes prints the query label, the answer and its exit summary,
    and no banner.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from andyur import execconfig
from andyur.agentspec import parser
from andyur.registry.models import RUNTIME_PROTOCOL_EXEC_V1

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "demos" / "hermes" / "agent.json"
HERMES_DIGEST = "sha256:9469b3e78b9545b6d576eb8887a95352e9a0ea83730eaf31431cf862ca1010e1"


@pytest.fixture(scope="module")
def manifest():
    return parser.parse_manifest(json.loads(MANIFEST.read_text()), source=str(MANIFEST))


def _facts(bearer="Bearer gate-mcp-token-value"):
    return execconfig.RunFacts(
        run_id="run-hermes", deadline_epoch=2_000_000_000,
        model_base_url="http://10.42.0.5:8765/llm", model_openai_base_url="http://10.42.0.5:8765/llm/v1",
        model_name="gemma4-andyur:latest", mcp_url="http://10.42.0.5:8766/mcp",
        workspace_home=execconfig.WORKSPACE_HOME, workspace_tmp=execconfig.WORKSPACE_TMP,
        input_path="", mcp_bearer=bearer)


def test_hermes_is_a_stock_exec_v1_workload_by_manifest_alone(manifest):
    runtime = manifest.runtime
    assert manifest.metadata.id == "agt_hermes"
    assert runtime.interface_protocol == RUNTIME_PROTOCOL_EXEC_V1
    assert runtime.image.ref == "docker.io/nousresearch/hermes-agent"
    assert runtime.image.digest == HERMES_DIGEST
    command = list(runtime.command)
    # the venv binary, never the s6 entrypoint or the privilege-dropping shim
    assert command[0] == "/opt/hermes/.venv/bin/hermes"
    # single-query from stdin, never -z (which forces YOLO)
    assert command[1:4] == ["chat", "--query-file", "-"]
    assert "-z" not in command and "--oneshot" not in command and "--yolo" not in command
    assert "-Q" not in command and "--quiet" not in command
    # only the run's MCP server as tools, bounded turns, no host rules or memory
    assert command[command.index("--toolsets") + 1] == "andyur"
    assert command[command.index("--max-turns") + 1] == "8"
    assert "--ignore-rules" in command
    assert runtime.process.input_mode == "stdin"
    # hermes refuses a window below 64K; gemma4-andyur is served at 65536
    assert manifest.model_requested == "gemma4-andyur:latest"


def test_the_configuration_resolves_through_the_real_planner_and_names_no_platform_internals(manifest):
    facts = _facts()
    configuration = manifest.runtime.configuration
    plain, secret_names = execconfig.plan_environment(configuration, facts)
    env = dict(plain)
    assert env == {"HOME": execconfig.WORKSPACE_HOME,
                   "HERMES_HOME": execconfig.WORKSPACE_HOME,
                   "HERMES_WRITE_SAFE_ROOT": execconfig.WORKSPACE_HOME}
    assert list(secret_names) == []                                      # the file carries the bearer
    [(path, content)] = execconfig.render_files(configuration, facts)
    assert path == f"{execconfig.WORKSPACE_HOME}/config.yaml"            # $HERMES_HOME/config.yaml
    assert 'base_url: "http://10.42.0.5:8765/llm/v1"' in content          # the run's front, OpenAI shape
    assert 'default: "gemma4-andyur:latest"' in content                  # the granted model, by name
    assert "provider: custom" in content
    assert "api_key: andyur-front" in content                            # a placeholder, not a credential
    assert "context_length: 65536" in content                            # stated, so hermes does not probe
    assert 'url: "http://10.42.0.5:8766/mcp"' in content
    assert 'Authorization: "Bearer gate-mcp-token-value"' in content
    assert "check: false" in content                                     # no GitHub update poll
    assert "memory_enabled: false" in content
    assert "${" not in content                                           # fully substituted


def test_every_reference_is_in_the_closed_vocabulary(manifest):
    refs = {e.reference for e in manifest.runtime.configuration.env if e.reference}
    assert refs == {"workspace.home"}
    text = json.dumps(json.loads(MANIFEST.read_text()))
    assert "ANDYUR_" not in text and "channel" not in text.lower() and "run_token" not in text
    raw = json.loads(MANIFEST.read_text())
    raw["runtime"]["configuration"]["env"]["LEAK"] = {"from": "services.tools.mcp_bearer_secret"}
    with pytest.raises(parser.InvalidManifest):
        parser.parse_manifest(raw, source="mutant")

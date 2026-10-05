from andyur.agentspec import PlatformPolicy, compile_resolution, parse_manifest
from andyur.registry.models import AuthorityCeiling


def _manifest():
    return parse_manifest({
        "apiVersion": "andyur.ai/v1",
        "kind": "Agent",
        "metadata": {"id": "agt_byoa", "name": "byoa-agent", "version": "1.0.0"},
        "runtime": {
            "type": "container",
            "image": {
                "ref": "ghcr.io/acme/byoa-agent",
                "digest": "sha256:" + "ab" * 32,
            },
            "command": ["/app/agent", "--serve"],
            "interface": {"protocol": "andyur-agent-runtime/v1"},
            "resources": {"cpu": "2", "memory": "4Gi"},
        },
        "instructions": "Perform the assigned task.",
    })


def _policy():
    return PlatformPolicy(
        tool_catalog={},
        ceiling=AuthorityCeiling(actions=(), resources=()),
        approved_models=(),
        revision="policy-17",
    )


def test_compiler_embeds_runtime_in_authority_snapshot():
    compiled = compile_resolution(_manifest(), _policy())

    runtime = compiled.resolution.runtime
    assert runtime is compiled.runtime
    assert runtime.runtime_type == "container"
    assert runtime.interface_version == "andyur-agent-runtime/v1"
    assert runtime.image_ref == "ghcr.io/acme/byoa-agent"
    assert runtime.image_digest == "sha256:" + "ab" * 32
    assert runtime.command == ("/app/agent", "--serve")
    assert runtime.resources.cpu == "2"
    assert runtime.resources.memory == "4Gi"
    assert runtime.policy_revision == "policy-17"
    assert runtime.manifest_digest.startswith("sha256:")


def test_compiled_runtime_is_derived_from_the_authority_snapshot():
    compiled = compile_resolution(_manifest(), _policy())

    assert tuple(compiled.__dataclass_fields__) == ("resolution",)
    assert compiled.runtime is compiled.resolution.runtime


def test_legacy_resolution_contract_remains_runtime_optional():
    from andyur.registry.manifest_registry import _parse_manifest

    resolution = _parse_manifest("legacy", {
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": "agt_legacy",
        "name": "legacy-agent",
        "instructions": "Legacy builtin agent.",
        "model": None,
        "tools": [],
        "ceiling": {"actions": [], "resources": []},
    })
    assert resolution.runtime is None

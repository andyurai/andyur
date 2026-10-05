import json

import pytest

from andyur.registry.governed import GovernedAgentRegistry
from andyur.registry.models import InvalidAgentManifest


DIGEST = "sha256:" + "11" * 32
IMAGE_DIGEST = "sha256:" + "22" * 32
MANIFEST_DIGEST = "sha256:" + "33" * 32
REF = "registry.example/andyur/agents@" + DIGEST


def _authority_manifest():
    return {
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": "agt_byoa",
        "name": "byoa-agent",
        "instructions": "Run the assigned task.",
        "model": None,
        "tools": [],
        "ceiling": {"actions": [], "resources": []},
    }


def _runtime_overlay(agent_id="agt_byoa"):
    return {
        agent_id: {
            "runtime_type": "container",
            "interface_version": "andyur-agent-runtime/v1",
            "manifest_digest": MANIFEST_DIGEST,
            "image_ref": "ghcr.io/acme/byoa-agent",
            "image_digest": IMAGE_DIGEST,
            "command": ["/app/agent"],
            "resources": {"cpu": "1", "memory": "1Gi"},
            "policy_revision": "review-42",
        }
    }


def _registry(tmp_path, overlay=None):
    key = tmp_path / "cosign.pub"
    key.write_text("test key")

    def pull(_ref, dest):
        from pathlib import Path
        out = Path(dest)
        (out / "agent.json").write_text(json.dumps(_authority_manifest()))
        if overlay is not None:
            encoded = overlay if isinstance(overlay, str) else json.dumps(overlay)
            (out / "runtime-resolutions.json").write_text(encoded)

    return GovernedAgentRegistry(
        REF, str(key), verify=lambda _ref, _key: None, pull=pull)


def test_governed_runtime_is_bound_to_same_verified_snapshot(tmp_path):
    registry = _registry(tmp_path, _runtime_overlay())
    resolution = registry.resolve("agt_byoa")

    assert resolution.registry_digest == DIGEST
    assert resolution.runtime is not None
    assert resolution.runtime.image_ref == "ghcr.io/acme/byoa-agent"
    assert resolution.runtime.image_digest == IMAGE_DIGEST
    assert resolution.runtime.command == ("/app/agent",)
    assert resolution.runtime.interface_version == "andyur-agent-runtime/v1"


def test_old_governed_artifact_remains_readable_but_has_no_runtime(tmp_path):
    resolution = _registry(tmp_path).resolve("agt_byoa")
    assert resolution.registry_digest == DIGEST
    assert resolution.runtime is None


def test_runtime_overlay_cannot_smuggle_an_unknown_agent(tmp_path):
    with pytest.raises(InvalidAgentManifest, match="absent from the authority snapshot"):
        _registry(tmp_path, _runtime_overlay("agt_other"))


def test_governed_container_runtime_requires_digest(tmp_path):
    overlay = _runtime_overlay()
    overlay["agt_byoa"]["image_digest"] = None
    with pytest.raises(InvalidAgentManifest, match="image_ref and sha256 image_digest"):
        _registry(tmp_path, overlay)


def test_valid_builtin_runtime_is_accepted_without_container_fields(tmp_path):
    overlay = {"agt_byoa": {
        "runtime_type": "builtin-claude",
        "interface_version": None,
        "manifest_digest": MANIFEST_DIGEST,
    }}
    runtime = _registry(tmp_path, overlay).resolve("agt_byoa").runtime
    assert runtime is not None
    assert runtime.runtime_type == "builtin-claude"
    assert runtime.image_ref is None


@pytest.mark.parametrize(("mutation", "message"), [
    (lambda row: row.update(extra=True), "unknown fields"),
    (lambda row: row.update(interface_version="andyur-agent-runtime/v2"),
     "is not served here"),
    (lambda row: row.update(manifest_digest="sha256:nope"),
     "manifest_digest must be sha256"),
    (lambda row: row.update(image_digest="sha256:nope"),
     "image_ref and sha256 image_digest"),
    (lambda row: row.update(image_ref="-evil/image"), "unpinned OCI"),
    (lambda row: row.update(image_ref="GHCR.IO/acme/image"), "unpinned OCI"),
    (lambda row: row.update(command=["x"] * 65), "command must be null"),
    (lambda row: row.update(command=["--api-token=secret"]),
     "command must be null"),
    (lambda row: row.update(resources={"cpu": "banana"}),
     "bounded resource quantity"),
])
def test_runtime_overlay_rejects_each_invalid_execution_field(
        tmp_path, mutation, message):
    overlay = _runtime_overlay()
    mutation(overlay["agt_byoa"])
    with pytest.raises(InvalidAgentManifest, match=message):
        _registry(tmp_path, overlay)


@pytest.mark.parametrize("agent_id", ["agt_", "agt space", "x_123", "agt_" + "x" * 200])
def test_runtime_overlay_requires_the_canonical_agent_id_shape(tmp_path, agent_id):
    with pytest.raises(InvalidAgentManifest, match="invalid agent id"):
        _registry(tmp_path, _runtime_overlay(agent_id))


def test_runtime_overlay_rejects_malformed_json(tmp_path):
    with pytest.raises(InvalidAgentManifest, match="invalid runtime overlay"):
        _registry(tmp_path, '{"agt_byoa":')


def test_runtime_overlay_rejects_oversized_file_before_json_decode(tmp_path):
    with pytest.raises(InvalidAgentManifest, match="exceeds 1048576 bytes"):
        _registry(tmp_path, " " * (1024 * 1024 + 1))

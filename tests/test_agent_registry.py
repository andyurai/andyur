"""The demo-facing Agent Registry read contract."""

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from andyur.registry import (AgentNotFound, InvalidAgentManifest,
                             ManifestAgentRegistry)
from andyur.registry.service import (reset_configured_registry,
                                     restore_default_registry)
from andyur.registry.api import router
from andyur.registry.models import MAX_TOOL_BINDINGS
from andyur import identity
from conftest import NO_AUTH, WORKER_SVID, svid_header

registry_app = FastAPI()
registry_app.include_router(router)
client = TestClient(registry_app)


@pytest.fixture(autouse=True)
def _isolate_process_registry():
    """No temporary catalog may leak into another test module's real app.

    Restoring the default factory is the inverse of installing one; dropping
    the snapshot alone leaves an installed factory live."""
    restore_default_registry()
    yield
    restore_default_registry()


def _manifest(**updates) -> dict:
    out = {
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": "agt_reader",
        "name": "reader",
        "instructions": "Read the supplied content.",
        "model": None,
        "tools": [
            {
                "name": "files",
                "reach_url": "http://files.internal/mcp",
                "resource_id": "tool:files",
                "authority": "managed",
            }
        ],
        "ceiling": {"actions": ["files:read"], "resources": ["tool:files"]},
    }
    out.update(updates)
    return out


def _write(directory, name="reader.json", manifest=None):
    directory.mkdir(exist_ok=True)
    (directory / name).write_text(json.dumps(
        _manifest() if manifest is None else manifest
    ))


def test_manifest_registry_resolves_an_immutable_complete_snapshot(tmp_path):
    _write(tmp_path)
    registry = ManifestAgentRegistry(tmp_path)

    assert {
        "agent_id": registry.list_agents()[0].agent_id,
        "name": registry.list_agents()[0].name,
    } == {
        "agent_id": "agt_reader", "name": "reader"
    }
    resolved = registry.resolve("agt_reader")
    assert resolved.instructions == "Read the supplied content."
    assert resolved.tools[0].reach_url == "http://files.internal/mcp"
    assert resolved.tools[0].resource_id == "tool:files"
    assert resolved.ceiling.actions == ("files:read",)
    assert resolved.ceiling.resources == ("tool:files",)
    with pytest.raises(Exception):
        resolved.name = "mutated"


def test_null_and_empty_ceilings_remain_distinct(tmp_path):
    manifest = _manifest(tools=[], ceiling={"actions": [], "resources": None})
    _write(tmp_path, manifest=manifest)
    ceiling = ManifestAgentRegistry(tmp_path).resolve("agt_reader").ceiling
    assert ceiling.actions == ()
    assert ceiling.resources is None


def test_manifest_rejects_tool_lists_over_the_definition_bound(tmp_path):
    tool = _manifest()["tools"][0]
    tools = [{**tool, "name": f"tool-{i}", "resource_id": f"tool:{i}"}
             for i in range(MAX_TOOL_BINDINGS + 1)]
    _write(tmp_path, manifest=_manifest(
        tools=tools, ceiling={"actions": None, "resources": None}))
    with pytest.raises(InvalidAgentManifest, match="32-binding limit"):
        ManifestAgentRegistry(tmp_path)


@pytest.mark.parametrize(
    "change, message",
    [
        ({"surprise": True}, "unknown field"),
        ({"instructions": ""}, "instructions"),
        ({"tools": [{"name": "xx", "reach_url": "/mcp", "resource_id": "tool:x",
                      "authority": "managed"}]}, "absolute http"),
        ({"tools": [{"name": "xx", "reach_url": "http://host:99999/mcp",
                      "resource_id": "tool:x", "authority": "managed"}]},
         "invalid port"),
        ({"tools": [{"name": "xx", "reach_url": "http://user:secret@host/mcp",
                      "resource_id": "tool:x", "authority": "managed"}]},
         "must not contain credentials"),
        ({"tools": [], "ceiling": {"actions": None, "resources": ["tool:ghost"]}},
         "not declared by tools"),
    ],
)
def test_invalid_manifests_fail_at_registry_construction(tmp_path, change, message):
    _write(tmp_path, manifest=_manifest(**change))
    with pytest.raises(InvalidAgentManifest, match=message):
        ManifestAgentRegistry(tmp_path)


def test_duplicate_agent_names_are_refused(tmp_path):
    _write(tmp_path, "one.json")
    _write(tmp_path, "two.json", _manifest(agent_id="agt_other"))
    with pytest.raises(InvalidAgentManifest, match="duplicate agent name"):
        ManifestAgentRegistry(tmp_path)


def test_largest_valid_tcp_port_remains_launchable(tmp_path):
    manifest = _manifest(tools=[{
        "name": "files", "reach_url": "http://files.internal:65535/mcp",
        "resource_id": "tool:files", "authority": "managed",
    }])
    _write(tmp_path, manifest=manifest)
    resolved = ManifestAgentRegistry(tmp_path).resolve("agt_reader")
    assert resolved.tools[0].reach_url == "http://files.internal:65535/mcp"


def test_unknown_agent_has_a_typed_answer(tmp_path):
    _write(tmp_path)
    registry = ManifestAgentRegistry(tmp_path)
    with pytest.raises(AgentNotFound):
        registry.resolve("agt_missing")


def test_authenticated_registry_api_lists_and_resolves(tmp_path, monkeypatch):
    _write(tmp_path)
    monkeypatch.setenv("ANDYUR_AGENT_REGISTRY_DIR", str(tmp_path))
    reset_configured_registry()

    listed = client.get("/v1/registry/agents")
    assert listed.status_code == 200
    # A loose manifest is in no bundle and carries no card, and the listing says
    # so explicitly rather than omitting the keys: a consumer that has to tell
    # "no card" from "this server is too old to have cards" cannot.
    assert listed.json() == {"agents": [
        {"agent_id": "agt_reader", "name": "reader", "bundle": None, "card": None}]}

    resolved = client.get("/v1/registry/agents/agt_reader/resolve")
    assert resolved.status_code == 200
    assert resolved.json() == {
        "agent_id": "agt_reader",
        "name": "reader",
        "bundle": None,
        "card": None,
        "instructions": "Read the supplied content.",
        "model": None,
        "tools": [{
            "name": "files",
            "reach_url": "http://files.internal/mcp",
            "resource_id": "tool:files",
            "authority": "managed",
        }],
        "ceiling": {
            "actions": ["files:read"], "resources": ["tool:files"]
        },
        # manifest mode: no snapshot digest; this manifest declares no runtime
        "registry_digest": None,
        "runtime": None,
    }


def test_registry_api_refuses_anonymous_and_worker_callers(tmp_path, monkeypatch):
    _write(tmp_path)
    monkeypatch.setenv("ANDYUR_AGENT_REGISTRY_DIR", str(tmp_path))
    reset_configured_registry()

    assert client.get("/v1/registry/agents", headers=NO_AUTH).status_code == 401
    assert client.get(
        "/v1/registry/agents", headers=svid_header(WORKER_SVID)
    ).status_code == 403


def test_registry_api_allows_control_plane_identity(tmp_path, monkeypatch):
    _write(tmp_path)
    monkeypatch.setenv("ANDYUR_AGENT_REGISTRY_DIR", str(tmp_path))
    reset_configured_registry()
    control_plane = f"spiffe://{identity.TRUST_DOMAIN}/control-plane"
    assert client.get(
        "/v1/registry/agents", headers=svid_header(control_plane)
    ).status_code == 200
    assert client.get(
        "/v1/registry/agents/agt_reader/resolve",
        headers=svid_header(control_plane),
    ).status_code == 200


def test_invalid_registry_returns_named_503(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDYUR_AGENT_REGISTRY_DIR", str(tmp_path / "missing"))
    reset_configured_registry()
    response = client.get("/v1/registry/agents")
    assert response.status_code == 503
    assert "agent registry is unavailable" in response.json()["detail"]


def test_runtime_registry_outage_returns_503_for_list_and_resolve():
    from andyur.registry.api import registry_provider
    from andyur.registry import RegistryUnavailable

    class DownCatalog:
        def list_agents(self):
            raise RegistryUnavailable("catalog offline")

        def resolve(self, agent_id):
            raise RegistryUnavailable("catalog offline")

    registry_app.dependency_overrides[registry_provider] = lambda: DownCatalog()
    try:
        listed = client.get("/v1/registry/agents")
        resolved = client.get("/v1/registry/agents/agt_reader/resolve")
    finally:
        registry_app.dependency_overrides.clear()
    assert listed.status_code == 503
    assert resolved.status_code == 503
    assert "catalog offline" in listed.json()["detail"]
    assert "catalog offline" in resolved.json()["detail"]


def test_registry_api_returns_404_for_unknown_immutable_id(tmp_path, monkeypatch):
    _write(tmp_path)
    monkeypatch.setenv("ANDYUR_AGENT_REGISTRY_DIR", str(tmp_path))
    reset_configured_registry()
    response = client.get("/v1/registry/agents/agt_missing/resolve")
    assert response.status_code == 404
    assert "agt_missing" in response.json()["detail"]


def test_shipped_authority_demo_registry_preserves_security_boundaries():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    registry = ManifestAgentRegistry(root / "demos" / "agent-registry")
    resolved = {item.agent_id: item for item in registry.list_agents()}
    assert set(resolved) == {
        "agt_classifier", "agt_specialist", "agt_9c2e_roaming", "agt_bystander",
        "agt_teller", "agt_muzzled", "agt_oncall", "agt_oncall_ollama",
        "agt_oncall_relay", "agt_capacity",
        "agt_kubernetes_smoke",
    }
    assert resolved["agt_classifier"].ceiling.actions == ("files:read",)
    assert resolved["agt_teller"].ceiling.resources == ("tool:bank",)
    assert resolved["agt_muzzled"].ceiling.actions == ()
    assert resolved["agt_bystander"].ceiling.actions is None
    assert resolved["agt_kubernetes_smoke"].ceiling.actions == ()
    assert resolved["agt_kubernetes_smoke"].tools == ()
    assert {tool.resource_id for tool in resolved["agt_teller"].tools} == {
        "tool:bank"
    }

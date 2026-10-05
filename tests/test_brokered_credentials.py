import copy

import httpx
import pytest
from starlette.testclient import TestClient

from andyur.proxy import app as proxy_app
from andyur.proxy import sidecar
from andyur.registry import InvalidAgentManifest, ManifestAgentRegistry
from andyur.runner import registry_consumption
from andyur.runner import toolsidecar
from test_manifest_registry import GOOD, _write


def _brokered_manifest():
    manifest = copy.deepcopy(GOOD)
    manifest["tools"][0].update(
        authority="brokered", credential_ref="github-service",
        # Required since a brokered binding that declares no headers can never
        # make a call: the sidecar injects only what the binding declared.
        credential_headers=["Authorization"])
    return manifest


def test_registry_requires_explicit_closed_brokered_reference(tmp_path):
    tool = ManifestAgentRegistry(_write(tmp_path, _brokered_manifest())).resolve(
        "agt_classifier").tools[0]
    assert tool.authority == "brokered"
    assert tool.credential_ref == "github-service"
    for value in (None, "../../root", "UPPER", "ab"):
        manifest = _brokered_manifest()
        if value is None:
            manifest["tools"][0].pop("credential_ref")
        else:
            manifest["tools"][0]["credential_ref"] = value
        with pytest.raises(InvalidAgentManifest, match="credential_ref"):
            ManifestAgentRegistry(_write(tmp_path, manifest, f"{str(value).replace('/', '_')}.json"))


def test_registry_never_allows_fallback_reference_on_delegated_or_passthrough(tmp_path):
    for authority in ("managed", "passthrough"):
        manifest = _brokered_manifest()
        manifest["tools"][0]["authority"] = authority
        with pytest.raises(InvalidAgentManifest, match="only for brokered"):
            ManifestAgentRegistry(_write(tmp_path, manifest, f"{authority}.json"))


def test_partition_preserves_brokered_mode_and_reference(tmp_path):
    resolution = ManifestAgentRegistry(_write(tmp_path, _brokered_manifest())).resolve(
        "agt_classifier")
    managed, passthrough = registry_consumption.managed_from_resolution(resolution)
    assert passthrough == {}
    assert managed["filesystem"]["credential_mode"] == "brokered"
    assert managed["filesystem"]["credential_ref"] == "github-service"


def test_sidecar_injects_only_vault_header_and_never_calls_exchange():
    seen = {}
    async def body():
        yield b'{"ok":true}'
    def upstream(request):
        seen.update(headers=dict(request.headers), url=str(request.url))
        return httpx.Response(200, content=body())
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    router = sidecar.Router({"github": sidecar.ToolRoute.from_managed("github", {
        "url": "https://github.example/mcp", "audience": "resource:github",
        "scheme": "https", "host": "github.example", "port": 443, "path": "/mcp",
        "credential_mode": "brokered", "credential_ref": "github-service",
        "credential_headers": ["Authorization"]})})
    app = proxy_app.build_app(
        router=router,
        identity=sidecar.RunIdentity("", lambda: "", lambda: {}),
        scope=["repos:read"], pin="repo:one", gateway_url="http://unused",
        exchange_fn=lambda **_: pytest.fail("brokered mode must never exchange"),
        brokered_credential_fn=lambda ref: (
            {"Authorization": "Bearer vault-secret"}) if ref == "github-service"
            else pytest.fail("wrong ref"),
        tool_client_factory=lambda: client)
    with TestClient(app) as caller:
        response = caller.post("/tools/github/mcp", headers={
            "Authorization": "Bearer agent-forgery", "X-Api-Key": "agent-key"})
    assert response.status_code == 200
    assert seen["headers"]["authorization"] == "Bearer vault-secret"
    assert "x-api-key" not in seen["headers"]


def test_brokered_failure_never_downgrades_to_delegation_or_bare_call():
    upstream_calls = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: upstream_calls.append(request) or httpx.Response(200)))
    router = sidecar.Router({"x": sidecar.ToolRoute.from_managed("x", {
        "url": "https://x.example/mcp", "audience": "resource:x", "scheme": "https",
        "host": "x.example", "port": 443, "path": "/mcp",
        "credential_mode": "brokered", "credential_ref": "x-service"})})
    app = proxy_app.build_app(
        router=router, identity=sidecar.RunIdentity("", lambda: "", lambda: {}),
        scope=[], pin=None, gateway_url="http://unused",
        exchange_fn=lambda **_: pytest.fail("must not fallback to delegation"),
        brokered_credential_fn=lambda _: (_ for _ in ()).throw(RuntimeError("vault sealed")),
        tool_client_factory=lambda: client)
    with TestClient(app) as caller:
        response = caller.post("/tools/x/mcp")
    assert response.status_code == 502
    assert upstream_calls == []


def test_runtime_source_uses_workload_identity_caches_briefly_and_revokes(monkeypatch):
    for name in ("ANDYUR_OPENBAO_ADDR", "ANDYUR_OPENBAO_CA_FILE",
                 "ANDYUR_OPENBAO_RUNTIME_ROLE", "ANDYUR_OPENBAO_JWT_FILE"):
        monkeypatch.setenv(name, name.lower())
    events = []
    class Vault:
        def __init__(self, *args): events.append(("init", args))
        def login(self, jwt): events.append(("login", jwt))
        def read_service_headers(self, ref):
            events.append(("read", ref)); return {"X-Api-Key": "secret"}
        def close(self): events.append(("close",))
    monkeypatch.setattr(toolsidecar, "OpenBaoClient", Vault)
    source = toolsidecar._BrokeredSource()
    assert source.get("github-service") == {"X-Api-Key": "secret"}
    assert source.get("github-service") == {"X-Api-Key": "secret"}
    assert events.count(("read", "github-service")) == 1
    source.close()
    assert events[-1] == ("close",)

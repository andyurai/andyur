"""Brokered credential headers: declared by the binding, enforced at the sidecar.

The defect this closes: the permitted header set was a hardcoded literal
{authorization, x-api-key} in TWO files, and the vault secret was exactly one
name/value pair. Datadog authenticates with DD-API-KEY and DD-APPLICATION-KEY
together, so the most important observability vendor for an SRE agent could not
be brokered at all -- it failed closed, correctly, and it failed.

Which headers a vendor needs is a fact about that vendor. It is authority data
reviewed with the binding, not a platform constant.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from andyur.credential_service.openbao import OpenBaoError
from andyur.proxy import app as proxy_app
from andyur.proxy import sidecar
from andyur.registry.manifest_registry import (
    FORBIDDEN_CREDENTIAL_HEADERS,
    MAX_CREDENTIAL_HEADERS,
    _parse_tool,
)
from andyur.registry.models import InvalidAgentManifest


def tool_doc(**over) -> dict:
    doc = {
        "name": "datadog",
        "reach_url": "https://api.datadoghq.example/mcp",
        "resource_id": "resource:datadog",
        "authority": "brokered",
        "credential_ref": "datadog-service",
        "credential_headers": ["DD-API-KEY", "DD-APPLICATION-KEY"],
    }
    doc.update(over)
    return doc


# --------------------------------------------------------------------------
# The registry: which headers a binding may set is reviewed authority data.
# --------------------------------------------------------------------------

def test_a_vendor_needing_two_headers_can_now_be_declared():
    """Datadog. This is the case the old hardcoded pair could not express."""
    binding = _parse_tool("t", tool_doc())
    assert binding.credential_headers == ("DD-API-KEY", "DD-APPLICATION-KEY")


def test_a_brokered_binding_must_declare_its_headers():
    """The sidecar refuses to inject anything a binding did not declare, so a
    brokered binding without them can never make a call. Refused at PUBLISH,
    where the operator sees it -- refusing at call time means an immutable,
    already-signed snapshot 502s every request with no in-place remedy."""
    with pytest.raises(InvalidAgentManifest, match="must declare credential_headers"):
        _parse_tool("t", tool_doc(credential_headers=None))


def test_a_non_brokered_binding_declares_none_and_that_is_fine():
    doc = tool_doc(authority="managed", credential_headers=None)
    doc.pop("credential_ref")
    assert _parse_tool("t", doc).credential_headers is None


@pytest.mark.parametrize("headers,expected", [
    ([], "non-empty list"),
    (["DD-API-KEY"] * (MAX_CREDENTIAL_HEADERS + 1), "limit"),
    (["bad name"], "not a valid HTTP header name"),
    (["X-Evil\r\nInjected"], "not a valid HTTP header name"),
    (["Authorization: Bearer"], "not a valid HTTP header name"),
    ([""], "not a valid HTTP header name"),
    ([123], "not a valid HTTP header name"),
    (["DD-API-KEY", "dd-api-key"], "duplicate"),
])
def test_malformed_header_declarations_are_refused(headers, expected):
    with pytest.raises(InvalidAgentManifest, match=expected):
        _parse_tool("t", tool_doc(credential_headers=headers))


@pytest.mark.parametrize("forbidden", sorted(FORBIDDEN_CREDENTIAL_HEADERS))
def test_headers_that_decide_routing_or_origin_can_never_be_declared(forbidden):
    """A credential authenticates a request. It must not be able to redirect
    it, reframe it, or change who it claims to be from."""
    with pytest.raises(InvalidAgentManifest, match="routing, framing or origin"):
        _parse_tool("t", tool_doc(credential_headers=[forbidden]))


@pytest.mark.parametrize("authority", ["managed", "passthrough"])
def test_only_a_brokered_tool_may_declare_credential_headers(authority):
    """Nothing else injects a credential, so declaring headers would be a claim
    nothing honours -- and an unenforced declaration reads as a control."""
    doc = tool_doc(authority=authority)
    doc.pop("credential_ref")
    with pytest.raises(InvalidAgentManifest, match="only meaningful for a brokered"):
        _parse_tool("t", doc)


# --------------------------------------------------------------------------
# The vault: transport material, bounded, but NOT the authorization decision.
# --------------------------------------------------------------------------

def _vault(tmp_path, secret):
    from tests.test_openbao_client import _client, _private

    def handler(request):
        if request.url.path.endswith("login"):
            return httpx.Response(200, json={"auth": {
                "client_token": "t", "lease_duration": 30}})
        if request.url.path.endswith("revoke-self"):
            return httpx.Response(204, json={})
        return httpx.Response(200, json={"data": {"data": secret}})

    client = _client(tmp_path, handler)
    client.login(_private(tmp_path, "jwt", "svid"))
    return client


def test_the_vault_returns_every_header_the_secret_carries(tmp_path):
    client = _vault(tmp_path, {"headers": {
        "DD-API-KEY": "a", "DD-APPLICATION-KEY": "b"}})
    assert client.read_service_headers("datadog-service") == {
        "DD-API-KEY": "a", "DD-APPLICATION-KEY": "b"}


@pytest.mark.parametrize("secret,expected", [
    ({"headers": {}}, "1..8 headers"),
    ({"headers": {f"H{i}": "v" for i in range(9)}}, "1..8 headers"),
    ({"headers": "nope"}, "1..8 headers"),
    ({"header_name": "a", "header_value": "b"}, "invalid shape"),
    ({"headers": {"ok": "a"}, "extra": 1}, "invalid shape"),
    ({"headers": {"bad name": "v"}}, "invalid header name"),
    ({"headers": {"H": "line\r\ninjected"}}, "value is invalid"),
    ({"headers": {"H": ""}}, "value is invalid"),
    ({"headers": {"H": 5}}, "value is invalid"),
])
def test_the_vault_refuses_a_malformed_secret(tmp_path, secret, expected):
    client = _vault(tmp_path, secret)
    with pytest.raises(OpenBaoError, match=expected):
        client.read_service_headers("datadog-service")


def test_the_vault_does_not_decide_which_names_are_allowed(tmp_path):
    """Deliberate. The vault holds transport material; whether THIS binding may
    set THIS header is authority data, answered at the sidecar. A single
    allowlist here was the old answer and could not describe any vendor outside
    two names."""
    client = _vault(tmp_path, {"headers": {"DD-API-KEY": "a"}})
    assert client.read_service_headers("datadog-service") == {"DD-API-KEY": "a"}


# --------------------------------------------------------------------------
# The sidecar: THE enforcement point.
# --------------------------------------------------------------------------

def _sidecar(declared, returned):
    seen = {}

    async def body():
        yield b'{"ok":true}'

    def upstream(request):
        seen.update(headers=dict(request.headers))
        return httpx.Response(200, content=body())

    router = sidecar.Router({"dd": sidecar.ToolRoute.from_managed("dd", {
        "url": "https://dd.example/mcp", "audience": "resource:dd",
        "scheme": "https", "host": "dd.example", "port": 443, "path": "/mcp",
        "credential_mode": "brokered", "credential_ref": "dd-service",
        "credential_headers": declared})})
    app = proxy_app.build_app(
        router=router,
        identity=sidecar.RunIdentity("", lambda: "", lambda: {}),
        scope=[], pin="", gateway_url="http://unused",
        exchange_fn=lambda **_: pytest.fail("brokered mode must never exchange"),
        brokered_credential_fn=lambda ref: returned,
        tool_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(upstream)))
    with TestClient(app) as caller:
        response = caller.post("/tools/dd/mcp")
    return response, seen


def test_both_declared_headers_reach_the_vendor():
    response, seen = _sidecar(
        ["DD-API-KEY", "DD-APPLICATION-KEY"],
        {"DD-API-KEY": "a", "DD-APPLICATION-KEY": "b"})
    assert response.status_code == 200
    assert seen["headers"]["dd-api-key"] == "a"
    assert seen["headers"]["dd-application-key"] == "b"


def test_a_header_the_binding_never_declared_is_refused_and_the_call_withheld():
    """THE enforcement. A compromised credential store can change which VALUES
    reach a vendor. It must not be able to change which HEADERS do."""
    response, seen = _sidecar(
        ["DD-API-KEY"],
        {"DD-API-KEY": "a", "Authorization": "Bearer smuggled"})
    assert response.status_code == 502
    assert seen == {}, "the call must be withheld, not sent without the header"


def test_a_binding_declaring_no_headers_brokers_nothing():
    """Fail closed on the default. A binding that declares nothing gets
    nothing injected, rather than falling back to some platform-wide guess."""
    response, seen = _sidecar([], {"Authorization": "Bearer anything"})
    assert response.status_code == 502
    assert seen == {}


def test_a_subset_of_the_declared_headers_is_accepted():
    """Declaring two and returning one is a smaller credential, not an
    escalation, so it is allowed."""
    response, seen = _sidecar(
        ["DD-API-KEY", "DD-APPLICATION-KEY"], {"DD-API-KEY": "a"})
    assert response.status_code == 200
    assert seen["headers"]["dd-api-key"] == "a"


def test_the_declared_set_is_compared_case_insensitively():
    """HTTP header names are case-insensitive, so a vault that answers
    'dd-api-key' against a binding declaring 'DD-API-KEY' is the same header."""
    response, seen = _sidecar(["DD-API-KEY"], {"dd-api-key": "a"})
    assert response.status_code == 200
    assert seen["headers"]["dd-api-key"] == "a"


def test_an_agent_supplied_header_never_survives_into_the_vendor_call():
    """Unchanged property, re-asserted here because this commit rewrote the
    line that injects."""
    seen = {}

    async def body():
        yield b'{"ok":true}'

    def upstream(request):
        seen.update(headers=dict(request.headers))
        return httpx.Response(200, content=body())

    router = sidecar.Router({"dd": sidecar.ToolRoute.from_managed("dd", {
        "url": "https://dd.example/mcp", "audience": "resource:dd",
        "scheme": "https", "host": "dd.example", "port": 443, "path": "/mcp",
        "credential_mode": "brokered", "credential_ref": "dd-service",
        "credential_headers": ["DD-API-KEY"]})})
    app = proxy_app.build_app(
        router=router,
        identity=sidecar.RunIdentity("", lambda: "", lambda: {}),
        scope=[], pin="", gateway_url="http://unused",
        exchange_fn=lambda **_: pytest.fail("no exchange"),
        brokered_credential_fn=lambda ref: {"DD-API-KEY": "real"},
        tool_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(upstream)))
    with TestClient(app) as caller:
        caller.post("/tools/dd/mcp", headers={
            "DD-API-KEY": "agent-forgery", "Authorization": "Bearer forged"})
    assert seen["headers"]["dd-api-key"] == "real"
    assert "authorization" not in seen["headers"]


def test_a_declared_header_the_vault_did_not_return_is_still_stripped():
    """THE defect two reviews disagreed about, and the one that ran the code
    was right.

    The drop-set was built from what the vault RETURNED, so a header the
    binding DECLARED but the vault omitted was never dropped -- `_clean` does
    not know that name, so the agent's value survived and reached the vendor
    beside the real credential. Datadog would see a two-header credential half
    of which the agent chose.

    `offered <= declared` still admits a strict subset on purpose: a smaller
    credential is a narrowing. What must not survive is the agent's forgery in
    the gap.
    """
    seen = {}

    async def body():
        yield b'{"ok":true}'

    def upstream(request):
        seen.update(headers=dict(request.headers))
        return httpx.Response(200, content=body())

    router = sidecar.Router({"dd": sidecar.ToolRoute.from_managed("dd", {
        "url": "https://dd.example/mcp", "audience": "resource:dd",
        "scheme": "https", "host": "dd.example", "port": 443, "path": "/mcp",
        "credential_mode": "brokered", "credential_ref": "dd-service",
        "credential_headers": ["DD-API-KEY", "DD-APPLICATION-KEY"]})})
    app = proxy_app.build_app(
        router=router,
        identity=sidecar.RunIdentity("", lambda: "", lambda: {}),
        scope=[], pin="", gateway_url="http://unused",
        exchange_fn=lambda **_: pytest.fail("brokered mode must never exchange"),
        # the vault holds only ONE of the two declared headers
        brokered_credential_fn=lambda ref: {"DD-API-KEY": "REAL-VAULT-KEY"},
        tool_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(upstream)))
    with TestClient(app) as caller:
        response = caller.post("/tools/dd/mcp", headers={
            "DD-APPLICATION-KEY": "AGENT-FORGERY"})

    assert response.status_code == 200
    assert seen["headers"]["dd-api-key"] == "REAL-VAULT-KEY"
    assert "dd-application-key" not in seen["headers"], (
        "a DECLARED header the vault did not return must still be stripped; "
        "otherwise the agent supplies half the credential")

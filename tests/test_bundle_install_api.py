"""Who may install a bundle, over the real HTTP surface.

The filesystem behaviour is covered in test_bundle_install.py. This covers the
one thing only the API can answer: installing agents is ADMIN-ONLY, and it is
admin-only for a reason worth stating -- an owner who could install a bundle
could hand themselves an agent whose ceiling holds any action the platform
knows. That is a privilege escalation dressed as a package manager.
"""

import json

import pytest
from starlette.testclient import TestClient

from andyur import config
from andyur.server import app as app_module, oidc
from andyur.registry.service import reset_configured_registry

client = TestClient(app_module.app)

ADMIN_ROLE = "andyur-admin"
_CLAIMS = {
    # bob holds a populated roles claim that simply lacks the admin role, so
    # the refusal is not passing merely because no roles were present.
    "bob-tok": {"sub": "bob", "realm_access": {"roles": ["ops"]}},
    "carol-tok": {"sub": "carol", "realm_access": {"roles": ["ops", ADMIN_ROLE]}},
}

BUNDLE = [{
    "schema_version": "andyur.agent-resolution/v1",
    "agent_id": "agt_api_triage",
    "name": "api-triage",
    "instructions": "Classify the detection.",
    "model": None,
    "tools": [],
    "ceiling": {"actions": ["alerts:read"], "resources": None},
    "card": {"summary": "Classifies detections.", "category": "detection",
             "requires": []},
}]


def _raise():
    raise oidc.InvalidUserToken("bad token")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("ANDYUR_REGISTRY", raising=False)
    monkeypatch.setenv("ANDYUR_AGENT_REGISTRY_DIR", str(tmp_path))
    (tmp_path / "seed").mkdir()
    (tmp_path / "seed" / "seed.json").write_text(json.dumps({
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": "agt_seed", "name": "seed",
        "instructions": "Seed.", "model": None, "tools": [],
        "ceiling": {"actions": [], "resources": None},
    }))
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(config, "ADMIN_ROLE", ADMIN_ROLE)
    monkeypatch.setattr(oidc, "validate_user_claims",
                        lambda t: _CLAIMS.get(t) or _raise())
    reset_configured_registry()
    yield tmp_path
    reset_configured_registry()


def _hdr(tok):
    return {"X-Andyur-User-Token": tok}


def test_a_non_admin_cannot_install_a_bundle(env):
    """The escalation this gate exists to stop: bob writes his own ceiling."""
    r = client.put("/v1/registry/bundles/mine",
                   json={"agents": BUNDLE}, headers=_hdr("bob-tok"))

    assert r.status_code == 403
    assert not (env / "mine").exists()


def test_an_admin_can_install_and_the_catalogue_shows_it_at_once(env):
    r = client.put("/v1/registry/bundles/soc",
                   json={"agents": BUNDLE}, headers=_hdr("carol-tok"))

    assert r.status_code == 200, r.text
    assert r.json() == {"bundle": "soc", "agents": ["api-triage"],
                        "replaced": False}

    # No restart: the listing serves it on the next request.
    listed = client.get("/v1/registry/agents", headers=_hdr("carol-tok"))
    entry = [a for a in listed.json()["agents"] if a["name"] == "api-triage"]
    assert entry and entry[0]["bundle"] == "soc"
    assert entry[0]["card"]["summary"] == "Classifies detections."


def test_a_non_admin_cannot_uninstall_a_bundle(env):
    r = client.delete("/v1/registry/bundles/seed", headers=_hdr("bob-tok"))

    assert r.status_code == 403
    assert (env / "seed").exists()


def test_an_unknown_field_in_the_request_body_is_refused(env):
    """The API's own rule: unknown fields are refused, not ignored. A caller who
    typos `replace` must not get a 200 and an install that did not replace."""
    r = client.put("/v1/registry/bundles/soc",
                   json={"agents": BUNDLE, "replaceit": True},
                   headers=_hdr("carol-tok"))

    assert r.status_code == 422


def test_a_traversing_bundle_name_is_refused_over_http(env):
    """The path check has to hold at the edge too, where the name arrives from
    a URL rather than from a function argument."""
    r = client.put("/v1/registry/bundles/..",
                   json={"agents": BUNDLE}, headers=_hdr("carol-tok"))

    assert r.status_code in (404, 409)
    assert not (env.parent / "agents").exists()


def test_listing_bundles_is_readable_by_a_non_admin(env):
    """Reading the catalogue is operator-level, the same as `registry list`.
    Only CHANGING what may exist is admin."""
    r = client.get("/v1/registry/bundles", headers=_hdr("bob-tok"))

    assert r.status_code == 200
    assert {"bundle": "seed", "agents": 1} in r.json()["bundles"]

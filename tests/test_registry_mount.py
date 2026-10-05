"""The /v1/registry read API is mounted on the real andyur.server.app, with the
right role gate.

The mutation contract: delete `app.include_router(registry_api.router)` in
andyur/server/app.py and the routes 404 for everyone, so the operator/control-
plane 200 assertions fail. That is what proves this test exercises the mount and
not something else. Verified by actually removing the line.

Auth comes from the router's own `auth.require(OPERATOR, CONTROL_PLANE)`, so the
403/401 cases also prove the mount carries the dependency, not just the path.
"""

import conftest
from fastapi.testclient import TestClient

from andyur import identity
from andyur.server.app import app

client = TestClient(app)


def _role(role: str) -> dict:
    return conftest.svid_header(f"spiffe://{identity.TRUST_DOMAIN}/{role}")


def test_operator_can_list_the_registry():
    # The suite's default TestClient identity is the operator SVID.
    r = client.get("/v1/registry/agents")
    assert r.status_code == 200, r.text
    assert "agents" in r.json()


def test_control_plane_can_list_the_registry():
    r = client.get("/v1/registry/agents", headers=_role("control-plane"))
    assert r.status_code == 200, r.text


def test_worker_is_forbidden():
    r = client.get("/v1/registry/agents", headers=conftest.svid_header(conftest.WORKER_SVID))
    assert r.status_code == 403, r.text


def test_anonymous_is_unauthorized():
    r = client.get("/v1/registry/agents", headers=conftest.NO_AUTH)
    assert r.status_code == 401, r.text


def test_the_resolve_route_is_mounted_and_gated():
    """The second route exists too, and its auth runs before the lookup: an
    anonymous caller gets 401, not a 404 that would mean the route is absent."""
    r = client.get("/v1/registry/agents/agt_missing/resolve", headers=conftest.NO_AUTH)
    assert r.status_code == 401, r.text
    # and an operator asking for a genuinely unknown id gets the handler's 404,
    # proving the route is reached (not an unmounted-path 404 for everyone).
    r2 = client.get("/v1/registry/agents/agt_missing/resolve")
    assert r2.status_code == 404, r2.text

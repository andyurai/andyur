"""U3: cross-user isolation (ownership-based).

Each agent is owned by a user; a user may only create, trigger, read, or reach the
agents they own, and a non-owner cannot even learn another user's agent exists (404,
no existence oracle). A run is transitively confined to its owner's agent.
"""

import pytest
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module, oidc, runtoken

client = TestClient(app_module.app)


def _raise():
    raise oidc.InvalidUserToken("bad token")


@pytest.fixture
def users(monkeypatch):
    """Two users: 'alice-tok' -> alice, 'bob-tok' -> bob; anything else is invalid."""
    monkeypatch.setattr(config, "USER_AUTH", True)

    def _claims(t):
        sub = {"alice-tok": "alice", "bob-tok": "bob"}.get(t)
        return {"sub": sub} if sub else _raise()

    monkeypatch.setattr(oidc, "validate_user_claims", _claims)


def _mk(name, tok):
    r = client.post("/agents", json={"name": name}, headers={"X-Andyur-User-Token": tok})
    assert r.status_code == 201, r.text   # a silent 4xx here turns every later assert into noise
    return r


# -- a user cannot READ another user's agent (404, no existence oracle) --------

def test_a_user_cannot_read_another_users_agent(env, users):
    _mk("afin", "alice-tok")
    assert client.get("/agents/afin", headers={"X-Andyur-User-Token": "bob-tok"}).status_code == 404
    assert client.get("/agents/afin", headers={"X-Andyur-User-Token": "alice-tok"}).status_code == 200


# -- a user cannot TRIGGER another user's agent --------------------------------

def test_a_user_cannot_trigger_another_users_agent(env, users):
    _mk("atrig", "alice-tok")
    denied = client.post("/agents/atrig/trigger", json={"reason": "x"},
                         headers={"X-Andyur-User-Token": "bob-tok"})
    assert denied.status_code == 404
    ok = client.post("/agents/atrig/trigger", json={"reason": "x"},
                     headers={"X-Andyur-User-Token": "alice-tok"})
    assert ok.status_code == 201


# -- listing shows only your own agents ----------------------------------------

def test_list_shows_only_your_own_agents(env, users):
    _mk("aone", "alice-tok")
    _mk("btwo", "bob-tok")
    names = {a["name"] for a in
             client.get("/agents", headers={"X-Andyur-User-Token": "alice-tok"}).json()}
    assert "aone" in names and "btwo" not in names


# -- operator endpoints require a valid user token when user-auth is on --------

def test_operator_endpoints_need_a_user_token(env, users):
    _mk("aneed", "alice-tok")
    assert client.get("/agents/aneed").status_code == 401           # no token
    assert client.get("/agents").status_code == 401                 # list too
    assert client.get("/agents/aneed",
                      headers={"X-Andyur-User-Token": "forged"}).status_code == 401


# -- a run is transitively confined to its owner's agent -----------------------

def test_a_run_cannot_reach_another_users_agent_data(env, users):
    _mk("ascout", "alice-tok")   # alice's
    _mk("bvault", "bob-tok")     # bob's
    with db.connect() as c:
        c.execute("INSERT INTO runs (id, agent, state, created_at) "
                  "VALUES ('r1', 'ascout', 'running', ?)", (db.utcnow(),))
    hdr = {"X-Andyur-Run-Token": runtoken.mint("ascout", "r1", "wf")}
    # alice's ascout run tries to write bob's vault -> blocked (cross-agent)
    r = client.put("/agents/bvault/files/x.md", json={"content": "steal"}, headers=hdr)
    assert r.status_code == 403

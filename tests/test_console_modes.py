"""Admin vs user authority under user-auth (the console's two modes).

Admin is an IdP-asserted role (ANDYUR_ADMIN_ROLE found in ANDYUR_ROLES_CLAIM of
the validated OIDC token), and it grants VISIBILITY and LIFECYCLE over every
owner's agents plus the ops surfaces (workers, workflow halt). It never grants
impersonation: triggering stays owner-only, because a run presents its caller's
token as the RFC 8693 subject_token and must act as a user whose credential it
actually holds.

These are also the regression tests for the gap the mode split exposed: pause,
resume, and ceiling-read took no user token at all, so any authenticated user
could freeze or inspect another tenant's agent by name.
"""

import pytest
from fastapi.testclient import TestClient

from andyur import config
from andyur.server import app as app_module, oidc

client = TestClient(app_module.app)

ADMIN_ROLE = "andyur-admin"

_CLAIMS = {
    "alice-tok": {"sub": "alice"},
    # bob carries a non-admin role, so every "bob is refused" case exercises a
    # populated roles claim that simply lacks ADMIN_ROLE, not an absent one.
    "bob-tok": {"sub": "bob", "realm_access": {"roles": ["ops"]}},
    "carol-tok": {"sub": "carol", "realm_access": {"roles": ["ops", ADMIN_ROLE]}},
}


def _raise():
    raise oidc.InvalidUserToken("bad token")


@pytest.fixture
def users(monkeypatch):
    """alice and bob are plain users; carol carries the admin realm role."""
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(config, "ADMIN_ROLE", ADMIN_ROLE)
    monkeypatch.setattr(oidc, "validate_user_claims",
                        lambda t: _CLAIMS.get(t) or _raise())


def _mk(name, tok):
    r = client.post("/agents", json={"name": name},
                    headers={"X-Andyur-User-Token": tok})
    assert r.status_code == 201, r.text
    return r


def _hdr(tok):
    return {"X-Andyur-User-Token": tok}


# -- visibility ----------------------------------------------------------------

def test_admin_sees_every_owners_agents_with_owner_column(env, users):
    _mk("cmone", "alice-tok")
    _mk("cmtwo", "bob-tok")
    rows = client.get("/agents", headers=_hdr("carol-tok")).json()
    assert {r["name"]: r["owner"] for r in rows} == {"cmone": "alice", "cmtwo": "bob"}
    # the plain user's list is still filtered (the admin path did not widen it)
    assert [r["name"] for r in client.get("/agents", headers=_hdr("alice-tok")).json()] \
        == ["cmone"]


def test_admin_reads_and_deletes_another_users_agent(env, users):
    _mk("cmdoomed", "alice-tok")
    assert client.get("/agents/cmdoomed", headers=_hdr("carol-tok")).status_code == 200
    assert client.delete("/agents/cmdoomed", headers=_hdr("carol-tok")).status_code == 200
    assert client.get("/agents/cmdoomed", headers=_hdr("alice-tok")).status_code == 404


# -- no impersonation ----------------------------------------------------------

def test_admin_cannot_trigger_another_users_agent(env, users):
    _mk("cmrun", "alice-tok")
    denied = client.post("/agents/cmrun/trigger", json={"reason": "x"},
                         headers=_hdr("carol-tok"))
    assert denied.status_code == 404
    # positive control: the owner's identical request starts a run
    assert client.post("/agents/cmrun/trigger", json={"reason": "x"},
                       headers=_hdr("alice-tok")).status_code == 201


# -- the pause/resume/ceiling gap (regression) ---------------------------------

def test_a_user_cannot_pause_another_users_agent(env, users):
    _mk("cmvictim", "alice-tok")
    assert client.post("/agents/cmvictim/pause", headers=_hdr("bob-tok")).status_code == 404
    # the refusal really refused: alice's agent is still unpaused
    assert client.get("/agents/cmvictim", headers=_hdr("alice-tok")).json()["paused"] in (0, False)
    # positive controls: the owner and the admin both may
    assert client.post("/agents/cmvictim/pause", headers=_hdr("alice-tok")).status_code == 200
    assert client.post("/agents/cmvictim/resume", headers=_hdr("carol-tok")).status_code == 200


def test_a_user_cannot_resume_another_users_paused_agent(env, users):
    _mk("cmfrozen", "alice-tok")
    client.post("/agents/cmfrozen/pause", headers=_hdr("alice-tok"))
    assert client.post("/agents/cmfrozen/resume", headers=_hdr("bob-tok")).status_code == 404
    assert client.get("/agents/cmfrozen", headers=_hdr("alice-tok")).json()["paused"] in (1, True)


def test_a_user_cannot_read_another_users_ceiling(env, users):
    _mk("cmcap", "alice-tok")
    assert client.get("/agents/cmcap/ceiling", headers=_hdr("bob-tok")).status_code == 404
    assert client.get("/agents/cmcap/ceiling", headers=_hdr("alice-tok")).status_code == 200
    assert client.get("/agents/cmcap/ceiling", headers=_hdr("carol-tok")).status_code == 200


def test_a_user_cannot_write_another_users_ceiling(env, users):
    # the write is the higher-authority sibling of the read: {"actions": []}
    # would brick, {"actions": null} would widen another tenant's hard maximum
    _mk("cmwr", "alice-tok")
    body = {"actions": []}
    assert client.put("/agents/cmwr/ceiling", json=body,
                      headers=_hdr("bob-tok")).status_code == 404
    # the refusal really refused: alice's ceiling is still unrestricted
    ceil = client.get("/agents/cmwr/ceiling", headers=_hdr("alice-tok")).json()
    assert ceil["actions"] is None
    # positive controls: the owner and the admin may both write it
    assert client.put("/agents/cmwr/ceiling", json=body,
                      headers=_hdr("alice-tok")).status_code == 200
    assert client.put("/agents/cmwr/ceiling", json={"actions": None},
                      headers=_hdr("carol-tok")).status_code == 200


# -- ops surfaces are admin-only -----------------------------------------------

def test_workers_and_halt_are_admin_only(env, users):
    assert client.get("/workers", headers=_hdr("alice-tok")).status_code == 403
    assert client.get("/workers", headers=_hdr("carol-tok")).status_code == 200
    assert client.post("/workflows/wf1/halt", headers=_hdr("alice-tok")).status_code == 403
    assert client.post("/workflows/wf1/halt", headers=_hdr("carol-tok")).status_code == 200
    assert client.post("/workflows/wf1/unhalt", headers=_hdr("alice-tok")).status_code == 403
    assert client.post("/workflows/wf1/unhalt", headers=_hdr("carol-tok")).status_code == 200


def test_infra_ops_reachable_by_the_raw_operator_seam_with_no_user_token(env, users):
    # the CLI / host operator presents the operator SVID and NO user token; the
    # emergency kill switch and workers view must stay reachable for it, or
    # turning user-auth on would make halt browser-only. (A browser user always
    # rides the BFF, which attaches a token, so this bypass is not reachable from
    # a page.) Contrast the owner-scoped routes below.
    assert client.get("/workers").status_code == 200
    assert client.post("/workflows/wf1/halt").status_code == 200
    assert client.post("/workflows/wf1/unhalt").status_code == 200


def test_owner_scoped_routes_still_demand_a_user_token(env, users):
    # the no-token infra bypass is deliberately NOT extended to owner-scoped
    # routes: those need to know WHICH user, so a missing token is 401, never a pass
    _mk("cmscoped", "alice-tok")
    assert client.post("/agents/cmscoped/pause").status_code == 401
    assert client.get("/agents/cmscoped").status_code == 401
    assert client.get("/agents").status_code == 401


# -- /me: the UI's single mode source ------------------------------------------

def test_me_reports_the_authenticated_principal(env, users):
    assert client.get("/me", headers=_hdr("alice-tok")).json() == {
        "user_auth": True, "sub": "alice", "admin": False}
    assert client.get("/me", headers=_hdr("carol-tok")).json() == {
        "user_auth": True, "sub": "carol", "admin": True}
    assert client.get("/me", headers=_hdr("forged")).status_code == 401
    assert client.get("/me").status_code == 401


def test_me_without_user_auth_is_the_single_operator(env):
    assert client.get("/me").json() == {"user_auth": False, "sub": None, "admin": True}


# -- role-claim parsing never widens on surprise ---------------------------------

@pytest.mark.parametrize("claims,expected", [
    ({"realm_access": {"roles": [ADMIN_ROLE]}}, True),
    ({"realm_access": {"roles": ["other"]}}, False),
    # a space-delimited STRING is scope syntax, not a roles array: rejected, so a
    # client-influenced `scope` value can never be read as an admin assertion
    ({"realm_access": {"roles": f"ops {ADMIN_ROLE}"}}, False),
    ({"realm_access": {"roles": {ADMIN_ROLE: True}}}, False),   # hostile shape: dict
    ({"realm_access": {"roles": 5}}, False),                    # hostile shape: number
    ({"realm_access": ["roles"]}, False),                       # path hits a non-dict
    ({}, False),                                                # claim absent
    ({"realm_access": {"roles": [None, 5, ADMIN_ROLE]}}, True), # junk entries skipped
])
def test_is_admin_claim_shapes(monkeypatch, claims, expected):
    monkeypatch.setattr(config, "ADMIN_ROLE", ADMIN_ROLE)
    assert app_module._is_admin(claims) is expected


def test_no_configured_admin_role_means_nobody_is_admin(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_ROLE", "")
    assert app_module._is_admin({"realm_access": {"roles": [ADMIN_ROLE]}}) is False


def test_roles_claim_path_is_configurable(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_ROLE", ADMIN_ROLE)
    monkeypatch.setattr(config, "ROLES_CLAIM", "groups")
    assert app_module._is_admin({"groups": [ADMIN_ROLE]}) is True
    assert app_module._is_admin({"realm_access": {"roles": [ADMIN_ROLE]}}) is False


# -- startup refuses user-auth without a verifiable issuer + audience -----------

def test_user_auth_requires_issuer_and_audience(monkeypatch):
    # admin/ownership are read from the user's token, so it must be validated
    # against a known issuer AND audience -- else a token minted for another
    # audience in the same realm would be trusted for authority.
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "")
    monkeypatch.setattr(config, "OIDC_AUDIENCE", "")
    with pytest.raises(config.InsecureProfile):
        config.assert_user_auth()
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://idp.test/realms/andyur")
    with pytest.raises(config.InsecureProfile):     # audience still missing
        config.assert_user_auth()
    monkeypatch.setattr(config, "OIDC_AUDIENCE", "andyur")
    config.assert_user_auth()                        # both set -> OK


def test_user_auth_off_needs_no_oidc_config(monkeypatch):
    monkeypatch.setattr(config, "USER_AUTH", False)
    monkeypatch.setattr(config, "OIDC_ISSUER", "")
    monkeypatch.setattr(config, "OIDC_AUDIENCE", "")
    config.assert_user_auth()                        # no-op, no raise

"""U1: user delegation + agent ownership.

Each agent instance is owned by a user authenticated via OIDC; runs inherit the
owner as their `sub`, carried in the signed run grant and surfaced on RunCtx.
Covers the OIDC validation itself (real JWT decode against an injected signer) and
the ownership/sealing path through the live app.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from andyur import config, db
from andyur.server import app as app_module, oidc, runtoken

client = TestClient(app_module.app)

# a throwaway RSA keypair standing in for the IdP's signing key
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUB = _KEY.public_key()
_ISS = "https://idp.test/realms/andyur"
_AUD = "andyur"


def _oidc(sub="alice", iss=_ISS, aud=_AUD, exp_delta=3600, **extra):
    claims = {"sub": sub, "iss": iss, "aud": aud,
              "exp": int(time.time()) + exp_delta, **extra}
    return jwt.encode(claims, _KEY, algorithm="RS256", headers={"kid": "test"})


class _FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": _PUB})()


@pytest.fixture
def idp(monkeypatch):
    """Point the OIDC validator at our fake signer + expected issuer/audience."""
    monkeypatch.setattr(oidc, "_jwks", _FakeJWKS())
    monkeypatch.setattr(oidc, "OIDC_ISSUER", _ISS)
    monkeypatch.setattr(oidc, "OIDC_AUDIENCE", _AUD)


# -- the OIDC validation itself (real jwt.decode) ------------------------------

def test_valid_oidc_token_yields_sub(idp):
    assert oidc.validate_user_token(_oidc(sub="alice")) == "alice"


def test_valid_oidc_claims_are_available_for_provider_identity_mapping(idp):
    token = _oidc(sub="pairwise", oid="object-7", tid="tenant-3")
    assert oidc.validate_user_claims(token)["oid"] == "object-7"


def test_expired_token_is_rejected(idp):
    with pytest.raises(oidc.InvalidUserToken):
        oidc.validate_user_token(_oidc(exp_delta=-10))


def test_wrong_audience_is_rejected(idp):
    with pytest.raises(oidc.InvalidUserToken):
        oidc.validate_user_token(_oidc(aud="someone-else"))


def test_wrong_issuer_is_rejected(idp):
    with pytest.raises(oidc.InvalidUserToken):
        oidc.validate_user_token(_oidc(iss="https://evil.test"))


def test_tampered_signature_is_rejected(idp):
    tok = _oidc()
    tampered = tok[:-3] + ("aaa" if tok[-3:] != "aaa" else "bbb")
    with pytest.raises(oidc.InvalidUserToken):
        oidc.validate_user_token(tampered)


def test_token_without_sub_is_rejected(idp, monkeypatch):
    # a token the fake signer will validate but with no subject
    claims = {"iss": _ISS, "aud": _AUD, "exp": int(time.time()) + 60}
    tok = jwt.encode(claims, _KEY, algorithm="RS256", headers={"kid": "test"})
    with pytest.raises(oidc.InvalidUserToken):
        oidc.validate_user_token(tok)


# -- agent ownership through the live app --------------------------------------

@pytest.fixture
def user_auth(monkeypatch):
    monkeypatch.setattr(config, "USER_AUTH", True)
    # in these app tests the OIDC check is stubbed; the decode path is covered above
    monkeypatch.setattr(oidc, "validate_user_claims",
                        lambda t: {"sub": "alice"} if t == "good" else _raise())


def _raise():
    raise oidc.InvalidUserToken("bad")


def test_creating_an_agent_records_its_owner(env, user_auth):
    r = client.post("/agents", json={"name": "aowner", "description": "d"},
                    headers={"X-Andyur-User-Token": "good"})
    assert r.status_code == 201
    with db.connect() as c:
        owner = c.execute("SELECT owner FROM agents WHERE name='aowner'").fetchone()["owner"]
    assert owner == "alice"


def test_creating_an_agent_without_a_user_token_is_refused(env, user_auth):
    r = client.post("/agents", json={"name": "anotoken", "description": "d"})
    assert r.status_code == 401


def test_creating_an_agent_with_an_invalid_user_token_is_refused(env, user_auth):
    r = client.post("/agents", json={"name": "abadtoken"},
                    headers={"X-Andyur-User-Token": "forged"})
    assert r.status_code == 401


def test_a_run_inherits_the_owner_and_the_grant_carries_it(env, user_auth):
    client.post("/agents", json={"name": "arun"}, headers={"X-Andyur-User-Token": "good"})
    run_id = client.post("/agents/arun/trigger", json={"reason": "go"}, headers={"X-Andyur-User-Token": "good"}).json()["run_id"]
    with db.connect() as c:
        assert c.execute("SELECT acting_user FROM runs WHERE id=?", (run_id,)).fetchone()["acting_user"] == "alice"
    # the token minted for this run carries sub in its signed payload
    tok = client.post(f"/runs/{run_id}/token").json()["run_token"]
    assert runtoken.verify(tok)["sub"] == "alice"


def test_user_reaches_runctx_and_cannot_be_forged_by_a_header(env, user_auth):
    # a run acting for alice: require_run reads sub from the SIGNED grant, not a header
    client.post("/agents", json={"name": "actx"}, headers={"X-Andyur-User-Token": "good"})
    run_id = client.post("/agents/actx/trigger", json={"reason": "go"}, headers={"X-Andyur-User-Token": "good"}).json()["run_id"]
    tok = runtoken.mint("actx", run_id, "wf", sub="alice")
    r = client.get("/identity/verify-run", headers={
        "X-Andyur-Run-Token": tok,
        "X-Andyur-User-Token": "bob-tries-to-be-someone-else",  # ignored
    })
    assert r.status_code == 200 and r.json()["user"] == "alice"


def test_user_axis_is_off_by_default(env):
    # user-auth off: agents are ownerless, no user token needed (backward compatible)
    r = client.post("/agents", json={"name": "aoff"})
    assert r.status_code == 201
    with db.connect() as c:
        assert c.execute("SELECT owner FROM agents WHERE name='aoff'").fetchone()["owner"] is None

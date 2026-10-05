"""Which claim is the user, and what an ops refusal tells you to do instead.

Three platform defects found while wiring a federated demo, and their fixes:

  * `acting_user` was hard-wired to `sub`. With Keycloak that is a UUID, so the
    audit trail -- and every resource server that resolves the delegated token
    -- named `f78382c2-...` instead of `sarah.miller`.
  * `andyur agents trigger` pre-flighted the ADMIN-ONLY `/workers` and indexed
    the 403's detail STRING as if it were a list of worker rows, so the command
    crashed for exactly the principals entitled to use it (owners).
  * An admin-only refusal named the role it wanted and no alternative, which
    reads as "the platform has no answer for you" when in fact it does.
"""

import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from andyur import config
from andyur.server import app as app_module, oidc

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUB = _KEY.public_key()
_ISS = "https://idp.test/realms/andyur"
_AUD = "andyur"


def _oidc(**extra):
    claims = {"iss": _ISS, "aud": _AUD, "exp": int(time.time()) + 3600, **extra}
    return jwt.encode(claims, _KEY, algorithm="RS256", headers={"kid": "test"})


class _FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": _PUB})()


@pytest.fixture
def idp(monkeypatch):
    monkeypatch.setattr(oidc, "_jwks", _FakeJWKS())
    monkeypatch.setattr(oidc, "OIDC_ISSUER", _ISS)
    monkeypatch.setattr(oidc, "OIDC_AUDIENCE", _AUD)
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(app_module.config, "USER_AUTH", True)


# -- which claim is the user ---------------------------------------------------

def test_default_subject_claim_is_sub(idp, monkeypatch):
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "sub")
    who, _ = app_module._authed_principal(
        _oidc(sub="f78382c2-0614", preferred_username="sarah.miller"))
    assert who == "f78382c2-0614"


def test_subject_claim_can_be_pointed_at_a_legible_claim(idp, monkeypatch):
    """The whole point: the audit trail says a person, not a UUID."""
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "preferred_username")
    who, _ = app_module._authed_principal(
        _oidc(sub="f78382c2-0614", preferred_username="sarah.miller"))
    assert who == "sarah.miller"


def test_a_missing_configured_claim_fails_closed(idp, monkeypatch):
    """It must NOT fall back to `sub`.

    A fallback would put UUIDs and usernames in one ownership column, where a
    comparison between them silently never matches -- the user would stop
    seeing their own agents with no error to explain it.
    """
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "preferred_username")
    with pytest.raises(app_module.HTTPException) as exc:
        app_module._authed_principal(_oidc(sub="f78382c2-0614"))
    assert exc.value.status_code == 401
    assert "preferred_username" in exc.value.detail
    assert "f78382c2-0614" not in exc.value.detail   # did not quietly use `sub`


def test_a_blank_claim_is_not_an_identity(idp, monkeypatch):
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "preferred_username")
    with pytest.raises(app_module.HTTPException) as exc:
        app_module._authed_principal(_oidc(sub="u", preferred_username="   "))
    assert exc.value.status_code == 401


def test_a_non_string_claim_is_not_an_identity(idp, monkeypatch):
    """A hostile or merely odd token must not make a list the owner of an agent."""
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "groups")
    with pytest.raises(app_module.HTTPException) as exc:
        app_module._authed_principal(_oidc(sub="u", groups=["a", "b"]))
    assert exc.value.status_code == 401


def test_an_over_long_claim_is_refused_at_the_same_bound_the_column_uses(idp, monkeypatch):
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "preferred_username")
    long = "x" * (app_module.MAX_ACTING_USER_CHARS + 1)
    with pytest.raises(app_module.HTTPException) as exc:
        app_module._authed_principal(_oidc(sub="u", preferred_username=long))
    assert exc.value.status_code == 401


# -- the CLI pre-flight --------------------------------------------------------

class _Resp:
    def __init__(self, status, payload):
        self.status_code, self._payload = status, payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _Client:
    def __init__(self, resp):
        self._resp = resp

    def get(self, path):
        if isinstance(self._resp, Exception):
            raise self._resp
        return self._resp


def test_daemon_alive_reads_live_workers():
    from andyur import cli
    assert cli._daemon_alive(_Client(_Resp(200, [{"alive": False}, {"alive": True}])))
    assert not cli._daemon_alive(_Client(_Resp(200, [{"alive": False}])))


def test_daemon_alive_survives_the_admin_only_403(capsys):
    """THE CRASH: `/workers` is admin-only and owners are the ones who trigger.

    The 403 body is a detail string; indexing it raised
    `TypeError: string indices must be integers`.
    """
    from andyur import cli
    assert cli._daemon_alive(
        _Client(_Resp(403, {"detail": "this surface requires the 'andyur-admin' role"})))
    # and it says nothing: a 403 here is the ORDINARY case, not a fault
    assert capsys.readouterr().err == ""


def test_daemon_alive_assumes_a_worker_when_it_cannot_look():
    """Unreadable is not absent.

    Guessing "no daemon" would send an unprivileged caller down the local-runner
    path, which needs credentials they are even less likely to hold. The server
    has already accepted the run; waiting is a visible state, running in the
    wrong place is not.
    """
    from andyur import cli
    assert cli._daemon_alive(_Client(httpx.ConnectError("refused")))
    assert cli._daemon_alive(_Client(_Resp(200, ValueError("not json"))))
    assert cli._daemon_alive(_Client(_Resp(200, {"detail": "not a list"})))
    assert cli._daemon_alive(_Client(_Resp(500, "boom")))


def test_a_non_403_failure_is_reported_rather_than_swallowed(capsys):
    from andyur import cli
    cli._daemon_alive(_Client(_Resp(503, "unavailable")))
    assert "503" in capsys.readouterr().err


# -- what a refusal tells you to do instead ------------------------------------

def test_admin_refusal_names_the_owner_facing_alternative(idp, monkeypatch):
    monkeypatch.setattr(app_module.config, "ADMIN_ROLE", "andyur-admin")
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "sub")
    with pytest.raises(app_module.HTTPException) as exc:
        app_module._admin_gate(_oidc(sub="sarah"),
                               alternative="Pause the agent instead.")
    assert exc.value.status_code == 403
    assert "andyur-admin" in exc.value.detail
    assert "Pause the agent instead." in exc.value.detail


def test_admin_refusal_without_an_alternative_is_unchanged(idp, monkeypatch):
    monkeypatch.setattr(app_module.config, "ADMIN_ROLE", "andyur-admin")
    monkeypatch.setattr(app_module.config, "OIDC_SUBJECT_CLAIM", "sub")
    with pytest.raises(app_module.HTTPException) as exc:
        app_module._admin_gate(_oidc(sub="sarah"))
    assert exc.value.detail.endswith("claim)")

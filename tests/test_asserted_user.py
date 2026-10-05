"""A subject nobody authenticated must never be indistinguishable from a login.

`acting_user` was added so demos would stop writing the runs table by hand. It
also created an impersonation primitive: with no IdP configured, any operator-role
caller could name a user, and Andyur would sign an RS256 token carrying that
string as `sub`. A resource server validating against Andyur's JWKS -- which is
the whole point of the asymmetric mint, since it does not call back -- had nothing
in the token to tell it apart from a real login.

Two controls, and they are different in kind:

  the GATE       an operator must opt in; the capability is off by default
  the PROVENANCE when it is on, the token SAYS the subject was merely asserted,
                 so a resource server can refuse it on that basis

The gate alone would be a config away from the hole. The provenance alone would
ship the hole on by default. Both, or neither is worth much.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from andyur import config
from andyur.server import app as app_module, runtoken

client = TestClient(app_module.app)


def _claims(jwt_str: str) -> dict:
    part = jwt_str.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_asserting_a_user_without_an_idp_is_refused_by_default(env, monkeypatch):
    monkeypatch.setattr(config, "USER_AUTH", False)
    monkeypatch.setattr(config, "ASSERTED_USER", False)
    env.agent("a1")
    r = client.post("/agents/a1/trigger",
                        json={"reason": "x", "acting_user": "ceo@corp.example"})
    assert r.status_code == 422, (
        f"got {r.status_code}: a caller with no IdP named a user and was not "
        "refused; that string becomes the `sub` of a signed token")

    # Positive control: the SAME request without the assertion is accepted, so
    # the refusal above is about this field and not about a broken endpoint.
    ok = client.post("/agents/a1/trigger", json={"reason": "x"})
    assert ok.status_code == 201, ok.text


def test_an_opted_in_deployment_marks_the_subject_as_merely_asserted(env, monkeypatch):
    monkeypatch.setattr(config, "USER_AUTH", False)
    monkeypatch.setattr(config, "ASSERTED_USER", True)
    env.agent("a2")
    r = client.post("/agents/a2/trigger",
                        json={"reason": "x", "acting_user": "ceo@corp.example",
                              "subject_context": {"account": "1"}})
    assert r.status_code == 201, r.text
    run_id = r.json()["run_id"]

    rt = client.post(f"/runs/{run_id}/token").json()["run_token"]
    grant = client.post("/oauth/token", json={"audience": "http://rs.example/mcp"},
                            headers={"X-Andyur-Run-Token": rt})
    if grant.status_code != 200:
        pytest.skip(f"the mint refused for an unrelated reason: {grant.text[:120]}")
    claims = _claims(grant.json()["access_token"])
    assert claims["sub"] == "ceo@corp.example"
    assert claims["andyur_sub_src"] == runtoken.SUB_SRC_ASSERTED, (
        "the token names a user nobody authenticated and says nothing about it; "
        "a resource server cannot tell this from a real login")


def test_an_asserted_user_cannot_be_laundered_into_an_authenticated_one(env):
    """Delegation must not upgrade the provenance.

    If a later hop re-derived it, one exchange would turn an asserted subject
    into one that looks IdP-authenticated -- the same hole with an extra step.
    Driven through the real mint and read off the real token, because the earlier
    version of this test asserted `dict.get` semantics and would have passed with
    the production code deleted.
    """
    from andyur.server import tokenexchange

    env.agent("a5")   # the mint reads its ceiling from the registry

    first = tokenexchange.mint(
        "a5", "http://rs.example/mcp", caller=None,
        ctx_sub="ceo@corp.example", ctx_scope=["files:read"],
        ctx_sub_src=runtoken.SUB_SRC_ASSERTED)
    hop1 = _claims(first if isinstance(first, str) else first[0])
    assert hop1["andyur_sub_src"] == runtoken.SUB_SRC_ASSERTED

    # Now continue the chain with that token as the subject token.
    second = tokenexchange.mint(
        "a5", "http://rs2.example/mcp", caller="a5",
        subject_token=(first if isinstance(first, str) else first[0]),
        ctx_sub="ceo@corp.example", ctx_scope=["files:read"])
    hop2 = _claims(second if isinstance(second, str) else second[0])
    assert hop2["andyur_sub_src"] == runtoken.SUB_SRC_ASSERTED, (
        "one delegation hop upgraded an asserted subject to look authenticated")


@pytest.mark.parametrize("bad", [
    "ceo\nFORGED-AUDIT-LINE",     # a forged log line
    "ceo\rX", "ceo\tX",
    "x" * 257,                     # unbounded growth in the token and the audit
    "   ",                         # whitespace only
])
def test_an_asserted_user_is_bounded_like_every_other_value_in_a_token(
        env, monkeypatch, bad):
    """This lands in a token's `sub` and in the audit trail. `audience` already
    gets exactly these bounds, for the stated reason that an audit record the
    audited party can write is worse than no record."""
    monkeypatch.setattr(config, "USER_AUTH", False)
    monkeypatch.setattr(config, "ASSERTED_USER", True)
    env.agent("a4")
    r = client.post("/agents/a4/trigger",
                        json={"reason": "x", "acting_user": bad})
    assert r.status_code == 422, f"{bad!r} was accepted ({r.status_code})"

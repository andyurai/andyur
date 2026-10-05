"""F-08: GET /runs/{run_id}/subject-token returns the user's credential, so it
requires the run's OWN attested per-run SVID, not merely a run token.

The run token is a portable bearer secret; a copy lifted from one container
must not be spendable from another to lift the user's subject token. This
endpoint therefore forces strict SVID binding regardless of the global
ANDYUR_REQUIRE_RUN_SVID setting. These tests pin that the strictness is at the
endpoint: a run token backed by only a ROLE SVID (or no SVID) is refused even
in LAX mode, while a plain run-token endpoint accepts the same, and only a
matching PER-RUN SVID unlocks the token.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from andyur import config, db, identity
from andyur.server import app as app_module, runtoken

from conftest import NO_AUTH, OPERATOR_SVID, svid_header

client = TestClient(app_module.app)


@pytest.fixture(autouse=True)
def _agent_auth_on(monkeypatch):
    """These tests exercise the run-token path, which require_run only takes
    when AGENT_AUTH is on (conftest sets it so). Pin it explicitly: the
    full-suite reload tests in test_profile.py can leave config.AGENT_AUTH
    stale-False (an order-dependent leak tracked for the B lane), and a test
    of run-token auth must not silently fall through to role auth."""
    monkeypatch.setattr(config, "AGENT_AUTH", True)


def _seed_running(env, agent: str, run_id: str, subject_token: str) -> dict:
    env.agent(agent)
    with db.connect() as c:
        c.execute(
            "INSERT INTO runs (id, agent, state, created_at, workflow_id, "
            "subject_token, acting_user, user_asserted_by) "
            "VALUES (?, ?, 'running', ?, 'wf', ?, 'alice', 'idp')",
            (run_id, agent, db.utcnow(), subject_token))
    return {"X-Andyur-Run-Token": runtoken.mint(
        agent, run_id, "wf", sub="alice", sub_src="idp")}


def _per_run_svid(agent: str, run_id: str) -> dict:
    return svid_header(f"spiffe://{identity.TRUST_DOMAIN}/agent/{agent}/run/{run_id}")


def test_no_svid_is_refused_even_in_lax_mode(env, monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)  # global lax
    hdr = {**_seed_running(env, "sctok", "run-sc-1", "alice.jwt"), **NO_AUTH}
    # Truly no bearer (NO_AUTH suppresses the suite's default operator SVID):
    # the endpoint's own require_svid forces strict, so this 401s in lax mode.
    r = client.get("/runs/run-sc-1/subject-token", headers=hdr)
    assert r.status_code == 401


def test_a_role_svid_is_refused_even_in_lax_mode(env, monkeypatch):
    """The anti-replay core: a run token backed only by a ROLE (operator) SVID
    -- not the run's own per-run identity -- is refused. In lax global mode a
    plain endpoint would accept it (next test), so this proves the endpoint
    itself demands the per-run SVID."""
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    hdr = {**_seed_running(env, "sctokr", "run-sc-r", "alice.jwt"),
           "Authorization": f"Bearer test-svid:{OPERATOR_SVID}"}
    r = client.get("/runs/run-sc-r/subject-token", headers=hdr)
    assert r.status_code == 403


def test_a_plain_run_token_endpoint_accepts_the_same_bare_token(env, monkeypatch):
    """Positive control: the token is valid and the run is live; only the
    subject-token endpoint's extra strictness rejected it above. verify-run
    uses plain require_run (lax), so the identical setup is accepted."""
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    hdr = {**_seed_running(env, "sctok2", "run-sc-2", "alice.jwt"), **NO_AUTH}
    r = client.get("/identity/verify-run", headers=hdr)
    assert r.status_code == 200


def test_a_matching_per_run_svid_unlocks_the_token(env, monkeypatch):
    """The runner's real path: a per-run SVID naming this exact agent/run is
    presented alongside the token, and the endpoint returns the subject token.
    AS_TOKEN_ENDPOINT is set because the token is only stored/read when there is
    an external AS to present it to."""
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    hdr = {**_seed_running(env, "sctok3", "run-sc-3", "alice.subject.jwt"),
           **_per_run_svid("sctok3", "run-sc-3")}
    r = client.get("/runs/run-sc-3/subject-token", headers=hdr)
    assert r.status_code == 200
    assert r.json()["subject_token"] == "alice.subject.jwt"
    assert r.json()["expected_subject"] == "alice"
    assert r.json()["expected_actor"] == (
        "spiffe://andyur.local/agent/sctok3/run/run-sc-3")


def test_entra_returns_verified_tenant_object_continuity(env, monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_PROVIDER", "entra")
    monkeypatch.setattr(
        app_module.oidc, "validate_user_claims",
        lambda token: {"sub": "login-pairwise", "tid": "tenant", "oid": "object"})
    hdr = {**_seed_running(env, "scentra", "run-entra", "entra.subject.jwt"),
           **_per_run_svid("scentra", "run-entra")}
    response = client.get("/runs/run-entra/subject-token", headers=hdr)
    assert response.status_code == 200
    assert response.json()["expected_subject"] == '["tenant","object"]'


def test_entra_withholds_subject_token_without_tenant_object_claims(env, monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_PROVIDER", "entra")
    monkeypatch.setattr(app_module.oidc, "validate_user_claims",
                        lambda token: {"sub": "pairwise-only"})
    hdr = {**_seed_running(env, "scentra2", "run-entra2", "entra.subject.jwt"),
           **_per_run_svid("scentra2", "run-entra2")}
    response = client.get("/runs/run-entra2/subject-token", headers=hdr)
    assert response.status_code == 403
    assert "subject_token" not in response.text


def test_a_mismatched_per_run_svid_is_refused(env, monkeypatch):
    """Negative: a per-run SVID for a DIFFERENT run (a stolen-token replay from
    another container) is rejected, so the token cannot be lifted cross-run."""
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    hdr = {**_seed_running(env, "sctok4", "run-sc-4", "alice.subject.jwt"),
           **_per_run_svid("sctok4", "OTHER-RUN")}
    r = client.get("/runs/run-sc-4/subject-token", headers=hdr)
    assert r.status_code == 403

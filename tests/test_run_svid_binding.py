"""Slice 4 enforcement: a run token must be presented from the container it
belongs to. The server binds the R1 HMAC token to the caller's container-attested
per-run SVID, so a stolen token replayed from a different container is rejected."""

import pytest
from fastapi import HTTPException

from andyur import config, identity
from andyur.server import auth

CTX = {"agent": "scout", "run_id": "run-1", "workflow_id": "wf-1"}


def _svid(svid_id):
    """Make validate_token return a fixed SPIFFE id, as if a real SVID was sent."""
    return lambda tok: svid_id


def _bearer(x="tok"):
    return f"Bearer {x}"


# -- the match: token and attested SVID name the same agent/run ----------------

def test_matching_per_run_svid_is_accepted(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    monkeypatch.setattr(identity, "validate_token",
                        _svid("spiffe://andyur.local/agent/scout/run/run-1"))
    auth._bind_run_token_to_svid(CTX, _bearer())  # no raise


def test_mismatched_run_is_rejected(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    # SVID is for a DIFFERENT run than the token -> stolen-token replay
    monkeypatch.setattr(identity, "validate_token",
                        _svid("spiffe://andyur.local/agent/scout/run/OTHER"))
    with pytest.raises(HTTPException) as e:
        auth._bind_run_token_to_svid(CTX, _bearer())
    assert e.value.status_code == 403


def test_mismatched_agent_is_rejected(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    monkeypatch.setattr(identity, "validate_token",
                        _svid("spiffe://andyur.local/agent/IMPOSTOR/run/run-1"))
    with pytest.raises(HTTPException) as e:
        auth._bind_run_token_to_svid(CTX, _bearer())
    assert e.value.status_code == 403


# -- lax (default) vs strict when no per-run SVID is presented ------------------

def test_no_svid_is_allowed_in_lax_mode(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    auth._bind_run_token_to_svid(CTX, None)         # no bearer -> allowed (lax)


def test_no_svid_is_rejected_in_strict_mode(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", True)
    with pytest.raises(HTTPException) as e:
        auth._bind_run_token_to_svid(CTX, None)
    assert e.value.status_code == 401


def test_role_svid_is_allowed_in_lax_but_rejected_in_strict(monkeypatch):
    monkeypatch.setattr(identity, "validate_token",
                        _svid("spiffe://andyur.local/operator"))  # not a per-run SVID
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    auth._bind_run_token_to_svid(CTX, _bearer())    # lax: skip
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", True)
    with pytest.raises(HTTPException) as e:
        auth._bind_run_token_to_svid(CTX, _bearer())
    assert e.value.status_code == 403


# -- edges: a mismatch is ALWAYS checked; an invalid SVID is rejected ----------

def test_a_mismatch_is_rejected_in_every_configuration(monkeypatch):
    """Replaces `test_identity_off_is_a_noop_even_with_a_mismatch`, which
    asserted that a stolen run token replayed from another container is accepted
    when identity is off. That was the whole of R1 turned off by a flag, with a
    passing test recording it as intended behaviour."""
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    monkeypatch.setattr(identity, "validate_token",
                        _svid("spiffe://andyur.local/agent/other/run/z"))
    with pytest.raises(HTTPException) as e:
        auth._bind_run_token_to_svid(CTX, _bearer())
    assert e.value.status_code == 403


def test_invalid_svid_is_rejected(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)

    def _bad(tok):
        raise ValueError("bad signature")

    monkeypatch.setattr(identity, "validate_token", _bad)
    with pytest.raises(HTTPException) as e:
        auth._bind_run_token_to_svid(CTX, _bearer())
    assert e.value.status_code == 401

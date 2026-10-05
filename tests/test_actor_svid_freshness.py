"""The actor-SVID freshness check judges the REMAINING run, not the full bound.

Regression for the 801s-vs-960s false refusal (2026-08-13): the SPIRE agent
serves cached JWT-SVIDs down to half their TTL, so a slow model's first tool
call minutes into a run received a token with less than RUN_TTL+60 left and
was refused, even though the token comfortably outlived the run. The invariant
the check defends is "the token must not expire before the run ends plus a
refresh margin" -- which shrinks as the run progresses.
"""

import time

import jwt
import pytest

from andyur.runner import runner


def _token(lifetime_s: int) -> str:
    return jwt.encode({"exp": int(time.time()) + lifetime_s, "sub": "spiffe://t/run/x"},
                      "test-key", algorithm="HS256")


@pytest.fixture(autouse=True)
def _reset_deadline(monkeypatch):
    monkeypatch.setattr(runner, "RUN_TTL_SECONDS", 900)
    monkeypatch.setattr(runner, "_run_deadline", None)
    yield


def test_late_fetch_accepts_a_token_that_outlives_the_remaining_run(monkeypatch):
    """500s of run left; a 700s token is plenty. Refusing it was the bug."""
    monkeypatch.setattr(runner.identity, "fetch_token", lambda audience: _token(700))
    monkeypatch.setattr(runner, "_run_deadline", time.time() + 500)
    assert runner._fetch_actor_token("aud") is not None


def test_late_fetch_still_refuses_a_token_that_dies_before_the_run_does(monkeypatch):
    """500s of run left; a 400s token strands the final refresh. Fail closed."""
    monkeypatch.setattr(runner.identity, "fetch_token", lambda audience: _token(400))
    monkeypatch.setattr(runner, "_run_deadline", time.time() + 500)
    assert runner._fetch_actor_token("aud") is None


def test_before_the_run_clock_is_armed_the_full_bound_applies(monkeypatch):
    """No deadline yet means no remainder to measure: a token shorter than the
    whole bound plus margin is refused, exactly as before the fix."""
    monkeypatch.setattr(runner.identity, "fetch_token", lambda audience: _token(700))
    assert runner._fetch_actor_token("aud") is None


def test_arming_the_deadline_anchors_it_to_the_run_bound():
    before = time.time()
    runner._arm_run_deadline()
    assert runner._run_deadline == pytest.approx(before + 900, abs=5)

"""The one home for the /runs/{id}/finish HTTP contract (runfinish.post_finish).

Owns: retry a 5xx or network error, treat any other <500 as terminal, and
report whether the run reached a confirmed terminal state. The runner's four
finish call sites and the daemon's exec/v1 completion all go through this."""
from __future__ import annotations

import asyncio

import pytest

from andyur import runfinish


class _Resp:
    def __init__(self, status): self.status_code = status


class _Api:
    """Records the finish bodies and replies with a scripted status sequence."""
    def __init__(self, statuses):
        self._statuses = list(statuses)
        self.calls = []

    async def post(self, url, json):
        self.calls.append((url, json))
        nxt = self._statuses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return _Resp(nxt)


def _run(api, **kw):
    return asyncio.run(runfinish.post_finish(api, "r1", summary="s", error=None, **kw))


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    async def instant(_): pass
    monkeypatch.setattr(runfinish.asyncio, "sleep", instant)


@pytest.mark.parametrize("status", [200, 201, 204, 409, 404])
def test_terminal_statuses_confirm_in_one_attempt(status):
    api = _Api([status])
    confirmed, reason = _run(api)
    assert confirmed is True and reason == ""
    assert len(api.calls) == 1


def test_a_5xx_is_retried_then_confirmed():
    api = _Api([503, 502, 200])
    confirmed, _ = _run(api)
    assert confirmed is True and len(api.calls) == 3


def test_a_network_error_is_retried():
    api = _Api([ConnectionError("reset"), 200])
    confirmed, _ = _run(api)
    assert confirmed is True and len(api.calls) == 2


def test_a_transient_401_is_retried_then_confirmed():
    # A finish landing during an SVID/token rotation fails auth transiently;
    # giving up would strand the run exactly as a 5xx would. So a 401 is retried.
    api = _Api([401, 200])
    confirmed, _ = _run(api)
    assert confirmed is True and len(api.calls) == 2


def test_a_persistent_4xx_is_retried_then_reported_unconfirmed():
    api = _Api([400, 400, 400])
    confirmed, reason = _run(api)
    assert confirmed is False and "400" in reason
    assert len(api.calls) == 3


def test_exhausted_5xx_is_unconfirmed_with_the_reason():
    api = _Api([503, 503, 503])
    confirmed, reason = _run(api)
    assert confirmed is False and "503" in reason
    assert len(api.calls) == 3


def test_the_body_is_summary_and_error():
    api = _Api([200])
    asyncio.run(runfinish.post_finish(api, "r1", summary="the result", error="boom"))
    assert api.calls[0][1] == {"summary": "the result", "error": "boom"}

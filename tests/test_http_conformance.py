"""HTTP-layer conformance guards from the whole-codebase audit.

Two properties the audit found unguarded:
  - RFC 9110 sec 11.1: the Authorization scheme is case-insensitive, so a
    conforming client's `bearer` must be accepted -- most sharply on the frozen
    public BYOA channel, whose own protocol doc third parties implement against.
  - A control-plane request body must be bounded, or an agent-reachable tool
    write could OOM the shared server before any validation runs.
"""

import asyncio

import pytest
from fastapi.testclient import TestClient

from andyur import identity
from andyur.runner.agentchannel import AgentChannel
from andyur.server import app as app_module

client = TestClient(app_module.app)


# --- RFC 9110: case-insensitive bearer scheme --------------------------------

@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "BeArEr"])
def test_bearer_token_helper_is_case_insensitive(scheme):
    assert identity.bearer_token(f"{scheme} tok-123") == "tok-123"


@pytest.mark.parametrize("header", [None, "", "Basic tok", "Bearer", "Bearer ",
                                    "tok-no-scheme"])
def test_bearer_token_helper_rejects_non_bearer(header):
    assert identity.bearer_token(header) is None


class _Req:
    """Minimal stand-in for AgentChannel._authorized's `request.headers.get`."""

    def __init__(self, authorization):
        self.headers = {"authorization": authorization}


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
def test_public_channel_accepts_case_insensitive_bearer(scheme):
    """The frozen /v1/context + /v1/events channel must accept a conforming
    third-party runtime adapter's lowercase scheme, not 401 it."""
    channel = AgentChannel({"protocol_version": "andyur-agent-runtime/v1"},
                           token="run-secret")
    assert channel._authorized(_Req(f"{scheme} run-secret")) is True


def test_public_channel_still_refuses_a_wrong_token_and_wrong_scheme():
    channel = AgentChannel({}, token="run-secret")
    assert channel._authorized(_Req("bearer wrong-token")) is False   # right scheme, wrong token
    assert channel._authorized(_Req("Basic run-secret")) is False     # wrong scheme


# --- control-plane request-body cap ------------------------------------------

def test_body_size_limit_refuses_an_over_declared_content_length():
    """The middleware refuses on Content-Length alone, before the app buffers a
    byte -- tested directly (a tiny declared limit) so we don't allocate the real
    64 MiB cap in the suite. This is the OOM guard's actual enforcement point."""
    middleware = app_module._BodySizeLimit(None, limit=100)
    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "headers": [(b"content-length", b"999")]}
    asyncio.run(middleware(scope, receive, send))
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 413


def test_a_transcript_sized_body_is_not_rejected_by_the_cap():
    """Regression (audit MED-A): the cap must admit the run's own transcript write.
    The runner PUTs the whole transcript as one body derived from the <=64 MiB
    agent stream, so a body LARGER than the old 4 MiB cap must NOT 413 -- it must
    reach routing (whatever auth/4xx happens there is not the size gate). A 4 MiB
    cap regressed this into silent audit-record loss."""
    eight_mib = b"x" * (8 * 1024 * 1024)
    assert app_module._MAX_REQUEST_BYTES >= len(eight_mib)   # the cap admits it
    r = client.put("/agents/scout/files/runs/r1/transcript.jsonl",
                   content=eight_mib,
                   headers={"content-type": "application/json"})
    assert r.status_code != 413


def test_a_small_body_reaches_a_real_control_plane_route():
    """Positive control that the cap is a SIZE gate, not a blanket refusal: a small
    body reaches an actual control-plane route (/messages) rather than a 404 path,
    so 'not 413' means it genuinely passed the guard into routing."""
    r = client.post("/messages", json={})
    assert r.status_code != 413
    assert r.status_code != 404          # /messages is a real control-plane route


# --- an over-cap transcript is surfaced, not silently dropped (MED-A follow-up) ---
# The body cap admits typical transcripts but is a bound, not a guarantee: the
# in-process runner accumulates the transcript across many turns with no single-
# stream bound, so a pathological run can still 413. Because the runner's HTTP
# client does not raise on 4xx, that loss was silent; these pin that it now warns.

from andyur.runner import runner as _runner


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code

    @property
    def is_success(self):
        return 200 <= self.status_code < 300


def test_a_persisted_transcript_produces_no_warning():
    assert _runner._transcript_refusal_warning(_Resp(200), "ok\n") is None
    assert _runner._transcript_refusal_warning(_Resp(204), "ok\n") is None
    assert _runner._transcript_refusal_warning(None, "ok\n") is None      # no response


def test_a_refused_transcript_warns_with_its_size_and_status():
    w = _runner._transcript_refusal_warning(_Resp(413), "abcd")           # 4 bytes
    assert w is not None
    assert "413" in w and "4-byte" in w
    assert "ANDYUR_MAX_REQUEST_BYTES" in w      # names the actionable knob


def test_put_file_returns_the_response_so_a_refusal_is_visible():
    """The enabling change: _put_file must RETURN the response. A None return
    (its old signature) would hide the 413 from the caller and drop the audit
    record silently again."""
    class _FakeApi:
        async def put(self, *a, **k):
            return _Resp(413)

    r = asyncio.run(_runner._put_file(_FakeApi(), "scout",
                                      "runs/r1/transcript.jsonl", "x", "r1"))
    assert r is not None and r.status_code == 413

"""gateway.local_exchange: the per-run sidecar's LOCAL-mint exchange_fn.

It mints at Andyur's own /oauth/token, authenticated by the run token, and is
the counterpart to server.asclient.exchange (the external-AS leg). The security
properties: the run token authenticates the call (so the actor/user/pin come
from the run, never the body), only audience + scope travel, and a refusal RAISES
so the sidecar fails closed."""

import json
import urllib.parse

import pytest

from andyur import identity
from andyur.runner import gateway


def _capture(monkeypatch, status=200, body=b'{"access_token":"MINTED","expires_in":300}'):
    seen = {}

    def fake_http(host, port, method, path, headers, payload, timeout):
        seen.update(host=host, port=port, method=method, path=path,
                    headers=headers, form=dict(urllib.parse.parse_qsl(
                        (payload or b"").decode())))
        return (status, {}, body)

    monkeypatch.setattr(gateway, "_http", fake_http)
    return seen


def test_local_exchange_mints_at_andyur_with_the_run_token(monkeypatch):
    seen = _capture(monkeypatch)
    fn = gateway.local_exchange("RUN-TOKEN-123", "127.0.0.1:8642")
    resp = fn(audience="resource:telemetry", scope=["obs:read"],
              subject_token="ignored", actor_token="ignored",
              authorization_details="ignored", resource="ignored")
    assert resp["access_token"] == "MINTED"
    # minted at Andyur's own token endpoint, authenticated by the RUN token
    assert seen["method"] == "POST" and seen["path"] == "/oauth/token"
    assert seen["headers"][identity.RUN_TOKEN_HEADER] == "RUN-TOKEN-123"
    # only audience + scope travel; the actor/user/pin come from the run token
    assert seen["form"]["audience"] == "resource:telemetry"
    assert seen["form"]["scope"] == "obs:read"
    assert seen["form"]["grant_type"].endswith("token-exchange")


def test_local_exchange_ignores_caller_supplied_identity(monkeypatch):
    """subject_token/actor_token/authorization_details from the caller must NOT
    reach the mint -- the run token fixes identity and pin."""
    seen = _capture(monkeypatch)
    gateway.local_exchange("RUN", "h:1")(
        audience="resource:x", scope=None,
        subject_token="FORGED-USER", actor_token="FORGED-ACTOR",
        authorization_details="FORGED-PIN")
    flat = " ".join(f"{k}={v}" for k, v in seen["form"].items())
    assert "FORGED" not in flat
    assert "authorization_details" not in seen["form"]
    # placeholder subject only; the run token is the real authenticator
    assert seen["form"]["subject_token"] == "andyur-sidecar"


def test_local_exchange_raises_on_refusal_so_the_sidecar_fails_closed(monkeypatch):
    _capture(monkeypatch, status=400,
             body=b'{"detail":{"error":"invalid_target"}}')
    with pytest.raises(gateway.GatewayUnavailable):
        gateway.local_exchange("RUN", "h:1")(audience="resource:x", scope=[])


def test_local_exchange_raises_when_the_mint_does_not_answer(monkeypatch):
    monkeypatch.setattr(gateway, "_http", lambda *a, **k: None)
    with pytest.raises(gateway.GatewayUnavailable):
        gateway.local_exchange("RUN", "h:1")(audience="resource:x", scope=[])


def test_local_exchange_attaches_the_run_svid_bearer(monkeypatch):
    """Under ANDYUR_REQUIRE_RUN_SVID the mint refuses a run-scoped call with no
    Authorization bearer -- the leg verify_mint and the gateway policy already
    send. Omitting it made sidecar egress dead in the hardened configuration."""
    seen = _capture(monkeypatch)
    fn = gateway.local_exchange("RUN.tok", "127.0.0.1:8642",
                                actor_token="SVID.run")
    fn(audience="resource:ci")
    assert seen["headers"]["Authorization"] == "Bearer SVID.run"
    # the run token still authenticates the call alongside it
    assert seen["headers"][identity.RUN_TOKEN_HEADER] == "RUN.tok"


def test_local_exchange_sends_no_bearer_when_it_has_none(monkeypatch):
    seen = _capture(monkeypatch)
    fn = gateway.local_exchange("RUN.tok", "127.0.0.1:8642")
    fn(audience="resource:ci")
    assert "Authorization" not in seen["headers"]

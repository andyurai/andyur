"""Authenticated atomic state consumed by the production deny-only broker."""

from fastapi.testclient import TestClient
import pytest

from andyur import config, db, identity
from andyur.server import app as app_module, brokerstate_server, runtoken
from conftest import NO_AUTH, svid_header


client = TestClient(brokerstate_server.app)


def test_backend_probe_checks_the_private_uds(monkeypatch):
    observed = {}

    class Response:
        status_code = 200

    class Client:
        def __init__(self, *, transport, timeout, trust_env):
            observed.update(timeout=timeout, trust_env=trust_env,
                            transport=transport)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def get(self, url):
            observed["url"] = url
            return Response()

    monkeypatch.setattr(brokerstate_server.httpx, "Client", Client)
    monkeypatch.setattr(brokerstate_server.sys, "argv", ["brokerstate", "--check"])
    monkeypatch.setenv("ANDYUR_BROKER_STATE_SOCKET", "/run/state.sock")
    with pytest.raises(SystemExit) as stopped:
        brokerstate_server.main()
    assert stopped.value.code == 0
    assert observed["url"] == "http://andyur-broker-state/ready"
    assert observed["timeout"] == 0.75
    assert observed["trust_env"] is False


def test_backend_probe_fails_closed_when_the_uds_is_unavailable(monkeypatch):
    class Client:
        def __init__(self, **_):
            pass

        def __enter__(self):
            raise brokerstate_server.httpx.ConnectError("UDS unavailable")

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(brokerstate_server.httpx, "Client", Client)
    monkeypatch.setattr(brokerstate_server.sys, "argv", ["brokerstate", "--check"])
    monkeypatch.setenv("ANDYUR_BROKER_STATE_SOCKET", "/run/state.sock")
    with pytest.raises(SystemExit) as stopped:
        brokerstate_server.main()
    assert stopped.value.code == 1
general_client = TestClient(app_module.app)


def _seed(env, *, run_id="broker-state-1"):
    env.agent("broker-agent")
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO runs (id, agent, state, created_at, workflow_id, "
            "acting_user, scope, subject_context, registry_digest, "
            "ceiling_audiences) VALUES (?, 'broker-agent', 'running', ?, "
            "'wf', 'alice', '[\"read\"]', '{\"account\":\"447\"}', "
            "'sha256:" + "a" * 64 + "', '[\"urn:calendar\"]')",
            (run_id, db.utcnow()),
        )
    token = runtoken.mint(
        "broker-agent", run_id, "wf", purpose=runtoken.PURPOSE_BROKER)
    peer = f"spiffe://{identity.TRUST_DOMAIN}/agent/broker-agent/run/{run_id}"
    return {
        "X-Andyur-Run-Token": token,
        "X-Forwarded-Client-Cert": f"URI={peer}",
        **svid_header(peer),
    }


def test_exact_broker_token_and_run_svid_return_closed_atomic_state(env, monkeypatch):
    monkeypatch.setattr(config, "AGENT_AUTH", True)
    headers = _seed(env)
    response = client.get("/runs/broker-state-1/broker-state", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "schema": "andyur.deny-broker-state/v1",
        "run_id": "broker-state-1",
        "agent": "broker-agent",
        "live": True,
        "expected_subject": "alice",
        "expected_actor": (
            "spiffe://andyur.local/agent/broker-agent/run/broker-state-1"),
        "registry_sha256": "a" * 64,
        "audiences": ["urn:calendar"],
        "actions": ["read"],
        "pin": {"account": "447"},
    }


def test_broker_state_refuses_missing_wrong_purpose_and_wrong_svid(env, monkeypatch):
    monkeypatch.setattr(config, "AGENT_AUTH", True)
    headers = _seed(env, run_id="broker-state-2")
    assert client.get(
        "/runs/broker-state-2/broker-state", headers=NO_AUTH).status_code == 401
    ordinary = runtoken.mint("broker-agent", "broker-state-2", "wf")
    assert client.get("/runs/broker-state-2/broker-state", headers={
        **headers, "X-Andyur-Run-Token": ordinary}).status_code == 401
    assert client.get("/runs/broker-state-2/broker-state", headers={
        **headers,
        **svid_header("spiffe://andyur.local/agent/broker-agent/run/other"),
    }).status_code == 403


def test_broker_state_refuses_spoofed_cross_run_tls_peer_and_general_api(env, monkeypatch):
    monkeypatch.setattr(config, "AGENT_AUTH", True)
    headers = _seed(env, run_id="broker-state-peer")
    headers["X-Forwarded-Client-Cert"] = (
        "URI=spiffe://andyur.local/agent/broker-agent/run/other")
    assert client.get(
        "/runs/broker-state-peer/broker-state", headers=headers).status_code == 403
    # The ordinary network API does not expose this route; only the UDS backend
    # may interpret Envoy's TLS-derived XFCC.
    assert general_client.get(
        "/runs/broker-state-peer/broker-state", headers=headers).status_code == 404


def test_broker_state_refuses_terminal_run_before_returning_snapshot(env, monkeypatch):
    monkeypatch.setattr(config, "AGENT_AUTH", True)
    headers = _seed(env, run_id="broker-state-3")
    with db.connect() as conn:
        conn.execute("UPDATE runs SET state='failed' WHERE id='broker-state-3'")
    assert client.get(
        "/runs/broker-state-3/broker-state", headers=headers).status_code == 401

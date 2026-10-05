"""The exec/v1 serve-only services over the REAL wire, no cluster (R MED-3):
the declared bearer opens /mcp and nothing else does, /ready answers on the
front, /llm is 503 by name with no model proxy. Runs the real
_start_serve_only_services (real ToolService + _TokenGuard + ExecFront) in
process mode in well under a second."""
from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest

from andyur.runner import runner

INITIALIZE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {},
    "clientInfo": {"name": "gate", "version": "0"}}})
MCP_HEADERS = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}


@pytest.fixture()
def services(monkeypatch):
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer-value")
    monkeypatch.setenv("ANDYUR_CHANNEL_TOKEN", "channel-token-value")
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    with patch("andyur.runner.driver._server_call"):
        front, svc, mcp_url = runner._start_serve_only_services(
            "alice", "r1", None, None, enforced_model="granted-model")
        try:
            front_url = f"http://127.0.0.1:{front._server.servers[0].sockets[0].getsockname()[1]}"
            yield front_url, mcp_url
        finally:
            front.stop()
            svc.stop()


def _initialize(mcp_url, headers):
    return httpx.post(mcp_url, content=INITIALIZE, headers={**MCP_HEADERS, **headers}, timeout=5)


def test_the_declared_bearer_opens_mcp_and_nothing_else_does(services):
    _, mcp_url = services
    ok = _initialize(mcp_url, {"Authorization": "Bearer declared-bearer-value"})
    assert ok.status_code == 200, ok.text
    assert "mcp-session-id" in {k.lower() for k in ok.headers}
    for name, headers in {
        "none": {},
        "wrong": {"Authorization": "Bearer " + "x" * 21},
        "channel": {"Authorization": "Bearer channel-token-value"},
        "bare": {"Authorization": "declared-bearer-value"},
        "lowercase-scheme-but-wrong": {"authorization": "bearer nope"},
    }.items():
        r = _initialize(mcp_url, headers)
        assert r.status_code == 401, (name, r.status_code, r.text)
        assert r.headers.get("www-authenticate") == "Bearer", name
    # a non-UTF-8 header (httpx refuses to send one) over a raw socket: a
    # refused credential, 401, not a decode error surfacing as 500
    import socket
    host, port = mcp_url[len("http://"):].split("/", 1)[0].rsplit(":", 1)
    s = socket.create_connection((host, int(port)))
    s.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer \xff\xfe\r\n"
              b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close()
    assert data.startswith(b"HTTP/1.1 401"), data[:80]
    assert b"www-authenticate: bearer" in data.lower()


def test_the_front_answers_ready_and_names_the_missing_model_proxy(services):
    front_url, _ = services
    assert httpx.get(front_url + "/ready").json() == {"ready": True, "model_proxy": False}
    assert httpx.post(front_url + "/llm/api/chat", json={"model": "granted-model"}).status_code == 503
    assert httpx.post(front_url + "/llm/api/chat", content=b"{}").status_code == 403   # no model named
    assert httpx.get(front_url + "/llm/api/tags").status_code == 404      # the policy, live


def test_a_run_granted_no_model_has_every_model_call_refused(monkeypatch):
    """R MED-1: with no grant the front refuses every model call by name; it
    never falls back to a default the policy did not approve."""
    monkeypatch.setenv("ANDYUR_MCP_TOKEN", "declared-bearer-value")
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    with patch("andyur.runner.driver._server_call"):
        front, svc, _ = runner._start_serve_only_services("alice", "r1", None, None, enforced_model=None)
        try:
            base = f"http://127.0.0.1:{front._server.servers[0].sockets[0].getsockname()[1]}"
            r = httpx.post(base + "/llm/api/chat", json={"model": "qwen3:8b"})
            assert r.status_code == 403 and r.json()["error"] == "no_model_granted"
            assert "granted no model" in r.json()["detail"]
        finally:
            front.stop(); svc.stop()

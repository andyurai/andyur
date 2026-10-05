"""The ext_authz decision service: identity PROVISIONED (not agent-supplied),
exchange MANDATORY, liveness checked, authority computed in ONE place
(registry.authority_for, injected here), fail-closed. The Envoy wire contract
(200 allow / 403 deny, no credential to the tool) is proven live in the gate;
here the decision logic is proven without Envoy, SPIRE, or an AS.
"""
from __future__ import annotations

import hashlib
import inspect
import threading
import time

import anyio
import httpx
import pytest
from starlette.testclient import TestClient

from andyur.dataplane import extauthz

AUD = "resource:calendar"


def _sealed(**changes):
    values = {
        "agent": "scout", "run_id": "r1",
        "expected_subject": "alice",
        "expected_actor": "spiffe://andyur.local/agent/scout/run/r1",
        "audience": AUD, "actions": ("calendar:read",),
        "resource_pin_json": '{"account":"447"}',
        "registry_sha256": hashlib.sha256(b"registry-v7").hexdigest(),
    }
    return extauthz.SealedAuthorityEnvelope(**{**values, **changes})


def _deny_client(*, envelope=None, live=True, identity=None, digest=None,
                 decision=None, authority_fn=None):
    envelope = envelope or _sealed()
    decision = decision or {
        "audience": AUD, "actions": ["calendar:read"],
        "pin": {"account": "447"},
    }
    app = extauthz.build_deny_only_broker(
        envelope=envelope,
        liveness_fn=lambda run_id: live,
        identity_fn=lambda run_id: identity or (
            envelope.expected_subject, envelope.expected_actor),
        registry_digest_fn=lambda agent, run_id: (
            digest or envelope.registry_sha256),
        authority_fn=authority_fn or (
            lambda agent, run_id, audience, method, tool: decision),
    )
    return TestClient(app)


def test_deny_only_broker_positive_control_is_ready_but_cannot_issue():
    seen = {}

    def authority(agent, run_id, audience, method, tool):
        seen.update(agent=agent, run_id=run_id, audience=audience,
                    method=method, tool=tool)
        return {"audience": AUD, "actions": ["calendar:read"],
                "pin": {"account": "447"}}

    client = _deny_client(authority_fn=authority)
    assert client.get("/ready").status_code == 200
    response = client.post(
        "/authz/mcp", content=b'{"agent":"attacker","audience":"admin"}',
        headers={"authorization": "Bearer attacker", "x-run-id": "other"})
    assert response.status_code == 403
    assert response.text == "credential issuance is disabled"
    assert "authorization" not in response.headers
    assert seen == {"agent": "scout", "run_id": "r1",
                    "audience": AUD, "method": None, "tool": None}
    assert "exchange_fn" not in inspect.signature(
        extauthz.build_deny_only_broker).parameters


def test_broker_authority_contract_is_run_bound_not_container_generation_bound():
    """Operational Pod generations must never become authorization inputs."""
    assert "generation" not in inspect.signature(
        extauthz.SealedAuthorityEnvelope).parameters
    seen = []
    client = _deny_client(authority_fn=lambda *args: seen.append(args) or {
        "audience": AUD, "actions": ["calendar:read"],
        "pin": {"account": "447"},
    })
    assert client.get("/ready").status_code == 200
    assert seen == [("scout", "r1", AUD, None, None)]


def test_every_state_consumer_receives_the_exact_sealed_run_id():
    envelope = _sealed()
    seen = []
    app = extauthz.build_deny_only_broker(
        envelope=envelope,
        liveness_fn=lambda run_id: seen.append(("live", run_id)) or True,
        identity_fn=lambda run_id: seen.append(("identity", run_id)) or (
            envelope.expected_subject, envelope.expected_actor),
        registry_digest_fn=lambda agent, run_id: seen.append(
            ("registry", agent, run_id)) or envelope.registry_sha256,
        authority_fn=lambda agent, run_id, audience, method, tool: seen.append(
            ("authority", agent, run_id, audience, method, tool)) or {
                "audience": AUD, "actions": ["calendar:read"],
                "pin": {"account": "447"}},
    )
    assert TestClient(app).get("/ready").status_code == 200
    assert seen == [
        ("live", "r1"), ("identity", "r1"),
        ("registry", "scout", "r1"),
        ("authority", "scout", "r1", AUD, None, None),
    ]


@pytest.mark.parametrize("changes,reason", [
    ({"live": False}, "not active"),
    ({"identity": ("mallory", "spiffe://andyur.local/agent/other/run/r1")},
     "sealed identity changed"),
    ({"digest": "0" * 64}, "registry generation changed"),
    ({"decision": {"audience": "other", "actions": ["calendar:read"],
                    "pin": {"account": "447"}}}, "sealed authority changed"),
    ({"decision": {"audience": AUD, "actions": ["calendar:write"],
                    "pin": {"account": "447"}}}, "sealed authority changed"),
    ({"decision": {"audience": AUD, "actions": ["calendar:read"],
                    "pin": {"account": "999"}}}, "sealed authority changed"),
])
def test_deny_only_broker_withdraws_readiness_and_authz_on_state_drift(
        changes, reason):
    client = _deny_client(**changes)
    ready = client.get("/ready")
    denied = client.post("/authz")
    assert ready.status_code == 503 and reason in ready.text
    assert denied.status_code == 403 and reason in denied.text
    assert "authorization" not in denied.headers


@pytest.mark.parametrize("which", ["liveness", "identity", "registry", "authority"])
def test_deny_only_broker_converts_dependency_failure_to_named_refusal(which):
    def fail(*_):
        raise RuntimeError("dependency unavailable")

    envelope = _sealed()
    app = extauthz.build_deny_only_broker(
        envelope=envelope,
        liveness_fn=fail if which == "liveness" else lambda *_: True,
        identity_fn=fail if which == "identity" else lambda *_: (
            envelope.expected_subject, envelope.expected_actor),
        registry_digest_fn=fail if which == "registry" else (
            lambda *_: envelope.registry_sha256),
        authority_fn=fail if which == "authority" else (
            lambda *_: {"audience": AUD, "actions": ["calendar:read"],
                        "pin": {"account": "447"}}),
    )
    client = TestClient(app)
    assert client.get("/ready").status_code == 503
    assert client.post("/authz").status_code == 403


def test_deny_only_broker_bounds_the_request_before_state_or_parsing():
    calls = []
    app = extauthz.build_deny_only_broker(
        envelope=_sealed(),
        liveness_fn=lambda *_: calls.append("live") or True,
        identity_fn=lambda *_: calls.append("identity") or ("alice", "actor"),
        registry_digest_fn=lambda *_: calls.append("registry") or "0" * 64,
        authority_fn=lambda *_: calls.append("authority") or {},
    )
    response = TestClient(app).post(
        "/authz", content=b"x" * (extauthz.MAX_BROKER_REQUEST_BYTES + 1))
    assert response.status_code == 413
    assert calls == []


@pytest.mark.parametrize("changes,reason", [
    ({"expected_subject": ""}, "expected_subject"),
    ({"expected_actor": "run-r1"}, "SPIFFE"),
    ({"actions": ["calendar:read"]}, "actions"),
    ({"actions": ("z", "a")}, "actions"),
    ({"resource_pin_json": '{"account": "447"}'}, "canonical JSON"),
    ({"registry_sha256": "not-a-digest"}, "SHA-256"),
])
def test_sealed_authority_envelope_is_closed_and_canonical(changes, reason):
    with pytest.raises(ValueError, match=reason):
        _sealed(**changes)


@pytest.mark.parametrize("actor", [
    "spiffe://", "spiffe://foreign.test/agent/scout/run/r1",
    "spiffe://andyur.local/agent/other/run/r1",
    "spiffe://andyur.local/agent/scout/run/other",
    "spiffe://andyur.local/agent/scout/run/r1?admin=true",
    "spiffe://andyur.local/agent/scout/run/r1#fragment",
])
def test_sealed_actor_is_exactly_bound_to_agent_and_run(actor):
    with pytest.raises(ValueError, match="exact agent/run SPIFFE"):
        _sealed(expected_actor=actor)


@pytest.mark.parametrize("actions", [(1, "a"), ({"x": 1},)])
def test_sealed_actions_refuse_malformed_types_without_raw_exceptions(actions):
    with pytest.raises(ValueError, match="actions"):
        _sealed(actions=actions)


def test_sealed_action_refuses_invalid_unicode_as_a_named_validation_error():
    with pytest.raises(ValueError, match="invalid Unicode"):
        _sealed(actions=("calendar:\ud800",))


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_sealed_pin_refuses_non_finite_json(constant):
    with pytest.raises(ValueError, match="canonical JSON"):
        _sealed(resource_pin_json=f'{{"amount":{constant}}}')


def test_sealed_actions_have_count_and_aggregate_bounds():
    with pytest.raises(ValueError, match="aggregate bound"):
        _sealed(actions=tuple(f"action:{i:04d}" for i in range(
            extauthz.MAX_BROKER_ACTIONS + 1)))
    with pytest.raises(ValueError, match="aggregate bound"):
        _sealed(actions=tuple(
            f"{i:04d}:" + "x" * 250
            for i in range(extauthz.MAX_BROKER_ACTION_BYTES // 256 + 1)))


def test_current_authority_actions_and_pin_fail_closed_at_the_same_bounds():
    too_many = [f"action:{i:04d}" for i in range(extauthz.MAX_BROKER_ACTIONS + 1)]
    assert _deny_client(decision={"audience": AUD, "actions": too_many,
                                  "pin": {"account": "447"}}).get(
                                      "/ready").status_code == 503
    assert _deny_client(decision={"audience": AUD, "actions": ["calendar:read"],
                                  "pin": {"amount": float("nan")}}).get(
                                      "/ready").status_code == 503


def test_current_authority_pin_is_bounded_before_canonical_serialization():
    exact = {"v": "x" * (extauthz.MAX_BROKER_PIN_BYTES - len('{"v":""}'))}
    exact_envelope = _sealed(resource_pin_json=extauthz._canonical_pin(exact))
    assert _deny_client(
        envelope=exact_envelope,
        decision={"audience": AUD, "actions": ["calendar:read"],
                  "pin": exact}).get("/ready").status_code == 200

    oversized = {"v": "x" * extauthz.MAX_BROKER_PIN_BYTES}
    assert _deny_client(decision={"audience": AUD, "actions": ["calendar:read"],
                                  "pin": oversized}).get(
                                      "/ready").status_code == 503
    too_many = {str(i): i for i in range(extauthz.MAX_BROKER_PIN_NODES + 1)}
    assert _deny_client(decision={"audience": AUD, "actions": ["calendar:read"],
                                  "pin": too_many}).get(
                                      "/ready").status_code == 503
    deep = current = {}
    for _ in range(extauthz.MAX_BROKER_PIN_DEPTH + 1):
        child = {}
        current["child"] = child
        current = child
    assert _deny_client(decision={"audience": AUD, "actions": ["calendar:read"],
                                  "pin": deep}).get("/ready").status_code == 503
    large_numbers = {str(i): 10 ** 100 for i in range(64)}
    assert _deny_client(decision={"audience": AUD, "actions": ["calendar:read"],
                                  "pin": large_numbers}).get(
                                      "/ready").status_code == 503


def test_sealed_pin_refuses_invalid_unicode_as_a_named_validation_error():
    with pytest.raises(ValueError, match="invalid Unicode"):
        _sealed(resource_pin_json='{"value":"\ud800"}')


def test_hung_state_dependency_times_out_and_shutdown_completes(monkeypatch):
    release = threading.Event()
    entered = threading.Event()

    def hung(*_):
        entered.set()
        release.wait()
        return True

    monkeypatch.setattr(extauthz, "DENY_ONLY_STATE_TIMEOUT_SECONDS", 0.05)
    app = extauthz.build_deny_only_broker(
        envelope=_sealed(), liveness_fn=hung,
        identity_fn=lambda *_: ("alice", _sealed().expected_actor),
        registry_digest_fn=lambda *_: _sealed().registry_sha256,
        authority_fn=lambda *_: {})
    started = time.monotonic()
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 503 and "timed out" in response.text
        assert entered.is_set()
    assert time.monotonic() - started < 1.0
    release.set()


def test_state_check_capacity_saturation_is_refused_without_queueing(monkeypatch):
    release = threading.Event()
    lock = threading.Lock()
    entered = 0
    all_entered = threading.Event()

    def hung(*_):
        nonlocal entered
        with lock:
            entered += 1
            if entered == extauthz.DENY_ONLY_STATE_CONCURRENCY:
                all_entered.set()
        release.wait()
        return True

    monkeypatch.setattr(extauthz, "DENY_ONLY_STATE_TIMEOUT_SECONDS", 2.0)
    app = extauthz.build_deny_only_broker(
        envelope=_sealed(), liveness_fn=hung,
        identity_fn=lambda *_: ("alice", _sealed().expected_actor),
        registry_digest_fn=lambda *_: _sealed().registry_sha256,
        authority_fn=lambda *_: {})
    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
                transport=transport, base_url="http://broker") as client:
            async with anyio.create_task_group() as group:
                for _ in range(extauthz.DENY_ONLY_STATE_CONCURRENCY):
                    group.start_soon(client.get, "/ready")
                assert await anyio.to_thread.run_sync(all_entered.wait, 1.0)
                response = await client.post("/authz")
                assert response.status_code == 403
                assert response.text == "broker state-check capacity exhausted"
                release.set()

    anyio.run(exercise)


def test_repeated_timeouts_cannot_accumulate_more_residual_workers(monkeypatch):
    release = threading.Event()
    lock = threading.Lock()
    entered = 0

    def hung(*_):
        nonlocal entered
        with lock:
            entered += 1
        release.wait()
        return True

    monkeypatch.setattr(extauthz, "DENY_ONLY_STATE_TIMEOUT_SECONDS", 0.01)
    app = extauthz.build_deny_only_broker(
        envelope=_sealed(), liveness_fn=hung,
        identity_fn=lambda *_: ("alice", _sealed().expected_actor),
        registry_digest_fn=lambda *_: _sealed().registry_sha256,
        authority_fn=lambda *_: {})
    client = TestClient(app)
    try:
        responses = [client.get("/ready") for _ in range(
            extauthz.DENY_ONLY_STATE_CONCURRENCY * 2)]
        assert all(response.status_code == 503 for response in responses)
        assert entered == extauthz.DENY_ONLY_STATE_CONCURRENCY
    finally:
        release.set()


def test_prestart_timeout_releases_dependency_slot(monkeypatch):
    monkeypatch.setattr(extauthz, "DENY_ONLY_STATE_TIMEOUT_SECONDS", 0.01)
    app = extauthz.build_deny_only_broker(
        envelope=_sealed(), liveness_fn=lambda *_: True,
        identity_fn=lambda *_: ("alice", _sealed().expected_actor),
        registry_digest_fn=lambda *_: _sealed().registry_sha256,
        authority_fn=lambda *_: {"audience": AUD, "actions": ["calendar:read"],
                                 "pin": {"account": "447"}})

    async def exercise():
        limiter = anyio.to_thread.current_default_thread_limiter()
        borrowers = [object() for _ in range(limiter.total_tokens)]
        for borrower in borrowers:
            await limiter.acquire_on_behalf_of(borrower)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
                transport=transport, base_url="http://broker") as client:
            try:
                for _ in range(extauthz.DENY_ONLY_STATE_CONCURRENCY):
                    response = await client.get("/ready")
                    assert response.status_code == 503
                    assert "timed out" in response.text
            finally:
                for borrower in borrowers:
                    limiter.release_on_behalf_of(borrower)
            monkeypatch.setattr(
                extauthz, "DENY_ONLY_STATE_TIMEOUT_SECONDS", 0.25)
            assert (await client.get("/ready")).status_code == 200

    anyio.run(exercise)


def _client(*, decision, live=True, exchange_fn=None):
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD,
        exchange_fn=exchange_fn or (lambda *a: "DELEGATED.JWT"),
        authority_fn=lambda agent, run_id, aud, method=None, tool=None: decision,
        liveness_fn=lambda run_id: live)
    return TestClient(app)


# -- construction: exchange is mandatory --------------------------------------

def test_build_app_refuses_to_start_without_an_exchange_coordinator():
    """A managed call must never proceed without a platform credential, so a
    decision service that could allow one is refused at construction."""
    with pytest.raises(ValueError, match="exchange coordinator"):
        extauthz.build_app(run_agent="scout", run_id="r1", audience=AUD,
                           exchange_fn=None)


# -- fail-closed denials -------------------------------------------------------

def test_a_terminated_run_is_denied_even_when_authority_would_allow():
    """Liveness: a run that has ended is refused before any authority/exchange,
    so a still-unexpired token cannot be spent past the run's life."""
    c = _client(decision={"actions": None, "pin": None, "audience": AUD},
                live=False)
    r = c.post("/authz")
    assert r.status_code == 403 and "not active" in r.text


def test_a_refused_audience_is_denied():
    c = _client(decision={"actions": None, "pin": None, "audience": None})
    assert c.post("/authz").status_code == 403


def test_an_empty_action_set_is_denied():
    c = _client(decision={"actions": [], "pin": None, "audience": AUD})
    assert c.post("/authz").status_code == 403


def test_authority_failure_is_denied_not_allowed():
    def _boom(agent, run_id, aud, method=None, tool=None): raise KeyError("unknown agent")
    app = extauthz.build_app(run_agent="scout", run_id="r1", audience=AUD,
                             exchange_fn=lambda *a: "T", authority_fn=_boom,
                             liveness_fn=lambda r: True)
    assert TestClient(app).post("/authz").status_code == 403


def test_liveness_failure_is_denied():
    def _boom(run_id): raise RuntimeError("db down")
    app = extauthz.build_app(run_agent="scout", run_id="r1", audience=AUD,
                             exchange_fn=lambda *a: "T",
                             authority_fn=lambda a, r, aud, m=None, t=None: {"audience": AUD},
                             liveness_fn=_boom)
    assert TestClient(app).post("/authz").status_code == 403


# -- allow + injection ---------------------------------------------------------

def test_a_permitted_call_is_allowed_and_injects_the_delegated_token():
    seen = {}
    def _exchange(agent, run_id, scope, pin, aud):
        seen.update(agent=agent, run_id=run_id, aud=aud)
        return "DELEGATED.JWT"
    c = _client(decision={"actions": ["files:read"], "pin": None, "audience": AUD},
                exchange_fn=_exchange)
    r = c.post("/authz")
    assert r.status_code == 200
    assert r.headers["authorization"] == "Bearer DELEGATED.JWT"
    # identity is PROVISIONED, not taken from a request header
    assert seen == {"agent": "scout", "run_id": "r1", "aud": AUD}


def test_allowed_but_unmintable_is_withheld_not_passed():
    def _exchange(*a): raise RuntimeError("AS down")
    c = _client(decision={"actions": None, "pin": None, "audience": AUD},
                exchange_fn=_exchange)
    assert c.post("/authz").status_code == 403


def test_post_and_subpaths_are_authorized_the_same_way():
    """Envoy replays the ORIGINAL method (MCP calls are POST) and appends the
    request path after the ext_authz path_prefix (so the service sees
    /authz/mcp). Both must reach the decision -- otherwise real tool traffic
    405s or 404s while every other test stays green."""
    c = _client(decision={"actions": None, "pin": None, "audience": AUD})
    r = c.post("/authz/mcp")
    assert r.status_code == 200 and r.headers["authorization"] == "Bearer DELEGATED.JWT"
    d = _client(decision={"actions": [], "pin": None, "audience": AUD})
    assert d.post("/authz/mcp/tools/call").status_code == 403


def test_delete_is_admitted_like_the_other_mcp_methods():
    """MCP streamable-HTTP uses DELETE to end a session; Envoy admits it, so the
    decision service must too (or Envoy would 405 a DELETE before the tool)."""
    c = _client(decision={"actions": None, "pin": None, "audience": AUD})
    assert c.request("DELETE", "/authz").status_code == 200


def test_parse_mcp_extracts_method_and_tool():
    assert extauthz.parse_mcp(b'{"method":"tools/call","params":{"name":"read"}}') == ("tools/call", "read")
    assert extauthz.parse_mcp(b'{"method":"tools/list"}') == ("tools/list", None)
    assert extauthz.parse_mcp(b'not json') == (None, None)
    assert extauthz.parse_mcp(b'{}') == (None, None)


def test_the_decision_receives_the_mcp_method_and_tool():
    """MCP-aware: the parsed method + tool reach the authority decision, so a
    per-tool policy can allow read_calendar but deny delete_calendar even on the
    same permitted server (audience)."""
    seen = {}
    def _auth(agent, run_id, aud, method, tool):
        seen.update(method=method, tool=tool)
        return {"audience": aud} if tool == "read" else {"audience": None}
    app = extauthz.build_app(run_agent="scout", run_id="r1", audience=AUD,
                             exchange_fn=lambda *a: "T", authority_fn=_auth,
                             liveness_fn=lambda r: True)
    c = TestClient(app)
    ok = c.post("/authz/mcp", content=b'{"method":"tools/call","params":{"name":"read"}}')
    assert ok.status_code == 200 and seen == {"method": "tools/call", "tool": "read"}
    no = c.post("/authz/mcp", content=b'{"method":"tools/call","params":{"name":"delete"}}')
    assert no.status_code == 403


def test_is_allowed_matches_the_mints_reading():
    assert extauthz.is_allowed({"audience": AUD, "actions": None})
    assert extauthz.is_allowed({"audience": AUD, "actions": ["x"]})
    assert not extauthz.is_allowed({"audience": None, "actions": ["x"]})
    assert not extauthz.is_allowed({"audience": AUD, "actions": []})


# -- per-tool authority from registry grants (mcp_tools) -----------------------

from andyur.registry import McpToolGrant

GRANTS = (McpToolGrant("read_calendar", "calendar:read"),
          McpToolGrant("delete_calendar", "calendar:delete"))


def _tool_client(*, decision, mcp_tools=GRANTS, live=True):
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD,
        exchange_fn=lambda *a: "DELEGATED.JWT",
        authority_fn=lambda agent, run_id, aud, method=None, tool=None: decision,
        liveness_fn=lambda run_id: live,
        mcp_tools=mcp_tools)
    return TestClient(app)


def _call(c, tool):
    return c.post("/authz/mcp", content=(
        '{"method":"tools/call","params":{"name":"%s"}}' % tool).encode())


def test_permitted_tools_is_the_single_per_tool_decision():
    grants = {"read_calendar": "calendar:read",
              "delete_calendar": "calendar:delete"}
    # not enumerated: nothing declared to decide against
    assert extauthz.permitted_tools({"actions": ["x"]}, None) is None
    # unrestricted actions: every ENUMERATED grant, never anything else
    assert extauthz.permitted_tools({"actions": None}, grants) == \
        ["read_calendar", "delete_calendar"]
    # the ordinary case: only grants whose required action is present
    assert extauthz.permitted_tools({"actions": ["calendar:read"]}, grants) == \
        ["read_calendar"]
    assert extauthz.permitted_tools({"actions": []}, grants) == []


def test_tools_call_is_gated_on_the_named_tools_registry_grant():
    """The run's actions include calendar:read only: the granted tool passes,
    the enumerated-but-ungranted one and an unknown one are refused."""
    c = _tool_client(decision={"actions": ["calendar:read"], "pin": None,
                               "audience": AUD})
    assert _call(c, "read_calendar").status_code == 200
    r = _call(c, "delete_calendar")
    assert r.status_code == 403 and "not granted" in r.text
    assert _call(c, "shell_exec").status_code == 403
    # a tools/call that names no tool cannot be checked -> refused
    r = c.post("/authz/mcp", content=b'{"method":"tools/call","params":{}}')
    assert r.status_code == 403


def test_unenumerated_binding_keeps_the_audience_level_posture():
    """mcp_tools=None is the pre-existing contract: the audience decision
    stands alone and no per-tool refusal is invented."""
    c = _tool_client(decision={"actions": ["calendar:read"], "pin": None,
                               "audience": AUD}, mcp_tools=None)
    assert _call(c, "anything_at_all").status_code == 200


def test_enumeration_closes_the_mcp_method_vocabulary():
    """An mcp_tools grant is a statement 'this server is used for THESE tools';
    resources/* must not ride the same delegated credential through a side
    door. Without enumeration the vocabulary stays open (back-compat)."""
    d = {"actions": None, "pin": None, "audience": AUD}
    closed = _tool_client(decision=d)
    r = closed.post("/authz/mcp", content=b'{"method":"resources/read"}')
    assert r.status_code == 403 and "outside the tool-enumerated" in r.text
    for m in ("initialize", "ping", "tools/list", "notifications/initialized"):
        ok = closed.post("/authz/mcp",
                         content=('{"method":"%s"}' % m).encode())
        assert ok.status_code == 200, m
    open_ = _tool_client(decision=d, mcp_tools=None)
    assert open_.post("/authz/mcp",
                      content=b'{"method":"resources/read"}').status_code == 200


def test_allow_response_tags_the_authorized_method_for_the_response_filter():
    """x-andyur-mcp comes from the DECISION SERVICE's response (Envoy turns it
    into dynamic metadata); accept-encoding: identity rides only tools/list so
    the rewrite reads an uncompressed body."""
    c = _tool_client(decision={"actions": None, "pin": None, "audience": AUD})
    r = c.post("/authz/mcp", content=b'{"method":"tools/list"}')
    assert r.headers["x-andyur-mcp"] == "tools/list"
    assert r.headers["accept-encoding"] == "identity"
    r2 = _call(c, "read_calendar")
    assert r2.headers["x-andyur-mcp"] == "tools/call"
    assert "accept-encoding" not in r2.headers
    # the body-less transport leg carries no method and no tag
    r3 = c.request("GET", "/authz/mcp")
    assert r3.status_code == 200 and "x-andyur-mcp" not in r3.headers


# -- the tools/list rewrite ----------------------------------------------------

LIST_JSON = ('{"jsonrpc":"2.0","id":1,"result":{"tools":['
             '{"name":"read_calendar","description":"r"},'
             '{"name":"delete_calendar","description":"d"}]}}').encode()


def test_filter_tools_payload_filters_the_json_shape():
    out = extauthz.filter_tools_payload(LIST_JSON, {"read_calendar"})
    assert b"read_calendar" in out and b"delete_calendar" not in out
    import json
    assert json.loads(out)["result"]["tools"] == [
        {"name": "read_calendar", "description": "r"}]


def test_filter_tools_payload_filters_the_sse_shape_and_keeps_framing():
    sse = b"event: message\ndata: " + LIST_JSON + b"\n\n"
    out = extauthz.filter_tools_payload(sse, {"read_calendar"})
    assert out.startswith(b"event: message\ndata: ")
    assert b"delete_calendar" not in out and b"read_calendar" in out


def test_filter_tools_payload_drops_unnamed_entries_and_passes_non_lists():
    """An entry without a readable name cannot be checked -> dropped (narrow).
    A message that names no tools (an error) passes through unchanged."""
    body = (b'{"jsonrpc":"2.0","id":1,"result":{"tools":['
            b'{"description":"anonymous"},{"name":"read_calendar"}]}}')
    out = extauthz.filter_tools_payload(body, {"read_calendar"})
    assert b"anonymous" not in out and b"read_calendar" in out
    err = b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}'
    import json
    assert json.loads(extauthz.filter_tools_payload(err, set())) == \
        json.loads(err)


def test_filter_tools_payload_refuses_what_it_cannot_read():
    for garbage in (b"\x1f\x8b\x08gzip-ish\xff", b"", b"event: message\n\n",
                    b"data: {not json}\n\n"):
        with pytest.raises(ValueError):
            extauthz.filter_tools_payload(garbage, set())


def test_toolfilter_endpoint_rewrites_with_the_same_decision():
    c = _tool_client(decision={"actions": ["calendar:read"], "pin": None,
                               "audience": AUD})
    r = c.post("/toolfilter", content=LIST_JSON)
    assert r.status_code == 200
    assert b"read_calendar" in r.content and b"delete_calendar" not in r.content


def test_toolfilter_endpoint_empties_the_list_when_authority_is_gone():
    """The rewrite recomputes the decision: a run whose authority has been
    emptied since the request was authorized gets an empty menu."""
    c = _tool_client(decision={"actions": [], "pin": None, "audience": None})
    r = c.post("/toolfilter", content=LIST_JSON)
    assert r.status_code == 200
    import json
    assert json.loads(r.content)["result"]["tools"] == []


def test_toolfilter_endpoint_passes_bytes_untouched_when_unenumerated():
    c = _tool_client(decision={"actions": None, "pin": None, "audience": AUD},
                     mcp_tools=None)
    r = c.post("/toolfilter", content=b"opaque \xff bytes")
    assert r.status_code == 200 and r.content == b"opaque \xff bytes"


def test_toolfilter_endpoint_fails_closed_on_an_unreadable_body():
    """An unverifiable list must never reach the agent: /toolfilter returns 200
    with a fail-closed JSON-RPC error, never the raw bytes."""
    import json
    c = _tool_client(decision={"actions": None, "pin": None, "audience": AUD})
    r = c.post("/toolfilter", content=b"\x1f\x8b\x08compressed")
    assert r.status_code == 200
    assert r.content != b"\x1f\x8b\x08compressed"
    assert json.loads(r.content)["error"]["code"] == -32000


def test_toolfilter_failclosed_carries_the_request_id_and_sse_framing():
    """JSON-RPC 2.0 sec 5: the error id must equal the request id when known;
    and on an SSE upstream the error must be SSE-framed or the client never
    sees it. The body here is readable enough to recover the id but the
    decision fails, forcing the error path."""
    import json
    def _boom(*a, **k): raise RuntimeError("decision down")
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD,
        exchange_fn=lambda *a, **k: "T", authority_fn=_boom,
        liveness_fn=lambda r: True, mcp_tools=GRANTS)
    c = TestClient(app)
    body = b'{"jsonrpc":"2.0","id":42,"result":{"tools":[{"name":"read_calendar"}]}}'
    # JSON upstream: bare JSON error carrying id 42
    r = c.post("/toolfilter", content=body)
    assert r.status_code == 200 and json.loads(r.content)["id"] == 42
    # SSE upstream: same error, SSE-framed
    r2 = c.post("/toolfilter", content=body,
                headers={"x-andyur-upstream-ct": "text/event-stream"})
    assert r2.content.startswith(b"event: message\ndata: ")
    assert r2.content.endswith(b"\n\n")
    assert json.loads(r2.content.split(b"data: ", 1)[1]) ["id"] == 42


def test_toolfilter_fails_closed_on_an_oversized_body():
    import json
    c = _tool_client(decision={"actions": None, "pin": None, "audience": AUD})
    big = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}' + \
        b" " * (extauthz.MAX_TOOLS_LIST_BYTES + 1)
    r = c.post("/toolfilter", content=big)
    assert r.status_code == 200
    assert json.loads(r.content)["error"]["code"] == -32000


# -- F-02 cnf sender binding at the exchange seam ------------------------------

def test_cnf_fn_makes_every_exchange_request_sender_bound():
    """With cnf_fn set, the thumbprint of the run cert is passed to the exchange
    as the requested binding on every mint. The coordinator REQUESTS the binding
    but does not decode the returned token (that is the resource's job, and an
    A/B seam per ADR-006); it just injects what the AS issued."""
    seen = {}
    def _exchange(agent, run_id, scope, pin, aud, cnf=None):
        seen["cnf"] = cnf
        return "ISSUED.JWT"
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD, exchange_fn=_exchange,
        authority_fn=lambda a, r, aud, m=None, t=None: {"actions": None,
                                                        "pin": None, "audience": aud},
        liveness_fn=lambda r: True, cnf_fn=lambda: "THUMB123")
    r = TestClient(app).post("/authz/mcp", content=b'{"method":"ping"}')
    assert r.status_code == 200 and seen["cnf"] == "THUMB123"
    assert r.headers["authorization"] == "Bearer ISSUED.JWT"


def test_require_mcp_tools_refuses_an_unenumerated_production_binding():
    """Production sibling of require_identity: a managed MCP binding must declare
    mcp_tools ([] to permit none); None (audience-level) is refused."""
    with pytest.raises(ValueError, match="must declare mcp_tools"):
        extauthz.build_app(run_agent="scout", run_id="r1", audience=AUD,
                           exchange_fn=lambda *a, **k: "T",
                           require_mcp_tools=True, mcp_tools=None)
    # explicit [] is accepted (permits no tool)
    extauthz.build_app(run_agent="scout", run_id="r1", audience=AUD,
                       exchange_fn=lambda *a, **k: "T",
                       require_mcp_tools=True, mcp_tools=())


def test_toolfilter_rechecks_liveness_at_response_time():
    """A run that terminated while a slow tools/list was in flight must get the
    fail-closed error, not its menu -- symmetric with /authz's liveness gate."""
    import json
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD,
        exchange_fn=lambda *a, **k: "T",
        authority_fn=lambda a, r, aud, m=None, t=None: {"actions": None,
                                                        "pin": None, "audience": aud},
        liveness_fn=lambda r: False, mcp_tools=GRANTS)
    r = TestClient(app).post("/toolfilter", content=LIST_JSON)
    assert r.status_code == 200
    assert json.loads(r.content)["error"]["code"] == -32000


def test_an_unreadable_cnf_thumbprint_withholds_the_token():
    """Binding configured but the run cert thumbprint cannot be read: an unbound
    token must never be minted as a fallback (F-02)."""
    def _exchange(*a, cnf=None): return "SHOULD.NOT.MINT"
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD, exchange_fn=_exchange,
        authority_fn=lambda a, r, aud, m=None, t=None: {"actions": None,
                                                        "pin": None, "audience": aud},
        liveness_fn=lambda r: True, cnf_fn=lambda: None)
    r = TestClient(app).post("/authz/mcp", content=b'{"method":"ping"}')
    assert r.status_code == 403 and "bind the delegated token" in r.text


def test_without_cnf_fn_the_exchange_is_called_bearer_style():
    """Back-compat: no binding configured -> the exchange keeps its 5-arg
    signature, no cnf kwarg forced."""
    def _exchange(agent, run_id, scope, pin, aud):  # no cnf param
        return "BEARER.JWT"
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD, exchange_fn=_exchange,
        authority_fn=lambda a, r, aud, m=None, t=None: {"actions": None,
                                                        "pin": None, "audience": aud},
        liveness_fn=lambda r: True)
    r = TestClient(app).post("/authz/mcp", content=b'{"method":"ping"}')
    assert r.status_code == 200 and r.headers["authorization"] == "Bearer BEARER.JWT"


# -- round-2: batch/garbage request shapes fail closed (review-confirmed) -------

def test_mcp_body_kind_classifies_shapes():
    assert extauthz.mcp_body_kind(b"") == "empty"
    assert extauthz.mcp_body_kind(b"   ") == "empty"
    assert extauthz.mcp_body_kind(b'{"method":"ping"}') == "object"
    assert extauthz.mcp_body_kind(b'[{"method":"tools/call"}]') == "array"
    assert extauthz.mcp_body_kind(b'123') == "invalid"
    assert extauthz.mcp_body_kind(b'not json') == "invalid"


def test_a_batched_tools_call_cannot_bypass_the_per_tool_gate():
    """A JSON-RPC batch (top-level array) parses to method=None; it must NOT be
    treated as the body-less transport leg, or a batched forbidden tools/call
    would skip the per-tool check and still be minted a token."""
    c = _tool_client(decision={"actions": ["calendar:read"], "pin": None,
                               "audience": AUD})
    batch = b'[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_calendar"}}]'
    assert c.post("/authz/mcp", content=batch).status_code == 403
    # a batched RESERVED method is refused too
    assert c.post("/authz/mcp",
                  content=b'[{"method":"resources/read"}]').status_code == 403
    # garbage / scalar bodies are refused
    assert c.post("/authz/mcp", content=b'\x1f\x8b\x08gz').status_code == 403
    assert c.post("/authz/mcp", content=b'123').status_code == 403


def test_a_method_less_single_object_still_passes_an_enumerated_binding():
    """A single JSON-RPC RESPONSE (result/id, no method) invokes no tool and is
    legitimate client->server traffic; it must not be swept up by the batch
    fail-closed."""
    c = _tool_client(decision={"actions": None, "pin": None, "audience": AUD})
    assert c.post("/authz/mcp",
                  content=b'{"jsonrpc":"2.0","id":1,"result":{}}').status_code == 200


def test_permitted_tools_matches_on_the_base_action_not_the_qualifier():
    """A granted action carrying an @resource qualifier still satisfies a tool
    grant that requires the base action -- consistent with the manifest ceiling
    cross-check; the resource narrowing is the PEP's pin check, not this one."""
    grants = {"write_file": "files:write"}
    assert extauthz.permitted_tools(
        {"actions": ["files:write@account=447"]}, grants) == ["write_file"]


# -- round-2: the toolfilter genuinely RE-decides at response time -------------

def test_toolfilter_recomputes_the_decision_each_call():
    """A run whose authority is emptied AFTER the request was authorized must
    get an empty menu on the response-time rewrite -- proving the decision is
    recomputed, not cached from build_app."""
    import json
    calls = {"n": 0}
    def _auth(agent, run_id, aud, method=None, tool=None):
        calls["n"] += 1
        # full grant on the first decision (the tools/list request), emptied on
        # the SECOND (the response-time /toolfilter recompute).
        first = calls["n"] == 1
        return {"actions": None if first else [],
                "pin": None, "audience": aud if first else None}
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD,
        exchange_fn=lambda *a, **k: "T", authority_fn=_auth,
        liveness_fn=lambda r: True, mcp_tools=GRANTS)
    c = TestClient(app)
    # request-time decision (full) authorizes the tools/list
    assert c.post("/authz/mcp", content=b'{"method":"tools/list"}').status_code == 200
    # response-time decision (emptied) must yield an empty menu
    r = c.post("/toolfilter", content=LIST_JSON)
    assert json.loads(r.content)["result"]["tools"] == []
    assert calls["n"] == 2


# -- round-2: SSE multi-line data accumulation (WHATWG SSE) --------------------

def test_filter_tools_payload_accumulates_multiline_sse_data():
    """One event's payload may span consecutive data: lines (joined by newline);
    the rewrite must reassemble before parsing, not refuse."""
    sse = (b"event: message\n"
           b'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[\n'
           b'data: {"name":"read_calendar"},{"name":"delete_calendar"}]}}\n\n')
    out = extauthz.filter_tools_payload(sse, {"read_calendar"})
    assert b"read_calendar" in out and b"delete_calendar" not in out
    assert out.endswith(b"\n\n")


def test_filter_tools_payload_sse_preserves_full_framing():
    sse = b"event: message\ndata: " + LIST_JSON + b"\n\n"
    out = extauthz.filter_tools_payload(sse, {"read_calendar"})
    assert out.startswith(b"event: message\ndata: ") and out.endswith(b"\n\n")


# -- round-2: withholding actually withholds (no token minted) -----------------

def test_unreadable_cnf_thumbprint_mints_nothing_and_leaks_no_header():
    called = {"exchange": False}
    def _exchange(*a, **k):
        called["exchange"] = True
        return "SHOULD.NOT.MINT"
    app = extauthz.build_app(
        run_agent="scout", run_id="r1", audience=AUD, exchange_fn=_exchange,
        authority_fn=lambda a, r, aud, m=None, t=None: {"actions": None,
                                                        "pin": None, "audience": aud},
        liveness_fn=lambda r: True, cnf_fn=lambda: None)
    r = TestClient(app).post("/authz/mcp", content=b'{"method":"ping"}')
    assert r.status_code == 403
    assert called["exchange"] is False
    assert "authorization" not in r.headers

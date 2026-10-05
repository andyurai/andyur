"""Phase 2: the sidecar mints a delegated token and forwards to the tool.

The load-bearing properties, each asserted against the request that actually
leaves the sidecar (via a mock tool transport), because a proxy that looks right
and forwards the wrong credential is the failure that matters:

  * the exchange asks for the manifest's resource_id as the audience, the run's
    SVID as actor, the user's T0 as subject;
  * the tool receives the MINTED token, never the agent's Authorization;
  * the agent's forged x-andyur-* headers never reach the tool;
  * a failed exchange withholds the call (fail closed), it does not forward bare.
"""

import httpx
import jwt
import pytest
from starlette.testclient import TestClient

from andyur import otel
from andyur.proxy import app as proxy_app
from andyur.proxy import sidecar as sc
from andyur.proxy.dpop import ClosedDPoPHolder, RunDPoPHolder
from andyur.resource_dpop import _thumbprint, access_token_hash


def _identity():
    return sc.RunIdentity(
        subject_token="T0.dana",
        expected_subject="dana",
        actor_token=lambda: "SVID.run",
        mtls_material=lambda: {"cert": "/c", "key": "/k", "bundle": "/b"},
    )


def _router():
    return sc.Router({
        "obs": sc.ToolRoute.from_managed("obs", {
            "url": "http://127.0.0.1:8797/mcp", "audience": "resource:telemetry",
            "scheme": "http", "host": "127.0.0.1", "port": 8797, "path": "/mcp"}),
    })


def _brokered_router():
    return sc.Router({
        "warehouse": sc.ToolRoute.from_managed("warehouse", {
            "url": "https://warehouse.example/mcp",
            "audience": "resource:warehouse", "scheme": "https",
            "host": "warehouse.example", "port": 443, "path": "/mcp",
            "credential_mode": "brokered", "credential_ref": "warehouse-key",
            "credential_headers": ["X-API-Key"]}),
    })


def _chunks(*parts: bytes):
    """An ASYNC streaming response body (AsyncClient requires an AsyncByteStream):
    yielding more than one part lets a test prove the sidecar relays chunks as
    they arrive, not a single buffered blob."""
    async def gen():
        for p in parts:
            yield p
    return gen()


def _mock_tool():
    """A mock upstream tool that records what the sidecar forwarded, and returns
    a STREAMING body (so the sidecar's streaming path is what is exercised)."""
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["headers"] = dict(request.headers)
        seen["body"] = request.content
        return httpx.Response(200, content=_chunks(b'{"ok":', b' true}'),
                              headers={"x-tool": "yes",
                                       "content-type": "application/json"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client, seen


def _build(exchange_fn, tool_client, *, trusted_traceparent=None):
    return proxy_app.build_app(
        router=_router(), identity=_identity(),
        scope=["telemetry:read"],
        pin='[{"type":"andyur_pin","identifier":"checkout"}]',
        gateway_url="http://gw:9000",
        trusted_traceparent=trusted_traceparent,
        exchange_fn=exchange_fn,
        tool_client_factory=lambda: tool_client,
    )


# --- pure: the exchange request the sidecar would make ------------------------

def test_exchange_request_uses_resource_id_as_audience():
    route = list(_router()._tools.values())[0]
    req = sc.exchange_request(_identity(), route, ["telemetry:read"], "PIN")
    assert req["resource"] == "resource:telemetry"
    assert req["audience"] == "resource:telemetry"
    assert req["resource"] != route.reach_url         # not the url
    assert req["actor_token"] == "SVID.run"
    assert req["subject_token"] == "T0.dana"
    assert req["expected_subject"] == "dana"
    assert req["scope"] == ["telemetry:read"]
    assert req["authorization_details"] == "PIN"


# --- the token cache ----------------------------------------------------------

def test_cache_returns_the_same_token_within_ttl_and_re_mints_after():
    calls = {"n": 0}
    def exchange(**kw):
        calls["n"] += 1
        return {"access_token": f"tok-{calls['n']}", "expires_in": 300}
    route = list(_router()._tools.values())[0]
    cache = sc.TokenCache()
    t1 = sc.delegated_token(_identity(), route, ["telemetry:read"], "PIN", exchange, cache)
    t2 = sc.delegated_token(_identity(), route, ["telemetry:read"], "PIN", exchange, cache)
    assert t1 == t2 == "tok-1"
    assert calls["n"] == 1, "second call should hit the cache, not re-exchange"


def test_cache_separates_by_audience_and_pin():
    seen = []
    def exchange(**kw):
        seen.append((kw["audience"], kw["authorization_details"]))
        return {"access_token": "t", "expires_in": 300}
    r = list(_router()._tools.values())[0]
    cache = sc.TokenCache()
    sc.delegated_token(_identity(), r, ["s"], "PIN-A", exchange, cache)
    sc.delegated_token(_identity(), r, ["s"], "PIN-B", exchange, cache)
    assert len(seen) == 2, "a different pin is a different token"


def test_cache_never_extends_a_short_signed_lifetime(monkeypatch):
    monkeypatch.setattr(sc.time, "monotonic", lambda: 100.0)
    cache = sc.TokenCache(floor=30.0, skew=0.0)
    key = ("resource:telemetry", ("s",), "")
    cache.put(key, "short", 5)
    assert cache._entries[key] == ("short", 105.0)


# --- the full listener flow ---------------------------------------------------

def test_tool_call_forwards_the_minted_token_not_the_agents(monkeypatch):
    got = {}
    def exchange(**kw):
        got.update(kw)
        return {"access_token": "MINTED-checkout", "expires_in": 300}
    tool_client, seen = _mock_tool()
    app = _build(exchange, tool_client)
    r = TestClient(app).post(
        "/tools/obs/mcp",
        content=b'{"jsonrpc":"2.0","method":"initialize"}',
        headers={"Authorization": "Bearer AGENT-TOKEN",
                 "X-Andyur-Actor-Token": "forged-by-agent",
                 "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json() == {"ok": True}
    # forwarded to the tool's real address, path preserved
    assert seen["url"] == "http://127.0.0.1:8797/mcp"
    # the tool gets the MINTED token
    assert seen["headers"]["authorization"] == "Bearer MINTED-checkout"
    # the agent's own token and forged identity header are GONE
    assert "AGENT-TOKEN" not in seen["headers"].get("authorization", "")
    assert "x-andyur-actor-token" not in seen["headers"]
    # the body is forwarded intact
    assert b"initialize" in seen["body"]
    # the exchange asked for the resource_id audience, run actor, user subject
    assert got["audience"] == "resource:telemetry"
    assert got["actor_token"] == "SVID.run" and got["subject_token"] == "T0.dana"
    assert got["expected_subject"] == "dana"


def test_tool_call_replaces_agent_trace_with_a_sidecar_child_of_the_run(monkeypatch):
    monkeypatch.setattr(otel, "OTEL_ON", True)
    trusted = "00-11111111111111111111111111111111-2222222222222222-01"
    forged = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
    tool_client, seen = _mock_tool()
    app = _build(
        lambda **kw: {"access_token": "MINTED", "expires_in": 300},
        tool_client, trusted_traceparent=trusted)
    response = TestClient(app).post(
        "/tools/obs/mcp", content=b"{}",
        headers={"traceparent": forged, "tracestate": "attacker=x",
                 "baggage": "customer-secret=value"})
    assert response.status_code == 200
    outbound = seen["headers"]["traceparent"]
    assert outbound.split("-")[1] == trusted.split("-")[1]
    assert outbound != trusted, "the sidecar must create its own CLIENT span"
    assert outbound != forged
    assert "tracestate" not in seen["headers"]
    assert "baggage" not in seen["headers"]


def test_a_failed_exchange_withholds_the_call(monkeypatch):
    """Fail closed: if the AS refuses, the tool is never called, and the sidecar
    returns 502 rather than forwarding without a token."""
    def exchange(**kw):
        raise RuntimeError("AS said no")
    tool_client, seen = _mock_tool()
    app = _build(exchange, tool_client)
    r = TestClient(app).post("/tools/obs/mcp", content=b"{}",
                             headers={"Content-Type": "application/json"})
    assert r.status_code == 502
    assert seen == {}, "the tool was called despite no token"


def test_the_tool_client_is_pooled_not_built_per_request():
    """The client (and, in production, its mTLS handshake) is built ONCE and
    reused for the sidecar's lifetime, not per request."""
    made = {"n": 0}
    tool_client, _ = _mock_tool()
    def factory():
        made["n"] += 1
        return tool_client
    app = proxy_app.build_app(
        router=_router(), identity=_identity(), scope=["s"], pin=None,
        gateway_url="http://gw:9000",
        exchange_fn=lambda **k: {"access_token": "t", "expires_in": 300},
        tool_client_factory=factory)
    c = TestClient(app)
    for _ in range(3):
        c.post("/tools/obs/mcp", content=b"{}",
               headers={"Content-Type": "application/json"})
    assert made["n"] == 1, "the client must be pooled, not rebuilt per request"


def test_the_pools_close_on_sidecar_teardown():
    """Both pools are closed on teardown -- the tool client holds the run's
    X509-SVID, so its close ends the run's ability to present the credential."""
    closed = {"tool": False, "gw": False}

    class _Closable:
        def __init__(self, which):
            self._which = which
        async def aclose(self):
            closed[self._which] = True

    app = proxy_app.build_app(
        router=_router(), identity=_identity(), scope=[], pin=None,
        gateway_url="http://gw:9000", llm_master_key="k",
        exchange_fn=lambda **k: {"access_token": "t"},
        tool_client_factory=lambda: _Closable("tool"),
        gateway_client_factory=lambda: _Closable("gw"))
    with TestClient(app):          # enter/exit runs the lifespan (startup+shutdown)
        pass
    assert closed == {"tool": True, "gw": True}


def test_dpop_managed_call_binds_exchange_and_live_resource_request():
    holder = RunDPoPHolder()
    cache = sc.TokenCache()
    got = {}

    def exchange(**kwargs):
        got.update(kwargs)
        return {"access_token": "CURITY-TOKEN", "expires_in": 120}

    tool_client, seen = _mock_tool()
    app = proxy_app.build_app(
        router=_router(), identity=_identity(), scope=["telemetry:read"], pin=None,
        gateway_url="", exchange_fn=exchange,
        tool_client_factory=lambda: tool_client, dpop_holder=holder, cache=cache)
    with TestClient(app) as client:
        response = client.post("/tools/obs/mcp", content=b"{}")
        assert response.status_code == 200
        assert seen["headers"]["authorization"] == "DPoP CURITY-TOKEN"
        proof = seen["headers"]["dpop"]
        header = jwt.get_unverified_header(proof)
        claims = jwt.decode(proof, jwt.PyJWK.from_dict(header["jwk"]).key,
                            algorithms=["ES256"], options={"verify_aud": False})
        assert claims["htm"] == "POST"
        assert claims["htu"] == "http://127.0.0.1:8797/mcp"
        public_jwk = {name: header["jwk"][name]
                      for name in ("kty", "crv", "x", "y")}
        assert _thumbprint(public_jwk) == holder.jkt
        assert claims["ath"] == access_token_hash("CURITY-TOKEN")
        assert got["dpop_key"].dpop_jkt == holder.jkt
    assert holder.closed is True
    assert cache.closed is True
    with pytest.raises(ClosedDPoPHolder):
        holder.resource_proof("POST", "https://tool", "token")


def test_dpop_exchange_failure_never_falls_back_to_bearer():
    holder = RunDPoPHolder()
    tool_client, seen = _mock_tool()
    app = proxy_app.build_app(
        router=_router(), identity=_identity(), scope=[], pin=None,
        gateway_url="", dpop_holder=holder,
        exchange_fn=lambda **_: (_ for _ in ()).throw(RuntimeError("refused")),
        tool_client_factory=lambda: tool_client)
    with TestClient(app) as client:
        assert client.post("/tools/obs/mcp", content=b"{}").status_code == 502
    assert seen == {}
    assert holder.closed is True


def test_dpop_holder_does_not_change_brokered_credential_transport():
    holder = RunDPoPHolder()
    tool_client, seen = _mock_tool()
    app = proxy_app.build_app(
        router=_brokered_router(), identity=_identity(), scope=[], pin=None,
        gateway_url="", dpop_holder=holder,
        brokered_credential_fn=lambda _: {"X-API-Key": "sealed-secret"},
        tool_client_factory=lambda: tool_client)
    with TestClient(app) as client:
        response = client.post("/tools/warehouse/mcp", content=b"{}")
        assert response.status_code == 200
        assert seen["headers"]["x-api-key"] == "sealed-secret"
        assert "authorization" not in seen["headers"]
        assert "dpop" not in seen["headers"]
    assert holder.closed is True


def test_an_unknown_tool_is_404_and_never_forwarded():
    tool_client, seen = _mock_tool()
    app = _build(lambda **k: {"access_token": "x"}, tool_client)
    r = TestClient(app).post("/tools/ghost/mcp", content=b"{}")
    assert r.status_code == 404
    assert seen == {}


def _dummy_tool_client():
    """A tool client the /llm tests never call -- so eager build does not try to
    load the fake mTLS cert paths in _identity()."""
    return httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(500)))


def _llm_app(gw_client, **kw):
    return proxy_app.build_app(
        router=_router(), identity=_identity(), scope=[], pin=None,
        gateway_url="http://gw:9000",
        llm_master_key="LITELLM-MASTER",
        enforced_model="claude-haiku-4-5",
        exchange_fn=lambda **k: {"access_token": "x"},
        tool_client_factory=_dummy_tool_client,
        gateway_client_factory=lambda: gw_client,
        **kw)


def test_the_llm_path_forwards_the_validated_object_and_refuses_a_case_variant_model_key():
    """One policy with the exec/v1 front (R HIGH): the gateway receives the
    VALIDATED, re-serialised object, never the raw bytes, and a case-variant
    duplicate key that a Go decoder would take as the model is refused here."""
    gw_seen = {}

    def gw_handler(request: httpx.Request) -> httpx.Response:
        gw_seen["body"] = request.content
        return httpx.Response(200, content=_chunks(b'{"llm":', b' "ok"}'),
                              headers={"content-type": "application/json"})

    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))
    client = TestClient(_llm_app(gw_client))
    r = client.post("/llm/v1/messages",
                    content=b'{ "model" : "claude-haiku-4-5" , "messages": [] }',
                    headers={"content-type": "application/json"})
    assert r.status_code == 200
    assert gw_seen["body"] == b'{"model":"claude-haiku-4-5","messages":[]}'
    gw_seen.clear()
    r = client.post("/llm/v1/messages",
                    content=b'{"model": "claude-haiku-4-5", "MODEL": "claude-opus-4-8"}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 403 and gw_seen == {}


def test_the_llm_path_injects_the_master_key_never_t0_or_the_agents_key():
    """The shared LiteLLM gateway gets its SERVICE credential (the master key)
    the sidecar holds, as native-Anthropic x-api-key. The agent's own key is
    stripped, and the run's user token T0 is NOT forwarded as gateway authority."""
    gw_seen = {}
    def gw_handler(request: httpx.Request) -> httpx.Response:
        gw_seen["url"] = str(request.url)
        gw_seen["x_api_key"] = request.headers.get("x-api-key")
        gw_seen["auth"] = request.headers.get("authorization")
        gw_seen["body"] = request.content
        return httpx.Response(200, content=_chunks(b'{"llm":', b' "ok"}'),
                              headers={"content-type": "application/json"})
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))
    r = TestClient(_llm_app(gw_client)).post(
        "/llm/v1/messages",
        content=b'{"model":"claude-haiku-4-5","messages":[]}',
        headers={"x-api-key": "AGENT-KEY", "Authorization": "Bearer AGENT",
                 "Content-Type": "application/json"})
    assert r.status_code == 200
    assert gw_seen["url"] == "http://gw:9000/v1/messages"
    assert gw_seen["x_api_key"] == "LITELLM-MASTER"          # the sidecar's cred
    assert gw_seen["x_api_key"] != "AGENT-KEY"               # not the agent's
    assert gw_seen["auth"] != "Bearer T0.dana"               # T0 is not authority
    assert b"claude-haiku-4-5" in gw_seen["body"]            # body forwarded


def test_the_llm_path_refuses_an_alternate_model():
    """A run may call ONLY its manifest model; an alternate is refused before the
    gateway is reached (never silently rewritten)."""
    called = {"n": 0}
    def gw_handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json={"llm": "ok"})
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))
    r = TestClient(_llm_app(gw_client)).post(
        "/llm/v1/messages",
        content=b'{"model":"claude-opus-4-8","messages":[]}',
        headers={"Content-Type": "application/json"})
    assert r.status_code == 403
    assert called["n"] == 0, "the gateway was called for a disallowed model"


def test_the_llm_path_refuses_a_missing_model():
    called = {"n": 0}
    def gw_handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json={"llm": "ok"})
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(gw_handler))
    r = TestClient(_llm_app(gw_client)).post(
        "/llm/v1/messages", content=b'{"messages":[]}',
        headers={"Content-Type": "application/json"})
    assert r.status_code == 403
    assert called["n"] == 0


def test_llm_master_key_is_never_attached_to_admin_or_arbitrary_routes():
    called = []
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: called.append(request) or httpx.Response(200)))
    client = TestClient(_llm_app(gw_client))
    body = b'{"model":"claude-haiku-4-5"}'
    for method, path in (("post", "/llm/key/generate"),
                         ("post", "/llm/team/new"),
                         ("get", "/llm/v1/models"),
                         ("delete", "/llm/v1/messages")):
        assert client.request(method.upper(), path, content=body).status_code == 404
    assert called == []


def test_llm_request_strips_agent_trace_identity_before_gateway():
    seen = {}
    def handler(request):
        seen.update({k.lower(): v for k, v in request.headers.items()})
        return httpx.Response(200, content=_chunks(b'{"ok":true}'))
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response = TestClient(_llm_app(gw_client)).post(
        "/llm/v1/messages",
        content=b'{"model":"claude-haiku-4-5","messages":[]}',
        headers={"traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
                 "tracestate": "attacker=x", "baggage": "secret=value"})
    assert response.status_code == 200
    assert "traceparent" not in seen
    assert "tracestate" not in seen
    assert "baggage" not in seen


def test_llm_request_replaces_agent_trace_with_trusted_run_context():
    seen = {}
    trusted = "00-11111111111111111111111111111111-2222222222222222-01"
    forged = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
    def handler(request):
        seen.update({k.lower(): v for k, v in request.headers.items()})
        return httpx.Response(200, content=_chunks(b'{"ok":true}'))
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response = TestClient(_llm_app(
        gw_client, trusted_traceparent=trusted)).post(
            "/llm/v1/messages",
            content=b'{"model":"claude-haiku-4-5","messages":[]}',
            headers={"traceparent": forged, "baggage": "attacker=secret"})
    assert response.status_code == 200
    assert seen["traceparent"] == trusted
    assert seen["traceparent"] != forged
    assert "baggage" not in seen


def test_llm_oversized_body_is_refused_before_gateway(monkeypatch):
    monkeypatch.setattr(proxy_app, "_LLM_MAX_BODY", 32)
    called = []
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: called.append(request) or httpx.Response(200)))
    response = TestClient(_llm_app(gw_client)).post(
        "/llm/v1/messages", content=b"x" * 33)
    assert response.status_code == 413
    assert called == []


def test_llm_per_run_call_budget_is_enforced(monkeypatch):
    monkeypatch.setattr(proxy_app, "_LLM_MAX_CALLS", 1)
    calls = []
    gw_client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: calls.append(request) or
        httpx.Response(200, content=_chunks(b'{"ok":true}'))))
    client = TestClient(_llm_app(gw_client))
    body = b'{"model":"claude-haiku-4-5","messages":[]}'
    assert client.post("/llm/v1/messages", content=body).status_code == 200
    assert client.post("/llm/v1/messages", content=body).status_code == 429
    assert len(calls) == 1


def test_forwarding_is_confined_to_the_declared_path_and_mcp_methods():
    """The upstream URL is the route's DECLARED path: splicing the agent's
    remainder let a compromised agent present the run's delegated token and
    mTLS cert to any path on the tool's host, and misrouted every tool not
    served at exactly /mcp."""
    router = sc.Router({
        "deep": sc.ToolRoute.from_managed("deep", {
            "url": "http://127.0.0.1:9812/api/v2/mcp",
            "audience": "resource:deep", "scheme": "http", "host": "127.0.0.1",
            "port": 9812, "path": "/api/v2/mcp"}),
    })
    tool_client, seen = _mock_tool()
    app = proxy_app.build_app(
        router=router, identity=_identity(), scope=[], pin=None,
        gateway_url="", exchange_fn=lambda **kw: {"access_token": "M"},
        tool_client_factory=lambda: tool_client)
    client = TestClient(app)
    # the declared endpoint works, and the wire URL is the declared path
    ok = client.post("/tools/deep/api/v2/mcp", content=b"{}")
    assert ok.status_code == 200
    assert seen["url"] == "http://127.0.0.1:9812/api/v2/mcp"
    # an agent-picked path is refused and NOTHING reaches the tool
    seen.clear()
    for path in ("/tools/deep/mcp", "/tools/deep/admin",
                 "/tools/deep/api/v2/mcp/extra"):
        assert client.post(path, content=b"{}").status_code == 404
    # non-MCP methods are refused even on the declared path
    assert client.put("/tools/deep/api/v2/mcp", content=b"{}").status_code == 404
    assert client.patch("/tools/deep/api/v2/mcp", content=b"{}").status_code == 404
    assert seen == {}


def test_tool_per_run_call_budget_is_enforced_before_exchange(monkeypatch):
    monkeypatch.setattr(proxy_app, "_TOOL_MAX_CALLS", 1)
    exchanges = []
    tool_client, _seen = _mock_tool()
    app = proxy_app.build_app(
        router=_router(), identity=_identity(), scope=[], pin=None,
        gateway_url="", exchange_fn=lambda **kw: (
            exchanges.append(kw) or {"access_token": "M", "expires_in": 300}),
        tool_client_factory=lambda: tool_client)
    client = TestClient(app)
    assert client.post("/tools/obs/mcp", content=b"{}").status_code == 200
    assert client.post("/tools/obs/mcp", content=b"{}").status_code == 429
    assert len(exchanges) == 1


def test_cache_get_survives_a_concurrent_expiry_removal():
    """Two anyio worker threads can read the same just-expired entry; the loser
    of the removal race must re-mint, not KeyError its call into a 502."""
    cache = sc.TokenCache()
    key = ("resource:telemetry", ("telemetry:read",), "")

    class Vanishing(dict):
        # models the window between reading the expired hit and removing it:
        # the OTHER thread's removal already happened
        def get(self, k, default=None):
            return ("stale", float("-inf"))
    cache._entries = Vanishing()
    assert cache.get(key) is None

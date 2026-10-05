"""The broker holds the platform's provider key, so it is a target itself.

Three properties, each closing a different way that key gets spent by someone
who should not be spending it:

  who is calling   an unauthenticated proxy that forwards with a real API key is
                   an open credential for anything that can reach the port
  what they reach  the key can do more than inference; a proxy that forwards any
                   path lends every bit of that to the agent
  how much         the run that has been talked into a loop is exactly the run
                   that will not stop itself

And one property that is easy to lose while adding the first: the credential the
agent must hold to call the model must NOT be the credential that acts on the
control plane.
"""

import importlib

import pytest
import conftest
from fastapi.testclient import TestClient

from andyur import config
from andyur.server import runtoken


@pytest.fixture
def broker(monkeypatch):
    """A broker in the production profile: callers must authenticate.

    Run liveness is stubbed live here so each test exercises ONE property. The
    liveness check itself is covered by its own tests below, which unstub it."""
    monkeypatch.setenv("ANDYUR_PROFILE", "prod")
    monkeypatch.setattr(config, "PROD", True)
    import andyur.broker as broker_module
    importlib.reload(broker_module)
    monkeypatch.setattr(broker_module, "PROD", True)
    async def _no_liveness_check(ctx):
        return None

    monkeypatch.setattr(broker_module, "_assert_run_is_live", _no_liveness_check)
    return broker_module


@pytest.fixture
def client(broker):
    return TestClient(broker.app)


def broker_token(run_id="run-1", agent="alice"):
    return runtoken.mint(agent, run_id, "wf-1", purpose=runtoken.PURPOSE_BROKER)


# --- who is calling ---------------------------------------------------------

def test_an_unauthenticated_call_is_refused(broker, client, monkeypatch):
    """Otherwise anything that can reach the port spends the platform's key,
    and the bill is the first sign anyone gets.

    Two things make this a real guard, not a coincidence: NO_AUTH opts out of
    the suite's default operator SVID (conftest injects one on any header-less
    request), so this is a genuinely credential-less call and the 401 comes from
    the PROD require-a-credential branch, not a purpose mismatch; and the
    upstream is stubbed, so a call that slipped past that branch would raise
    here rather than return a coincidental 401 from a keyless provider."""
    reached = {}

    async def fake_send(req, **kw):
        reached["yes"] = True
        raise RuntimeError("a refused call must never reach the upstream")

    monkeypatch.setattr(broker._client, "send", fake_send)
    r = client.post("/v1/messages", json={}, headers=conftest.NO_AUTH)
    assert r.status_code == 401
    assert "yes" not in reached


def test_a_forged_credential_is_refused(client):
    r = client.post("/v1/messages", json={},
                    headers={"Authorization": "Bearer not.a.token"})
    assert r.status_code == 401


def test_a_control_plane_run_token_is_refused_at_the_broker(client):
    """Audience binding, and the reason it exists. The model client sends its
    credential on every call, so that credential lives inside the agent's reach.
    If a control-plane run token were accepted here, the token the agent is
    ALLOWED to hold would be the token it is not, and R2's environment scrub
    would be undone by the mechanism meant to enforce it."""
    control_plane_token = runtoken.mint("alice", "run-1", "wf-1")   # PURPOSE_RUN
    r = client.post("/v1/messages", json={},
                    headers={"Authorization": f"Bearer {control_plane_token}"})
    assert r.status_code == 401


def test_a_broker_token_is_refused_at_the_control_plane():
    """The same binding in the other direction, so neither credential can stand
    in for the other."""
    token = broker_token()
    with pytest.raises(runtoken.InvalidRunToken):
        runtoken.verify(token)               # defaults to PURPOSE_RUN


def test_an_expired_credential_is_refused(broker, client, monkeypatch):
    """The 401 must be Andyur's expiry check, not a keyless upstream's refusal:
    stub the upstream so a token that slipped past expiry would raise here
    instead of coincidentally returning 401 from the provider (BROKER_UPSTREAM
    defaults to api.anthropic.com, which 401s a keyless request)."""
    reached = {}

    async def fake_send(req, **kw):
        reached["yes"] = True
        raise RuntimeError("an expired credential must never reach the upstream")

    monkeypatch.setattr(broker._client, "send", fake_send)
    stale = runtoken.mint("alice", "run-1", "wf-1", ttl=-10,
                          purpose=runtoken.PURPOSE_BROKER)
    r = client.post("/v1/messages", json={},
                    headers={"Authorization": f"Bearer {stale}"})
    assert r.status_code == 401
    assert "yes" not in reached


def test_the_expiry_check_itself_refuses_a_stale_token():
    """Directly, independent of any transport, so the guard cannot be a
    coincidence of who answers. verify() must reject an expired token by its own
    clock; the positive control (a fresh token of the same shape verifying)
    proves the refusal is the expiry check and not a blanket failure."""
    fresh = runtoken.mint("alice", "run-1", "wf-1",
                          purpose=runtoken.PURPOSE_BROKER)
    assert runtoken.verify(fresh, purpose=runtoken.PURPOSE_BROKER)["run_id"] == "run-1"
    stale = runtoken.mint("alice", "run-1", "wf-1", ttl=-10,
                          purpose=runtoken.PURPOSE_BROKER)
    with pytest.raises(runtoken.InvalidRunToken, match="expired"):
        runtoken.verify(stale, purpose=runtoken.PURPOSE_BROKER)


def test_the_dev_profile_does_not_demand_a_credential(monkeypatch):
    """On a single trusted machine the broker sits on loopback beside its
    operator. Demanding a token there buys nothing and teaches people to
    disable checks, so the requirement lands with the production profile.

    The upstream is stubbed. Asserting 'not 401' against the REAL provider made
    this test send a live request with whatever key happened to be in the
    environment: network-dependent, credential-dependent, and passing only on a
    machine that had a key. A security test that talks to the internet is not a
    test, it is a bill."""
    monkeypatch.setenv("ANDYUR_PROFILE", "dev")
    monkeypatch.setattr(config, "PROD", False)
    import andyur.broker as broker_module
    importlib.reload(broker_module)
    monkeypatch.setattr(broker_module, "PROD", False)

    reached = {}

    async def fake_send(req, **kw):
        reached["yes"] = True
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(broker_module._client, "send", fake_send)
    with pytest.raises(RuntimeError):
        # NO_AUTH because the suite's default identity is a CONTROL-PLANE SVID
        # and this is the broker, which reads Authorization as its own purpose-
        # bound credential. Without this the call arrives authenticated as
        # something the broker does not recognise, and "unauthenticated dev call"
        # is not what gets tested.
        TestClient(broker_module.app).post("/v1/messages", json={},
                                           headers=conftest.NO_AUTH)
    assert reached, "an unauthenticated dev call should have been forwarded"


# --- what they may reach ----------------------------------------------------

@pytest.mark.parametrize("path", [
    "/v1/organizations/api_keys",     # mint further keys with the platform's key
    "/v1/organizations/users",
    "/v1/organizations/workspaces",
    "/admin",
    "/v1/../v1/organizations",
])
def test_only_inference_paths_are_forwarded(client, path):
    """The provider key may carry account and key-management authority. A proxy
    that forwards whatever path it is handed lends all of it to the component we
    already assume is compromised."""
    r = client.post(path, json={}, headers={"Authorization": f"Bearer {broker_token()}"})
    assert r.status_code == 403


def test_the_inference_path_is_allowed(client, monkeypatch):
    """The allowlist has to leave the platform working, or it gets removed."""
    calls = {}

    async def fake_send(req, **kw):
        calls["url"] = str(req.url)
        raise RuntimeError("stop before the network")

    import andyur.broker as broker_module
    monkeypatch.setattr(broker_module._client, "send", fake_send)
    with pytest.raises(RuntimeError):
        client.post("/v1/messages", json={},
                    headers={"Authorization": f"Bearer {broker_token()}"})
    assert "/v1/messages" in calls["url"]


# --- how much ---------------------------------------------------------------

def test_a_run_cannot_spend_without_limit(client, broker, monkeypatch):
    """A ceiling, not a budget: it exists so a looping or subverted run cannot
    spend without bound before a human notices."""
    monkeypatch.setattr(broker, "_MAX_CALLS", 3)

    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(broker._client, "send", fake_send)
    headers = {"Authorization": f"Bearer {broker_token(run_id='loopy')}"}
    for _ in range(3):
        with pytest.raises(RuntimeError):        # allowed through to the upstream
            client.post("/v1/messages", json={}, headers=headers)
    r = client.post("/v1/messages", json={}, headers=headers)
    assert r.status_code == 429


def test_the_ceiling_is_per_run_not_global(client, broker, monkeypatch):
    """One noisy run must not exhaust another run's allowance; that would turn a
    spend control into a denial of service between tenants."""
    monkeypatch.setattr(broker, "_MAX_CALLS", 1)

    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(broker._client, "send", fake_send)
    with pytest.raises(RuntimeError):
        client.post("/v1/messages", json={},
                    headers={"Authorization": f"Bearer {broker_token(run_id='a')}"})
    assert client.post("/v1/messages", json={},
                       headers={"Authorization": f"Bearer {broker_token(run_id='a')}"}
                       ).status_code == 429
    with pytest.raises(RuntimeError):            # a different run is unaffected
        client.post("/v1/messages", json={},
                    headers={"Authorization": f"Bearer {broker_token(run_id='b')}"})


def test_the_ceiling_survives_table_overflow(client, broker, monkeypatch):
    """Eviction must not hand a run a fresh allowance.

    `_calls[run_id] = used` leaves an existing key where it is, so the dict's
    front -- what eviction drops -- held the LONGEST-LIVED run, not the coldest.
    A run at its ceiling only had to make enough distinct run ids appear to have
    its counter dropped and start again, indefinitely. Here the busy run keeps
    calling while the table overflows around it, and must stay refused.
    """
    monkeypatch.setattr(broker, "_MAX_CALLS", 2)
    monkeypatch.setattr(broker, "_MAX_TRACKED_RUNS", 4)

    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(broker._client, "send", fake_send)

    def call(run_id):
        return client.post("/v1/messages", json={},
                           headers={"Authorization": f"Bearer {broker_token(run_id=run_id)}"})

    for _ in range(2):                                  # spend the allowance
        with pytest.raises(RuntimeError):
            call("busy")
    assert call("busy").status_code == 429

    for i in range(20):                                 # flood the table
        with pytest.raises(RuntimeError):
            call(f"filler-{i}")
        assert call("busy").status_code == 429, (
            f"the ceiling reset after {i + 1} evictions")


def test_a_run_can_see_its_own_usage(client, broker, monkeypatch):
    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(broker._client, "send", fake_send)
    headers = {"Authorization": f"Bearer {broker_token(run_id='seen')}"}
    with pytest.raises(RuntimeError):
        client.post("/v1/messages", json={}, headers=headers)
    body = client.get("/usage", headers=headers).json()
    assert body == {"run_id": "seen", "calls": 1, "ceiling": broker._MAX_CALLS}


def test_usage_does_not_enumerate_other_runs(client, broker, monkeypatch):
    """A run reading the whole spend table learns which other runs exist and
    which are busy: a target list. It sees its own line and nothing else."""
    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(broker._client, "send", fake_send)
    with pytest.raises(RuntimeError):
        client.post("/v1/messages", json={},
                    headers={"Authorization": f"Bearer {broker_token(run_id='victim')}"})
    body = client.get(
        "/usage", headers={"Authorization": f"Bearer {broker_token(run_id='nosy')}"}).json()
    assert "victim" not in str(body)
    assert body["calls"] == 0


def test_usage_needs_a_credential(client):
    assert client.get("/usage").status_code == 401


# --- the traversal bypass, driven at the ASGI layer -------------------------
#
# These MUST NOT use TestClient for the attack paths. httpx normalizes dot
# segments client-side, so `/v1/messages/../../v1/organizations` becomes
# `/v1/organizations` before dispatch and is refused for the wrong reason --
# the test passes while the real attack, which arrives un-normalized over the
# wire, succeeds. Uvicorn percent-decodes but does not remove dot segments.

import anyio


def _raw_request(app, raw_path: str, token: str) -> tuple[int, str]:
    """Drive the ASGI app with a path the server never normalized, the way it
    actually arrives on the wire. Returns (status, upstream path reached)."""
    seen = {}
    status = {}

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            status["code"] = message["status"]

    async def fake_send(req, **kw):
        seen["url"] = str(req.url)
        raise RuntimeError("stop before the network")

    import andyur.broker as broker_module
    real_send = broker_module._client.send
    broker_module._client.send = fake_send
    try:
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": "POST", "path": raw_path, "raw_path": raw_path.encode(),
            "root_path": "", "scheme": "http", "query_string": b"",
            "headers": [(b"host", b"broker"), (b"content-type", b"application/json"),
                        (b"authorization", f"Bearer {token}".encode())],
            "client": ("127.0.0.1", 1234), "server": ("broker", 8643),
        }
        try:
            anyio.from_thread.run  # noqa: B018  (anyio present check)
        except AttributeError:
            pass
        anyio.run(app, scope, receive, send)
    except RuntimeError as exc:
        if "stop before the network" not in str(exc):
            raise
    finally:
        broker_module._client.send = real_send
    return status.get("code", 0), seen.get("url", "")


@pytest.mark.parametrize("raw_path", [
    "/v1/messages/../../v1/organizations/api_keys",
    "/v1/messages/../organizations",
    "/v1/messages/./../../admin",
    "//v1/messages/../../v1/organizations",
])
def test_dot_segments_cannot_walk_out_of_the_allowlist(broker, raw_path):
    """The attack that made this file necessary. The raw path starts with an
    allowed prefix, so a naive check permits it; the HTTP client then removes
    the dot segments, and the request that leaves carrying the real provider key
    is one nobody authorized. Check and request must be the same string."""
    status, url = _raw_request(broker.app, raw_path, broker_token())
    assert status == 403, f"{raw_path} was not refused (reached {url})"
    assert "organizations" not in url and "admin" not in url


def test_the_allowlist_is_anchored_on_path_segments(broker):
    """A bare prefix match reads as 'these endpoints' and behaves as 'these
    string prefixes', so an upstream route that merely starts with the same
    characters is reachable."""
    status, url = _raw_request(broker.app, "/v1/messages_not_really", broker_token())
    assert status == 403, f"reached {url}"


def test_a_legitimate_inference_path_still_reaches_the_upstream(broker):
    status, url = _raw_request(broker.app, "/v1/messages", broker_token())
    assert url.endswith("/v1/messages"), url


# --- spending must stop when the run does ----------------------------------

@pytest.fixture
def live_broker(monkeypatch):
    """The production broker with the liveness check ACTIVE."""
    monkeypatch.setenv("ANDYUR_PROFILE", "prod")
    monkeypatch.setattr(config, "PROD", True)
    import andyur.broker as broker_module
    importlib.reload(broker_module)
    monkeypatch.setattr(broker_module, "PROD", True)
    broker_module._liveness.clear()
    return broker_module


class _Stub:
    """Stands in for the lazily-built control-plane client."""

    def __init__(self, get):
        self.get = get


def _stub_factory(get):
    """_cp_client is a coroutine now (it builds TLS off the event loop)."""
    async def factory():
        return _Stub(get)
    return factory


def _answer_liveness(broker_module, monkeypatch, alive=None, raises=False, status=200):
    class _R:
        status_code = status

        def json(self):
            return {"live": alive}

    async def fake_get(url, **kw):
        if raises:
            raise OSError("control plane unreachable")
        return _R()

    monkeypatch.setattr(broker_module, "_cp_client", _stub_factory(fake_get))


def test_a_killed_run_cannot_keep_spending(live_broker, monkeypatch):
    """The credential here is the one the agent is DESIGNED to hold, so it is the
    platform credential most easily exfiltrated, and its TTL outlives the run.
    Without this, destroying a run does not stop it buying inference on the
    platform's key -- the kill switch would stop the work and not the bill."""
    _answer_liveness(live_broker, monkeypatch, alive=False)
    r = TestClient(live_broker.app).post(
        "/v1/messages", json={},
        headers={"Authorization": f"Bearer {broker_token(run_id='killed')}"})
    assert r.status_code == 403


def test_refreshing_liveness_moves_the_run_to_the_hot_end(live_broker, monkeypatch):
    """The commit said "both tables now pop-and-reinsert"; only _calls was
    pinned, so deleting the _liveness move-to-hot line left the suite green.

    Driven through the real request path, because the bug is at the CALL SITE,
    not in _evict_lru: a test that pops and reinserts by hand proves only that
    the helper works on input the test arranged. Lower stakes than the ceiling
    (a lost entry costs one extra control-plane call and can never serve a stale
    "alive"), but an unpinned claim is how the ceiling bug survived four reviews.
    """
    _answer_liveness(live_broker, monkeypatch, alive=True)

    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(live_broker._client, "send", fake_send)
    monkeypatch.setattr(live_broker, "_LIVENESS_TTL", 0)   # always re-check

    live_broker._liveness.clear()
    for i in range(4):                       # older entries, inserted first
        live_broker._liveness[f"older-{i}"] = (0.0, True)

    client = TestClient(live_broker.app)
    with pytest.raises(RuntimeError):        # refresh the OLDEST-inserted run
        client.post("/v1/messages", json={},
                    headers={"Authorization": f"Bearer {broker_token(run_id='older-0')}"})

    keys = list(live_broker._liveness)
    assert keys[-1] == "older-0", (
        f"a just-refreshed run is not at the hot end: {keys}")


def test_a_live_run_is_served(live_broker, monkeypatch):
    _answer_liveness(live_broker, monkeypatch, alive=True)

    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(live_broker._client, "send", fake_send)
    with pytest.raises(RuntimeError):
        TestClient(live_broker.app).post(
            "/v1/messages", json={},
            headers={"Authorization": f"Bearer {broker_token(run_id='alive')}"})


def test_an_unreachable_control_plane_eventually_stops_spending(live_broker, monkeypatch):
    """Fails CLOSED, the same rule the runner's halt poll uses. A check that can
    be defeated by making it fail is not a check."""
    _answer_liveness(live_broker, monkeypatch, raises=True)
    r = TestClient(live_broker.app).post(
        "/v1/messages", json={},
        headers={"Authorization": f"Bearer {broker_token(run_id='unknown')}"})
    assert r.status_code == 503


def test_a_brief_outage_is_survived_on_the_last_known_good_answer(live_broker, monkeypatch):
    """A control-plane hiccup must not stop every agent mid-thought, so a cached
    'alive' is served through a bounded grace window -- bounded, because an
    attacker who can make the check fail must not make it fail permanently."""
    _answer_liveness(live_broker, monkeypatch, alive=True)

    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(live_broker._client, "send", fake_send)
    client = TestClient(live_broker.app)
    headers = {"Authorization": f"Bearer {broker_token(run_id='blip')}"}
    with pytest.raises(RuntimeError):
        client.post("/v1/messages", json={}, headers=headers)   # caches alive
    _answer_liveness(live_broker, monkeypatch, raises=True)
    monkeypatch.setattr(live_broker, "_LIVENESS_TTL", 0)        # force a recheck
    with pytest.raises(RuntimeError):
        client.post("/v1/messages", json={}, headers=headers)   # served from cache
    monkeypatch.setattr(live_broker, "_LIVENESS_GRACE", 0)      # grace exhausted
    assert client.post("/v1/messages", json={}, headers=headers).status_code == 503


def test_a_control_plane_error_is_not_evidence_the_run_died(live_broker, monkeypatch):
    """A 500 means the control plane could not answer, not that the run ended.
    Treating those the same killed healthy runs -- and cached the mistake, so a
    live run stayed locked out for the whole TTL after the outage cleared."""
    _answer_liveness(live_broker, monkeypatch, alive=None, status=500)
    r = TestClient(live_broker.app).post(
        "/v1/messages", json={},
        headers={"Authorization": f"Bearer {broker_token(run_id='healthy')}"})
    assert r.status_code == 503, "an unanswerable check is unavailability, not death"
    assert "healthy" not in live_broker._liveness, "a non-answer must not be cached"


def test_the_liveness_check_carries_the_callers_own_credential(live_broker, monkeypatch):
    """So the liveness endpoint is not an open oracle: you can only ask about a
    run whose credential you already hold."""
    seen = {}

    async def fake_get(url, **kw):
        seen.update(kw.get("headers") or {})

        class _R:
            status_code = 200

            def json(self):
                return {"live": True}
        return _R()

    monkeypatch.setattr(live_broker, "_cp_client", _stub_factory(fake_get))

    async def fake_send(req, **kw):
        raise RuntimeError("stop before the network")

    monkeypatch.setattr(live_broker._client, "send", fake_send)
    token = broker_token(run_id="mine")
    with pytest.raises(RuntimeError):
        TestClient(live_broker.app).post(
            "/v1/messages", json={}, headers={"Authorization": f"Bearer {token}"})
    assert seen.get("X-Andyur-Run-Token") == token


# --- traversal that means something different downstream --------------------

@pytest.mark.parametrize("raw_path", [
    "/v1/messages/%252e%252e/%252e%252e/v1/organizations/api_keys",  # double-encoded
    "/v1/messages/%25%32%65%25%32%65/v1/organizations",              # nested encoding
    "/v1/messages/..;/..;/v1/organizations/api_keys",                # path parameter
    "/v1/messages/%5c..%5c..%5cv1/organizations",                    # backslash
    "/v1/messages/%2e%2e/%2e%2e/v1/organizations",                   # single-encoded
])
def test_paths_that_a_gateway_would_re_decode_are_refused(broker, raw_path):
    """The first fix normalized and forwarded byte-for-byte, which is only safe
    if nothing downstream decodes again -- and gateways in front of a provider
    routinely do. `%252e%252e` survives one unquote as a literal `%2e%2e`, and
    resolves to a dot segment at the next hop. A path that needs interpretation
    to be safe is a path to refuse."""
    status, url = _raw_request(broker.app, raw_path, broker_token())
    assert status == 403, f"{raw_path} was forwarded as {url}"


def test_a_trailing_slash_in_the_allowlist_does_not_break_the_endpoint(monkeypatch):
    """`ANDYUR_BROKER_ALLOW_PATHS=/v1/messages/` made /v1/messages return 403:
    the config broke the exact endpoint it named."""
    import andyur.broker as b
    assert b._parse_prefixes("/v1/messages/") == ("/v1/messages",)


def test_a_root_prefix_is_refused_outright():
    """`/` reads as a restriction and behaves as an open proxy, which is the
    single worst way for the allowlist to be wrong."""
    import andyur.broker as b
    with pytest.raises(RuntimeError):
        b._parse_prefixes("/")


def test_importing_the_broker_needs_no_identity_infrastructure(monkeypatch):
    """Building the TLS client at import blocked on SPIRE, so `import
    andyur.broker` hung for 30 seconds and then died before main() ever ran --
    with ANDYUR_MTLS=on, which is the documented production mode. A module that
    cannot be imported without working identity infrastructure cannot be tested
    either."""
    import importlib
    import andyur.broker as b

    called = {"n": 0}
    monkeypatch.setattr(b.identity, "client_tls",
                        lambda role: (called.__setitem__("n", called["n"] + 1), (None, True))[1])
    importlib.reload(b)
    assert called["n"] == 0, "no identity work may happen at import"


def test_an_empty_bearer_still_forwards_the_api_key_credential(broker):
    """Two functions parsed the same credential with different rules: an empty
    bearer plus a valid x-api-key authenticated in one and produced nothing in
    the other, so the liveness check went out with no token, got a 401, and --
    since a 401 now means 'cannot confirm' -- 503'd every model call."""
    class _Req:
        headers = {"authorization": "Bearer ", "x-api-key": "the-real-token"}

    assert broker._presented_credential(_Req()) == "the-real-token"


def test_concurrent_first_callers_build_exactly_one_client(monkeypatch):
    """Without single-flight, N concurrent first-callers each ran the blocking
    SVID fetch and each built a client, and N-1 were dropped still open: an fd
    and connection-pool leak proportional to concurrency, repeated at every
    rebuild boundary for the life of the process."""
    import asyncio
    import importlib
    import andyur.broker as b
    importlib.reload(b)

    built = {"n": 0}

    def slow_tls(role):
        import time as _t
        _t.sleep(0.05)
        built["n"] += 1
        return (None, True)

    monkeypatch.setattr(b.identity, "client_tls", slow_tls)

    async def drive():
        return await asyncio.gather(*[b._cp_client() for _ in range(25)])

    clients = asyncio.run(drive())
    assert built["n"] == 1, f"{built['n']} SVID fetches for one client"
    assert len({id(c) for c in clients}) == 1, "callers got different clients"


def test_a_fresh_host_is_not_treated_as_recently_failed(monkeypatch):
    """monotonic() is uptime, so a 0.0 sentinel made 'we failed recently' true
    for the first retry window after boot, and the broker refused to even
    attempt identity setup."""
    import importlib
    import andyur.broker as b
    importlib.reload(b)
    monkeypatch.setattr(b.time, "monotonic", lambda: 5.0)
    monkeypatch.setattr(b, "_CP_RETRY_AFTER", 30.0)

    import asyncio
    called = {"n": 0}
    monkeypatch.setattr(b.identity, "client_tls",
                        lambda role: (called.__setitem__("n", 1), (None, True))[1])
    asyncio.run(b._cp_client())
    assert called["n"] == 1, "identity setup was skipped on a freshly booted host"


def test_a_compressed_upstream_response_arrives_readable(monkeypatch):
    """The broker must hand back a body its caller can parse.

    It streamed aiter_raw (bytes as they arrived, still gzipped) while stripping
    the content-encoding header that says to decompress, so the caller got
    compressed bytes labelled as plain. api.anthropic.com always gzips, so the
    broker had never actually worked against its real upstream -- every response
    was unparseable. It survived because the local model used in every test does
    not compress. Found by pointing the harness at a real model.

    Drives the REAL broker app against a REAL gzipping server.
    """
    import gzip
    import json
    import threading

    import httpx
    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import Response as RawResponse

    from andyur import broker

    up = FastAPI()

    @up.post("/v1/messages")
    async def messages():
        body = gzip.compress(json.dumps({"content": [{"text": "hi"}]}).encode())
        return RawResponse(content=body, media_type="application/json",
                           headers={"content-encoding": "gzip"})

    server = uvicorn.Server(uvicorn.Config(up, host="127.0.0.1", port=0,
                                           log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    while not server.started:
        threading.Event().wait(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]

    monkeypatch.setattr(
        broker, "_client",
        httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=30.0))
    monkeypatch.setattr(broker, "_authenticate",
                        lambda *a, **k: {"run_id": "r-test", "agent": "scout"})

    try:
        from fastapi.testclient import TestClient

        with TestClient(broker.app) as c:
            r = c.post("/v1/messages", json={"model": "m"},
                       headers={"Authorization": "Bearer t"})
        assert r.status_code == 200, r.text
        assert r.json()["content"][0]["text"] == "hi", \
            f"unparseable body: {r.content[:40]!r}"
    finally:
        server.should_exit = True
        th.join(timeout=5)

"""The console signs in as its OWN OAuth client, not the CLI's, and the
launcher wires what it built into the server it starts.

The console client is Auth Code + PKCE only, no resource-owner password grant,
single `andyur` audience -- so a console session token cannot be replayed at
another audience and does not share the CLI's ROPC configuration. These lock the
wiring: `authlogin.login` threads the client id, and the console passes its
dedicated one both for the initial exchange and for later refreshes.
"""
import asyncio
import inspect
import time

import httpx
import pytest

from andyur import authlogin, config, identity
from andyur import console
from andyur.console import server as console_server


def test_login_defaults_to_the_cli_client_but_accepts_an_override():
    sig = inspect.signature(authlogin.login)
    assert sig.parameters["client_id"].default == authlogin.CLIENT_ID == "andyur-cli"


def test_login_carries_the_client_id_on_the_wire_authorize_and_token(monkeypatch):
    """The property the split exists for: the client id the caller passes must
    appear in BOTH the authorize request and the token exchange. Asserted over
    the wire (captured URL + token form), with a DISTINCTIVE value so reverting
    authlogin's `client_id` back to the CLIENT_ID constant reddens this."""
    monkeypatch.setattr(authlogin, "discover", lambda issuer: {
        "authorization_endpoint": "http://idp.test/auth",
        "token_endpoint": "http://idp.test/token",
        "issuer": issuer,
    })
    # Fixed state so the fake callback matches login's CSRF check; verifier still
    # uses token_bytes, so PKCE is unaffected.
    monkeypatch.setattr(authlogin.secrets, "token_urlsafe", lambda n=32: "FIXEDSTATE")
    opened = {}
    monkeypatch.setattr(authlogin.webbrowser, "open",
                        lambda url: opened.setdefault("url", url) or True)

    class _FakeServer:
        def __init__(self, addr, handler): self.server_port = addr[1]
        def handle_request(self):
            authlogin._Catcher.result = {"state": "FIXEDSTATE", "code": "code123"}
        def server_close(self): pass
    monkeypatch.setattr(authlogin.http.server, "HTTPServer", _FakeServer)

    posted = {}
    def fake_post_form(endpoint, form, what=""):
        posted["form"] = form
        return 200, {"access_token": "a", "refresh_token": "r", "expires_in": 300}
    monkeypatch.setattr(authlogin.boundedhttp, "post_form", fake_post_form)

    body = authlogin.login("http://idp.test", client_id="acme-console",
                           open_browser=True, timeout=5)

    assert "client_id=acme-console" in opened["url"]      # authorize request
    assert posted["form"]["client_id"] == "acme-console"  # token exchange
    assert body["access_token"] == "a"


def test_console_client_id_defaults_and_is_env_overridable(monkeypatch):
    assert config.CONSOLE_CLIENT_ID == "andyur-console"
    monkeypatch.setenv("ANDYUR_CONSOLE_CLIENT_ID", "acme-console")
    import importlib
    importlib.reload(config)
    try:
        assert config.CONSOLE_CLIENT_ID == "acme-console"
    finally:
        monkeypatch.delenv("ANDYUR_CONSOLE_CLIENT_ID", raising=False)
        importlib.reload(config)


def test_bind_holds_the_port_it_prints_and_names_a_taken_one():
    """The launcher binds the socket itself and hands it to uvicorn, so the
    port in the launch URL is the one listening (no bind/close/rebind window).
    A port already in use is a one-line SystemExit naming it, not a traceback
    (seen live: a console-modes gate lost a console to a dev stack's port)."""
    sock, port = console._bind(None)
    try:
        assert sock.getsockname() == ("127.0.0.1", port) and port > 0
        with pytest.raises(SystemExit) as exc:
            console._bind(port)
        assert f"127.0.0.1:{port}" in str(exc.value)
        assert "--port" in str(exc.value)
    finally:
        sock.close()


@pytest.mark.parametrize("port", [80, 443])
def test_bind_refuses_a_default_port(port):
    # browsers omit :80 / :443 from Origin and Host, so the exact-match fences
    # could never pass there
    with pytest.raises(SystemExit) as exc:
        console._bind(port)
    assert "default port" in str(exc.value)


def _stub_launch(monkeypatch, captured):
    """Stub the ends of launch(): the socket, the app, and the server. Each
    stub records what it was handed so the wiring is asserted, not assumed."""
    listener = object()
    monkeypatch.setattr(console, "_bind", lambda port: (listener, 9999))
    def build_app(secret, **kw):
        captured["secret"] = secret
        captured["build"] = kw
        return object()
    monkeypatch.setattr(console_server, "build_app", build_app)
    import uvicorn
    def run(self, sockets=None):
        captured["sockets"] = sockets
        captured["config"] = self.config
    monkeypatch.setattr(uvicorn.Server, "run", run)
    from andyur import otel
    from opentelemetry import trace
    monkeypatch.setattr(otel, "setup_tracing", lambda name: trace.get_tracer(name))
    return listener


def test_console_launch_logs_in_and_refreshes_as_the_console_client(monkeypatch, capsys):
    """The whole point: under user-auth the console must use CONSOLE_CLIENT_ID for
    the login AND hand the same client to the refresh session -- never the CLI's.
    And what launch builds must be what the server serves."""
    captured = {}

    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "http://idp.test/realms/andyur")
    monkeypatch.setattr(config, "OIDC_AUDIENCE", "andyur")
    # DISTINCTIVE, not the shipped default, so this cannot pass against a
    # hardcoded 'andyur-console' literal in the console wiring.
    monkeypatch.setattr(config, "CONSOLE_CLIENT_ID", "acme-console")

    def fake_login(issuer, **kw):
        captured["login_client_id"] = kw.get("client_id")
        return {"access_token": "a", "token_endpoint": "http://idp.test/token"}
    monkeypatch.setattr(authlogin, "login", fake_login)

    real_session = console_server.UserSession
    def spy_session(tokens, *, token_endpoint, client_id):
        captured["session_client_id"] = client_id
        s = real_session(tokens, token_endpoint=token_endpoint, client_id=client_id)
        captured["session"] = s
        return s
    monkeypatch.setattr(console_server, "UserSession", spy_session)
    listener = _stub_launch(monkeypatch, captured)

    console.launch(open_browser=False)

    assert captured["login_client_id"] == "acme-console"
    assert captured["session_client_id"] == "acme-console"
    b = captured["build"]
    assert b["user_session"] is captured["session"]          # the login is USED
    assert b["origin"] == "http://127.0.0.1:9999"             # the fences' host
    assert captured["secret"] != b["launch"].value            # secret is not the token
    assert captured["sockets"] == [listener]                  # the bound socket serves
    assert captured["config"].timeout_graceful_shutdown == 5
    # the line the gates parse (infra/lib/console-gate.sh console_launch_token)
    assert f"andyur console -> http://127.0.0.1:9999/?launch={b['launch'].value}\n" in capsys.readouterr().out


def test_launch_survives_ctrl_c_without_a_traceback(monkeypatch):
    captured = {}
    monkeypatch.setattr(config, "USER_AUTH", False)
    _stub_launch(monkeypatch, captured)
    import uvicorn
    def run(self, sockets=None):
        raise KeyboardInterrupt
    monkeypatch.setattr(uvicorn.Server, "run", run)
    console.launch(open_browser=False)      # returns; no exception


# -- the operator identity is fetched off the event loop -----------------------

def test_concurrent_calls_share_one_svid_fetch_off_the_event_loop(monkeypatch):
    # identity.httpx_auth() defines only the sync flow, which httpx runs inline
    # on the loop: N concurrent calls took N x the SVID fetch time and starved
    # /healthz (measured live at 3.01 s for three 1 s fetches). And N worker
    # threads would only queue on identity's module lock (a convoy Ctrl-C then
    # waits for). The adapter runs ONE fetch in a worker thread and every
    # concurrent caller shares it.
    calls = []
    loop_alive = []
    def slow_fetch(*a, **k):
        calls.append(k.get("timeout"))
        time.sleep(0.2)
        return "tok"
    monkeypatch.setattr(identity, "fetch_token", slow_fetch)
    ok = httpx.MockTransport(lambda r: httpx.Response(200, json={"auth": r.headers.get("authorization")}))
    async def heartbeat():
        # proves the loop was never blocked: ticks land while the fetch sleeps
        for _ in range(4):
            await asyncio.sleep(0.03)
            loop_alive.append(time.monotonic())
    async def go():
        async with httpx.AsyncClient(auth=console_server.OperatorSvidAuth(), transport=ok,
                                     base_url="http://cp") as c:
            rs, _ = await asyncio.gather(asyncio.gather(*(c.get("/x") for _ in range(5))), heartbeat())
            return rs
    rs = asyncio.run(go())
    assert all(r.json()["auth"] == "Bearer tok" for r in rs)
    # THE NUMBER, not the constant. Asking for `SVID_BUDGET` moves with it, so
    # raising the budget to an hour -- a console that hangs a request for an
    # hour on a dead Workload API -- stayed green. The budget is part of what
    # makes the BFF's 503 prompt, so it is pinned as a value.
    assert console_server.SVID_BUDGET == 10.0, console_server.SVID_BUDGET
    assert calls == [10.0]                              # one fetch, budgeted
    assert len(loop_alive) == 4


def test_a_hanging_svid_fetch_is_named_within_its_budget(monkeypatch):
    monkeypatch.setattr(console_server, "SVID_BUDGET", 0.2)
    def hang(*a, **k):
        time.sleep(0.5)
        return "late"
    monkeypatch.setattr(identity, "fetch_token", hang)
    async def go():
        async with httpx.AsyncClient(auth=console_server.OperatorSvidAuth(),
                                     transport=httpx.MockTransport(lambda r: httpx.Response(200)),
                                     base_url="http://cp") as c:
            t0 = time.monotonic()
            with pytest.raises(console_server.IdentityUnavailable) as exc:
                await c.get("/x")
            return time.monotonic() - t0, str(exc.value)
    elapsed, msg = asyncio.run(go())
    assert "no SVID within" in msg and elapsed < 0.45


def test_async_auth_flow_names_an_identity_failure(monkeypatch):
    def broken(*a, **k):
        raise RuntimeError('SPIFFE socket file "/x/api.sock" does not exist')
    monkeypatch.setattr(identity, "fetch_token", broken)
    async def go():
        async with httpx.AsyncClient(auth=console_server.OperatorSvidAuth(),
                                     transport=httpx.MockTransport(lambda r: httpx.Response(200)),
                                     base_url="http://cp") as c:
            await c.get("/x")
    with pytest.raises(console_server.IdentityUnavailable) as exc:
        asyncio.run(go())
    assert "api.sock" in str(exc.value) and "Workload API socket" in str(exc.value)

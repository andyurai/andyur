"""The console BFF's security fences and proxy behavior.

The BFF holds the operator identity and proxies the control plane, so its whole
job is to refuse anything that is not a legitimate console call. These tests
drive the real Starlette app with a MOCK control plane injected as the upstream,
so no SPIRE or live server is needed -- the properties under test are the
launch-token exchange, the session-secret gate, the Origin and Host checks, the
route allowlist, the body caps in both directions, the upstream deadline, query
forwarding, the strict CSP, that every refusal is named and redacted, and that
the served page carries no credential and nothing inline.
"""
import asyncio
import logging
import os
import re

import httpx
import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from andyur import config, observability
from andyur.console import pagecheck, server
from tests.console_js import js_literals

SECRET = "test-console-secret"
LAUNCH = "test-launch-token"
ORIGIN = "http://127.0.0.1:9999"
HOST = ORIGIN.split("://", 1)[1]
H = server.SESSION_HEADER


def _app(**kw):
    kw.setdefault("launch", server.LaunchToken(LAUNCH))
    return server.build_app(SECRET, origin=ORIGIN, **kw)


def _client(**kw):
    # base_url=ORIGIN makes the TestClient send the console's own Host header,
    # the way a browser on the printed URL does.
    return TestClient(_app(**kw), base_url=ORIGIN)


def _echo(seen):
    """A mock control plane: records (method, path) and echoes a tiny body."""
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.raw_path.decode()))
        return httpx.Response(200, json={"ok": True, "path": str(request.url.path)})
    # ASYNC client -- the proxy awaits it (a sync client in an async handler
    # corrupts the connection pool; this is the shape the real BFF uses).
    return httpx.AsyncClient(base_url="http://control-plane",
                             transport=httpx.MockTransport(handler))


@pytest.fixture
def seen():
    return []


@pytest.fixture
def client(seen):
    return _client(upstream=_echo(seen))


def _h(secret=SECRET, origin=None):
    h = {H: secret}
    if origin is not None:
        h["origin"] = origin
    return h


def _exchange(client, token=LAUNCH):
    return client.post("/session", json={"launch": token})


# -- the launch token -----------------------------------------------------------

def test_the_launch_token_is_exchanged_exactly_once_for_the_secret(client, seen):
    r = _exchange(client)
    assert r.status_code == 200 and r.json() == {"secret": SECRET}
    # a second exchange is refused BY NAME: a token seen in a process list or a
    # shell log is worthless after the first page load spent it
    r2 = _exchange(client)
    assert r2.status_code == 403 and r2.json()["reason"] == "launch_spent"
    assert "already used" in r2.json()["detail"]
    # and the secret it handed out is the one the proxy honours
    assert client.get("/api/agents", headers=_h(r.json()["secret"])).status_code == 200
    assert seen == [("GET", "/agents")]


@pytest.mark.parametrize("body", [
    {"launch": "guess"}, {"launch": ""}, {}, {"launch": 42}, {"launch": "é"},
    "not json", "[" * 3000, ["a", "list"], '{"launch": "\\udfff"}', '{"launch": NaN}',
])
def test_a_wrong_or_missing_token_never_yields_the_secret(client, body):
    if isinstance(body, str):
        r = client.post("/session", content=body,
                        headers={"content-type": "application/json"})
    else:
        r = client.post("/session", json=body)
    assert r.status_code == 403 and r.json()["reason"] == "launch_unknown", body
    assert SECRET not in r.text
    # the real token is still unspent: a wrong guess must not burn it
    assert _exchange(client).status_code == 200


def test_the_exchange_is_fenced_by_origin_and_host(client):
    r = client.post("/session", json={"launch": LAUNCH},
                    headers={"origin": "http://evil.example"})
    assert r.status_code == 403 and r.json()["reason"] == "cross_origin"
    r = client.post("/session", json={"launch": LAUNCH},
                    headers={"host": "evil.example:9999"})
    assert r.status_code == 403 and r.json()["reason"] == "bad_host"
    # neither refusal spent it
    assert _exchange(client).status_code == 200


def test_the_exchange_has_its_own_small_body_cap(client):
    big = b'{"launch": "' + b"x" * server.SESSION_BODY_BYTES + b'"}'
    r = client.post("/session", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.json()["reason"] == "body_too_large"
    assert _exchange(client).status_code == 200            # not spent


def test_near_miss_console_paths_are_named_refusals_not_static_404s(client):
    for method, path in (("POST", "/session/"), ("GET", "/session/x"), ("GET", "/api"),
                         ("GET", "/api?x=1")):
        r = client.request(method, path, headers=_h())
        assert r.headers["content-type"].startswith("application/json"), (method, path)
        assert r.json()["reason"] in ("not_a_console_route",), (method, path, r.json())
        assert r.headers["cache-control"] == "no-store"


def test_only_post_reaches_the_exchange(client):
    r = client.get("/session")
    assert r.status_code == 405 and r.json()["reason"] == "method_not_allowed"
    assert r.headers["allow"] == "POST"
    assert _exchange(client).status_code == 200


# -- the session-secret gate ---------------------------------------------------

def test_a_call_without_the_session_secret_is_refused(client):
    r = client.get("/api/agents")
    assert r.status_code == 401 and r.json()["reason"] == "bad_session"
    # RFC 9110 15.5.2: a 401 carries a challenge
    assert r.headers["www-authenticate"].startswith("ConsoleSession ")


def test_a_wrong_session_secret_is_refused(client):
    assert client.get("/api/agents", headers=_h("nope")).status_code == 401


def test_the_correct_secret_is_admitted(client, seen):
    r = client.get("/api/agents", headers=_h())
    assert r.status_code == 200 and seen == [("GET", "/agents")]


def _raw(app, method, path, headers):
    """Drive the ASGI app with raw header bytes that httpx refuses to send
    (non-ASCII), the way a hostile local client can."""
    async def run():
        sent = {}
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(msg):
            if msg["type"] == "http.response.start":
                sent["status"] = msg["status"]
            elif msg["type"] == "http.response.body":
                sent["body"] = sent.get("body", b"") + msg.get("body", b"")
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": headers, "server": ("127.0.0.1", 9999),
                 "client": ("127.0.0.1", 1)}
        await app(scope, receive, send)
        return sent
    return asyncio.run(run())


def test_a_non_ascii_secret_is_a_refusal_not_a_type_error(seen):
    # compare_digest on str raises TypeError for non-ASCII; seen live as a 500.
    app = _app(upstream=_echo(seen))
    sent = _raw(app, "GET", "/api/agents", [(b"host", HOST.encode()),
                                            (H.encode(), b"\xe9\xff")])
    assert sent["status"] == 401 and b"bad_session" in sent["body"]
    assert seen == []
    # positive control through the same raw path
    ok = _raw(app, "GET", "/api/agents", [(b"host", HOST.encode()),
                                          (H.encode(), SECRET.encode())])
    assert ok["status"] == 200 and seen == [("GET", "/agents")]


# -- the Origin and Host checks ----------------------------------------------

def test_a_cross_origin_request_is_refused_even_with_the_secret(client, seen):
    r = client.get("/api/agents", headers=_h(origin="http://evil.example"))
    assert r.status_code == 403 and r.json()["reason"] == "cross_origin"
    assert seen == []


@pytest.mark.parametrize("origin", ["null", "http://127.0.0.1:99990",
                                    "http://localhost:9999", "HTTP://127.0.0.1:9999"])
def test_near_miss_origins_are_refused(client, origin):
    r = client.get("/api/agents", headers=_h(origin=origin))
    assert r.status_code == 403 and r.json()["reason"] == "cross_origin", origin


def test_the_consoles_own_origin_is_allowed(client):
    assert client.get("/api/agents", headers=_h(origin=ORIGIN)).status_code == 200


@pytest.mark.parametrize("host", ["evil.example:9999", "127.0.0.1:99990",
                                  "127.0.0.1", "localhost:9999"])
def test_a_request_for_another_host_is_refused_even_with_the_secret(client, seen, host):
    # a page on evil.example whose DNS now points at 127.0.0.1 reaches this
    # port with Host: evil.example and, being same-origin to itself, no Origin
    r = client.get("/api/agents", headers={**_h(), "host": host})
    assert r.status_code == 403 and r.json()["reason"] == "bad_host", host
    assert seen == []


def test_a_request_without_a_host_is_a_400(seen):
    sent = _raw(_app(upstream=_echo(seen)), "GET", "/api/agents", [(H.encode(), SECRET.encode())])
    assert sent["status"] == 400 and b"missing_host" in sent["body"]


def test_the_consoles_own_host_is_allowed(client, seen):
    r = client.get("/api/agents", headers={**_h(), "host": HOST})
    assert r.status_code == 200 and seen == [("GET", "/agents")]


# -- the route allowlist -------------------------------------------------------

def test_allowlisted_routes_proxy(client, seen):
    client.get("/api/agents", headers=_h())
    client.post("/api/agents", headers=_h(), json={"name": "x"})
    client.get("/api/agents/foo", headers=_h())
    client.post("/api/agents/foo/trigger", headers=_h(), json={"reason": "r"})
    client.post("/api/agents/foo/pause", headers=_h(), json={})
    client.post("/api/agents/foo/resume", headers=_h(), json={})
    client.delete("/api/agents/foo", headers=_h())
    client.get("/api/v1/registry/agents", headers=_h())
    client.get("/api/v1/registry/agents/agt_x/resolve", headers=_h())
    client.get("/api/agents/foo/ceiling", headers=_h())
    client.get("/api/me", headers=_h())
    client.get("/api/workers", headers=_h())               # admin; server gates
    client.post("/api/workflows/wf1/halt", headers=_h())
    client.post("/api/workflows/wf1/unhalt", headers=_h())
    client.get("/api/runs", headers=_h())
    client.get("/api/runs/r1", headers=_h())
    client.get("/api/runs/r1/events?after=3", headers=_h())
    client.post("/api/runs/r1/turn", headers=_h(), json={"body": "hi"})
    client.post("/api/runs/r1/close", headers=_h())
    client.get("/api/runs/r1/transcript", headers=_h())
    client.get("/api/runs/r1/exchanges", headers=_h())
    client.get("/api/runs/r1/actions", headers=_h())
    client.get("/api/workflows/wf1/flow", headers=_h())
    # every allowlisted route reached the control plane, by exact path
    assert len(seen) == len(server._ALLOWLIST) == 23
    assert ("GET", "/runs/r1/events?after=3") in seen
    # the golden path's Requested / Decision / Approved by / Result come from
    # here, and the 4.2 exit criterion is that they render without a database
    assert ("GET", "/runs/r1/actions") in seen
    assert ("GET", "/agents/foo/ceiling") in seen
    assert ("GET", "/me") in seen and ("GET", "/workers") in seen


@pytest.mark.parametrize("method,path", [
    ("PUT", "/api/agents/foo/ceiling"),  # ceiling WRITE stays off the console
    ("POST", "/api/oauth/token"),       # the token endpoint -- must never proxy
    ("GET", "/api/agents/foo/files/mcp.json"),   # not on the console allowlist
    ("PUT", "/api/agents/foo"),         # PUT is not an allowed method here
    ("PATCH", "/api/agents/foo"),       # nor PATCH: every method reaches the fence
    ("OPTIONS", "/api/agents"),         # a preflight is refused, never forwarded
    ("HEAD", "/api/agents"),
    ("POST", "/api/runs/r1/token"),     # run-token issuance is not a console call
    ("POST", "/api/oauth/token?x=1"),   # a query string widens nothing
])
def test_non_allowlisted_routes_are_refused(client, seen, method, path):
    r = client.request(method, path, headers=_h())
    assert r.status_code == 403, (method, path)
    if method != "HEAD":
        assert r.json()["reason"] == "not_a_console_route"
    assert seen == []          # never reached the control plane


def test_the_allowlist_anchors_the_whole_path():
    # fullmatch, not match: `$` also matches before a trailing newline
    assert server._allowed("GET", "/workers") == "workers"
    assert server._allowed("GET", "/workers\n") is None
    assert server._allowed("GET", "/workers/") is None


def test_the_query_string_is_forwarded_but_does_not_widen_the_allowlist(client, seen):
    r = client.delete("/api/agents/foo?force=true", headers=_h())
    assert r.status_code == 200
    assert seen == [("DELETE", "/agents/foo?force=true")]
    # dots in the QUERY are data, not path: forwarded verbatim, never a path
    client.get("/api/agents/foo?next=/../workers", headers=_h())
    assert seen[-1] == ("GET", "/agents/foo?next=/../workers")


@pytest.mark.parametrize("path,upstream", [
    ("/api/agents/x%3Fforce=1/ceiling", "/agents/x%3Fforce=1/ceiling"),
    ("/api/agents/x%23frag/ceiling", "/agents/x%23frag/ceiling"),
    ("/api/agents/caf%C3%A9", "/agents/caf%C3%A9"),
])
def test_the_raw_path_is_forwarded_so_the_allowlist_and_the_upstream_agree(client, seen, path, upstream):
    # matched decoded (one segment), forwarded raw: a decoded `?` or `#`
    # re-parsed as a URL used to split the upstream path at the allowlist's
    # blind spot (`/agents/x%3F/ceiling` reached `/agents/x`)
    assert client.get(path, headers=_h()).status_code == 200
    assert seen == [("GET", upstream)]


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/agents/%2E%2E"),                 # would reach GET / upstream
    ("DELETE", "/api/agents/%2E%2E"),              # would reach DELETE /
    ("POST", "/api/workflows/%2E%2E/halt"),        # would reach POST /halt
    ("GET", "/api/agents/%2E"),                    # would reach GET /agents
])
def test_a_dot_segment_is_refused_before_the_allowlist(client, seen, method, path):
    # percent-encoded dots reach the proxy un-normalised (httpx only collapses
    # literal ones), which is exactly the raw-client case the guard exists for;
    # each of these lands INSIDE a `[^/]+` slot, so only the guard stops it
    r = client.request(method, path, headers=_h())
    assert r.status_code == 403 and r.json()["reason"] == "bad_path"
    assert seen == []


# -- the body caps -------------------------------------------------------------

def test_a_body_over_the_cap_is_refused_before_reaching_the_control_plane(client, seen):
    big = b"x" * (server.MAX_BODY_BYTES + 1)
    r = client.post("/api/agents", headers=_h(), content=big)
    assert r.status_code == 413 and r.json()["reason"] == "body_too_large"
    assert r.headers["connection"] == "close"
    assert seen == []
    # positive control: a body at the cap is forwarded
    ok = client.post("/api/agents", headers=_h(), content=b"x" * server.MAX_BODY_BYTES)
    assert ok.status_code == 200 and seen == [("POST", "/agents")]


def test_the_cap_counts_bytes_received_across_chunks():
    # The TestClient delivers a body as one chunk; drive _read_body with a
    # hand-written receive so the accumulation across chunks is what is tested.
    def request(chunks):
        it = iter(chunks)
        async def receive():
            try:
                c = next(it)
                return {"type": "http.request", "body": c, "more_body": True}
            except StopIteration:
                return {"type": "http.request", "body": b"", "more_body": False}
        return Request({"type": "http", "headers": [], "method": "POST", "path": "/",
                        "query_string": b""}, receive)
    mib = b"x" * (1 << 20)
    over = asyncio.run(server._read_body(request([mib] * 17), 16 * (1 << 20)))
    assert over is server.Reason.BODY_TOO_LARGE
    at = asyncio.run(server._read_body(request([mib] * 16), 16 * (1 << 20)))
    assert isinstance(at, bytes) and len(at) == 16 * (1 << 20)


def test_a_client_that_leaves_mid_body_is_named_not_a_traceback():
    async def receive():
        return {"type": "http.disconnect"}
    req = Request({"type": "http", "headers": [], "method": "POST", "path": "/",
                   "query_string": b""}, receive)
    assert asyncio.run(server._read_body(req, 1024)) is server.Reason.CLIENT_DISCONNECTED


def test_a_body_that_dribbles_past_the_deadline_is_named(monkeypatch):
    monkeypatch.setattr(server, "BODY_DEADLINE", 0.2)
    async def receive():
        await asyncio.sleep(0.1)
        return {"type": "http.request", "body": b"x", "more_body": True}
    req = Request({"type": "http", "headers": [], "method": "POST", "path": "/",
                   "query_string": b""}, receive)
    assert asyncio.run(server._read_body(req, 1024)) is server.Reason.BODY_TIMEOUT


def test_every_reason_has_a_status_and_a_sentence():
    assert set(server._REFUSALS) == set(server.Reason)


def test_the_cap_is_derived_from_the_manifest_input_bound():
    from andyur.registry.models import MAX_INPUT_BYTES
    assert server.MAX_BODY_BYTES == 2 * MAX_INPUT_BYTES


# -- the served page -----------------------------------------------------------

def test_the_served_html_contains_no_credential(client):
    body = client.get("/").text
    assert "andyur" in body.lower()                 # it IS the console page
    assert SECRET not in body and LAUNCH not in body  # nothing session-bound is baked in
    assert "Bearer " not in body                     # nor any operator token
    assert "spiffe://" not in body


def test_the_served_page_has_nothing_inline(client):
    # The CSP forbids inline script and style; this pins that the page never
    # needs them, with the same parser-based check the live gate runs.
    assert pagecheck.inline_violations(client.get("/").text) == []
    js = client.get("/app.js")
    assert js.headers["content-type"].startswith(("text/javascript", "application/javascript"))
    # THE HEADER THE PAGE SENDS IS ASSERTED IN tests/test_console_page.py, by
    # driving the real script and reading the request it makes. It is NOT
    # asserted here, and the source-literal form that used to live here was
    # worse than nothing: `STORE_KEY` holds the identical string, so the set of
    # andyur-* literals was satisfied whether or not the fetch used the header
    # at all -- a console that authenticated under a wrong name entirely passed
    # 3,099 tests. A grep of a file cannot answer a question about a request.
    assert client.get("/app.css").headers["content-type"].startswith("text/css")


def test_the_page_script_renders_no_inline_style_or_handler(client):
    # The CSP has no 'unsafe-inline' for style either, and every page the
    # console shows is markup this script BUILDS, so the same parser that
    # checks the served page has to see that markup too. A regex over the
    # source missed the quote-adjacent, escaped-quote and unquoted forms, and
    # could not see inside a template's ${...} holes at all.
    js = client.get("/app.js").text
    literals = js_literals(js)
    # positive control: a scanner that returned nothing would pass vacuously.
    assert any("<table>" in lit for lit in literals), "the scanner found no markup"
    assert len(literals) > 200, len(literals)
    for lit in literals:
        assert pagecheck.inline_violations(lit) == [], lit[:200]
    # setAttribute is the one path that builds an attribute without markup, so
    # the parser can never see it.
    assert not re.search(r"""setAttribute\(\s*["'](style|on[a-z]+)["']""", js)


@pytest.mark.parametrize("src,expect", [
    ("x = `<p style=\"a\">`;", "style"),                       # in a template
    ("x = `<div>${c?'<b style=\"a\">':''}</div>`;", "style"),  # inside a ${} hole
    ("x = `<a href=\"x\"onclick=\"y()\">`;", "onclick"),     # no space before the handler
    ("x = `<p style=color:red>`;", "style"),                     # unquoted value
    # The trap this scanner exists for: app.js escapes with a regex literal
    # whose character class holds a quote and a backtick. A scanner that reads
    # that as a string mis-reads every literal after it and reports nothing.
    ("f=s=>s.replace(/[&<>\"'`]/g,c=>c); x = `<p style=\"a\">`;", "style"),
    ("x = `<p class=\"a\">`;", None),
])
def test_the_js_scanner_sees_what_chrome_would_block(src, expect):
    found = [v for lit in js_literals(src) for v in pagecheck.inline_violations(lit)]
    if expect is None:
        assert found == []
    else:
        assert found and expect in found[0], found


@pytest.mark.parametrize("html,expect", [
    ('<button onclick="x()">', "onclick"),
    ('<button/onclick="x()">', "onclick"),
    ('<a href="x"onclick="y()">', "onclick"),
    ('<div\nonLoad="z">', "onload"),
    ('<p style="color:red">', "style"),
    ('<style>a{}</style>', "<style>"),
    ('<script>alert(1)</script>', "<script>"),
    ('<script src="/app.js"></script><p class="ok">', None),
])
def test_the_inline_check_sees_what_a_browser_sees(html, expect):
    found = pagecheck.inline_violations(html)
    if expect is None:
        assert found == []
    else:
        assert found and expect in found[0]


def test_healthz_needs_no_secret_and_carries_the_trace_ui_template(client, monkeypatch):
    r = client.get("/healthz")
    assert r.status_code == 200 and "trace_ui" in r.json()
    monkeypatch.setattr(server, "TRACE_UI_URL", "http://jaeger/trace/{trace_id}")
    assert client.get("/healthz").json()["trace_ui"] == "http://jaeger/trace/{trace_id}"


def _api_calls(js):
    """Every api('<METHOD>', <path expr>) in app.js as (method, expr): the
    expression runs to the first `,` or `)` at parenthesis depth zero."""
    import re
    out = []
    for m in re.finditer(r"api\(\s*'([A-Z]+)'\s*,\s*", js):
        i, depth, expr = m.end(), 0, ""
        while i < len(js):
            c = js[i]
            if c == "'" :
                j = js.index("'", i + 1); expr += js[i:j + 1]; i = j + 1; continue
            if c == "(": depth += 1
            if c == ")":
                if depth == 0: break
                depth -= 1
            if c == "," and depth == 0: break
            expr += c; i += 1
        out.append((m.group(1), expr.strip()))
    return out


def test_every_api_path_the_page_calls_is_on_the_allowlist(client):
    # drift guard: a page that calls a route the BFF refuses would fail only
    # in a browser. Static analysis of app.js: every api() call's path
    # expression, with its JS pieces replaced by placeholder segments (the
    # lifecycle verb by one of its values).
    js = client.get("/app.js").text
    calls = _api_calls(js)
    assert len(calls) >= 12, calls
    # _api_calls only recognises api('METHOD', ...) with single quotes. A call
    # written api("POST", ...) or api(M, ...) would be invisible to it and the
    # guard would pass while the page called a route the BFF refuses. The only
    # other `api(` in the file is the function's own definition.
    assert js.count("api(") == len(calls) + 1, (js.count("api("), len(calls))
    verbs = ("pause", "resume", "halt", "unhalt")      # the values ACTIONS hands to `verb`
    for method, expr in calls:
        pieces = [p.strip() for p in expr.split("+")]
        paths = ["".join(p.strip("'") if p.startswith("'") else (v if p.endswith("verb") else "x")
                         for p in pieces).split("?")[0] for v in verbs]
        assert any(server._allowed(method, path) for path in paths), (method, expr, paths[0])


def test_a_csp_and_security_headers_are_set(client):
    # Every directive is pinned, on the UI, the assets and the API alike:
    # connect-src 'self' stops background fetches to another host and
    # script/style-src 'self' with NO 'unsafe-inline' is what makes a markup
    # injection inert.
    expected = ("default-src 'self'; connect-src 'self'; img-src 'self'; "
                "script-src 'self'; style-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
    for path in ("/", "/app.js", "/app.css", "/api/agents", "/healthz"):
        r = client.get(path, headers=_h())
        assert r.headers.get("content-security-policy") == expected, path
        assert r.headers.get("referrer-policy") == "no-referrer", path
        assert r.headers.get("x-content-type-options") == "nosniff", path


def test_dynamic_responses_are_never_cached(client):
    assert client.get("/api/agents", headers=_h()).headers["cache-control"] == "no-store"
    assert client.get("/api/nope", headers=_h()).headers["cache-control"] == "no-store"
    assert _exchange(client).headers["cache-control"] == "no-store"
    assert client.get("/app.css").headers.get("cache-control") != "no-store"


# -- every refusal is named, logged and redacted -------------------------------

def test_every_refusal_carries_its_reason_by_name_and_is_logged(client, caplog):
    # the page, the log line and the span all use this one word
    with caplog.at_level(logging.INFO, logger="andyur.console"):
        assert client.get("/api/agents").json()["reason"] == "bad_session"
        assert client.get("/api/agents", headers=_h(origin="http://x")).json()["reason"] == "cross_origin"
        assert client.get("/api/nope", headers=_h()).json()["reason"] == "not_a_console_route"
    logged = [r.event_fields for r in caplog.records if getattr(r, "event_name", "") == "console.refuse"]
    assert [f["console_reason"] for f in logged] == ["bad_session", "cross_origin",
                                                     "not_a_console_route"]
    # the same line also carries the PLATFORM bucket, so console refusals group
    # with every other refusal on the platform
    assert [f["reason"] for f in logged] == ["refused", "refused", "invalid"]
    assert all(f["status"] in (401, 403) and f["method"] == "GET" for f in logged)
    assert SECRET not in caplog.text and "nope" not in str(logged)      # names, never paths
    assert logged[0]["route"] == "agents.list"     # a refusal on a known route names it
    assert logged[2]["route"] == ""


def test_the_console_reason_vocabulary_is_registered_with_the_module_that_owns_it():
    # The console refusal words are a log dimension, so the module that decides
    # what may appear in a log lists them. Adding a Reason without registering
    # it there would raise at the moment of the refusal -- in production, on the
    # path whose job is to explain a refusal.
    assert {r.value for r in server.Reason} == observability._CONSOLE_REASONS
    # and every one of them buckets into the platform's own vocabulary
    assert set(server._REASON_BUCKET) == set(server.Reason)
    assert set(server._REASON_BUCKET.values()) <= observability._REASONS


def test_a_client_chosen_method_token_is_bucketed_in_details_and_logs(client, caplog):
    with caplog.at_level(logging.INFO, logger="andyur.console"):
        r = client.request("PROPFIND" * 40, "/session")
    assert r.status_code == 405 and "PROPFIND" not in r.text and "OTHER" in r.json()["detail"]
    assert [x.event_fields["method"] for x in caplog.records
            if getattr(x, "event_name", "") == "console.refuse"] == ["OTHER"]


def test_refusal_details_are_redacted():
    # a failure cause that contains a token must not reach the browser
    def handler(request):
        raise httpx.ConnectError("refused by http://u:p@cp Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig")
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/agents", headers=_h())
    assert r.status_code == 502 and r.json()["reason"] == "upstream_unreachable"
    assert "eyJ" not in r.text and "u:p@" not in r.text
    assert "<redacted>" in r.json()["detail"]


# -- the proxy relays the control plane faithfully -----------------------------

def test_upstream_status_and_body_pass_through():
    # a control plane that says 404 must reach the UI as 404 + its detail, not
    # be flattened to 200 -- the UI's whole error branch depends on it.
    def handler(request):
        return httpx.Response(404, json={"detail": "no agent named 'x'"})
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/agents/x", headers=_h())
    assert r.status_code == 404
    assert r.json()["detail"] == "no agent named 'x'"


def test_a_forwarded_content_type_reaches_the_control_plane():
    seen = {}
    def handler(request):
        seen["ct"] = request.headers.get("content-type")
        seen["ae"] = request.headers.get("accept-encoding")
        return httpx.Response(201, json={})
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    # a distinctive type, so a proxy that hardcodes application/json fails
    _client(upstream=up).post("/api/agents", headers={**_h(), "content-type": "text/plain; charset=acme"},
                              content=b"x")
    assert seen["ct"] == "text/plain; charset=acme"
    assert seen["ae"] == "identity"          # the response cap counts wire bytes


def test_an_unreachable_control_plane_is_a_502_with_a_detail():
    # the BFF's own error must speak the control plane's {"detail": ...} shape so
    # the UI surfaces it rather than a bare "Bad Gateway".
    def handler(request):
        raise httpx.ConnectError("connection refused")
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/agents", headers=_h())
    assert r.status_code == 502
    assert "unreachable" in r.json()["detail"]
    assert r.json()["reason"] == "upstream_unreachable"


def test_a_truncated_upstream_body_is_a_protocol_error_not_unreachable():
    def handler(request):
        raise httpx.RemoteProtocolError("peer closed connection without sending complete message body")
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/agents", headers=_h())
    assert r.status_code == 502 and r.json()["reason"] == "upstream_protocol_error"


def test_the_control_planes_own_challenge_and_allow_headers_pass_through():
    def handler(request):
        return httpx.Response(401, json={"detail": "bad svid"},
                              headers={"www-authenticate": 'Bearer realm="cp"', "x-other": "no"})
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/me", headers=_h())
    assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer realm="cp"'
    assert "x-other" not in r.headers          # only the RFC-required ones travel


def test_an_upstream_read_timeout_is_a_named_504():
    def handler(request):
        raise httpx.ReadTimeout("slow")
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/agents", headers=_h())
    assert r.status_code == 504 and r.json()["reason"] == "upstream_timeout"


def test_an_upstream_that_trickles_past_the_deadline_is_a_named_504(monkeypatch):
    # httpx's timeout is per read; only the total deadline stops a trickle
    monkeypatch.setattr(server, "UPSTREAM_DEADLINE", 0.2)
    async def trickle():
        for _ in range(50):
            await asyncio.sleep(0.05)
            yield b"x"
    def handler(request):
        return httpx.Response(200, content=trickle())
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/agents", headers=_h())
    assert r.status_code == 504 and r.json()["reason"] == "upstream_timeout"


def test_an_oversized_upstream_response_is_refused_not_buffered():
    def handler(request):
        return httpx.Response(200, content=b"y" * (server.MAX_BODY_BYTES + 1))
    up = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(handler))
    r = _client(upstream=up).get("/api/agents", headers=_h())
    assert r.status_code == 502 and r.json()["reason"] == "upstream_too_large"
    # positive control: a body at the cap passes through whole
    def ok(request):
        return httpx.Response(200, content=b"y" * server.MAX_BODY_BYTES)
    up2 = httpx.AsyncClient(base_url="http://cp", transport=httpx.MockTransport(ok))
    assert len(_client(upstream=up2).get("/api/agents", headers=_h()).content) == server.MAX_BODY_BYTES


def test_a_failing_operator_identity_is_a_named_503_not_a_traceback():
    # The upstream client fetches a JWT-SVID per request through its auth flow;
    # when SPIRE is not there that flow raises IdentityUnavailable. Seen live
    # as a raw 500 (Starlette's traceback page) before this was named.
    class _NoSpire(httpx.Auth):
        async def async_auth_flow(self, request):
            raise server.IdentityUnavailable('SPIFFE socket file "/x/api.sock" does not exist')
            yield request  # pragma: no cover
    up = httpx.AsyncClient(base_url="http://cp", auth=_NoSpire(),
                           transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    r = _client(upstream=up).get("/api/agents", headers=_h())
    assert r.status_code == 503
    assert r.json()["reason"] == "identity_unavailable"
    assert "api.sock" in r.json()["detail"] and "run.sh up" in r.json()["detail"]
    assert r.headers["cache-control"] == "no-store"   # went through the middleware


def test_any_other_auth_failure_is_not_disguised_as_an_identity_problem():
    # a bug in the auth flow must surface as a bug, not be labelled by guess
    class _Bug(httpx.Auth):
        async def async_auth_flow(self, request):
            raise RuntimeError("programming error")
            yield request  # pragma: no cover
    up = httpx.AsyncClient(base_url="http://cp", auth=_Bug(),
                           transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(RuntimeError):
        _client(upstream=up).get("/api/agents", headers=_h())


# -- the user session (user-auth mode) -----------------------------------------

def _echo_header_upstream(seen):
    def handler(request):
        seen.append(request.headers.get("x-andyur-user-token"))
        return httpx.Response(200, json={"ok": True})
    return httpx.AsyncClient(base_url="http://cp",
                             transport=httpx.MockTransport(handler))


def _idp(responses):
    """A mock IdP token endpoint: pops canned responses per refresh POST."""
    calls = []
    def handler(request):
        calls.append(dict(httpx.QueryParams(request.content.decode())))
        status, body = responses.pop(0)
        return httpx.Response(status, json=body)
    return calls, httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_the_user_token_rides_every_proxied_call_but_never_the_browser_leg():
    seen = []
    session = server.UserSession(
        {"access_token": "user-tok"},           # no refresh token, no expiry
        token_endpoint="http://idp/token", client_id="andyur-cli")
    c = _client(upstream=_echo_header_upstream(seen), user_session=session)
    r = c.get("/api/agents", headers=_h())
    assert r.status_code == 200 and seen == ["user-tok"]
    # the served page never carries the user token either
    assert "user-tok" not in c.get("/").text


def test_without_a_user_session_no_user_header_is_invented():
    seen = []
    c = _client(upstream=_echo_header_upstream(seen))
    c.get("/api/agents", headers=_h())
    assert seen == [None]


def test_a_browser_supplied_user_token_is_dropped_not_forwarded():
    # a page holding the session secret must not be able to pick its own user
    # identity: the proxy builds headers from scratch and injects the token
    # itself, so an inbound x-andyur-user-token never rides through.
    seen = []
    # no user_session: the upstream must see None, not the browser's value
    c = _client(upstream=_echo_header_upstream(seen))
    c.get("/api/agents", headers={**_h(), "x-andyur-user-token": "attacker-picked"})
    assert seen == [None]
    # with a session, the SESSION's token rides -- never the browser's
    seen2 = []
    session = server.UserSession({"access_token": "session-tok"},
                                 token_endpoint="http://idp/token", client_id="andyur-cli")
    c2 = _client(upstream=_echo_header_upstream(seen2), user_session=session)
    c2.get("/api/agents", headers={**_h(), "x-andyur-user-token": "attacker-picked"})
    assert seen2 == ["session-tok"]


def test_an_expired_access_token_is_refreshed_before_the_call():
    seen = []
    calls, idp = _idp([(200, {"access_token": "fresh-tok",
                              "refresh_token": "rt2", "expires_in": 300})])
    # DISTINCTIVE client id (not the CLIENT_ID constant), so the wire assertion
    # below proves the refresh POST carries the SESSION's client, not a hardcoded
    # constant -- the exact regression a hardcoded refresh client_id would hide.
    session = server.UserSession(
        {"access_token": "stale-tok", "refresh_token": "rt1", "expires_in": 1},
        token_endpoint="http://idp/token", client_id="acme-refresh-client")
    session._expires_at = 0                      # force "already expired"
    c = _client(upstream=_echo_header_upstream(seen), user_session=session, idp=idp)
    assert c.get("/api/agents", headers=_h()).status_code == 200
    assert seen == ["fresh-tok"]                 # never the stale one
    assert calls == [{"grant_type": "refresh_token", "refresh_token": "rt1",
                      "client_id": "acme-refresh-client"}]
    # rotation absorbed: the NEXT refresh would spend rt2, not rt1
    assert session._refresh == "rt2"


def test_the_rotated_refresh_token_is_spent_on_the_next_refresh_not_the_old_one():
    # rotation absorption, proven through the seam: after refresh #1 returns rt2,
    # refresh #2 must present rt2 -- re-presenting rt1 would be a replay.
    seen = []
    calls, idp = _idp([
        (200, {"access_token": "a2", "refresh_token": "rt2", "expires_in": 1}),
        (200, {"access_token": "a3", "refresh_token": "rt3", "expires_in": 300}),
    ])
    session = server.UserSession(
        {"access_token": "a1", "refresh_token": "rt1", "expires_in": 1},
        token_endpoint="http://idp/token", client_id="andyur-cli")
    session._expires_at = 0
    c = _client(upstream=_echo_header_upstream(seen), user_session=session, idp=idp)
    assert c.get("/api/agents", headers=_h()).json()  # refresh #1 spends rt1 -> a2/rt2
    session._expires_at = 0                            # force refresh #2
    assert c.get("/api/agents", headers=_h()).json()  # refresh #2 spends rt2 -> a3
    assert [call["refresh_token"] for call in calls] == ["rt1", "rt2"]
    assert seen == ["a2", "a3"]


def test_a_refused_refresh_is_a_401_asking_to_sign_in_again():
    seen = []
    calls, idp = _idp([(400, {"error": "invalid_grant" + "x" * 500})])
    session = server.UserSession(
        {"access_token": "stale", "refresh_token": "rt1", "expires_in": 1},
        token_endpoint="http://idp/token", client_id="andyur-cli")
    session._expires_at = 0
    c = _client(upstream=_echo_header_upstream(seen), user_session=session, idp=idp)
    r = c.get("/api/agents", headers=_h())
    assert r.status_code == 401
    assert "sign in again" in r.json()["detail"]
    assert r.json()["reason"] == "session_expired"
    assert r.headers["www-authenticate"].startswith("ConsoleSession ")
    assert len(r.json()["detail"]) < 200         # the IdP's error code is bounded
    assert seen == []                            # the stale token was never sent


def test_a_dead_session_stops_hammering_the_idp():
    # after a refused refresh, later calls must NOT re-POST the (now spent)
    # refresh token -- the session is latched dead and answers from state.
    calls, idp = _idp([(400, {"error": "invalid_grant"})])
    session = server.UserSession(
        {"access_token": "stale", "refresh_token": "rt1", "expires_in": 1},
        token_endpoint="http://idp/token", client_id="andyur-cli")
    session._expires_at = 0
    c = _client(upstream=_echo_header_upstream([]), user_session=session, idp=idp)
    for _ in range(4):
        assert c.get("/api/agents", headers=_h()).status_code == 401
    assert len(calls) == 1                       # exactly ONE token-endpoint POST


def test_a_short_lived_token_does_not_refresh_on_every_call():
    # the early window is clamped to half the lifetime: a 10s token must not
    # trip the 30s default lead and refresh on the very next request.
    calls, idp = _idp([])                        # a refresh here would IndexError
    session = server.UserSession(
        {"access_token": "shortlived", "refresh_token": "rt1", "expires_in": 10},
        token_endpoint="http://idp/token", client_id="andyur-cli")
    seen = []
    c = _client(upstream=_echo_header_upstream(seen), user_session=session, idp=idp)
    assert c.get("/api/agents", headers=_h()).status_code == 200
    assert seen == ["shortlived"] and calls == []


def test_a_live_access_token_is_not_refreshed():
    # a genuinely live session must reach upstream WITHOUT any IdP round trip.
    def refuse(request):
        raise AssertionError("refreshed a live token")
    idp = httpx.AsyncClient(transport=httpx.MockTransport(refuse))
    session = server.UserSession(
        {"access_token": "live-tok", "refresh_token": "rt1", "expires_in": 300},
        token_endpoint="http://idp/token", client_id="andyur-cli")
    seen = []
    c = _client(upstream=_echo_header_upstream(seen), user_session=session, idp=idp)
    assert c.get("/api/agents", headers=_h()).status_code == 200
    assert seen == ["live-tok"]


def test_an_exported_setting_beats_a_checked_out_env_file(tmp_path, monkeypatch):
    """A value the operator EXPORTED must win over a file in the checkout.

    `load_dotenv(override=True)` did the opposite, and it rewrites os.environ
    itself, so every child process inherited the file's value too: a gate that
    ran `export ANDYUR_OTEL=on` exercised a DARK console and then failed
    reporting that the collector was down. It went unnoticed because the main
    checkout has no .env at all.
    """
    env_file = tmp_path / ".env"
    env_file.write_text("ANDYUR_OTEL=off\nANDYUR_ONLY_IN_FILE=from_file\n")
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path / "pkg")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / ".env").write_text("ANDYUR_OTEL=off\n")
    monkeypatch.setenv("ANDYUR_OTEL", "on")
    monkeypatch.delenv("ANDYUR_ONLY_IN_FILE", raising=False)

    config._load_env()

    assert os.environ["ANDYUR_OTEL"] == "on"          # the export wins
    # positive control: the file is still read for anything NOT exported, so
    # the assertion above is precedence and not the loader being disabled
    assert os.environ.get("ANDYUR_ONLY_IN_FILE") == "from_file"

"""ADR-003 bar items proven over REAL sockets, not MockTransport.

The phase-2 suite proves streaming and pooling against httpx.MockTransport,
which exercises the sidecar's code but not the wire: a regression that buffers
inside uvicorn/starlette framing, or a client config that opens a fresh
upstream connection per call, would stay green there. Here the sidecar runs
under a real uvicorn on a real loopback socket, and the upstream tool is a
real HTTP/1.1 server that (a) refuses to finish its response until the client
has PROVEN it received the first chunk, and (b) counts distinct TCP
connections. Causal gating, not sleeps: a buffering sidecar deadlocks into a
clean timeout failure rather than passing by luck.
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import http.server
import ipaddress
import json
import ssl
import threading
import time

import httpx
import pytest
import uvicorn

from andyur.proxy import app as proxy_app
from andyur.proxy import sidecar as sc


def _fake_exchange(**_kw):
    # The exchange is not this file's subject; the local and external legs
    # have their own live proofs (registry gate, actor-leg step 6).
    return {"access_token": "MINTED", "expires_in": 300}


class _Upstream:
    """A real HTTP/1.1 tool stub: chunked responses, keep-alive, and counters.

    `release` gates the SECOND chunk of a streamed response; the test sets it
    only after the client has read the first chunk, so chunk-1-before-
    upstream-completion is proven by construction.
    """

    def __init__(self):
        self.connections = 0
        self.requests = 0
        self.release = threading.Event()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):                       # once per TCP connection
                outer.connections += 1
                super().setup()

            def log_message(self, *a):             # keep test output clean
                pass

            def do_POST(self):
                outer.requests += 1
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                def chunk(data: bytes):
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                    self.wfile.flush()

                if self.path.endswith("/mcp"):
                    chunk(b'{"first":')
                    # refuse to complete until the client proves receipt
                    if not outer.release.wait(timeout=10):
                        # deadlock = the sidecar buffered; end the response so
                        # the failure is an assertion, not a hung suite
                        chunk(b' "NEVER-RELEASED"}')
                    else:
                        chunk(b' true, "second": true}')
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@contextlib.contextmanager
def _serve(app):
    """Run the app under a REAL uvicorn on a loopback socket; yield its base URL."""
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline, \
            "sidecar never came up"
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture
def live_sidecar():
    """The REAL proxy app under a REAL uvicorn, pointed at a real upstream."""
    upstream = _Upstream()
    route = sc.ToolRoute.from_managed("t", {
        "url": f"http://127.0.0.1:{upstream.port}/mcp",
        "audience": "resource:t", "scheme": "http", "host": "127.0.0.1",
        "port": upstream.port, "path": "/mcp"})
    app = proxy_app.build_app(
        router=sc.Router({"t": route}),
        identity=sc.RunIdentity("T0", lambda: "SVID", lambda: {}),
        scope=["t:use"], pin=None, gateway_url="",
        exchange_fn=_fake_exchange,
        # ONE pooled client, exactly as build_app's default constructs it,
        # minus the mTLS material this host cannot mint
        tool_client_factory=lambda: httpx.AsyncClient(
            timeout=httpx.Timeout(10.0), limits=proxy_app._LIMITS))
    with _serve(app) as base:
        yield base, upstream
    upstream.stop()


def test_sidecar_streams_first_chunk_before_upstream_completes(live_sidecar):
    base, upstream = live_sidecar
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    got = b""
    with httpx.Client(timeout=10.0) as client:
        with client.stream("POST", f"{base}/tools/t/mcp", content=body) as r:
            assert r.status_code == 200
            for chunk in r.iter_raw():
                got += chunk
                if b'"first":' in got and not upstream.release.is_set():
                    # chunk 1 arrived while the upstream response is still
                    # OPEN (it is blocked on this very event) -- incremental
                    # delivery proven causally, so NOW let it finish
                    upstream.release.set()
    assert b'"second": true' in got
    # the gate never timed out: completion happened because we released it
    assert b"NEVER-RELEASED" not in got, \
        "the sidecar buffered the response; upstream finished by timeout"


def test_sidecar_reuses_one_upstream_connection_across_calls(live_sidecar):
    base, upstream = live_sidecar
    upstream.release.set()                         # no gating for this one
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    with httpx.Client(timeout=10.0) as client:
        for _ in range(3):
            r = client.post(f"{base}/tools/t/mcp", content=body)
            assert r.status_code == 200
    assert upstream.requests == 3
    # one pooled keep-alive connection served all three calls; a
    # client-per-request regression shows up as three TCP connections
    assert upstream.connections == 1, \
        f"expected one pooled upstream connection, saw {upstream.connections}"


# --- the https tool leg: a real handshake with the run's cert -----------------

def _issue(cn: str, *, ca=None, ip: str | None = None):
    """An ephemeral cert (and key), self-signed CA or CA-signed leaf."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name)
               .issuer_name(ca[0].subject if ca else name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(hours=1)))
    if ca is None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if ip is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
    return builder.sign(ca[1] if ca else key, hashes.SHA256()), key


def _pem(tmp_path, name: str, cert=None, key=None) -> str:
    from cryptography.hazmat.primitives import serialization
    blob = b""
    if cert is not None:
        blob += cert.public_bytes(serialization.Encoding.PEM)
    if key is not None:
        blob += key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
    path = tmp_path / name
    path.write_bytes(blob)
    return str(path)


class _TlsUpstream:
    """A real TLS tool stub that REQUIRES a client certificate, recording which
    one the peer presented and the Authorization it carried."""

    def __init__(self, cert_path: str, key_path: str, ca_path: str):
        self.peer_cert_sha256 = None
        self.authorization = None
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                outer.peer_cert_sha256 = hashlib.sha256(
                    self.connection.getpeercert(binary_form=True)).hexdigest()
                outer.authorization = self.headers.get("Authorization")
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.load_verify_locations(ca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def test_https_reach_url_presents_the_run_cert_and_carries_the_bearer(tmp_path):
    """The wire property the sender-bound story depends on, proven on a real
    socket: an https reach_url produces a real TLS handshake in which the
    sidecar's DEFAULT tool client presents the run's X509-SVID, and the
    delegated bearer travels only inside that channel. With the upstream URL
    rebuilt as http:// (the pre-fix behavior) the handshake never happens, the
    loaded cert is never presented, and this test fails."""
    from cryptography.hazmat.primitives import serialization

    ca = _issue("test-ca")
    server_cert, server_key = _issue("tool", ca=ca, ip="127.0.0.1")
    run_cert, run_key = _issue("run-svid", ca=ca)
    ca_path = _pem(tmp_path, "ca.pem", cert=ca[0])
    upstream = _TlsUpstream(
        _pem(tmp_path, "server.pem", cert=server_cert),
        _pem(tmp_path, "server.key", key=server_key),
        ca_path)
    route = sc.ToolRoute.from_managed("t", {
        "url": f"https://127.0.0.1:{upstream.port}/mcp",
        "audience": "resource:t", "scheme": "https", "host": "127.0.0.1",
        "port": upstream.port, "path": "/mcp"})
    # No tool_client_factory override: the point is the REAL default client,
    # built from the run's mTLS material exactly as production wires it.
    app = proxy_app.build_app(
        router=sc.Router({"t": route}),
        identity=sc.RunIdentity(
            "T0", lambda: "SVID",
            lambda: {"cert": _pem(tmp_path, "run.pem", cert=run_cert),
                     "key": _pem(tmp_path, "run.key", key=run_key),
                     "bundle": ca_path}),
        scope=["t:use"], pin=None, gateway_url="",
        exchange_fn=_fake_exchange)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    try:
        with _serve(app) as base, httpx.Client(timeout=10.0) as client:
            r = client.post(f"{base}/tools/t/mcp", content=body)
        assert r.status_code == 200
    finally:
        upstream.stop()
    expected = hashlib.sha256(
        run_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert upstream.peer_cert_sha256 == expected, \
        "the tool did not see the run's own certificate on the wire"
    assert upstream.authorization == "Bearer MINTED", \
        "the delegated bearer did not ride the mutually authenticated channel"

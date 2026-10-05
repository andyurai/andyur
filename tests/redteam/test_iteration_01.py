"""ITERATION 01 -- seven-persona review of the external-AS work, 7 August 2026.

Red-team regressions for the login and gateway-config surface. See
`tests/redteam/README.md` for the convention.

Every test here encodes an attack that was RUN against this code, not one that
was imagined. Two of them landed and are now fixed; the rest are controls that
held and are kept so a later change cannot silently re-open them.

The attack scripts themselves lived in a session scratch directory that does not
survive, which is why they are here instead: a finding with no test is a finding
that comes back.
"""

import json
import os
import stat
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytestmark = pytest.mark.redteam

from andyur import authlogin


# --------------------------------------------------------------------------
# LANDED: the credentials file followed a planted symlink
# --------------------------------------------------------------------------

def test_save_token_refuses_to_write_through_a_symlink(tmp_path, monkeypatch):
    """Reproduced before the fix: a symlink at the credentials path truncated the
    victim file, wrote the bearer token through it, and forced it to mode 0600.

    `gateway.py` already used O_EXCL for exactly this; the one writer holding a
    CREDENTIAL was the one that did not.
    """
    home = tmp_path / "home"
    home.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("important original content")
    (home / "credentials.json").symlink_to(victim)
    monkeypatch.setenv("ANDYUR_HOME", str(home))

    with pytest.raises(Exception):
        authlogin.save_token({"access_token": "SECRET.TOKEN.VALUE"})

    assert victim.read_text() == "important original content", "victim was written"
    assert "SECRET" not in victim.read_text()


def test_save_token_writes_0600_and_is_readable_back(tmp_path, monkeypatch):
    """Positive control: the refusal above must not be a writer that never works."""
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    p = authlogin.save_token({"access_token": "T0.for.alice"})
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert authlogin.load_token() == "T0.for.alice"


def test_save_token_leaves_no_temp_file_behind(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    authlogin.save_token({"access_token": "x"})
    assert [p.name for p in tmp_path.iterdir()] == ["credentials.json"]


# --------------------------------------------------------------------------
# LANDED: a poisoned discovery document exfiltrated the code and the verifier
# --------------------------------------------------------------------------

def _discovery_server(doc):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/.well-known/openid-configuration":
                body = json.dumps(doc(self.server.server_port)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_discovery_refuses_endpoints_off_the_issuers_origin():
    """THE ATTACK THAT LANDED. A document whose `issuer` matched but whose
    `token_endpoint` was on another origin made the client POST the authorization
    code AND the code_verifier to that origin.

    Matching the issuer proves the document is about the right server. It does
    not constrain where the document sends you.
    """
    srv = _discovery_server(lambda port: {
        "issuer": f"http://127.0.0.1:{port}",
        "authorization_endpoint": f"http://127.0.0.1:{port}/authorize",
        "token_endpoint": "http://evil.example/steal",
    })
    try:
        with pytest.raises(RuntimeError) as e:
            authlogin.discover(f"http://127.0.0.1:{srv.server_port}")
        assert "origin" in str(e.value)
    finally:
        srv.shutdown()


def test_discovery_accepts_a_same_origin_document():
    """Positive control for the test above."""
    srv = _discovery_server(lambda port: {
        "issuer": f"http://127.0.0.1:{port}",
        "authorization_endpoint": f"http://127.0.0.1:{port}/authorize",
        "token_endpoint": f"http://127.0.0.1:{port}/token",
    })
    try:
        doc = authlogin.discover(f"http://127.0.0.1:{srv.server_port}")
        assert doc["token_endpoint"].endswith("/token")
    finally:
        srv.shutdown()


def test_discovery_refuses_cleartext_off_loopback():
    """OIDC Discovery sec 3: the issuer is an https URL. Over cleartext anyone on
    the path rewrites the document, and the document names where the code goes."""
    with pytest.raises(RuntimeError) as e:
        authlogin.discover("http://as.example")
    assert "cleartext" in str(e.value) or "http" in str(e.value)


def test_discovery_still_refuses_an_issuer_mismatch():
    """Held before and must keep holding (OIDC Discovery sec 4.3)."""
    srv = _discovery_server(lambda port: {
        "issuer": "http://somewhere.else",
        "authorization_endpoint": f"http://127.0.0.1:{port}/authorize",
        "token_endpoint": f"http://127.0.0.1:{port}/token",
    })
    try:
        with pytest.raises(RuntimeError) as e:
            authlogin.discover(f"http://127.0.0.1:{srv.server_port}")
        assert "issuer mismatch" in str(e.value)
    finally:
        srv.shutdown()


def test_save_token_keeps_only_what_the_cli_uses(tmp_path, monkeypatch):
    """The AS response can carry a refresh_token and id_token; this client uses
    neither, so persisting them is a credential at rest for no reason. The
    relative expires_in becomes an absolute expires_at load_token can honor."""
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    authlogin.save_token({
        "access_token": "AT", "token_type": "Bearer", "expires_in": 3600,
        "refresh_token": "RT-MUST-NOT-PERSIST", "id_token": "IDT-MUST-NOT-PERSIST",
        "issuer": "https://as.example", "scope": "openid"})
    stored = json.loads(authlogin.credentials_path().read_text())
    assert "refresh_token" not in stored and "id_token" not in stored
    assert stored["access_token"] == "AT"
    assert stored["expires_at"] > time.time()
    assert authlogin.load_token() == "AT"


def test_load_token_treats_an_expired_record_as_signed_out(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    authlogin.save_token({"access_token": "AT", "expires_in": 3600})
    stored = json.loads(authlogin.credentials_path().read_text())
    stored["expires_at"] = int(time.time()) - 1
    authlogin.credentials_path().write_text(json.dumps(stored))
    assert authlogin.load_token() is None
    # positive control: a record with no recorded expiry is still honored
    del stored["expires_at"]
    authlogin.credentials_path().write_text(json.dumps(stored))
    assert authlogin.load_token() == "AT"


def test_logout_revokes_best_effort_and_always_unlinks(tmp_path, monkeypatch):
    """RFC 7009 revocation is attempted when the AS advertises it, but an
    unreachable AS must never leave the user unable to sign out locally."""
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    revoked = {}
    authlogin.save_token({"access_token": "AT", "issuer": "https://as.example"})
    monkeypatch.setattr(authlogin, "discover", lambda issuer: {
        "revocation_endpoint": "https://as.example/revoke"})
    monkeypatch.setattr(authlogin.boundedhttp, "post_form",
                        lambda url, form, what="": revoked.update({url: form}) or (200, {}))
    assert authlogin.logout() is True
    assert revoked["https://as.example/revoke"]["token"] == "AT"
    assert not authlogin.credentials_path().exists()
    # discovery failing (offline) still signs out locally
    authlogin.save_token({"access_token": "AT", "issuer": "https://as.example"})
    monkeypatch.setattr(authlogin, "discover",
                        lambda issuer: (_ for _ in ()).throw(RuntimeError("down")))
    assert authlogin.logout() is True
    assert not authlogin.credentials_path().exists()


def test_logout_never_sends_the_token_to_a_cross_origin_revocation_endpoint(
        tmp_path, monkeypatch):
    """A hostile discovery document naming a revocation_endpoint on another
    origin must NOT receive the stored bearer -- the same class of attack the
    discovery token_endpoint origin check defends, one leg over. The local
    unlink still happens."""
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    calls = []
    authlogin.save_token({"access_token": "AT", "issuer": "https://as.example"})
    monkeypatch.setattr(authlogin, "discover", lambda issuer: {
        "revocation_endpoint": "https://evil.example/revoke"})
    monkeypatch.setattr(authlogin.boundedhttp, "post_form",
                        lambda url, form, what="": calls.append(url) or (200, {}))
    assert authlogin.logout() is True
    assert calls == [], "the token was sent to a cross-origin revocation endpoint"
    assert not authlogin.credentials_path().exists()


def test_logout_unlinks_even_when_revocation_raises_a_base_exception(
        tmp_path, monkeypatch):
    """The local sign-out MUST happen even if the best-effort revocation is
    interrupted by a BaseException (e.g. a Ctrl-C during the bounded network
    wait). The unlink lives in a finally, so the credential is gone regardless."""
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    authlogin.save_token({"access_token": "AT", "issuer": "https://as.example"})
    monkeypatch.setattr(authlogin, "discover", lambda issuer: {
        "revocation_endpoint": "https://as.example/revoke"})

    def _interrupt(*a, **k):
        raise KeyboardInterrupt()

    monkeypatch.setattr(authlogin.boundedhttp, "post_form", _interrupt)
    with pytest.raises(KeyboardInterrupt):
        authlogin.logout()
    # the interrupt still propagated, but the credential was removed first
    assert not authlogin.credentials_path().exists()


def test_save_token_coerces_a_string_expires_in(tmp_path, monkeypatch):
    """RFC 6749 recommends numeric expires_in, but real servers send it as a
    JSON string. A silently-inert expiry control is worse than none, so the
    string form must still produce an expires_at."""
    monkeypatch.setenv("ANDYUR_HOME", str(tmp_path))
    authlogin.save_token({"access_token": "AT", "expires_in": "3600"})
    stored = json.loads(authlogin.credentials_path().read_text())
    assert stored["expires_at"] > time.time()
    # a non-numeric expires_in leaves no expiry rather than a guessed one
    authlogin.save_token({"access_token": "AT2", "expires_in": "not-a-number"})
    assert "expires_at" not in json.loads(authlogin.credentials_path().read_text())

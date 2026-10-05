"""`andyur auth login` -- an ordinary OIDC client, and nothing more.

Andyur NEVER renders a password box and never sees a password. This opens the
login page of whichever authorization server is configured, and the user
authenticates there. Standalone Andyur gets the reference AS's page
(`infra/reference-as`); an enterprise gets Okta's or Entra's. Same code either
way, because the only thing that changes is the discovery document.

The flow is RFC 8252 (OAuth for native apps):

  * a PUBLIC client, so no secret is embedded anywhere -- a CLI cannot keep one
  * PKCE, REQUIRED not optional (RFC 9700 sec 2.1.1: a public client MUST use it)
  * a LOOPBACK redirect (sec 7.3), never a custom URI scheme
  * `state`, checked on the callback
  * the listener accepts exactly ONE request and then stops

What this replaces: `ANDYUR_ASSERTED_USER`, where an operator typed a subject and
Andyur signed an assertion that a named human had authorised the action. Nobody
had. Here the user actually authenticates and Andyur holds a token the AS issued.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import logging
import os
import secrets
import stat
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

from . import boundedhttp

log = logging.getLogger(__name__)

# The AS matches redirect_uri EXACTLY -- the variable-port allowance RFC 8252
# sec 7.3 grants loopback clients is not implemented by every server, and the
# reference AS does not implement it. So the ports are a registered candidate
# list and the CLI takes the first one that is free.
PORTS = (8765, 8766, 8767, 8768, 8769)
CLIENT_ID = "andyur-cli"

# Loopback only. Binding 0.0.0.0 would let anything on the network deliver a
# code to this listener.
HOST = "127.0.0.1"


def credentials_path() -> Path:
    return Path(os.environ.get("ANDYUR_HOME") or (Path.home() / ".andyur")) / "credentials.json"


def load_token() -> str | None:
    """The stored access token, or None. Never raises: not being logged in is
    an ordinary state, not an error. A record past its recorded expiry is
    treated as not signed in, because presenting a token the AS will refuse
    turns every later command's real error into '401, go figure out why'."""
    try:
        data = json.loads(credentials_path().read_text())
    except (OSError, ValueError):
        return None
    expires_at = data.get("expires_at")
    if isinstance(expires_at, (int, float)) and expires_at <= time.time():
        return None
    tok = data.get("access_token")
    return tok if isinstance(tok, str) and tok else None


def save_token(payload: dict) -> Path:
    # ONLY what later commands read is kept. The AS response also carries
    # whatever else the tenant issues -- refresh_token, id_token -- and this
    # client uses neither, so persisting them would be credentials at rest for
    # no reason. expires_in is a relative offset that means nothing later;
    # stored as the absolute time load_token can compare against.
    kept = {k: payload[k] for k in ("access_token", "token_type", "scope",
                                    "issuer") if k in payload}
    # expires_in per RFC 6749 sec 5.1 is "RECOMMENDED ... in seconds". Some
    # servers send it as a JSON string ("3600"); coerce so the expiry control
    # is not silently inert for those tenants -- a check that quietly stops
    # applying is worse than no check. A non-numeric value is left unset (the
    # token simply has no known expiry) rather than guessed.
    expires_in = payload.get("expires_in")
    if isinstance(expires_in, str):
        try:
            expires_in = float(expires_in)
        except ValueError:
            expires_in = None
    if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) \
            and expires_in > 0:
        kept["expires_at"] = int(time.time() + expires_in)
    payload = kept
    p = credentials_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0600 BEFORE writing. Writing first and chmod-ing after leaves
    # the token world-readable for the width of that window.
    # O_NOFOLLOW so a symlink planted at this path is not followed. Reproduced
    # before this: a symlink at credentials.json truncated the victim file, wrote
    # the bearer token through it, and forced the victim to mode 0600.
    #
    # Written to a fresh temp file and renamed, so there is never a window where
    # the real path exists with the wrong mode or with half a document, and an
    # interrupted write cannot destroy a working credential. `gateway.py` already
    # uses O_EXCL for this reason; the one writer holding a CREDENTIAL was the one
    # that did not.
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        os.unlink(tmp)
    except OSError:
        pass
    fd = os.open(tmp, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh)
        # Refuse to replace a symlink; os.replace would follow it.
        if p.is_symlink():
            raise RuntimeError(
                f"{p} is a symlink; refusing to write a credential through it")
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


def logout() -> bool:
    """Remove the stored credential, revoking it at the AS first when we can.

    Revocation (RFC 7009) is BEST-EFFORT: an unreachable AS or one that does
    not advertise a revocation endpoint must never leave the user unable to
    sign out locally. The unlink is the part that must happen."""
    p = credentials_path()
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        data = {}
    token, issuer = data.get("access_token"), data.get("issuer")
    # The local unlink is the part that MUST happen, so it sits in a finally:
    # best-effort revocation runs first, but a BaseException from the network
    # attempt (a Ctrl-C during the bounded wait, say) must not leave the user
    # unable to sign out locally.
    try:
        revoked = False
        if isinstance(token, str) and token and isinstance(issuer, str) and issuer:
            try:
                endpoint = discover(issuer).get("revocation_endpoint")
                if isinstance(endpoint, str) and _same_origin(endpoint, issuer):
                    boundedhttp.post_form(
                        endpoint,
                        {"token": token, "token_type_hint": "access_token",
                         "client_id": CLIENT_ID},
                        what="the authorization server's revocation endpoint")
                    revoked = True
            except Exception as exc:                           # noqa: BLE001
                # Best-effort, but NOT silent: the caller prints "signed out",
                # and a user who believes the token is dead while it is still
                # valid at the AS is worse off than one told the local copy was
                # removed only.
                log.warning("logout: could not revoke the token at %s (%s: %s); "
                            "the local credential was removed but the token "
                            "remains valid at the authorization server until it "
                            "expires", issuer, type(exc).__name__, exc)
        if not revoked and isinstance(token, str) and token:
            log.info("logout: no reachable revocation endpoint; removed the "
                     "local credential only")
    finally:
        try:
            p.unlink()
            unlinked = True
        except OSError:
            unlinked = False
    return unlinked


def discover(issuer: str) -> dict:
    """OIDC Discovery. The endpoints are READ, never constructed.

    Constructing them is gap G3: `<issuer>/.well-known/jwks.json` 404s against
    Keycloak, whose document advertises a different path entirely.
    """
    parsed = urllib.parse.urlparse(issuer)
    if parsed.scheme != "https" and not _is_loopback(parsed.hostname):
        # OIDC Discovery sec 3 defines the issuer as an https URL. Over cleartext
        # anyone on the path rewrites the document, and the document names the
        # endpoint this process will POST the authorization code to. Loopback is
        # exempt because the standalone reference AS runs there and there is no
        # network to be on the path of.
        raise RuntimeError(
            f"refusing to discover {issuer} over {parsed.scheme or 'no scheme'}: "
            "the discovery document names the endpoint this client sends the "
            "authorization code to, so a rewritten one redirects the credential")

    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    doc = json.loads(boundedhttp.get_bytes(
        url, what="the authorization server's discovery document"))
    for required in ("authorization_endpoint", "token_endpoint", "issuer"):
        if not isinstance(doc.get(required), str):
            raise RuntimeError(
                f"the discovery document at {url} has no {required}; this does "
                "not look like an OpenID Provider")
    if doc["issuer"].rstrip("/") != issuer.rstrip("/"):
        # OIDC Discovery sec 4.3: the issuer in the document MUST match the one
        # used to fetch it, or a hostile document could redirect the whole flow.
        raise RuntimeError(
            f"discovery issuer mismatch: asked {issuer}, document says {doc['issuer']}")

    # THE ENDPOINTS MUST SHARE THE ISSUER'S ORIGIN.
    #
    # The issuer check alone is not enough, and this was reproduced end to end: a
    # document whose `issuer` matched but whose `token_endpoint` pointed at
    # another origin made this client POST the authorization code AND the
    # code_verifier to that origin. Matching the issuer proves the document is
    # about the right server; it does not constrain where it sends you.
    for name in ("authorization_endpoint", "token_endpoint"):
        if not _same_origin(doc[name], issuer):
            raise RuntimeError(
                f"discovery {name} {doc[name]!r} is not on the issuer's origin "
                f"({issuer}); refusing, because this is where the authorization "
                "code and the PKCE verifier would be sent")
    return doc


def _is_loopback(host: str | None) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


def _same_origin(url: str, issuer: str) -> bool:
    a, b = urllib.parse.urlparse(url), urllib.parse.urlparse(issuer)
    return (a.scheme, a.hostname, a.port or _default_port(a.scheme)) == \
           (b.scheme, b.hostname, b.port or _default_port(b.scheme))


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


class _Catcher(http.server.BaseHTTPRequestHandler):
    result: dict = {}

    def do_GET(self):                                    # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        q = urllib.parse.parse_qs(parsed.query)
        type(self).result = {k: v[0] for k, v in q.items()}
        body = (b"<html><body style='font:15px system-ui;text-align:center;"
                b"padding:60px'><h2>Signed in</h2>"
                b"<p>You can close this tab and return to the terminal.</p>"
                b"</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # The URL of this request carries the authorization code.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):                           # noqa: A003
        pass                                             # the code is in the URL


def login(issuer: str, *, scope: str = "openid", audience: str = "",
          resources: tuple[str, ...] = (), open_browser: bool = True,
          timeout: float = 300.0, client_id: str = CLIENT_ID) -> dict:
    """Run the flow and return the AS's token response.

    `client_id` defaults to the CLI's public client; the console passes its own
    dedicated client so the two do not share ROPC/audience configuration."""
    doc = discover(issuer)

    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)

    server = None
    for port in PORTS:
        try:
            server = http.server.HTTPServer((HOST, port), _Catcher)
            break
        except OSError:
            continue
    if server is None:
        raise RuntimeError(
            f"none of the registered loopback ports {PORTS} is free. They are a "
            "fixed list because the authorization server matches redirect_uri "
            "exactly; free one and try again")

    redirect_uri = f"http://{HOST}:{server.server_port}/callback"
    _Catcher.result = {}

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    # RFC 8707. ANDYUR is the audience of the login token, because Andyur is the
    # party that receives and VALIDATES it -- and a consumer must check that `aud`
    # names itself. A token addressed elsewhere being accepted here is the exact
    # failure audience binding exists to prevent.
    #
    # The resource CONSTRAINT (which account the work is about) is deliberately
    # NOT here: it is chosen after authentication, so it cannot be in this token,
    # and it enters at the exchange where one specific tool is being called.
    # RFC 8707 `resource` is REPEATABLE, so the login asks for two different
    # things with one parameter:
    #
    #   audience   Andyur, because Andyur receives this token and a consumer must
    #              check that `aud` names itself.
    #   resources  what the work is ABOUT -- the pin.
    #
    # In STANDALONE the login is the session, so choosing the pin here is
    # choosing it when the session is established. It is also stronger than the
    # alternative: a pin in the token is attested by the authorization server,
    # where a pin in the trigger body is asserted by whoever called the trigger.
    #
    # In a deployment WITH an application in front, the pin is chosen after
    # authentication in that application's session and does not belong here.
    targets = ([audience] if audience else []) + [r for r in resources if r]
    authz = doc["authorization_endpoint"] + "?" + urllib.parse.urlencode(
        {**params, "resource": targets}, doseq=True)

    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    # flush=True on every line: this process then BLOCKS waiting for a callback,
    # and stdout through a pipe is block-buffered, so without it the URL a user
    # needs in order to continue does not appear until the flow has already
    # timed out.
    print(f"opening {doc['authorization_endpoint']} to sign in", flush=True)
    if open_browser and not webbrowser.open(authz):
        print("could not open a browser; visit this URL:", flush=True)
        print(f"  {authz}", flush=True)
    elif not open_browser:
        print(f"  {authz}", flush=True)

    thread.join(timeout)
    server.server_close()
    result = _Catcher.result
    if not result:
        raise RuntimeError(f"no callback received within {timeout:.0f}s")

    if result.get("error"):
        raise RuntimeError(
            f"the authorization server refused: {result['error']} "
            f"{result.get('error_description', '')}".strip())
    # CSRF. Compared in constant time, and BEFORE the code is spent.
    if not secrets.compare_digest(result.get("state", ""), state):
        raise RuntimeError(
            "the callback carried the wrong `state`; discarding it rather than "
            "exchanging a code this client may not have asked for")
    code = result.get("code")
    if not code:
        raise RuntimeError("the callback carried no authorization code")

    token_form = {"grant_type": "authorization_code", "client_id": client_id,
                  "code": code, "redirect_uri": redirect_uri,
                  "code_verifier": verifier}
    if targets:
        token_form["resource"] = targets
    status, body = boundedhttp.post_form(
        doc["token_endpoint"], token_form,
        what="the authorization server's token endpoint")
    if status != 200 or not isinstance(body, dict) or not body.get("access_token"):
        err = (body or {}).get("error") if isinstance(body, dict) else None
        raise RuntimeError(
            f"the code could not be exchanged ({status}"
            + (f", {err}" if err else "") + ")")
    body["issuer"] = doc["issuer"]
    # The token endpoint the code was just exchanged at, so a caller refreshing
    # later (the console's UserSession) reuses this validated value instead of
    # re-running discovery -- one fetch, one set of origin/issuer checks.
    body["token_endpoint"] = doc["token_endpoint"]
    return body

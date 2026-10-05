"""Tool-egress helpers shared by the per-run sidecar.

Once this module hosted a per-run `agentgateway` process as the tool-credential
broker. That path is gone (ADR-003): the per-run sidecar in `andyur/proxy` is
the sole tool egress, and what remains here are the pure, side-effect-free
helpers it still calls:

  * `split_tools` -- partition an mcp.json into the managed tools (those that
    declare platform authority) and the passthrough rest, deriving each managed
    tool's canonical resource id from its URL (ADR-002).
  * `preflight` -- bounded reachability probing before the agent is promised a
    tool, so an unreachable upstream is a named withhold rather than a failed
    MCP `initialize` the agent cannot explain.
  * `local_exchange` / `_server_host_port` -- the LOCAL-mint exchange_fn the
    sidecar uses when Andyur is the authorization server: the RFC 8693 form
    POSTed to Andyur's own `/oauth/token`, authenticated by the run token, with
    the run's JWT-SVID as the Authorization leg.
  * `MINT_BUDGET`, `discovery_enabled` -- the per-run mint preflight's total
    budget and the RFC 9728 discovery flag the sidecar reports (it does not
    apply discovery; the registry is the binding authority).

The external-AS exchange lives in `andyur/server/asclient`; the sidecar's data
plane (strip, mint, mTLS, stream) lives in `andyur/proxy`.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
import urllib.parse
from urllib.parse import urlparse

from .. import config, identity

log = logging.getLogger(__name__)

_PREFLIGHT_TIMEOUT = float(os.environ.get("ANDYUR_GATEWAY_PREFLIGHT_TIMEOUT", "2"))
# Total wall clock preflight may consume, however many servers are declared. Each
# probe is serial and a blackholed host costs the full per-host timeout, and this
# runs synchronously on the runner's event loop.
_PREFLIGHT_BUDGET = float(os.environ.get("ANDYUR_GATEWAY_PREFLIGHT_BUDGET", "10"))
# Each managed tool costs an ephemeral port and a preflight probe. Operator-
# written config, but a typo should not cost the run its ports.
_MAX_MANAGED = int(os.environ.get("ANDYUR_GATEWAY_MAX_TOOLS", "32"))
# Total wall clock the startup mint check may consume across ALL audiences. Each
# call is capped, but the set was not, and this runs on the runner's event loop.
MINT_BUDGET = float(os.environ.get("ANDYUR_GATEWAY_MINT_BUDGET", "10"))


class GatewayUnavailable(RuntimeError):
    """The gateway cannot be stood up, so managed tools must be withheld."""


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def split_tools(mcp_servers: dict) -> tuple[dict, dict]:
    """Partition the agent's tool servers into the ones carrying platform
    authority and the ones passed through untouched.

    MANAGED means an http server declaring `andyur.audience`, i.e. one the
    operator has said should be called with platform authority.

    WHY THE AUDIENCE IS SAFE TO READ FROM mcp.json: a run cannot write it.
    `workspace.run_may_write` permits only memory/, artifacts/ and the run's own
    runs/<id>/, so tool configuration is operator-owned. If that ever changes, an
    agent choosing its own audience becomes an agent choosing its own authority.
    """
    managed, passthrough = {}, {}
    for name, cfg in (mcp_servers or {}).items():
        if not isinstance(cfg, dict):
            passthrough[name] = cfg
            continue
        andyur = cfg.get("andyur")
        andyur = andyur if isinstance(andyur, dict) else {}
        # `authority: true` opts a tool in without naming an audience, because
        # under ADR 002 the audience IS this server's canonical resource
        # identifier -- so making an operator type the URL a second time is a
        # second source of truth that can only ever disagree with the first.
        opted_in = bool(andyur) and (andyur.get("authority") is True
                                     or andyur.get("audience"))
        declared = andyur.get("audience")
        url = cfg.get("url")
        kind = cfg.get("type", "http")

        if not opted_in:
            # Not opted in. Passed through as it was, minus any stray `andyur`
            # block: it is not part of any SDK server shape, and forwarding an
            # unrecognised key into someone else's config is how a future version
            # of that config starts meaning something we did not intend.
            passthrough[name] = {k: v for k, v in cfg.items() if k != "andyur"}
            continue

        # From here the operator has ASKED for this tool to carry platform
        # authority. Anything we cannot deliver that for is WITHHELD rather than
        # passed through: the alternative is calling it with no token at all,
        # which is the one outcome worse than the tool being missing.
        if len(managed) >= _MAX_MANAGED:
            log.error("tool %s exceeds the %s managed-tool cap; WITHHELD. Each "
                      "one costs a listening socket and a preflight probe",
                      name, _MAX_MANAGED)
            continue
        if not isinstance(url, str) or not url:
            log.error("tool %s asks for platform authority but has no usable "
                      "url; WITHHELD rather than called unauthenticated", name)
            continue
        if kind not in ("http", "streamable-http"):
            # `sse` is the deprecated 2024-11-05 transport: a GET stream plus a
            # POST endpoint the server announces at runtime, which a pinned
            # single upstream cannot represent. Telling the gateway "http" anyway
            # turns a working tool into a broken one with no log line.
            log.error("tool %s uses the '%s' transport, which cannot carry "
                      "platform authority through the gateway; WITHHELD",
                      name, kind)
            continue
        parsed = _split_url(url)
        if parsed is None:
            log.error("tool %s has a url this gateway cannot honour (%r); "
                      "WITHHELD rather than called unauthenticated", name, url)
            continue
        scheme, host, port, path = parsed
        refusal = scheme_refusal(scheme)
        if refusal is not None:
            log.error("tool %s: %s; WITHHELD", name, refusal)
            continue
        # THE AUDIENCE IS THE RESOURCE'S OWN CANONICAL IDENTIFIER (ADR 002).
        #
        # It used to be an opaque operator-written string like `tool:ci`. That is
        # conformant -- RFC 8693 sec 2.1 defines an audience as a logical name --
        # but RFC 8707 sec 3 then makes binding that name to a real endpoint the
        # client's out-of-band job, which in practice meant an operator keeping
        # two facts in agreement by hand. It also meant no standard MCP client
        # could ever obtain a usable token, because MCP sends the server's
        # canonical URL as its `resource`.
        #
        # Derived, so it cannot drift from the URL it names, and so RFC 9728
        # discovery can VERIFY it: the resource's own metadata must declare this
        # exact value (sec 3.3), which turns the audience from something asserted
        # into something proven.
        audience = _canonical_resource(url)
        if declared is not None and declared != audience:
            # Named AND wrong. Refused rather than silently corrected: an
            # operator who wrote an audience believes it means something, and the
            # commonest reason to hit this is a `tool:ci` left over from before
            # ADR 002.
            log.error("tool %s declares andyur.audience %r, but under ADR 002 an "
                      "MCP tool's audience is its canonical resource id, which "
                      "for this url is %r. WITHHELD. Drop the audience (the url "
                      "is enough) or correct it", name, declared, audience)
            continue
        managed[name] = {"url": url, "audience": audience, "scheme": scheme,
                         "host": host, "port": port, "path": path}
    return managed, passthrough


def _canonical_resource(url: str) -> str:
    """A resource identifier that two parties can compare and agree on.

    Normalised so trivia cannot make one endpoint look like two: the default port
    is dropped, an explicit one is kept, and a trailing slash on the path is
    removed. `http://h:80/mcp/` and `http://h/mcp` are the same resource, and a
    ceiling naming one must match the other.
    """
    u = urlparse(url)
    port = u.port
    netloc = u.hostname or ""
    if port is not None and port != _default_port(u.scheme):
        netloc = f"{netloc}:{port}"
    return f"{u.scheme}://{netloc}{(u.path or '').rstrip('/')}"


def _split_url(url: str) -> tuple[str, str, int, str] | None:
    """Validate a managed reach_url and split it into (scheme, host, port, path).

    The sidecar rebuilds the upstream URL from these parts (never from the
    agent's request), so anything the rebuilt URL would not faithfully
    reproduce returns None, and the caller WITHHOLDS on None. In particular:

    * only `http` and `https` are accepted. `https` is honoured end to end:
      the sidecar's pooled httpx client performs the TLS handshake against the
      run's trust bundle and presents the run's X509-SVID as its client
      certificate. (The old blanket refusal of https existed for agentgateway,
      which took a bare host:port; that data plane is gone, ADR-003.)
    * a query or fragment is refused, because only the declared path is
      carried, so `?tenant=a` would be dropped and the agent would silently be
      talking to a different tenant's endpoint than the operator configured.
    """
    try:
        u = urlparse(url)
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    if u.query or u.fragment:
        return None
    # An IPv6 literal (`http://[::1]:8080/mcp`) parses with a colon-bearing
    # hostname, and the sidecar rebuilds the upstream as
    # `scheme://host:port/path` -- which for `::1` is the malformed
    # `scheme://::1:8080/path`. Refuse it here (a named withhold) rather than
    # emit a URL that fails deep in httpx with no explanation. Logged at the
    # point of knowledge so the operator sees the specific reason, not just the
    # generic "cannot honour" the callers print. Bracketed-host support can be
    # added when a managed tool actually needs it.
    if ":" in u.hostname:
        log.error("reach_url %r has an IPv6-literal host; bracketed IPv6 hosts "
                  "are not supported for managed tools -- use a hostname", url)
        return None
    path = u.path or "/"
    if not path.startswith("/"):
        return None
    return u.scheme, u.hostname, u.port or _default_port(u.scheme), path


def scheme_refusal(scheme: str) -> str | None:
    """Why this managed reach_url scheme may not carry platform authority, or
    None if it may.

    The sidecar attaches the run's delegated bearer token to this leg, so in
    production a plaintext hop would hand that token to any on-path observer
    and the documented mTLS sender-binding could never hold. Dev keeps http so
    the getting-started path needs no PKI.
    """
    if scheme != "http":
        return None
    if config.PROD:
        return ("a plaintext http reach_url cannot carry the run's delegated "
                "token in production; serve the tool over https")
    return None


def preflight(managed: dict, timeout: float = _PREFLIGHT_TIMEOUT,
              budget: float = _PREFLIGHT_BUDGET) -> tuple[dict, dict]:
    """Probe each upstream, returning (reachable, unreachable_with_reason).

    An upstream that is already down is dropped BEFORE the config is written,
    because of how MCP fails. A session opens with `initialize`; if that request
    cannot reach the upstream the client gets a transport error and no session at
    all, so the agent does not learn the tool exists, let alone why it is missing.
    Dropping it here converts that into a named withholding the operator can read.
    It is a TOCTOU check by nature -- an upstream can die a moment later -- and
    that residual case is what the per-tool listener confines.

    Bounded in TOTAL, not just per host. This runs synchronously on the runner's
    event loop, and a handful of blackholed hosts at the per-host timeout each
    would stall the whole runner. Servers not reached inside the budget are
    withheld and SAID to be withheld for that reason, rather than quietly treated
    as reachable.
    """
    reachable, refused = {}, {}
    deadline = time.monotonic() + budget
    for name, cfg in managed.items():
        left = deadline - time.monotonic()
        if left <= 0:
            refused[name] = (f"not probed: the {budget}s preflight budget was "
                             "spent on earlier servers")
            continue
        try:
            with socket.create_connection((cfg["host"], cfg["port"]),
                                          min(timeout, left)):
                reachable[name] = cfg
        except OSError as exc:
            refused[name] = (f"{cfg['host']}:{cfg['port']} unreachable "
                             f"({exc.strerror or exc})")
    return reachable, refused


# One HTTP/1.1 exchange with a TOTAL bound on time AND bytes.
#
# Hand-rolled on a socket, deliberately, because urllib cannot express this.
# Its `timeout=` is PER SOCKET OPERATION, so a responder that dribbles one byte
# slower than the timeout resets the clock on every byte: `http.client`'s
# _MAXLINE is 65536, so a 0.5s "timeout" is really a 9-hour status line. An
# earlier fix threaded a `budget` parameter through and changed nothing, because
# the parameter still landed in that per-operation timeout -- measured at 16.3s
# for 40 dripped bytes.
#
# This matters beyond flakiness: both callers run SYNCHRONOUSLY on the runner's
# event loop, before the run's TTL is even entered, and in pod mode the agent
# shares the sidecar's network namespace and can squat a port to be the slow
# responder.
_MAX_RESPONSE = 64 * 1024


def _remaining(deadline: float) -> float:
    """Seconds until `deadline`, NEVER negative.

    A module-level function, not an inline `max()`, so the property is one fact
    with one test. `socket.settimeout` raises ValueError -- not OSError -- on a
    negative value, and the budget can cross zero between a loop guard and the
    very next line, which escaped a function whose contract says it never raises.
    The window is sub-microsecond and cannot be reproduced by timing, so the
    clamp is asserted directly instead. Zero is a legal timeout.
    """
    return max(0.0, deadline - time.monotonic())


def _http(host: str, port: int, method: str, path: str, headers: dict,
          body: bytes | None, budget: float) -> tuple[int, dict, bytes] | None:
    """Returns (status, headers, body) or None if it could not be completed
    within `budget` seconds total. Never raises."""
    deadline = time.monotonic() + budget

    def left() -> float:
        return _remaining(deadline)

    def expired() -> bool:
        return time.monotonic() >= deadline

    # Header values are concatenated into the request, so a CR or LF in one would
    # let a caller inject a header or a second request. Every value here is
    # internally generated today, but "safe because of a fact asserted somewhere
    # else" is exactly the assumption that rots, so the guard stays.
    for key, value in headers.items():
        if any(c in f"{key}{value}" for c in "\r\n"):
            return None
    request = f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    for key, value in headers.items():
        request += f"{key}: {value}\r\n"
    if body is not None:
        request += f"Content-Length: {len(body)}\r\n"
    request += "Connection: close\r\n\r\n"
    raw = request.encode() + (body or b"")

    sock = None
    try:
        if expired():
            return None
        sock = socket.create_connection((host, port), left())
        sock.settimeout(left())
        sock.sendall(raw)
        buf = b""
        while not expired() and len(buf) < _MAX_RESPONSE:
            sock.settimeout(left())
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            head, sep, rest = buf.partition(b"\r\n\r\n")
            if not sep:
                continue
            length = None
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    try:
                        length = int(value.strip())
                    except ValueError:
                        length = None
            if length is not None and len(rest) >= length:
                break
        if expired():
            return None
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    head, _, payload = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        return None
    parsed = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name:
            parsed[name.strip().lower()] = value.strip()
    if "chunked" in parsed.get("transfer-encoding", "").lower():
        payload = _dechunk(payload)
    return status, parsed, payload


def _dechunk(body: bytes) -> bytes:
    """Undo chunked framing, or return b"" if it is not well formed.

    The stock server sets Content-Length, so this is unreachable today -- but it
    becomes reachable the moment ANDYUR_SERVER_URL sits behind a re-framing
    reverse proxy, and the failure was silent and MISATTRIBUTED: the framing
    bytes made the JSON unparseable, so a mint that had worked perfectly was
    reported as "returned no access_token" and every managed tool was withheld
    while blaming it.
    """
    out, rest = b"", body
    while True:
        size_line, sep, rest = rest.partition(b"\r\n")
        if not sep:
            return b""
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            return b""
        if size == 0:
            return out
        if len(rest) < size:
            return b""
        out, rest = out + rest[:size], rest[size:].removeprefix(b"\r\n")


# RFC 9728 discovery, OFF by default.
#
# What it does and, more importantly, what it does NOT do. Discovery CONFIRMS;
# it never SUPPLIES. It reads the resource's own metadata and refuses a tool
# whose declared authorization server is not ours -- that resource needs the
# cross-domain hops (RFC 8693 assertion, then RFC 7523 at THEIR AS), which are
# not built, so sending it a token its AS will never accept is a call that fails
# at the far end for a reason nobody can see from here.
#
# It deliberately does not take the audience from the metadata. The resource
# names its own identifier, so honouring it would let a tool server ask to be
# issued a token for someone else's audience; the registry ceiling would still
# refuse, but the right place to stop that is before asking. The audience stays
# operator-written.
#
# There is also an unsettled identifier question underneath, and it is logged
# rather than papered over: MCP's canonical resource id is an HTTP URL, while
# Andyur's audiences are opaque (`tool:bank`). Reconciling the two schemes is a
# repo-wide decision, not something a discovery probe should make quietly.
DISCOVERY_ENV = "ANDYUR_TOOL_DISCOVERY"
# Total wall clock discovery may consume across ALL declared servers. Same reason
# as _PREFLIGHT_BUDGET and MINT_BUDGET: this runs on the runner's event loop,
# before the run TTL is entered.
DISCOVERY_BUDGET = float(os.environ.get("ANDYUR_TOOL_DISCOVERY_BUDGET", "10"))


def discovery_enabled() -> bool:
    return os.environ.get(DISCOVERY_ENV, "off").lower() in ("1", "on", "true")


def local_exchange(run_token: str, server: str, timeout: float = 10.0,
                   actor_token: str | None = None):
    """An exchange_fn for the per-run sidecar that mints at ANDYUR's OWN
    `/oauth/token` (ADR-003: 'the sidecar exchanges at Andyur's /oauth/token'),
    authenticated by the RUN TOKEN. This is the LOCAL-mint counterpart to
    `server.asclient.exchange`, which is the EXTERNAL-AS leg (it needs
    ANDYUR_AS_TOKEN_ENDPOINT and sends subject+actor tokens). The per-run sidecar
    uses this one when Andyur is the authorization server.

    Returns a callable matching the sidecar's exchange_fn contract
    (`sidecar.delegated_token`): called with the RFC 8693 kwargs, returns the
    mint's JSON ({'access_token', 'expires_in', ...}), and RAISES on refusal so
    the caller fails closed (no token -> the tool is not called).

    The run token authenticates the caller and already carries the actor, the
    user (sub) and the PIN, so this deliberately IGNORES subject_token,
    actor_token and authorization_details from the RFC 8693 caller kwargs and
    sends only the audience and the narrowed scope. `/oauth/token` refuses a
    body-supplied pin (422) and takes the actor from the run, so restating them
    here would fail or, worse, let a caller assert an identity the run token has
    already fixed.

    `actor_token` here is a different leg entirely: the run's JWT-SVID as the
    HTTP Authorization bearer, presented alongside the run-token header. Under
    ANDYUR_REQUIRE_RUN_SVID the mint refuses a run-scoped call without it, so
    omitting it would make this exchange dead in
    exactly the hardened configuration.
    """
    host, _, port = server.partition(":")

    def _mint(*, audience, scope=None, **_ignored) -> dict:
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            # A placeholder subject: the RUN token authenticated us and names the
            # user, but the endpoint requires the field to be present.
            "subject_token": "andyur-sidecar",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
        }
        if scope:
            form["scope"] = scope if isinstance(scope, str) else " ".join(scope)
        payload = urllib.parse.urlencode(form).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   identity.RUN_TOKEN_HEADER: run_token}
        if actor_token:
            headers["Authorization"] = f"Bearer {actor_token}"
        answer = _http(host, int(port or 80), "POST", "/oauth/token",
                       headers, payload, timeout)
        if answer is None:
            raise GatewayUnavailable(
                f"the mint at {server} did not answer within {timeout}s")
        status, _, raw = answer
        try:
            parsed = json.loads(raw or b"{}")
        except ValueError:
            parsed = {}
        if status == 200 and parsed.get("access_token"):
            return parsed
        detail = parsed.get("detail", parsed)
        raise GatewayUnavailable(
            f"Andyur's mint refused an exchange for {audience!r} "
            f"(HTTP {status}): {str(detail)[:200]}")

    return _mint


def _server_host_port() -> str | None:
    """Andyur's token endpoint as agentgateway addresses it, or None if we cannot.

    None when `SERVER_URL` is https, for the reason in `_split_url`: the run token
    would travel in cleartext to port 443. `ANDYUR_MTLS=on` makes the control
    plane https AND client-cert-required, and agentgateway has no RFC 8705 mTLS
    client-auth method, so that combination cannot work today and must fail
    loudly rather than leak.
    """
    u = urlparse(config.SERVER_URL)
    if u.scheme != "http" or not u.hostname:
        return None
    return f"{u.hostname}:{u.port or _default_port(u.scheme)}"


# Where the gateway reads the run's subject token from. An internal header on the
# loopback hop between the gateway and the token endpoint; it never reaches the
# agent and never reaches the tool.
_SUBJECT_TOKEN_HEADER = "x-andyur-subject-token"
# Same mechanism, one leg over: the run's JWT-SVID rides this header so the
# exchange can present WHO IS ACTING beside who the work is for. Route `set`
# overwrites, so the agent cannot name a different actor any more than it can
# name a different subject.
_ACTOR_TOKEN_HEADER = "x-andyur-actor-token"

"""The agent console BFF (backend-for-frontend).

A localhost-only process that serves the static console UI and proxies a small
ALLOWLIST of control-plane routes. It exists because the control plane requires
an operator JWT-SVID on every call and a browser cannot obtain one: the BFF
holds the operator identity (`OperatorSvidAuth` over `identity.fetch_token`,
plus `identity.client_tls("operator")`), so the browser never sees a
credential.

It inherits the CLI's trust boundary: whoever can run this as the operator role
binary already has operator power. It adds NO new authority. localhost is not a
trust boundary by itself, so the proxy is fenced:

  * a LAUNCH TOKEN, single-use, printed in the launch URL. The page exchanges
    it exactly once at `POST /session` for the SESSION SECRET, which the page
    then keeps for itself (memory plus the tab's sessionStorage, so a reload
    does not strand the operator). A launch token seen in a process list, a
    shell log or a browser history is worthless after the first page load
    spends it.
  * the SESSION SECRET, required as a custom header (`SESSION_HEADER`) on
    every /api call. A cross-site page cannot add a custom header without a
    CORS preflight; this app answers the preflight with a refusal carrying no
    Access-Control headers, so the browser never sends the real request -- and
    another local process cannot drive the proxy without knowing the secret.
  * ORIGIN and HOST checks -- a request whose Origin is present and not the
    console's own is refused, and so is one whose Host is not the console's own
    (a DNS-rebinding page reaches the loopback with its own Host).
  * a ROUTE ALLOWLIST -- the proxy forwards only the specific control-plane
    paths the console needs, never an arbitrary relay. Every entry has a name;
    the name, never the path, is what logs and spans carry.
  * BODY CAPS in both directions -- the proxy buffers at most `MAX_BODY_BYTES`
    per request and per upstream response, and `/session` at most
    `SESSION_BODY_BYTES`; the upstream call has a total deadline.

Every refusal and failure has a NAME (`Reason`). The same word is in the
response body, in the structured log line, and (step 2) on the span.

TWO MODES. The console's own ANDYUR_USER_AUTH decides whether to run a login;
every authority DISTINCTION is decided by the SERVER, never by this process or
the page (which only render what `GET /me` reports):

  * `ANDYUR_USER_AUTH=off` -- the single-operator dev tool: no login, operator
    authority, `/me` answers admin.
  * `ANDYUR_USER_AUTH=on` -- launch runs the existing RFC 8252 browser login
    (`authlogin.login`, PKCE, loopback callback) against the user IdP, and every
    proxied call carries the logged-in user's token as `x-andyur-user-token`
    (held in a `UserSession`, memory only). The control plane owner-scopes what
    the user sees and does; a token carrying ANDYUR_ADMIN_ROLE in the configured
    roles claim (ANDYUR_ROLES_CLAIM; any IdP, the default matches Keycloak's
    realm roles) gets the admin surface (all owners' agents, workers, workflow
    halt). Keep this env in sync with the SERVER's: console-off/server-on 401s
    every call, console-on/server-off logs a user in for nothing.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import pathlib
import re
import secrets
import time
from contextlib import asynccontextmanager
from enum import Enum

import httpx
from opentelemetry import trace as _otel_trace
from opentelemetry.trace import Status, StatusCode
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, request_response
from starlette.staticfiles import StaticFiles

from .. import identity, observability, otel, redact
from ..config import SERVER_URL, TRACE_UI_URL
from ..registry.models import MAX_INPUT_BYTES

_LOG = logging.getLogger("andyur.console")
SERVICE = "andyur-console"
# One tracer for the console's own decision spans (console.proxy,
# console.session.*); the request span around them comes from otel.ObservedASGI
# and the identity fetch is an otel.observe_dependency client span. Telemetry
# is on by default and off with ANDYUR_OTEL=off; nothing here may change a
# response, so every record goes through otel's try_* helpers.
_tracer = otel.setup_tracing(SERVICE)

# The page is markup only: its script and stylesheet are separate files under
# static/ (see pagecheck.py for the rule) and every handler is attached by
# event delegation on data-action attributes, so script-src and style-src are
# 'self' with nothing inline. `connect-src 'self'` stops background fetches
# to any other host; `default-src 'self'` stops loading external resources;
# object-src/base-uri/form-action/frame-ancestors 'none' close the usual
# escape hatches. This is a backstop for a page that already carries no
# credential, not a promise that a compromised page can leak nothing: a
# top-level navigation is outside every directive here. `referrer-policy:
# no-referrer` keeps the launch URL out of any Referer.
_CSP = ("default-src 'self'; connect-src 'self'; img-src 'self'; "
        "script-src 'self'; style-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")

# The header the page presents its session secret in. Not X- prefixed
# (RFC 6648); the value is a URL-safe token.
SESSION_HEADER = "andyur-console-session"
_CHALLENGE = 'ConsoleSession realm="andyur-console"'

# Caps. The transport ceiling for a console body is twice the manifest input
# bound (MAX_INPUT_BYTES of sealed UTF-8, the largest thing step 4's launch
# form will send): headroom for JSON escaping of ordinary text. A body made of
# control characters escapes six-fold and is refused here at 413 instead of at
# the control plane's 422; that is the trade. The same number bounds what the
# proxy buffers from the control plane (an agents list, a manifest with long
# instructions). /session carries a 60-byte token exchange.
MAX_BODY_BYTES = 2 * MAX_INPUT_BYTES
SESSION_BODY_BYTES = 4096
# Wall-clock bound on receiving a request body: uvicorn cancels its keep-alive
# timer on the first byte, so without this a dribbling client holds the
# connection (and the buffer) for as long as it likes.
BODY_DEADLINE = 30.0
# Total wall-clock for one proxied call. httpx's own timeout is per read, so a
# control plane that trickles bytes would otherwise hold the request forever.
UPSTREAM_DEADLINE = 30.0
# How long one SVID fetch may take before the call is named identity_unavailable
# rather than upstream_timeout. Below UPSTREAM_DEADLINE on purpose: an agent
# that accepts and never answers must be reported as the identity plane, not
# as the control plane. It also bounds how long the one worker thread blocks,
# which is how long Ctrl-C waits for it.
SVID_BUDGET = 10.0


def _dynamic(path: str) -> bool:
    return path.startswith("/session") or path == "/api" or path.startswith("/api/")


async def _security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["content-security-policy"] = _CSP
    resp.headers["x-content-type-options"] = "nosniff"
    resp.headers["referrer-policy"] = "no-referrer"
    if _dynamic(request.url.path):
        # Control-plane data and the session exchange must never land in a
        # browser or proxy cache.
        resp.headers["cache-control"] = "no-store"
    return resp


class Reason(str, Enum):
    """Why the BFF refused or failed. The value is the word the response body,
    the log line and (step 2) the span attribute all carry."""
    CROSS_ORIGIN = "cross_origin"
    MISSING_HOST = "missing_host"
    BAD_HOST = "bad_host"
    BAD_SESSION = "bad_session"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    BAD_PATH = "bad_path"
    NOT_A_CONSOLE_ROUTE = "not_a_console_route"
    BODY_TOO_LARGE = "body_too_large"
    CLIENT_DISCONNECTED = "client_disconnected"
    LAUNCH_SPENT = "launch_spent"
    LAUNCH_UNKNOWN = "launch_unknown"
    SESSION_EXPIRED = "session_expired"
    IDP_ERROR = "idp_error"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    UPSTREAM_UNREACHABLE = "upstream_unreachable"
    UPSTREAM_PROTOCOL_ERROR = "upstream_protocol_error"
    UPSTREAM_TIMEOUT = "upstream_timeout"
    UPSTREAM_TOO_LARGE = "upstream_too_large"
    BODY_TIMEOUT = "body_timeout"


# The console's exact reason travels on the span; the metric side is bounded
# to the platform's reason vocabulary (observability._REASONS), one bucket per
# console reason, so cardinality stays closed without the words being lost.
_REASON_BUCKET: dict[Reason, str] = {
    Reason.CROSS_ORIGIN: "refused", Reason.MISSING_HOST: "invalid",
    Reason.BAD_HOST: "refused", Reason.BAD_SESSION: "refused",
    Reason.METHOD_NOT_ALLOWED: "invalid", Reason.BAD_PATH: "invalid",
    Reason.NOT_A_CONSOLE_ROUTE: "invalid", Reason.BODY_TOO_LARGE: "exhausted",
    Reason.CLIENT_DISCONNECTED: "invalid", Reason.LAUNCH_SPENT: "refused",
    Reason.LAUNCH_UNKNOWN: "refused", Reason.SESSION_EXPIRED: "unavailable",
    Reason.IDP_ERROR: "unavailable", Reason.IDENTITY_UNAVAILABLE: "unavailable",
    Reason.UPSTREAM_UNREACHABLE: "unavailable",
    Reason.UPSTREAM_PROTOCOL_ERROR: "invalid", Reason.UPSTREAM_TIMEOUT: "timeout",
    Reason.UPSTREAM_TOO_LARGE: "exhausted", Reason.BODY_TIMEOUT: "timeout",
}

# Refusals caused by the control plane rather than by the caller. These are the
# ones that also count against the dependency, so an outage is visible as one.
_UPSTREAM_REASONS = frozenset({
    Reason.UPSTREAM_UNREACHABLE, Reason.UPSTREAM_PROTOCOL_ERROR,
    Reason.UPSTREAM_TIMEOUT, Reason.UPSTREAM_TOO_LARGE,
})

# One table: the status and the human sentence for every reason. Placeholders
# are filled by _refuse; the sentence is redacted before it leaves.
_REFUSALS: dict[Reason, tuple[int, str]] = {
    Reason.CROSS_ORIGIN: (403, "cross-origin request refused"),
    Reason.MISSING_HOST: (400, "request without a Host header refused"),
    Reason.BAD_HOST: (403, "request for another host refused"),
    Reason.BAD_SESSION: (401, "missing or wrong console session"),
    Reason.METHOD_NOT_ALLOWED: (405, "{method} is not allowed here"),
    Reason.BAD_PATH: (403, "bad path"),
    Reason.NOT_A_CONSOLE_ROUTE: (403, "not a console route: {method} {path}"),
    Reason.BODY_TOO_LARGE: (413, "request body too large (limit {limit} bytes)"),
    Reason.CLIENT_DISCONNECTED: (400, "the client went away before its request body arrived"),
    Reason.LAUNCH_SPENT: (403, "this launch link was already used, probably by another tab "
                               "of this console; use that tab. If you did not open one, stop "
                               "the console: something else spent the link"),
    Reason.LAUNCH_UNKNOWN: (403, "unknown launch token"),
    Reason.SESSION_EXPIRED: (401, "{cause}; restart `andyur console` to sign in again"),
    Reason.IDP_ERROR: (502, "the session could not be refreshed at the IdP: {cause}"),
    Reason.IDENTITY_UNAVAILABLE: (503, "operator identity unavailable: {cause}. Is the SPIRE "
                                       "agent serving SVIDs? `./run.sh up` restarts it"),
    Reason.UPSTREAM_UNREACHABLE: (502, "control plane unreachable: {cause}"),
    Reason.UPSTREAM_PROTOCOL_ERROR: (502, "control plane answered badly: {cause}"),
    Reason.BODY_TIMEOUT: (408, "request body did not arrive within {seconds:.0f}s"),
    Reason.UPSTREAM_TIMEOUT: (504, "control plane did not answer within {seconds:.0f}s"),
    Reason.UPSTREAM_TOO_LARGE: (502, "control plane response exceeded {limit} bytes"),
}


_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE")


def _method_name(method: str) -> str:
    """A closed vocabulary for the method: the wire token is client-chosen
    and unbounded, and it lands in a log field and a 405 sentence."""
    return method if method in _METHODS else "OTHER"


def _refuse(reason: Reason, *, method: str = "", path: str = "", route: str = "",
            allow: str = "", **fmt) -> JSONResponse:
    """The one place a refusal is built: status and sentence from the table,
    secrets redacted, the reason logged BY NAME, protocol headers attached."""
    status, template = _REFUSALS[reason]
    method = _method_name(method) if method else ""
    detail = redact.redact(template.format(method=method, path=path, **fmt))
    headers: dict[str, str] = {}
    if status == 401:
        headers["www-authenticate"] = _CHALLENGE      # RFC 9110 15.5.2
    if status == 405:
        headers["allow"] = allow                       # RFC 9110 15.5.6
    if status == 413:
        headers["connection"] = "close"                # do not drain the rest
    # The decision on the current span, by name, and one bounded metric. The
    # log line below inherits the trace and span ids from the same span.
    outcome = ("timeout" if status in (408, 504) else
               "failure" if status >= 500 else "denied")
    span = _otel_trace.get_current_span()
    span.set_attribute("andyur.console.outcome", "refused")
    span.set_attribute("andyur.console.reason", reason.value)
    span.set_attribute("http.response.status_code", status)
    if status >= 500:
        # A 5xx is the console FAILING, not the console refusing. Left as OK,
        # every "errors in the last hour" query over the trace store read zero
        # while the operator's page was down.
        span.set_status(Status(StatusCode.ERROR, reason.value))
    otel.try_record_metric(
        SERVICE, "andyur.authorization.decisions",
        andyur__outcome=outcome, andyur__reason=_REASON_BUCKET[reason])
    if reason in _UPSTREAM_REASONS:
        # The one hop this process makes. Named as a dependency so "the console
        # is slow" and "the control plane is slow" are different signals.
        otel.try_record_metric(
            SERVICE, "andyur.dependency.failures",
            andyur__dependency="control-plane",
            andyur__reason=_REASON_BUCKET[reason],
            andyur__operation="fetch")
    observability.event(_LOG, "console.refuse", reason=_REASON_BUCKET[reason],
                        console_reason=reason.value, status=status,
                        method=method, route=route)
    return JSONResponse({"detail": detail, "reason": reason.value}, status,
                        headers=headers)


# The ONLY control-plane routes the console proxies: (name, method, path
# regex). A request whose method+path is not on this list is refused: the BFF
# is a console backend, not a general `andyur api` relay. Everything here is an
# operator-safe read or a lifecycle action the console UI actually issues. The
# name is what telemetry carries; the path never is.
_ALLOWLIST: list[tuple[str, str, re.Pattern]] = [
    (name, m, re.compile(p)) for name, m, p in [
        ("me", "GET", r"^/me$"),                                  # who am I / am I admin
        ("agents.list", "GET", r"^/agents$"),
        ("agents.create", "POST", r"^/agents$"),                  # optional registry_agent_id
        ("agents.show", "GET", r"^/agents/[^/]+$"),               # one instance + recent runs
        ("agents.delete", "DELETE", r"^/agents/[^/]+$"),
        ("agents.trigger", "POST", r"^/agents/[^/]+/trigger$"),
        ("agents.pause", "POST", r"^/agents/[^/]+/pause$"),       # kill switch
        ("agents.resume", "POST", r"^/agents/[^/]+/resume$"),
        ("agents.ceiling", "GET", r"^/agents/[^/]+/ceiling$"),
        ("registry.list", "GET", r"^/v1/registry/agents$"),
        ("registry.resolve", "GET", r"^/v1/registry/agents/[^/]+/resolve$"),
        # Runs: history, detail, following, and what a run exchanged. All
        # owner-gated on the server (run_view, _run_owner_gate).
        ("runs.list", "GET", r"^/runs$"),
        ("runs.show", "GET", r"^/runs/[^/]+$"),
        ("runs.events", "GET", r"^/runs/[^/]+/events$"),        # conversation cursor
        ("runs.turn", "POST", r"^/runs/[^/]+/turn$"),
        ("runs.close", "POST", r"^/runs/[^/]+/close$"),
        ("runs.transcript", "GET", r"^/runs/[^/]+/transcript$"),
        ("runs.exchanges", "GET", r"^/runs/[^/]+/exchanges$"),
        # The consequential actions a run requested, and what Andyur decided
        # about each (docs/lane-a-action-contract.md). The golden path's
        # Requested / Decision / Approved by / Result all come from here, and
        # the exit criterion is that they render WITHOUT opening a database,
        # kubectl or Jaeger -- so this route is the whole reason the story is
        # demonstrable from the product surface.
        ("runs.actions", "GET", r"^/runs/[^/]+/actions$"),
        ("workflows.flow", "GET", r"^/workflows/[^/]+/flow$"),
        # Admin surfaces. Proxied for every console; the SERVER refuses a
        # non-admin user token (403), so listing them here grants nothing.
        ("workers", "GET", r"^/workers$"),
        ("workflows.halt", "POST", r"^/workflows/[^/]+/halt$"),
        ("workflows.unhalt", "POST", r"^/workflows/[^/]+/unhalt$"),
    ]
]


def _allowed(method: str, path: str) -> str | None:
    """The allowlist entry name for this call, or None. fullmatch, not match:
    `$` in a Python regex also matches just before a trailing newline, so
    `rx.match` would accept `/workers\\n`; fullmatch anchors the whole string."""
    for name, m, rx in _ALLOWLIST:
        if m == method and rx.fullmatch(path):
            return name
    return None


def unverified_subject(token: str) -> str | None:
    """A JWT's `sub`, read WITHOUT verifying the signature. TELEMETRY ONLY.

    Safe here and nowhere else, because this value never reaches a decision:
    the control plane validates the very same token and enforces every owner
    gate on the claims IT verified. It exists so a trace can answer "which
    human deleted that agent", which a decision span with no principal cannot.
    Bounded in length so a forged token cannot turn a span attribute into a
    payload.
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        sub = claims.get("sub") if isinstance(claims, dict) else None
    except (ValueError, TypeError, IndexError, AttributeError, RecursionError):
        return None
    return sub if isinstance(sub, str) and 0 < len(sub) <= 128 else None


class UserSession:
    """The logged-in user's IdP tokens, held in BFF PROCESS MEMORY only.

    Never written to disk: the CLI's credential cache (`authlogin.save_token`)
    deliberately drops refresh tokens, and this class exists so the console does
    not have to weaken that -- a refresh token at rest is a long-lived
    credential, one in a short-lived process is a session.

    The access token is refreshed under a lock shortly before expiry, because
    Keycloak rotates refresh tokens and two concurrent refreshes would race a
    one-time credential. A session with no refresh token just rides its access
    token until the control plane's own 401 reaches the page.
    """

    _EARLY = 30  # refresh at most this many seconds before expiry

    def __init__(self, tokens: dict, *, token_endpoint: str, client_id: str):
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._lock = asyncio.Lock()
        # Once set, the session cannot refresh and every call raises. A latch,
        # never cleared: a refresh that failed for ANY reason may already have
        # spent the (rotating) refresh token at the IdP, so re-presenting it is a
        # replay -- which reuse detection turns into a whole-session revocation.
        # Latching dead trades a transient IdP blip for a re-login instead of a
        # hammer loop against the token endpoint (the UI polls every few
        # seconds), which is the safe direction for a local operator tool.
        self._dead: str | None = None
        self._absorb(tokens)

    def _absorb(self, tokens: dict) -> None:
        access = tokens.get("access_token")
        if not access:
            raise SessionExpired("the IdP response carried no access token")
        self._access = access
        # Telemetry only; see unverified_subject. Recomputed on refresh because
        # a refreshed token could carry a different subject, and a stale one on
        # the span would be worse than none.
        self._subject = unverified_subject(access)
        # Keycloak rotates the refresh token on use; absent from a refresh
        # response, the one we already hold stays valid.
        self._refresh = tokens.get("refresh_token") or getattr(self, "_refresh", None)
        expires_in = tokens.get("expires_in")
        if isinstance(expires_in, str):     # RFC 6749 sec 5.1 says seconds; some
            try:                            # servers send a JSON string
                expires_in = float(expires_in)
            except ValueError:
                expires_in = None
        if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) \
                and expires_in > 0:
            self._expires_at = time.time() + expires_in
            # Clamp the early window to half the lifetime: with a short access
            # token (30-60s is a common hardened setting) a fixed 30s lead would
            # put every request past the threshold and refresh on EVERY call --
            # a permanent refresh (and, with rotation, a permanent replay window)
            # loop. Never refresh more than halfway into the token's life.
            self._early = min(self._EARLY, expires_in / 2)
        else:
            self._expires_at = None

    @property
    def subject(self) -> str | None:
        """Who this session is, for the decision span. Never for a decision."""
        return self._subject

    async def access_token(self, http: httpx.AsyncClient) -> str:
        if self._dead:
            raise SessionExpired(self._dead)
        if self._refresh is None or self._expires_at is None:
            return self._access
        async with self._lock:
            if self._dead:                       # a waiter that queued behind a
                raise SessionExpired(self._dead)  # refresh that just died
            if time.time() < self._expires_at - self._early:
                return self._access
            absorbed = False
            span = _tracer.start_span("console.session.refresh")
            try:
                resp = await http.post(self._token_endpoint, data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._refresh,
                    "client_id": self._client_id,
                })
                body = (resp.json() if resp.headers.get(
                    "content-type", "").startswith("application/json") else {})
                if resp.status_code != 200 or not body.get("access_token"):
                    # The IdP's error code is IdP-controlled text; bound it.
                    code = str(body.get("error", "no detail"))[:64]
                    self._dead = (f"the IdP refused to refresh the session "
                                  f"({resp.status_code}, {code})")
                    raise SessionExpired(self._dead)
                self._absorb(body)
                absorbed = True
                return self._access
            finally:
                # The refresh token is spent-or-in-doubt the moment the POST
                # left this process. If we did NOT absorb a new one -- a non-200
                # (handled above), a network error, a malformed body, or a task
                # cancellation unwinding through this block (CancelledError is a
                # BaseException, so no `except` catches it, but `finally` runs) --
                # latch the session dead so the next call re-logs-in rather than
                # replaying a possibly-consumed token.
                if not absorbed and self._dead is None:
                    self._dead = ("the session refresh did not complete; "
                                  "sign in again")
                span.set_attribute("andyur.console.outcome",
                                   "refreshed" if absorbed else
                                   "expired" if self._dead and "refused" in self._dead
                                   else "idp_error")
                span.end()


class SessionExpired(Exception):
    """The user's IdP session cannot be renewed; they must sign in again."""


class LaunchToken:
    """The single-use token in the launch URL. `spend()` succeeds exactly once
    for the right value; the check and the state change happen in one
    synchronous step on the event loop, so two racing exchanges cannot both
    win. A wrong guess never spends it."""

    def __init__(self, value: str):
        self._value = value
        self._spent = False

    @property
    def value(self) -> str:
        """For the launcher, which prints it in the URL exactly once."""
        return self._value

    def spend(self, presented: str) -> Reason | None:
        """None on success; otherwise the reason the exchange is refused."""
        # Bytes, not str: compare_digest on str raises TypeError for non-ASCII
        # input, which turned `{"launch": "é"}` into an unnamed 500; and
        # surrogatepass, because json.loads happily yields a lone surrogate
        # that a strict encode would turn into a UnicodeEncodeError 500.
        if not secrets.compare_digest(presented.encode("utf-8", "surrogatepass"),
                                      self._value.encode("ascii")):
            return Reason.LAUNCH_UNKNOWN
        if self._spent:
            return Reason.LAUNCH_SPENT
        self._spent = True
        return None


class IdentityUnavailable(Exception):
    """This process could not obtain its operator SVID: the Workload API
    socket is missing, the agent is not serving, or attestation was refused.
    Raised by the async auth flow so the proxy can name the failure instead of
    catching every exception."""


class OperatorSvidAuth(httpx.Auth):
    """The operator JWT-SVID on every request, fetched OFF the event loop.

    `identity.httpx_auth()` defines only the sync flow, which httpx runs inline
    on the loop for an async client: every Workload API round trip (up to
    SVID_TIMEOUT) then stalls the whole BFF, /healthz included (measured:
    three concurrent calls plus /healthz all finished together at 3x the fetch
    time). This adapter lives here, not in identity.py, because the exec/v1
    evidence binds that file by source hash and the sync callers (CLI, daemon,
    runner) do not need it. It reuses identity.fetch_token unchanged; that
    function's own lock makes the worker-thread call safe."""

    def __init__(self) -> None:
        self._inflight: asyncio.Task | None = None
        # The operator identity this process acts as, for the decision span.
        # One process, one identity, so it is read from the first SVID and kept.
        self.spiffe_id: str | None = None

    async def _fetch(self) -> str:
        """One SVID fetch at a time, shared by every request that needs one
        while it runs. identity.fetch_token serialises on a module lock, so N
        concurrent threads would only queue behind the first (and each would
        run to completion after its request had gone; Ctrl-C waited for all of
        them). One worker, bounded by SVID_BUDGET on both the lock and the
        Workload API wait, is the whole cost."""
        if self._inflight is None or self._inflight.done():
            self._inflight = asyncio.create_task(asyncio.to_thread(
                identity.fetch_token, timeout=SVID_BUDGET))
        # shield: one request's cancellation must not cancel the shared fetch.
        # observe_dependency: an `identity.fetch` CLIENT span plus the
        # andyur.dependency.* metrics, in the platform's own vocabulary.
        with otel.observe_dependency(
                SERVICE, "identity", "fetch",
                lambda exc: "timeout" if isinstance(exc, TimeoutError) else "unavailable"):
            return await asyncio.wait_for(asyncio.shield(self._inflight), SVID_BUDGET)

    async def async_auth_flow(self, request):
        try:
            token = await self._fetch()
        except TimeoutError as exc:
            raise IdentityUnavailable(
                f"no SVID within {SVID_BUDGET:.0f}s from the Workload API socket "
                f"{identity.socket_path()}") from exc
        except Exception as exc:                               # noqa: BLE001
            raise IdentityUnavailable(
                f"{exc} (Workload API socket {identity.socket_path()})") from exc
        if self.spiffe_id is None:
            self.spiffe_id = unverified_subject(token)
        request.headers["Authorization"] = f"Bearer {token}"
        yield request


def _operator_upstream() -> httpx.AsyncClient:
    """One long-lived client carrying the operator identity, the async twin
    of the CLI's _client(). The SVID is fetched fresh per request by the auth
    flow (off the event loop, see OperatorSvidAuth), so short-lived tokens are
    never stale; it never leaves this process.

    It is an ASYNC client, awaited from the handlers: a sync httpx.Client called
    from an async Starlette handler blocks the loop AND corrupts its connection
    pool under concurrent/rapid requests (seen live as 'Extra data' JSON errors
    when the pool hands back another response's bytes)."""
    cert, verify = identity.client_tls("operator")
    # The adapter is kept on the client so the decision span can name the
    # identity this process acted as; it learns it from the first SVID.
    auth = OperatorSvidAuth()
    client = httpx.AsyncClient(base_url=SERVER_URL, timeout=30,
                               auth=auth, cert=cert, verify=verify)
    client.andyur_operator_auth = auth
    return client


async def _read_body(request: Request, limit: int) -> bytes | Reason:
    """The request body, or the Reason it could not be taken. The cap is
    enforced on the bytes actually received, so Content-Length (which a client
    can lie about or omit) plays no part."""
    chunks: list[bytes] = []
    received = 0
    try:
        async with asyncio.timeout(BODY_DEADLINE):
            async for chunk in request.stream():
                received += len(chunk)
                if received > limit:
                    return Reason.BODY_TOO_LARGE
                chunks.append(chunk)
    except ClientDisconnect:
        return Reason.CLIENT_DISCONNECTED
    except TimeoutError:
        return Reason.BODY_TIMEOUT
    return b"".join(chunks)


class _AnyMethod:
    """Wrap a request handler as an ASGI app so the Route admits EVERY method.
    Starlette gives a plain function route GET and HEAD only and answers the
    rest with its own text 405, which skips the fences and the JSON shape;
    here every method token reaches the handler and the allowlist is the only
    method authority."""

    def __init__(self, fn):
        self._app = request_response(fn)

    async def __call__(self, scope, receive, send):
        await self._app(scope, receive, send)


def build_app(session_secret: str, *, origin: str, launch: LaunchToken,
              upstream: httpx.AsyncClient | None = None,
              user_session: UserSession | None = None,
              idp: httpx.AsyncClient | None = None) -> Starlette:
    """`session_secret` gates every /api call and is handed out exactly once by
    `POST /session` in exchange for `launch`; `origin` is the console's own
    scheme://host:port, the only Origin and Host the fences accept. `upstream`
    is the control-plane client (defaults to the operator-attested one;
    injected in tests). `user_session`, when given (user-auth deployments), is
    the logged-in user whose token every proxied call carries -- the operator
    SVID says which MACHINE PROCESS is calling, the user token says which
    HUMAN, and the control plane scopes by the human. `idp` is the client
    refreshes go through (defaults to a plain one; injected in tests)."""
    # Track what we constructed so lifespan closes only OUR clients and never an
    # injected one the caller (a test, or a shared setup) still owns.
    own_upstream = upstream is None
    if own_upstream:
        upstream = _operator_upstream()
    # The IdP client exists only to refresh a user session; without one there is
    # nothing to refresh, so do not build (or later close) a client no path uses.
    own_idp = idp is None and user_session is not None
    if own_idp:
        idp = httpx.AsyncClient(timeout=15)
    expected_host = origin.split("://", 1)[1]
    secret_bytes = session_secret.encode("ascii")

    def _browser_fence(request: Request) -> Reason | None:
        """Origin and Host: the request must come from the console's own page
        on the console's own address. A cross-origin fetch (a malicious page in
        another tab) and a DNS-rebinding page (right IP, wrong Host) are both
        refused before any secret is looked at."""
        req_origin = request.headers.get("origin")
        if req_origin is not None and req_origin != origin:
            return Reason.CROSS_ORIGIN
        host = request.headers.get("host")
        if host is None:
            return Reason.MISSING_HOST                 # RFC 9112 3.2
        if host != expected_host:
            return Reason.BAD_HOST
        return None

    def _session_fence(request: Request) -> Reason | None:
        # Constant-time compare on bytes (headers decode as latin-1, so every
        # byte round-trips), so a wrong/absent secret is a 401 regardless of
        # timing and a non-ASCII byte is a refusal, not a TypeError.
        got = request.headers.get(SESSION_HEADER, "").encode("latin-1")
        if not secrets.compare_digest(got, secret_bytes):
            return Reason.BAD_SESSION
        return None

    async def session(request: Request) -> Response:
        """Exchange the launch token for the session secret, once."""
        with _tracer.start_as_current_span("console.session.issue") as span:
            resp = await _session(request)
            if resp.status_code == 200:
                span.set_attribute("andyur.console.outcome", "issued")
            return resp

    async def _session(request: Request) -> Response:
        method = request.method
        if "rest" in request.path_params:
            # /session/<anything, even nothing> is not a console route;
            # named, not a static 404
            return _refuse(Reason.NOT_A_CONSOLE_ROUTE, method=method,
                           path="/session/" + request.path_params["rest"])
        if method != "POST":
            return _refuse(Reason.METHOD_NOT_ALLOWED, method=method,
                           path="/session", allow="POST")
        why = _browser_fence(request)
        if why is not None:
            return _refuse(why, method=method, path="/session")
        body = await _read_body(request, SESSION_BODY_BYTES)
        if isinstance(body, Reason):
            return _refuse(body, method=method, path="/session",
                           limit=SESSION_BODY_BYTES, seconds=BODY_DEADLINE)
        try:
            presented = json.loads(body or b"{}").get("launch", "")
        except (ValueError, AttributeError, RecursionError):
            presented = ""
        if not isinstance(presented, str):
            presented = ""
        why = launch.spend(presented)
        if why is not None:
            return _refuse(why, method=method, path="/session")
        return JSONResponse({"secret": session_secret})

    async def proxy(request: Request) -> Response:
        with _tracer.start_as_current_span("console.proxy") as span:
            return await _proxy(request, span)

    async def _proxy(request: Request, span) -> Response:
        method = request.method
        path = "/" + request.path_params.get("rest", "")
        # The allowlist entry is looked up first so that a refusal on an
        # allowlisted route (no secret, wrong Origin) is logged with the route
        # NAME; the fences still run before anything is forwarded.
        route = _allowed(method, path)
        if route:
            span.set_attribute("andyur.console.route", route)
        # WHO. A decision span that cannot say which principal made the request
        # cannot answer the question a trace is read for after an incident: not
        # "was an agent deleted" but "who deleted it". Under user-auth that is
        # the signed-in human; with the console as a single-operator tool it is
        # the SPIFFE id this process holds. Neither is ever a credential.
        if user_session is not None and user_session.subject:
            span.set_attribute("enduser.id", user_session.subject)
        why = _browser_fence(request) or _session_fence(request)
        if why is not None:
            return _refuse(why, method=method, path=path, route=route or "")
        # Defense in depth against a non-normalizing client sending literal
        # `.`/`..` segments (httpx -- both the TestClient and this proxy's own
        # upstream -- already collapse them, so the allowlist's `[^/]+` and the
        # upstream never see a traversal; a raw client could, hence this guard).
        if any(seg in (".", "..") for seg in path.split("/")):
            return _refuse(Reason.BAD_PATH, method=method, path=path)
        # The ALLOWLIST is matched on the decoded PATH only; the query string
        # is forwarded but never widens what routes are reachable.
        if route is None:
            return _refuse(Reason.NOT_A_CONSOLE_ROUTE, method=method, path=path)
        # Forward the RAW path bytes the client sent, not the decoded string
        # the allowlist matched: a decoded `?` or `#` re-parsed as a URL would
        # split the upstream path where the allowlist saw one segment
        # (`/agents/x%3F/ceiling` matched agents.ceiling but reached
        # `/agents/x`). Raw in, raw out; the control plane decodes once.
        raw = request.scope.get("raw_path") or request.url.path.encode()
        raw_rest = raw.decode("ascii", "strict")[len("/api"):] or "/"
        # The scope's query_string, not request.url.query: Starlette rebuilds
        # the URL from the DECODED path, so a decoded `?` would surface there
        # as a query that the client never sent.
        query = request.scope.get("query_string", b"").decode("ascii", "strict")
        target = raw_rest + (("?" + query) if query else "")
        body = await _read_body(request, MAX_BODY_BYTES)
        if isinstance(body, Reason):
            return _refuse(body, method=method, route=route, limit=MAX_BODY_BYTES,
                           seconds=BODY_DEADLINE)
        headers = {"content-type": request.headers.get(
                       "content-type", "application/json"),
                   # Ask for no content encoding. The response cap below counts
                   # DECODED bytes (aiter_bytes), so a body the control plane
                   # compressed anyway is still bounded at the cap plus one
                   # read's expansion; nothing past the cap is buffered.
                   "accept-encoding": "identity"}
        # The control plane ignores inbound trace context by default (it roots
        # a run's trace at its own trigger span); sending it costs nothing and
        # lets a deployment that trusts operator callers stitch the hops.
        otel.inject_traceparent(headers, span)
        if user_session is not None:
            # The browser NEVER sends or sees this token; the BFF injects it, so
            # a page compromise can act only through the allowlist while the
            # session lasts, not exfiltrate the credential itself.
            try:
                headers["x-andyur-user-token"] = await user_session.access_token(idp)
            except SessionExpired as exc:
                return _refuse(Reason.SESSION_EXPIRED, method=method, route=route,
                               cause=str(exc))
            except Exception as exc:                            # noqa: BLE001
                # A first-time refresh failure surfaces here as its raw type
                # (httpx error, or a ValueError from a malformed token body); the
                # session is already latched dead for the next call. Anything but
                # a clean SessionExpired is an IdP problem.
                return _refuse(Reason.IDP_ERROR, method=method, route=route,
                               cause=str(exc))
        chunks: list[bytes] = []
        received = 0
        try:
            async with asyncio.timeout(UPSTREAM_DEADLINE):
                async with upstream.stream(method, target, content=body or None,
                                           headers=headers) as up:
                    # aiter_bytes, not aiter_raw: httpx pre-reads a response
                    # it built from bytes and raw iteration then refuses it.
                    # The cap still bounds what is buffered: the loop stops at
                    # the first chunk past it, decoded or not.
                    async for chunk in up.aiter_bytes():
                        received += len(chunk)
                        if received > MAX_BODY_BYTES:
                            return _refuse(Reason.UPSTREAM_TOO_LARGE, method=method,
                                           route=route, limit=MAX_BODY_BYTES)
                        chunks.append(chunk)
                    status = up.status_code
                    media = up.headers.get("content-type", "application/json")
                    # RFC 9110: a 401 MUST carry its challenge and a 405 its
                    # Allow; the control plane's own travel through unchanged.
                    passthrough = {h: up.headers[h] for h in ("www-authenticate", "allow")
                                   if h in up.headers}
        except IdentityUnavailable as exc:
            # Named by the auth flow itself: no SVID could be fetched. Seen
            # live as a raw 500 with a traceback before it had a name.
            return _refuse(Reason.IDENTITY_UNAVAILABLE, method=method, route=route,
                           cause=str(exc))
        except (TimeoutError, httpx.TimeoutException):
            return _refuse(Reason.UPSTREAM_TIMEOUT, method=method, route=route,
                           seconds=UPSTREAM_DEADLINE)
        except httpx.RemoteProtocolError as exc:
            # The control plane was reached and answered badly (a truncated
            # body, a malformed frame): not "unreachable".
            return _refuse(Reason.UPSTREAM_PROTOCOL_ERROR, method=method, route=route,
                           cause=str(exc))
        except httpx.HTTPError as exc:
            # Same body shape as the control plane's own errors ({"detail": ...})
            # so the UI's one error extractor surfaces this message too, instead
            # of falling through to a bare "Bad Gateway" exactly when the control
            # plane is down and the detail matters most.
            return _refuse(Reason.UPSTREAM_UNREACHABLE, method=method, route=route,
                           cause=str(exc))
        body_out = b"".join(chunks)
        span.set_attribute("andyur.console.outcome", "forwarded")
        span.set_attribute("andyur.console.upstream_status", status)
        # WHO THIS PROCESS ACTED AS. Set here and not before the call: the
        # adapter learns the SPIFFE id from the SVID it fetches for THIS
        # request, so reading it earlier left the attribute off the first
        # request's span -- and the first request is the one an investigator
        # starts from.
        auth = getattr(upstream, "andyur_operator_auth", None)
        if auth is not None and auth.spiffe_id:
            span.set_attribute("andyur.operator.id", auth.spiffe_id)
        span.set_attribute("http.response.status_code", status)
        if route == "agents.trigger" and status == 201:
            # A run started from the console: put its id on the span so the
            # console action and the run's own trace correlate by run id.
            try:
                run_id = json.loads(body_out).get("run_id")
            except (ValueError, AttributeError):
                run_id = None
            if isinstance(run_id, str):
                span.set_attribute("andyur.run_id", run_id)
        # Pass the control plane's status + JSON body straight through; the UI
        # renders both success and the server's own error detail.
        return Response(body_out, status_code=status, media_type=media,
                        headers=passthrough)

    async def health(_request: Request) -> Response:
        # trace_ui: the operator's per-trace link template (opt-in, may be "")
        # instance_id: THIS console process, so a gate can bind its collector
        # read-back to the spans it actually caused. `service=andyur-console`
        # is shared by every console on a machine -- three worktrees ran on this
        # one in a day -- so a time window alone lets another process's spans
        # answer for yours, in either direction.
        return JSONResponse({"ok": True, "service": "andyur-console",
                             "control_plane": SERVER_URL, "trace_ui": TRACE_UI_URL,
                             "instance_id": otel.INSTANCE_ID})

    @asynccontextmanager
    async def _lifespan(_app):
        # Close only the clients WE built (own_*), each in its own guard so one
        # failing close cannot skip the other. An injected client belongs to the
        # caller and is left alone.
        try:
            yield
        finally:
            if own_upstream:
                try:
                    await upstream.aclose()
                except Exception:                              # noqa: BLE001
                    pass
            if own_idp:
                try:
                    await idp.aclose()
                except Exception:                              # noqa: BLE001
                    pass

    app = Starlette(
        routes=[
            Route("/healthz", health),
            Route("/session", _AnyMethod(session)),
            Route("/session/{rest:path}", _AnyMethod(session)),
            Route("/api", _AnyMethod(proxy)),
            Route("/api/{rest:path}", _AnyMethod(proxy)),
        ],
        lifespan=_lifespan,
    )
    # The static UI is mounted LAST so it never shadows /api, /session or
    # /healthz. It carries no credential -- the SVID is server-side only, and the
    # session secret is handed out by /session, never baked into a file.
    static_dir = pathlib.Path(__file__).parent / "static"
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="ui")
    # CSP + security headers on every response (UI, static, and API).
    app.add_middleware(BaseHTTPMiddleware, dispatch=_security_headers)
    # The request span and andyur.http.server.* metrics around EVERY request
    # (static, /healthz, /session, /api), so a probe of static paths is not
    # invisible. Browser trace context is untrusted: never a parent.
    #
    # health_spans=True is deliberate and is the opposite of the platform
    # default. That default exists because a Kubernetes readiness probe arrives
    # every few seconds for the life of a Pod and would be most of a run's
    # trace. The console is a LOOPBACK OPERATOR TOOL with no prober: /healthz is
    # fetched once when the page boots, and it is the call that tells the page
    # which control plane it is talking to and where to link a trace. A boot
    # that fails there is exactly the one an operator needs in the trace.
    return otel.ObservedASGI(app, service_name=SERVICE,
                             operation="console.request", health_spans=True)


def new_session_secret() -> str:
    return secrets.token_urlsafe(32)


def new_launch_token() -> LaunchToken:
    return LaunchToken(secrets.token_urlsafe(32))

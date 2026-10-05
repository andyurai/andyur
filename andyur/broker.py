"""Model broker: holds the provider API key so the agent never sees it (R2).

The agent runs as arbitrary code (Claude Code with Bash and a fetch tool). If
the provider key sits in its environment, one prompt injection exfiltrates it.
The broker fixes that: the agent's model calls are pointed at this proxy
(`ANTHROPIC_BASE_URL` = the broker), which injects the real key and forwards to
the upstream provider, streaming the response back. The agent subprocess runs
with NO provider key, so there is nothing to steal.

Holding the key makes the broker a target in its own right, so it enforces
three things rather than proxying whatever arrives:

  who is calling   a purpose-bound token, signed by the control plane, naming
                   the run. Without it the broker is an open credential: any
                   process that can reach the port spends the platform's key.
  what they may    an allowlist of upstream paths. The key may carry more
    reach          authority than inference -- account and key-management
                   endpoints live on the same host -- and a proxy that forwards
                   any path lends the agent every bit of it.
  how much         a per-run call ceiling, because the run that has been talked
                   into a loop is exactly the run that will not stop itself.

The token an agent holds here is deliberately NOT its control-plane token. The
model client sends its credential on every call, so that credential must live in
the agent's environment; if it were the run token, R2's scrub would be undone by
the very mechanism meant to enforce it. See runtoken.PURPOSE_BROKER.

Never log request or response bodies: they carry the agent's prompt and the
model's reply, which is the most sensitive material on the platform.

Launched as:  python -m andyur.broker   (or ./run.sh broker)
"""

import asyncio
import os
import posixpath
import threading
import time

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from .config import (
    BROKER_HOST,
    BROKER_PORT,
    BROKER_UPSTREAM,
    PROD,
    SERVER_URL,
)
from . import identity
from .server import runtoken

# The one secret the broker holds and the agent never does.
_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# Anthropic API version header the upstream requires if the client omits it.
_ANTHROPIC_VERSION = os.environ.get("ANTHROPIC_VERSION", "2023-06-01")

# Upstream paths a run may reach. Inference only: everything an agent legitimately
# does is here, and nothing else on the provider's API is any of its business.
# Prefix match, so versioned and sub-resource paths stay covered without listing
# each one.
def _parse_prefixes(spec: str) -> tuple:
    """Normalize the allowlist so its entries cannot defeat their own anchoring.

    Two config shapes bit here. A trailing slash (`/v1/messages/`) made the
    endpoint it names return 403, because neither the equality nor the
    segment-anchored comparison matched. And a bare `/` allowed everything,
    which is an allowlist that reads as a restriction and behaves as an
    open proxy -- the single worst way for this file to be wrong."""
    out = []
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue
        if not item.startswith("/"):
            item = "/" + item
        if item.strip("/") == "":
            # A bare "/" or "//" survives normalization as an empty prefix, which
            # every path matches. Refuse it loudly rather than resolve it to
            # something: an allowlist that reads as a restriction and behaves as
            # an open proxy is the single worst way for this to be wrong.
            raise RuntimeError(
                "ANDYUR_BROKER_ALLOW_PATHS may not contain a root path: it would "
                "allow every upstream path, including account and key management")
        out.append(item.rstrip("/"))
    if not out:
        # An empty allowlist refuses everything, which is safe and silent -- the
        # broker simply 403s every model call and no config error is ever
        # reported. Fail at startup where it can be read.
        raise RuntimeError(
            "ANDYUR_BROKER_ALLOW_PATHS is empty: the broker would refuse every "
            "model call")
    return tuple(out)


_ALLOWED_PREFIXES = _parse_prefixes(os.environ.get(
    "ANDYUR_BROKER_ALLOW_PATHS", "/v1/messages,/v1/models,/v1/complete"))

# Ceiling on model calls per run. A bound, not a budget: it exists so a looping
# or subverted run cannot spend without limit before anyone notices. Cost-based
# budgets belong here too, and would read the usage the response reports.
_MAX_CALLS = int(os.environ.get("ANDYUR_BROKER_MAX_CALLS_PER_RUN", "500"))

# Metering. Kept in memory on purpose: the broker is a hot path, and a proxy that
# writes to a database on every model call fails when the database does. The
# control plane already records authoritative per-run cost from the run result;
# this exists to ENFORCE, and to answer "what is running right now".
_calls: dict[str, int] = {}
_lock = threading.Lock()
# Bound the table. Without eviction a long-lived broker accumulates one entry per
# run forever, and a run id is never reused so nothing ever reclaims them.
_MAX_TRACKED_RUNS = int(os.environ.get("ANDYUR_BROKER_MAX_TRACKED_RUNS", "10000"))

# Liveness cache: run_id -> (checked_at, alive). The control plane is the only
# thing that knows whether a run still exists, and asking it on every model call
# would put it on the hot path of inference. A few seconds of staleness is the
# price; the ceiling above bounds what that staleness can cost.
_LIVENESS_TTL = float(os.environ.get("ANDYUR_BROKER_LIVENESS_TTL", "10"))
_MAX_TRACKED_LIVENESS = _MAX_TRACKED_RUNS
# How long a cached "alive" may be served while the control plane is unreachable
# before the broker stops spending. Bounded, because an attacker who can make the
# check fail must not thereby make it permanent.
_LIVENESS_GRACE = float(os.environ.get("ANDYUR_BROKER_LIVENESS_GRACE", "60"))
_liveness: dict[str, tuple[float, bool]] = {}

# Headers we never forward upstream: the client's auth (we replace it with the
# real key) and every hop-by-hop header, which by RFC 9110 describes THIS
# connection and is meaningless -- or harmful -- on the next one. `connection`
# and `keep-alive` are about the agent-to-broker socket; `te`/`upgrade` invite
# the provider to renegotiate a protocol the agent chose; `expect: 100-continue`
# makes the upstream wait on a handshake this proxy will never complete on its
# behalf; and `proxy-authorization` is a credential addressed to the proxy
# itself, so forwarding it hands the provider something it was never meant to
# see. Forwarding what you do not understand is how a proxy lends authority.
_DROP_REQ = {"host", "content-length", "x-api-key", "authorization",
             "accept-encoding", "connection", "keep-alive", "te", "trailer",
             "transfer-encoding", "upgrade", "proxy-authorization",
             "proxy-connection", "expect"}
# content-encoding is dropped because _stream() hands back a DECODED body. The
# two must change together: decode here, or forward the header, never one alone.
#
# date/server are dropped because THIS response is generated here, and uvicorn
# supplies its own. Passing the upstream's through produced two of each, and
# RFC 9110 makes Date a singleton -- clients are entitled to reject a duplicate,
# and the count compounded per hop (agent -> model proxy -> broker -> provider).
_DROP_RESP = {"content-length", "content-encoding", "transfer-encoding",
              "connection", "keep-alive", "date", "server"}

app = FastAPI(title="andyur-broker")
_client = httpx.AsyncClient(base_url=BROKER_UPSTREAM, timeout=600.0)

# Control-plane client for the liveness check, built ON FIRST USE and never at
# import. Building it eagerly was worse than the problem it solved: fetching an
# SVID blocks until SPIRE answers, so `import andyur.broker` hung for 30s and
# then died before main() ever ran. A module that cannot be imported without a
# working identity infrastructure is a module that cannot be tested, either.
#
# It carries the same TLS posture as every other component, because with
# ANDYUR_MTLS on the control plane demands a client certificate and a bare
# client would fail every check forever.
_control_plane: httpx.AsyncClient | None = None
# -inf, not 0.0: monotonic() is uptime, so a zero sentinel makes "we failed
# recently" TRUE for the first ANDYUR_BROKER_TLS_RETRY seconds after boot, and
# the broker refuses to even attempt identity setup on a freshly started host.
_cp_failed_at: float = float("-inf")
# One builder at a time. Without it, N concurrent first-callers each ran the
# blocking SVID fetch and each built a client, and N-1 were dropped still open:
# an fd and connection-pool leak proportional to concurrency, repeated at every
# rebuild boundary for the life of the process.
_cp_lock = asyncio.Lock()
# How long to stop retrying identity setup after it fails. Without this, a
# failure is not cached at all and EVERY request pays the full SVID timeout
# again, serialized -- ten queued runs became minutes of a frozen broker.
_CP_RETRY_AFTER = float(os.environ.get("ANDYUR_BROKER_TLS_RETRY", "30"))
# Rebuild the client periodically so a rotated SVID is picked up. An X509-SVID
# is short-lived by design (SPIRE's default is an hour); a client built once and
# kept forever starts failing every handshake when its certificate expires, and
# nothing short of a restart recovers.
_CP_MAX_AGE = float(os.environ.get("ANDYUR_BROKER_TLS_MAX_AGE", "1800"))
_cp_built_at: float = 0.0


async def _cp_client() -> httpx.AsyncClient:
    """The control-plane client, built off the event loop.

    identity.client_tls fetches an SVID from the Workload API, which is a
    synchronous network call bounded by a 30s timeout. Calling it inline in an
    async handler freezes the entire broker for that long -- every concurrent
    proxy and every in-flight streaming response -- which is the exact failure
    the liveness check was made async to avoid. Moving it from import time to
    request time did not fix it; it moved it somewhere worse, because now it can
    happen repeatedly.
    """
    global _control_plane, _cp_failed_at, _cp_built_at
    async with _cp_lock:
        now = time.monotonic()
        if _control_plane is not None and now - _cp_built_at > _CP_MAX_AGE:
            # Drop the reference and let it be collected once the requests
            # holding it finish. Closing it here tore down the connection pool
            # underneath liveness checks that were already on the wire, turning
            # a routine credential refresh into failed requests.
            _control_plane = None
        if _control_plane is None:
            if now - _cp_failed_at < _CP_RETRY_AFTER:
                raise RuntimeError("control-plane client unavailable (retry pending)")
            loop = asyncio.get_running_loop()
            try:
                cert, verify = await loop.run_in_executor(
                    None, identity.client_tls, "broker")
            except Exception:
                _cp_failed_at = time.monotonic()
                raise
            _control_plane = httpx.AsyncClient(
                base_url=SERVER_URL, timeout=3.0, cert=cert, verify=verify)
            _cp_built_at = time.monotonic()
        return _control_plane


def _presented_credential(request) -> str:
    """The one place the caller's credential is read.

    It was read in two places with subtly different rules: an empty bearer plus a
    valid x-api-key authenticated in one and produced nothing in the other, so
    the liveness check went out with no token, got a 401, and -- since a 401 now
    means "cannot confirm" -- 503'd every model call with nothing cached to fall
    back on. Two functions doing the same parse is the bug."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        if token:
            return token
    return request.headers.get("x-api-key", "")


def _authenticate(request: Request) -> dict:
    """Identify the run behind this call, or refuse it.

    The model client sends its credential as a bearer token (the Anthropic SDK's
    ANTHROPIC_AUTH_TOKEN) or as x-api-key; accept either, since which one the
    client uses is its business and not a security property.

    In the dev profile an unauthenticated call is allowed through, because the
    broker then sits on loopback beside a single trusted operator and demanding
    a token would only teach people to disable the check. In production it is
    required: there, the broker is reachable by every run container.
    """
    presented = _presented_credential(request)
    if not presented:
        if PROD:
            raise HTTPException(401, "broker requires a run credential")
        return {"run_id": "anonymous", "agent": None}
    try:
        # PURPOSE_BROKER: a control-plane run token presented here is REFUSED.
        # The two credentials name the same run and must not substitute for one
        # another, or the token the agent is allowed to hold becomes the token
        # it is not.
        return runtoken.verify(presented, purpose=runtoken.PURPOSE_BROKER)
    except runtoken.InvalidRunToken as exc:
        raise HTTPException(401, f"invalid broker credential: {exc}")


def _authorize_path(path: str) -> str:
    """Refuse any upstream path outside inference, and return the path to send.

    The provider key may be able to do far more than run a model: read the
    organization, list workspaces, mint further API keys. A proxy that forwards
    whatever path it is handed lends the agent all of it, and the agent is the
    component we assume is compromised.

    NORMALIZE FIRST, THEN AUTHORIZE, AND FORWARD WHAT YOU CHECKED. Checking the
    raw path is a bypass, not a nit: `/v1/messages/../../v1/organizations/api_keys`
    starts with an allowed prefix, so a raw check permits it, and the HTTP client
    then applies RFC 3986 dot-segment removal before the request leaves -- so the
    path that arrives upstream, carrying the real key, is the one that was never
    authorized. The check and the request must be about the same string.

    Segment-anchored, too. A bare prefix match forwards `/v1/messages_evil`,
    which reads as "these endpoints" and behaves as "these string prefixes".
    """
    # Refuse anything that could mean something DIFFERENT to the upstream than
    # it means here. normpath understands `/../`; it has no idea that `%252e%252e`
    # is a dot segment one decode away, that `..;` is a parameter many servers
    # strip, or that `\..\` is a separator on some. This proxy normalized and
    # then forwarded byte-for-byte, which is correct only if nobody downstream
    # decodes again -- and gateways in front of a provider routinely do.
    #
    # An inference path needs none of these characters, so the safe reading is
    # the strict one: a request that requires interpretation to be safe is a
    # request to refuse.
    raw = "/" + path.lstrip("/")
    if any(ch in raw for ch in ("%", ";", "\\")):
        raise HTTPException(403, "broker forwards inference paths only")
    full = posixpath.normpath(raw)
    # normpath leaves a leading `..` in place when it cannot resolve one, which
    # would escape the base URL entirely. Nothing legitimate produces it.
    if full.startswith("..") or "/../" in full:
        raise HTTPException(403, "broker forwards inference paths only")
    for prefix in _ALLOWED_PREFIXES:      # already normalized, no trailing slash
        if full == prefix or full.startswith(prefix + "/"):
            return full
    raise HTTPException(403, "broker forwards inference paths only")


def _evict_lru(table: dict, limit: int) -> None:
    """Drop the least recently TOUCHED entries. Callers must hold _lock.

    Insertion order is not recency order: `d[k] = v` on an existing key leaves
    its position alone, so a dict iterated front-to-back yields the OLDEST
    entries, and the oldest entry of a call table is the run that has been
    talking longest -- the one whose count matters most. Every writer here
    move-to-ends first (pop then reinsert), which is what makes the front of
    the dict genuinely cold.
    """
    for stale in list(table)[: len(table) - limit]:
        table.pop(stale, None)


def _meter(run_id: str) -> None:
    """Count this call against the run, and stop the run that will not stop.

    THE CEILING WAS RESETTABLE. This did `_calls[run_id] = used`, which does not
    move an existing key, so the longest-lived run sat permanently at the front
    of the dict and was the FIRST evicted on overflow -- taking its count with
    it and starting the run back at zero. A run that wanted to spend without
    limit only had to cause enough distinct run ids to appear (10k at defaults),
    and could repeat it indefinitely. The eviction meant to bound memory
    unbounded the thing the ceiling exists to bound.
    """
    with _lock:
        used = _calls.pop(run_id, 0) + 1   # pop+reinsert = move to the hot end
        _calls[run_id] = used
        if len(_calls) > _MAX_TRACKED_RUNS:
            _evict_lru(_calls, _MAX_TRACKED_RUNS)
    if used > _MAX_CALLS:
        raise HTTPException(
            429, f"run exceeded its model-call ceiling ({_MAX_CALLS})")


async def _assert_run_is_live(ctx: dict) -> None:
    """Refuse to spend on behalf of a run that no longer exists.

    The credential here is one the agent is DESIGNED to hold -- its model client
    reads it from the environment -- so it is the platform credential most easily
    exfiltrated, and its TTL outlives the run by design. Without this check,
    killing a run does not stop it spending: the token keeps buying inference on
    the platform's key until it expires, from anywhere that can reach this port.

    The control plane already refuses a run token whose run has finished, for
    exactly this reason. The asymmetry was the bug: the credential kept OUT of
    the agent's reach was liveness-checked, and the one placed IN it was not.

    Fails CLOSED after a sustained outage, the same rule the runner's halt poll
    uses: a check that can be defeated by making it fail is not a check. A brief
    blip is tolerated from cache, because a control-plane hiccup should not stop
    every agent mid-thought.

    ASYNC, and that is not a style preference. A blocking call here freezes the
    whole broker -- every concurrent proxy and every in-flight streaming
    response -- for the duration, so one slow control plane turns into a
    platform-wide inference stall in the single component that holds the
    provider key.
    """
    run_id = ctx.get("run_id")
    if not run_id or not PROD:
        return
    now = time.monotonic()
    cached = _liveness.get(run_id)
    if cached and now - cached[0] < _LIVENESS_TTL:
        if not cached[1]:
            raise HTTPException(403, "run is no longer live")
        return
    alive = None
    try:
        client = await _cp_client()
        r = await client.get(
            f"/runs/{run_id}/live",
            headers=_check_auth(ctx),
        )
        # ONLY an explicit, well-formed answer decides a run is dead. A 500 (a
        # database outage, say) means the control plane could not answer, not
        # that the run ended -- treating those the same killed healthy runs and,
        # worse, cached the mistake, locking a live run out for the whole TTL.
        if r.status_code == 200:
            body = r.json()
            alive = body.get("live") is True
    except Exception:
        alive = None
    if alive is None:
        # Unavailable. Keep serving on the last known-good answer until it goes
        # stale, then stop: unreachable is not permission.
        if cached and now - cached[0] < _LIVENESS_GRACE and cached[1]:
            return
        raise HTTPException(503, "cannot confirm the run is live")
    with _lock:
        _liveness.pop(run_id, None)        # move to the hot end, as in _meter
        _liveness[run_id] = (now, alive)
        if len(_liveness) > _MAX_TRACKED_LIVENESS:
            _evict_lru(_liveness, _MAX_TRACKED_LIVENESS)
    if not alive:
        raise HTTPException(403, "run is no longer live")


def _check_auth(ctx: dict) -> dict:
    """Present the RUN's own broker credential when asking about that run.

    So the liveness endpoint is not an open oracle: you can only ask about a run
    whose credential you already hold. The broker has no identity of its own to
    offer, but it does not need one -- it is asking on behalf of a caller that
    just proved which run it is."""
    token = ctx.get("_presented")
    return {"X-Andyur-Run-Token": token} if token else {}


def _forward_headers(incoming) -> dict:
    """Build the upstream headers: drop the client's auth (it never holds a real
    key) and inject the broker's key. This is the security-critical step."""
    headers = {k: v for k, v in dict(incoming).items() if k.lower() not in _DROP_REQ}
    if _API_KEY:
        headers["x-api-key"] = _API_KEY  # the credential the agent never holds
    headers.setdefault("anthropic-version", _ANTHROPIC_VERSION)
    return headers


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


@app.get("/usage")
async def usage(request: Request) -> dict:
    """This run's live model-call count and the ceiling it is measured against.

    Registered ABOVE the catch-all proxy below, because FastAPI matches routes in
    definition order and `/{path:path}` swallows everything after it -- an
    operational endpoint defined later is silently unreachable.

    Scoped to the CALLER's run, never the whole table. A run enumerating every
    other run's id and spend is reconnaissance: it names live targets and shows
    which are busy. Platform-wide spend belongs to the control plane, which
    already records authoritative per-run cost and has an operator identity to
    authorize the question.
    """
    ctx = _authenticate(request)
    run_id = ctx.get("run_id") or "anonymous"
    with _lock:
        used = _calls.get(run_id, 0)
    return {"run_id": run_id, "calls": used, "ceiling": _MAX_CALLS}


@app.api_route(
    "/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
)
async def proxy(path: str, request: Request) -> Response:
    # Order matters: cheap local decisions first, the remote one last. Checking
    # liveness before the path allowlist would let an unreachable control plane
    # answer 503 to a request that should have been a flat 403, hiding an attack
    # behind an outage -- and it would spend a round trip on traffic that was
    # never going to be forwarded.
    ctx = _authenticate(request)
    ctx["_presented"] = _presented_credential(request)
    # The authorized path is what gets sent. Passing the raw path here after
    # checking a normalized one would reintroduce exactly the bypass the
    # normalization exists to close.
    upstream_path = _authorize_path(path)
    await _assert_run_is_live(ctx)
    _meter(ctx.get("run_id") or "anonymous")
    body = await request.body()
    headers = _forward_headers(request.headers)

    upstream_req = _client.build_request(
        request.method, upstream_path, headers=headers, content=body,
        params=request.query_params,
    )
    upstream = await _client.send(upstream_req, stream=True)
    resp_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in _DROP_RESP
    }

    async def _stream():
        # aiter_bytes, NOT aiter_raw: httpx decodes the upstream's
        # content-encoding for us.
        #
        # This was aiter_raw, which forwards the bytes exactly as they arrived
        # -- still gzipped -- while content-encoding was stripped above, so the
        # caller was handed compressed bytes labelled as plain and every
        # response failed to parse. api.anthropic.com always gzips, so the
        # broker had never actually worked against its real upstream; the local
        # model used in every test does not compress, which is what hid it.
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await upstream.aclose()

    return StreamingResponse(
        _stream(), status_code=upstream.status_code, headers=resp_headers
    )


def main() -> None:
    if BROKER_HOST not in ("127.0.0.1", "localhost", "::1") and not PROD:
        print(
            f"[broker] listening on {BROKER_HOST}:{BROKER_PORT} (non-loopback) in "
            "the DEV profile, so callers are not authenticated. It forwards with "
            "the provider key: firewall this port, or use ANDYUR_PROFILE=prod.",
            flush=True,
        )
    uvicorn.run(app, host=BROKER_HOST, port=BROKER_PORT, log_level="warning")


if __name__ == "__main__":
    main()

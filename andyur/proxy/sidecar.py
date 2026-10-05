"""Per-run proxy sidecar: the credential-handling and routing core.

Thin and Andyur-owned, over OSS (httpx for forwarding, py-spiffe via
`andyur.identity` for the run's SVIDs). NOT a hand-rolled HTTP proxy: the
request/stream plumbing rides on real libraries so the `toolproxy.py` bug class
(header parsing, stream handling) stays out. The committed plan is to replace
this data plane with Envoy + ext_authz after the end-to-end demo is green.

The flow this serves (`docs/reviews/spire-registry-v2-review-notes.md` /
`spire-registry-design-v2.md`):

    agent --(loopback, NO credential)--> sidecar
        sidecar strips anything the agent sent (S1/S2) and holds the run's SVIDs
        tools:    sidecar --delegated token--> tool, over mTLS (run X509-SVID)
                  when the reach_url is https; production refuses http reach_urls
        LLM/REST: sidecar --token--> shared LLM gateway (LiteLLM) --> provider

This module is Phase 1: the security-critical, side-effect-free core --
inbound credential stripping, the run's identity material, outbound header
construction, and route classification. The HTTP listener, the RFC 8693 exchange
to mint the delegated token, and the mTLS forward are Phase 2, and slot onto the
pieces here.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from typing import Callable, Mapping
from urllib.parse import urlsplit

# The headers the sidecar SETS for the exchange leg. The agent never sets these;
# it cannot, because they are in the strip set below and overwritten regardless.
ACTOR_TOKEN_HEADER = "x-andyur-actor-token"
SUBJECT_TOKEN_HEADER = "x-andyur-subject-token"

# Everything the agent could use to assert an identity or replay a credential.
# Removed from every inbound request BEFORE the sidecar sets the real values, so
# the agent holds no credential and cannot smuggle one (S1/S2). The agent reaches
# the sidecar over loopback inside the run's own network namespace, so there is
# no inbound bearer to preserve -- the boundary is the namespace, not a header.
_STRIP_EXACT = frozenset({
    "authorization", "proxy-authorization", "cookie",
    # native Anthropic auth: the agent talks to the LLM leg with `x-api-key`, and
    # it must never carry through -- the sidecar replaces it with the gateway's
    # service credential, which the agent never holds.
    "x-api-key",
})
_STRIP_PREFIXES = ("x-andyur-",)


def strip_inbound(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a copy of the agent's request headers with every credential- and
    identity-bearing header removed, case-insensitively. Content headers
    (content-type, accept, and the rest) are preserved so the forwarded request
    is still a valid MCP/HTTP call."""
    out: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in _STRIP_EXACT:
            continue
        if any(lowered.startswith(prefix) for prefix in _STRIP_PREFIXES):
            continue
        out[key] = value
    return out


@dataclasses.dataclass(frozen=True)
class ToolRoute:
    """One managed tool the sidecar can reach on the run's behalf.

    `audience` is the manifest's resource_id (the authorization audience), NOT
    derived from `reach_url` -- reach_url is routing only. scheme/host/port/path
    are the validated split of reach_url for the outbound connection; the
    sidecar rebuilds the upstream URL from them (never from the agent's
    request), so an https reach_url gets a real TLS handshake with the run's
    X509-SVID as the client certificate.
    """
    name: str
    reach_url: str
    audience: str
    scheme: str
    host: str
    port: int
    path: str
    credential_mode: str = "managed"
    credential_ref: str | None = None
    # Which headers this binding's brokered credential may set, carried from the
    # registry. The sidecar refuses anything the vault returns outside it.
    credential_headers: tuple[str, ...] = ()
    # The SERVER'S per-run decision: exactly the tools this run may call on this
    # binding. `None` means the binding enumerates nothing and the leg stays
    # audience-authorized; a tuple -- even an empty one -- means it enumerates
    # and this is the whole set.
    #
    # The sidecar does not compute this. It used to, from the binding's static
    # grants with a hardcoded `actions: None`, which short-circuited to "every
    # enumerated tool" and dropped the run's narrowed authority on the floor.
    permitted_tools: tuple[str, ...] | None = None

    @classmethod
    def from_managed(cls, name: str, entry: Mapping) -> "ToolRoute":
        """Build from a `managed_from_resolution` entry
        ({url, audience, scheme, host, port, path})."""
        return cls(name=name, reach_url=entry["url"], audience=entry["audience"],
                   scheme=entry["scheme"], host=entry["host"],
                   port=int(entry["port"]), path=entry["path"],
                   credential_mode=entry.get("credential_mode", "managed"),
                   credential_ref=entry.get("credential_ref"),
                   credential_headers=tuple(
                       entry.get("credential_headers") or ()),
                   permitted_tools=(
                       None if entry.get("permitted_tools") is None
                       else tuple(entry["permitted_tools"])))


class RunIdentity:
    """The run's credential material, held by the sidecar and never by the agent.

    The three pieces come from different places and are kept behind callables so
    this is testable without SPIRE or a live AS:

      subject_token   the user's token (T0), read from the run record
      actor_token()   the run's JWT-SVID, fetched from the SPIRE Agent Workload
                      API over UDS (audience = the AS); the RFC 8693 actor leg
      mtls_material() {cert, key, bundle} paths for the run's X509-SVID, for the
                      mTLS client cert presented to tools (the S5 leg)

    Fetched through callables rather than at construction so a rotation is a fresh
    call, and so a test injects fakes instead of standing up SPIRE.
    """

    def __init__(self, subject_token: str,
                 actor_token: Callable[[], str],
                 mtls_material: Callable[[], Mapping[str, str]],
                 expected_subject: str = "", expected_actor: str = ""):
        self._subject_token = subject_token
        self._expected_subject = expected_subject
        self._expected_actor = expected_actor
        self._actor_token = actor_token
        self._mtls_material = mtls_material

    @property
    def subject_token(self) -> str:
        return self._subject_token

    @property
    def expected_subject(self) -> str:
        return self._expected_subject

    @property
    def expected_actor(self) -> str:
        return self._expected_actor

    def actor_token(self) -> str:
        return self._actor_token()

    def mtls_material(self) -> Mapping[str, str]:
        return self._mtls_material()

    def exchange_headers(self) -> dict[str, str]:
        """The headers that carry the two legs to the AS's token endpoint:
        subject (the user) and actor (the run). This is what the exchange reads;
        `set`, so whatever the agent sent under these names is already gone."""
        return {
            SUBJECT_TOKEN_HEADER: self._subject_token,
            ACTOR_TOKEN_HEADER: self._actor_token(),
        }


@dataclasses.dataclass(frozen=True)
class Route:
    """The classification of one inbound request."""
    kind: str                       # "tool" | "llm" | "unknown"
    tool: ToolRoute | None = None


class Router:
    """Maps an inbound request path to a tool or the LLM/REST egress.

    Convention (loopback, single listener): a tool is reached under
    `/tools/<name>/...` and the model/REST egress under `/llm/...`. The agent's
    tool config points each tool at the matching sidecar path, so the sidecar
    never has to guess an audience from a URL -- it looks the tool up by name and
    uses the manifest's resource_id.
    """

    def __init__(self, tools: Mapping[str, ToolRoute], llm_prefix: str = "/llm"):
        self._tools = dict(tools)
        self._llm_prefix = llm_prefix.rstrip("/")

    @property
    def has_tools(self) -> bool:
        return bool(self._tools)

    @property
    def has_brokered_tools(self) -> bool:
        return any(tool.credential_mode == "brokered" for tool in self._tools.values())

    def classify(self, path: str) -> Route:
        parts = urlsplit(path).path.strip("/").split("/")
        if parts and parts[0] == "tools" and len(parts) >= 2:
            tool = self._tools.get(parts[1])
            return Route("tool", tool) if tool else Route("unknown")
        if urlsplit(path).path.rstrip("/") == self._llm_prefix or \
                urlsplit(path).path.startswith(self._llm_prefix + "/"):
            return Route("llm")
        return Route("unknown")


# --- Phase 2: minting the delegated token for a tool call ---------------------

def exchange_request(identity: RunIdentity, route: ToolRoute,
                     scope, pin) -> dict:
    """The kwargs for the RFC 8693 exchange for one tool call.

    resource AND audience are the manifest's `resource_id` (the canonical
    audience), never derived from the reach_url. scope is the run's narrowed
    grant; authorization_details is the pin. Pure, so the request the sidecar
    would make is asserted directly."""
    return dict(
        subject_token=identity.subject_token,
        expected_subject=identity.expected_subject,
        expected_actor=identity.expected_actor,
        actor_token=identity.actor_token(),
        resource=route.audience,
        audience=route.audience,
        scope=scope,
        authorization_details=pin,
    )


class TokenCache:
    """Delegated tokens cached per (audience, scope, pin) for their TTL.

    Without this the exchange rate is one AS round trip per tool call; with it,
    `runs x audiences / TTL`. The TTL is floored so a mint the AS marks as very
    short-lived does not make the cache useless, and a small skew is subtracted
    so a token is re-minted before, not after, it expires.

    Deliberately not clock-injected beyond `time.monotonic`: a cache that serves
    a stale token is a wrong-authority bug, so it errs toward re-minting.
    """

    def __init__(self, floor: float = 30.0, skew: float = 5.0):
        self._floor = floor
        self._skew = skew
        self._entries: dict[tuple, tuple[str, float]] = {}
        self._lock = threading.RLock()
        self._closed = False

    @staticmethod
    def key(route: ToolRoute, scope, pin, binding: str = "") -> tuple:
        scope_key = tuple(scope) if scope else ()
        return (route.audience, scope_key, pin or "", binding)

    def get(self, key: tuple) -> str | None:
        with self._lock:
            if self._closed:
                raise RuntimeError("the run token cache is closed")
            hit = self._entries.get(key)
            if hit is None:
                return None
            token, expires_at = hit
            if time.monotonic() >= expires_at:
                self._entries.pop(key, None)
                return None
            return token

    def put(self, key: tuple, token: str, expires_in: float | None) -> None:
        # Never extend an AS-signed lifetime. The floor controls exchange churn
        # only for responses that omit expiry; a shorter verified TTL wins.
        ttl = float(expires_in) if expires_in is not None else self._floor
        with self._lock:
            if self._closed:
                raise RuntimeError("the run token cache is closed")
            self._entries[key] = (token, time.monotonic() + ttl - self._skew)

    def close(self) -> None:
        with self._lock:
            self._entries.clear()
            self._closed = True

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed


def delegated_token(identity: RunIdentity, route: ToolRoute, scope, pin,
                    exchange_fn: Callable[..., Mapping], cache: TokenCache, *,
                    binding: str = "", exchange_extra: Mapping | None = None) -> str:
    """The token to present to `route`'s tool: from cache, or freshly exchanged.

    `exchange_fn` is injected (defaults to `asclient.exchange` at the call site)
    so this is testable without a live AS. Raises whatever the exchange raises;
    there is no degraded success -- a call that cannot mint withholds."""
    k = cache.key(route, scope, pin, binding)
    cached = cache.get(k)
    if cached is not None:
        return cached
    request = exchange_request(identity, route, scope, pin)
    request.update(exchange_extra or {})
    resp = exchange_fn(**request)
    token = resp["access_token"]
    cache.put(k, token, resp.get("expires_in"))
    return token

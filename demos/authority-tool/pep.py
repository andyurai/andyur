"""A policy enforcement point for an MCP server that accepts Andyur's tokens.

COPY THIS INTO YOUR OWN MCP SERVER. It is deliberately not part of the `andyur`
package. Andyur is the trust domain's context authority; the resource server is
YOURS, and so is the decision it makes. Andyur making that decision for you would
be the same category error as Andyur being your authorization server.

Everything here is standard OAuth 2.1 resource-server behaviour against a JWKS.
There is nothing Andyur-specific in the mechanism -- only in which claims carry
which fact, which is what the module docstrings name.

WHY THIS EXISTS AT ALL. Until it did, Andyur minted narrow, audience-bound,
pinned tokens and **nothing on the receiving side checked any of it**. Every
constraint was self-asserted. A resource server that validates is what turns a
minted constraint into an enforced one; half a handshake is not a handshake.

WHAT THIS DOES NOT CHECK, and you should know before relying on it:

  * `cnf` (RFC 8705 certificate binding) is checked by `verify_cnf` -- but only
    a server whose transport carries client certificates can call it, because
    the check needs the LIVE peer certificate of the very connection the token
    arrived on. `verify_token` runs inside the MCP SDK's auth hook, which has
    no connection context, so it cannot do this for you: wire `verify_cnf`
    where your server sees the TLS peer (the Envoy data-plane gate does). A
    token WITHOUT `cnf` remains a BEARER: possession is sufficient. Pass
    `require_cnf=True` to refuse those too.
  * `act.sub` against the mTLS peer identity. The design requires these be equal,
    because without it a valid token and a valid but DIFFERENT identity can be
    combined. That check needs client certificates on the connection, which this
    transport does not carry.

Both are named in `verify_token`'s own log line rather than silently skipped. A
PEP that omits a check quietly is worse than one that omits it loudly, because
the operator believes the check happened.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time

from typing import TYPE_CHECKING

import anyio
import jwt
from jwt import PyJWKClient

if TYPE_CHECKING:
    # For type-checkers only; the runtime import lives inside verify_token so a
    # resource server on any framework can use require()/verify_cnf without the
    # MCP SDK installed.
    from mcp.server.auth.provider import AccessToken

log = logging.getLogger(__name__)

# Andyur's RAR type. The pin ("what the work is about") travels under this, so a
# resource server can answer "was this token minted for the account I am being
# asked to touch?" without calling anyone back.
AUTHORITY_TYPE = "urn:andyur:authority"
# The shape an EXTERNAL authorization server issues. RFC 9396 details are
# registered by type at the AS, and an opaque urn is not something an adopter
# will add to their policy store; a plain name is.
PIN_TYPE = "andyur_pin"
# How long the JWKS fetch may take, and how long an unresolvable `kid` is
# remembered. Both exist to bound what an unauthenticated caller can cost.
JWKS_TIMEOUT = 3
UNKNOWN_KID_TTL = 60


# THE SDK'S AccessToken DROPS WHAT IT DOES NOT DECLARE.
#
# `mcp.server.auth.provider.AccessToken` is a plain pydantic BaseModel with
# five fields and the default `extra="ignore"`. Passing `claims=` and
# `subject=` to it therefore SILENTLY discards them -- no error, no warning --
# and every `require()` downstream then reads an EMPTY claims dict. That is not
# a fail-closed loss: an empty dict means no `restricted` flag and no actions,
# which reads as UNRESTRICTED for actions while still failing closed on pins.
# So the visible symptom is "the token names no 'service'" while scope
# enforcement has quietly stopped happening.
#
# Subclassing declares the two fields, so they survive. Checked at import
# rather than assumed, because the shape of an upstream model is not ours.
def _access_token_class():
    from mcp.server.auth.provider import AccessToken as _Base

    class AndyurAccessToken(_Base):
        claims: dict = {}
        subject: str = ""

    probe = AndyurAccessToken(token="x", client_id="c", scopes=[],
                              expires_at=0, claims={"sub": "probe"}, subject="probe")
    if probe.claims.get("sub") != "probe":
        raise RuntimeError(
            "the MCP AccessToken subclass does not carry `claims`; refusing to "
            "start a PEP that would authorise against an empty claim set")
    return AndyurAccessToken


class AndyurTokenVerifier:
    """Verifies an Andyur-minted `at+jwt` against Andyur's published JWKS.

    `audience` is THIS server's canonical resource identifier. It is the whole
    point: a token minted for another target must be refused here even though it
    is perfectly valid there. Passing None disables that check, which defeats the
    control, so it is not permitted.
    """

    def __init__(self, jwks_url: str, issuer: str, audience: str,
                 leeway: int = 30):
        if not audience:
            raise ValueError(
                "a resource server must know its own audience; without it every "
                "valid token in the trust domain is accepted here")
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway
        # BOUNDED, and off the event loop. PyJWKClient's fetch is synchronous
        # urllib, and PyJWT refetches on ANY unmatched kid -- bypassing the
        # cache. That is an unauthenticated remote DoS: a token needs no valid
        # signature and no valid claims to carry a `kid`, and each one forced a
        # blocking fetch inside `async def verify_token`. Measured against a slow
        # JWKS: ten hostile requests froze the server for 50s and a legitimate
        # call that had been served in 0.02s took 4.75s.
        #
        # Three things fix it: a short timeout, running the fetch in a worker
        # thread, and remembering kids that have just failed so a flood cannot
        # force a refetch per request.
        self._keys = PyJWKClient(jwks_url, cache_keys=True, lifespan=300,
                                 timeout=JWKS_TIMEOUT)
        self._unknown_kids: dict[str, float] = {}

    def _recently_unknown(self, kid: str) -> bool:
        seen = self._unknown_kids.get(kid)
        if seen is None:
            return False
        if time.monotonic() - seen > UNKNOWN_KID_TTL:
            self._unknown_kids.pop(kid, None)
            return False
        return True

    def _signing_key_for(self, token: str):
        """Runs in a worker thread. Records a kid we could not resolve, so a
        flood of unknown kids cannot force one JWKS fetch per request."""
        try:
            return self._keys.get_signing_key_from_jwt(token).key
        except Exception:
            kid = jwt.get_unverified_header(token).get("kid")
            if isinstance(kid, str):
                if len(self._unknown_kids) > 512:
                    self._unknown_kids.clear()
                self._unknown_kids[kid] = time.monotonic()
            raise

    async def verify_token(self, token: str) -> "AccessToken | None":
        """Return an AccessToken if the presentation is valid, else None.

        None rather than an exception: the SDK turns it into a 401, and the
        reason belongs in OUR log, not in a response body that would tell an
        unauthenticated caller which check it failed.

        The MCP SDK is imported HERE, not at module load: `require` and
        `verify_cnf` are useful to a resource server on any framework, and
        forcing it to install the MCP SDK just to import this file would be a
        false dependency. Only this method, which returns the SDK's
        AccessToken, actually needs it.
        """
        AccessToken = _access_token_class()
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:                       # noqa: BLE001
            log.warning("token refused: unreadable header (%s)", exc)
            return None
        # RFC 9068 sec 4: an `at+jwt` consumer must reject a token that is not
        # typed as one. Without this an ID token from the same issuer, which is
        # for a different purpose entirely, would validate here.
        # RFC 9068 sec 2.1 permits `at+jwt` AND the media-type form
        # `application/at+jwt`, and RFC 7519 makes the type case-insensitive.
        # Refusing the other spellings locks out a conforming issuer.
        typ = header.get("typ")
        if not isinstance(typ, str) or typ.lower().removeprefix("application/") \
                != "at+jwt":
            # Truncated: `typ` is attacker-chosen and unbounded, and this line is
            # written on every unauthenticated request.
            log.warning("token refused: typ is %.64r, not at+jwt", typ)
            return None
        kid = header.get("kid")
        if isinstance(kid, str) and self._recently_unknown(kid):
            log.warning("token refused: kid %r was unresolvable moments ago; "
                        "not refetching the JWKS for it", kid[:64])
            return None
        try:
            key = await anyio.to_thread.run_sync(
                self._signing_key_for, token)
            claims = jwt.decode(
                token, key,
                # Pinned. Without an explicit list a token names its own
                # algorithm, and "none" is an algorithm.
                #
                # Worth knowing what actually stops RS256->HS256 confusion in
                # THIS stack, so nobody relies on the wrong thing: PyJWKClient
                # hands PyJWT an RSAPublicKey object and HS256 needs a string
                # secret, so PyJWT refuses on the key type before this list is
                # consulted. Widening this list does not open the attack here.
                # Keep it pinned anyway -- that guard is PyJWT's, not ours, and
                # a refactor that passed a PEM string would remove it.
                algorithms=["RS256"],
                # THE audience check. This is what makes a token minted for
                # another target useless here.
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                # `client_id` and `jti` are REQUIRED of an at+jwt by RFC 9068
                # sec 2.2, and sec 4 says a resource server must reject a token
                # missing required claims. Andyur's own mint comment says exactly
                # that; this is the server that has to act on it.
                options={"require": ["exp", "iat", "sub", "aud", "iss",
                                     "client_id", "jti"],
                         "verify_aud": True, "verify_iss": True,
                         "verify_exp": True, "verify_signature": True},
            )
        except Exception as exc:                       # noqa: BLE001
            # The CLASS, not the message. The comment said this and the code
            # logged both anyway; a PyJWT message can carry claim values, and
            # this log is read by people not entitled to them.
            log.warning("token refused by %s", type(exc).__name__)
            return None

        try:
            actions, pin, _ = _authority(claims)
        except Refused as why:
            log.warning("token refused: %s", why)
            return None
        log.info("token accepted: sub=%r act=%r aud=%r jti=%r actions=%s pin=%s "
                 "(cnf NOT checked here -- no connection context in this hook; "
                 "a TLS-terminating server must call verify_cnf with the live "
                 "peer certificate; act.sub NOT bound to a TLS peer)",
                 claims.get("sub"), (claims.get("act") or {}).get("sub"),
                 claims.get("aud"), claims.get("jti"), actions, pin or None)
        return AccessToken(
            token=token,
            # The party that requested the token, per RFC 9068 sec 2.2.
            client_id=str(claims.get("client_id") or ""),
            # What the SDK enforces `required_scopes` against.
            scopes=actions,
            expires_at=int(claims["exp"]),
            resource=self._audience,
            subject=str(claims.get("sub") or ""),
            claims=claims,
        )


def _authority(claims: dict) -> tuple[list[str], dict, bool]:
    """(actions, pin, restricted).

    `restricted` is False only when NOTHING states an action model. It is
    separate from an empty `actions` list on purpose: absent means "no action
    model restricts this token", an explicit `[]` means "nothing is permitted",
    and collapsing them makes a deny-all token read as a permit-all one.

    Multiple entries of our type are REFUSED rather than merged. Merging is not
    safe in either direction: unioning the actions lets a permissive entry widen
    a restrictive one, and last-wins on the pin makes a call the token granted
    get refused. Andyur mints exactly one entry, so anything else is either a
    future format this code does not understand or someone else's construction --
    both of which are reasons to stop, not to guess.
    """
    details = claims.get("authorization_details")
    if details is not None and not isinstance(details, list):
        # RFC 9396 says this is a JSON array. Anything else means we cannot read
        # the pin, and reading actions from `scope` while silently dropping the
        # pin is the fail-open half of that mistake.
        raise Refused("authorization_details is not a list; this token cannot "
                      "be interpreted")
    # TWO SHAPES, one meaning. Andyur's own mint emits
    # `{"type": "urn:andyur:authority", "resources": {...}}`; an external
    # authorization server issues `{"type": "andyur_pin", "identifier": "..."}`,
    # because RFC 9396 details are registered by type at the AS and an opaque urn
    # is not something an adopter will register. Both are read here rather than
    # translated at one end, because this server may receive either depending on
    # who minted -- and a PEP that understood only one would silently find NO
    # PIN in the other, which is the fail-open half of the mistake.
    ours = [d for d in (details or [])
            if isinstance(d, dict)
            and d.get("type") in (AUTHORITY_TYPE, PIN_TYPE)]
    if len({d.get("type") for d in ours}) > 1:
        raise Refused(
            "the token carries authority in more than one format; they cannot "
            "be safely reconciled, so it is refused rather than guessed at")

    pin: dict = {}
    actions: list[str] = []
    restricted = False
    if ours:
        if ours[0].get("type") == PIN_TYPE:
            # One `andyur_pin` per pinned dimension. Every entry must carry an
            # identifier: an entry that names nothing constrains nothing, and
            # treating it as absent would silently unpin the call.
            for entry in ours:
                ident = entry.get("identifier")
                if not isinstance(ident, str) or not ident:
                    raise Refused(
                        "an andyur_pin carries no identifier; it constrains "
                        "nothing, and an unpinned detail is not a detail pinned "
                        "to everything")
                # The pin's dimension, from RFC 9396 `datatypes`. Without it a
                # detail says only "checkout" and cannot answer "was this minted
                # for the TEAM I am being asked about".
                dims = entry.get("datatypes")
                key = (str(dims[0]) if isinstance(dims, list) and dims
                       else "resource")
                pin[key] = ident
                if isinstance(entry.get("actions"), list):
                    actions = [str(a) for a in entry["actions"]]
                    restricted = True
        else:
            if len(ours) > 1:
                raise Refused(
                    f"the token carries {len(ours)} {AUTHORITY_TYPE} entries; "
                    "they cannot be safely merged, so it is refused rather "
                    "than guessed at")
            entry = ours[0]
            if isinstance(entry.get("resources"), dict):
                pin = dict(entry["resources"])
            if isinstance(entry.get("actions"), list):
                actions = [str(a) for a in entry["actions"]]
                restricted = True
    if not restricted:
        scope = claims.get("scope")
        if isinstance(scope, list):
            actions, restricted = [str(s) for s in scope], True
        elif isinstance(scope, str):
            actions, restricted = scope.split(), True
    return actions, pin, restricted




class Refused(Exception):
    """This token does not authorise this call. Raised by `require`."""


def x5t_s256(cert_der: bytes) -> str:
    """The RFC 8705 sec 3.1 certificate thumbprint: base64url-encoded SHA-256
    of the certificate's DER encoding, trailing '=' padding omitted."""
    return base64.urlsafe_b64encode(
        hashlib.sha256(cert_der).digest()).rstrip(b"=").decode()


def verify_cnf(claims: dict, peer_cert_der: bytes | None, *,
               require_cnf: bool = False) -> None:
    """RFC 8705 sender binding: the token is spendable ONLY over the mTLS
    connection whose client certificate it was bound to.

    Call this from a server that terminates TLS itself, passing the DER of the
    LIVE peer certificate on the connection the token arrived on -- a stored or
    reconstructed certificate would verify possession of a file, not of the
    channel, which is the whole point.

    The matrix is fail-closed in every direction that matters:

      * `cnf.x5t#S256` present + peer certificate present -> thumbprints must
        match, or the token was stolen from (or minted for) another workload.
      * `cnf` present + NO peer certificate -> refused. A bound token accepted
        over an unauthenticated channel silently degrades to a bearer.
      * `cnf` present but carrying only a method this server cannot verify
        (`jkt` needs a DPoP proof this function is not given) -> refused. A
        confirmation we cannot check is not a confirmation.
      * no `cnf` at all -> accepted as a bearer (the pre-binding posture),
        unless `require_cnf=True` -- the strict tier for a deployment whose
        authorization server always binds.
    """
    cnf = claims.get("cnf")
    if cnf is None:
        if require_cnf:
            raise Refused(
                "the token carries no cnf confirmation and this server "
                "requires sender-bound tokens")
        return
    if not isinstance(cnf, dict):
        raise Refused("the token's cnf claim is not an object; it cannot be "
                      "interpreted, so it is refused rather than ignored")
    thumb = cnf.get("x5t#S256")
    if not isinstance(thumb, str) or not thumb:
        raise Refused(
            "the token is confirmation-bound with a method this server cannot "
            "verify; accepting it would silently drop the binding")
    if not peer_cert_der:
        raise Refused(
            "the token is bound to a client certificate but this connection "
            "presented none; a bound token must not degrade to a bearer")
    # Compare as BYTES: `thumb` is attacker-influenced, and hmac.compare_digest
    # raises TypeError on a non-ASCII str -- which would surface as a 500 on a
    # token-supplied value instead of a clean refusal. A valid x5t#S256 is
    # base64url (ASCII); anything else simply will not match, which is the
    # correct outcome.
    if not hmac.compare_digest(thumb.encode("utf-8", "surrogatepass"),
                               x5t_s256(peer_cert_der).encode("ascii")):
        raise Refused(
            "the presented client certificate does not match the token's "
            "cnf.x5t#S256: this token was not bound to this channel")


def require(access, action: str, resources: dict | None = None, *,
            allow_unpinned: bool = False) -> dict:
    """Authorise ONE tool call against the presented token.

    Call this at the top of every tool that touches something. `verify_token`
    cannot do it: it runs before the SDK knows which tool was called, so it can
    only establish that the token is genuine and meant for this server. Which
    ACTION on which RESOURCE is a per-call question.

    `resources` is what the caller is asking to touch, e.g. `{"account": "447"}`.
    NAMING A RESOURCE HERE REQUIRES THE TOKEN TO NAME IT TOO. If you ask "may I
    touch account X" and the token says nothing about accounts, the answer is no
    -- not "yes, it did not object".

    That is a correction of a real hole, demonstrated end to end: this loop used
    to be `if key in pin and pin[key] != value`, so a token from an UNPINNED run
    (Andyur omits `authorization_details` entirely when a run has no pin) skipped
    the check completely, and the same user with the same scope could move money
    in any account they named. The resource-side control the whole design rests
    on was off, and nothing said so.

    `allow_unpinned=True` is the deliberate exception, for a tool where an
    unpinned token is genuinely acceptable -- a global read, say. It is a keyword
    so it cannot be passed by accident, and it should be rare enough to argue
    about in review.

    The token is a CEILING. Returning normally means the token permits this; it
    does not mean your own service policy or current state does. Check those too.
    """
    if access is None:
        raise Refused("no verified token on this request")
    claims = getattr(access, "claims", None) or {}
    actions, pin, restricted = _authority(claims)
    if restricted and action not in actions:
        raise Refused(f"the token permits {sorted(actions)}, not {action!r}")
    for key, value in (resources or {}).items():
        if key not in pin:
            if allow_unpinned:
                continue
            raise Refused(
                f"the token names no {key!r}, so it cannot authorise a call "
                f"against {key}={value!r}. An unpinned token is not a token "
                "pinned to everything")
        if str(pin[key]) != str(value):
            raise Refused(
                f"the token is pinned to {key}={pin[key]!r} and this call "
                f"targets {key}={value!r}: it was not minted for this resource")
    return claims


def expires_in(access) -> int:
    """Seconds of validity left, for a server that wants to log the window it is
    accepting. Negative should be impossible -- `verify_token` rejects expired
    tokens -- so a negative here means clock skew worth knowing about."""
    return int(getattr(access, "expires_at", 0) - time.time())

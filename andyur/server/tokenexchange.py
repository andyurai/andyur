"""Downstream delegation via RFC 8693 token exchange (U4).

When a run acting for Alice delegates to another AGENT, the authority must travel
WITH the request and may only get narrower. (The delegatee is always a registered
agent -- an external tool or service is the `audience` a grant is spent AT, not the
actor it is minted for, because the actor's ceiling is read from the agent
registry.) This module mints a downstream grant that:

  * keeps the SAME user (`sub`): delegation never drops or swaps the human it acts for;
  * appends the delegatee to a nested `act` chain (RFC 8693 actor claim), so the full
    "Alice, via scout, via reviewer" provenance is auditable in one token;
  * narrows the scope to a SUBSET of the parent's (equal or tighter, never wider) --
    widening is impossible by construction, not by a check that could be forgotten;
  * binds an audience so a token minted for one target cannot be replayed at another.

The internal run token (HMAC, see runtoken.py) stays for server-internal calls: the
server holds the secret and is both minter and verifier. A downstream/external target
is NOT the server, so it cannot share that secret. This exchange therefore issues an
ASYMMETRIC (RS256) JWT the target validates against Andyur's published JWKS
(`/.well-known/jwks.json`) without ever calling back -- the standard OAuth pattern.

Opt-in: a shared RSA key across replicas vian ANDYUR_EXCHANGE_KEY (a PEM path); if
unset an ephemeral keypair is generated at first use (single node / dev only, since
replicas would each mint under a different key).
"""

from __future__ import annotations

import json
import logging
import secrets
import time

from .. import config
from . import runtoken
from . import registry

log = logging.getLogger(__name__)

_KID = "andyur-exchange"
# The RFC 9396 authorization_details type. A collision-resistant URN rather than a
# bare word: RFC 9396 sec 2.1 recommends a namespace the API designer controls for
# any API deployed across different servers, and Andyur is meant to be deployed by
# others. Changing it later breaks every resource server that pinned the string.
_AUTHORITY_TYPE = "urn:andyur:authority"
# An audience names one target. Long enough for a URI, short enough that it
# cannot be used to bloat a token or a log line.
_MAX_AUDIENCE = 256
_key = None  # cached RSA private key


class ExchangeError(Exception):
    """A token exchange could not be performed (no user to delegate, bad subject
    token, or a malformed request)."""


class UnknownActor(ExchangeError):
    """The named delegatee has no registry row, so no ceiling can be read for it.
    Distinct from a malformed request: the caller named a target that does not
    exist, which is RFC 8693's `invalid_target`, not `invalid_request`."""


class MalformedPin(ExchangeError):
    """The run's pin is not a shape the mint can read.

    Its own error, because `narrow()` reports an unreadable pin the same way it
    reports a refused audience -- both come back with `audience: None` -- and
    using that as a proxy made a malformed pin arrive at the operator as "this
    audience is above your ceiling". That is a wrong diagnosis pointing at the
    wrong control, which is worse than no diagnosis."""


class AuthorityEmpty(ExchangeError):
    """The four terms intersected to nothing, so there is no grant to mint.

    Refused rather than issued. A token whose scope is `[]` is a credential that
    silently permits nothing: it validates, it is accepted everywhere, and every
    call made with it fails somewhere else for reasons that never mention the
    ceiling. Whoever is on call debugs it as an outage. This is the same argument
    that makes an unregistered actor an error rather than an empty grant."""


class AudienceRefused(ExchangeError):
    """The actor's registry ceiling does not permit the requested audience. A
    subclass of ExchangeError so existing callers still turn it into a refusal,
    but a distinct type so "above the ceiling" is never flattened into "malformed
    request" in an audit trail."""


class InvalidDelegatedToken(Exception):
    """A presented downstream JWT failed verification (signature, audience, expiry)."""


def _private_key():
    """Load the RSA signing key from ANDYUR_EXCHANGE_KEY, or generate an ephemeral one.
    Cached so every mint in a process signs under the same key (one JWKS entry)."""
    global _key
    if _key is None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        if config.EXCHANGE_KEY_PATH:
            with open(config.EXCHANGE_KEY_PATH, "rb") as fh:
                _key = serialization.load_pem_private_key(fh.read(), password=None)
        else:
            _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _key


def public_jwks() -> dict:
    """Andyur's exchange public key as a JWKS document, for external targets to fetch
    and validate downstream tokens against (no callback to the server)."""
    import jwt

    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_private_key().public_key()))
    jwk.update({"kid": _KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def _narrow(parent_scope, requested):
    """Return a scope that is a SUBSET of `parent_scope`. `None`/`["*"]` means the
    parent is unrestricted, so the child is whatever it requests (or unrestricted).
    Otherwise the child is the intersection: anything requested beyond the parent is
    silently dropped -- a downstream grant can never be wider than its parent."""
    unrestricted = parent_scope is None or "*" in parent_scope
    if requested is None:
        return None if unrestricted else list(parent_scope)
    if unrestricted:
        return list(requested)
    return [s for s in requested if s in parent_scope]


def narrow_scope(parent_scope, requested):
    """Public wrapper on the never-widen rule, for callers that narrow authority
    without minting a token (e.g. the internal delegation carry)."""
    return _narrow(parent_scope, requested)


def _parent_claims(subject_token: str | None, ctx_sub, ctx_scope, caller=None,
                   ctx_sub_src=None):
    """Resolve the delegation parent. A subject token continues an existing chain (a
    prior downstream JWT); without one, the caller's own run (ctx) is the root of the
    chain. Either way the resulting `sub` is fixed by the parent and cannot be chosen
    by the caller."""
    if subject_token:
        claims = verify_delegated(subject_token)   # a prior downstream JWT
        sub = claims.get("sub")
        if ctx_sub is not None and sub != ctx_sub:
            raise ExchangeError("subject token's user does not match the caller")
        # The presented grant must have been minted FOR the caller. Matching only
        # the user made ANY same-user grant a re-mint key: an agent holding a
        # narrow token could present someone else's wider one and continue that
        # chain instead of its own. RFC 8693 puts the delegatee in `act.sub`, and
        # the delegatee is the party entitled to spend it and therefore to extend
        # it. Skipped for the operator (caller is None), which is not delegating.
        if caller is not None:
            holder = (claims.get("act") or {}).get("sub")
            if holder != caller:
                raise ExchangeError(
                    f"subject token was minted for '{holder}', not for the "
                    f"calling agent '{caller}': it cannot be extended by a party "
                    "it was not delegated to")
        # The provenance rides with the subject across the hop. Re-deriving it
        # here would make delegation a laundering step: an asserted subject would
        # come out of one exchange looking IdP-authenticated.
        return (sub, claims.get("scope"), claims.get("act"), _pin_of(claims),
                claims.get("andyur_sub_src", runtoken.SUB_SRC_IDP))
    return ctx_sub, ctx_scope, None, None, ctx_sub_src


def _pin_of(claims: dict):
    """The resource bound carried by a prior grant, or None. Read defensively:
    a token is verified, but `authorization_details` is still a list of arbitrary
    JSON objects and a wrong shape must not raise on the authorization path."""
    details = claims.get("authorization_details")
    if not isinstance(details, list):
        return None
    for entry in details:
        if isinstance(entry, dict) and entry.get("type") == _AUTHORITY_TYPE:
            pin = entry.get("resources")
            return pin if isinstance(pin, dict) else None
    return None


def exchange(actor: str, audience: str, **kw) -> str:
    """The minted token alone. `mint()` when the caller needs to report what was
    actually granted -- which an OAuth response is required to do whenever the
    grant came back smaller than the request (RFC 6749 sec 3.3)."""
    return mint(actor, audience, **kw)[0]


def mint(actor: str, audience: str, *, caller: str | None = None,
             ctx_sub=None, ctx_scope=None,
             subject_token: str | None = None, requested_scope=None,
             pin=None, ttl: int | None = None, ctx_sub_src=None) -> str:
    """Mint a downstream RS256 JWT delegating to `actor` for `audience`.

    THIS IS THE MINT, and it is where the target design puts enforcement. There
    is deliberately no request-time check anywhere that asks "is this run allowed
    to touch account 447": the answer is decided HERE, once, and the token that
    comes out simply cannot express anything wider. A token minted for 447 has no
    way to say 999, which is why the design calls the token a ceiling rather than
    a permission.

    Four terms, all conjuncts, any one of which can empty the grant:

      entitlement  what the USER may do  -- the parent's scope, never the
                   caller's request, so a delegatee cannot ask its way upward.
      pin          what the WORK is about -- sealed on the run at creation and
                   inherited across delegation (coordinator.resolve_pin), so the
                   agent has no say in it by the time it arrives here.
      ceiling      what the agents involved may EVER hold -- read from the
                   registry by name. BOTH ceilings apply: the delegatee's,
                   because it is who will spend the token, and the CALLER's,
                   because it is who receives it. Naming a more capable delegatee
                   was otherwise a way for a read-only agent to be handed write
                   authority -- the ceiling constrained the string in `act.sub`
                   rather than the party in possession, which is not containment.
                   Note `registry.authority_for` takes no ceiling parameter: "the
                   run supplied a wider ceiling" is not a request that can be
                   expressed, which beats validating one it handed us.
      audience     the ONE target this grant is for. Above the ceiling, the whole
                   authority is empty rather than redirected -- rewriting the
                   audience would hand back a token for a target nobody asked
                   about.

    The user (`sub`) comes from the parent and is never chosen by the caller, and
    the delegatee is appended to the nested `act` chain. Raises ExchangeError if
    there is no user to delegate for, and AudienceRefused if the actor's ceiling
    does not permit the target."""
    # THE PROD INVARIANT LIVES HERE, at the mint, not only at the one door in
    # front of it. In production Andyur never signs its own tool authority; the
    # /oauth/token endpoint refuses before it reaches this function. That makes
    # the endpoint the sole thing standing between prod and a locally-signed
    # token -- so a future SECOND caller added without repeating the check would
    # silently reintroduce prod self-signing with no boot-time signal (exactly
    # the class 17876bb moved from boot to point-of-use). Keeping the invariant
    # local to the mint costs nothing on the guarded path and fails any such
    # caller loudly. Deliberately NOT an ExchangeError: this is a program
    # invariant violation, not a user-facing refusal, and must not be caught and
    # downgraded to a 400 by the endpoint's exception handlers.
    if config.PROD:
        raise RuntimeError(
            "tokenexchange.mint reached in production: Andyur must not sign its "
            "own tool authority in prod (authority comes from the configured "
            "external AS). The caller bypassed the /oauth/token prod refusal.")
    parent_sub, parent_scope, parent_act, parent_pin, sub_src = _parent_claims(
        subject_token, ctx_sub, ctx_scope, caller, ctx_sub_src)

    # The parent's resource bound must survive the hop. Dropping it was a
    # laundering step: a grant minted under a run pinned to 447, presented from an
    # UNPINNED run, came back carrying no resource claim at all, and a resource
    # server that was going to ask "was this minted for 447?" got a token that
    # answers nothing. Presented from a DIFFERENTLY pinned run it was worse -- the
    # 447 grant's actions were restamped onto 999, a pairing no authenticated
    # party ever asserted. This is the rule coordinator.resolve_pin already
    # enforces for delegated runs, in both directions: a child may not add a pin
    # its parent did not have, nor change the one it did.
    if parent_pin is not None:
        if pin is not None and pin != parent_pin:
            raise ExchangeError(
                "the subject token is pinned to "
                f"{sorted(parent_pin.items())} but the calling run is pinned to "
                f"{sorted(pin.items())}: a grant cannot be re-pinned to a "
                "resource nobody delegated it for")
        pin = parent_pin
    if not parent_sub:
        raise ExchangeError("nothing to delegate: the parent has no user (sub)")
    if not actor:
        raise ExchangeError("delegation needs an actor (the delegatee)")
    if not isinstance(audience, str) or not audience.strip():
        raise ExchangeError("delegation needs an audience (the target)")
    # "*" is this codebase's sentinel for "restricts nothing" in every OTHER term,
    # so accepting it as a literal audience mints a token that reads as valid for
    # every target to anyone who applies the same convention one layer down.
    if audience.strip() == "*":
        raise ExchangeError(
            "'*' is not an audience: a token must name the ONE target it may be "
            "spent at, and '*' is the wildcard this codebase uses elsewhere")
    audience = audience.strip()
    # An audience travels into the token, into the audit record and into every
    # log line about this exchange, and it is caller-supplied. A newline in it
    # let an agent FORGE a second `mint ISSUED` line -- a syntactically perfect
    # issuance for a target it was never granted, attributed to whoever it liked.
    # An audit record the audited party can write is worse than no record.
    #
    # Bounded too: nothing else caps it, so a megabyte audience became a megabyte
    # in the token and a megabyte per log line.
    if len(audience) > _MAX_AUDIENCE or any(c in audience for c in "\r\n\t"):
        raise ExchangeError(
            "an audience must be a single line of at most "
            f"{_MAX_AUDIENCE} characters: it names one target, and it is written "
            "into the token and into the audit trail")

    act = {"sub": actor}
    if parent_act is not None:
        act["act"] = parent_act   # nest the prior chain beneath the new actor

    # TERM 1 (entitlement) capping the caller's REQUEST. The request is not one of
    # the four terms -- it is what the caller would like, and this line is where it
    # stops being able to exceed what the parent held. Kept as its own step so the
    # terms below can only make the answer smaller, never restore what this dropped.
    requested = _narrow(parent_scope, requested_scope)

    # TERMS 2, 3 and 4 (pin, ceiling, audience), read from the registry and from the
    # run rather than accepted from the caller.
    #
    # An UNREGISTERED actor is refused rather than quietly granted nothing: the
    # registry denies all for an unknown agent, which is the right default there,
    # but minting on top of it produces a syntactically valid token that permits
    # no action -- and a credential that silently does nothing is a support
    # ticket, not a security control. authority_for answers "does it exist" and
    # "what is its ceiling" from ONE read, so the actor cannot be deleted between
    # the two questions and turn this error back into an empty grant.
    # Checked HERE rather than inferred from the result. `narrow()` denies an
    # unreadable pin by emptying the whole authority, INCLUDING the audience, so
    # "audience is None" cannot tell a refused audience apart from a malformed pin.
    if pin is not None and not isinstance(pin, dict):
        log.error("mint REFUSED: caller=%s actor=%s -- pin is %s, not a mapping",
                  caller, actor, type(pin).__name__)
        raise MalformedPin(
            f"the run's pin is a {type(pin).__name__}, not a mapping: the "
            "resources this authority is bound to cannot be read, so no token "
            "can be minted for it")

    try:
        # The CALLER's ceiling first. This agent is the one that receives the
        # minted token, and a compromised agent that can name any delegatee can
        # otherwise mint itself authority its own ceiling forbids: the token comes
        # back in the response body, so "it was minted for someone else" is not a
        # control over who holds it. Applied to the audience too, so a caller
        # confined to tool:calendar cannot obtain a tool:payments grant by
        # nominating an agent that is allowed one.
        if caller is not None:
            held = registry.authority_for(caller, requested, pin, audience)
            if held["audience"] is None and audience is not None:
                log.warning("mint REFUSED: caller=%r may not HOLD audience=%r "
                            "(caller ceiling)", caller, audience)
                raise AudienceRefused(
                    f"'{caller}' may not hold a token for the audience "
                    f"'{audience}': it is above this agent's registry ceiling")
            requested = held["actions"]

        authority = registry.authority_for(actor, requested, pin, audience)
    except registry.UnknownAgent as exc:
        log.warning("mint REFUSED: caller=%r actor=%r audience=%r -- %s",
                    caller, actor, audience, exc)
        raise UnknownActor(str(exc)) from exc
    if authority["audience"] is None and audience is not None:
        log.warning("mint REFUSED: actor=%r may not be granted audience=%r "
                    "(actor ceiling), requested by caller=%s",
                    actor, audience, caller)
        raise AudienceRefused(
            f"'{actor}' may not be granted the audience '{audience}': it is "
            "above this agent's registry ceiling")

    # A narrowed mint is a 200 with a shorter scope, which is invisible to an
    # operator and nearly invisible to the agent. This is the only record that a
    # ceiling or a pin acted, so it is WARNING rather than INFO/DEBUG: "the agent
    # cannot write any more" is a support question, and without this line the
    # answer is not in the logs at all.
    # Report narrowing against what the client actually asked for. `requested`
    # above is already capped to the parent for authorization, but using that
    # capped value here hides the fact that a caller requested a wider scope.
    asked = (list(requested_scope) if requested_scope is not None
             else (list(parent_scope) if parent_scope is not None else None))
    granted = authority["actions"]
    if asked is not None and granted is not None and set(asked) != set(granted):
        log.warning("mint NARROWED: caller=%r actor=%r audience=%r pin=%s "
                    "asked=%s granted=%s (ceiling and/or pin)",
                    caller, actor, audience, pin, sorted(asked), sorted(granted))

    if granted is not None and not granted:
        log.warning("mint REFUSED: caller=%r actor=%r audience=%r pin=%s -- the "
                    "authority intersected to nothing (asked=%s)",
                    caller, actor, audience, pin, asked)
        raise AuthorityEmpty(
            f"no authority remains for '{actor}' after the entitlement, pin, "
            "ceiling and audience are intersected: refusing to mint a token "
            "that would permit nothing")

    now = int(time.time())
    claims = {
        "iss": config.EXCHANGE_ISSUER,
        "sub": parent_sub,
        # HOW that subject was established. A resource server validating this
        # token against Andyur's JWKS otherwise cannot tell a real login from a
        # name an API client typed: both arrive as a signed `sub`. Namespaced
        # because it is Andyur's own claim -- RFC 8693 has no field for it, and
        # `amr` (RFC 8176) describes authentication METHODS, which is not what
        # this is. A server that requires real users refuses anything but "idp".
        "andyur_sub_src": sub_src or runtoken.SUB_SRC_IDP,
        "act": act,
        "aud": audience,
        "scope": authority["actions"],
        "iat": now,
        "exp": now + (ttl or config.EXCHANGE_TTL),
        # RFC 9068 sec 2.2 makes `client_id` and `jti` REQUIRED of an `at+jwt`,
        # and this header says `at+jwt`. Without them a resource server
        # validating per sec 4 must reject the token, so claiming the type while
        # omitting the claims is worse than not claiming it.
        #
        # `client_id` is the party that REQUESTED the token (RFC 9068 sec 2.2),
        # which is the caller -- not `actor`, the delegatee it was minted for.
        #
        # Those differ, and the difference is caller-controlled: on the JSON path
        # `actor` is a body field, gated only by an allow-list that permits
        # everything when unconfigured. So keying client_id on the actor let a
        # caller mint a token naming a DIFFERENT registered agent as the client
        # while holding and spending it itself. This module already argues the
        # point three functions up: the token comes back in the response body, so
        # "it was minted for someone else" is not a control over who holds it.
        # Anything downstream keying on client_id -- a SIEM, a per-client rate
        # limit, a resource server's allow-list -- was being fed a value the
        # caller picked.
        "client_id": caller or "operator",
        # `jti` makes a token individually identifiable, which is what lets a
        # resource server detect replay and an audit trail name ONE credential
        # rather than "a token for tool:ci around 14:03".
        "jti": secrets.token_urlsafe(16),
    }
    # The pin travels WITH the grant, so a resource server can answer "was this
    # token minted for the account I am being asked to touch?" without calling
    # back. Carried under authorization_details because that is the shape the
    # target design uses (RFC 9396) -- this is the first field of it, not the
    # whole migration off scope strings, which is a separate piece of work.
    if authority["pin"]:
        detail = {"type": _AUTHORITY_TYPE, "resources": authority["pin"]}
        # `actions is None` means "no action model restricts this run", which is
        # NOT the same statement as `"actions": null` inside a RAR object -- a
        # resource server reading a null there has to guess whether it means
        # everything or nothing, and one of those guesses is a breach. Say
        # nothing rather than say it ambiguously; the `scope` claim already
        # carries the unrestricted case.
        if authority["actions"] is not None:
            detail["actions"] = authority["actions"]
        claims["authorization_details"] = [detail]
    import jwt

    token = jwt.encode(claims, _private_key(), algorithm="RS256",
                      headers={"kid": _KID, "typ": "at+jwt"})
    # ISSUANCE is logged, not only refusal and narrowing.
    #
    # Until now this endpoint logged when it said no and said nothing when it
    # said yes, so a live credential could exist with no record on either side --
    # which makes the `jti` two lines up pointless. Its stated purpose is to let
    # an audit trail name ONE credential, and it cannot do that if nothing ever
    # writes it down. The token itself is never logged, only its identity.
    log.info("mint ISSUED: jti=%s caller=%r actor=%r audience=%r sub=%r "
             "scope=%s pin=%s exp=%s",
             claims["jti"], caller or "operator", actor, audience, parent_sub,
             authority["actions"], authority["pin"] or None, claims["exp"])
    # `asked` travels back so the caller can tell the client what it actually got.
    return token, {"claims": claims, "asked": asked, "granted": granted}


def verify_delegated(token: str, audience: str | None = None) -> dict:
    """Validate a downstream JWT against Andyur's key (as an external target would,
    via the JWKS) and return its claims. Raises InvalidDelegatedToken on any failure."""
    import jwt

    try:
        claims = jwt.decode(
            token,
            _private_key().public_key(),
            algorithms=["RS256"],
            audience=audience,
            options={"require": ["sub", "exp"], "verify_aud": bool(audience)},
        )
    except Exception as exc:
        raise InvalidDelegatedToken(str(exc)) from exc
    return claims

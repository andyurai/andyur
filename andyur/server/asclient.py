"""The outbound RFC 8693 leg: Andyur asks the ADOPTER'S authorization server to
mint, instead of signing an access token itself.

This is `docs/decisions.md` #1 in code. Andyur is not an authorization server;
the AS is the enterprise's, always. What Andyur owns is the facts no AS can know
-- which run this is, who it acts for, which agent, and what the work is about --
and it supplies them as parameters of the exchange:

    subject_token          the user's access token       who it is FOR
    actor_token            the run's JWT-SVID            WHO IS ACTING (`act`)
    resource               the tool's canonical URL      RFC 8707, becomes `aud`
    scope                  the four-term intersection    what it may DO
    authorization_details  the pin                       RFC 9396, what it is ABOUT

WHAT THIS MODULE DOES NOT DO, AND MUST NOT: narrow. By the time a request is
built here the authority is already decided by `registry.narrow`, and this module
only serialises it. Measured against the reference AS (`infra/reference-as`), an
authorization server carries whatever `authorization_details` the client asks for
-- it allow-lists the RAR *type* and never its *content*, because a token
exchange has no prior granted set to compare against. Ask for `identifier: "*"`
and you get it. So a narrowing bug here is not caught downstream by anything.

WHAT AN AS MAY NOT SUPPORT. Only the exchange itself is required. `act`, RFC 8707
and RFC 9396 are all optional and degrade:

    act                    Keycloak cannot emit it; attribution falls back to the
                           OAuth client, which names the agent and not the run
    authorization_details  absent -> the pin is not IN the token, and the gateway
                           and the PDP remain the enforcement point (O1)
    resource               absent -> `aud` comes from `audience` instead

Andyur must therefore never REQUIRE any of the three, which is why each is
omitted from the request rather than sent empty.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from .. import boundedhttp, config
from . import asproviders

log = logging.getLogger("andyur.asclient")

GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

# The exchange is on the authorization path and SYNCHRONOUS, so a stalled AS
# holds a threadpool thread. Short and total, per andyur/boundedhttp.py.
BUDGET = 0.55
MAX_BYTES = 256 << 10
_jwks = None


class ASError(Exception):
    """The AS refused, or could not be reached.

    Carries the AS's own `error` code when there is one, because an error naming
    the wrong cause costs more than one naming none.
    """

    def __init__(self, message: str, *, code: str | None = None,
                 status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


class ASNotConfigured(ASError):
    """Andyur was asked to use an external AS and does not have one."""


def configured() -> bool:
    return bool(config.AS_TOKEN_ENDPOINT)


def _jwk_client():
    global _jwks
    if _jwks is None:
        import jwt

        if not config.AS_JWKS_URL:
            raise ASError("ANDYUR_AS_JWKS is unset; issued tokens cannot be verified")

        class BoundedJWKClient(jwt.PyJWKClient):
            def fetch_data(self) -> Any:
                try:
                    data = json.loads(boundedhttp.get_bytes(
                        self.uri, what="the authorization server's JWKS",
                        max_bytes=MAX_BYTES, budget=BUDGET,
                        headers=self.headers or None))
                except Exception as exc:
                    raise jwt.exceptions.PyJWKClientConnectionError(
                        f"failed to fetch authorization-server JWKS: {exc}") from exc
                if self.jwk_set_cache is not None:
                    self.jwk_set_cache.put(data)
                return data

        _jwks = BoundedJWKClient(config.AS_JWKS_URL)
    return _jwks


def _verify_response(token: str, *, expected_subject: str, expected_actor: str,
                     audience: str | None, resource: str | None, scope,
                     authorization_details,
                     expected_provider_scopes: frozenset[str] | None = None) -> dict:
    """Verify the signed result and every guarantee selected for this tenant."""
    import jwt

    expected_audience = resource or audience
    try:
        key = _jwk_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256", "ES256", "RS384", "ES384"],
            audience=expected_audience, issuer=config.AS_ISSUER,
            options={"require": ["sub", "exp", "iat", "aud"]})
    except Exception as exc:
        raise ASError(f"issued access token failed verification: {exc}") from exc

    if not isinstance(expected_subject, str) or not expected_subject:
        raise ASError("exchange has no server-authenticated expected subject")
    try:
        issued_subject = asproviders.subject_identity(config.AS_PROVIDER, claims)
    except asproviders.ProviderConfigurationError as exc:
        raise ASError(f"issued access token has no usable subject identity: {exc}") from exc
    if issued_subject != expected_subject:
        raise ASError("issued access token substituted the delegated subject")
    asked_scope = (set(expected_provider_scopes) if expected_provider_scopes is not None
                   else set(scope.split() if isinstance(scope, str) else (scope or [])))
    raw_scope = claims.get("scope", claims.get("scp", []))
    if not isinstance(raw_scope, (str, list, tuple)):
        raise ASError("issued access token has malformed scope claims")
    got_scope = set(raw_scope.split() if isinstance(raw_scope, str) else raw_scope)
    if not got_scope.issubset(asked_scope):
        raise ASError("issued access token widened the requested scope")

    required = asproviders.CAPABILITY_REQUIREMENTS[
        asproviders.capability(config.AS_CAPABILITY)]
    if "delegated" in required:
        act = claims.get("act") or {}
        if not isinstance(act, dict):
            raise ASError("issued access token has a malformed actor claim")
        if not isinstance(expected_actor, str) or not expected_actor \
                or act.get("sub") != expected_actor:
            raise ASError("issued access token omitted or substituted the run actor")
    if "contextual" in required:
        expected = (json.loads(_details_json(authorization_details))
                    if authorization_details else None)
        if not expected or claims.get("authorization_details") != expected:
            raise ASError("issued access token omitted or substituted pinned context")
    issued, expires = claims.get("iat"), claims.get("exp")
    if (not isinstance(issued, (int, float)) or isinstance(issued, bool)
            or not isinstance(expires, (int, float)) or isinstance(expires, bool)
            or expires <= issued):
        raise ASError("issued access token has invalid lifetime claims")
    if expires - issued > config.EXCHANGE_TTL:
        raise ASError("issued access token lifetime exceeds Andyur's exchange TTL")
    remaining = int(expires - time.time())
    claims["_andyur_expires_in"] = max(remaining, 0)
    return claims


def exchange(*, subject_token: str, expected_subject: str, actor_token: str,
             expected_actor: str = "",
             audience: str | None, scope, resource: str | None = None,
             authorization_details=None,
             dpop_proof: str | None = None) -> dict:
    """Perform the exchange and return the AS's token response.

    Raises ASError on any refusal or failure. There is no degraded success: a
    call that cannot obtain a credential withholds the capability rather than
    proceeding without one.
    """
    if not configured():
        raise ASNotConfigured(
            "ANDYUR_AS_TOKEN_ENDPOINT is unset, so there is no authorization "
            "server to ask. Andyur does not sign access tokens (decisions.md #1)")
    if config.PROD:
        unsafe = config.as_problems()
        if unsafe:
            raise ASError(
                "production authorization-server configuration is not certified: "
                + "; ".join(unsafe))
    if not subject_token:
        raise ASError(
            "nothing to delegate: this run has no user token to present as the "
            "subject of the exchange")
    if not expected_subject:
        raise ASError(
            "the run has no server-authenticated subject for response continuity")
    if not actor_token:
        # Refusing rather than omitting. Without an actor the issued token says
        # the USER acted directly, and no resource server could tell delegation
        # from impersonation -- the exact property this design exists to provide.
        raise ASError(
            "no actor token: an exchange without one asserts the user acted "
            "directly, which is impersonation rather than delegation")
    required = asproviders.CAPABILITY_REQUIREMENTS[
        asproviders.capability(config.AS_CAPABILITY)]
    if "delegated" in required and not expected_actor:
        raise ASError("the run has no separately sealed expected actor")
    if audience and resource and audience != resource:
        raise ASError("audience and resource must name one identical target")

    # Each optional parameter is OMITTED rather than sent empty. An AS that
    # rejects an empty `resource` would fail a request that simply had no
    # resource constraint, and a deployment may legitimately have none
    # (docs/authority-flow-by-step.md, step 1).
    scope_string = (" ".join(scope) if scope and not isinstance(scope, str)
                    else scope)
    provider_scope = config.AS_RESOURCE_SCOPE
    expected_provider_scopes = None
    if config.AS_PROVIDER == "entra":
        provider_scope, expected_provider_scopes = asproviders.entra_scope_mapping(
            config.AS_RESOURCE_SCOPE, scope_string)
    elif config.AS_PROVIDER == "reference" and config.AS_RESOURCE_SCOPE:
        # The reference AS has a fixed scope vocabulary; a registry-driven run
        # names logical actions, so translate when a map is configured. The
        # reference exchange is RFC 8693, which carries the request in `scope`
        # (Entra's obo carries it separately in provider_scope), so the
        # translated request replaces scope_string; the claims are what the
        # issued token is then verified to carry. Without a map the provider
        # passes scopes through unchanged (the actor-leg AS-vocabulary case).
        scope_string, expected_provider_scopes = asproviders.reference_scope_mapping(
            config.AS_RESOURCE_SCOPE, scope_string)
    details_string = (_details_json(authorization_details)
                      if authorization_details else None)
    try:
        form, provider_headers = asproviders.build_request(
            provider_name=config.AS_PROVIDER,
            client_id=config.AS_CLIENT_ID,
            client_secret=config.AS_CLIENT_SECRET,
            subject_token=subject_token,
            actor_token=actor_token,
            audience=audience,
            resource=resource,
            scope=scope_string,
            authorization_details=details_string,
            provider_scope=provider_scope)
    except asproviders.ProviderConfigurationError as exc:
        raise ASError(f"authorization-server provider configuration: {exc}") from exc

    headers = dict(provider_headers)
    if dpop_proof:
        headers["DPoP"] = dpop_proof

    try:
        request = (boundedhttp.post_json_response
                   if asproviders.request_encoding(config.AS_PROVIDER) == "json"
                   else boundedhttp.post_form)
        status, body = request(
            config.AS_TOKEN_ENDPOINT, form, what="the authorization server's "
            "token endpoint", budget=BUDGET, max_bytes=MAX_BYTES,
            headers=headers or None)
    except Exception as exc:                                   # noqa: BLE001
        # Fails CLOSED and says which component: an operator reading this needs
        # to know it was THEIR AS that did not answer, not Andyur.
        raise ASError(
            f"the authorization server could not be reached or did not answer "
            f"within {BUDGET}s: {type(exc).__name__}") from exc

    if status != 200 or not isinstance(body, dict):
        code = (body or {}).get("error") if isinstance(body, dict) else None
        desc = (body or {}).get("error_description") if isinstance(body, dict) else None
        raise ASError(
            f"the authorization server refused the exchange "
            f"({code or 'no error code'}: {(desc or '')[:200]})",
            code=code, status=status)

    token = body.get("access_token")
    if not token or not isinstance(token, str):
        raise ASError("the authorization server answered 200 with no access_token")
    if not isinstance(body.get("token_type"), str) or body["token_type"].lower() \
            not in {"bearer", "dpop"}:
        raise ASError("the authorization server returned an unsupported token_type")
    if asproviders.requires_issued_token_type(config.AS_PROVIDER) and \
            body.get("issued_token_type") != TOKEN_TYPE_ACCESS:
        raise ASError(
            "the authorization server omitted or changed issued_token_type")
    claims = _verify_response(
        token, expected_subject=expected_subject, expected_actor=expected_actor,
        audience=audience, resource=resource, scope=scope,
        authorization_details=authorization_details,
        expected_provider_scopes=expected_provider_scopes)
    if "_andyur_expires_in" in claims:
        advertised = body.get("expires_in", claims["_andyur_expires_in"])
        try:
            body["expires_in"] = min(float(advertised),
                                     claims["_andyur_expires_in"])
        except (TypeError, ValueError):
            body["expires_in"] = claims["_andyur_expires_in"]

    log.info("exchange OK: aud=%r resource=%r scope=%r rar=%s dpop=%s",
             audience, resource, form.get("scope"),
             bool(authorization_details), bool(dpop_proof))
    return body


def _details_json(details) -> str:
    if isinstance(details, str):
        return details
    return json.dumps(details, separators=(",", ":"))

"""OIDC user-token validation (U1: user delegation).

This is how the human on whose behalf an agent acts enters the system. The caller
presents the end user's OIDC token (a JWT from an enterprise IdP); the server
validates it against the IdP's JWKS (signature, issuer, audience, expiry) and
returns the user identity, `sub`. That `sub` becomes the OWNER of the agent it
creates, and every run of that agent inherits it (see auth / app).

Opt-in vian ANDYUR_USER_AUTH=on. No network happens until validate_user_token is
called, and the JWKS client caches keys, so validation is a local check after the
first fetch. The JWKS client is module-level so tests can inject a fake signer.
"""

from typing import Any

from .. import boundedhttp
from ..config import OIDC_AUDIENCE, OIDC_ISSUER, OIDC_JWKS_URL


class InvalidUserToken(Exception):
    """The user's OIDC token could not be validated."""


_jwks = None  # lazily-built PyJWKClient; tests may set this to a fake


def _jwk_client():
    global _jwks
    if _jwks is None:
        import jwt

        url = OIDC_JWKS_URL or (
            OIDC_ISSUER.rstrip("/") + "/.well-known/jwks.json" if OIDC_ISSUER else ""
        )
        if not url:
            raise InvalidUserToken(
                "no OIDC JWKS configured (set ANDYUR_OIDC_JWKS or ANDYUR_OIDC_ISSUER)"
            )
        _jwks = _bounded_jwk_client_class()(url)
    return _jwks


def _bounded_jwk_client_class():
    """PyJWKClient, with its JWKS fetch bounded in TOTAL time and size.

    Built lazily inside a function because `jwt` is imported lazily above -- the
    server must start without it when user-auth is off.

    The stock client fetches with `urlopen(..., timeout=30)`, which bounds a
    single read and not the call. The IdP is the adopter's component and sits on
    the request path for every user-authenticated call, so a JWKS endpoint that
    drips bytes stalls authentication for as long as it cares to. Same defect as
    the PDP client had, same fix, one implementation: andyur/boundedhttp.py.

    Only `fetch_data` is replaced. Caching, key selection and the 300s lifespan
    are PyJWT's and stay PyJWT's -- there is no second copy of that logic here.
    """
    import json as _json

    import jwt

    class _Bounded(jwt.PyJWKClient):
        def fetch_data(self) -> Any:
            # PyJWT documents this method as raising PyJWKClientConnectionError
            # on a failed fetch, and its own callers key off that. Keeping the
            # contract means the bound changes WHEN this fails, never HOW.
            try:
                body = boundedhttp.get_bytes(self.uri, what="the IdP's JWKS",
                                             headers=self.headers or None)
                jwk_set = _json.loads(body)
            except Exception as exc:
                raise jwt.exceptions.PyJWKClientConnectionError(
                    f'Fail to fetch data from the url, err: "{exc}"') from exc

            # Cached only on success, matching upstream: writing None on error
            # would turn a transient outage into a cache wipe that breaks
            # legitimate authentication until the IdP returns.
            if self.jwk_set_cache is not None:
                self.jwk_set_cache.put(jwk_set)
            return jwk_set

    return _Bounded


def validate_user_claims(token: str) -> dict:
    """Validate an OIDC JWT and return its authenticated claims."""
    import jwt

    try:
        signing_key = _jwk_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "ES256", "RS384", "ES384"],
            audience=OIDC_AUDIENCE or None,
            issuer=OIDC_ISSUER or None,
            options={
                "require": ["sub", "exp"],
                "verify_aud": bool(OIDC_AUDIENCE),
                "verify_iss": bool(OIDC_ISSUER),
            },
        )
    except InvalidUserToken:
        raise
    except Exception as exc:  # PyJWT raises many subclasses; normalize them
        raise InvalidUserToken(str(exc)) from exc

    sub = claims.get("sub")
    if not sub:
        raise InvalidUserToken("token has no 'sub' claim")
    return claims


def validate_user_token(token: str) -> str:
    """Validate an OIDC JWT and return its `sub`."""
    return validate_user_claims(token)["sub"]

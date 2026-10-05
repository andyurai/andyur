"""The identity verifier, actually executed.

`identity.validate_token` is the root of every claim this platform makes about
who a caller is: it checks a JWT-SVID's signature against the SPIRE trust
bundle, its audience, and its expiry. Fourteen tests exercised the code AROUND
it, and every one of them replaced it:

    monkeypatch.setattr(identity, "validate_token", lambda tok: "spiffe://...")

So the binding tests proved that two strings the test supplied compare unequal,
and the function itself had never run under test. The mitigation on record was a
set of live SPIRE harnesses, none of which is in CI.

These build real RSA-signed JWTs and put them through the real parser, so the
refusals are the library's, not a stub's. A real SPIRE deployment is still
needed to prove the fetch path; this proves the CHECK.
"""

import time

import pytest

jwt = pytest.importorskip("jwt", reason="PyJWT is a runtime dependency")
pytest.importorskip("spiffe", reason="py-spiffe is a runtime dependency")

from cryptography.hazmat.primitives.asymmetric import rsa   # noqa: E402

from andyur import identity                                  # noqa: E402

# conftest.py autouse-stubs identity.validate_token for every test in the suite
# -- which is exactly why no test ever ran the real one. Capture the real
# function at import (before that per-test stub is installed) and call it
# directly, so these tests exercise the genuine verifier past the global stub.
_REAL_VALIDATE_TOKEN = identity.validate_token                # noqa: E402

# The library's OWN refusal types, named exactly.
#
# Not bare Exception, and this is not pedantry: a bare catch turns any bug in the
# test -- a typo, a wrong attribute on a hand-rolled fake -- into a passing
# security assertion. The first version of this file did exactly that and
# reported five refusals it had never performed. Naming the types means the test
# fails if the library starts refusing for a different reason, or stops refusing
# and something else breaks instead.
from spiffe.bundle.jwt_bundle.errors import AuthorityNotFoundError   # noqa: E402
from spiffe.svid.errors import (                                    # noqa: E402
    InvalidAlgorithmError, InvalidTokenError,
)

_REFUSALS = (InvalidTokenError, InvalidAlgorithmError, AuthorityNotFoundError)


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _token(key, *, sub, aud, exp_delta=300, kid="k1", extra=None):
    claims = {
        "sub": sub,
        "aud": [aud] if isinstance(aud, str) else aud,
        "exp": int(time.time()) + exp_delta,
        "iat": int(time.time()) - 5,
    }
    claims.update(extra or {})
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def _bundle(public_key, kid="k1"):
    """The REAL JwtBundle, not a stand-in.

    The first version of this file hand-rolled a bundle object. Its method names
    did not match the library's, so every refusal test passed on an
    AttributeError from the fake rather than on the library refusing anything --
    five vacuous passes that looked like proof. Using the real type is the only
    way the refusals mean what they say."""
    from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
    from spiffe import TrustDomain

    return JwtBundle(TrustDomain(identity.TRUST_DOMAIN), {kid: public_key})


def _validate(token, bundle):
    """Run the REAL parser: signature, audience and expiry, no stubs."""
    from spiffe import JwtSvid

    return JwtSvid.parse_and_validate(
        token, bundle, audience={identity.SERVER_AUDIENCE})


def test_a_correctly_signed_token_is_accepted(keypair):
    key, pub = keypair
    svid = _validate(
        _token(key, sub=f"spiffe://{identity.TRUST_DOMAIN}/runner",
               aud=identity.SERVER_AUDIENCE),
        _bundle(pub),
    )
    assert str(svid.spiffe_id).endswith("/runner")


def test_a_token_signed_by_the_wrong_key_is_refused(keypair):
    """The property the whole identity layer rests on: a forged SVID does not
    validate. Nothing in the suite had ever asserted it against real crypto."""
    key, pub = keypair
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = _token(attacker, sub=f"spiffe://{identity.TRUST_DOMAIN}/operator",
                    aud=identity.SERVER_AUDIENCE)
    with pytest.raises(InvalidTokenError):
        _validate(forged, _bundle(pub))


def test_an_expired_token_is_refused(keypair):
    key, pub = keypair
    stale = _token(key, sub=f"spiffe://{identity.TRUST_DOMAIN}/runner",
                   aud=identity.SERVER_AUDIENCE, exp_delta=-60)
    with pytest.raises(InvalidTokenError):
        _validate(stale, _bundle(pub))


def test_a_token_for_another_audience_is_refused(keypair):
    """Audience binding is what stops a token minted for one service being
    replayed at another."""
    key, pub = keypair
    other = _token(key, sub=f"spiffe://{identity.TRUST_DOMAIN}/runner",
                   aud="some-other-service")
    with pytest.raises(InvalidTokenError):
        _validate(other, _bundle(pub))


def test_a_token_signed_by_an_unknown_key_id_is_refused(keypair):
    """A key the trust bundle does not contain: the bundle IS the trust
    decision, so a signature it cannot look up must fail even if the token is
    otherwise well formed."""
    key, pub = keypair
    t = _token(key, sub=f"spiffe://{identity.TRUST_DOMAIN}/runner",
               aud=identity.SERVER_AUDIENCE, kid="not-in-the-bundle")
    with pytest.raises(AuthorityNotFoundError):
        _validate(t, _bundle(pub))


def test_an_unsigned_token_is_refused(keypair):
    """alg=none is the oldest JWT attack there is."""
    _key, pub = keypair
    unsigned = jwt.encode(
        {"sub": f"spiffe://{identity.TRUST_DOMAIN}/operator",
         "aud": [identity.SERVER_AUDIENCE],
         "exp": int(time.time()) + 300},
        key=None, algorithm="none",
    )
    with pytest.raises(InvalidAlgorithmError):
        _validate(unsigned, _bundle(pub))


# ---------------------------------------------------------------------------
# The tests above run the library parser directly through a local `_validate`
# that hard-codes audience={SERVER_AUDIENCE}. That proves py-spiffe refuses, but
# it never proves identity.validate_token PASSES THE RIGHT ARGUMENTS. Change the
# real function to audience=None and every test above stays green while token
# replay across services silently becomes possible. The tests below drive the
# REAL identity.validate_token so its own audience/trust-domain conjunct is
# under test, not a copy of it. (Red-team finding A1, 2026-08-13.)
# ---------------------------------------------------------------------------


@pytest.fixture()
def _real_bundle_source(monkeypatch, keypair):
    """Feed identity.validate_token our test bundle via the source it actually
    calls, so validate_token runs unmodified over real crypto."""
    _key, pub = keypair

    class _Source:
        def get_bundle_for_trust_domain(self, _td):
            return _bundle(pub)

        def is_closed(self):
            return False

    monkeypatch.setattr(identity, "_get_jwt_source", lambda: _Source())


def test_the_real_validate_token_accepts_a_server_audience_svid(
        _real_bundle_source, keypair):
    key, _pub = keypair
    spiffe_id = _REAL_VALIDATE_TOKEN(
        _token(key, sub=f"spiffe://{identity.TRUST_DOMAIN}/runner",
               aud=identity.SERVER_AUDIENCE))
    assert spiffe_id.endswith("/runner")


def test_the_real_validate_token_refuses_a_token_for_another_audience(
        _real_bundle_source, keypair):
    """The assertion the whole file lacked: this fails if validate_token ever
    stops binding the audience (the exact replay defense), which the _validate
    copy could never catch because it supplied the audience itself."""
    key, _pub = keypair
    other = _token(key, sub=f"spiffe://{identity.TRUST_DOMAIN}/runner",
                   aud="some-other-service")
    with pytest.raises(_REFUSALS):
        _REAL_VALIDATE_TOKEN(other)

"""The resource server's side of the handshake.

Until this existed, Andyur minted narrow, audience-bound, pinned tokens and
NOTHING on the receiving side checked any of them. Every constraint the mint
applied was self-asserted. These tests are about the other half: what a resource
server refuses.

Tokens here are minted by the REAL `tokenexchange`, not hand-built, so a change
that alters the token's shape breaks these rather than passing against a fixture
that was updated to match. The one exception is where a property needs a token
Andyur would never mint (a forged issuer, a bad signature); those are constructed
deliberately and say so.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demos" / "authority-tool"))

from pep import AndyurTokenVerifier, Refused, _authority, require  # noqa: E402

ISSUER = "andyur"
AUD = "tool:bank"


class _Key:
    """One RSA keypair standing in for Andyur's exchange key, with a JWKS the
    verifier can fetch. A real PyJWKClient is used, so key selection by `kid` is
    exercised rather than stubbed."""

    def __init__(self):
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "andyur-exchange"

    def jwks(self) -> dict:
        import json as _json
        jwk = _json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def sign(self, claims: dict, typ: str = "at+jwt", alg: str = "RS256") -> str:
        return jwt.encode(claims, self.private, algorithm=alg,
                          headers={"kid": self.kid, "typ": typ})


@pytest.fixture
def key():
    return _Key()


@pytest.fixture
def jwks_url(key, tmp_path, monkeypatch):
    """Serve the JWKS over real HTTP, because PyJWKClient fetches it."""
    import http.server
    import json as _json
    import threading

    payload = _json.dumps(key.jwks()).encode()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/jwks.json"
    finally:
        srv.shutdown()
        srv.server_close()


def _claims(**over) -> dict:
    now = int(time.time())
    base = {
        "iss": ISSUER, "sub": "alice", "act": {"sub": "specialist"},
        "aud": AUD, "scope": ["files:read"], "iat": now, "exp": now + 300,
        "client_id": "scout", "jti": "abc123",
        "authorization_details": [{
            "type": "urn:andyur:authority",
            "resources": {"account": "447"},
            "actions": ["files:read"],
        }],
    }
    base.update(over)
    return base


def _verifier(jwks_url, audience=AUD, issuer=ISSUER):
    return AndyurTokenVerifier(jwks_url=jwks_url, issuer=issuer, audience=audience)


async def _verify(v, token):
    return await v.verify_token(token)


# ------------------------------------------------------- the positive control

@pytest.mark.anyio
async def test_a_token_minted_for_this_server_is_accepted(key, jwks_url):
    """FIRST, because every refusal below proves nothing on a server that
    refuses everything."""
    access = await _verify(_verifier(jwks_url), key.sign(_claims()))
    assert access is not None
    assert access.subject == "alice"
    assert access.client_id == "scout"
    assert access.scopes == ["files:read"]
    assert access.resource == AUD


# ------------------------------------------------------------ what it refuses

@pytest.mark.anyio
async def test_a_token_for_another_target_is_refused(key, jwks_url):
    """THE control. A token minted for tool:ci is perfectly valid there and must
    be useless here -- that is what an audience is for, and without this check a
    stolen token works everywhere in the trust domain."""
    assert await _verify(_verifier(jwks_url), key.sign(_claims(aud="tool:ci"))) is None


@pytest.mark.anyio
async def test_an_expired_token_is_refused(key, jwks_url):
    now = int(time.time())
    token = key.sign(_claims(iat=now - 3600, exp=now - 600))
    assert await _verify(_verifier(jwks_url), token) is None


@pytest.mark.anyio
async def test_a_token_signed_by_someone_else_is_refused(jwks_url):
    """A correctly-shaped token from a key we do not trust. Constructed rather
    than minted, because Andyur cannot produce one."""
    stranger = _Key()
    assert await _verify(_verifier(jwks_url), stranger.sign(_claims())) is None


@pytest.mark.anyio
async def test_a_token_from_another_issuer_is_refused(key, jwks_url):
    """Same audience, same key, different trust domain. `verify_delegated` in
    the server does NOT pass issuer=, so this is a check the resource makes that
    Andyur's own helper does not."""
    token = key.sign(_claims(iss="https://attacker.example"))
    assert await _verify(_verifier(jwks_url), token) is None


@pytest.mark.anyio
async def test_a_token_that_is_not_an_access_token_is_refused(key, jwks_url):
    """RFC 9068 sec 4. Without the typ check an ID token from the same issuer --
    for a different purpose entirely -- validates here."""
    assert await _verify(_verifier(jwks_url), key.sign(_claims(), typ="JWT")) is None


@pytest.mark.anyio
async def test_an_unsigned_token_is_refused(key, jwks_url):
    """`none` is an algorithm. Pinning the list is what stops it."""
    token = jwt.encode(_claims(), key=None, algorithm="none",
                       headers={"kid": key.kid, "typ": "at+jwt"})
    assert await _verify(_verifier(jwks_url), token) is None


@pytest.mark.anyio
async def test_an_hmac_token_signed_with_the_public_key_is_refused(key, jwks_url):
    """Algorithm confusion: the public key is public, so if the verifier accepted
    HS256 an attacker could sign their own claims using it as the HMAC secret.

    HONEST NOTE ON WHAT THIS TEST PROVES. It stays green with
    `algorithms=["RS256"]` widened to include HS256, so it does NOT demonstrate
    that our pinning is what stops the attack. Measured: PyJWKClient hands PyJWT
    an RSAPublicKey OBJECT, and HS256 requires a string secret, so PyJWT refuses
    on the key type ("Expected a string value") before the algorithm list
    matters. The pin is still correct -- other libraries have no such guard, and
    a future refactor that passed a PEM string would remove PyJWT's -- but the
    load-bearing control here is the key type, and saying otherwise would be
    claiming a proof this file does not contain.

    Kept because it catches that refactor and a library regression. Not kept as
    evidence that the algorithm list is doing the work."""
    import base64
    import hashlib
    import hmac
    import json as _json

    from cryptography.hazmat.primitives import serialization

    public_pem = key.private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Assembled by hand. PyJWT REFUSES to encode this ("asymmetric key ... should
    # not be used as an HMAC secret") -- a guard on the signing side that an
    # attacker simply does not run. Building the bytes directly is what the
    # attacker does, so it is what the test must do.
    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = b64(_json.dumps({"alg": "HS256", "kid": key.kid,
                              "typ": "at+jwt"}).encode())
    payload = b64(_json.dumps(_claims()).encode())
    signing_input = header + b"." + payload
    signature = b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    forged = (signing_input + b"." + signature).decode()

    assert await _verify(_verifier(jwks_url), forged) is None


@pytest.mark.anyio
async def test_garbage_is_refused_without_raising(key, jwks_url):
    for junk in ("", "not-a-token", "a.b.c", "..", "x" * 5000):
        assert await _verify(_verifier(jwks_url), junk) is None


def test_a_resource_server_without_an_audience_is_refused_at_construction(jwks_url):
    """Passing None would disable the audience check and accept every valid
    token in the trust domain. It is not an option worth offering."""
    with pytest.raises(ValueError):
        AndyurTokenVerifier(jwks_url=jwks_url, issuer=ISSUER, audience="")


# --------------------------------------------- per-call authorisation: require

class _Access:
    def __init__(self, claims):
        self.claims = claims


def test_require_allows_a_granted_action_on_the_pinned_resource():
    """The positive control for `require`, which otherwise could refuse
    everything and pass every test below."""
    assert require(_Access(_claims()), "files:read", {"account": "447"})


def test_require_refuses_an_action_above_the_grant():
    with pytest.raises(Refused) as why:
        require(_Access(_claims()), "payments:transfer", {"account": "447"})
    assert "payments:transfer" in str(why.value)


def test_require_refuses_a_resource_the_token_was_not_pinned_to():
    """The pin's whole job: a token minted to act on account 447 must not move
    money in 999, however correctly it was signed."""
    with pytest.raises(Refused) as why:
        require(_Access(_claims()), "files:read", {"account": "999"})
    assert "447" in str(why.value) and "999" in str(why.value)


def test_require_refuses_when_there_is_no_verified_token():
    with pytest.raises(Refused):
        require(None, "files:read", {"account": "447"})


def test_an_absent_action_list_is_unrestricted_and_an_empty_one_is_deny_all():
    """These are DIFFERENT, and collapsing them makes a deny-all token read as a
    permit-all one. Absent means no action model restricts this token; `[]` means
    nothing is permitted."""
    absent = _claims(authorization_details=[{
        "type": "urn:andyur:authority", "resources": {"account": "447"}}])
    absent.pop("scope")
    actions, pin, restricted = _authority(absent)
    assert actions == [] and pin == {"account": "447"} and restricted is False
    assert require(_Access(absent), "payments:transfer", {"account": "447"})

    # The scope is DELIBERATELY permissive. With an empty scope too, falling
    # through to it changes nothing and the test cannot tell the two shapes
    # apart -- a mutation treating `actions: []` as unrestricted survived until
    # this line gave it somewhere wider to fall through to.
    deny_all = _claims(scope=["files:read", "payments:transfer"],
                       authorization_details=[{
                           "type": "urn:andyur:authority",
                           "resources": {"account": "447"},
                           "actions": []}])
    actions, _, restricted = _authority(deny_all)
    assert actions == [] and restricted is True, (
        "an explicit empty actions list was widened by the scope fallback")
    with pytest.raises(Refused):
        require(_Access(deny_all), "files:read", {"account": "447"})
    with pytest.raises(Refused):
        require(_Access(deny_all), "payments:transfer", {"account": "447"})


def test_the_pin_still_binds_when_no_action_restricts_the_token():
    unrestricted = _claims(authorization_details=[{
        "type": "urn:andyur:authority", "resources": {"account": "447"}}])
    unrestricted.pop("scope")
    with pytest.raises(Refused):
        require(_Access(unrestricted), "payments:transfer", {"account": "999"})


def test_authority_ignores_a_rar_entry_that_is_not_ours():
    """Another product's authorization_details entry must not be read as if it
    were Andyur's ceiling."""
    claims = _claims(authorization_details=[
        {"type": "urn:someone:else", "actions": ["payments:transfer"],
         "resources": {"account": "999"}},
        {"type": "urn:andyur:authority", "actions": ["files:read"],
         "resources": {"account": "447"}},
    ])
    actions, pin, restricted = _authority(claims)
    assert actions == ["files:read"] and restricted is True
    assert pin == {"account": "447"}
    with pytest.raises(Refused):
        require(_Access(claims), "payments:transfer", {"account": "999"})


# ------------------------------------------- against a REAL Andyur-minted token

@pytest.mark.anyio
async def test_a_real_andyur_token_validates_at_a_real_resource_server(
        env, key, jwks_url, monkeypatch):
    """End to end through `tokenexchange.mint`, so the token's real shape is what
    is verified. A fixture updated to match a change would hide exactly the
    interop break that made agentgateway refuse every call."""
    from andyur import db
    from andyur.server import tokenexchange

    with db.connect() as c:
        for name in ("scout", "specialist"):
            c.execute("INSERT OR IGNORE INTO agents (name, description, paused, "
                      "created_at) VALUES (?, '', 0, ?)", (name, db.utcnow()))

    # The FIXTURE's key, so the JWKS being served is the one that signed. A
    # second _Key() here signs with a key the resource server has never seen,
    # which fails for a reason that has nothing to do with what is under test.
    monkeypatch.setattr(tokenexchange, "_private_key", lambda: key.private)

    token, _ = tokenexchange.mint(
        "specialist", AUD, caller="scout", ctx_sub="alice",
        ctx_scope=["files:read"], pin={"account": "447"})

    access = await _verify(_verifier(jwks_url), token)
    assert access is not None, "a token Andyur really minted was refused"
    assert access.subject == "alice"
    assert "files:read" in access.scopes
    assert require(access, "files:read", {"account": "447"})
    with pytest.raises(Refused):
        require(access, "files:read", {"account": "999"})


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ------------------------------------ what a security review found by running it

def test_an_UNPINNED_token_cannot_touch_a_named_resource():
    """The hole this file exists to close, demonstrated end to end before it was
    fixed: Andyur omits `authorization_details` entirely for an unpinned run, and
    the old check was `if key in pin and ...` -- so a token with no pin skipped
    the comparison and the same user with the same scope moved money in ANY
    account they named. An unpinned token is not a token pinned to everything."""
    unpinned = _claims(scope=["payments:transfer"])
    del unpinned["authorization_details"]
    with pytest.raises(Refused) as why:
        require(_Access(unpinned), "payments:transfer", {"account": "999"})
    assert "names no 'account'" in str(why.value)


def test_a_token_pinned_to_a_DIFFERENT_key_cannot_touch_this_one():
    """Same hole, second shape: a pin on `customer` said nothing about
    `account`, and nothing-said used to mean allowed."""
    other = _claims(authorization_details=[{
        "type": "urn:andyur:authority", "resources": {"customer": "c1"},
        "actions": ["payments:transfer"]}])
    with pytest.raises(Refused):
        require(_Access(other), "payments:transfer", {"account": "999"})


def test_a_tool_may_opt_out_of_requiring_a_pin_explicitly():
    """The exception has to exist -- a global read is legitimate -- but it is a
    keyword so it cannot be passed by accident."""
    unpinned = _claims(scope=["files:read"])
    del unpinned["authorization_details"]
    assert require(_Access(unpinned), "files:read", {"account": "999"},
                   allow_unpinned=True)


def test_two_authority_entries_are_refused_rather_than_merged():
    """Merging is unsafe in both directions: unioning actions lets a permissive
    entry widen a restrictive one, and last-wins on the pin refuses a call the
    token actually granted. Andyur mints exactly one entry, so more than one is
    a format this code does not understand."""
    two = _claims(authorization_details=[
        {"type": "urn:andyur:authority", "resources": {"account": "447"},
         "actions": ["files:read"]},
        {"type": "urn:andyur:authority", "resources": {"account": "999"},
         "actions": ["payments:transfer"]},
    ])
    with pytest.raises(Refused) as why:
        require(_Access(two), "files:read", {"account": "447"})
    assert "cannot be safely merged" in str(why.value)


@pytest.mark.parametrize("bad", [{"type": "x"}, "a string", 42])
def test_authorization_details_that_is_not_a_list_is_refused(bad):
    """RFC 9396 says it is an array. Iterating a dict yields its KEYS, so the pin
    was silently dropped and the actions came from `scope` -- fail-open on the
    exact claim that carries the resource bound."""
    with pytest.raises(Refused):
        require(_Access(_claims(authorization_details=bad)), "files:read",
                {"account": "447"})


@pytest.mark.anyio
@pytest.mark.parametrize("typ", ["at+jwt", "application/at+jwt", "AT+JWT",
                                 "application/AT+JWT"])
async def test_every_spelling_rfc_9068_permits_is_accepted(key, jwks_url, typ):
    """RFC 9068 sec 2.1 allows the media-type form, and RFC 7519 makes the type
    case-insensitive. Refusing them locks out a conforming issuer."""
    assert await _verify(_verifier(jwks_url), key.sign(_claims(), typ=typ)) is not None


@pytest.mark.anyio
@pytest.mark.parametrize("missing", ["client_id", "jti"])
async def test_a_token_missing_a_claim_rfc_9068_requires_is_refused(
        key, jwks_url, missing):
    """RFC 9068 sec 2.2 makes both REQUIRED and sec 4 says a resource server must
    reject a token without them. Andyur's own mint comment says exactly that;
    this is the server that has to act on it."""
    claims = _claims()
    del claims[missing]
    assert await _verify(_verifier(jwks_url), key.sign(claims)) is None


@pytest.mark.anyio
async def test_a_flood_of_unknown_kids_does_not_refetch_the_jwks_each_time(
        key, jwks_url, monkeypatch):
    """An unauthenticated remote DoS: PyJWT refetches on ANY unmatched kid,
    bypassing the cache, and the fetch is blocking urllib inside an async
    handler. Measured before the fix: ten hostile requests froze the server for
    50s and a legitimate call went from 0.02s to 4.75s."""
    verifier = _verifier(jwks_url)
    fetches = []
    real = verifier._keys.get_signing_key_from_jwt

    def counting(token):
        fetches.append(1)
        return real(token)

    monkeypatch.setattr(verifier._keys, "get_signing_key_from_jwt", counting)
    hostile = jwt.encode(_claims(), "secret", algorithm="HS256",
                         headers={"typ": "at+jwt", "kid": "no-such-key"})
    for _ in range(8):
        assert await verifier.verify_token(hostile) is None
    assert len(fetches) == 1, (
        f"{len(fetches)} JWKS fetches for one unknown kid; a flood can force one "
        "per request")


@pytest.mark.anyio
async def test_the_required_claim_list_is_not_empty(key, jwks_url):
    """A mutation emptying `require` survived, because no test presented a token
    missing a claim the list names. Each one is checked individually so the list
    cannot quietly shrink."""
    for claim in ("exp", "iat", "sub", "aud", "iss", "client_id", "jti"):
        claims = _claims()
        del claims[claim]
        assert await _verify(_verifier(jwks_url), key.sign(claims)) is None, (
            f"a token with no {claim} was accepted")


def test_require_with_no_resources_still_enforces_the_action():
    """A tool that names no resource gets no pin enforcement -- that is by
    construction, since there is nothing to compare. The ACTION ceiling must
    still apply, or such a tool would be unguarded entirely."""
    with pytest.raises(Refused):
        require(_Access(_claims()), "payments:transfer")
    assert require(_Access(_claims()), "files:read")


# --- F-02: RFC 8705 cnf sender binding (pep.verify_cnf) -----------------------

import base64 as _b64
import hashlib as _hl

from pep import verify_cnf, x5t_s256  # noqa: E402

_CERT_A = b"DER-of-certificate-A"
_CERT_B = b"DER-of-certificate-B"


def _thumb(der):
    return _b64.urlsafe_b64encode(_hl.sha256(der).digest()).rstrip(b"=").decode()


def test_x5t_s256_is_the_rfc_8705_thumbprint():
    """base64url(SHA-256(DER)), no trailing padding (RFC 8705 sec 3.1)."""
    assert x5t_s256(_CERT_A) == _thumb(_CERT_A)
    assert "=" not in x5t_s256(_CERT_A)


def test_a_token_bound_to_the_presented_certificate_passes():
    verify_cnf({"cnf": {"x5t#S256": _thumb(_CERT_A)}}, _CERT_A)  # no raise


def test_a_token_bound_to_a_different_certificate_is_refused():
    """The stolen-token replay: bound to cert A, presented over cert B."""
    with pytest.raises(Refused, match="not bound to this channel"):
        verify_cnf({"cnf": {"x5t#S256": _thumb(_CERT_A)}}, _CERT_B)


def test_a_bound_token_over_a_connection_with_no_client_cert_is_refused():
    """A bound token accepted over an unauthenticated channel silently degrades
    to a bearer -- refused."""
    with pytest.raises(Refused, match="presented none"):
        verify_cnf({"cnf": {"x5t#S256": _thumb(_CERT_A)}}, None)


def test_a_cnf_with_only_an_unverifiable_method_is_refused():
    """cnf.jkt needs a DPoP proof this function is not given; a confirmation we
    cannot check must not be accepted as if it were absent."""
    with pytest.raises(Refused, match="cannot verify"):
        verify_cnf({"cnf": {"jkt": "some-dpop-thumb"}}, _CERT_A)


def test_a_non_object_cnf_is_refused():
    with pytest.raises(Refused, match="not an object"):
        verify_cnf({"cnf": "x5t#S256=whatever"}, _CERT_A)


def test_a_bearer_token_without_cnf_is_accepted_unless_strict():
    verify_cnf({}, _CERT_A)                       # bearer, pre-binding posture
    verify_cnf({}, None)                          # no cert needed for a bearer
    with pytest.raises(Refused, match="requires sender-bound"):
        verify_cnf({}, _CERT_A, require_cnf=True)


def test_verify_cnf_refuses_a_non_ascii_thumbprint_cleanly():
    """A non-ASCII cnf thumbprint is attacker-influenced; it must yield Refused,
    not a TypeError bubbling up as a 500 (hmac.compare_digest rejects non-ASCII
    str)."""
    with pytest.raises(Refused, match="not bound to this channel"):
        verify_cnf({"cnf": {"x5t#S256": "abcédef"}}, _CERT_A)


def test_x5t_s256_known_answer_vector():
    """Pin an independent expected value so a shared bug (hex, standard-alphabet
    base64, padding) can't pass both sides. SHA-256(b"") base64url, no pad."""
    # echo -n '' | openssl dgst -sha256 -binary | basenc --base64url | tr -d '='
    assert x5t_s256(b"") == "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"


# --- F-02: full PEP composition (verify_token -> verify_cnf -> require) --------

@pytest.mark.anyio
async def test_the_full_pep_chain_composes_for_a_cnf_bound_token(key, jwks_url):
    """Prove the three functions compose, so a regression BETWEEN them (not just
    inside one) is caught: a signed at+jwt carrying cnf is verified, then
    channel-bound against the live cert, then authorized for the action."""
    cert = _CERT_A
    claims = _claims(cnf={"x5t#S256": _thumb(cert)})
    token = key.sign(claims)
    v = _verifier(jwks_url)
    access = await _verify(v, token)
    assert access is not None                       # signature/iss/aud/exp pass
    # channel binding against the presented cert
    verify_cnf(access.claims, cert, require_cnf=True)          # no raise
    with pytest.raises(Refused):
        verify_cnf(access.claims, _CERT_B, require_cnf=True)   # wrong cert
    # per-call authorization on the pinned resource
    require(access, "files:read", {"account": "447"})          # no raise
    with pytest.raises(Refused):
        require(access, "files:write", {"account": "447"})     # above the grant

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from andyur.resource_dpop import DPoPRefused, DPoPVerifier, access_token_hash


TOKEN = "curity-access-token"
ACTOR = "spiffe://andyur.test/agent/a/run/r1"
URL = "https://tool.andyur.test/mcp"
NOW = int(time.time())


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64u(n.x.to_bytes(32, "big")),
            "y": b64u(n.y.to_bytes(32, "big"))}


def jkt(key):
    import json
    raw = json.dumps(jwk(key), separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(raw).digest())


def proof(key, **changes):
    claims = {"jti": str(uuid.uuid4()), "iat": NOW, "htm": "POST",
              "htu": URL, "ath": access_token_hash(TOKEN)}
    claims.update(changes.pop("claims", {}))
    headers = {"typ": "dpop+jwt", "jwk": jwk(key)}
    headers.update(changes.pop("headers", {}))
    return jwt.encode(claims, changes.pop("signing_key", key),
                      algorithm=changes.pop("algorithm", "ES256"), headers=headers)


@pytest.fixture
def holder():
    return ec.generate_private_key(ec.SECP256R1())


def claims(holder):
    return {"act": {"sub": ACTOR}, "cnf": {"jkt": jkt(holder)}}


def validate(verifier, holder, value=None, **kw):
    return verifier.validate(access_token=kw.pop("access_token", TOKEN),
                             access_claims=kw.pop("access_claims", claims(holder)),
                             proof=value or proof(holder), method=kw.pop("method", "POST"),
                             external_url=kw.pop("external_url", URL),
                             expected_actor=kw.pop("expected_actor", ACTOR),
                             now=kw.pop("now", NOW), **kw)


def test_positive_control_and_exact_replay_denial(holder):
    verifier = DPoPVerifier()
    value = proof(holder)
    assert validate(verifier, holder, value).actor == ACTOR
    with pytest.raises(DPoPRefused, match="replayed"):
        validate(verifier, holder, value)


@pytest.mark.parametrize("mutation, message", [
    ({"method": "GET"}, "method or external URL"),
    ({"external_url": URL + "/wrong"}, "method or external URL"),
    ({"expected_actor": ACTOR + "/wrong"}, "sealed run actor"),
    ({"access_token": TOKEN + "-other"}, "ath"),
    ({"now": NOW + 5}, "freshness"),
    ({"now": NOW - 2}, "freshness"),
])
def test_live_request_mutations_are_refused(holder, mutation, message):
    with pytest.raises(DPoPRefused, match=message):
        validate(DPoPVerifier(), holder, **mutation)


def test_wrong_holder_missing_binding_and_actor_are_refused(holder):
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(DPoPRefused, match="holder"):
        validate(DPoPVerifier(), holder, proof(other))
    for changed, message in (({"act": {"sub": ACTOR}}, "cnf"),
                             ({"cnf": {"jkt": jkt(holder)}}, "actor")):
        with pytest.raises(DPoPRefused, match=message):
            validate(DPoPVerifier(), holder, access_claims=changed)


def test_proof_shape_and_required_claims_are_closed(holder):
    private = jwk(holder)
    private["d"] = "private"
    cases = [
        proof(holder, headers={"kid": "extra"}),
        proof(holder, headers={"typ": "JWT"}),
        proof(holder, headers={"jwk": private}),
        proof(holder, claims={"jti": ""}),
        proof(holder, claims={"jti": "x" * 129}),
        proof(holder, claims={"ath": "wrong"}),
        proof(holder, claims={"htm": "GET"}),
        proof(holder, claims={"htu": URL + "/wrong"}),
    ]
    for value in cases:
        with pytest.raises(DPoPRefused):
            validate(DPoPVerifier(), holder, value)


def test_capacity_closes_without_evicting_live_entries(holder):
    verifier = DPoPVerifier(per_run_entries=2, aggregate_entries=3)
    first = proof(holder, claims={"jti": "first"})
    validate(verifier, holder, first)
    validate(verifier, holder, proof(holder, claims={"jti": "second"}))
    with pytest.raises(DPoPRefused, match="run replay capacity is closed"):
        validate(verifier, holder, proof(holder, claims={"jti": "third"}))
    with pytest.raises(DPoPRefused, match="replayed"):
        validate(verifier, holder, first)


def test_expired_replay_entries_are_reclaimed(holder):
    verifier = DPoPVerifier(
        freshness_seconds=5, clock_skew_seconds=1,
        per_run_entries=1, aggregate_entries=1)
    validate(verifier, holder,
             proof(holder, claims={"jti": "expired", "iat": NOW - 5}),
             now=NOW - 5)
    validate(verifier, holder,
             proof(holder, claims={"jti": "replacement", "iat": NOW}),
             now=NOW)
    assert verifier.counts() == (1, 1)


def test_concurrent_exact_replay_executes_once(holder):
    verifier = DPoPVerifier()
    value = proof(holder, claims={"jti": "one-concurrent-proof"})

    def attempt(_):
        try:
            validate(verifier, holder, value)
            return True
        except DPoPRefused:
            return False

    with ThreadPoolExecutor(max_workers=12) as pool:
        accepted = list(pool.map(attempt, range(12)))
    assert accepted.count(True) == 1
    assert accepted.count(False) == 11

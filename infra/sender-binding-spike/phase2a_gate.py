#!/usr/bin/env python3
"""Disposable Phase-2a gate against the pinned Go reference AS over HTTPS."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from requests.adapters import HTTPAdapter
from requests_oauth2client import ClientSecretPost, DPoPKey, OAuth2Client

from phase1_gate import NoNonceDPoPKey


ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
ACTOR_TOKEN = "urn:ietf:params:oauth:token-type:jwt"
RESOURCE = "https://telemetry.internal/teams/checkout"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unsigned(claims: dict) -> str:
    return b64u(b'{"alg":"none","typ":"JWT"}') + "." + b64u(
        json.dumps(claims, separators=(",", ":")).encode()
    ) + "."


SUBJECT = unsigned({"sub": "alice", "iss": "chat-app", "act": {"sub": "chat-app"}})
ACTOR = unsigned({"sub": "spiffe://andyur.example/agent/sre/run/phase2a"})


def session(cert: str) -> requests.Session:
    value = requests.Session()
    value.verify = cert
    value.trust_env = False
    value.cookies.clear()
    value.mount("https://", HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1))
    return value


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    nums = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(nums.x.to_bytes(32, "big")),
        "y": b64u(nums.y.to_bytes(32, "big")),
    }


def proof(
    key: ec.EllipticCurvePrivateKey,
    endpoint: str,
    *,
    typ: str = "dpop+jwt",
    htm: str = "POST",
    htu: str | None = None,
    iat: int | None = None,
    jti: str | None = None,
    extra: dict | None = None,
    header_extra: dict | None = None,
) -> str:
    claims = {
        "htm": htm,
        "htu": endpoint if htu is None else htu,
        "iat": int(time.time()) if iat is None else iat,
        "jti": str(uuid.uuid4()) if jti is None else jti,
    }
    claims.update(extra or {})
    headers = {"typ": typ, "jwk": public_jwk(key)}
    headers.update(header_extra or {})
    return jwt.encode(claims, key, algorithm="ES256", headers=headers)


def form() -> dict[str, str]:
    return {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": "client_one",
        "client_secret": "gateway-secret",
        "subject_token": SUBJECT,
        "subject_token_type": ACCESS_TOKEN,
        "actor_token": ACTOR,
        "actor_token_type": ACTOR_TOKEN,
        "requested_token_type": ACCESS_TOKEN,
        "resource": RESOURCE,
        "scope": "telemetry:read",
    }


def exchange_raw(http: requests.Session, endpoint: str, dpop: str | None) -> requests.Response:
    headers = {"DPoP": dpop} if dpop is not None else {}
    return http.post(endpoint, data=form(), headers=headers, allow_redirects=False, timeout=(2, 3))


def validate_semantics(token_type: str | None, claims: dict, expected_jkt: str) -> None:
    if not isinstance(token_type, str) or token_type.lower() != "dpop":
        raise ValueError("token response is not exactly DPoP")
    if claims.get("cnf") != {"jkt": expected_jkt}:
        raise ValueError("token is not bound to the expected holder key")
    if claims.get("sub") != "alice":
        raise ValueError("issued subject continuity failed")
    expected_actor = {
        "sub": "spiffe://andyur.example/agent/sre/run/phase2a",
        "act": {"sub": "chat-app"},
    }
    if claims.get("act") != expected_actor:
        raise ValueError("issued actor-chain continuity failed")


def decode_and_verify(
    http: requests.Session, base: str, token: str, token_type: str | None, expected_jkt: str
) -> dict:
    discovery = http.get(f"{base}/.well-known/openid-configuration", timeout=(2, 3)).json()
    jwks = http.get(discovery["jwks_uri"], timeout=(2, 3)).json()
    header = jwt.get_unverified_header(token)
    matches = [key for key in jwks["keys"] if key.get("kid") == header.get("kid")]
    if len(matches) != 1:
        raise AssertionError("issued token did not select exactly one pinned-AS JWKS key")
    claims = jwt.decode(
        token,
        jwt.PyJWK.from_dict(matches[0]).key,
        algorithms=["RS256"],
        issuer=base,
        audience=RESOURCE,
        options={"require": ["iss", "sub", "aud", "iat", "exp", "cnf"]},
    )
    validate_semantics(token_type, claims, expected_jkt)
    return claims


def run(base: str, cert: str) -> dict:
    endpoint = f"{base}/token"
    http = session(cert)
    client = OAuth2Client(endpoint, auth=ClientSecretPost("client_one", "gateway-secret"))
    client.session.verify = cert
    client.session.trust_env = False
    client.session.cookies.clear()
    client.session.mount("https://", HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1))
    holder = NoNonceDPoPKey.generate(alg="ES256")
    try:
        token = client.token_exchange(
            subject_token=SUBJECT,
            subject_token_type=ACCESS_TOKEN,
            actor_token=ACTOR,
            actor_token_type=ACTOR_TOKEN,
            requested_token_type=ACCESS_TOKEN,
            resource=RESOURCE,
            scope="telemetry:read",
            dpop_key=holder,
            requests_kwargs={"allow_redirects": False, "timeout": (2, 3)},
        )
        claims = decode_and_verify(http, base, token.access_token, token.token_type, holder.dpop_jkt)

        semantic_mutations: dict[str, str] = {}
        missing_cnf = dict(claims)
        missing_cnf.pop("cnf")
        other_holder = DPoPKey.generate(alg="ES256")
        for label, mutated_type, changed in (
            ("token_type_bearer", "Bearer", claims),
            ("token_type_missing", None, claims),
            ("token_type_ambiguous", "DPoP Bearer", claims),
            ("cnf_missing", token.token_type, missing_cnf),
            ("cnf_wrong_holder", token.token_type, {**claims, "cnf": {"jkt": other_holder.dpop_jkt}}),
            ("cnf_extra_member", token.token_type, {**claims, "cnf": {"jkt": holder.dpop_jkt, "x5t#S256": "x"}}),
            ("subject_drift", token.token_type, {**claims, "sub": "mallory"}),
            ("actor_drift", token.token_type, {**claims, "act": {"sub": "spiffe://wrong"}}),
        ):
            if mutated_type == token.token_type and changed == claims:
                raise AssertionError(f"semantic mutation {label} did not apply")
            try:
                validate_semantics(mutated_type, changed, holder.dpop_jkt)
            except ValueError as exc:
                semantic_mutations[label] = type(exc).__name__
            else:
                raise AssertionError(f"semantic mutation {label} stayed green")
        validate_semantics(token.token_type, claims, holder.dpop_jkt)

        key = ec.generate_private_key(ec.SECP256R1())
        negatives: dict[str, int] = {}

        def denied(label: str, value: str | None) -> None:
            response = exchange_raw(http, endpoint, value)
            try:
                body = response.json()
                if response.status_code < 400 or "access_token" in body:
                    raise AssertionError(f"negative {label} issued: {response.status_code} {body}")
                negatives[label] = response.status_code
            finally:
                response.close()

        denied("missing_proof", None)
        denied("wrong_typ", proof(key, endpoint, typ="JWT"))
        now = int(time.time())
        base_proof_claims = {"htm": "POST", "htu": endpoint, "iat": now, "jti": str(uuid.uuid4())}
        none_proof = b64u(json.dumps({"alg": "none", "typ": "dpop+jwt", "jwk": public_jwk(key)}).encode())
        none_proof += "." + b64u(json.dumps(base_proof_claims).encode()) + "."
        denied("alg_none", none_proof)
        symmetric_secret = b"phase2a-symmetric-proof-key-32bytes"
        symmetric_jwk = {"kty": "oct", "k": b64u(symmetric_secret)}
        denied(
            "symmetric_alg_and_jwk",
            jwt.encode(
                base_proof_claims,
                symmetric_secret,
                algorithm="HS256",
                headers={"typ": "dpop+jwt", "jwk": symmetric_jwk},
            ),
        )
        other_key = ec.generate_private_key(ec.SECP256R1())
        denied(
            "signature_key_mismatch",
            proof(key, endpoint, header_extra={"jwk": public_jwk(other_key)}),
        )
        private_header = public_jwk(key)
        private_number = key.private_numbers().private_value
        private_header["d"] = b64u(private_number.to_bytes(32, "big"))
        denied("private_jwk_member", proof(key, endpoint, header_extra={"jwk": private_header}))
        denied("wrong_htu", proof(key, endpoint, htu=f"{base}/wrong"))
        denied("wrong_htm", proof(key, endpoint, htm="GET"))
        # go-oidc's pinned proof window is 600 seconds; cross it rather than
        # testing the clock-sensitive inclusive boundary.
        denied("stale_iat", proof(key, endpoint, iat=int(time.time()) - 1200))
        denied("future_iat", proof(key, endpoint, iat=int(time.time()) + 1200))
        replay = proof(key, endpoint, jti="phase2a-replay-fixed")
        first = exchange_raw(http, endpoint, replay)
        try:
            if first.status_code != 200 or "access_token" not in first.json():
                raise AssertionError("replay mutation lacked a positive first presentation")
        finally:
            first.close()
        denied("replayed_jti", replay)

        return {
            "schema": "andyur.sender-binding.phase2a/v1",
            "status": "pass",
            "reference_as": {"issuer": base, "https": urlsplit(base).scheme == "https"},
            "mature_client": {"token_type": token.token_type, "cnf_matches": True},
            "issued": {"sub": claims["sub"], "aud": claims["aud"], "act": claims["act"]},
            "semantic_negative_mutations": semantic_mutations,
            "negative_denials": negatives,
            "profile_note": (
                "The client-generated ordinary token proof contains neither nonce nor ath; "
                "unknown proof claims are not treated as an AS authorization input."
            ),
        }
    finally:
        client.session.close()
        http.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reference-dir", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.base.rstrip("/"), args.cert)
    result["evidence_inputs"] = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in {
            "phase2a_gate": Path(__file__),
            "phase1_confinement": Path(__file__).with_name("phase1_gate.py"),
            "verify_phase2a": Path(__file__).with_name("verify-phase2a.sh"),
            "reference_as_main": args.reference_dir / "main.go",
            "reference_as_test": args.reference_dir / "main_test.go",
            "reference_as_go_mod": args.reference_dir / "go.mod",
            "reference_as_go_sum": args.reference_dir / "go.sum",
            "reference_as_patch": args.reference_dir / "patches/0001-token-exchange-request-carries-scope-and-authdetails.patch",
            "reference_as_patch_builder": args.reference_dir / "patches/apply.sh",
            "phase2a_lock": Path(__file__).with_name("requirements.txt"),
            "oauth_lock": Path(__file__).parent.parent / "oauth-client-bakeoff/requirements.txt",
        }.items()
    }
    policy_inputs = sorted(
        path for path in (args.reference_dir / "data").rglob("*") if path.is_file()
    )
    policy_manifest = b"".join(
        path.relative_to(args.reference_dir).as_posix().encode() + b"\0" + path.read_bytes() + b"\0"
        for path in policy_inputs
    )
    result["evidence_inputs"]["reference_policy_manifest"] = hashlib.sha256(policy_manifest).hexdigest()
    owned_inputs = sorted(
        path
        for path in args.reference_dir.rglob("*")
        if path.is_file()
        and "patches/go-oidc" not in path.relative_to(args.reference_dir).as_posix()
        and "/.git/" not in ("/" + path.relative_to(args.reference_dir).as_posix() + "/")
    )
    owned_manifest = b"".join(
        path.relative_to(args.reference_dir).as_posix().encode() + b"\0" + path.read_bytes() + b"\0"
        for path in owned_inputs
    )
    result["evidence_inputs"]["reference_owned_source_manifest"] = hashlib.sha256(
        owned_manifest
    ).hexdigest()
    result["profile"] = {
        "dpop_required": True,
        "tls_direct": True,
        "go_oidc_version": "v0.25.0",
        "go_oidc_commit": "6aeac93f370044ca9a59a556b9230cd10bd96868",
        "request_deadline_seconds": 3,
        "gate_deadline_seconds": 40,
        "teardown_deadline_seconds": 2,
    }
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)

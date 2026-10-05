#!/usr/bin/env python3
"""Disposable ADR-007 Phase-1 DPoP client/verifier capability gate.

This is structurally test-only. It must never be imported by production code.
It records counts and public hashes only, never access tokens or private JWKs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import platform
import os
import signal
import ssl
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from jwskate import Jwk
from requests.adapters import HTTPAdapter
from requests_oauth2client import (
    ClientSecretBasic,
    DPoPKey,
    InvalidTokenResponse,
    OAuth2Client,
)


ISSUER = "https://phase1-as.invalid"
AUDIENCE = "urn:andyur:phase1:resource"


class NonceUnsupported(RuntimeError):
    """The nonce-free ADR-007 profile received an AS or RS nonce challenge."""


class NoNonceDPoPKey(DPoPKey):
    """Confine requests-oauth2client without replacing its DPoP machinery."""

    def handle_as_provided_dpop_nonce(self, response: requests.Response) -> None:
        response.close()
        raise NonceUnsupported("AS DPoP nonce is unsupported")

    def handle_rs_provided_dpop_nonce(self, response: requests.Response) -> None:
        response.close()
        raise NonceUnsupported("resource DPoP nonce is unsupported")


@dataclass
class State:
    counts: Counter = field(default_factory=Counter)
    proofs: dict[str, list[str]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, case: str, proof: str | None) -> int:
        with self.lock:
            self.counts[case] += 1
            if proof:
                self.proofs.setdefault(case, []).append(proof)
            return self.counts[case]


def _public_jkt(proof: str) -> str:
    header = jwt.get_unverified_header(proof)
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk or jwk.get("kty") == "oct":
        raise AssertionError("DPoP proof did not contain one public asymmetric JWK")
    return Jwk(jwk).thumbprint()


def _verify_proof(
    proof: str,
    expected_htu: str,
    *,
    expected_htm: str = "POST",
    ath: str | None = None,
    expected_nonce: str | None = None,
) -> dict:
    header = jwt.get_unverified_header(proof)
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
        raise AssertionError("DPoP JOSE header is outside the closed Phase-1 profile")
    jwk = header.get("jwk")
    key = jwt.PyJWK.from_dict(jwk).key
    claims = jwt.decode(
        proof,
        key,
        algorithms=["ES256"],
        options={
            "verify_aud": False,
            "require": ["jti", "iat", "htm", "htu"],
        },
    )
    if claims["htm"] != expected_htm or claims["htu"] != expected_htu:
        raise AssertionError("DPoP proof method or target did not match")
    if claims.get("nonce") != expected_nonce or (expected_nonce is None and "nonce" in claims):
        raise AssertionError("DPoP proof nonce did not match the expected challenge state")
    if ath is None and "ath" in claims:
        raise AssertionError("token-endpoint proof unexpectedly contained ath")
    if ath is not None and claims.get("ath") != ath:
        raise AssertionError("resource proof ath did not match exact token")
    return claims


def _fd_count() -> int | None:
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            return len(os.listdir(directory))
        except OSError:
            pass
    return None


def _ath(token: str) -> str:
    digest = hashlib.sha256(token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _validate_token(
    token: str,
    token_type: str | None,
    public_key,
    expected_jkt: str,
) -> dict:
    if not isinstance(token_type, str) or token_type.lower() != "dpop":
        raise ValueError("token_type is not exactly DPoP")
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["ES256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["sub", "iat", "exp", "aud", "cnf"]},
    )
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict) or set(cnf) != {"jkt"}:
        raise ValueError("cnf is not the closed jkt object")
    if not isinstance(cnf["jkt"], str) or cnf["jkt"] != expected_jkt:
        raise ValueError("cnf.jkt does not match the holder key")
    return claims


def _token_response(signing_key, proof: str) -> bytes:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "phase1-user",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 120,
        "cnf": {"jkt": _public_jkt(proof)},
    }
    access_token = jwt.encode(claims, signing_key, algorithm="ES256", headers={"kid": "phase1"})
    return json.dumps(
        {
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": 120,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
        separators=(",", ":"),
    ).encode()


def _handler(state: State, signing_key):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:
            return

        def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            case = self.headers.get("X-Case", "success")
            proof = self.headers.get("DPoP")
            attempt = state.record(case, proof)
            if case.startswith("nonce"):
                self._send(
                    400,
                    b'{"error":"use_dpop_nonce"}',
                    {"DPoP-Nonce": f"nonce-{attempt}"},
                )
                return
            if not proof:
                self._send(400, b'{"error":"invalid_dpop_proof"}')
                return
            _verify_proof(proof, f"{base_url}/token")
            self._send(200, _token_response(signing_key, proof))

        def do_GET(self) -> None:
            case = self.headers.get("X-Case", "rs")
            proof = self.headers.get("DPoP")
            authorization = self.headers.get("Authorization", "")
            if not proof or not authorization.startswith("DPoP "):
                self._send(400, b'{"error":"invalid_dpop_proof"}')
                return
            token = authorization.removeprefix("DPoP ")
            attempt = state.record(case, proof)
            _verify_proof(
                proof,
                f"{base_url}/resource",
                expected_htm="GET",
                ath=_ath(token),
                expected_nonce=None if attempt == 1 else "rs-nonce",
            )
            if attempt == 1:
                self._send(
                    401,
                    b'{"error":"use_dpop_nonce"}',
                    {
                        "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                        "DPoP-Nonce": "rs-nonce",
                    },
                )
            else:
                self._send(200, b'{"ok":true}')

    return Handler


def _client(base: str) -> OAuth2Client:
    client = OAuth2Client(
        f"{base}/token",
        auth=ClientSecretBasic("phase1-client", "phase1-secret"),
    )
    client.session.verify = cert_path
    client.session.trust_env = False
    client.session.cookies.clear()
    client.session.mount(
        "https://",
        HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1, pool_block=True),
    )
    return client


def _exchange(client: OAuth2Client, key: DPoPKey, case: str):
    return client.token_exchange(
        subject_token="sealed-subject-reference",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="sealed-actor-assertion",
        actor_token_type="urn:ietf:params:oauth:token-type:jwt",
        requested_token_type="urn:ietf:params:oauth:token-type:access_token",
        dpop_key=key,
        audience=AUDIENCE,
        scope="telemetry:read",
        requests_kwargs={
            "headers": {"X-Case": case},
            "allow_redirects": False,
            "timeout": (1.0, 1.0),
        },
    )


def run() -> dict:
    state = State()
    as_key = ec.generate_private_key(ec.SECP256R1())
    server = ThreadingHTTPServer(("localhost", 0), _handler(state, as_key))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    global base_url
    base_url = f"https://localhost:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    guarded = NoNonceDPoPKey.generate(alg="ES256")
    client = _client(base_url)
    result: dict[str, Any] | None = None
    try:
        token = _exchange(client, guarded, "success")
        token_claims = _validate_token(
            token.access_token,
            token.token_type,
            as_key.public_key(),
            guarded.dpop_jkt,
        )
        success_claims = _verify_proof(state.proofs["success"][0], f"{base_url}/token")

        try:
            _exchange(client, guarded, "nonce_guarded")
            raise AssertionError("guarded AS nonce challenge unexpectedly succeeded")
        except NonceUnsupported:
            pass
        if state.counts["nonce_guarded"] != 1 or guarded.as_nonce is not None:
            raise AssertionError("guarded AS nonce path retried or retained nonce state")

        fd_before = _fd_count()
        for _ in range(32):
            try:
                _exchange(client, guarded, "nonce_guarded_stress")
                raise AssertionError("guarded AS nonce stress unexpectedly succeeded")
            except NonceUnsupported:
                pass
        stress_claims = [
            _verify_proof(proof, f"{base_url}/token")
            for proof in state.proofs["nonce_guarded_stress"]
        ]
        stress_jtis = [claims["jti"] for claims in stress_claims]
        if len(stress_jtis) != 32 or len(set(stress_jtis)) != 32:
            raise AssertionError("guarded AS proofs did not have distinct jti values")

        default_key = DPoPKey.generate(alg="ES256")
        mutated = _client(base_url)
        try:
            try:
                _exchange(mutated, default_key, "nonce_default_mutation")
                raise AssertionError("default nonce mutation unexpectedly succeeded")
            except InvalidTokenResponse:
                pass
        finally:
            mutated.session.close()
        if state.counts["nonce_default_mutation"] != 3 or default_key.as_nonce != "nonce-3":
            raise AssertionError("exact default AS nonce auto-retry mutation was not observed")
        default_as_claims = [
            _verify_proof(
                proof,
                f"{base_url}/token",
                expected_nonce=None if index == 0 else f"nonce-{index}",
            )
            for index, proof in enumerate(state.proofs["nonce_default_mutation"])
        ]
        if [claims.get("nonce") for claims in default_as_claims] != [None, "nonce-1", "nonce-2"]:
            raise AssertionError("default AS retry proofs did not carry challenge nonces")
        if len({claims["jti"] for claims in default_as_claims}) != 3:
            raise AssertionError("default AS retry proofs reused jti")

        try:
            requests.get(
                f"{base_url}/resource",
                headers={"X-Case": "rs_guarded"},
                auth=token,
                verify=cert_path,
                timeout=(1.0, 1.0),
            )
            raise AssertionError("guarded RS nonce challenge unexpectedly succeeded")
        except NonceUnsupported:
            pass
        if state.counts["rs_guarded"] != 1 or guarded.rs_nonce is not None:
            raise AssertionError("guarded RS nonce path replayed or retained nonce state")

        rs_stress = requests.Session()
        rs_stress.trust_env = False
        rs_stress.verify = cert_path
        rs_stress.mount("https://", HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1))
        try:
            for index in range(32):
                try:
                    rs_stress.get(
                        f"{base_url}/resource",
                        headers={"X-Case": f"rs_guarded_stress_{index}"},
                        auth=token,
                        timeout=(1.0, 1.0),
                    )
                    raise AssertionError("guarded RS nonce stress unexpectedly succeeded")
                except NonceUnsupported:
                    pass
        finally:
            rs_stress.close()
        fd_after = _fd_count()
        if fd_before is not None and fd_after is not None and fd_after > fd_before + 2:
            raise AssertionError("nonce refusal leaked file descriptors")

        rs_default_key = DPoPKey.generate(alg="ES256")
        rs_default_client = _client(base_url)
        try:
            default_token = _exchange(rs_default_client, rs_default_key, "success_default")
            response = requests.get(
                f"{base_url}/resource",
                headers={"X-Case": "rs_default_mutation"},
                auth=default_token,
                verify=cert_path,
                timeout=(1.0, 1.0),
            )
            response.close()
        finally:
            rs_default_client.session.close()
        if state.counts["rs_default_mutation"] != 2:
            raise AssertionError("exact default RS auto-replay mutation was not observed")
        default_rs_claims = [
            _verify_proof(
                proof,
                f"{base_url}/resource",
                expected_htm="GET",
                ath=_ath(default_token.access_token),
                expected_nonce=None if index == 0 else "rs-nonce",
            )
            for index, proof in enumerate(state.proofs["rs_default_mutation"])
        ]
        if [claims.get("nonce") for claims in default_rs_claims] != [None, "rs-nonce"]:
            raise AssertionError("default RS replay proof did not carry challenge nonce")
        if len({claims["jti"] for claims in default_rs_claims}) != 2:
            raise AssertionError("default RS replay proof reused jti")

        serialized = token.as_dict()
        private_export_present = bool(serialized.get("dpop_key", {}).get("private_key", {}).get("d"))
        if not private_export_present:
            raise AssertionError("expected library private-key serialization hazard changed")

        now = int(time.time())
        base_claims = dict(token_claims)
        alternate_key = ec.generate_private_key(ec.SECP256R1())

        def encoded(claims: dict, key=as_key, algorithm: str = "ES256") -> str:
            return jwt.encode(claims, key, algorithm=algorithm)

        mutations: list[tuple[str, str, str | None, tuple[type[BaseException], ...]]] = []
        mutations.append(("wrong_signature", encoded(base_claims, alternate_key), "DPoP", (jwt.InvalidSignatureError,)))
        wrong_issuer = dict(base_claims, iss="https://wrong.invalid")
        mutations.append(("wrong_issuer", encoded(wrong_issuer), "DPoP", (jwt.InvalidIssuerError,)))
        wrong_audience = dict(base_claims, aud="wrong-audience")
        mutations.append(("wrong_audience", encoded(wrong_audience), "DPoP", (jwt.InvalidAudienceError,)))
        expired = dict(base_claims, exp=now - 1)
        mutations.append(("expired", encoded(expired), "DPoP", (jwt.ExpiredSignatureError,)))
        future_iat = dict(base_claims, iat=now + 3600)
        mutations.append(("future_iat", encoded(future_iat), "DPoP", (jwt.ImmatureSignatureError,)))
        mutations.append(
            (
                "disallowed_alg",
                jwt.encode(base_claims, "fixture-secret-is-at-least-32-bytes", algorithm="HS256"),
                "DPoP",
                (jwt.InvalidAlgorithmError,),
            )
        )
        for claim in ("iss", "sub", "iat", "exp", "aud", "cnf"):
            missing = dict(base_claims)
            missing.pop(claim)
            mutations.append((f"missing_{claim}", encoded(missing), "DPoP", (jwt.MissingRequiredClaimError,)))
        for label, cnf in (
            ("cnf_string", "not-an-object"),
            ("cnf_missing_jkt", {}),
            ("cnf_wrong_jkt", {"jkt": "wrong"}),
            ("cnf_non_string_jkt", {"jkt": 7}),
            ("cnf_extra_member", {"jkt": guarded.dpop_jkt, "x5t#S256": "unexpected"}),
        ):
            malformed = dict(base_claims, cnf=cnf)
            mutations.append((label, encoded(malformed), "DPoP", (ValueError,)))
        mutations.extend(
            [
                ("token_type_bearer", token.access_token, "Bearer", (ValueError,)),
                ("token_type_missing", token.access_token, None, (ValueError,)),
                ("token_type_ambiguous", token.access_token, "DPoP Bearer", (ValueError,)),
            ]
        )
        mutation_results = {}
        for label, mutated_token, mutated_type, expected_errors in mutations:
            if mutated_token == token.access_token and mutated_type == token.token_type:
                raise AssertionError(f"mutation {label} did not apply")
            try:
                _validate_token(mutated_token, mutated_type, as_key.public_key(), guarded.dpop_jkt)
            except expected_errors as exc:
                mutation_results[label] = type(exc).__name__
            else:
                raise AssertionError(f"token mutation {label} stayed green")

        result = {
            "schema": "andyur.sender-binding.phase1/v1",
            "status": "pass",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "libraries": {
                "requests-oauth2client": importlib.metadata.version("requests-oauth2client"),
                "PyJWT": jwt.__version__,
            },
            "proof": {
                "alg": jwt.get_unverified_header(state.proofs["success"][0])["alg"],
                "typ": jwt.get_unverified_header(state.proofs["success"][0])["typ"],
                "public_jwk_only": True,
                "htm": success_claims["htm"],
                "htu_path": "/token",
                "observed_distinct_jti": len(set(stress_jtis)),
                "has_iat": isinstance(success_claims["iat"], int),
                "has_nonce": "nonce" in success_claims,
                "has_ath": "ath" in success_claims,
                "jkt_sha256": hashlib.sha256(guarded.dpop_jkt.encode()).hexdigest(),
            },
            "token": {
                "token_type": token.token_type,
                "verified_cnf_matches": True,
                "negative_mutations": mutation_results,
            },
            "nonce_confinement": {
                "guarded_as_attempts": state.counts["nonce_guarded"],
                "default_as_mutation_attempts": state.counts["nonce_default_mutation"],
                "guarded_rs_attempts": state.counts["rs_guarded"],
                "default_rs_mutation_attempts": state.counts["rs_default_mutation"],
                "guarded_state_absent": guarded.as_nonce is None and guarded.rs_nonce is None,
                "stress_as_challenges": state.counts["nonce_guarded_stress"],
                "stress_rs_challenges": sum(
                    count for case, count in state.counts.items() if case.startswith("rs_guarded_stress_")
                ),
                "fd_growth": None if fd_before is None or fd_after is None else fd_after - fd_before,
            },
            "known_custody_gap": {
                "private_jwk_serializable_via_token_as_dict": private_export_present,
            },
        }
    finally:
        client.session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise AssertionError("TLS fixture server thread survived cleanup")
    if result is None:
        raise AssertionError("gate produced no result")
    result["cleanup"] = {"server_thread_alive": thread.is_alive(), "complete": True}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cert_path = args.cert
    key_path = args.key
    base_url = ""
    signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(TimeoutError("gate deadline exceeded")))
    signal.alarm(30)
    try:
        result = run()
    finally:
        signal.alarm(0)
    result["evidence_inputs"] = {
        "gate_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "exclusion_gate_sha256": hashlib.sha256(
            Path(__file__).with_name("exclusion_gate.py").read_bytes()
        ).hexdigest(),
        "verify_script_sha256": hashlib.sha256(
            Path(__file__).with_name("verify.sh").read_bytes()
        ).hexdigest(),
        "phase1_lock_sha256": hashlib.sha256(Path(__file__).with_name("requirements.txt").read_bytes()).hexdigest(),
        "oauth_lock_sha256": hashlib.sha256(
            (Path(__file__).parent.parent / "oauth-client-bakeoff" / "requirements.txt").read_bytes()
        ).hexdigest(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)
    print(json.dumps(result, indent=2, sort_keys=True))

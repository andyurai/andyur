#!/usr/bin/env python3
"""Disposable Phase-2b direct HTTPS resource DPoP enforcement gate."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client as http_client
import json
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwskate import Jwk, SignedJwt
from requests.adapters import HTTPAdapter
from requests_oauth2client import ClientSecretPost, DPoPKey, OAuth2Client

from phase1_gate import NoNonceDPoPKey
from phase2a_gate import ACCESS_TOKEN, ACTOR, ACTOR_TOKEN, RESOURCE, SUBJECT, b64u, proof, public_jwk, session


FRESHNESS_SECONDS = 5
CLOCK_SKEW_SECONDS = 1
MAX_REPLAY_ENTRIES = 256


class ResourceServer(ThreadingHTTPServer):
    request_queue_size = 32
    daemon_threads = True
    block_on_close = False


def ath(token: str) -> str:
    return b64u(hashlib.sha256(token.encode("ascii")).digest())


@dataclass
class ResourceState:
    as_key: Any
    issuer: str
    audience: str
    expected_url: str = ""
    expected_authority: str = ""
    executions: int = 0
    seen: dict[tuple[str, str], int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    enforce_ath: bool = True
    enforce_replay: bool = True
    enforce_live_uri: bool = True
    last_error: str = ""
    test_now: int | None = None
    expiry_from_iat: bool = True

    def validate(
        self, authorization: str | None, dpop: str | None, host_values: list[str], request_target: str
    ) -> None:
        if not isinstance(authorization, str) or not authorization.startswith("DPoP "):
            raise ValueError("authorization scheme is not DPoP")
        if not dpop:
            raise ValueError("DPoP proof is missing")
        token = authorization.removeprefix("DPoP ")
        token_header = jwt.get_unverified_header(token)
        if token_header.get("typ") not in ("at+jwt", "application/at+jwt") or token_header.get("alg") != "RS256":
            raise ValueError("access token JOSE profile mismatch")
        token_claims = jwt.decode(
            token,
            self.as_key,
            algorithms=["RS256"],
            issuer=self.issuer,
            audience=self.audience,
            options={"require": ["iss", "sub", "aud", "iat", "exp", "cnf", "client_id", "jti", "act"]},
        )
        cnf = token_claims.get("cnf")
        if not isinstance(cnf, dict) or set(cnf) != {"jkt"} or not isinstance(cnf["jkt"], str):
            raise ValueError("token cnf is not one closed jkt binding")

        header = jwt.get_unverified_header(dpop)
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
            raise ValueError("resource proof JOSE profile mismatch")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict) or set(jwk) not in (
            {"kty", "crv", "x", "y"},
            {"kty", "crv", "x", "y", "alg"},
        ):
            raise ValueError(f"resource proof JWK is not one public P-256 key: {sorted(jwk or {})}")
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or jwk.get("alg", "ES256") != "ES256":
            raise ValueError("resource proof key type is unsupported")
        if Jwk(jwk).thumbprint() != cnf["jkt"]:
            raise ValueError("resource proof holder does not match token cnf")
        claims = jwt.decode(
            dpop,
            jwt.PyJWK.from_dict(jwk).key,
            algorithms=["ES256"],
            leeway=CLOCK_SKEW_SECONDS,
            options={"verify_aud": False, "require": ["jti", "iat", "htm", "htu", "ath"]},
        )
        if len(host_values) != 1 or host_values[0] != self.expected_authority:
            raise ValueError("live HTTP authority does not match the sealed listener authority")
        parsed_target = urlsplit(request_target)
        if (
            not request_target.startswith("/")
            or request_target.startswith("//")
            or parsed_target.scheme
            or parsed_target.netloc
            or parsed_target.fragment
        ):
            raise ValueError("HTTP request target is not the closed origin-form profile")
        live_url = f"https://{host_values[0]}{parsed_target.path}"
        expected_htu = live_url if self.enforce_live_uri else self.expected_url
        if claims["htm"] != "POST" or claims["htu"] != expected_htu:
            raise ValueError("resource proof method or URI mismatch")
        now = int(time.time()) if self.test_now is None else self.test_now
        if not isinstance(claims["iat"], int) or not (
                -CLOCK_SKEW_SECONDS <= now - claims["iat"] < FRESHNESS_SECONDS):
            raise ValueError("resource proof is outside the freshness window")
        if not isinstance(claims["jti"], str) or not claims["jti"] or len(claims["jti"]) > 128:
            raise ValueError("resource proof jti is outside the closed profile")
        if self.enforce_ath and claims["ath"] != ath(token):
            raise ValueError("resource proof ath does not bind the exact token")
        with self.lock:
            self.seen = {key: expires for key, expires in self.seen.items() if expires > now}
            replay_key = (cnf["jkt"], claims["jti"])
            if self.enforce_replay and replay_key in self.seen:
                raise ValueError("resource proof replayed")
            if len(self.seen) >= MAX_REPLAY_ENTRIES:
                raise ValueError("resource replay cache capacity reached")
            # Retain the JTI through the proof's last possible acceptance,
            # including the bounded future-clock allowance. Receipt-time TTL
            # pruning lets a future-dated proof become replayable again.
            expiry_base = claims["iat"] if self.expiry_from_iat else now
            self.seen[replay_key] = expiry_base + FRESHNESS_SECONDS
            self.executions += 1


def handler(state: ResourceState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            try:
                state.validate(
                    self.headers.get("Authorization"),
                    self.headers.get("DPoP"),
                    self.headers.get_all("Host", []),
                    self.path,
                )
            except Exception as exc:
                state.last_error = f"{type(exc).__name__}: {exc}"
                body, status = b'{"error":"invalid_dpop_proof"}', 401
            else:
                body, status = b'{"executed":true}', 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def oauth_client(endpoint: str, cert: str) -> OAuth2Client:
    client = OAuth2Client(endpoint, auth=ClientSecretPost("client_one", "gateway-secret"))
    client.session.verify = cert
    client.session.trust_env = False
    client.session.cookies.clear()
    client.session.mount("https://", HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1))
    return client


def exchange(client: OAuth2Client, holder: DPoPKey):
    return client.token_exchange(
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


def run(as_base: str, cert: str, key_path: str) -> dict:
    http = session(cert)
    discovery = http.get(f"{as_base}/.well-known/openid-configuration", timeout=(2, 3)).json()
    jwks = http.get(discovery["jwks_uri"], timeout=(2, 3)).json()
    as_keys = [key for key in jwks["keys"] if key.get("kid") == "rs256_key"]
    if len(as_keys) != 1:
        raise AssertionError("reference AS did not expose one expected RS256 key")
    state = ResourceState(jwt.PyJWK.from_dict(as_keys[0]).key, as_base, RESOURCE)
    server = ResourceServer(("localhost", 0), handler(state))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    resource_url = f"https://localhost:{server.server_port}/mcp/tools/call"
    state.expected_url = resource_url
    state.expected_authority = f"localhost:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    holder = NoNonceDPoPKey.generate(alg="ES256")
    client = oauth_client(f"{as_base}/token", cert)
    resource_http = session(cert)
    results: dict[str, int] = {}
    try:
        token = exchange(client, holder)
        positive = resource_http.post(resource_url, auth=token, json={"tool": "query_metrics"}, timeout=(2, 3))
        try:
            if positive.status_code != 200 or state.executions != 1:
                raise AssertionError(
                    f"real library resource proof positive did not execute exactly once: {state.last_error}"
                )
        finally:
            positive.close()
        query_positive = resource_http.post(
            resource_url + "?transport=fixture#not-on-wire",
            auth=token,
            json={"tool": "query_metrics"},
            timeout=(2, 3),
        )
        try:
            if query_positive.status_code != 200 or state.executions != 2:
                raise AssertionError("RFC 9449 query/fragment exclusion positive failed")
        finally:
            query_positive.close()

        def request(
            label: str,
            dpop: str | None,
            access_token: str = token.access_token,
            expected: int = 401,
            target: str = resource_url,
            host: str | None = None,
            scheme: str = "DPoP",
        ) -> None:
            headers = {"Authorization": f"{scheme} {access_token}"}
            if dpop is not None:
                headers["DPoP"] = dpop
            if host is not None:
                headers["Host"] = host
            before = state.executions
            response = resource_http.post(target, headers=headers, json={}, timeout=(2, 3))
            try:
                if response.status_code != expected:
                    raise AssertionError(f"resource mutation {label} returned {response.status_code}, want {expected}")
                if expected != 200 and state.executions != before:
                    raise AssertionError(f"resource mutation {label} executed the operation")
                results[label] = response.status_code
            finally:
                response.close()

        correct_ath = ath(token.access_token)
        request("missing_proof", None)
        request("bearer_authorization_scheme", str(holder.proof("POST", resource_url, ath=correct_ath)), scheme="Bearer")
        other = DPoPKey.generate(alg="ES256")
        request("wrong_holder", str(other.proof("POST", resource_url, ath=correct_ath)))
        request("wrong_ath", str(holder.proof("POST", resource_url, ath=ath("different-token"))))
        request("missing_ath", str(holder.proof("POST", resource_url)))
        request("wrong_method", str(holder.proof("GET", resource_url, ath=correct_ath)))
        for label, target in (
            ("wrong_scheme", resource_url.replace("https://", "http://")),
            ("wrong_host", resource_url.replace("localhost", "127.0.0.1")),
            ("wrong_port", resource_url.replace(f":{server.server_port}", ":1")),
            ("wrong_path", resource_url + "/wrong"),
        ):
            request(label, str(holder.proof("POST", target, ath=correct_ath)))
        request(
            "wrong_wire_host",
            str(holder.proof("POST", resource_url, ath=correct_ath)),
            host="other.invalid",
        )
        request(
            "wrong_wire_path",
            str(holder.proof("POST", resource_url, ath=correct_ath)),
            target=resource_url + "/other",
        )
        duplicate_before = state.executions
        duplicate_connection = http_client.HTTPSConnection(
            "localhost",
            server.server_port,
            context=ssl.create_default_context(cafile=cert),
            timeout=3,
        )
        duplicate_connection.putrequest("POST", "/mcp/tools/call", skip_host=True)
        duplicate_connection.putheader("Host", state.expected_authority)
        duplicate_connection.putheader("Host", "other.invalid")
        duplicate_connection.putheader("Authorization", f"DPoP {token.access_token}")
        duplicate_connection.putheader("DPoP", str(holder.proof("POST", resource_url, ath=correct_ath)))
        duplicate_connection.putheader("Content-Length", "0")
        duplicate_connection.endheaders()
        duplicate_response = duplicate_connection.getresponse()
        duplicate_response.read()
        duplicate_connection.close()
        if duplicate_response.status != 401 or state.executions != duplicate_before:
            raise AssertionError("duplicate live Host headers were not denied before execution")
        results["duplicate_wire_host"] = duplicate_response.status

        def raw_target(label: str, target: str) -> None:
            before = state.executions
            connection = http_client.HTTPSConnection(
                "localhost", server.server_port, context=ssl.create_default_context(cafile=cert), timeout=3
            )
            connection.putrequest("POST", target, skip_host=True)
            connection.putheader("Host", state.expected_authority)
            connection.putheader("Authorization", f"DPoP {token.access_token}")
            connection.putheader("DPoP", str(holder.proof("POST", resource_url, ath=correct_ath)))
            connection.putheader("Content-Length", "0")
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status < 400 or state.executions != before:
                raise AssertionError(f"ambiguous request target {label} was not denied")
            results[label] = response.status

        raw_target("absolute_form_target", "https://other.invalid/mcp/tools/call")
        raw_target("network_path_target", "//other.invalid/mcp/tools/call")
        raw_target("fragment_target", "/mcp/tools/call#fragment")
        stale = DPoPKey(holder.private_key, alg="ES256", iat_generator=lambda: int(time.time()) - 30)
        future = DPoPKey(holder.private_key, alg="ES256", iat_generator=lambda: int(time.time()) + 30)
        request("stale_iat", str(stale.proof("POST", resource_url, ath=correct_ath)))
        request("future_iat", str(future.proof("POST", resource_url, ath=correct_ath)))
        wrong_typ = DPoPKey(holder.private_key, alg="ES256", jwt_typ="JWT")
        request("wrong_typ", str(wrong_typ.proof("POST", resource_url, ath=correct_ath)))

        base_claims = {
            "jti": "phase2b-structure",
            "iat": int(time.time()),
            "htm": "POST",
            "htu": resource_url,
            "ath": correct_ath,
        }

        def signed(claims: dict, *, typ: str | None = "dpop+jwt", signing_key=holder.private_key,
                   header_jwk=None, alg: str = "ES256") -> str:
            return str(SignedJwt.sign(
                claims,
                key=signing_key,
                alg=alg,
                typ=typ,
                extra_headers={"jwk": holder.public_jwk if header_jwk is None else header_jwk},
            ))

        request("missing_typ", signed(base_claims, typ=None))
        none_header = b64u(json.dumps({"alg": "none", "typ": "dpop+jwt", "jwk": dict(holder.public_jwk)}).encode())
        none_proof = none_header + "." + b64u(json.dumps(base_claims).encode()) + "."
        request("alg_none", none_proof)
        symmetric_secret = b"phase2b-symmetric-proof-key-32bytes"
        symmetric_jwk = {"kty": "oct", "k": b64u(symmetric_secret)}
        symmetric_proof = jwt.encode(
            base_claims,
            symmetric_secret,
            algorithm="HS256",
            headers={"typ": "dpop+jwt", "jwk": symmetric_jwk},
        )
        request("symmetric_alg_and_jwk", symmetric_proof)
        for label, jti in (("empty_jti", ""), ("wrong_type_jti", 7), ("overlong_jti", "x" * 129)):
            request(label, signed({**base_claims, "jti": jti}))
        without_jti = dict(base_claims)
        without_jti.pop("jti")
        request("missing_jti", signed(without_jti))

        alt_ec = ec.generate_private_key(ec.SECP256R1())
        private = public_jwk(alt_ec)
        private["d"] = b64u(alt_ec.private_numbers().private_value.to_bytes(32, "big"))
        request("private_jwk", proof(alt_ec, resource_url, htm="POST", extra={"ath": correct_ath}, header_extra={"jwk": private}))

        signature_holder = NoNonceDPoPKey.generate(alg="ES256")
        signature_token = exchange(client, signature_holder)
        request(
            "signature_key_mismatch",
            signed(
                {**base_claims, "jti": "phase2b-signature-mismatch", "ath": ath(signature_token.access_token)},
                signing_key=holder.private_key,
                header_jwk=signature_holder.public_jwk,
            ),
            access_token=signature_token.access_token,
        )

        replay = str(holder.proof("POST", resource_url, ath=correct_ath))
        request("replay_positive", replay, expected=200)
        request("replay_denied", replay)

        second = exchange(client, holder)
        if second.access_token == token.access_token:
            raise AssertionError("same-scope token swap mutation did not change token bytes")
        request(
            "token_proof_swap",
            str(holder.proof("POST", resource_url, ath=ath(token.access_token))),
            access_token=second.access_token,
        )

        # Exact enforcement mutations turn the corresponding denial red.
        state.enforce_ath = False
        request("ath_enforcement_removed", str(holder.proof("POST", resource_url, ath=ath("wrong"))), expected=200)
        state.enforce_ath = True
        request("ath_enforcement_restored", str(holder.proof("POST", resource_url, ath=ath("wrong"))))
        fixed = str(holder.proof("POST", resource_url, ath=correct_ath))
        request("replay_control", fixed, expected=200)
        state.enforce_replay = False
        request("replay_enforcement_removed", fixed, expected=200)
        state.enforce_replay = True
        request("replay_enforcement_restored", fixed)
        state.enforce_live_uri = False
        request(
            "live_uri_enforcement_removed",
            str(holder.proof("POST", resource_url, ath=correct_ath)),
            expected=200,
            target=resource_url + "/other",
        )
        state.enforce_live_uri = True
        request(
            "live_uri_enforcement_restored",
            str(holder.proof("POST", resource_url, ath=correct_ath)),
            target=resource_url + "/other",
        )

        # Actual resource-wire token validation mutations. A test RSA key is
        # temporarily made the PEP's trusted key so semantic failures are not
        # masked by signature failure; the real AS key is restored afterward.
        actual_as_key = state.as_key
        fixture_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        actual_claims = jwt.decode(token.access_token, options={"verify_signature": False})

        def fixture_token(claims: dict, *, typ: str = "at+jwt", key=fixture_key) -> str:
            return jwt.encode(claims, key, algorithm="RS256", headers={"typ": typ, "kid": "phase2b-fixture"})

        state.as_key = fixture_key.public_key()
        good_fixture = fixture_token(actual_claims)
        request(
            "token_verifier_positive",
            str(holder.proof("POST", resource_url, ath=ath(good_fixture))),
            access_token=good_fixture,
            expected=200,
        )
        token_mutations = {
            "token_wrong_issuer": {**actual_claims, "iss": "https://wrong.invalid"},
            "token_wrong_audience": {**actual_claims, "aud": "https://wrong.invalid"},
            "token_expired": {**actual_claims, "exp": int(time.time()) - 1},
            "token_cnf_missing": {key: value for key, value in actual_claims.items() if key != "cnf"},
            "token_cnf_malformed": {**actual_claims, "cnf": "not-an-object"},
            "token_cnf_extra": {**actual_claims, "cnf": {"jkt": holder.dpop_jkt, "x5t#S256": "unexpected"}},
        }
        for required_claim in ("iss", "sub", "aud", "iat", "exp", "client_id", "jti", "act"):
            token_mutations[f"token_missing_{required_claim}"] = {
                key: value for key, value in actual_claims.items() if key != required_claim
            }
        for label, claims in token_mutations.items():
            mutated = fixture_token(claims)
            request(label, str(holder.proof("POST", resource_url, ath=ath(mutated))), access_token=mutated)
        wrong_typ_token = fixture_token(actual_claims, typ="JWT")
        request(
            "token_wrong_typ",
            str(holder.proof("POST", resource_url, ath=ath(wrong_typ_token))),
            access_token=wrong_typ_token,
        )
        hs_token = jwt.encode(
            actual_claims,
            b"phase2b-token-symmetric-key-32bytes",
            algorithm="HS256",
            headers={"typ": "at+jwt", "kid": "phase2b-symmetric"},
        )
        request(
            "token_disallowed_algorithm",
            str(holder.proof("POST", resource_url, ath=ath(hs_token))),
            access_token=hs_token,
        )
        state.as_key = actual_as_key
        wrong_signature = fixture_token(actual_claims)
        request(
            "token_wrong_signature",
            str(holder.proof("POST", resource_url, ath=ath(wrong_signature))),
            access_token=wrong_signature,
        )

        # Concurrent exact-proof replay: precisely one request may dispatch.
        concurrent_proof = str(holder.proof("POST", resource_url, ath=correct_ath))
        concurrent_before = state.executions
        barrier = threading.Barrier(12)

        def concurrent_call() -> int:
            local = session(cert)
            try:
                barrier.wait(timeout=2)
                response = local.post(
                    resource_url,
                    headers={"Authorization": f"DPoP {token.access_token}", "DPoP": concurrent_proof},
                    json={},
                    timeout=(2, 3),
                )
                try:
                    return response.status_code
                finally:
                    response.close()
            finally:
                local.close()

        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(lambda _: concurrent_call(), range(12)))
        if statuses.count(200) != 1 or statuses.count(401) != 11 or state.executions != concurrent_before + 1:
            raise AssertionError(f"concurrent replay race was not exactly-once: {statuses}")
        results["concurrent_replay_one_success"] = statuses.count(200)

        # Exact regression: a proof one second ahead is within the allowed
        # skew. At receipt+freshness it is still acceptable, so its JTI must
        # remain present. Restoring receipt-time expiry makes the exact replay
        # execute and proves this is the enforcement point.
        base_now = int(time.time())
        state.test_now = base_now
        skewed = DPoPKey(
            holder.private_key, alg="ES256",
            iat_generator=lambda: base_now + CLOCK_SKEW_SECONDS)
        secure_proof = str(skewed.proof("POST", resource_url, ath=correct_ath))
        request("future_skew_positive", secure_proof, expected=200)
        state.test_now = base_now + FRESHNESS_SECONDS
        request("future_skew_replay_denied", secure_proof)

        state.test_now = base_now
        state.expiry_from_iat = False
        if state.expiry_from_iat is not False:
            raise AssertionError("receipt-time expiry mutation did not apply")
        mutation_proof = str(skewed.proof("POST", resource_url, ath=correct_ath))
        request("future_skew_mutation_first", mutation_proof, expected=200)
        state.test_now = base_now + FRESHNESS_SECONDS
        request("future_skew_mutation_replay_red", mutation_proof, expected=200)
        state.expiry_from_iat = True
        state.test_now = base_now
        if state.expiry_from_iat is not True:
            raise AssertionError("proof-expiry enforcement was not restored")
        restored_proof = str(skewed.proof("POST", resource_url, ath=correct_ath))
        request("future_skew_restored_positive", restored_proof, expected=200)
        state.test_now = base_now + FRESHNESS_SECONDS
        request("future_skew_restored_replay_denied", restored_proof)
        state.test_now = None

        # Capacity boundary and expiry pruning through the live PEP.
        with state.lock:
            state.seen = {(holder.dpop_jkt, f"prefill-{index}"): int(time.time()) + FRESHNESS_SECONDS for index in range(MAX_REPLAY_ENTRIES - 1)}
        request("replay_capacity_last_slot", str(holder.proof("POST", resource_url, ath=correct_ath)), expected=200)
        request("replay_capacity_closed", str(holder.proof("POST", resource_url, ath=correct_ath)))
        with state.lock:
            state.seen = {key: int(time.time()) - 1 for key in state.seen}
        request("replay_expiry_prunes", str(holder.proof("POST", resource_url, ath=correct_ath)), expected=200)

        return {
            "schema": "andyur.sender-binding.phase2b/v1",
            "status": "pass",
            "resource": {"https": True, "path": "/mcp/tools/call", "executions": state.executions},
            "profile": {"freshness_seconds": FRESHNESS_SECONDS,
                        "clock_skew_seconds": CLOCK_SKEW_SECONDS,
                        "max_replay_entries": MAX_REPLAY_ENTRIES},
            "denials_and_mutations": results,
        }
    finally:
        client.session.close()
        resource_http.close()
        http.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise AssertionError("resource PEP server survived teardown")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--as-base", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reference-dir", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.as_base.rstrip("/"), args.cert, args.key)
    result["evidence_inputs"] = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in {
            "phase2b_gate": Path(__file__),
            "phase2a_gate": Path(__file__).with_name("phase2a_gate.py"),
            "phase1_confinement": Path(__file__).with_name("phase1_gate.py"),
            "verify_phase2b": Path(__file__).with_name("verify-phase2b.sh"),
            "phase2b_lock": Path(__file__).with_name("requirements.txt"),
            "oauth_lock": Path(__file__).parent.parent / "oauth-client-bakeoff/requirements.txt",
        }.items()
    }
    reference_inputs = sorted(
        path for path in args.reference_dir.rglob("*")
        if path.is_file() and "patches/go-oidc" not in path.relative_to(args.reference_dir).as_posix()
    )
    manifest = b"".join(
        path.relative_to(args.reference_dir).as_posix().encode() + b"\0" + path.read_bytes() + b"\0"
        for path in reference_inputs
    )
    result["evidence_inputs"]["reference_owned_source_manifest"] = hashlib.sha256(manifest).hexdigest()
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)

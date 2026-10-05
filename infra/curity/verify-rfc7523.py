#!/usr/bin/env python3
"""Live Curity RFC 7523 -> RFC 8693 actor-continuity gate.

This is a local tenant gate, not production code. It provisions disposable
clients through Curity's local idsh console, records no credential material,
and deletes the clients before returning. A result is emitted only on green.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import subprocess
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from andyur.resource_dpop import DPoPRefused, DPoPVerifier, access_token_hash


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# WHICH CONTAINER IS CURITY, AND WHY IT IS NOT A CONSTANT ANY MORE.
#
# This defaulted to `confident_jackson` -- a name DOCKER invented, on one
# evening, because the image was run without `--name`. It resolved on exactly
# one machine: the one where that draw happened. Everywhere else the gate
# `docker exec`s into a container that does not exist, and the RFC 7523
# evidence was therefore bound to a local accident rather than to anything a
# second machine could reproduce. That is the prepared-machine failure living
# in a default argument.
#
# Resolved by IMAGE instead, which is a property of what the thing IS. The
# explicit env var still wins, for a tenant this cannot guess.
CURITY_IMAGE = "curity/idsvr"
_container_cache: str | None = None


def curity_container() -> str:
    """Resolve lazily, and REFUSE rather than guess.

    Lazy because `verify-single-exchange.py` exec_module()s this file to reuse
    its helpers; resolving at import would make merely loading the module fail
    on a machine with no Docker, which has nothing to do with what that caller
    wants. Cached because the answer cannot change inside one gate run.

    Ambiguity is an error, not a coin toss: two Curity containers mean the
    operator has a choice to make and the gate must not make it for them.
    """
    global _container_cache
    if _container_cache is not None:
        return _container_cache
    explicit = os.environ.get("ANDYUR_CURITY_CONTAINER", "").strip()
    if explicit:
        _container_cache = explicit
        return explicit
    # NOT `--filter ancestor=`: that matches an exact image reference, so it
    # finds nothing for `curity.azurecr.io/curity/idsvr:11.4.0` when asked for
    # `curity/idsvr` -- and a filter that matches nothing is indistinguishable
    # from a tenant that is not running. Match the image NAME, which survives
    # both the registry prefix and the tag.
    found = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"],
        text=True, capture_output=True, timeout=15)
    names = [line.split("\t", 1)[0]
             for line in found.stdout.splitlines() if "\t" in line
             and CURITY_IMAGE in line.split("\t", 1)[1]]
    if len(names) != 1:
        raise RuntimeError(
            f"expected exactly one running {CURITY_IMAGE!r} container, found "
            f"{len(names)}: {names or 'none'}. Start the Curity tenant, or name "
            "it with ANDYUR_CURITY_CONTAINER=<container>.")
    _container_cache = names[0]
    return names[0]
TOKEN_ENDPOINT = os.environ.get(
    "ANDYUR_CURITY_TOKEN_ENDPOINT", "http://127.0.0.1:8443/oauth/v2/oauth-token")
DISCOVERY = os.environ.get(
    "ANDYUR_CURITY_DISCOVERY",
    "http://127.0.0.1:8443/oauth/v2/oauth-anonymous/.well-known/openid-configuration",
)
AUDIENCE = "https://tool.andyur.test"
SCOPE = "andyur.invoke"
ASSERTION_ISSUER = "spiffe://andyur.test"
RUN_SUBJECT = f"spiffe://andyur.test/agent/conformance/run/{uuid.uuid4()}"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_rsa_jwk(key, kid: str) -> dict:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
        "n": b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def public_ec_jwk(key) -> dict:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC", "crv": "P-256",
        "x": b64u(numbers.x.to_bytes(32, "big")),
        "y": b64u(numbers.y.to_bytes(32, "big")),
    }


def jkt(key) -> str:
    jwk = public_ec_jwk(key)
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(canonical).digest())


def dpop(key, *, nonce: str | None = None, endpoint: str = TOKEN_ENDPOINT,
         method: str = "POST", ath: str | None = None,
         issued_at: int | None = None, jti_value: str | None = None) -> str:
    claims = {
        "htm": method, "htu": endpoint,
        "iat": int(time.time()) if issued_at is None else issued_at,
        "jti": jti_value or str(uuid.uuid4()),
    }
    if nonce:
        claims["nonce"] = nonce
    if ath:
        claims["ath"] = ath
    return jwt.encode(claims, key, algorithm="ES256", headers={
        "typ": "dpop+jwt", "jwk": public_ec_jwk(key)})


def client_assertion(client: str, key, kid: str) -> str:
    now = int(time.time())
    return jwt.encode({
        "iss": client, "sub": client, "aud": TOKEN_ENDPOINT,
        "iat": now, "exp": now + 60, "jti": str(uuid.uuid4()),
    }, key, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def token_request(form: dict[str, str], client: str, auth_key, auth_kid: str,
                  holder=None) -> tuple[int, dict, dict[str, str], int]:
    attempts = 0
    nonce = None
    while True:
        attempts += 1
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        request_form = dict(form)
        request_form.update({
            "client_id": client,
            "client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion(client, auth_key, auth_kid),
        })
        if holder is not None:
            headers["DPoP"] = dpop(holder, nonce=nonce)
        request = urllib.request.Request(
            TOKEN_ENDPOINT, urllib.parse.urlencode(request_form).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read(256 << 10)
            body = json.loads(raw) if raw else {}
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            status = response.status
        if (holder is not None and attempts == 1 and status in (400, 401)
                and body.get("error") == "use_dpop_nonce"
                and response_headers.get("dpop-nonce")):
            nonce = response_headers["dpop-nonce"]
            continue
        return status, body, response_headers, attempts


def idsh(lines: list[str]) -> None:
    program = "\n".join(["configure", *lines, "commit", "exit", "exit", ""])
    completed = subprocess.run(
        ["docker", "exec", "-i", curity_container(), "/opt/idsvr/bin/idsh", "-N"],
        input=program, text=True, capture_output=True, timeout=15)
    if completed.returncode or "[error]" in completed.stdout.lower():
        # Curity may echo the failed command, which can contain a secret. Never
        # include console output in this gate's failure or evidence.
        safe = re.sub(r"(?i)(secret|jwks)\s+\S+", r"\1 <redacted>",
                      completed.stdout + completed.stderr)
        raise RuntimeError(
            "Curity idsh configuration transaction failed: " + safe[-1200:])


def configure(subject: str, broker: str, subject_auth_jwks: str,
              broker_auth_jwks: str, trusted_jwks: str) -> None:
    base = ("profiles profile token-service oauth-service settings "
            "authorization-server client-store config-backed client")
    idsh([
        ("set profiles profile token-service oauth-service settings "
         "authorization-server client-authentication asymmetrically-signed-jwt "
        "signature-algorithm RS256"),
        f"set {base} {subject} client-name {subject}",
        f"set {base} {subject} capabilities client-credentials",
        f"set {base} {subject} jwks {subject_auth_jwks}",
        f"set {base} {subject} access-token-ttl 120",
        f"set {base} {subject} audience {AUDIENCE}",
        f"set {base} {subject} scope {SCOPE}",
        f"set {base} {broker} client-name {broker}",
        f"set {base} {broker} capabilities oauth-token-exchange",
        f"set {base} {broker} capabilities assertion jwt trust issuer {ASSERTION_ISSUER}",
        f"set {base} {broker} capabilities assertion jwt trust jwks {trusted_jwks}",
        f"set {base} {broker} jwks {broker_auth_jwks}",
        f"set {base} {broker} access-token-ttl 120",
        f"set {base} {broker} audience {AUDIENCE}",
        f"set {base} {broker} scope {SCOPE}",
        f"set {base} {broker} dpop token-dpop-binding required",
    ])


def cleanup(*clients: str) -> None:
    base = ("profiles profile token-service oauth-service settings "
            "authorization-server client-store config-backed client")
    idsh([f"delete {base} {client}" for client in clients])


def set_token_procedure(source: str) -> None:
    encoded = base64.b64encode(source.encode()).decode()
    idsh([
        ("set processing procedures token-procedure andyur-oauth-exchange "
         f"oauth-token-oauth-token-exchange script {encoded}"),
    ])


def exchange(source_token: str, actor_token: str, broker: str,
             broker_auth, broker_auth_kid: str, holder) -> tuple[str, dict, int]:
    status, response, _, attempts = token_request({
        "grant_type": TOKEN_EXCHANGE,
        "subject_token": source_token, "subject_token_type": ACCESS,
        "actor_token": actor_token, "actor_token_type": ACCESS,
        "requested_token_type": ACCESS, "audience": AUDIENCE, "scope": SCOPE,
    }, broker, broker_auth, broker_auth_kid, holder)
    if status != 200 or not response.get("access_token"):
        raise AssertionError("delegated positive control did not issue")
    return response["access_token"], verify_jwt(response["access_token"]), attempts


def assertion(key, kid: str, *, audience: str = TOKEN_ENDPOINT,
              jti_value: str | None = None) -> str:
    now = int(time.time())
    return jwt.encode({
        "iss": ASSERTION_ISSUER, "sub": RUN_SUBJECT, "aud": audience,
        "iat": now, "exp": now + 120, "jti": jti_value or str(uuid.uuid4()),
    }, key, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def deny_assertion(label: str, value: str, broker: str, auth_key, auth_kid: str,
                   holder) -> dict:
    status, body, _, attempts = token_request({
        "grant_type": JWT_BEARER, "assertion": value, "scope": SCOPE,
    }, broker, auth_key, auth_kid, holder)
    if status < 400 or body.get("access_token"):
        raise AssertionError(f"{label} assertion was accepted")
    return {"status": status, "error": body.get("error"), "attempts": attempts}


def verify_jwt(token: str, *, require_cnf: bool = True) -> dict:
    with urllib.request.urlopen(DISCOVERY, timeout=5) as response:
        discovery = json.load(response)
    with urllib.request.urlopen(discovery["jwks_uri"], timeout=5) as response:
        keys = json.load(response)["keys"]
    header = jwt.get_unverified_header(token)
    matches = [item for item in keys if item.get("kid") == header.get("kid")]
    if len(matches) != 1:
        raise AssertionError("issued token did not select exactly one JWKS key")
    required = ["iss", "sub", "aud", "iat", "exp"]
    if require_cnf:
        required.append("cnf")
    return jwt.decode(token, jwt.PyJWK.from_dict(matches[0]).key,
                      algorithms=["RS256"], issuer=discovery["issuer"], audience=AUDIENCE,
                      options={"require": required})


def live_resource_gate(access_token: str, access_claims: dict, holder) -> dict:
    executions = 0
    verifier = DPoPVerifier()
    resource_url = ""

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_POST(self):
            nonlocal executions
            try:
                authorization = self.headers.get("Authorization", "")
                if not authorization.startswith("DPoP ") \
                        or authorization.removeprefix("DPoP ") != access_token:
                    raise DPoPRefused("authorization is not the issued DPoP token")
                verifier.validate(
                    access_token=access_token, access_claims=access_claims,
                    proof=self.headers.get("DPoP", ""), method="POST",
                    external_url=resource_url, expected_actor=RUN_SUBJECT)
            except DPoPRefused:
                status, body = 401, b'{"error":"invalid_dpop_proof"}'
            else:
                executions += 1
                status, body = 200, b'{"executed":true}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    tls_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(seconds=60))
            .not_valid_after(now + datetime.timedelta(seconds=600))
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(tls_key, hashes.SHA256()))
    with tempfile.TemporaryDirectory(prefix="andyur-curity-resource-") as directory:
        cert_path, key_path = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(tls_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        resource_url = f"https://127.0.0.1:{server.server_port}/invoke"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client_context = ssl.create_default_context(cafile=str(cert_path))

        def call(value: str, token: str = access_token) -> int:
            request = urllib.request.Request(resource_url, b"{}", headers={
                "Authorization": f"DPoP {token}", "DPoP": value,
                "Content-Type": "application/json"})
            try:
                response = urllib.request.urlopen(request, timeout=3, context=client_context)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                response.read()
                return response.status

        token_ath = access_token_hash(access_token)
        proof_value = dpop(holder, endpoint=resource_url, ath=token_ath)
        if call(proof_value) != 200 or executions != 1:
            raise AssertionError("HTTPS resource positive did not execute once")
        denials = {}
        for label, value in {
            "replay": proof_value,
            "wrong_holder": dpop(ec.generate_private_key(ec.SECP256R1()),
                                 endpoint=resource_url, ath=token_ath),
            "wrong_ath": dpop(holder, endpoint=resource_url,
                              ath=access_token_hash("different-token")),
            "wrong_method": dpop(holder, endpoint=resource_url, method="GET", ath=token_ath),
            "wrong_target": dpop(holder, endpoint=resource_url + "/wrong", ath=token_ath),
            "stale": dpop(holder, endpoint=resource_url, ath=token_ath,
                          issued_at=int(time.time()) - 30),
            "future": dpop(holder, endpoint=resource_url, ath=token_ath,
                           issued_at=int(time.time()) + 30),
        }.items():
            status = call(value)
            if status != 401 or executions != 1:
                raise AssertionError(f"HTTPS resource attack {label} was not denied")
            denials[label] = status
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise AssertionError("HTTPS resource survived teardown")
    return {"https": True, "executions": executions, "denials": denials,
            "replay_entries": verifier.counts()[1], "teardown": True}


def main() -> None:
    suffix = secrets.token_hex(4)
    subject, broker = f"andyur-live-subject-{suffix}", f"andyur-live-broker-{suffix}"
    trusted = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_auth = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    broker_auth = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = f"spire-{suffix}"
    jwks_raw = json.dumps({"keys": [public_rsa_jwk(trusted, kid)]},
                          separators=(",", ":")).encode()
    holder = ec.generate_private_key(ec.SECP256R1())
    subject_auth_kid, broker_auth_kid = f"subject-{suffix}", f"broker-{suffix}"
    encoded_jwks = lambda key, value: base64.b64encode(json.dumps(
        {"keys": [public_rsa_jwk(key, value)]}, separators=(",", ":")).encode()).decode()
    configured = False
    procedure_source = (HERE / "token-exchange.js").read_text()
    procedure_mutated = False
    try:
        configure(subject, broker,
                  encoded_jwks(subject_auth, subject_auth_kid),
                  encoded_jwks(broker_auth, broker_auth_kid),
                  base64.b64encode(jwks_raw).decode())
        configured = True
        status, source, _, source_attempts = token_request({
            "grant_type": "client_credentials", "scope": SCOPE,
        }, subject, subject_auth, subject_auth_kid)
        if status != 200 or not source.get("access_token"):
            raise AssertionError("subject positive control did not issue")

        valid_assertion = assertion(trusted, kid)
        status, actor, _, actor_attempts = token_request({
            "grant_type": JWT_BEARER, "assertion": valid_assertion, "scope": SCOPE,
        }, broker, broker_auth, broker_auth_kid, holder)
        if status != 200 or not actor.get("access_token"):
            raise AssertionError(f"trusted actor assertion did not issue: {status} {actor.get('error')}")
        actor_claims = verify_jwt(actor["access_token"], require_cnf=False)
        if actor_claims.get("sub") != RUN_SUBJECT:
            raise AssertionError("actor token lost the run subject")

        access_token, claims, exchange_attempts = exchange(
            source["access_token"], actor["access_token"], broker,
            broker_auth, broker_auth_kid, holder)
        if claims.get("act") != {"sub": RUN_SUBJECT} or claims.get("cnf") != {"jkt": jkt(holder)}:
            raise AssertionError("delegated token lost exact actor or holder binding")

        exact = '  accessTokenData.act = {sub: actorToken.get("sub")};\n'
        mutated_source = procedure_source.replace(exact, "", 1)
        if mutated_source == procedure_source or exact in mutated_source:
            raise AssertionError("exact act.sub mutation did not apply")
        set_token_procedure(mutated_source)
        procedure_mutated = True
        _, mutated_claims, _ = exchange(
            source["access_token"], actor["access_token"], broker,
            broker_auth, broker_auth_kid, holder)
        if mutated_claims.get("act") == {"sub": RUN_SUBJECT}:
            raise AssertionError("act.sub mutation stayed green")
        set_token_procedure(procedure_source)
        procedure_mutated = False
        _, restored_claims, _ = exchange(
            source["access_token"], actor["access_token"], broker,
            broker_auth, broker_auth_kid, holder)
        if restored_claims.get("act") != {"sub": RUN_SUBJECT}:
            raise AssertionError("restored act.sub assertion did not return green")
        resource_result = live_resource_gate(
            access_token, claims, holder)

        negatives = {
            "attacker_signature": deny_assertion(
                "attacker-signature", assertion(attacker, kid), broker,
                broker_auth, broker_auth_kid, holder),
            "wrong_audience": deny_assertion(
                "wrong-audience", assertion(trusted, kid, audience="https://wrong.invalid"),
                broker, broker_auth, broker_auth_kid, holder),
        }
        result = {
            "schema": "andyur-curity-rfc7523-live/v1", "result": "pass",
            "product_version": "11.4.0", "issuer": claims["iss"],
            "actor_subject": RUN_SUBJECT, "audience": AUDIENCE, "scope": SCOPE,
            "positive": {
                "subject_status": 200, "actor_status": 200, "exchange_status": 200,
                "actor_continuity": True, "dpop_jkt_continuity": True,
                "actor_intermediate_dpop_bound": actor_claims.get("cnf") == {"jkt": jkt(holder)},
                "source_attempts": source_attempts, "actor_attempts": actor_attempts,
                "exchange_attempts": exchange_attempts,
            },
            "mutation": {
                "act_assignment_removed": True,
                "semantic_assertion_red": True,
                "procedure_restored": True,
                "semantic_assertion_restored_green": True,
            },
            "resource_enforcement": resource_result,
            "negative": negatives,
            "source_sha256": {
                "infra/curity/verify-rfc7523.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "infra/curity/token-exchange.js": hashlib.sha256((HERE / "token-exchange.js").read_bytes()).hexdigest(),
                "andyur/resource_dpop.py": hashlib.sha256(
                    (ROOT / "andyur/resource_dpop.py").read_bytes()).hexdigest(),
            },
            "teardown": {"clients_deleted": True},
        }
    finally:
        if procedure_mutated:
            set_token_procedure(procedure_source)
        if configured:
            cleanup(subject, broker)
    output = HERE / "result-rfc7523-live-2026-08-20-macos-arm64.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": "pass", "actor": RUN_SUBJECT,
                      "negative": sorted(negatives)}))


if __name__ == "__main__":
    main()

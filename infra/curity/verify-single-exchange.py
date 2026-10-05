#!/usr/bin/env python3
"""Live single-leg Curity RFC 8693 + SPIFFE actor gate."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, rsa


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_spec = importlib.util.spec_from_file_location(
    "curity_legacy_gate", HERE / "verify-rfc7523.py")
legacy = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(legacy)

ACTOR_JWT = "urn:ietf:params:oauth:token-type:jwt"
PLUGIN_ID = "andyur-spiffe"


def plugin_config(jwks: str) -> None:
    base = ("profiles profile token-service oauth-service settings "
            "authorization-server token-procedure-plugins "
            f"token-procedure-plugin {PLUGIN_ID} "
            "andyur-spiffe-actor-token-exchange")
    endpoint = ("profiles profile token-service oauth-service endpoints endpoint "
                "token-service-token token-endpoint-procedures "
                "oauth-token-oauth-token-exchange")
    legacy.idsh([
        f"set {base} actor-issuer {legacy.ASSERTION_ISSUER}",
        f"set {base} actor-audience {legacy.TOKEN_ENDPOINT}",
        f"set {base} actor-jwks {jwks}",
        f"set {base} max-actor-lifetime-seconds 300",
        f"set {base} clock-skew-seconds 2",
        f"set {endpoint} token-procedure-plugin {PLUGIN_ID}",
    ])


def plugin_cleanup() -> None:
    endpoint = ("profiles profile token-service oauth-service endpoints endpoint "
                "token-service-token token-endpoint-procedures "
                "oauth-token-oauth-token-exchange")
    plugins = ("profiles profile token-service oauth-service settings "
               "authorization-server token-procedure-plugins token-procedure-plugin")
    legacy.idsh([
        f"set {endpoint} procedure andyur-oauth-exchange",
        f"delete {plugins} {PLUGIN_ID}",
    ])


def exchange(source_token: str, actor_token: str, client: str, auth_key,
             auth_kid: str, holder) -> tuple[int, dict, int]:
    status, body, _, wire_attempts = legacy.token_request({
        "grant_type": legacy.TOKEN_EXCHANGE,
        "subject_token": source_token,
        "subject_token_type": legacy.ACCESS,
        "actor_token": actor_token,
        "actor_token_type": ACTOR_JWT,
        "requested_token_type": legacy.ACCESS,
        "audience": legacy.AUDIENCE,
        "scope": legacy.SCOPE,
    }, client, auth_key, auth_kid, holder)
    return status, body, wire_attempts


def main() -> None:
    suffix = secrets.token_hex(4)
    subject = f"andyur-single-subject-{suffix}"
    broker = f"andyur-single-broker-{suffix}"
    trusted = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_auth = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    broker_auth = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    holder = ec.generate_private_key(ec.SECP256R1())
    actor_kid = f"spire-{suffix}"
    subject_kid, broker_kid = f"subject-{suffix}", f"broker-{suffix}"

    def jwks(key, kid: str) -> str:
        return json.dumps({"keys": [legacy.public_rsa_jwk(key, kid)]},
                          separators=(",", ":"))

    configured = False
    try:
        legacy.configure(
            subject, broker,
            base64.b64encode(jwks(subject_auth, subject_kid).encode()).decode(),
            base64.b64encode(jwks(broker_auth, broker_kid).encode()).decode(),
            base64.b64encode(jwks(trusted, actor_kid).encode()).decode())
        configured = True
        plugin_config(jwks(trusted, actor_kid))

        subject_status, source, _, source_attempts = legacy.token_request({
            "grant_type": "client_credentials", "scope": legacy.SCOPE,
        }, subject, subject_auth, subject_kid)
        if subject_status != 200 or not source.get("access_token"):
            raise AssertionError("subject positive control did not issue")

        valid_actor = legacy.assertion(trusted, actor_kid)
        status, issued, exchange_wire_attempts = exchange(
            source["access_token"], valid_actor, broker, broker_auth, broker_kid, holder)
        if status != 200 or not issued.get("access_token"):
            raise AssertionError(f"single token exchange failed: {status} {issued.get('error')}")
        claims = legacy.verify_jwt(issued["access_token"])
        if claims.get("act") != {"sub": legacy.RUN_SUBJECT}:
            raise AssertionError("single exchange lost exact act.sub")
        if claims.get("cnf") != {"jkt": legacy.jkt(holder)}:
            raise AssertionError("single exchange lost DPoP binding")

        negatives = {}
        for label, actor in {
            "attacker_signature": legacy.assertion(attacker, actor_kid),
            "wrong_audience": legacy.assertion(
                trusted, actor_kid, audience="https://wrong.invalid"),
        }.items():
            denied_status, denied, attempts = exchange(
                source["access_token"], actor, broker, broker_auth, broker_kid, holder)
            if denied_status < 400 or denied.get("access_token"):
                raise AssertionError(f"{label} actor was accepted")
            negatives[label] = {
                "status": denied_status, "error": denied.get("error"),
                "wire_attempts": attempts,
            }

        # Exact enforcement-point mutation: trust the attacker's public key.
        plugin_config(jwks(attacker, actor_kid))
        red_status, red, _ = exchange(
            source["access_token"], legacy.assertion(attacker, actor_kid),
            broker, broker_auth, broker_kid, holder)
        if red_status != 200 or not red.get("access_token"):
            raise AssertionError("trusted-JWKS mutation did not turn the attack red")
        plugin_config(jwks(trusted, actor_kid))
        restored_status, restored, _ = exchange(
            source["access_token"], legacy.assertion(attacker, actor_kid),
            broker, broker_auth, broker_kid, holder)
        if restored_status < 400 or restored.get("access_token"):
            raise AssertionError("trusted-JWKS restoration did not return green")

        resource = legacy.live_resource_gate(issued["access_token"], claims, holder)
        plugin_jar = HERE / "plugin/target/plugin/spiffe-actor-token-procedure-1.0.0.jar"
        result = {
            "schema": "andyur-curity-single-exchange-live/v1",
            "result": "pass",
            "product_version": "11.4.0",
            "actor_subject": legacy.RUN_SUBJECT,
            "positive": {
                "logical_token_exchanges": 1,
                "source_wire_attempts": source_attempts,
                "exchange_wire_attempts_including_dpop_nonce": exchange_wire_attempts,
                "actor_intermediate_token_issued": False,
                "actor_continuity": True,
                "dpop_jkt_continuity": True,
            },
            "negative": negatives,
            "mutation": {
                "trusted_jwks_replaced_with_attacker": True,
                "attacker_acceptance_red": True,
                "trusted_jwks_restored": True,
                "attacker_denial_restored_green": True,
            },
            "resource_enforcement": resource,
            "source_sha256": {
                "infra/curity/verify-single-exchange.py": hashlib.sha256(
                    Path(__file__).read_bytes()).hexdigest(),
                "infra/curity/plugin.jar": hashlib.sha256(
                    plugin_jar.read_bytes()).hexdigest(),
                "andyur/resource_dpop.py": hashlib.sha256(
                    (ROOT / "andyur/resource_dpop.py").read_bytes()).hexdigest(),
            },
            "teardown": {"clients_deleted": True, "plugin_configuration_removed": True},
        }
    finally:
        if configured:
            try:
                plugin_cleanup()
            finally:
                legacy.cleanup(subject, broker)

    output = HERE / "result-single-exchange-live-2026-08-20-macos-arm64.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": "pass", "actor": legacy.RUN_SUBJECT,
                      "logical_token_exchanges": 1}))


if __name__ == "__main__":
    main()

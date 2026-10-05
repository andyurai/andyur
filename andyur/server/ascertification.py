"""Validation of live authorization-server conformance evidence.

A provider name selects wire syntax; it is not evidence that a particular
tenant was configured safely.  Production therefore requires a short-lived
artifact emitted by the live conformance gate and bound to the exact runtime
configuration.  Credentials never belong in this artifact.
"""

from __future__ import annotations

import json
import base64
import hashlib
import math
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


SCHEMA = "andyur-as-certification/v2"
SUITE = "andyur-as-conformance-v1"
MATRIX_SCHEMA = "andyur-delegated-authorization-matrix/v1"
OVERLAY_SCHEMA = "andyur-delegated-authorization-overlay/v1"
OVERLAY_SUITE = "andyur-delegated-authorization-conformance-v1"
MATRIX_PATH = Path(__file__).with_name("as-certification-matrix.json")
MATRIX_MAX_BYTES = 64 << 10
MATRIX_PROFILE = {
    "contract": "delegated-authorization",
    "provider_binding": "required-by-signed-overlay",
    "tenant_binding": "required-by-signed-overlay",
    "capability": "delegated-spiffe-jwt-actor",
    "route_class": "agent-attributed-managed-dpop",
    "product_version_binding": "required-by-signed-overlay",
    "status": "design-only",
}
MATRIX_SOURCES = (
    "https://www.rfc-editor.org/rfc/rfc8693.html",
    "https://www.rfc-editor.org/rfc/rfc9449.html",
    "https://www.rfc-editor.org/rfc/rfc9068.html",
    "https://github.com/spiffe/spiffe/blob/dc4e9d9b4eff8aa181a54cd330ff9f877186060e/standards/JWT-SVID.md",
)
MAX_BYTES = 64 << 10
MAX_VALIDITY_SECONDS = 31 * 24 * 60 * 60
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = frozenset({
    "schema", "suite", "result", "provider", "capability", "issuer",
    "token_endpoint", "jwks_url", "client_id", "discovery_sha256",
    "product_version", "issued_at", "expires_at", "signature_alg",
    "signing_key_sha256", "scope_config_sha256", "signature",
})
_SIGNED_FIELDS = _FIELDS - {"signature"}

_OVERLAY_FIELDS = frozenset({
    "schema", "suite", "result", "core_schema", "core_sha256", "provider",
    "tenant", "capability", "route_class", "issuer", "token_endpoint",
    "jwks_url", "client_id", "client_auth_method", "policy_config_sha256",
    "product_version", "evidence_sha256", "issued_at", "expires_at",
    "certification_generation",
    "signature_alg", "signing_key_sha256", "signature",
})
_OVERLAY_SIGNED_FIELDS = _OVERLAY_FIELDS - {"signature"}

_MATRIX_INVARIANTS = frozenset({
    "subject-continuity", "actor-signature", "actor-audience",
    "actor-run-binding", "actor-lifetime", "target-and-scope",
    "resource-pin", "sender-binding", "single-attempt-cancellation",
    "rotation-revocation", "halt-teardown", "secret-isolation",
})
_MATRIX_ROW_FIELDS = frozenset({
    "id", "required", "enforcement_point", "positive", "negative",
    "expected_denial", "mutation", "mutation_expected_red", "observation",
    "provider_support", "timeout_ms",
})
_OVERLAY_CLIENT_AUTH_METHODS = frozenset({
    "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth",
    "client_secret_basic", "client_secret_post",
})


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _secure_https_url(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port  # force validation of nonnumeric and out-of-range ports
    except ValueError:
        return False
    return (parsed.scheme == "https" and bool(hostname)
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment)


def certification_matrix(path: str | Path = MATRIX_PATH) -> tuple[dict, str]:
    """Load and validate the closed production-qualification matrix."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MATRIX_MAX_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"certification matrix cannot be read: {type(exc).__name__}") from exc
    if len(raw) > MATRIX_MAX_BYTES:
        raise ValueError("certification matrix exceeds the 64 KiB safety limit")
    try:
        document = json.loads(raw, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("certification matrix is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {
            "schema", "profile", "official_sources", "limits", "rows"}:
        raise ValueError("certification matrix must use the closed v1 document shape")
    if document["schema"] != MATRIX_SCHEMA:
        raise ValueError(f"certification matrix schema must be {MATRIX_SCHEMA}")
    profile = document["profile"]
    if profile != MATRIX_PROFILE:
        raise ValueError("certification matrix profile is not the closed design contract")
    sources = document["official_sources"]
    if sources != list(MATRIX_SOURCES):
        raise ValueError("certification matrix requires the exact standards sources")
    limits = document["limits"]
    required_limits = {
        "target_concurrent_runs", "max_concurrent_requests_per_run",
        "broker_workers_per_run",
        "fleet_max_inflight_as", "broker_queue", "credential_cache_entries",
        "resource_replay_cache_entries_per_run",
        "resource_replay_cache_entries_aggregate",
        "resource_replay_memory_mib_aggregate", "resource_qps_limit_per_run",
        "resource_rate_period_seconds", "resource_burst_per_run",
        "as_attempts_per_request",
        "as_qps_limit", "as_rate_period_seconds", "as_burst",
        "liveness_qps_limit", "liveness_rate_period_seconds", "liveness_burst",
        "as_timeout_ms",
        "broker_local_reserve_ms", "broker_timeout_ms", "ext_authz_timeout_ms",
        "route_timeout_ms", "pre_admission_cancel_release_ms",
        "active_worker_release_ms", "p95_authorization_ms",
        "jwks_timeout_ms", "introspection_timeout_ms", "rotation_propagation_ms",
        "halt_admission_close_ms", "envoy_hard_kill_ms", "workload_fence_ms",
        "pod_deletion_ms", "sidecar_shutdown_ms", "max_token_lifetime_seconds",
        "max_actor_assertion_lifetime_seconds", "post_revocation_residual_seconds",
        "post_halt_saved_proof_residual_seconds", "proof_freshness_seconds",
        "proof_clock_skew_seconds", "proof_safety_seconds",
        "resource_replay_cache_ttl_seconds", "max_proof_bytes",
        "max_issued_token_bytes", "max_protected_header_bytes",
        "max_injected_headers_bytes", "max_token_response_bytes",
        "envoy_memory_mib_per_run",
        "broker_memory_mib_per_run", "supervisor_memory_mib_per_run",
        "memory_limit_mib_per_run", "cpu_limit_millicores_per_run",
        "envoy_cpu_millicores_per_run", "broker_cpu_millicores_per_run",
        "supervisor_cpu_millicores_per_run", "pid_limit_per_run",
        "envoy_pid_limit_per_run", "broker_pid_limit_per_run",
        "supervisor_pid_limit_per_run", "file_descriptor_limit_per_run",
        "envoy_fd_limit_per_run", "broker_fd_limit_per_run",
        "supervisor_fd_limit_per_run", "connection_limit_per_run",
        "envoy_connection_limit_per_run", "broker_connection_limit_per_run",
        "supervisor_connection_limit_per_run", "startup_timeout_ms",
        "envoy_startup_timeout_ms", "broker_startup_timeout_ms",
        "supervisor_startup_timeout_ms",
        "certification_validity_seconds",
    }
    if not isinstance(limits, dict) or set(limits) != required_limits \
            or any(type(value) is not int or value < 0 for value in limits.values()):
        raise ValueError("certification matrix limits are incomplete or invalid")
    if limits["broker_queue"] != 0 or limits["credential_cache_entries"] != 0 \
            or limits["as_attempts_per_request"] != 1:
        raise ValueError("first certification profile must be cacheless, queue-free, one-attempt")
    if limits["target_concurrent_runs"] <= 0 \
            or limits["max_concurrent_requests_per_run"] <= 0 \
            or limits["broker_workers_per_run"] <= 0 \
            or limits["fleet_max_inflight_as"] != (
                limits["target_concurrent_runs"] * min(
                    limits["max_concurrent_requests_per_run"],
                    limits["broker_workers_per_run"])):
        raise ValueError("certification run and fleet cardinality is inconsistent")
    if not (0 < limits["as_timeout_ms"] + limits["broker_local_reserve_ms"]
            <= limits["broker_timeout_ms"] < limits["ext_authz_timeout_ms"]
            < limits["route_timeout_ms"] <= limits["sidecar_shutdown_ms"]):
        raise ValueError("certification authorization timeouts are not strictly nested")
    if limits["as_timeout_ms"] > 550 or limits["broker_timeout_ms"] > 700 \
            or limits["ext_authz_timeout_ms"] > 850:
        raise ValueError("certification timeouts exceed the qualified ADR-007 profile")
    if limits["max_token_lifetime_seconds"] <= 0 \
            or limits["max_actor_assertion_lifetime_seconds"] <= 0 \
            or limits["certification_validity_seconds"] <= 0:
        raise ValueError("certification lifetimes must be positive")
    positive = required_limits - {
        "broker_queue", "credential_cache_entries",
    }
    if any(limits[name] <= 0 for name in positive):
        raise ValueError("certification security and operations limits must be positive")
    if limits["active_worker_release_ms"] < limits["broker_timeout_ms"] \
            or limits["pre_admission_cancel_release_ms"] >= limits["broker_timeout_ms"]:
        raise ValueError("certification cancellation release bounds are inconsistent")
    if limits["as_burst"] > limits["as_qps_limit"] * limits["as_rate_period_seconds"] \
            or limits["liveness_burst"] > (
                limits["liveness_qps_limit"] * limits["liveness_rate_period_seconds"]):
        raise ValueError("certification rate and burst limits are inconsistent")
    usable_proof = (limits["proof_freshness_seconds"]
                    - limits["proof_clock_skew_seconds"]
                    - limits["proof_safety_seconds"])
    if usable_proof <= 0 or limits["route_timeout_ms"] >= usable_proof * 1000 \
            or limits["post_halt_saved_proof_residual_seconds"] > (
                limits["proof_freshness_seconds"]):
        raise ValueError("certification proof freshness and route bounds are inconsistent")
    if limits["resource_replay_cache_ttl_seconds"] < (
            limits["proof_freshness_seconds"] + limits["proof_clock_skew_seconds"]):
        raise ValueError("certification replay state expires before accepted proofs")
    if limits["resource_burst_per_run"] > (
            limits["resource_qps_limit_per_run"] * limits["resource_rate_period_seconds"]):
        raise ValueError("certification resource rate and burst limits are inconsistent")
    if limits["resource_replay_cache_entries_per_run"] < (
            limits["resource_qps_limit_per_run"]
            * limits["resource_replay_cache_ttl_seconds"]
            + limits["resource_burst_per_run"]):
        raise ValueError("certification replay capacity cannot retain every live proof")
    if limits["resource_replay_cache_entries_aggregate"] < (
            limits["target_concurrent_runs"]
            * limits["resource_replay_cache_entries_per_run"]):
        raise ValueError("certification aggregate replay capacity is inconsistent")
    if not (limits["max_proof_bytes"] <= limits["max_protected_header_bytes"]
            and limits["max_issued_token_bytes"] <= limits["max_protected_header_bytes"]
            and limits["max_protected_header_bytes"] < limits["max_injected_headers_bytes"]
            <= limits["max_token_response_bytes"]):
        raise ValueError("certification token and protected-header sizes are inconsistent")
    if limits["max_injected_headers_bytes"] > 48 * 1024:
        raise ValueError("certification protected-header sizes exceed the Envoy profile")
    if sum(limits[name] for name in (
            "envoy_memory_mib_per_run", "broker_memory_mib_per_run",
            "supervisor_memory_mib_per_run")) > limits["memory_limit_mib_per_run"]:
        raise ValueError("certification component memory exceeds the per-run limit")
    for aggregate, components in {
        "cpu_limit_millicores_per_run": ("envoy_cpu_millicores_per_run", "broker_cpu_millicores_per_run", "supervisor_cpu_millicores_per_run"),
        "pid_limit_per_run": ("envoy_pid_limit_per_run", "broker_pid_limit_per_run", "supervisor_pid_limit_per_run"),
        "file_descriptor_limit_per_run": ("envoy_fd_limit_per_run", "broker_fd_limit_per_run", "supervisor_fd_limit_per_run"),
        "connection_limit_per_run": ("envoy_connection_limit_per_run", "broker_connection_limit_per_run", "supervisor_connection_limit_per_run"),
    }.items():
        if sum(limits[name] for name in components) > limits[aggregate]:
            raise ValueError(f"certification component limits exceed {aggregate}")
    if any(limits[name] > limits["startup_timeout_ms"] for name in (
            "envoy_startup_timeout_ms", "broker_startup_timeout_ms",
            "supervisor_startup_timeout_ms")):
        raise ValueError("certification component startup exceeds the Pod startup limit")
    if limits["rotation_propagation_ms"] > 5000 \
            or limits["post_revocation_residual_seconds"] > 300 \
            or limits["certification_validity_seconds"] > 7 * 24 * 60 * 60:
        raise ValueError("certification authority lifetime exceeds the selected profile")
    if not (limits["envoy_hard_kill_ms"] <= limits["workload_fence_ms"]
            <= limits["sidecar_shutdown_ms"] <= limits["pod_deletion_ms"]):
        raise ValueError("certification halt, fence, shutdown and deletion bounds conflict")
    rows = document["rows"]
    if not isinstance(rows, list) or any(
            not isinstance(row, dict) or set(row) != _MATRIX_ROW_FIELDS
            for row in rows):
        raise ValueError("certification matrix rows must use the closed v1 shape")
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)) or set(ids) != _MATRIX_INVARIANTS:
        raise ValueError("certification matrix must contain every invariant exactly once")
    for row in rows:
        if row["required"] is not True:
            raise ValueError(f"required certification row cannot be skipped: {row['id']}")
        for field in _MATRIX_ROW_FIELDS - {"required", "timeout_ms"}:
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError(f"certification row {row['id']} has empty {field}")
        if row["provider_support"] != "candidate-requires-live-proof":
            raise ValueError("design matrix rows require live candidate proof")
        if type(row["timeout_ms"]) is not int or row["timeout_ms"] <= 0:
            raise ValueError(f"certification row {row['id']} has invalid timeout")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return document, hashlib.sha256(canonical).hexdigest()


def _canonical_fields(document: dict, fields: frozenset[str]) -> bytes:
    return json.dumps(
        {name: document[name] for name in sorted(fields) if name in document},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _canonical(document: dict) -> bytes:
    return _canonical_fields(document, _SIGNED_FIELDS)


def _overlay_canonical(document: dict) -> bytes:
    return _canonical_fields(document, _OVERLAY_SIGNED_FIELDS)


def _public_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def sign(document: dict, private_key_pem: bytes) -> dict:
    """Return a signed copy; the caller's dictionary is never modified."""
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("certification signing key must be Ed25519")
    signed = dict(document)
    signed["signature_alg"] = "Ed25519"
    signed["signing_key_sha256"] = _public_fingerprint(key.public_key())
    canonical = (_overlay_canonical(signed)
                 if signed.get("schema") == OVERLAY_SCHEMA else _canonical(signed))
    signed["signature"] = base64.urlsafe_b64encode(
        key.sign(canonical)).rstrip(b"=").decode("ascii")
    return signed


def _load_public_key(path: str) -> Ed25519PublicKey:
    if not path:
        raise ValueError("ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE is required")
    with Path(path).open("rb") as handle:
        pem = handle.read((16 << 10) + 1)
    if len(pem) > 16 << 10:
        raise ValueError("certification public key exceeds 16 KiB")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("certification public key must be Ed25519")
    return key


def problems(path: str, *, provider: str, capability: str, issuer: str,
             token_endpoint: str, jwks_url: str, client_id: str,
             product_version: str = "", public_key_file: str = "",
             scope_config: str = "",
             now: float | None = None) -> list[str]:
    """Return every reason ``path`` cannot certify this exact deployment."""
    if not path:
        return [
            "ANDYUR_AS_CERTIFICATION_FILE is required in production: a vendor "
            "name selects request syntax but does not prove this tenant passed "
            "the live authorization-server conformance gate"
        ]
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        return [f"ANDYUR_AS_CERTIFICATION_FILE cannot be read: {type(exc).__name__}"]
    if len(raw) > MAX_BYTES:
        return ["ANDYUR_AS_CERTIFICATION_FILE exceeds the 64 KiB safety limit"]
    try:
        document = json.loads(raw, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ["ANDYUR_AS_CERTIFICATION_FILE is not valid UTF-8 JSON"]
    if not isinstance(document, dict):
        return ["ANDYUR_AS_CERTIFICATION_FILE must contain one JSON object"]

    found: list[str] = []
    unknown = sorted(set(document) - _FIELDS)
    if unknown:
        found.append(
            "certification contains unsupported fields (credentials and "
            f"extensions are forbidden): {', '.join(unknown)}")
    key = None
    if not public_key_file:
        found.append("ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE is required")
    try:
        if public_key_file:
            key = _load_public_key(public_key_file)
        if key is None:
            raise ValueError("public key is unavailable")
        if document.get("signature_alg") != "Ed25519":
            found.append("certification signature_alg must be Ed25519")
        elif document.get("signing_key_sha256") != _public_fingerprint(key):
            found.append("certification signing key does not match the pinned public key")
        else:
            encoded = document.get("signature")
            if not isinstance(encoded, str):
                raise ValueError("signature is missing")
            signature = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            key.verify(signature, _canonical(document))
    except (OSError, ValueError, TypeError, InvalidSignature) as exc:
        found.append(f"certification signature is invalid: {type(exc).__name__}")
    if document.get("schema") != SCHEMA:
        found.append(f"certification schema must be {SCHEMA}")
    if document.get("suite") != SUITE:
        found.append(f"certification suite must be {SUITE}")
    if document.get("result") != "pass":
        found.append("certification result is not pass")
    digest = document.get("discovery_sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        found.append("certification discovery_sha256 is not a lowercase SHA-256 digest")
    if document.get("scope_config_sha256") != hashlib.sha256(
            scope_config.encode("utf-8")).hexdigest():
        found.append("certification scope configuration does not match runtime configuration")
    expected = {
        "provider": provider,
        "capability": capability,
        "issuer": issuer,
        "token_endpoint": token_endpoint,
        "jwks_url": jwks_url,
        "client_id": client_id,
        "product_version": product_version,
    }
    for field, value in expected.items():
        if document.get(field) != value:
            found.append(f"certification {field} does not match runtime configuration")

    current = time.time() if now is None else now
    issued = document.get("issued_at")
    expires = document.get("expires_at")
    if type(issued) not in (int, float) or type(expires) not in (int, float) \
            or not math.isfinite(issued) or not math.isfinite(expires):
        found.append("certification issued_at and expires_at must be Unix timestamps")
    else:
        if issued > current + 300:
            found.append("certification issued_at is in the future")
        if expires <= current:
            found.append("certification has expired")
        if expires <= issued or expires - issued > MAX_VALIDITY_SECONDS:
            found.append("certification validity must be positive and at most 31 days")
    return found


def overlay_problems(path: str, *, provider: str, tenant: str, issuer: str,
                     token_endpoint: str, jwks_url: str, client_id: str,
                     client_auth_method: str, policy_config: str,
                     product_version: str, public_key_file: str,
                     certification_generation: int,
                     now: float | None = None) -> list[str]:
    """Return every reason a signed overlay cannot enable the delegated route."""
    if not path:
        return ["delegated authorization requires a signed provider/tenant overlay"]
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        return [f"delegated authorization overlay cannot be read: {type(exc).__name__}"]
    if len(raw) > MAX_BYTES:
        return ["delegated authorization overlay exceeds the 64 KiB safety limit"]
    try:
        document = json.loads(raw, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ["delegated authorization overlay is not valid UTF-8 JSON"]
    if not isinstance(document, dict):
        return ["delegated authorization overlay must contain one JSON object"]

    found: list[str] = []
    unknown = sorted(set(document) - _OVERLAY_FIELDS)
    missing = sorted(_OVERLAY_FIELDS - set(document))
    if unknown:
        found.append(f"overlay contains unsupported fields: {', '.join(unknown)}")
    if missing:
        found.append(f"overlay is missing required fields: {', '.join(missing)}")

    bindings = {
        "provider": provider, "tenant": tenant, "client_id": client_id,
        "client_auth_method": client_auth_method,
        "product_version": product_version,
    }
    for field, value in bindings.items():
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            found.append(f"overlay runtime {field} must be a non-empty bounded string")
    if not isinstance(client_auth_method, str) \
            or client_auth_method not in _OVERLAY_CLIENT_AUTH_METHODS:
        found.append("overlay runtime client_auth_method is not supported")
    for field, value in {
            "issuer": issuer, "token_endpoint": token_endpoint, "jwks_url": jwks_url,
    }.items():
        if not _secure_https_url(value):
            found.append(f"overlay runtime {field} must be an absolute secure HTTPS URL")
    if not isinstance(policy_config, str) or not policy_config or len(policy_config) > 1 << 20:
        found.append("overlay runtime policy_config must be non-empty and bounded")
    if type(certification_generation) is not int or certification_generation <= 0:
        found.append("overlay runtime certification_generation must be a positive integer")

    key = None
    try:
        key = _load_public_key(public_key_file)
        if document.get("signature_alg") != "Ed25519":
            found.append("overlay signature_alg must be Ed25519")
        elif document.get("signing_key_sha256") != _public_fingerprint(key):
            found.append("overlay signing key does not match the pinned public key")
        else:
            encoded = document.get("signature")
            if not isinstance(encoded, str):
                raise ValueError("signature is missing")
            signature = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            key.verify(signature, _overlay_canonical(document))
    except (OSError, ValueError, TypeError, InvalidSignature) as exc:
        found.append(f"overlay signature is invalid: {type(exc).__name__}")

    _, core_digest = certification_matrix()
    policy_digest = (hashlib.sha256(policy_config.encode("utf-8")).hexdigest()
                     if isinstance(policy_config, str) else None)
    expected = {
        "schema": OVERLAY_SCHEMA,
        "suite": OVERLAY_SUITE,
        "result": "pass",
        "core_schema": MATRIX_SCHEMA,
        "core_sha256": core_digest,
        "provider": provider,
        "tenant": tenant,
        "capability": MATRIX_PROFILE["capability"],
        "route_class": MATRIX_PROFILE["route_class"],
        "issuer": issuer,
        "token_endpoint": token_endpoint,
        "jwks_url": jwks_url,
        "client_id": client_id,
        "client_auth_method": client_auth_method,
        "policy_config_sha256": policy_digest,
        "product_version": product_version,
        "certification_generation": certification_generation,
    }
    for field, value in expected.items():
        if document.get(field) != value:
            found.append(f"overlay {field} does not match the required deployment")

    evidence = document.get("evidence_sha256")
    if not isinstance(evidence, dict) or set(evidence) != _MATRIX_INVARIANTS:
        found.append("overlay must contain evidence for every core invariant exactly once")
    elif any(not isinstance(value, str) or not _SHA256.fullmatch(value)
             for value in evidence.values()):
        found.append("overlay evidence values must be lowercase SHA-256 digests")

    current = time.time() if now is None else now
    issued = document.get("issued_at")
    expires = document.get("expires_at")
    if type(issued) is not int or type(expires) is not int:
        found.append("overlay issued_at and expires_at must be finite integer Unix timestamps")
    else:
        if issued > current + 300:
            found.append("overlay issued_at is in the future")
        if expires <= current:
            found.append("overlay has expired")
        matrix, _ = certification_matrix()
        maximum = matrix["limits"]["certification_validity_seconds"]
        if expires <= issued or expires - issued > maximum:
            found.append(
                "overlay validity must be positive and within the core certification limit")
    return found

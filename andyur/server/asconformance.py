"""Live tenant conformance gate for enterprise authorization servers.

This module is an operator-run verifier, not runtime request handling. It uses
the real provider adapter and response verifier, then writes the short-lived
artifact that production startup consumes. Secrets are read from files and are
never included in output.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from .. import boundedhttp, config
from . import ascertification, asclient, asproviders


class ConformanceError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConformanceError(f"{name} is required")
    return value


def _secret_file(name: str, *, required: bool = True) -> str:
    path = os.environ.get(name, "").strip()
    if not path:
        if required:
            raise ConformanceError(f"{name} is required; secrets are not accepted on argv")
        return ""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read((64 << 10) + 1)
    except OSError as exc:
        raise ConformanceError(f"{name} cannot be read: {type(exc).__name__}") from exc
    if len(raw) > 64 << 10:
        raise ConformanceError(f"{name} exceeds the 64 KiB safety limit")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ConformanceError(f"{name} is not UTF-8 text") from exc
    if not value:
        raise ConformanceError(f"{name} is empty")
    return value


def _discovery(url: str) -> tuple[dict, str]:
    if not url.startswith("https://"):
        raise ConformanceError("authorization-server discovery must use HTTPS")
    try:
        raw = boundedhttp.get_bytes(
            url, what="authorization-server discovery", max_bytes=256 << 10,
            budget=10.0)
        document = json.loads(raw)
    except Exception as exc:
        raise ConformanceError(
            f"authorization-server discovery failed: {type(exc).__name__}") from exc
    if not isinstance(document, dict):
        raise ConformanceError("authorization-server discovery is not a JSON object")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return document, hashlib.sha256(canonical).hexdigest()


def _verified_subject(token: str, audience: str) -> tuple[dict, str]:
    import jwt

    try:
        key = asclient._jwk_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256", "ES256", "RS384", "ES384"],
            audience=audience, issuer=config.AS_ISSUER,
            options={"require": ["sub", "exp", "iat", "aud"]})
        identity = asproviders.subject_identity(config.AS_PROVIDER, claims)
    except Exception as exc:
        raise ConformanceError(
            f"test subject token failed signed validation: {type(exc).__name__}: {exc}") from exc
    return claims, identity


def _write_artifact(path: str, artifact: dict) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".as-certification-",
                                     dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(artifact, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def certify(*, discovery_url: str, subject_token: str, subject_audience: str,
            actor_token: str, expected_actor: str = "",
            target_audience: str, scope: list[str],
            output: str, signing_private_key: bytes,
            now: int | None = None) -> dict:
    """Run the real exchange and emit evidence only after all checks pass."""
    # A failed recertification must not leave yesterday's still-readable pass
    # beside a red command. Production will then refuse until the gate passes.
    Path(output).unlink(missing_ok=True)
    provider_problems = asproviders.validate(
        config.AS_PROVIDER, config.AS_CAPABILITY)
    if provider_problems:
        raise ConformanceError("; ".join(provider_problems))
    if not config.AS_PRODUCT_VERSION:
        raise ConformanceError(
            "ANDYUR_AS_PRODUCT_VERSION is required (use 'managed' for rolling SaaS)")
    discovery, digest = _discovery(discovery_url)
    expected_metadata = {
        "issuer": config.AS_ISSUER,
        "token_endpoint": config.AS_TOKEN_ENDPOINT,
        "jwks_uri": config.AS_JWKS_URL,
    }
    for field, expected in expected_metadata.items():
        if discovery.get(field) != expected:
            raise ConformanceError(
                f"discovery {field} does not match configured {field}")

    _, expected_subject = _verified_subject(subject_token, subject_audience)
    if config.AS_PROVIDER == "pingfederate" and not actor_token:
        raise ConformanceError(
            "PingFederate certification requires a real actor-token file")
    # Core-only profiles do not transmit the actor. A non-empty sentinel keeps
    # Andyur's universal anti-impersonation precondition explicit and the exact
    # provider adapter proves it did not leak onto an unsupported wire profile.
    actor = actor_token or "core-profile-actor-not-transmitted"
    response = asclient.exchange(
        subject_token=subject_token, expected_subject=expected_subject,
        actor_token=actor, expected_actor=expected_actor,
        resource=target_audience,
        audience=target_audience, scope=scope)
    token = response["access_token"]

    # Mutation control: the same signed response must fail if the expected
    # principal changes. This distinguishes a continuity check from mere decode.
    try:
        asclient._verify_response(
            token, expected_subject=expected_subject + "#substituted",
            expected_actor=expected_actor, resource=target_audience,
            audience=target_audience, scope=scope,
            authorization_details=None)
    except asclient.ASError as exc:
        if "substituted" not in str(exc):
            raise ConformanceError(
                f"identity mutation failed for the wrong reason: {exc}") from exc
    else:
        raise ConformanceError("identity substitution mutation was accepted")

    issued = int(time.time()) if now is None else now
    artifact = {
        "schema": ascertification.SCHEMA,
        "suite": ascertification.SUITE,
        "result": "pass",
        "provider": config.AS_PROVIDER,
        "capability": config.AS_CAPABILITY,
        "issuer": config.AS_ISSUER,
        "token_endpoint": config.AS_TOKEN_ENDPOINT,
        "jwks_url": config.AS_JWKS_URL,
        "client_id": config.AS_CLIENT_ID,
        "product_version": config.AS_PRODUCT_VERSION,
        "scope_config_sha256": hashlib.sha256(
            config.AS_RESOURCE_SCOPE.encode("utf-8")).hexdigest(),
        "discovery_sha256": digest,
        "issued_at": issued,
        "expires_at": issued + 7 * 24 * 60 * 60,
    }
    try:
        artifact = ascertification.sign(artifact, signing_private_key)
    except (TypeError, ValueError) as exc:
        raise ConformanceError(f"certification signing failed: {exc}") from exc
    _write_artifact(output, artifact)
    problems = ascertification.problems(
        output, provider=config.AS_PROVIDER, capability=config.AS_CAPABILITY,
        issuer=config.AS_ISSUER, token_endpoint=config.AS_TOKEN_ENDPOINT,
        jwks_url=config.AS_JWKS_URL, client_id=config.AS_CLIENT_ID,
        product_version=config.AS_PRODUCT_VERSION,
        public_key_file=config.AS_CERTIFICATION_PUBLIC_KEY_FILE,
        scope_config=config.AS_RESOURCE_SCOPE, now=issued)
    if problems:
        Path(output).unlink(missing_ok=True)
        raise ConformanceError(f"emitted certification failed validation: {problems}")
    return artifact


def main() -> None:
    if config.AS_PROVIDER == "reference":
        raise SystemExit("reference is not a certifiable production provider")
    config.AS_CLIENT_SECRET = _secret_file("ANDYUR_AS_CLIENT_SECRET_FILE")
    subject = _secret_file("ANDYUR_AS_TEST_SUBJECT_TOKEN_FILE")
    actor = _secret_file("ANDYUR_AS_TEST_ACTOR_TOKEN_FILE", required=False)
    delegated = "delegated" in asproviders.CAPABILITY_REQUIREMENTS[
        asproviders.capability(config.AS_CAPABILITY)]
    expected_actor = (_required("ANDYUR_AS_TEST_EXPECTED_ACTOR")
                      if delegated else "")
    signing_key = _secret_file(
        "ANDYUR_AS_CERTIFICATION_PRIVATE_KEY_FILE").encode("utf-8")
    artifact = certify(
        discovery_url=_required("ANDYUR_AS_DISCOVERY_URL"),
        subject_token=subject,
        subject_audience=_required("ANDYUR_AS_TEST_SUBJECT_AUDIENCE"),
        actor_token=actor, expected_actor=expected_actor,
        target_audience=_required("ANDYUR_AS_TEST_TARGET_AUDIENCE"),
        scope=_required("ANDYUR_AS_TEST_SCOPE").split(),
        signing_private_key=signing_key,
        output=_required("ANDYUR_AS_CERTIFICATION_FILE"),
    )
    print(json.dumps({
        "result": artifact["result"], "provider": artifact["provider"],
        "capability": artifact["capability"],
        "expires_at": artifact["expires_at"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()

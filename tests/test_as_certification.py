import json
import hashlib
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from andyur.server import ascertification


BASE = {
    "schema": ascertification.SCHEMA,
    "suite": ascertification.SUITE,
    "result": "pass",
    "provider": "keycloak",
    "capability": "core",
    "issuer": "https://as.example",
    "token_endpoint": "https://as.example/token",
    "jwks_url": "https://as.example/jwks",
    "client_id": "andyur",
    "product_version": "26.2",
    "discovery_sha256": "a" * 64,
    "scope_config_sha256": "e3b0c44298fc1c149afbf4c8996fb924"
                           "27ae41e4649b934ca495991b7852b855",
}
PRIVATE_KEY = Ed25519PrivateKey.generate()


def validate(path, now=1_000_000):
    original = path
    path = Path(path)
    return ascertification.problems(
        str(original), provider="keycloak", capability="core",
        issuer="https://as.example", token_endpoint="https://as.example/token",
        jwks_url="https://as.example/jwks", client_id="andyur",
        product_version="26.2", public_key_file=str(path.parent / "certifier.pub"),
        now=now)


def write(tmp_path, **changes):
    document = {**BASE, "issued_at": 999_000, "expires_at": 1_001_000, **changes}
    document = ascertification.sign(document, PRIVATE_KEY.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    path = tmp_path / "certification.json"
    path.write_text(json.dumps(document))
    (tmp_path / "certifier.pub").write_bytes(PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return path


def write_overlay(tmp_path, **changes):
    _, core_digest = ascertification.certification_matrix()
    document = {
        "schema": ascertification.OVERLAY_SCHEMA,
        "suite": ascertification.OVERLAY_SUITE,
        "result": "pass",
        "core_schema": ascertification.MATRIX_SCHEMA,
        "core_sha256": core_digest,
        "provider": "standalone",
        "tenant": "demo",
        "capability": ascertification.MATRIX_PROFILE["capability"],
        "route_class": ascertification.MATRIX_PROFILE["route_class"],
        "issuer": "https://as.example",
        "token_endpoint": "https://as.example/token",
        "jwks_url": "https://as.example/jwks",
        "client_id": "andyur",
        "client_auth_method": "private_key_jwt",
        "policy_config_sha256": hashlib.sha256(b"policy-v1").hexdigest(),
        "product_version": "go-oidc-v0.25.0",
        "certification_generation": 7,
        "evidence_sha256": {
            invariant: hashlib.sha256(invariant.encode()).hexdigest()
            for invariant in ascertification._MATRIX_INVARIANTS
        },
        "issued_at": 999_000,
        "expires_at": 1_001_000,
        **changes,
    }
    document = ascertification.sign(document, PRIVATE_KEY.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps(document))
    (tmp_path / "overlay-certifier.pub").write_bytes(
        PRIVATE_KEY.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    return path


def validate_overlay(path, now=1_000_000):
    return ascertification.overlay_problems(
        str(path), provider="standalone", tenant="demo",
        issuer="https://as.example", token_endpoint="https://as.example/token",
        jwks_url="https://as.example/jwks", client_id="andyur",
        client_auth_method="private_key_jwt", policy_config="policy-v1",
        product_version="go-oidc-v0.25.0",
        certification_generation=7,
        public_key_file=str(Path(path).parent / "overlay-certifier.pub"), now=now)


def test_exact_unexpired_live_pass_is_accepted(tmp_path):
    assert validate(write(tmp_path)) == []


def test_missing_artifact_is_a_named_refusal():
    assert "required in production" in validate("")[0]


def test_expired_or_overlong_artifact_is_refused(tmp_path):
    assert any("expired" in p for p in validate(write(tmp_path, expires_at=999_999)))
    assert any("at most 31 days" in p for p in validate(
        write(tmp_path, issued_at=1, expires_at=ascertification.MAX_VALIDITY_SECONDS + 2)))


def test_artifact_is_bound_to_every_authority_endpoint_and_identity(tmp_path):
    for field in ("provider", "capability", "issuer", "token_endpoint",
                  "jwks_url", "client_id", "product_version"):
        assert any(field in p and "does not match" in p
                   for p in validate(write(tmp_path, **{field: "attacker"})))
    assert any("scope configuration" in p for p in ascertification.problems(
        str(write(tmp_path)), provider="keycloak", capability="core",
        issuer="https://as.example", token_endpoint="https://as.example/token",
        jwks_url="https://as.example/jwks", client_id="andyur",
        product_version="26.2", public_key_file=str(tmp_path / "certifier.pub"),
        scope_config="changed"))


def test_failed_wrong_suite_or_fake_digest_is_refused(tmp_path):
    assert any("result" in p for p in validate(write(tmp_path, result="fail")))
    assert any("suite" in p for p in validate(write(tmp_path, suite="old")))
    assert any("discovery_sha256" in p
               for p in validate(write(tmp_path, discovery_sha256="not-a-digest")))


def test_unsigned_tampered_and_wrong_key_artifacts_are_refused(tmp_path):
    path = write(tmp_path)
    document = json.loads(path.read_text())
    document["client_id"] = "attacker"
    path.write_text(json.dumps(document))
    assert any("signature is invalid" in p for p in validate(path))

    path = write(tmp_path)
    other = Ed25519PrivateKey.generate().public_key()
    (tmp_path / "certifier.pub").write_bytes(other.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    assert any("pinned public key" in p for p in validate(path))


def test_unknown_fields_are_refused_so_the_artifact_cannot_carry_secrets(tmp_path):
    problems = validate(write(tmp_path, client_secret="must-not-be-here"))
    assert any("unsupported fields" in p and "client_secret" in p for p in problems)


def test_matrix_is_closed_complete_and_has_a_stable_digest(tmp_path):
    document, digest = ascertification.certification_matrix()
    assert document["profile"] == ascertification.MATRIX_PROFILE
    assert len(document["rows"]) == 12
    assert all(row["required"] is True for row in document["rows"])
    assert len(digest) == 64 and int(digest, 16) >= 0
    reformatted = tmp_path / "reformatted.json"
    reformatted.write_text(json.dumps(document, indent=4, sort_keys=False))
    assert ascertification.certification_matrix(reformatted)[1] == digest


def test_matrix_standards_sources_pin_immutable_revisions():
    document, _ = ascertification.certification_matrix()
    assert document["official_sources"] == list(ascertification.MATRIX_SOURCES)
    assert all("/main/" not in source and "/master/" not in source
               for source in document["official_sources"])
    spiffe_source = document["official_sources"][-1]
    assert re.search(r"/blob/[0-9a-f]{40}/standards/JWT-SVID\.md$", spiffe_source)


@pytest.mark.parametrize("mutation,reason", [
    (("profile", "provider_binding", "pingfederate"), "closed design contract"),
    (("profile", "capability", "core"), "closed design contract"),
    (("profile", "route_class", "other"), "closed design contract"),
    (("limits", "credential_cache_entries", 1), "cacheless"),
    (("limits", "as_timeout_ms", True), "incomplete or invalid"),
    (("limits", "ext_authz_timeout_ms", 900), "qualified ADR-007"),
    (("rows", 0, False), "cannot be skipped"),
    (("rows", 0, True), "invalid timeout"),
])
def test_matrix_exact_mutations_are_refused_at_named_enforcement(
        tmp_path, mutation, reason):
    document, _ = ascertification.certification_matrix()
    group, key, value = mutation
    if group == "rows":
        field = "required" if value is False else "timeout_ms"
        document[group][key][field] = value
    else:
        document[group][key] = value
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match=reason):
        ascertification.certification_matrix(path)


def test_matrix_missing_row_and_untrusted_source_are_refused(tmp_path):
    document, _ = ascertification.certification_matrix()
    document["rows"].pop()
    path = tmp_path / "missing.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="every invariant exactly once"):
        ascertification.certification_matrix(path)
    document, _ = ascertification.certification_matrix()
    document["official_sources"][0] = "https://vendor.example/delegation"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="standards sources"):
        ascertification.certification_matrix(path)


def test_core_matrix_contains_no_vendor_identity():
    document, _ = ascertification.certification_matrix()
    encoded = json.dumps(document).lower()
    for vendor in ("pingfederate", "pingidentity", "okta", "auth0", "entra"):
        assert vendor not in encoded


def test_matrix_loading_is_bounded_and_normalizes_parse_errors(tmp_path):
    path = tmp_path / "matrix.json"
    path.write_bytes(b"x" * (ascertification.MATRIX_MAX_BYTES + 1))
    with pytest.raises(ValueError, match="64 KiB"):
        ascertification.certification_matrix(path)
    path.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="UTF-8 JSON"):
        ascertification.certification_matrix(path)
    with pytest.raises(ValueError, match="cannot be read"):
        ascertification.certification_matrix(tmp_path / "missing.json")


def test_matrix_is_present_and_loadable_in_the_built_wheel(tmp_path):
    subprocess.run([
        sys.executable, "-m", "pip", "wheel", ".", "--no-deps",
        "--wheel-dir", str(tmp_path),
    ], check=True, capture_output=True, text=True, timeout=60)
    [wheel] = tmp_path.glob("andyur-*.whl")
    member = "andyur/server/as-certification-matrix.json"
    with zipfile.ZipFile(wheel) as archive:
        assert member in archive.namelist()
        packaged = json.loads(archive.read(member))
        assert not any("sender-binding-spike" in name for name in archive.namelist())
        assert all(b"sender-binding-spike" not in archive.read(name)
                   for name in archive.namelist() if name.endswith((".py", ".json")))
    source, _ = ascertification.certification_matrix()
    assert packaged == source


def test_every_positive_matrix_limit_turns_red_at_zero(tmp_path):
    document, _ = ascertification.certification_matrix()
    zero_allowed = {"broker_queue", "credential_cache_entries"}
    for name in document["limits"]:
        if name in zero_allowed:
            continue
        mutation = json.loads(json.dumps(document))
        mutation["limits"][name] = 0
        assert mutation != document, f"mutation did not apply for {name}"
        path = tmp_path / f"zero-{name}.json"
        path.write_text(json.dumps(mutation))
        with pytest.raises(ValueError):
            ascertification.certification_matrix(path)


@pytest.mark.parametrize("name,value,reason", [
    ("resource_replay_cache_ttl_seconds", 5, "replay state"),
    ("post_halt_saved_proof_residual_seconds", 6, "proof freshness"),
    ("active_worker_release_ms", 699, "cancellation"),
    ("sidecar_shutdown_ms", 9000, "halt, fence, shutdown"),
    ("memory_limit_mib_per_run", 200, "component memory"),
    ("resource_replay_cache_entries_per_run", 351, "replay capacity"),
    ("resource_replay_cache_entries_aggregate", 4095, "aggregate replay capacity"),
    ("max_injected_headers_bytes", 90000, "protected-header sizes"),
    ("post_revocation_residual_seconds", 301, "authority lifetime"),
    ("rotation_propagation_ms", 5001, "authority lifetime"),
    ("certification_validity_seconds", 604801, "authority lifetime"),
])
def test_matrix_relational_mutations_turn_red_at_the_named_check(
        tmp_path, name, value, reason):
    document, _ = ascertification.certification_matrix()
    document["limits"][name] = value
    path = tmp_path / f"relation-{name}.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match=reason):
        ascertification.certification_matrix(path)


def test_matrix_provider_support_is_a_closed_design_state(tmp_path):
    document, _ = ascertification.certification_matrix()
    document["rows"][0]["provider_support"] = "certified"
    path = tmp_path / "provider-support.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="require live candidate proof"):
        ascertification.certification_matrix(path)


def test_exact_signed_delegated_overlay_is_accepted(tmp_path):
    assert validate_overlay(write_overlay(tmp_path)) == []


@pytest.mark.parametrize("field,value", [
    ("core_schema", "andyur-as-certification/v2"),
    ("core_sha256", "0" * 64),
    ("provider", "other"),
    ("tenant", "other"),
    ("capability", "core"),
    ("route_class", "unbound"),
    ("client_auth_method", "client_secret_basic"),
    ("policy_config_sha256", "0" * 64),
    ("product_version", "other"),
    ("certification_generation", 6),
])
def test_overlay_is_bound_to_core_route_and_exact_deployment(tmp_path, field, value):
    assert any(field in problem and "does not match" in problem
               for problem in validate_overlay(write_overlay(tmp_path, **{field: value})))


def test_overlay_refuses_legacy_bare_unknown_and_incomplete_documents(tmp_path):
    write_overlay(tmp_path)
    legacy = write(tmp_path)
    assert "overlay schema does not match the required deployment" in validate_overlay(legacy)

    core, _ = ascertification.certification_matrix()
    bare = tmp_path / "bare-core.json"
    bare.write_text(json.dumps(core))
    assert "overlay schema does not match the required deployment" in validate_overlay(bare)

    path = write_overlay(tmp_path, extension="not-allowed")
    assert any("unsupported fields" in problem for problem in validate_overlay(path))

    evidence = write_overlay(tmp_path)
    document = json.loads(evidence.read_text())
    document["evidence_sha256"].pop("secret-isolation")
    evidence.write_text(json.dumps(ascertification.sign(
        document, PRIVATE_KEY.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))))
    assert any("every core invariant" in problem
               for problem in validate_overlay(evidence))


def test_overlay_signature_covers_evidence_and_validity_is_core_bounded(tmp_path):
    path = write_overlay(tmp_path)
    document = json.loads(path.read_text())
    document["evidence_sha256"]["actor-signature"] = "0" * 64
    path.write_text(json.dumps(document))
    assert any("signature is invalid" in problem for problem in validate_overlay(path))

    assert any("core certification limit" in problem for problem in validate_overlay(
        write_overlay(tmp_path, issued_at=1, expires_at=604_802)))
    assert any("expired" in problem for problem in validate_overlay(
        write_overlay(tmp_path, expires_at=999_999)))


@pytest.mark.parametrize("field,value", [
    ("issued_at", float("nan")), ("issued_at", float("inf")),
    ("issued_at", float("-inf")), ("expires_at", float("nan")),
    ("expires_at", float("inf")), ("expires_at", float("-inf")),
])
def test_signer_and_loaders_refuse_non_finite_timestamps(tmp_path, field, value):
    with pytest.raises(ValueError, match="Out of range float values"):
        write_overlay(tmp_path, **{field: value})
    with pytest.raises(ValueError, match="Out of range float values"):
        write(tmp_path, **{field: value})

    path = write_overlay(tmp_path)
    text = path.read_text().replace('"expires_at": 1001000', '"expires_at": NaN')
    path.write_text(text)
    assert validate_overlay(path) == [
        "delegated authorization overlay is not valid UTF-8 JSON"]

    legacy = write(tmp_path)
    text = legacy.read_text().replace('"expires_at": 1001000', '"expires_at": NaN')
    legacy.write_text(text)
    assert validate(legacy) == [
        "ANDYUR_AS_CERTIFICATION_FILE is not valid UTF-8 JSON"]


@pytest.mark.parametrize("field,value,reason", [
    ("provider", "", "non-empty bounded string"),
    ("tenant", "", "non-empty bounded string"),
    ("client_id", "", "non-empty bounded string"),
    ("client_auth_method", "unknown", "not supported"),
    ("client_auth_method", [], "not supported"),
    ("client_auth_method", {}, "not supported"),
    ("product_version", "", "non-empty bounded string"),
    ("issuer", "http://as.example", "secure HTTPS URL"),
    ("issuer", "https://[::1/token", "secure HTTPS URL"),
    ("issuer", "https://as.example:bad", "secure HTTPS URL"),
    ("issuer", "https://as.example:70000", "secure HTTPS URL"),
    ("issuer", None, "secure HTTPS URL"),
    ("issuer", b"https://as.example", "secure HTTPS URL"),
    ("token_endpoint", "https://user@as.example/token", "secure HTTPS URL"),
    ("jwks_url", "https://as.example/jwks#fragment", "secure HTTPS URL"),
    ("policy_config", "", "non-empty and bounded"),
    ("policy_config", None, "non-empty and bounded"),
    ("policy_config", b"policy-v1", "non-empty and bounded"),
    ("certification_generation", 0, "positive integer"),
])
def test_overlay_runtime_tuple_must_be_intrinsically_valid(
        tmp_path, field, value, reason):
    path = write_overlay(tmp_path)
    kwargs = {
        "provider": "standalone", "tenant": "demo",
        "issuer": "https://as.example", "token_endpoint": "https://as.example/token",
        "jwks_url": "https://as.example/jwks", "client_id": "andyur",
        "client_auth_method": "private_key_jwt", "policy_config": "policy-v1",
        "product_version": "go-oidc-v0.25.0", "certification_generation": 7,
        "public_key_file": str(tmp_path / "overlay-certifier.pub"), "now": 1_000_000,
    }
    kwargs[field] = value
    assert any(reason in problem
               for problem in ascertification.overlay_problems(str(path), **kwargs))


def test_malformed_oversized_and_future_artifacts_are_controlled_refusals(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{")
    assert "valid UTF-8 JSON" in validate(path)[0]
    path.write_bytes(b"x" * (ascertification.MAX_BYTES + 1))
    assert "64 KiB" in validate(path)[0]
    assert any("future" in p for p in validate(write(tmp_path, issued_at=1_001_000)))

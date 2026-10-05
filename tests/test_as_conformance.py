import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa

from andyur import config
from andyur.server import ascertification, asclient, asconformance


CERT_KEY = Ed25519PrivateKey.generate()
CERT_PRIVATE = CERT_KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())


@pytest.fixture
def tenant(monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class JWKS:
        def get_signing_key_from_jwt(self, token):
            return type("SigningKey", (), {"key": key.public_key()})()

    issuer = "https://tenant.example/oauth2/default"
    token_endpoint = issuer + "/v1/token"
    jwks_url = issuer + "/v1/keys"
    monkeypatch.setattr(config, "AS_PROVIDER", "okta")
    monkeypatch.setattr(config, "AS_CAPABILITY", "core")
    monkeypatch.setattr(config, "AS_ISSUER", issuer)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", token_endpoint)
    monkeypatch.setattr(config, "AS_JWKS_URL", jwks_url)
    monkeypatch.setattr(config, "AS_CLIENT_ID", "andyur")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", "")
    monkeypatch.setattr(config, "AS_PRODUCT_VERSION", "managed")
    public_key = tmp_path / "certifier.pub"
    public_key.write_bytes(CERT_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", str(public_key))
    monkeypatch.setattr(config, "EXCHANGE_TTL", 300)
    monkeypatch.setattr(asclient, "_jwks", JWKS())
    discovery = {
        "issuer": issuer, "token_endpoint": token_endpoint,
        "jwks_uri": jwks_url,
    }
    monkeypatch.setattr(
        asconformance.boundedhttp, "get_bytes",
        lambda *a, **k: json.dumps(discovery).encode())

    now = int(time.time())
    subject = jwt.encode({
        "iss": issuer, "sub": "alice", "aud": "api-one",
        "iat": now, "exp": now + 300,
    }, key, algorithm="RS256")
    downstream = jwt.encode({
        "iss": issuer, "sub": "alice", "aud": "api-two",
        "scope": "files:read", "iat": now, "exp": now + 300,
    }, key, algorithm="RS256")
    monkeypatch.setattr(
        asclient.boundedhttp, "post_form",
        lambda *a, **k: (200, {
            "access_token": downstream, "token_type": "Bearer",
            "issued_token_type": asclient.TOKEN_TYPE_ACCESS,
            "expires_in": 300,
        }))
    return subject, discovery


def test_live_certifier_uses_real_signed_semantics_and_emits_runtime_artifact(
        tenant, tmp_path):
    subject, _ = tenant
    output = tmp_path / "certification.json"
    artifact = asconformance.certify(
        discovery_url="https://tenant.example/.well-known/openid-configuration",
        subject_token=subject, subject_audience="api-one", actor_token="",
        target_audience="api-two", scope=["files:read"],
        signing_private_key=CERT_PRIVATE,
        output=str(output))
    assert artifact["provider"] == "okta" and artifact["result"] == "pass"
    assert output.exists()
    assert ascertification.problems(
        str(output), provider="okta", capability="core",
        issuer=config.AS_ISSUER, token_endpoint=config.AS_TOKEN_ENDPOINT,
        jwks_url=config.AS_JWKS_URL, client_id=config.AS_CLIENT_ID,
        product_version="managed",
        public_key_file=config.AS_CERTIFICATION_PUBLIC_KEY_FILE) == []


def test_certifier_refuses_cleartext_discovery_before_any_exchange(tenant, tmp_path):
    subject, _ = tenant
    output = tmp_path / "never.json"
    output.write_text('{"result":"stale-pass"}')
    with pytest.raises(asconformance.ConformanceError, match="HTTPS"):
        asconformance.certify(
            discovery_url="http://tenant.example/discovery",
            subject_token=subject, subject_audience="api-one", actor_token="",
            target_audience="api-two", scope=["files:read"],
            signing_private_key=CERT_PRIVATE,
            output=str(output))
    assert not output.exists(), "a failed rerun must invalidate stale evidence"


def test_certifier_refuses_metadata_mismatch(tenant, tmp_path, monkeypatch):
    subject, discovery = tenant
    monkeypatch.setattr(
        asconformance.boundedhttp, "get_bytes",
        lambda *a, **k: json.dumps({**discovery, "jwks_uri": "https://evil/keys"}).encode())
    with pytest.raises(asconformance.ConformanceError, match="jwks_uri"):
        asconformance.certify(
            discovery_url="https://tenant.example/discovery",
            subject_token=subject, subject_audience="api-one", actor_token="",
            target_audience="api-two", scope=["files:read"],
            signing_private_key=CERT_PRIVATE,
            output=str(tmp_path / "never.json"))


def test_ping_certification_requires_a_real_actor_token(tenant, tmp_path,
                                                         monkeypatch):
    subject, _ = tenant
    monkeypatch.setattr(config, "AS_PROVIDER", "pingfederate")
    with pytest.raises(asconformance.ConformanceError, match="actor-token"):
        asconformance.certify(
            discovery_url="https://tenant.example/discovery",
            subject_token=subject, subject_audience="api-one", actor_token="",
            target_audience="api-two", scope=["files:read"],
            signing_private_key=CERT_PRIVATE,
            output=str(tmp_path / "never.json"))


def test_certifier_refuses_an_unversioned_product(tenant, tmp_path, monkeypatch):
    subject, _ = tenant
    monkeypatch.setattr(config, "AS_PRODUCT_VERSION", "")
    with pytest.raises(asconformance.ConformanceError, match="PRODUCT_VERSION"):
        asconformance.certify(
            discovery_url="https://tenant.example/discovery",
            subject_token=subject, subject_audience="api-one", actor_token="",
            target_audience="api-two", scope=["files:read"],
            signing_private_key=CERT_PRIVATE,
            output=str(tmp_path / "never.json"))


def test_wrong_pinned_key_removes_the_newly_emitted_artifact(
        tenant, tmp_path, monkeypatch):
    subject, _ = tenant
    wrong_key = Ed25519PrivateKey.generate().public_key()
    wrong_public = tmp_path / "wrong.pub"
    wrong_public.write_bytes(wrong_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", str(wrong_public))
    output = tmp_path / "must-not-survive.json"
    with pytest.raises(asconformance.ConformanceError, match="failed validation"):
        asconformance.certify(
            discovery_url="https://tenant.example/discovery",
            subject_token=subject, subject_audience="api-one", actor_token="",
            target_audience="api-two", scope=["files:read"],
            signing_private_key=CERT_PRIVATE, output=str(output))
    assert not output.exists()


def test_secret_file_read_is_bounded(tmp_path, monkeypatch):
    path = tmp_path / "oversized-secret"
    path.write_bytes(b"x" * ((64 << 10) + 1))
    monkeypatch.setenv("TEST_SECRET_FILE", str(path))
    with pytest.raises(asconformance.ConformanceError, match="64 KiB"):
        asconformance._secret_file("TEST_SECRET_FILE")

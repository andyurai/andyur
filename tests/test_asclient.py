"""The outbound RFC 8693 leg.

Every test here asserts a PROPERTY of the request Andyur builds or of how it
handles a refusal, not that a helper was called. The distinction matters: an
earlier TOCTOU test in this repo counted calls to one function and sailed past a
check that issued its own SQL.
"""

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa

from andyur import config
from andyur.server import ascertification, asclient


@pytest.fixture
def as_configured(monkeypatch):
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "andyur-gateway")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "s3cret")
    monkeypatch.setattr(config, "AS_PROVIDER", "reference")
    monkeypatch.setattr(config, "AS_CAPABILITY", "core")
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", "")


@pytest.fixture
def captured(monkeypatch):
    """Capture the form Andyur posts, and control what the AS answers."""
    box = {}

    def fake_post_form(url, form, *, what, budget, max_bytes, headers=None):
        box["url"] = url
        box["form"] = form
        box["headers"] = headers or {}
        box["budget"] = budget
        return box.get("status", 200), box.get("body", {
            "access_token": "issued.token.here", "token_type": "Bearer",
            "issued_token_type": asclient.TOKEN_TYPE_ACCESS})

    monkeypatch.setattr(asclient.boundedhttp, "post_form", fake_post_form)
    # Transport tests below isolate request/response framing. Signed-token
    # semantics have their own mutation-sensitive tests at the end of this file.
    monkeypatch.setattr(asclient, "_verify_response", lambda *a, **k: {})
    return box


def _exchange(**over):
    kw = dict(subject_token="alice.tok", expected_subject="alice",
              actor_token="run.svid",
              resource="https://telemetry.internal/teams/checkout",
              audience=None, scope=["telemetry:read"])
    kw.update(over)
    return asclient.exchange(**kw)


# --------------------------------------------------------------------------
# What Andyur sends
# --------------------------------------------------------------------------

def test_sends_rfc8693_grant_with_subject_and_actor(as_configured, captured):
    _exchange()
    f = captured["form"]
    assert f["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert f["subject_token"] == "alice.tok"
    assert f["actor_token"] == "run.svid"
    # The actor is what makes the result DELEGATION rather than impersonation.
    assert f["actor_token_type"] == asclient.TOKEN_TYPE_JWT


def test_proxy_exchange_revalidates_production_certification_before_transport(
        as_configured, captured, monkeypatch):
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(
        config, "as_problems", lambda: ["certification signature is invalid"])
    with pytest.raises(asclient.ASError, match="not certified.*signature"):
        _exchange()
    assert "url" not in captured, "unsafe configuration must fail before network I/O"


def test_proxy_exchange_allows_exact_certified_production_configuration(
        as_configured, captured, monkeypatch):
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(config, "as_problems", lambda: [])
    _exchange()
    assert captured["url"] == "https://as.example/token"


def test_entra_exchange_maps_action_to_exact_wire_scope(
        as_configured, captured, monkeypatch):
    monkeypatch.setattr(config, "AS_PROVIDER", "entra")
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", json.dumps({
        "schema": "andyur-entra-scope-map/v1",
        "actions": {"telemetry:read": {
            "request": "api://tool/Telemetry.Read", "claim": "Telemetry.Read"}},
    }))
    _exchange()
    assert captured["form"]["scope"] == "api://tool/Telemetry.Read"


def test_scope_is_space_delimited_not_a_json_array(as_configured, captured):
    """RFC 8693 sec 2.1 says `scope` is a space-delimited string.

    Andyur's own mint emitted a JSON array, which a stock resource server reads
    as NO authorities -- the exact inversion of what was meant.
    """
    _exchange(scope=["telemetry:read", "tickets:write"])
    assert captured["form"]["scope"] == "telemetry:read tickets:write"
    assert not captured["form"]["scope"].startswith("[")


def test_optional_parameters_are_omitted_not_sent_empty(as_configured, captured):
    """A deployment may legitimately have no resource constraint.

    Sending `resource=` or `authorization_details=` empty makes an AS reject a
    request that was simply unconstrained.
    """
    _exchange(resource=None, audience=None, scope=None,
              authorization_details=None)
    f = captured["form"]
    for absent in ("resource", "audience", "scope", "authorization_details"):
        assert absent not in f, f"{absent} should be omitted, not sent empty"


def test_pin_is_sent_as_rfc9396_authorization_details(as_configured, captured):
    pin = [{"type": "andyur_pin", "identifier": "checkout", "actions": ["read"]}]
    _exchange(authorization_details=pin)
    sent = json.loads(captured["form"]["authorization_details"])
    assert sent == pin


def test_dpop_proof_travels_as_a_header(as_configured, captured):
    _exchange(dpop_proof="proof.jwt.here")
    assert captured["headers"].get("DPoP") == "proof.jwt.here"
    # ...and the proof must never be a form field, where it would be logged by
    # an AS access log alongside the credentials.
    assert "DPoP" not in captured["form"] and "dpop" not in captured["form"]


def test_no_dpop_means_no_header(as_configured, captured):
    """Positive control for the test above: absence must be distinguishable."""
    _exchange()
    assert "DPoP" not in captured["headers"]


def test_auth0_uses_json_transport(as_configured, monkeypatch):
    monkeypatch.setattr(config, "AS_PROVIDER", "auth0")
    seen = {}
    monkeypatch.setattr(
        asclient.boundedhttp, "post_form",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("form used for Auth0")))

    def post_json(url, payload, **kwargs):
        seen.update(payload)
        return 200, {"access_token": "token", "token_type": "Bearer",
                     "issued_token_type": asclient.TOKEN_TYPE_ACCESS}

    monkeypatch.setattr(asclient.boundedhttp, "post_json_response", post_json)
    monkeypatch.setattr(asclient, "_verify_response", lambda *a, **k: {})
    _exchange()
    assert seen["requested_token_type"] == asclient.TOKEN_TYPE_ACCESS


def test_the_call_is_bounded(as_configured, captured):
    """The exchange is synchronous and on the authorization path, so a stalled
    AS holds a threadpool thread. An unbounded call here is a denial of service
    with extra steps."""
    _exchange()
    assert captured["budget"] == asclient.BUDGET
    assert asclient.BUDGET <= 10


# --------------------------------------------------------------------------
# What Andyur refuses
# --------------------------------------------------------------------------

def test_refuses_without_an_actor_token(as_configured, captured):
    with pytest.raises(asclient.ASError) as e:
        _exchange(actor_token="")
    assert "impersonation" in str(e.value)
    assert "form" not in captured, "must refuse BEFORE calling the AS"


def test_refuses_without_a_subject_token(as_configured, captured):
    with pytest.raises(asclient.ASError):
        _exchange(subject_token="")
    assert "form" not in captured


def test_refuses_without_a_server_authenticated_subject(as_configured, captured):
    with pytest.raises(asclient.ASError, match="server-authenticated subject"):
        _exchange(expected_subject="")
    assert "form" not in captured


def test_refuses_when_no_as_is_configured(monkeypatch, captured):
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "")
    with pytest.raises(asclient.ASNotConfigured):
        _exchange()


def test_as_refusal_carries_the_reason(as_configured, captured):
    """An error naming the wrong cause costs more than one naming none."""
    captured["status"] = 400
    captured["body"] = {"error": "invalid_target",
                        "error_description": "unregistered resource"}
    with pytest.raises(asclient.ASError) as e:
        _exchange()
    assert e.value.code == "invalid_target"
    assert e.value.status == 400
    assert "invalid_target" in str(e.value)


def test_unreachable_as_fails_closed_and_names_the_component(as_configured,
                                                             monkeypatch):
    def boom(*a, **k):
        raise TimeoutError("nope")
    monkeypatch.setattr(asclient.boundedhttp, "post_form", boom)
    with pytest.raises(asclient.ASError) as e:
        _exchange()
    # The operator needs to know it was THEIR AS that did not answer.
    assert "authorization server" in str(e.value)


def test_200_without_a_token_is_a_refusal_not_a_success(as_configured, captured):
    """A 200 carrying no access_token must not be read as a credential."""
    captured["body"] = {"token_type": "Bearer"}
    with pytest.raises(asclient.ASError):
        _exchange()


def test_unknown_token_type_is_refused(as_configured, captured):
    captured["body"] = {"access_token": "issued.token.here", "token_type": "Magic"}
    with pytest.raises(asclient.ASError, match="token_type"):
        _exchange()


def test_missing_or_changed_issued_token_type_is_refused(as_configured, captured):
    captured["body"] = {"access_token": "issued.token.here", "token_type": "Bearer"}
    with pytest.raises(asclient.ASError, match="issued_token_type"):
        _exchange()


def test_non_json_error_body_does_not_raise_a_traceback(as_configured, captured):
    """An AS behind a proxy can return an HTML error page."""
    captured["status"] = 502
    captured["body"] = None
    with pytest.raises(asclient.ASError) as e:
        _exchange()
    assert e.value.status == 502


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def test_partial_as_config_is_a_boot_problem(monkeypatch):
    """A half-configured AS otherwise fails at the first tool call, in a run."""
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "x")
    assert any("ANDYUR_AS_ISSUER" in p for p in config.as_problems())


def test_stray_as_config_without_an_endpoint_is_a_problem(monkeypatch):
    """Naming an issuer with no endpoint means Andyur keeps signing its own
    access tokens while the configuration says it should not."""
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "")
    monkeypatch.setattr(config, "AS_JWKS_URL", "")
    assert config.as_problems()


def test_no_as_config_at_all_is_the_supported_default(monkeypatch):
    """Positive control: the getting-started path must not require an AS."""
    for name in ("AS_TOKEN_ENDPOINT", "AS_ISSUER", "AS_CLIENT_ID",
                 "AS_CLIENT_SECRET", "AS_JWKS_URL"):
        monkeypatch.setattr(config, name, "")
    assert config.as_problems() == []


def test_production_refuses_an_insecure_jwks_transport(monkeypatch):
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(config, "AS_PROVIDER_SET", True)
    monkeypatch.setattr(config, "AS_CAPABILITY_SET", True)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "andyur")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "AS_JWKS_URL", "http://as.example/jwks")
    assert any("signing key" in problem for problem in config.as_problems())


# --------------------------------------------------------------------------
# Signed response semantics
# --------------------------------------------------------------------------

@pytest.fixture
def signed_as(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Client:
        def get_signing_key_from_jwt(self, token):
            return type("SigningKey", (), {"key": private.public_key()})()

    monkeypatch.setattr(asclient, "_jwks", Client())
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(config, "AS_CAPABILITY", "contextual")
    monkeypatch.setattr(config, "AS_PROVIDER", "reference")
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "andyur")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", "")

    def sign(**changes):
        now = int(time.time())
        claims = {
            "iss": "https://as.example", "sub": "alice", "aud": "tool:bank",
            "scope": ["files:read"], "act": {"sub": "spiffe://run/1"},
            "authorization_details": [{"type": "andyur_pin", "identifier": "447"}],
            "iat": now, "exp": now + 300,
        }
        claims.update(changes)
        for name, value in changes.items():
            if value is None:
                claims.pop(name, None)
        return jwt.encode(claims, private, algorithm="RS256")
    return sign


def _semantic_verify(token):
    return asclient._verify_response(
        token, expected_subject="alice", expected_actor="spiffe://run/1",
        audience="tool:bank", resource=None, scope=["files:read"],
        authorization_details=[{"type": "andyur_pin", "identifier": "447"}])


def test_contextual_response_accepts_the_complete_signed_envelope(signed_as):
    assert _semantic_verify(signed_as())["sub"] == "alice"


def test_entra_response_uses_verified_tenant_object_continuity(signed_as,
                                                                monkeypatch):
    monkeypatch.setattr(config, "AS_PROVIDER", "entra")
    monkeypatch.setattr(config, "AS_CAPABILITY", "core")
    token = signed_as(sub="different-pairwise-sub", tid="tenant", oid="object",
                      scp="Files.Read", scope=None)
    claims = asclient._verify_response(
        token, expected_subject='["tenant","object"]', expected_actor="",
        audience="tool:bank", resource=None, scope=["files:read"],
        authorization_details=None,
        expected_provider_scopes=frozenset({"Files.Read"}))
    assert claims["oid"] == "object"
    with pytest.raises(asclient.ASError, match="substituted"):
        asclient._verify_response(
            signed_as(sub="another", tid="tenant", oid="attacker"),
            expected_subject='["tenant","object"]', expected_actor="",
            audience="tool:bank", resource=None, scope=["files:read"],
            authorization_details=None,
            expected_provider_scopes=frozenset({"Files.Read"}))
    with pytest.raises(asclient.ASError, match="widened"):
        asclient._verify_response(
            signed_as(sub="pairwise", tid="tenant", oid="object", scope=None,
                      scp="Files.Read Files.Write"),
            expected_subject='["tenant","object"]', expected_actor="",
            audience="tool:bank", resource=None, scope=["files:read"],
            authorization_details=None,
            expected_provider_scopes=frozenset({"Files.Read"}))


def test_exchange_cannot_release_a_token_without_semantic_verification(
        signed_as, monkeypatch):
    token = signed_as(scope=["files:read", "files:write"])
    monkeypatch.setattr(
        asclient.boundedhttp, "post_form",
        lambda *a, **k: (200, {"access_token": token, "token_type": "bearer",
                               "issued_token_type": asclient.TOKEN_TYPE_ACCESS,
                               "expires_in": 9999}))
    subject = jwt.encode({"sub": "alice"}, "x" * 32, algorithm="HS256")
    actor = jwt.encode({"sub": "spiffe://run/1"}, "x" * 32, algorithm="HS256")
    with pytest.raises(asclient.ASError, match="widened"):
        asclient.exchange(
            subject_token=subject, expected_subject="alice", actor_token=actor,
            expected_actor="spiffe://run/1",
            audience="tool:bank", scope=["files:read"],
            authorization_details=[{"type": "andyur_pin", "identifier": "447"}])


def test_missing_trusted_subject_cannot_bypass_subject_continuity(signed_as):
    with pytest.raises(asclient.ASError, match="server-authenticated expected subject"):
        asclient._verify_response(
            signed_as(), expected_subject="", expected_actor="spiffe://run/1",
            audience="tool:bank", resource=None, scope=["files:read"],
            authorization_details=[{"type": "andyur_pin", "identifier": "447"}])


def test_malformed_actor_claim_fails_as_a_controlled_refusal(signed_as):
    with pytest.raises(asclient.ASError, match="malformed actor"):
        _semantic_verify(signed_as(act="not-an-object"))


def test_actor_continuity_uses_sealed_state_not_the_actor_credential(signed_as):
    """A substituted actor and matching AS output cannot define expectation."""
    with pytest.raises(asclient.ASError, match="run actor"):
        asclient._verify_response(
            signed_as(act={"sub": "spiffe://run/attacker"}),
            expected_subject="alice", expected_actor="spiffe://run/1",
            audience="tool:bank", resource=None, scope=["files:read"],
            authorization_details=[{"type": "andyur_pin", "identifier": "447"}])


def test_original_token_lifetime_not_just_remaining_life_is_bounded(signed_as):
    now = int(time.time())
    with pytest.raises(asclient.ASError, match="lifetime exceeds"):
        _semantic_verify(signed_as(iat=now - 10_000, exp=now + 100))
    with pytest.raises(asclient.ASError, match="invalid lifetime"):
        _semantic_verify(signed_as(iat=True, exp=now + 100))


def test_distinct_audience_and_resource_are_refused_before_transport(
        as_configured, captured):
    with pytest.raises(asclient.ASError, match="one identical target"):
        _exchange(audience="tool:a", resource="tool:b")
    assert "url" not in captured


@pytest.mark.parametrize("mutation,reason", [
    ({"aud": "tool:other"}, "Audience"),
    ({"scope": ["files:read", "files:write"]}, "widened"),
    ({"sub": "mallory"}, "subject"),
    ({"act": {"sub": "spiffe://run/other"}}, "actor"),
    ({"authorization_details": []}, "context"),
    ({"exp": 1}, "expired"),
])
def test_contextual_response_rejects_each_mutated_guarantee(signed_as, mutation,
                                                             reason):
    with pytest.raises(asclient.ASError, match=reason,):
        _semantic_verify(signed_as(**mutation))


def _prod_as_config(monkeypatch, provider: str, certification_file: str = "",
                    certification_public_key_file: str = ""):
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(config, "AS_PROVIDER", provider)
    monkeypatch.setattr(config, "AS_PROVIDER_SET", True)
    monkeypatch.setattr(config, "AS_CAPABILITY", "core")
    monkeypatch.setattr(config, "AS_CAPABILITY_SET", True)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "andyur")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "AS_JWKS_URL", "https://as.example/jwks")
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", certification_file)
    monkeypatch.setattr(
        config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", certification_public_key_file)
    monkeypatch.setattr(config, "AS_PRODUCT_VERSION", "26.2")


def test_production_refuses_the_reference_as_provider(monkeypatch):
    """The reference AS is a test fixture signed with a published example key,
    so anyone can mint tokens it accepts. 'Some external AS is configured' must
    not be satisfiable by the fixture itself, even behind a TLS front."""
    _prod_as_config(monkeypatch, "reference")
    assert any("reference" in p and "production" in p
               for p in config.as_problems())


def test_production_accepts_a_certified_real_vendor_provider(monkeypatch, tmp_path):
    """Positive control for the refusal above: the same production config with
    a real vendor name has no provider problem."""
    now = int(time.time())
    path = tmp_path / "certification.json"
    key = Ed25519PrivateKey.generate()
    public_key = tmp_path / "certification.pub"
    public_key.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    document = ascertification.sign({
        "schema": "andyur-as-certification/v2",
        "suite": "andyur-as-conformance-v1",
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
        "issued_at": now - 60,
        "expires_at": now + 3600,
    }, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    path.write_text(json.dumps(document))
    _prod_as_config(monkeypatch, "keycloak", str(path), str(public_key))
    assert config.as_problems() == []


# --- reference provider: logical actions translated at exchange time (ADR-010) -
_REF_MAP = ('{"schema":"andyur-reference-scope-map/v1","actions":{'
            '"obs:read":{"request":"telemetry:read","claim":"telemetry:read"}}}')


def test_reference_provider_with_a_map_translates_the_scope_it_sends(
        as_configured, captured, monkeypatch):
    """A registry run asks in logical actions (obs:read); with a map configured,
    the request Andyur posts to the reference AS carries the AS's vocabulary
    (telemetry:read), so the exchange the AS rejected before now matches."""
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", _REF_MAP)
    _exchange(scope=["obs:read"])
    assert captured["form"]["scope"] == "telemetry:read"


def test_reference_provider_without_a_map_passes_scopes_through(as_configured, captured):
    """No map configured (the actor-leg case, AS-vocabulary scopes direct): the
    reference provider must not touch the scope, so the chain still works as-is."""
    _exchange(scope=["telemetry:read"])
    assert captured["form"]["scope"] == "telemetry:read"

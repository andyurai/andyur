import base64

import pytest

from andyur.server import asproviders


BASE = dict(client_id="andyur", client_secret="secret", subject_token="T0",
            actor_token="S1", audience="api://tool", resource="api://tool",
            scope="files:read", authorization_details='[{"type":"andyur_pin"}]')
ENTRA_MAP = '{"schema":"andyur-entra-scope-map/v1","actions":{' \
    '"files:read":{"request":"api://tool/Files.Read","claim":"Files.Read"}}}'


def build(name, **changes):
    values = {"provider_scope": None, **BASE, **changes}
    return asproviders.build_request(provider_name=name, **values)


@pytest.mark.parametrize("name", sorted(asproviders.PROVIDERS))
def test_exported_client_auth_method_is_the_one_applied_on_the_wire(name):
    changes = {"provider_scope": "api://tool/.default"} if name == "entra" else {}
    form, headers = build(name, **changes)
    method = asproviders.client_auth_method(name)
    if method == "client_secret_basic":
        assert headers.get("Authorization", "").startswith("Basic ")
        assert "client_id" not in form and "client_secret" not in form
    elif method == "client_secret_post":
        assert headers == {}
        assert form["client_id"] == BASE["client_id"]
        assert form["client_secret"] == BASE["client_secret"]
    else:  # a new selector must add a real-wire assertion before it is usable
        pytest.fail(f"uncovered client-auth method {method!r}")


def test_reference_carries_the_complete_contextual_envelope():
    form, headers = build("reference")
    assert form["subject_token"] == "T0"
    assert form["actor_token"] == "S1"
    assert form["audience"] == form["resource"] == "api://tool"
    assert form["scope"] == "files:read"
    assert "andyur_pin" in form["authorization_details"]
    assert headers == {}
    assert asproviders.client_auth_method("reference") == "client_secret_post"


def test_keycloak_uses_rfc8693_but_cannot_claim_delegated():
    form, headers = build("keycloak")
    assert form["grant_type"] == asproviders.GRANT_EXCHANGE
    assert form["requested_token_type"] == asproviders.TOKEN_ACCESS
    assert headers["Authorization"].startswith("Basic ")
    assert "actor_token" not in form and "resource" not in form
    assert "authorization_details" not in form
    assert asproviders.validate("keycloak", "core") == []
    assert "supported: core" in asproviders.validate("keycloak", "delegated")[0]
    assert asproviders.client_auth_method("keycloak") == "client_secret_basic"


def test_entra_uses_obo_not_a_fake_rfc8693_exchange():
    request_scope, claims = asproviders.entra_scope_mapping(ENTRA_MAP, "files:read")
    form, headers = build("entra", provider_scope=request_scope)
    assert form == {
        "client_id": "andyur",
        "client_secret": "secret",
        "grant_type": asproviders.GRANT_JWT_BEARER,
        "assertion": "T0",
        "requested_token_use": "on_behalf_of",
        "scope": "api://tool/Files.Read",
    }
    assert "actor_token" not in form and "audience" not in form
    assert headers == {}
    assert claims == {"Files.Read"}
    assert asproviders.client_auth_method("entra") == "client_secret_post"


def test_entra_never_reuses_andyur_action_scope_as_provider_scope():
    with pytest.raises(asproviders.ProviderConfigurationError,
                       match="ANDYUR_AS_RESOURCE_SCOPE"):
        build("entra")


@pytest.mark.parametrize("raw,scope", [
    ("{}", "files:read"), (ENTRA_MAP, "files:write"),
    ('{"schema":"andyur-entra-scope-map/v1","actions":{"files:read":'
     '{"request":"api://tool/Files.Read","claim":"Files.Read","extra":true}}}',
     "files:read"),
    ('{"schema":"andyur-entra-scope-map/v1","actions":{"files:read":'
     '{"request":"api://tool/Files.Read api://tool/Files.Write",'
     '"claim":"Files.Read"}}}', "files:read"),
])
def test_entra_scope_map_refuses_malformed_or_unmapped_actions(raw, scope):
    with pytest.raises(asproviders.ProviderConfigurationError):
        asproviders.entra_scope_mapping(raw, scope)


def test_entra_refuses_an_unauthenticated_obo_request():
    with pytest.raises(asproviders.ProviderConfigurationError,
                       match="currently requires a client secret"):
        build("entra", client_secret="", provider_scope="api://tool/.default")


def test_entra_identity_is_tenant_and_object_not_pairwise_sub():
    first = {"sub": "login-pairwise", "tid": "tenant", "oid": "object"}
    downstream = {"sub": "api-pairwise", "tid": "tenant", "oid": "object"}
    assert asproviders.subject_identity("entra", first) \
        == asproviders.subject_identity("entra", downstream) \
        == '["tenant","object"]'


@pytest.mark.parametrize("claims", [
    {"oid": "object"}, {"tid": "tenant"}, {"tid": "", "oid": "object"},
])
def test_entra_identity_refuses_missing_tenant_or_object(claims):
    with pytest.raises(asproviders.ProviderConfigurationError, match="tid and oid"):
        asproviders.subject_identity("entra", claims)


def test_okta_uses_basic_client_auth_and_no_resource_parameter():
    form, headers = build("okta")
    expected = base64.b64encode(b"andyur:secret").decode()
    assert headers == {"Authorization": f"Basic {expected}"}
    assert "client_id" not in form and "client_secret" not in form
    assert form["requested_token_type"] == asproviders.TOKEN_ACCESS
    assert "resource" not in form and form["audience"] == "api://tool"
    assert "actor_token" not in form and "authorization_details" not in form


def test_okta_basic_auth_form_encodes_each_credential_component():
    _, headers = build("okta", client_id="id: with", client_secret="s:e/cret +")
    expected = base64.b64encode(
        b"id%3A+with:s%3Ae%2Fcret+%2B").decode()
    assert headers == {"Authorization": f"Basic {expected}"}


def test_okta_refuses_missing_basic_secret():
    with pytest.raises(asproviders.ProviderConfigurationError, match="HTTP Basic"):
        build("okta", client_secret="")


def test_auth0_uses_its_json_obo_shape_without_unsupported_actor_context():
    form, headers = build("auth0")
    assert asproviders.request_encoding("auth0") == "json"
    assert form == {
        "client_id": "andyur", "client_secret": "secret",
        "grant_type": asproviders.GRANT_EXCHANGE,
        "subject_token": "T0", "subject_token_type": asproviders.TOKEN_ACCESS,
        "requested_token_type": asproviders.TOKEN_ACCESS,
        "audience": "api://tool", "scope": "files:read",
    }
    assert headers == {}
    assert asproviders.client_auth_method("auth0") == "client_secret_post"


def test_pingfederate_uses_form_basic_and_preserves_the_actor_leg():
    form, headers = build("pingfederate")
    assert asproviders.request_encoding("pingfederate") == "form"
    assert headers["Authorization"].startswith("Basic ")
    assert form["actor_token"] == "S1"
    assert form["requested_token_type"] == asproviders.TOKEN_ACCESS
    assert "authorization_details" not in form


def test_pingam_core_uses_its_supported_impersonation_shape():
    form, headers = build("pingam")
    assert headers["Authorization"].startswith("Basic ")
    assert form["requested_token_type"] == asproviders.TOKEN_ACCESS
    for unsupported in ("actor_token", "actor_token_type", "audience",
                        "resource", "authorization_details"):
        assert unsupported not in form


@pytest.mark.parametrize("name,ceiling", [
    ("reference", "contextual"), ("auth0", "core"),
    ("pingfederate", "core"), ("pingam", "core"),
    ("entra", "core"), ("okta", "core"),
])
def test_provider_capability_support_is_fail_closed(name, ceiling):
    assert asproviders.validate(name, ceiling) == []
    # A capability ABOVE this provider's ceiling must be refused. For a
    # core-only provider that is `contextual` (a real widened-guarantee probe);
    # 'sender-bound' would be refused for everyone regardless of provider now
    # (it is withdrawn entirely), so it cannot catch a per-provider widening.
    if ceiling != "contextual":
        assert asproviders.validate(name, "contextual")


def test_unknown_provider_and_capability_are_refused():
    assert "unknown authorization-server provider" in asproviders.validate(
        "guess", "core")[0]
    assert "unknown authorization capability" in asproviders.validate(
        "reference", "magic")[0]


def test_sender_bound_capability_is_refused_with_the_reason():
    """Sender-binding is a two-party property: until a tool path verifies the
    token's cnf binding against the live connection, offering the capability
    would let configuration claim a guarantee nothing enforces. The refusal
    must say so, not report an unknown name."""
    problems = asproviders.validate("reference", "sender-bound")
    assert problems and "resource server" in problems[0]
    with pytest.raises(asproviders.ProviderConfigurationError) as e:
        asproviders.capability("sender-bound")
    assert "not offered" in str(e.value)


# --- the reference provider gets the same translation mechanism (ADR-010) -----
REFERENCE_MAP = '{"schema":"andyur-reference-scope-map/v1","actions":{' \
    '"obs:read":{"request":"telemetry:read","claim":"telemetry:read"},' \
    '"tickets:read":{"request":"tickets:read","claim":"tickets:read"},' \
    '"tickets:comment":{"request":"tickets:write","claim":"tickets:write"}}}'


def test_reference_scope_map_translates_logical_actions_to_the_as_vocabulary():
    """A registry run names logical actions the reference AS does not know; the
    map turns them into the AS's fixed vocabulary so the exchange is accepted."""
    request_scope, claims = asproviders.reference_scope_mapping(
        REFERENCE_MAP, "obs:read tickets:comment")
    assert request_scope == "telemetry:read tickets:write"
    assert claims == {"telemetry:read", "tickets:write"}


def test_reference_scope_map_refuses_an_unmapped_action_rather_than_dropping_it():
    """Silently dropping an unmapped action would issue a token narrower than the
    run's authority, read later as a tool bug -- so it fails loudly instead."""
    with pytest.raises(asproviders.ProviderConfigurationError, match="tickets:close"):
        asproviders.reference_scope_mapping(REFERENCE_MAP, "obs:read tickets:close")


def test_reference_scope_map_enforces_its_own_closed_schema_not_entras():
    """The reference and Entra maps are distinct closed schemas; feeding one to
    the other is refused, so a misconfiguration cannot silently cross vendors."""
    with pytest.raises(asproviders.ProviderConfigurationError, match="reference"):
        asproviders.reference_scope_mapping(ENTRA_MAP, "files:read")
    with pytest.raises(asproviders.ProviderConfigurationError, match="Entra"):
        asproviders.entra_scope_mapping(REFERENCE_MAP, "obs:read")

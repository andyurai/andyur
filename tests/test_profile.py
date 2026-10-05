"""The deployment profile: an unconfigured platform must refuse to serve.

Andyur's containment was individually opt-in, every control defaulting to off,
which made the DEFAULT deployment the unsafe one. Defaults are what a platform
is judged on -- nobody reads a hardening guide before the first run -- so the
production profile is now the default and it is enforced at startup.

These tests pin the two things that make that worth having: it actually refuses,
and it says precisely what is missing. A security check whose message does not
tell you how to satisfy it gets satisfied by setting the profile to dev.
"""

import json
import hashlib
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from andyur import config
from andyur.server import ascertification


@pytest.fixture
def prod(monkeypatch, tmp_path):
    """A fully contained production deployment. Each test removes ONE control
    and asserts the platform notices, so a check that silently stops working is
    a failing test rather than a quiet regression."""
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(config, "DEPLOYMENT", "docker")
    monkeypatch.setattr(config, "SANDBOX", True)
    monkeypatch.setattr(config, "AGENT_AUTH", True)
    monkeypatch.setattr(config, "USER_AUTH", True)
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", True)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "andyur")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "test-secret")
    monkeypatch.setattr(config, "AS_JWKS_URL", "https://as.example/jwks")
    # A real vendor name: production refuses the reference fixture outright,
    # and this fixture is the baseline every removed-one-control test builds on.
    monkeypatch.setattr(config, "AS_PROVIDER", "keycloak")
    monkeypatch.setattr(config, "AS_CAPABILITY", "core")
    monkeypatch.setattr(config, "AS_PROVIDER_SET", True)
    monkeypatch.setattr(config, "AS_CAPABILITY_SET", True)
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", "")
    monkeypatch.setattr(config, "AS_PRODUCT_VERSION", "26.2")
    monkeypatch.setattr(config, "AS_DELEGATED_OVERLAY_FILE", "")
    monkeypatch.setattr(config, "AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE", "")
    monkeypatch.setattr(config, "AS_TENANT", "")
    monkeypatch.setattr(config, "AS_CLIENT_AUTH_METHOD", "")
    monkeypatch.setattr(config, "AS_POLICY_CONFIG", "")
    monkeypatch.setattr(config, "AS_CERTIFICATION_GENERATION", 0)
    now = int(time.time())
    certification = tmp_path / "as-certification.json"
    certification_key = Ed25519PrivateKey.generate()
    certification_public_key = tmp_path / "as-certification.pub"
    certification_public_key.write_bytes(certification_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    document = ascertification.sign({
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
        "issued_at": now - 60,
        "expires_at": now + 3600,
    }, certification_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    certification.write_text(json.dumps(document))
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", str(certification))
    monkeypatch.setattr(
        config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", str(certification_public_key))
    monkeypatch.setattr(config, "SECCOMP_MODE", "require")
    monkeypatch.setattr(config, "EGRESS_NETWORK", "andyur-runs")
    monkeypatch.setattr(config, "BROKER_URL", "http://broker:8643")
    monkeypatch.setattr(config, "RUN_TOKEN_SECRET_SET", True)
    monkeypatch.setattr(config, "STORAGE", "local")
    monkeypatch.setattr(config, "GRAPH", "off")
    monkeypatch.setattr(config, "DB_URL", "")
    monkeypatch.setattr(config, "_delegation_configured", lambda: True)
    monkeypatch.setenv("ANDYUR_LLM", "api")
    # Set the key EXPLICITLY. _needs_broker() asks whether a provider key is
    # present, and the answer was being supplied by the developer's own
    # environment via a gitignored .env one directory up. So the test asserting
    # that production refuses to leak that key only asserted anything on a
    # machine that had one -- it passed here and failed in CI from the moment
    # CI existed. A test whose subject is an environment variable has to own
    # that variable.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fixture")


def test_a_contained_deployment_starts(prod):
    config.assert_profile()


def test_dev_requires_nothing(monkeypatch):
    """Running without containment stays entirely possible. The point is that it
    is a decision someone made, not a default they inherited."""
    monkeypatch.setattr(config, "PROD", False)
    monkeypatch.setattr(config, "SANDBOX", False)
    config.assert_profile()


@pytest.mark.parametrize("attr, value, expected_hint", [
    ("SANDBOX", False, "ANDYUR_SANDBOX"),
    ("AGENT_AUTH", False, "ANDYUR_AGENT_AUTH"),
    ("EGRESS_NETWORK", "", "ANDYUR_SANDBOX_NETWORK"),
    ("BROKER_URL", "", "ANDYUR_BROKER_URL"),
    ("SECCOMP_MODE", "auto", "ANDYUR_SECCOMP"),
    ("SECCOMP_MODE", "off", "ANDYUR_SECCOMP"),
])
def test_each_missing_control_refuses_the_boot(prod, monkeypatch, attr, value, expected_hint):
    monkeypatch.setattr(config, attr, value)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert expected_hint in str(exc.value)


def test_the_refusal_explains_the_risk_not_just_the_variable(prod, monkeypatch):
    """An error that only names a variable teaches nothing, and the fastest way
    to satisfy it is to switch to dev. Naming what goes wrong is what makes the
    right fix the easy one."""
    monkeypatch.setattr(config, "SANDBOX", False)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    message = str(exc.value)
    assert "shell" in message and "host" in message
    assert "ANDYUR_PROFILE=dev" in message   # and the honest escape hatch


def test_every_missing_control_is_reported_at_once(prod, monkeypatch):
    """Reporting one problem per restart turns a five-minute fix into five
    restarts, and the operator learns the shape of the requirement only by
    trial. Report the whole set."""
    monkeypatch.setattr(config, "SANDBOX", False)
    monkeypatch.setattr(config, "EGRESS_NETWORK", "")
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    message = str(exc.value)
    for hint in ("ANDYUR_SANDBOX", "ANDYUR_SANDBOX_NETWORK"):
        assert hint in message


@pytest.mark.parametrize("attr, value, expected_hint", [
    ("AS_CERTIFICATION_FILE", "", "ANDYUR_AS_CERTIFICATION_FILE"),
    ("AS_CERTIFICATION_PUBLIC_KEY_FILE", "",
     "ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE"),
    ("USER_AUTH", False, "ANDYUR_USER_AUTH"),
    ("REQUIRE_RUN_SVID", False, "ANDYUR_REQUIRE_RUN_SVID"),
])
def test_production_requires_the_complete_enterprise_authority_path(
        prod, monkeypatch, attr, value, expected_hint):
    """Production cannot silently downgrade to Andyur's reference signer, an
    unauthenticated subject, or bearer-only run capability."""
    monkeypatch.setattr(config, attr, value)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert expected_hint in str(exc.value)


def _no_as_at_all(monkeypatch):
    """Every ANDYUR_AS_* cleared, not just the endpoint: an endpoint-only clear
    is the half-configured shape, which is refused and tested separately."""
    for attr, empty in (
            ("AS_TOKEN_ENDPOINT", ""), ("AS_ISSUER", ""), ("AS_CLIENT_ID", ""),
            ("AS_CLIENT_SECRET", ""), ("AS_JWKS_URL", ""),
            ("AS_PROVIDER", "reference"), ("AS_CAPABILITY", "core"),
            ("AS_PROVIDER_SET", False), ("AS_CAPABILITY_SET", False),
            ("AS_PRODUCT_VERSION", ""), ("AS_RESOURCE_SCOPE", ""),
            ("AS_CERTIFICATION_FILE", ""),
            ("AS_CERTIFICATION_PUBLIC_KEY_FILE", ""),
            ("AS_CERTIFICATION_GENERATION", 0)):
        monkeypatch.setattr(config, attr, empty)


def test_an_as_is_not_required_without_delegated_authority_to_mint(
        prod, monkeypatch):
    """The broker rule, applied to the authorization server. Production never
    mints tool authority locally regardless: /oauth/token refuses the local
    signer unconditionally in prod and the runner's run-start probe withholds
    delegated tools with that same named refusal, so a prod deployment with no
    AS runs and its delegated tools fail closed at the mint. Requiring an AS at
    BOOT of deployments that never exercise delegated authority is how the
    shipped compose spent two days unbootable (gap 15b) -- ceremony, and
    ceremony is what teaches people to disable checks."""
    _no_as_at_all(monkeypatch)
    config.assert_profile()


@pytest.mark.parametrize("attr, value, expected_hint", [
    ("AS_ISSUER", "https://as.example", "ANDYUR_AS_ISSUER"),
    ("AS_CLIENT_ID", "andyur", "ANDYUR_AS_CLIENT_ID"),
    # The four the stray check first OMITTED. PROVIDER/CAPABILITY carry
    # non-empty defaults, so they are stray only when EXPLICITLY set: the
    # _SET flag is what a real environment would carry, and setting only the
    # string without it is the shape that used to slip through.
    ("AS_PROVIDER_SET", True, "ANDYUR_AS_PROVIDER"),
    ("AS_CAPABILITY_SET", True, "ANDYUR_AS_CAPABILITY"),
    ("AS_PRODUCT_VERSION", "26.2", "ANDYUR_AS_PRODUCT_VERSION"),
    ("AS_RESOURCE_SCOPE", "api://andyur/.default", "ANDYUR_AS_RESOURCE_SCOPE"),
])
def test_a_half_configured_as_still_refuses_the_boot(
        prod, monkeypatch, attr, value, expected_hint):
    """Dropping the boot requirement must not also drop the half-migration
    check: any single ANDYUR_AS_* set without the endpoint means Andyur would
    keep minting locally while the configuration says otherwise, and each such
    variable must name itself in the refusal -- so a partial migration fails at
    boot, not silently at the first tool call."""
    _no_as_at_all(monkeypatch)
    monkeypatch.setattr(config, attr, value)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert expected_hint in str(exc.value)
    assert "without ANDYUR_AS_TOKEN_ENDPOINT" in str(exc.value)


def test_provider_set_to_its_default_value_still_counts_as_configured(
        prod, monkeypatch):
    """The stray check keys ANDYUR_AS_PROVIDER on the _SET flag, not the string,
    so an operator who explicitly exports ANDYUR_AS_PROVIDER=reference (its
    default value) without an endpoint is still caught -- a default typed out is
    still a half-migration, and value-equality would have missed it."""
    _no_as_at_all(monkeypatch)
    monkeypatch.setattr(config, "AS_PROVIDER", "reference")
    monkeypatch.setattr(config, "AS_PROVIDER_SET", True)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_AS_PROVIDER" in str(exc.value)


def _configure_delegated_overlay(prod, monkeypatch, tmp_path, *, generation=7):
    monkeypatch.setattr(config, "AS_CAPABILITY", "delegated")
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", "")
    monkeypatch.setattr(config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", "")
    monkeypatch.setattr(config, "AS_TENANT", "tenant-one")
    monkeypatch.setattr(config, "AS_CLIENT_AUTH_METHOD", "client_secret_basic")
    monkeypatch.setattr(config, "AS_POLICY_CONFIG", "policy-v1")
    monkeypatch.setattr(config, "AS_CERTIFICATION_GENERATION", generation)
    key = Ed25519PrivateKey.generate()
    public_key = tmp_path / "overlay.pub"
    public_key.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    _, core_digest = ascertification.certification_matrix()
    now = int(time.time())
    document = ascertification.sign({
        "schema": ascertification.OVERLAY_SCHEMA,
        "suite": ascertification.OVERLAY_SUITE,
        "result": "pass",
        "core_schema": ascertification.MATRIX_SCHEMA,
        "core_sha256": core_digest,
        "provider": "keycloak",
        "tenant": "tenant-one",
        "capability": ascertification.MATRIX_PROFILE["capability"],
        "route_class": ascertification.MATRIX_PROFILE["route_class"],
        "issuer": config.AS_ISSUER,
        "token_endpoint": config.AS_TOKEN_ENDPOINT,
        "jwks_url": config.AS_JWKS_URL,
        "client_id": config.AS_CLIENT_ID,
        "client_auth_method": "client_secret_basic",
        "policy_config_sha256": hashlib.sha256(b"policy-v1").hexdigest(),
        "product_version": config.AS_PRODUCT_VERSION,
        "certification_generation": generation,
        "evidence_sha256": {
            row["id"]: hashlib.sha256(row["id"].encode()).hexdigest()
            for row in ascertification.certification_matrix()[0]["rows"]
        },
        "issued_at": now - 60,
        "expires_at": now + 3600,
    }, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    overlay = tmp_path / "overlay.json"
    overlay.write_text(json.dumps(document))
    monkeypatch.setattr(config, "AS_DELEGATED_OVERLAY_FILE", str(overlay))
    monkeypatch.setattr(
        config, "AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE", str(public_key))
    return overlay


def test_non_core_capability_requires_overlay_without_promoting_adapter(
        prod, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "AS_CAPABILITY", "delegated")
    problems = config.as_problems()
    assert any("does not have built-in support" in problem for problem in problems)
    for variable in (
            "ANDYUR_AS_DELEGATED_OVERLAY_FILE",
            "ANDYUR_AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE",
            "ANDYUR_AS_TENANT", "ANDYUR_AS_CLIENT_AUTH_METHOD",
            "ANDYUR_AS_POLICY_CONFIG", "ANDYUR_AS_CERTIFICATION_GENERATION"):
        assert any(variable in problem for problem in problems)

    _configure_delegated_overlay(prod, monkeypatch, tmp_path)
    problems = config.as_problems()
    assert len(problems) == 1
    assert "does not have built-in support" in problems[0]


def test_non_core_refuses_superseded_and_legacy_overlay_artifacts(
        prod, monkeypatch, tmp_path):
    overlay = _configure_delegated_overlay(prod, monkeypatch, tmp_path)
    monkeypatch.setattr(config, "AS_CERTIFICATION_GENERATION", 8)
    assert any("certification_generation does not match" in problem
               for problem in config.as_problems())

    monkeypatch.setattr(config, "AS_CERTIFICATION_GENERATION", 7)
    legacy = tmp_path / "legacy-v2.json"
    key = Ed25519PrivateKey.generate()
    legacy.write_text(json.dumps(ascertification.sign({
        "schema": ascertification.SCHEMA, "suite": ascertification.SUITE,
        "result": "pass", "provider": "keycloak", "capability": "core",
        "issuer": config.AS_ISSUER, "token_endpoint": config.AS_TOKEN_ENDPOINT,
        "jwks_url": config.AS_JWKS_URL, "client_id": config.AS_CLIENT_ID,
        "product_version": config.AS_PRODUCT_VERSION,
        "discovery_sha256": "a" * 64,
        "scope_config_sha256": hashlib.sha256(b"").hexdigest(),
        "issued_at": int(time.time()) - 60, "expires_at": int(time.time()) + 3600,
    }, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))))
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", str(legacy))
    monkeypatch.setattr(
        config, "AS_CERTIFICATION_PUBLIC_KEY_FILE",
        config.AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE)
    assert any("legacy v2 core certification settings must be unset" in problem
               for problem in config.as_problems())
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", "")
    monkeypatch.setattr(config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", "")
    overlay.write_text(legacy.read_text())
    assert any("overlay schema does not match" in problem
               for problem in config.as_problems())


def test_core_refuses_populated_delegated_settings_as_downgrade(
        prod, monkeypatch):
    monkeypatch.setattr(config, "AS_DELEGATED_OVERLAY_FILE", "/overlay.json")
    monkeypatch.setattr(config, "AS_DELEGATED_OVERLAY_PUBLIC_KEY_FILE", "/overlay.pub")
    monkeypatch.setattr(config, "AS_TENANT", "tenant-one")
    monkeypatch.setattr(config, "AS_CLIENT_AUTH_METHOD", "client_secret_basic")
    monkeypatch.setattr(config, "AS_POLICY_CONFIG", "policy-v1")
    monkeypatch.setattr(config, "AS_CERTIFICATION_GENERATION", 7)
    assert any("silent capability downgrade" in problem
               for problem in config.as_problems())


def test_overlay_client_auth_is_derived_from_adapter_wire_not_operator_label(
        prod, monkeypatch, tmp_path):
    _configure_delegated_overlay(prod, monkeypatch, tmp_path)
    monkeypatch.setattr(config, "AS_CLIENT_AUTH_METHOD", "private_key_jwt")
    problems = config.as_problems()
    assert any("adapter's wire method 'client_secret_basic'" in problem
               for problem in problems)
    assert not any("overlay client_auth_method does not match" in problem
                   for problem in problems), "overlay must compare adapter truth, not label"


def test_delegated_overlay_cannot_be_reused_for_contextual_capability(
        prod, monkeypatch, tmp_path):
    _configure_delegated_overlay(prod, monkeypatch, tmp_path)
    monkeypatch.setattr(config, "AS_CAPABILITY", "contextual")
    assert any("contextual requires its own closed matrix" in problem
               for problem in config.as_problems())


def test_dev_retains_the_reference_authority_path(prod, monkeypatch):
    """The self-contained signer remains an explicit development facility."""
    monkeypatch.setattr(config, "PROD", False)
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "")
    monkeypatch.setattr(config, "USER_AUTH", False)
    monkeypatch.setattr(config, "REQUIRE_RUN_SVID", False)
    config.assert_profile()


def test_a_broker_is_not_required_without_a_key_to_steal(prod, monkeypatch):
    """The broker exists to keep a provider API key out of the agent's
    environment. With no key present there is nothing to protect, so requiring a
    broker would be ceremony -- and ceremony is what teaches people to disable
    checks."""
    monkeypatch.setattr(config, "BROKER_URL", "")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANDYUR_LLM", "ollama")
    config.assert_profile()


@pytest.mark.parametrize("backend", ["api", "ollama", "subscription"])
def test_a_broker_is_required_whenever_a_key_is_present(prod, monkeypatch, backend):
    """The requirement follows the KEY, not the backend setting, because the
    daemon forwards ANTHROPIC_API_KEY into every run container whenever no
    broker is configured -- regardless of ANDYUR_LLM. Gating on the backend
    meant a stale key still exported from a .env was handed to every agent while
    production booted cleanly, since the two conditions asked different
    questions."""
    monkeypatch.setattr(config, "BROKER_URL", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    monkeypatch.setenv("ANDYUR_LLM", backend)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_BROKER_URL" in str(exc.value)


# --- secrets that must be real, not defaults or per-process randomness ------

def test_the_run_token_secret_must_be_shared(prod, monkeypatch):
    """The random per-process default works right up until something ELSE
    verifies a token Andyur signed: a second replica, or the broker. Then every
    call 401s and nothing explains why. Refusing at boot is cheaper than
    debugging that at 3am."""
    monkeypatch.setattr(config, "RUN_TOKEN_SECRET_SET", False)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_RUN_TOKEN_SECRET" in str(exc.value)
    assert "broker" in str(exc.value)


def test_published_default_object_store_credentials_are_refused(prod, monkeypatch):
    """'minioadmin' is a credential anyone can look up, on the store that holds
    every agent's mind."""
    monkeypatch.setattr(config, "STORAGE", "s3")
    monkeypatch.setattr(config, "S3_ACCESS_KEY", "minioadmin")
    monkeypatch.setattr(config, "S3_SECRET_KEY", "minioadmin")
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_S3_ACCESS_KEY" in str(exc.value)


def test_the_repository_default_graph_password_is_refused(prod, monkeypatch):
    monkeypatch.setattr(config, "GRAPH", "neo4j")
    monkeypatch.setattr(config, "NEO4J_PASSWORD", "andyurgraph")
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_NEO4J_PASSWORD" in str(exc.value)


def test_multi_node_delegation_needs_a_shared_signing_key(prod, monkeypatch):
    """Without it each replica mints downstream tokens against its own ephemeral
    key, so a delegation validates or fails depending on which replica answered
    -- an intermittent authorization bug, the worst kind."""
    monkeypatch.setattr(config, "DB_URL", "postgresql://andyur@db/andyur")
    monkeypatch.setattr(config, "EXCHANGE_KEY_PATH", "")
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_EXCHANGE_KEY" in str(exc.value)


def test_a_single_node_deployment_needs_no_exchange_key(prod, monkeypatch):
    """One process publishing the JWKS it signs with is self-consistent, so
    requiring the key there would be ceremony."""
    monkeypatch.setattr(config, "DB_URL", "")
    monkeypatch.setattr(config, "EXCHANGE_KEY_PATH", "")
    config.assert_profile()


def test_an_unrecognised_profile_refuses_to_run(monkeypatch):
    """`PROD = PROFILE == "prod"` alone fails OPEN on the single most likely
    thing an operator types. 'production', 'PROD ', 'prd' each silently disabled
    every containment control with no log line saying so -- and a wrong explicit
    value is worse than an absent one, because the operator believes they
    configured it."""
    import importlib
    for bad in ("production", "PRODUCTION", "prd", "staging", "prod-like"):
        monkeypatch.setenv("ANDYUR_PROFILE", bad)
        with pytest.raises(RuntimeError, match="not a profile"):
            importlib.reload(config)
    monkeypatch.setenv("ANDYUR_PROFILE", "dev")
    importlib.reload(config)


def test_whitespace_around_a_good_value_is_tolerated(monkeypatch):
    """Refusing 'prod ' would be pedantry that costs an outage; refusing
    'production' is the check doing its job. The difference is whether the
    intent is unambiguous."""
    import importlib
    monkeypatch.setenv("ANDYUR_PROFILE", "  PROD ")
    importlib.reload(config)
    assert config.PROD is True
    monkeypatch.setenv("ANDYUR_PROFILE", "dev")
    importlib.reload(config)


def test_deployment_is_explicit_and_unknown_values_are_never_guessed(monkeypatch):
    import importlib

    for bad in ("auto", "container", "k8s", "cloud", "production"):
        monkeypatch.setenv("ANDYUR_DEPLOYMENT", bad)
        with pytest.raises(RuntimeError, match="not a deployment"):
            importlib.reload(config)
    for good in ("native", "docker", "kubernetes"):
        monkeypatch.setenv("ANDYUR_DEPLOYMENT", good)
        importlib.reload(config)
        assert config.DEPLOYMENT == good
    monkeypatch.setenv("ANDYUR_DEPLOYMENT", "native")
    importlib.reload(config)


def test_an_unset_delegation_policy_refuses_the_boot(prod, monkeypatch):
    """Cross-agent WRITES are closed, but delegation is cross-agent INFLUENCE:
    a task title lands in the assignee's prompt. Unset, one compromised agent
    can wake every other agent on the platform with text of its choosing, and
    the only thing in the way is a sentence asking the reader to treat it as
    data -- a rate, not a boundary."""
    monkeypatch.setattr(config, "_delegation_configured", lambda: False)
    with pytest.raises(config.InsecureProfile) as exc:
        config.assert_profile()
    assert "ANDYUR_DELEGATIONS" in str(exc.value)


def test_open_delegation_is_allowed_when_it_is_a_decision(monkeypatch):
    """'unset' and 'everyone' must not be the same configuration. Choosing
    everyone stays available; it just has to be chosen."""
    import importlib
    from andyur.server import delegation
    monkeypatch.setenv("ANDYUR_DELEGATIONS", "*")
    importlib.reload(delegation)
    assert delegation.configured() is True
    assert delegation.may_delegate("planner", "researcher") is True
    monkeypatch.delenv("ANDYUR_DELEGATIONS", raising=False)
    importlib.reload(delegation)
    assert delegation.configured() is False


def test_an_allow_list_still_denies_what_it_omits(monkeypatch):
    import importlib
    from andyur.server import delegation
    monkeypatch.setenv("ANDYUR_DELEGATIONS", "planner:triage")
    importlib.reload(delegation)
    assert delegation.may_delegate("planner", "triage") is True
    assert delegation.may_delegate("planner", "billing") is False
    assert delegation.may_delegate("planner", "planner") is True    # self, always
    assert delegation.may_delegate(None, "billing") is True         # operator
    monkeypatch.delenv("ANDYUR_DELEGATIONS", raising=False)
    importlib.reload(delegation)


def test_the_suite_does_not_depend_on_the_developers_own_environment(monkeypatch):
    """The failure that made CI red from the day it was added.

    `config.load_dotenv` reads a gitignored `.env` one directory above the
    project, so `ANTHROPIC_API_KEY` was present on the author's machine and
    absent everywhere else. The test asserting that production refuses to leak
    that key therefore asserted nothing in CI, and the commit message's test
    count was true only on one laptop.

    This pins the general rule: no test may draw a security-relevant input from
    ambient environment. Anything the suite asserts about a variable, the suite
    sets.
    """
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(config, "PROD", True)
    monkeypatch.setattr(config, "BROKER_URL", "")
    # No key present, so no broker is required: the check follows the key, and
    # with the key genuinely absent this must NOT be the thing that fails.
    assert config._needs_broker() is False
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    assert config._needs_broker() is True


def test_a_mistyped_delegation_policy_is_refused_not_guessed():
    """The likeliest typo used to grant universal cross-agent delegation.

    `ANDYUR_DELEGATIONS="planner,triage"` -- a comma where a semicolon-and-colon
    belongs -- parsed to nothing; nothing means no allow-list; no allow-list
    means every agent may delegate to every agent. And the production gate
    passed, because a spec WAS set. So the operator believed they had restricted
    delegation while it was wide open, which is worse than leaving it unset.

    Tests the parser directly: reloading the module to observe an import-time
    failure leaves the module half-initialised, which makes the test about
    importlib rather than about the policy.
    """
    from andyur.server import delegation

    for bad in ("planner,triage", "planner:", ":triage", "planner triage",
                "planner:triage; oops"):
        with pytest.raises(delegation.InvalidDelegationPolicy):
            delegation._parse(bad)

    good = delegation._parse("planner:triage,research; triage:research")
    assert good == {"planner": {"triage", "research"}, "triage": {"research"}}
    assert delegation._parse("") == {}          # unset is handled by the caller


def test_open_delegation_remains_expressible():
    """Refusing typos must not remove the deliberate choice to allow everything."""
    import importlib
    from andyur.server import delegation

    import os
    os.environ["ANDYUR_DELEGATIONS"] = "*"
    try:
        importlib.reload(delegation)
        assert delegation.configured() is True
        assert delegation.may_delegate("anyone", "anyone-else") is True
    finally:
        os.environ.pop("ANDYUR_DELEGATIONS", None)
        importlib.reload(delegation)

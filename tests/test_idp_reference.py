"""The reference IdP (compose `idp` profile) keeps its reachability contract.

These pin the composition the live gate (infra/keycloak/verify-idp-reference.sh)
verifies against running containers: the IdP is a control-plane concern that an
agent run must have no route to, its database is on an internal segment only,
and nothing boots on default credentials.
"""

from __future__ import annotations

import pathlib

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text())
KEYCLOAK = COMPOSE["services"]["keycloak"]
KEYCLOAK_DB = COMPOSE["services"]["keycloak-db"]


def test_idp_services_are_opt_in_via_the_idp_profile():
    assert KEYCLOAK["profiles"] == ["idp"]
    assert KEYCLOAK_DB["profiles"] == ["idp"]


def test_keycloak_is_control_plane_reachable_only_never_on_the_run_network():
    assert sorted(KEYCLOAK["networks"]) == ["andyur-control", "andyur-idp"]
    assert "andyur-runs" not in KEYCLOAK["networks"]


def test_idp_database_sits_on_an_internal_segment_with_no_published_port():
    assert KEYCLOAK_DB["networks"] == ["andyur-idp"]
    assert "ports" not in KEYCLOAK_DB
    assert COMPOSE["networks"]["andyur-idp"]["internal"] is True


def test_no_other_service_joins_the_idp_database_segment():
    # The internal segment admits only the IdP pair: any third service on it
    # would be a route into the IdP's database. The live gate asserts the same
    # exclusivity against the running network's actual membership.
    members = {name for name, svc in COMPOSE["services"].items()
               if "andyur-idp" in (svc.get("networks") or [])}
    assert members == {"keycloak", "keycloak-db"}


def test_keycloak_publishes_on_loopback_only():
    ports = KEYCLOAK["ports"]
    assert len(ports) == 1
    assert ports[0].startswith("127.0.0.1:")


def test_idp_refuses_to_boot_without_generated_secrets():
    # The wrapper generates the secrets; compose itself must fail closed if
    # someone bypasses it, so no default-credential IdP can come up.
    command = "\n".join(KEYCLOAK["command"])
    assert "KC_BOOTSTRAP_ADMIN_PASSWORD:?" in command
    assert "KC_DB_PASSWORD:?" in command
    assert KEYCLOAK["environment"]["KC_BOOTSTRAP_ADMIN_PASSWORD"] == "${ANDYUR_IDP_ADMIN_PASSWORD:-}"
    assert KEYCLOAK_DB["environment"]["POSTGRES_PASSWORD"] == "${ANDYUR_IDP_DB_PASSWORD:-}"


def test_keycloak_imports_the_bundled_demo_realm_read_only():
    mounts = [v for v in KEYCLOAK["volumes"] if "realm-andyur.json" in v]
    assert len(mounts) == 1
    source = mounts[0].split(":")[0]
    assert mounts[0].endswith(":ro")
    assert (ROOT / "infra" / source).resolve().is_file()


def test_canonical_issuer_and_publish_share_one_port_variable():
    # KC_HOSTNAME (the iss in every token) and the host publish must agree, or
    # browser-obtained tokens fail validation at the server. One variable
    # keeps them one fact.
    assert "127.0.0.1:${ANDYUR_IDP_PORT:-8480}" in KEYCLOAK["environment"]["KC_HOSTNAME"]
    assert KEYCLOAK["ports"][0].startswith("127.0.0.1:${ANDYUR_IDP_PORT:-8480}:")


def test_control_plane_exposes_the_oidc_seam_off_by_default():
    env = COMPOSE["services"]["andyur-server"]["environment"]
    assert env["ANDYUR_USER_AUTH"] == "${ANDYUR_USER_AUTH:-off}"
    for key in ("ANDYUR_OIDC_ISSUER", "ANDYUR_OIDC_JWKS", "ANDYUR_OIDC_AUDIENCE",
                "ANDYUR_ADMIN_ROLE"):
        assert env[key] == "${%s:-}" % key

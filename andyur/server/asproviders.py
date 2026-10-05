"""Authorization-server protocol profiles and capability ceilings.

This module translates Andyur's sealed authority envelope to a vendor's token
request. It never narrows policy and never guesses that a vendor supplied a
guarantee which its documented protocol cannot represent.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from dataclasses import dataclass
from enum import Enum


class Capability(str, Enum):
    CORE = "core"
    DELEGATED = "delegated"
    CONTEXTUAL = "contextual"


CAPABILITY_NAMES = {item.value: item for item in Capability}
CAPABILITY_REQUIREMENTS = {
    Capability.CORE: frozenset({"core"}),
    Capability.DELEGATED: frozenset({"core", "delegated"}),
    Capability.CONTEXTUAL: frozenset({"core", "delegated", "contextual"}),
}

# Capabilities the platform knows about but must not offer, each with the
# reason. Sender-binding is a TWO-party property: the AS putting `cnf` in the
# token is worthless until the RESOURCE compares that binding against the live
# TLS client certificate or a DPoP proof, and no Andyur tool path performs
# that comparison yet (current-token-flow.md tracks it). An issuance-side
# check alone would let a tenant configure a guarantee nothing enforces.
_UNDELIVERABLE_CAPABILITIES = {
    "sender-bound": (
        "the 'sender-bound' capability is not offered: it requires the "
        "resource server to verify the token's cnf binding against the live "
        "TLS certificate or DPoP proof, and no Andyur tool path performs "
        "that verification yet. Use 'contextual'; the issued token remains "
        "a bearer token and must be handled as one"),
}


@dataclass(frozen=True)
class Provider:
    name: str
    guarantees: frozenset[str]
    request_profile: str
    encoding: str = "form"
    client_auth_method: str = "client_secret_basic"


PROVIDERS = {
    "reference": Provider("reference",
                          frozenset({"core", "delegated", "contextual"}), "rfc8693",
                          client_auth_method="client_secret_post"),
    "keycloak": Provider("keycloak", frozenset({"core"}), "keycloak-v2"),
    "entra": Provider("entra", frozenset({"core"}), "entra-obo",
                      client_auth_method="client_secret_post"),
    "okta": Provider("okta", frozenset({"core"}), "okta-obo"),
    # An Auth0 Action or Ping policy can add stronger semantics, but an adapter
    # cannot certify tenant configuration. Live certification promotes these.
    "auth0": Provider("auth0", frozenset({"core"}), "auth0-obo", "json",
                      "client_secret_post"),
    "pingfederate": Provider("pingfederate", frozenset({"core"}),
                             "pingfederate-rfc8693"),
    # PingAM delegation accepts only an AM-issued access/ID actor token, not a
    # SPIFFE JWT-SVID. The core profile therefore uses impersonation syntax and
    # transmits no actor; downstream subject/audience/scope are still verified.
    "pingam": Provider("pingam", frozenset({"core"}), "pingam-core"),
}

GRANT_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_JWT = "urn:ietf:params:oauth:token-type:jwt"


class ProviderConfigurationError(ValueError):
    pass


ENTRA_SCOPE_MAP_SCHEMA = "andyur-entra-scope-map/v1"
# The reference AS speaks a fixed vocabulary (telemetry:read, tickets:*) while
# the registry names its own logical actions (obs:read, tickets:comment). A run
# through the reference provider therefore needs the SAME action->provider-scope
# translation Entra already has (ADR-010: the map is the shape of every provider
# profile, not an Entra special case). The reference AS uses one scope string
# both to request and to assert, so its map's `request` and `claim` are equal.
REFERENCE_SCOPE_MAP_SCHEMA = "andyur-reference-scope-map/v1"


def _action_scope_map(raw: str, schema: str, label: str) -> dict:
    """Parse and strictly validate a closed action->{request,claim} scope map.

    Shared by every provider that translates Andyur's sealed actions to a
    vendor's scope vocabulary; `schema`/`label` name whose map it is."""
    if not raw or len(raw.encode("utf-8")) > 64 << 10:
        raise ProviderConfigurationError(
            f"ANDYUR_AS_RESOURCE_SCOPE must contain a bounded {label} scope map")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderConfigurationError(
            f"ANDYUR_AS_RESOURCE_SCOPE is not valid {label} scope-map JSON") from exc
    if not isinstance(document, dict) or set(document) != {"schema", "actions"} \
            or document.get("schema") != schema \
            or not isinstance(document.get("actions"), dict):
        raise ProviderConfigurationError(
            f"{label} scope map must use the closed {schema} schema")
    if not document["actions"]:
        raise ProviderConfigurationError(f"{label} scope map actions must not be empty")
    for action, entry in document["actions"].items():
        if not isinstance(action, str) or not action.strip() \
                or not isinstance(entry, dict) \
                or set(entry) != {"request", "claim"} \
                or not all(isinstance(entry.get(k), str) and entry[k]
                           and not any(ch.isspace() for ch in entry[k])
                           for k in ("request", "claim")):
            raise ProviderConfigurationError(
                f"every {label} action mapping must contain one exact non-empty "
                "request scope and one exact non-empty claim scope")
    return document["actions"]


def _entra_scope_map(raw: str) -> dict:
    return _action_scope_map(raw, ENTRA_SCOPE_MAP_SCHEMA, "Entra")


def _scope_mapping(raw: str, scope: str | list[str] | None,
                   schema: str, label: str) -> tuple[str, frozenset[str]]:
    """Translate the sealed Andyur actions a run asked for to the exact provider
    request scopes, returning (request_string, expected_claim_scopes). A mapping
    that is missing any asked action FAILS -- silently dropping one would issue a
    token narrower than the run's authority and read as a tool bug later."""
    actions = _action_scope_map(raw, schema, label)
    asked = scope.split() if isinstance(scope, str) else list(scope or [])
    if not asked:
        raise ProviderConfigurationError(f"{label} exchange requires at least one action scope")
    requests: list[str] = []
    claims: set[str] = set()
    for action in asked:
        entry = actions.get(action)
        if entry is None:
            raise ProviderConfigurationError(
                f"{label} scope map has no exact request/claim mapping for action {action!r}")
        requests.append(entry["request"])
        claims.add(entry["claim"])
    return " ".join(requests), frozenset(claims)


def entra_scope_mapping(raw: str, scope: str | list[str] | None) \
        -> tuple[str, frozenset[str]]:
    """Translate sealed Andyur actions to exact Entra request/claim scopes."""
    return _scope_mapping(raw, scope, ENTRA_SCOPE_MAP_SCHEMA, "Entra")


def reference_scope_mapping(raw: str, scope: str | list[str] | None) \
        -> tuple[str, frozenset[str]]:
    """Translate the registry's logical actions to the reference AS's fixed
    vocabulary (e.g. obs:read -> telemetry:read). Applied only when a map is
    configured; without one the reference provider passes scopes through, which
    is how the actor-leg proof drives it with AS-vocabulary scopes directly."""
    return _scope_mapping(raw, scope, REFERENCE_SCOPE_MAP_SCHEMA, "reference")


def provider(name: str) -> Provider:
    try:
        return PROVIDERS[name]
    except KeyError as exc:
        raise ProviderConfigurationError(
            f"unknown authorization-server provider {name!r}; use one of: "
            f"{', '.join(sorted(PROVIDERS))}") from exc


def capability(name: str) -> Capability:
    if name in _UNDELIVERABLE_CAPABILITIES:
        raise ProviderConfigurationError(_UNDELIVERABLE_CAPABILITIES[name])
    try:
        return CAPABILITY_NAMES[name]
    except KeyError as exc:
        raise ProviderConfigurationError(
            f"unknown authorization capability {name!r}; use one of: "
            f"{', '.join(CAPABILITY_NAMES)}") from exc


def validate(provider_name: str, capability_name: str) -> list[str]:
    """Return configuration problems without raising during config import."""
    try:
        selected = provider(provider_name)
        required = capability(capability_name)
    except ProviderConfigurationError as exc:
        return [str(exc)]
    needed = CAPABILITY_REQUIREMENTS[required]
    if not needed.issubset(selected.guarantees):
        return [
            f"ANDYUR_AS_PROVIDER={selected.name} does not have built-in "
            f"support for {capability_name}; supported: "
            f"{', '.join(sorted(selected.guarantees))}. "
            f"ANDYUR_AS_CAPABILITY={capability_name} claims a guarantee that "
            "this adapter cannot verify"
        ]
    return []


def subject_identity(provider_name: str, claims: dict) -> str:
    """Return the provider-stable identity represented by verified claims.

    Entra's ``sub`` is pairwise and can change between the login client and the
    downstream resource.  ``tid`` + ``oid`` identifies the same object within
    the same tenant across those audiences. Other profiles preserve ``sub``.
    """
    selected = provider(provider_name)
    if selected.name == "entra":
        tenant, object_id = claims.get("tid"), claims.get("oid")
        if not all(isinstance(value, str) and value.strip()
                   for value in (tenant, object_id)):
            raise ProviderConfigurationError(
                "Entra subject continuity requires non-empty tid and oid claims")
        return json.dumps([tenant, object_id], separators=(",", ":"))
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ProviderConfigurationError(
            f"{selected.name} subject continuity requires a non-empty sub claim")
    return subject


def request_encoding(provider_name: str) -> str:
    return provider(provider_name).encoding


def client_auth_method(provider_name: str) -> str:
    """Return the authentication method the selected adapter puts on the wire."""
    return provider(provider_name).client_auth_method


def requires_issued_token_type(provider_name: str) -> bool:
    return provider(provider_name).request_profile != "entra-obo"


def _basic(client_id: str, client_secret: str, provider_name: str) -> str:
    if not client_id or not client_secret:
        raise ProviderConfigurationError(
            f"{provider_name} requires a confidential client using HTTP Basic")
    encoded_id = urllib.parse.quote_plus(client_id, safe="")
    encoded_secret = urllib.parse.quote_plus(client_secret, safe="")
    raw = base64.b64encode(
        f"{encoded_id}:{encoded_secret}".encode("utf-8")).decode()
    return f"Basic {raw}"


def _apply_client_auth(selected: Provider, form: dict[str, str],
                       client_id: str, client_secret: str) \
        -> tuple[dict[str, str], dict[str, str]]:
    """Apply the same typed auth selector exported to overlay validation."""
    if selected.client_auth_method == "client_secret_basic":
        form.pop("client_id", None)
        return form, {"Authorization": _basic(
            client_id, client_secret, selected.name)}
    if selected.client_auth_method == "client_secret_post":
        if not client_id or not client_secret:
            raise ProviderConfigurationError(
                f"{selected.name} requires client_id and client_secret in the request body")
        form["client_id"] = client_id
        form["client_secret"] = client_secret
        return form, {}
    raise ProviderConfigurationError(
        f"{selected.name} has unsupported client-auth method "
        f"{selected.client_auth_method!r}")


def build_request(*, provider_name: str, client_id: str,
                  client_secret: str, subject_token: str, actor_token: str,
                  audience: str | None, resource: str | None,
                  scope: str | None, authorization_details: str | None,
                  provider_scope: str | None = None,
                  ) -> tuple[dict[str, str], dict[str, str]]:
    """Build the exact form and extra headers for one provider profile."""
    selected = provider(provider_name)
    target = resource or audience
    if selected.request_profile == "entra-obo":
        if not client_secret:
            raise ProviderConfigurationError(
                "Entra OBO currently requires a client secret; managed identity, "
                "certificate and private-key JWT modes are not configured")
        if not provider_scope:
            raise ProviderConfigurationError(
                "Entra OBO requires ANDYUR_AS_RESOURCE_SCOPE naming the exact "
                "downstream API scope; Andyur action scopes are not Entra scopes")
        form = {
            "client_id": client_id,
            "grant_type": GRANT_JWT_BEARER,
            "assertion": subject_token,
            "requested_token_use": "on_behalf_of",
            "scope": provider_scope,
        }
        return _apply_client_auth(selected, form, client_id, client_secret)

    if selected.request_profile == "auth0-obo":
        target = audience or resource
        if not target:
            raise ProviderConfigurationError(
                "Auth0 OBO requires the downstream API audience")
        if not client_id or not client_secret:
            raise ProviderConfigurationError(
                "Auth0 OBO requires an authenticated Custom API client")
        form = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": GRANT_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": TOKEN_ACCESS,
            "requested_token_type": TOKEN_ACCESS,
            "audience": target,
        }
        if scope:
            form["scope"] = scope
        return _apply_client_auth(selected, form, client_id, client_secret)

    form = {
        "grant_type": GRANT_EXCHANGE,
        "subject_token": subject_token,
        "subject_token_type": TOKEN_ACCESS,
    }
    if client_id and selected.request_profile == "rfc8693":
        form["client_id"] = client_id
    if actor_token and selected.request_profile in {
            "rfc8693", "pingfederate-rfc8693"}:
        form["actor_token"] = actor_token
        form["actor_token_type"] = TOKEN_JWT
    if selected.request_profile in {
            "keycloak-v2", "okta-obo", "pingfederate-rfc8693", "pingam-core"}:
        form["requested_token_type"] = TOKEN_ACCESS
    if audience and selected.request_profile != "pingam-core":
        form["audience"] = audience
    if resource and selected.request_profile in {
            "rfc8693", "pingfederate-rfc8693"}:
        form["resource"] = resource
    if scope:
        form["scope"] = scope
    if authorization_details and selected.request_profile == "rfc8693":
        form["authorization_details"] = authorization_details

    return _apply_client_auth(selected, form, client_id, client_secret)

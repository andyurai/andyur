from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


SCHEMA = "andyur-as-provision/v1"
PROVIDERS = frozenset({"entra", "okta", "auth0", "pingfederate", "pingam"})
_NAME = re.compile(r"^[a-z][a-z0-9-]{2,39}$")
_ACTION = re.compile(r"^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_.-]*$")
_TOP = frozenset({"schema", "provider", "name_prefix", "actions", "config"})
_CONFIG = {
    "entra": frozenset({"tenant_id", "redirect_uri", "middle_identifier",
                         "downstream_identifier"}),
    "okta": frozenset({"org_name", "base_url", "authorization_server_id",
                        "redirect_uri"}),
    "auth0": frozenset({"domain", "source_audience", "target_audience",
                         "redirect_uri"}),
    "pingfederate": frozenset({"issuer", "token_endpoint", "jwks_url"}),
    "pingam": frozenset({"issuer", "token_endpoint", "jwks_url"}),
}


class ProvisionSpecError(ValueError):
    pass


@dataclass(frozen=True)
class ProvisionSpec:
    provider: str
    name_prefix: str
    actions: dict[str, str]
    config: dict[str, str]


def load_spec(path: str) -> ProvisionSpec:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read((64 << 10) + 1)
    except OSError as exc:
        raise ProvisionSpecError(f"cannot read provisioning spec: {type(exc).__name__}") from exc
    if len(raw) > 64 << 10:
        raise ProvisionSpecError("provisioning spec exceeds 64 KiB")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvisionSpecError("provisioning spec is not UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != _TOP:
        raise ProvisionSpecError("provisioning spec must use the closed v1 top-level schema")
    if document.get("schema") != SCHEMA:
        raise ProvisionSpecError(f"provisioning schema must be {SCHEMA}")
    provider = document.get("provider")
    if provider not in PROVIDERS:
        raise ProvisionSpecError(f"provider must be one of: {', '.join(sorted(PROVIDERS))}")
    name = document.get("name_prefix")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ProvisionSpecError("name_prefix must be a lowercase DNS-style name (3-40 chars)")
    actions = document.get("actions")
    if not isinstance(actions, dict) or not actions:
        raise ProvisionSpecError("actions must be a non-empty object")
    for action, scope in actions.items():
        if not isinstance(action, str) or not _ACTION.fullmatch(action):
            raise ProvisionSpecError(f"invalid Andyur action {action!r}")
        if not isinstance(scope, str) or not scope or any(ch.isspace() for ch in scope):
            raise ProvisionSpecError(f"provider scope for {action!r} must be one token")
    config = document.get("config")
    if not isinstance(config, dict) or set(config) != _CONFIG[provider]:
        raise ProvisionSpecError(
            f"{provider} config fields must be exactly: {', '.join(sorted(_CONFIG[provider]))}")
    if not all(isinstance(value, str) and value.strip() for value in config.values()):
        raise ProvisionSpecError("every provider config value must be a non-empty string")
    for field in ("redirect_uri", "issuer", "token_endpoint", "jwks_url",
                  "source_audience", "target_audience", "middle_identifier",
                  "downstream_identifier"):
        value = config.get(field)
        if value and not value.startswith("https://") and not value.startswith("api://"):
            raise ProvisionSpecError(f"{field} must use https:// or api://")
    return ProvisionSpec(provider, name, dict(sorted(actions.items())), config)

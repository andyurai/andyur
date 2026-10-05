from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path

from .model import ProvisionSpec


VERSIONS = {"entra": "3.9.0", "azuread": "3.9.0", "okta": "6.13.0",
            "auth0": "1.53.0"}


def _hcl_string(value: str) -> str:
    return json.dumps(value)


def _header(provider: str, source: str) -> str:
    return f'''terraform {{
  required_version = ">= 1.11.0, < 2.0.0"
  required_providers {{
    {provider} = {{ source = "{source}", version = "= {VERSIONS[provider]}" }}
  }}
}}
'''


def _entra(spec: ProvisionSpec) -> tuple[str, dict]:
    middle_scope_id = str(uuid.uuid5(
        uuid.NAMESPACE_URL, f"andyur:{spec.name_prefix}:access_as_user"))
    scope_ids = {action: str(uuid.uuid5(uuid.NAMESPACE_URL,
                 f"andyur:{spec.name_prefix}:{action}")) for action in spec.actions}
    blocks = "\n".join(f'''    oauth2_permission_scope {{
      admin_consent_description  = "Andyur development access for {action}"
      admin_consent_display_name = "{action}"
      enabled                    = true
      id                         = var.scope_ids[{_hcl_string(action)}]
      type                       = "User"
      user_consent_description   = "Allow Andyur development access for {action}"
      user_consent_display_name  = "{action}"
      value                      = var.actions[{_hcl_string(action)}]
    }}''' for action in spec.actions)
    access = "\n".join(f'''    resource_access {{
      id   = azuread_application.downstream.oauth2_permission_scope_ids[{_hcl_string(scope)}]
      type = "Scope"
    }}''' for scope in spec.actions.values())
    main = _header("azuread", "hashicorp/azuread") + f'''
provider "azuread" {{
  tenant_id = var.tenant_id
}}
data "azuread_client_config" "current" {{}}

variable "tenant_id" {{ type = string }}
variable "name_prefix" {{ type = string }}
variable "redirect_uri" {{ type = string }}
variable "middle_identifier" {{ type = string }}
variable "downstream_identifier" {{ type = string }}
variable "actions" {{ type = map(string) }}
variable "scope_ids" {{ type = map(string) }}
variable "middle_scope_id" {{ type = string }}

resource "azuread_application" "downstream" {{
  display_name            = "${{var.name_prefix}}-downstream-api"
  identifier_uris         = [var.downstream_identifier]
  owners                  = [data.azuread_client_config.current.object_id]
  prevent_duplicate_names = true
  sign_in_audience        = "AzureADMyOrg"
  api {{
    requested_access_token_version = 2
{blocks}
  }}
}}
resource "azuread_service_principal" "downstream" {{
  client_id = azuread_application.downstream.client_id
  owners    = [data.azuread_client_config.current.object_id]
}}

resource "azuread_application" "middle" {{
  display_name            = "${{var.name_prefix}}-middle-tier"
  owners                  = [data.azuread_client_config.current.object_id]
  prevent_duplicate_names = true
  sign_in_audience        = "AzureADMyOrg"
  identifier_uris         = [var.middle_identifier]
  api {{
    requested_access_token_version = 2
    oauth2_permission_scope {{
      admin_consent_description  = "Allow Andyur development login"
      admin_consent_display_name = "Andyur development login"
      enabled                    = true
      id                         = var.middle_scope_id
      type                       = "User"
      user_consent_description   = "Allow Andyur development login"
      user_consent_display_name  = "Andyur development login"
      value                      = "access_as_user"
    }}
  }}
  required_resource_access {{
    resource_app_id = azuread_application.downstream.client_id
{access}
  }}
}}
resource "azuread_service_principal" "middle" {{
  client_id = azuread_application.middle.client_id
  owners    = [data.azuread_client_config.current.object_id]
}}
resource "azuread_application_password" "middle" {{
  application_id = azuread_application.middle.id
  display_name   = "andyur-development"
}}

resource "azuread_application" "login" {{
  display_name            = "${{var.name_prefix}}-test-login"
  owners                  = [data.azuread_client_config.current.object_id]
  prevent_duplicate_names = true
  sign_in_audience        = "AzureADMyOrg"
  public_client {{ redirect_uris = [var.redirect_uri] }}
  required_resource_access {{
    resource_app_id = azuread_application.middle.client_id
    resource_access {{
      id   = azuread_application.middle.oauth2_permission_scope_ids["access_as_user"]
      type = "Scope"
    }}
  }}
}}
resource "azuread_service_principal" "login" {{
  client_id = azuread_application.login.client_id
  owners    = [data.azuread_client_config.current.object_id]
}}

output "andyur_client_id" {{
  value = azuread_application.middle.client_id
}}
output "andyur_client_secret" {{
  value     = azuread_application_password.middle.value
  sensitive = true
}}
output "login_client_id" {{
  value = azuread_application.login.client_id
}}
output "downstream_audience" {{
  value = var.downstream_identifier
}}
output "source_audience" {{
  value = var.middle_identifier
}}
'''
    values = {**spec.config, "name_prefix": spec.name_prefix,
              "actions": spec.actions, "scope_ids": scope_ids,
              "middle_scope_id": middle_scope_id}
    return main, values


def _okta(spec: ProvisionSpec) -> tuple[str, dict]:
    main = _header("okta", "okta/okta") + '''
provider "okta" {
  org_name = var.org_name
  base_url = var.base_url
}
variable "org_name" { type = string }
variable "base_url" { type = string }
variable "authorization_server_id" { type = string }
variable "name_prefix" { type = string }
variable "redirect_uri" { type = string }
variable "actions" { type = map(string) }

resource "okta_app_oauth" "login" {
  label = "${var.name_prefix}-test-login"
  type = "native"
  grant_types = ["authorization_code"]
  response_types = ["code"]
  redirect_uris = [var.redirect_uri]
  token_endpoint_auth_method = "none"
}
resource "okta_app_oauth" "middle" {
  label = "${var.name_prefix}-middle-tier"
  type = "service"
  grant_types = ["urn:ietf:params:oauth:grant-type:token-exchange"]
  response_types = ["token"]
  token_endpoint_auth_method = "client_secret_basic"
}
resource "okta_auth_server_scope" "action" {
  for_each = var.actions
  auth_server_id = var.authorization_server_id
  name = each.value
  description = "Andyur action ${each.key}"
  consent = "IMPLICIT"
  metadata_publish = "NO_CLIENTS"
}
resource "okta_auth_server_policy" "middle" {
  auth_server_id = var.authorization_server_id
  status = "ACTIVE"
  name = "${var.name_prefix}-token-exchange"
  description = "Andyur-owned development token exchange"
  priority = 1
  client_whitelist = [okta_app_oauth.middle.client_id]
}
resource "okta_auth_server_policy_rule" "middle" {
  auth_server_id = var.authorization_server_id
  policy_id = okta_auth_server_policy.middle.id
  status = "ACTIVE"
  name = "${var.name_prefix}-token-exchange"
  priority = 1
  group_whitelist = ["EVERYONE"]
  grant_type_whitelist = ["urn:ietf:params:oauth:grant-type:token-exchange"]
  scope_whitelist = values(okta_auth_server_scope.action)[*].name
}
output "andyur_client_id" {
  value = okta_app_oauth.middle.client_id
}
output "andyur_client_secret" {
  value     = okta_app_oauth.middle.client_secret
  sensitive = true
}
output "login_client_id" {
  value = okta_app_oauth.login.client_id
}
'''
    return main, {**spec.config, "name_prefix": spec.name_prefix,
                  "actions": spec.actions}


def _auth0(spec: ProvisionSpec) -> tuple[str, dict]:
    main = _header("auth0", "auth0/auth0") + '''
provider "auth0" {
  domain = var.domain
}
variable "domain" { type = string }
variable "name_prefix" { type = string }
variable "source_audience" { type = string }
variable "target_audience" { type = string }
variable "redirect_uri" { type = string }
variable "actions" { type = map(string) }

resource "auth0_resource_server" "source" {
  name = "${var.name_prefix}-source-api"
  identifier = var.source_audience
  signing_alg = "RS256"
  token_lifetime = 300
  enforce_policies = true
  token_dialect = "access_token_authz"
}
resource "auth0_resource_server" "target" {
  name = "${var.name_prefix}-target-api"
  identifier = var.target_audience
  signing_alg = "RS256"
  token_lifetime = 300
  enforce_policies = true
  token_dialect = "access_token_authz"
}
resource "auth0_resource_server_scopes" "target" {
  resource_server_identifier = auth0_resource_server.target.identifier
  dynamic "scopes" {
    for_each = var.actions
    content {
      name        = scopes.value
      description = "Andyur action ${scopes.key}"
    }
  }
}
resource "auth0_client" "middle" {
  name = "${var.name_prefix}-middle-tier"
  app_type = "resource_server"
  is_first_party = true
  resource_server_identifier = auth0_resource_server.source.identifier
  grant_types = ["urn:ietf:params:oauth:grant-type:token-exchange"]
  token_exchange { allow_any_profile_of_type = ["on_behalf_of_token_exchange"] }
}
resource "auth0_client_credentials" "middle" {
  client_id             = auth0_client.middle.client_id
  authentication_method = "client_secret_post"
}
resource "auth0_client_grant" "delegated" {
  client_id = auth0_client.middle.client_id
  audience = auth0_resource_server.target.identifier
  scopes = values(var.actions)
  subject_type = "user"
}
resource "auth0_client" "login" {
  name = "${var.name_prefix}-test-login"
  app_type = "spa"
  is_first_party = true
  callbacks = [var.redirect_uri]
  grant_types = ["authorization_code"]
}
output "andyur_client_id" {
  value = auth0_client.middle.client_id
}
output "andyur_client_secret" {
  value     = auth0_client_credentials.middle.client_secret
  sensitive = true
}
output "login_client_id" {
  value = auth0_client.login.client_id
}
'''
    return main, {**spec.config, "name_prefix": spec.name_prefix,
                  "actions": spec.actions}


def _ping(spec: ProvisionSpec) -> tuple[str, dict]:
    bundle = {
        "schema": "andyur-ping-provision/v1", "provider": spec.provider,
        "owner": "andyur-development", "name_prefix": spec.name_prefix,
        "actions": spec.actions, "oauth": spec.config,
        "requirements": (["token-exchange processor policy", "subject-token processor",
                           "actor-token processor", "access-token manager"]
                         if spec.provider == "pingfederate" else
                         ["OAuth2 May Act script", "token exchanger plugin",
                          "token validator plugin", "token-exchange client"]),
    }
    return json.dumps(bundle, sort_keys=True, indent=2) + "\n", {}


def render(spec: ProvisionSpec, output: str) -> dict[str, str]:
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("output directory must be empty; refusing to overwrite state")
    if spec.provider == "entra":
        main, values = _entra(spec)
        files = {"main.tf": main, "terraform.tfvars.json": json.dumps(values, indent=2) + "\n"}
    elif spec.provider == "okta":
        main, values = _okta(spec)
        files = {"main.tf": main, "terraform.tfvars.json": json.dumps(values, indent=2) + "\n"}
    elif spec.provider == "auth0":
        main, values = _auth0(spec)
        files = {"main.tf": main, "terraform.tfvars.json": json.dumps(values, indent=2) + "\n"}
    else:
        bundle, _ = _ping(spec)
        files = {f"{spec.provider}-import.json": bundle}
    digests = {}
    for name, content in files.items():
        target = destination / name
        fd, temporary = tempfile.mkstemp(prefix=".as-provision-", dir=destination)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content); handle.flush(); os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            try: os.unlink(temporary)
            except FileNotFoundError: pass
        digests[name] = hashlib.sha256(content.encode()).hexdigest()
    manifest = {"schema": "andyur-as-provision-render/v1", "provider": spec.provider,
                "files": digests}
    (destination / "render-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    os.chmod(destination / "render-manifest.json", 0o600)
    return manifest

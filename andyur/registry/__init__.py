"""Andyur agent registry.

The read side of the locked contract: immutable authority plus, for C2 BYOA,
the optional immutable executable identity consumed by production launchers.

WHO MAY READ IT: EVERY AUTHENTICATED OPERATOR, AND THAT IS THE DESIGN.

The registry is a SHARED CATALOG OF APPROVED DEFINITIONS, not per-tenant
storage. It has no owner axis, `resolve_agent` takes no user token, and a
caller entitled to instantiate an agent from a definition is entitled to read
that definition -- including its `registry_digest`, its `image_ref`, its
`image_digest` and its full `command` argv. Under `ANDYUR_USER_AUTH=on` the
console allowlists this route for the browser, so that reach extends to any
signed-in console user.

This is written down because it was previously only implied, and a reviewer
reasonably read the absence of an owner axis as an oversight rather than a
decision (`ROADMAP.md` 34). An adopter who needs per-tenant
catalogs is not served by this component as it stands and should say so early:
adding the axis means an owner column, the user token plumbed through
`resolve_agent`, and the console's allowlist entry carrying it.

WHAT DOES NOT FOLLOW from that decision: a manifest's `credential_ref` names a
brokered secret, and "readable by anyone entitled to instantiate" is a weaker
claim than "readable by anyone who can authenticate as an operator". Whether a
credential reference belongs in a shared catalog at all is open and is tracked
on that same row -- the authority above covers image and command identity, not
secrets material.
"""

from .manifest_registry import ManifestAgentRegistry
from .models import (
    AgentNotFound,
    AgentCatalog,
    AgentRegistry,
    AgentResolution,
    AuthorityCeiling,
    AuthorityMode,
    InvalidAgentManifest,
    McpToolGrant,
    RegistryUnavailable,
    ResourceSpec,
    RuntimeResolution,
    RuntimeType,
    ToolBinding,
)
from .service import configured_registry

__all__ = [
    "AgentNotFound",
    "AgentCatalog",
    "AgentRegistry",
    "AgentResolution",
    "AuthorityCeiling",
    "AuthorityMode",
    "InvalidAgentManifest",
    "McpToolGrant",
    "RegistryUnavailable",
    "ManifestAgentRegistry",
    "ResourceSpec",
    "RuntimeResolution",
    "RuntimeType",
    "ToolBinding",
    "configured_registry",
]

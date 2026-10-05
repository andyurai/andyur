"""The developer-facing agent specification: AgentManifest v1 and its compiler.

This package is the request side of the BYOA split (ADR-008). A developer
publishes an AgentManifest -- what the agent is, how it is packaged, and what
it ASKS for. Platform policy owns what is GRANTED. `compile_resolution` is the
one place the two meet, and it can only narrow: nothing in a manifest can add
an action, resource, tool, or model that policy did not already approve.

Deliberately separate from `andyur.registry`, whose "manifest" files are the
platform-side resolution snapshots (`andyur.agent-resolution/v1`). One package
per meaning: `agentspec` holds requests, `registry` holds grants.
"""

from .models import (
    AgentManifest,
    CompiledAgent,
    ImageRef,
    InvalidManifest,
    ManifestDenied,
    ManifestMetadata,
    PlatformPolicy,
    ResourceSpec,
    RuntimeResolution,
    RuntimeSpec,
    ToolRequest,
)
from .parser import PROTOCOL_V1, load_manifest, manifest_digest, parse_manifest
from .compiler import compile_resolution

__all__ = [
    "AgentManifest",
    "CompiledAgent",
    "ImageRef",
    "InvalidManifest",
    "ManifestDenied",
    "ManifestMetadata",
    "PlatformPolicy",
    "PROTOCOL_V1",
    "ResourceSpec",
    "RuntimeResolution",
    "RuntimeSpec",
    "ToolRequest",
    "compile_resolution",
    "load_manifest",
    "manifest_digest",
    "parse_manifest",
]

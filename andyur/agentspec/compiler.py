"""compile_resolution: the one place a request meets platform policy.

Authority can only narrow. The manifest brings identity, packaging and requests;
policy brings approved tools, ceiling and models. The output is one immutable
AgentResolution containing both the granted authority and the approved runtime
identity, so production scheduling cannot choose executable bytes independently.
"""

from __future__ import annotations

import dataclasses

from ..registry.manifest_registry import SCHEMA_VERSION, _parse_manifest
from ..registry.models import (LIFETIME_CEILING_SECONDS,
                              LIFETIME_FLOOR_SECONDS,
                              AuthorityCeiling, InvalidAgentManifest,
                              LifecycleSpec, ToolBinding)
from .models import (
    AgentManifest,
    CompiledAgent,
    InconsistentPolicy,
    ManifestDenied,
    PlatformPolicy,
    RuntimeResolution,
)
from .parser import manifest_digest


def _grant_tool(server: str, requested: tuple[str, ...],
                approved: ToolBinding) -> ToolBinding:
    """Narrow one approved catalog binding to exactly the requested tools."""
    if approved.authority == "passthrough":
        raise ManifestDenied(
            f"capabilities: server {server!r} is passthrough; per-tool "
            "requests need a managed enforcement point")
    if approved.mcp_tools is None:
        raise ManifestDenied(
            f"capabilities: policy does not enumerate per-tool grants for "
            f"server {server!r}; a per-tool request cannot be compiled "
            "against an audience-level catalog entry")
    approved_names = {grant.name for grant in approved.mcp_tools}
    requested_set = set(requested)
    excess = sorted(requested_set - approved_names)
    if excess:
        raise ManifestDenied(
            f"capabilities: server {server!r} does not approve tool(s) "
            f"{excess}; approved: {sorted(approved_names)}")
    narrowed = tuple(grant for grant in approved.mcp_tools
                     if grant.name in requested_set)
    return dataclasses.replace(approved, mcp_tools=narrowed)


def _grant_lifecycle(requested, policy: PlatformPolicy) -> LifecycleSpec | None:
    """Intersect a requested lifetime with the policy ceiling.

    Duration is a PREFERENCE, so an over-long request narrows to the ceiling the
    way `_narrow_ceiling` drops undeclared resources.

    Service mode is refused unconditionally, and there is deliberately no policy
    that enables it. The runtime cannot deliver a resident agent yet, so no
    configuration should be able to promise one. The parser refuses it first;
    this is the second gate, because a compiler fed a manifest object built in
    code rather than parsed from a document must reach the same answer.
    """
    if requested is None:
        return None
    ceiling = policy.max_lifetime_seconds
    if ceiling is not None and not (
            LIFETIME_FLOOR_SECONDS <= ceiling <= LIFETIME_CEILING_SECONDS):
        # A ceiling below the floor narrows every request into a lifecycle the
        # overlay validator then refuses, and the operator sees an unhandled
        # traceback naming one agent's runtime overlay rather than the flag they
        # set. Refuse the POLICY, and say so.
        raise InconsistentPolicy(
            f"policy lifetime ceiling {ceiling} is outside the permitted "
            f"{LIFETIME_FLOOR_SECONDS}..{LIFETIME_CEILING_SECONDS} seconds; no "
            "manifest could be compiled against it")
    if policy.max_lifetime_seconds is None:
        raise ManifestDenied(
            "runtime.lifecycle: this platform grants no lifetime ceiling, so no "
            "manifest may declare a lifecycle; the platform default applies")
    if requested.mode != "task":
        raise ManifestDenied(
            f"runtime.lifecycle: mode {requested.mode!r} cannot be granted; the "
            "runtime serves one invocation per run and no policy may promise "
            "otherwise")

    max_seconds = min(requested.max_seconds, policy.max_lifetime_seconds)
    idle_seconds = requested.idle_seconds
    # Narrowing the wall clock can strand an idle window above it, where it
    # could never fire. Carry the same intersection down rather than emitting a
    # resolution the overlay validator would refuse.
    if idle_seconds is not None:
        idle_seconds = min(idle_seconds, max_seconds)
    return LifecycleSpec(mode=requested.mode, max_seconds=max_seconds,
                         idle_seconds=idle_seconds, on_exit=requested.on_exit)


def _narrow_ceiling(ceiling: AuthorityCeiling,
                    granted: tuple[ToolBinding, ...]) -> AuthorityCeiling:
    """Drop ceiling resources no granted tool declares, preserving tri-state."""
    if ceiling.resources is None:
        return ceiling
    declared = {tool.resource_id for tool in granted}
    return AuthorityCeiling(
        actions=ceiling.actions,
        resources=tuple(r for r in ceiling.resources if r in declared),
    )


def _resolution_document(manifest: AgentManifest, model: str | None,
                         tools: tuple[ToolBinding, ...],
                         ceiling: AuthorityCeiling) -> dict:
    """Authority portion in the locked andyur.agent-resolution/v1 wire shape."""
    return {
        "schema_version": SCHEMA_VERSION,
        "agent_id": manifest.metadata.id,
        "name": manifest.metadata.name,
        "instructions": manifest.instructions,
        "model": model,
        "tools": [
            {
                "name": tool.name,
                "reach_url": tool.reach_url,
                "resource_id": tool.resource_id,
                "authority": tool.authority,
                "expected_spiffe_id": tool.expected_spiffe_id,
                "credential_ref": tool.credential_ref,
                "credential_headers": (None if tool.credential_headers is None
                                       else list(tool.credential_headers)),
                "mcp_tools": (None if tool.mcp_tools is None else
                              [{"name": g.name, "requires": g.requires}
                               for g in tool.mcp_tools]),
            }
            for tool in tools
        ],
        "ceiling": {
            "actions": (None if ceiling.actions is None else list(ceiling.actions)),
            "resources": (None if ceiling.resources is None else list(ceiling.resources)),
        },
    }


def compile_resolution(manifest: AgentManifest,
                       policy: PlatformPolicy) -> CompiledAgent:
    """Compile one validated manifest under one immutable policy snapshot."""
    model = manifest.model_requested
    if model is not None and policy.approved_models is not None \
            and model not in policy.approved_models:
        raise ManifestDenied(
            f"model: {model!r} is not an approved model; approved: "
            f"{sorted(policy.approved_models)}")

    granted: list[ToolBinding] = []
    for request in manifest.tool_requests:
        approved = policy.tool_catalog.get(request.server)
        if approved is None:
            raise ManifestDenied(
                f"capabilities: server {request.server!r} is not in the "
                "approved tool catalog")
        granted.append(_grant_tool(request.server, request.tools, approved))
    granted_tools = tuple(granted)
    ceiling = _narrow_ceiling(policy.ceiling, granted_tools)

    document = _resolution_document(manifest, model, granted_tools, ceiling)
    try:
        authority_resolution = _parse_manifest(
            f"compiled:{manifest.metadata.id}", document)
    except InvalidAgentManifest as exc:
        raise InconsistentPolicy(
            f"policy for {manifest.metadata.id!r} composed into a resolution "
            f"the registry validator refuses: {exc}") from exc

    requested_runtime = manifest.runtime
    runtime = RuntimeResolution(
        runtime_type=requested_runtime.type,
        interface_version=requested_runtime.interface_protocol,
        manifest_digest=manifest_digest(manifest),
        image_ref=requested_runtime.image.ref if requested_runtime.image else None,
        image_digest=requested_runtime.image.digest if requested_runtime.image else None,
        command=requested_runtime.command,
        resources=requested_runtime.resources,
        policy_revision=policy.revision,
        lifecycle=_grant_lifecycle(requested_runtime.lifecycle, policy),
        # exec/v1 (ADR-011 D5), carried UNRESOLVED and ungranted. Unlike a
        # lifetime, neither of these is a request policy intersects: the
        # vocabulary already refused everything a manifest may not name, and
        # what remains resolves per run at launch, not here.
        #
        # These two kwargs are hand-written, like every other one in this call,
        # which is exactly the S-06 gap runtime_wire's docstring names: the
        # import-time check binds the four WIRE crossings and does not reach
        # this constructor, so a field added to RuntimeResolution and forgotten
        # HERE lands as its default with no complaint. Until that check widens,
        # the guard is test_the_compiler_carries_the_exec_v1_surface.
        process=requested_runtime.process,
        configuration=requested_runtime.configuration,
    )

    # C2 invariant: authority and executable identity are one launch snapshot.
    # Existing registry readers can still return runtime=None, but newly compiled
    # AgentManifests never produce a split pair that could drift before launch.
    resolution = dataclasses.replace(authority_resolution, runtime=runtime)
    return CompiledAgent(resolution=resolution)

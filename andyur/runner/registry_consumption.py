"""Turn a resolved agent definition into what the run harness consumes.

This is the wiring side of the locked registry contract
(`docs/reviews/spire-registry-v2-review-notes.md` section 7). The registry
module owns resolution; this owns using it.

The one non-obvious rule the contract fixes, and the reason this does NOT go
through `gateway.split_tools`: `reach_url` is routing only, and `resource_id` is
the authorization audience. `split_tools` DERIVES the audience from the URL (the
pre-registry ADR-002 scheme, which powers opt-in RFC 9728 discovery). Registry
tools carry an explicit, possibly-opaque `resource_id` instead, so they are
mapped here directly and the derived-audience path is left untouched for the
legacy workspace-mcp.json case. The audience is still not agent-chosen: it comes
from the registry manifest, which a run cannot write.
"""

from __future__ import annotations

import logging
from typing import Callable

from ..registry.models import (AgentResolution, MAX_TOOL_BINDINGS,
                               McpToolGrant, ToolBinding)
from . import gateway

log = logging.getLogger(__name__)


# Resolution happens SERVER-SIDE, not here. The control plane holds the
# configured registry (and any enterprise adapter), so `/agents/{name}/context`
# resolves the bound `registry_agent_id`, overrides `ctx["instructions"]`, and
# exposes `ctx["registry_model"]`. It deliberately does NOT return the full
# resolution: /context is run-readable, and the ceiling + internal reach_urls
# are operator-only (tools come from a separate sidecar-authenticated endpoint).
# A bound agent whose manifest cannot be resolved makes /context fail closed
# (503). The runner is a pure CONSUMER -- a runner-local catalog lookup would be
# a second authority and could not compose control-plane adapters, so there is
# deliberately no configured_registry() call in this process.


def model_from_ctx(ctx: dict) -> str | None:
    """The manifest's model from the server-resolved context, or None.

    The run-readable /context deliberately does NOT carry the full resolution
    (that would leak the operator-only ceiling and internal reach_urls); it
    carries `registry_model` (nullable) and `registry_agent_id`. None -- a legacy
    agent, or a manifest pinning no model -- falls to the driver default. The
    server has already overridden `ctx["instructions"]`, so the runner reads that
    directly and does not touch instructions here.
    """
    return ctx.get("registry_model") or None


def managed_from_resolution(resolution: AgentResolution) -> tuple[dict, dict]:
    """Partition a resolution's tools into (managed, passthrough), in the shapes
    the gateway and the SDK expect. See `_partition_tools`.

    This is the in-process path (the server resolved the whole manifest). The
    over-the-wire path -- a run fetching only its tool descriptors from
    `GET /runs/{run_id}/registry-tools` -- is `managed_from_descriptors`, and
    both funnel through the SAME partition so the audience and launch-failure
    rules behave identically however the tools arrived.
    """
    # No per-run decision exists on this path: there is no run yet, and the
    # server is the only party that may make one. Passing None everywhere keeps
    # the audience-level posture rather than inventing an authority here.
    return _partition_tools(resolution.tools, {})


def _partition_tools(tools, permitted_by_tool: dict) -> tuple[dict, dict]:
    """Partition ToolBindings into (managed, passthrough).

    managed[name]     = {url, audience, scheme, host, port, path}  -- the gateway
                        mints a token for `audience` (the resource_id) and routes
                        to scheme/host/port/path (split from reach_url).
    passthrough[name] = {type, url}                         -- handed to the SDK
                        untouched; Andyur attaches no credential.

    Fail closed: malformed/duplicate bindings and a MANAGED reach_url the
    generated config cannot faithfully reproduce abort launch. They are never
    silently reclassified or passed through without a credential.
    """
    managed: dict = {}
    passthrough: dict = {}
    names: set[str] = set()
    if len(tools) > MAX_TOOL_BINDINGS:
        raise UnlaunchableResolution(
            f"registry declares more than the {MAX_TOOL_BINDINGS}-binding limit")
    for tool in tools:
        if tool.authority not in ("managed", "brokered", "passthrough"):
            raise UnlaunchableResolution(
                f"tool {tool.name!r} has unknown authority {tool.authority!r}")
        if tool.name in names:
            raise UnlaunchableResolution(
                f"tool descriptor name {tool.name!r} is duplicated")
        names.add(tool.name)
        if tool.authority == "passthrough":
            # No platform authority requested, so routing is all that matters and
            # an unusable url just means the SDK will fail to reach it -- the same
            # outcome it would have without Andyur in the path.
            passthrough[tool.name] = {"type": "http", "url": tool.reach_url}
            continue
        if tool.authority == "brokered" and not tool.credential_ref:
            raise UnlaunchableResolution(
                f"brokered tool {tool.name!r} has no credential_ref")
        if len(managed) >= gateway._MAX_MANAGED:
            raise UnlaunchableResolution(
                f"registry declares more than the {gateway._MAX_MANAGED}-managed-tool "
                "runtime limit")
        parsed = gateway._split_url(tool.reach_url)
        if parsed is None:
            # A LAUNCH FAILURE, not a silent withhold. The manifest was supposed
            # to be validated (the registry rejects a malformed reach_url); if an
            # unusable one reaches here, the resolution is not launchable, so fail
            # loudly rather than hand the agent a resolution missing a tool it
            # declares as managed.
            raise UnlaunchableResolution(
                f"managed tool {tool.name!r} has a reach_url the gateway cannot "
                f"honour ({tool.reach_url!r})")
        scheme, host, port, path = parsed
        refusal = gateway.scheme_refusal(scheme)
        if refusal is not None:
            # Same rule, same loudness: a registry-declared managed tool that
            # may not carry the delegated token makes the whole resolution
            # unlaunchable rather than silently shipping a weaker run.
            raise UnlaunchableResolution(
                f"managed tool {tool.name!r}: {refusal}")
        managed[tool.name] = {
            "url": tool.reach_url,
            # The audience is the manifest's resource_id, NOT derived from the
            # url. This is the ADR-002 amendment the registry enables.
            "audience": tool.resource_id,
            "scheme": scheme, "host": host, "port": port, "path": path,
            "credential_ref": tool.credential_ref,
            "credential_mode": tool.authority,
            "credential_headers": (list(tool.credential_headers)
                                   if tool.credential_headers else None),
            # The server's sealed per-run decision. None (audience-level) and []
            # (enumerated, nothing permitted) are DIFFERENT answers and the
            # distinction is the whole control, so neither is collapsed by a
            # falsy test.
            "permitted_tools": permitted_by_tool.get(tool.name),
        }
    return managed, passthrough


# --- the over-the-wire tool path: GET /runs/{run_id}/registry-tools -----------
#
# A split/sidecar run does not hold the full resolution (that would leak the
# operator-only ceiling into a run-readable place). It fetches ONLY its tool
# descriptors from the run-authenticated endpoint the control plane exposes --
# `{registry_agent_id, tools: [{name, reach_url, resource_id, authority}]}` --
# and reshapes them here through the SAME partition the in-process path uses, so
# the resource_id-is-the-audience and launch-failure rules hold
# identically whether the tools arrived in-process or over the wire. The HTTP
# call itself lives in the credential-holding runner (it needs the run token and
# per-run SVID); this module only does the pure, testable transformation.

# The keys the run-tools endpoint promises for every descriptor. Named here so a
# server that changes the contract fails loudly on the first descriptor rather
# than mislabelling a managed tool as passthrough by a silent .get() default.
# `permitted_tools` is REQUIRED, not optional, and that is the point. It carries
# the server's per-run authority decision, and `null` is one of its meaningful
# values (audience-level). Read with a .get() default, a descriptor that lost the
# key -- a rolled-back control plane, a bug in the response builder -- would look
# exactly like "this binding enumerates nothing" and silently switch per-tool
# authority OFF for the whole run, on both sides, with no error anywhere.
_DESCRIPTOR_KEYS = ("name", "reach_url", "resource_id", "authority",
                    "permitted_tools")


def tool_bindings_from_descriptors(descriptors) -> list[ToolBinding]:
    """Rebuild ToolBindings from run-tools endpoint items. The server already
    validated them against the manifest; a descriptor missing a promised field
    is a LAUNCH FAILURE, not a tool silently reshaped -- guessing 'passthrough'
    for a tool whose authority field went missing would call a managed resource
    with no token, the one outcome the whole scheme exists to prevent."""
    if not isinstance(descriptors, (list, tuple)):
        raise UnlaunchableResolution("run-tools descriptors must be a list")
    if len(descriptors) > MAX_TOOL_BINDINGS:
        raise UnlaunchableResolution(
            f"registry declares more than the {MAX_TOOL_BINDINGS}-binding limit")
    bindings: list[ToolBinding] = []
    for d in descriptors:
        if not isinstance(d, dict):
            raise UnlaunchableResolution(
                "run-tools descriptor must be a JSON object")
        missing = [k for k in _DESCRIPTOR_KEYS if k not in d]
        if missing:
            raise UnlaunchableResolution(
                f"run-tools descriptor is missing {missing}; the control plane "
                f"contract was not honoured")
        invalid = [k for k in ("name", "reach_url", "resource_id")
                   if not isinstance(d[k], str) or not d[k]]
        if invalid:
            raise UnlaunchableResolution(
                f"run-tools descriptor has invalid string fields {invalid}")
        bindings.append(ToolBinding(
            name=d["name"], reach_url=d["reach_url"],
            resource_id=d["resource_id"], authority=d["authority"],
            credential_ref=d.get("credential_ref"),
            credential_headers=(tuple(d["credential_headers"])
                                if d.get("credential_headers") else None)))
    return bindings


def managed_from_descriptors(descriptors) -> tuple[dict, dict]:
    """(managed, passthrough) for a run's fetched tool descriptors -- the
    over-the-wire twin of `managed_from_resolution`."""
    permitted_by_tool = {d["name"]: d["permitted_tools"] for d in descriptors
                         if isinstance(d, dict) and "name" in d}
    return _partition_tools(tool_bindings_from_descriptors(descriptors),
                            permitted_by_tool)


# Ceiling materialization is SERVER-side now: POST /agents with a
# registry_agent_id makes the server resolve the manifest and apply its
# tri-state ceiling ATOMICALLY in the same create transaction. There is no
# client-side ceiling step, so the create/ceiling window and its compensation
# (and their TOCTOU hazards) are gone by construction rather than mitigated.


# --- provisioning: bind a resolved agent into the control plane ---------------

class UnlaunchableResolution(ValueError):
    """A resolution the harness cannot honour as-is. Raised rather than silently
    dropping a tool, because the registry promises a 'validated, launchable'
    resolution: a managed tool whose reach_url the config cannot reproduce means
    the resolution is NOT launchable, and launching with it silently missing
    would hand the agent fewer tools than the manifest declares with nothing
    saying so."""


class ProvisionError(RuntimeError):
    """Provisioning did not complete cleanly.

    `resolved` says whether the outcome is known: True means the state is
    definite (nothing was created), False means an AMBIGUOUS create -- a POST
    that got no response may have committed -- so an agent may exist that this
    call cannot prove it made, and an operator must reconcile rather than assume
    absence. There is no client-side delete: the server creates and applies the
    ceiling atomically, so there is nothing partial to roll back.
    """

    def __init__(self, message: str, *, resolved: bool):
        super().__init__(message)
        self.resolved = resolved


def _ok(status: int) -> bool:
    return 200 <= status < 300


def _exists(api: Callable[..., tuple], name: str) -> bool | None:
    """True/False if a GET can tell; None if the probe itself gave no answer.
    None must be read as 'cannot confirm absence', never as 'absent'."""
    try:
        status, _ = api("GET", f"/agents/{name}")
    except Exception:                                      # noqa: BLE001
        return None
    if status == 404:
        return False
    if _ok(status):
        return True
    return None


def _raise_ambiguous(api, name: str, why: str, cause) -> None:
    """A create whose outcome is UNKNOWN -- no response, or a 5xx the server may
    have hit AFTER committing the row. Do not assume absence: probe, and only a
    confirmed 404 is a clean nothing-provisioned; anything else is reconcile."""
    if _exists(api, name) is False:
        raise ProvisionError(
            f"create of {name!r} failed ({why}) and the agent does not exist; "
            f"nothing was provisioned", resolved=True) from cause
    raise ProvisionError(
        f"create of {name!r} was ambiguous ({why}) and an agent by that name "
        f"exists or cannot be confirmed absent; reconcile manually rather than "
        f"assuming absence", resolved=False) from cause


def provision_agent(
    api: Callable[..., tuple],
    resolution: AgentResolution,
    *,
    runtime_name: str | None = None,
    description: str | None = None,
) -> None:
    """Bind a resolved agent into the control plane in ONE server call.

    `runtime_name` is the agent's runtime/display name (e.g. a demo-prefixed
    `demo-classifier`); it defaults to the manifest name. It is DISTINCT from the
    binding: many runtime names (different prefixes) may bind the one immutable
    `registry_agent_id`, so `demo-classifier` and `t1-classifier` can both point
    at `agt_classifier`.

    POST /agents with the binding: the server resolves the manifest and applies
    its tri-state ceiling atomically in the same create transaction. No
    client-side ceiling step, nothing partial to compensate, no delete.

    `api(method, path, json=None) -> (status_code, body)`; it raises only on a
    transport failure. Outcome interpretation:

    - 2xx: created + ceiling applied atomically.
    - 4xx (incl. 409): a DEFINITE client rejection -- nothing was created.
    - transport raise OR 5xx: AMBIGUOUS. The server may have committed the row
      before a later failure (workspace/serialization), so absence is NOT
      assumed: it probes, and only a confirmed 404 is clean; otherwise
      ProvisionError(resolved=False) for an operator to reconcile.
    """
    name = runtime_name or resolution.name
    body = {"name": name,
            "description": description or f"registry:{resolution.agent_id}",
            "registry_agent_id": resolution.agent_id}
    try:
        status, _ = api("POST", "/agents", json=body)
    except Exception as create_exc:                        # noqa: BLE001
        _raise_ambiguous(api, name, f"no response ({create_exc})", create_exc)

    if _ok(status):
        return  # created + ceiling applied atomically
    if status == 409:
        raise ProvisionError(
            f"an agent named {name!r} already exists (409); this call did not "
            f"create it and will not modify it", resolved=True)
    if 400 <= status < 500:
        raise ProvisionError(
            f"create of {name!r} was rejected (HTTP {status}); nothing was "
            f"provisioned", resolved=True)
    # 5xx: the row may have committed before a later server-side failure.
    _raise_ambiguous(api, name, f"HTTP {status}", None)

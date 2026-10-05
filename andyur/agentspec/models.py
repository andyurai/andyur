"""Typed shapes for the AgentManifest request side of the BYOA split.

AgentManifest describes what a developer asks for; PlatformPolicy describes
what the platform approves. The canonical executable identity lives in the
registry read contract so authority and executable bytes can travel as one
immutable AgentResolution during C2 production launch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping

from ..registry.models import (
    AgentResolution,
    AuthorityCeiling,
    CaptureMode,
    ConfigFile,
    ConfigurationSpec,
    EnvVar,
    InputMode,
    LifecycleMode,
    OnExit,
    ProcessSpec,
    ResourceSpec,
    RuntimeResolution,
    RuntimeType,
    ToolBinding,
)

__all__ = ["CaptureMode", "ConfigFile", "ConfigurationSpec", "EnvVar",
           "InputMode", "ProcessSpec"]


class InvalidManifest(ValueError):
    """An AgentManifest failed validation. Raised at parse time, fail-closed."""


class ManifestDenied(PermissionError):
    """A valid manifest asked for something platform policy does not approve."""


class InconsistentPolicy(RuntimeError):
    """Platform policy composed into a resolution the locked validator refuses."""


@dataclass(frozen=True)
class ImageRef:
    """OCI image reference; digest is the immutable executable identity."""

    ref: str
    digest: str | None = None


@dataclass(frozen=True)
class LifecycleRequest:
    """The lifetime a developer asks for. Policy decides what is granted.

    Separate from ``LifecycleSpec`` for the same reason ``ToolRequest`` is
    separate from ``ToolBinding``: one is a request and cannot carry authority,
    the other is the granted result. Collapsing them would make the manifest
    look authoritative about how long its own agent may run.
    """

    mode: LifecycleMode
    max_seconds: int
    idle_seconds: int | None = None
    on_exit: OnExit = "fail"


# The exec/v1 shapes live in the registry read contract, not here, and are
# re-exported so existing importers are unaffected. They moved when
# `configuration` began crossing the wire into the signed launch snapshot: the
# decoder has to refuse a reference the parser would have refused, registry/
# cannot import agentspec/, and two spec families translated by the compiler is
# the precise asymmetry that made a nested field parse cleanly and then get
# dropped on the floor.

@dataclass(frozen=True)
class RuntimeSpec:
    """How the developer asks for the agent to execute."""

    type: RuntimeType
    image: ImageRef | None = None
    command: tuple[str, ...] | None = None
    interface_protocol: str | None = None
    resources: ResourceSpec | None = None
    lifecycle: LifecycleRequest | None = None
    process: ProcessSpec | None = None
    configuration: ConfigurationSpec | None = None


@dataclass(frozen=True)
class ToolRequest:
    """One MCP server and the closed set of tools requested on it."""

    server: str
    tools: tuple[str, ...]


@dataclass(frozen=True)
class ManifestMetadata:
    id: str
    name: str
    version: str


@dataclass(frozen=True)
class AgentManifest:
    """One parsed, validated developer manifest (andyur.ai/v1, kind Agent)."""

    metadata: ManifestMetadata
    runtime: RuntimeSpec
    instructions: str
    model_requested: str | None = None
    tool_requests: tuple[ToolRequest, ...] = ()
    input_schema: str | None = None
    output_schema: str | None = None


@dataclass(frozen=True)
class PlatformPolicy:
    """The platform-owned inputs used by the narrowing compiler."""

    tool_catalog: Mapping[str, ToolBinding]
    ceiling: AuthorityCeiling
    approved_models: tuple[str, ...] | None = None
    revision: str | None = None
    # The lifetime ceiling. `None` means the platform default applies and no
    # manifest may declare a lifecycle at all, which keeps an unconfigured
    # deployment behaving exactly as it did before this field existed.
    #
    # There is deliberately no `allow_service_mode` beside it. A resident agent
    # needs turn polling, per-window stream budgets and supervised restart, none
    # of which the runtime has; a policy switch enabling a capability that does
    # not exist is a promise nothing keeps. It arrives with the capability.
    max_lifetime_seconds: int | None = None


@dataclass(frozen=True)
class CompiledAgent:
    """Authority plus executable identity produced from one manifest/policy pair.

    ``runtime`` is a derived compatibility view for existing callers. The sole
    canonical value is embedded in ``resolution.runtime`` so executable identity
    cannot drift away from its authority snapshot.
    """

    resolution: AgentResolution
    @property
    def runtime(self) -> RuntimeResolution:
        runtime = self.resolution.runtime
        if runtime is None:
            raise InconsistentPolicy(
                "a compiled agent must carry executable identity in its "
                "authority resolution")
        return runtime

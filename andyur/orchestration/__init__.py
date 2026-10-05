"""Provider-neutral orchestration.

Andyur's orchestration semantics, defined independently of whatever runs them.
See `docs/orchestration-semantics.md` for the properties themselves and
`provider.py` for the interface a provider implements.

Nothing here imports a specific engine's SDK, and nothing outside
`andyur/orchestration/<provider>/` may.

NOTE ON ONE NAME. `orchestration.facade` is the ACCESSOR FUNCTION, not the
module of the same name -- the re-export below shadows it, deliberately, because
`orchestration.facade().request_agent_run(...)` is what call sites should read
like. To reach the module itself, import it by path:
`from andyur.orchestration.facade import OrchestrationFacade`.
"""

from .capabilities import (
    ALL_CAPABILITIES,
    MANDATORY,
    ProviderCapabilities,
    WORKFLOW_REQUIREMENTS,
    check,
    requirements_for,
)
from .errors import (
    HaltNotAcknowledged,
    OrchestrationError,
    ProviderCapabilityMissing,
    ProviderProtocolError,
    ProviderUnavailable,
    WorkflowAlreadyExists,
    WorkflowNotFound,
    WorkflowRejected,
)
from .models import (
    HaltOutcome,
    HaltRequest,
    ProviderHealth,
    ProviderWorkflowState,
    ScheduleHandle,
    ScheduleSpec,
    WorkflowHandle,
    WorkflowSignal,
    WorkflowStart,
    WorkflowState,
)
from .facade import (
    DEFERRED_WORK,
    OrchestrationFacade,
    SCHEDULED_AGENT,
    SINGLE_AGENT,
    facade,
    reset_facade,
)
from .governance import (
    ProviderMismatch,
    WorkflowGovernance,
    bind_provider,
    governance_of,
    provider_of,
    record_provider_state,
)
from .provider import WorkflowProvider
from .registry import (
    BUILDERS,
    UnknownProvider,
    build_workflow_provider,
    configured_name,
)

__all__ = [
    "ALL_CAPABILITIES", "MANDATORY", "ProviderCapabilities",
    "WORKFLOW_REQUIREMENTS", "check", "requirements_for",
    "HaltNotAcknowledged", "OrchestrationError", "ProviderCapabilityMissing",
    "ProviderProtocolError", "ProviderUnavailable", "WorkflowAlreadyExists",
    "WorkflowNotFound", "WorkflowRejected",
    "HaltOutcome", "HaltRequest", "ProviderHealth", "ProviderWorkflowState",
    "ScheduleHandle", "ScheduleSpec", "WorkflowHandle", "WorkflowSignal",
    "WorkflowStart", "WorkflowState",
    "WorkflowProvider",
    "ProviderMismatch", "WorkflowGovernance", "bind_provider",
    "governance_of", "provider_of", "record_provider_state",
    "OrchestrationFacade", "facade", "reset_facade",
    "SINGLE_AGENT", "SCHEDULED_AGENT", "DEFERRED_WORK",
    "BUILDERS", "UnknownProvider", "build_workflow_provider", "configured_name",
]

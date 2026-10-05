"""Provider-neutral orchestration errors.

A caller must be able to handle a failure without knowing which engine produced
it, so nothing below carries a provider's own exception type, message shape or
retry advice. A provider translates; it does not leak.

The distinction that matters most here is between REFUSED and FAILED.
`WorkflowRejected` means Andyur declined the work -- a cap, a halt, a missing
capability -- and retrying without changing something will decline again.
`ProviderUnavailable` means the engine could not be reached and the same request
may well succeed later. Collapsing the two is how a refusal becomes a retry
loop.
"""


class OrchestrationError(Exception):
    """Base for everything this package raises."""


class ProviderUnavailable(OrchestrationError):
    """The engine could not be reached, or could not answer in time.

    TRANSIENT BY CONTRACT. Raise this only when retrying the same request later
    could plausibly succeed, because callers are entitled to treat it that way.
    """


class ProviderCapabilityMissing(OrchestrationError):
    """The workflow needs a guarantee this provider does not offer.

    Carries both sides so the message can say which guarantee and which
    provider, rather than "unsupported". Fail closed: there is deliberately no
    "degrade to best effort" branch anywhere in this package (see
    capabilities.py).
    """

    def __init__(self, workflow_kind: str, provider: str, missing: frozenset[str]):
        self.workflow_kind = workflow_kind
        self.provider = provider
        self.missing = frozenset(missing)
        listed = ", ".join(sorted(self.missing))
        super().__init__(
            f"workflow kind '{workflow_kind}' requires {listed}, which provider "
            f"'{provider}' does not offer")


class WorkflowAlreadyExists(OrchestrationError):
    """A DIFFERENT workflow already holds this id.

    Not raised when the same logical workflow is started twice: `start` is
    idempotent on `workflow_id` and returns the existing handle. That is not a
    convenience, it is what makes an at-least-once delivery safe -- see the
    idempotency note in provider.py.
    """


class WorkflowNotFound(OrchestrationError):
    """No workflow with this id, as far as the provider knows.

    A provider that has forgotten a workflow (retention expired, history
    dropped) raises this rather than inventing a terminal state. Andyur's own
    record is authoritative for what happened; the provider is only
    authoritative for what is still executing.
    """


class WorkflowRejected(OrchestrationError):
    """Andyur declined the work. A refusal, not a failure; do not retry blind."""


class HaltNotAcknowledged(OrchestrationError):
    """The provider could not confirm it has stopped making durable progress.

    SEPARATE FROM ProviderUnavailable ON PURPOSE, because the operator needs to
    know the difference between "the kill switch could not be delivered" and
    "the engine is down". Neither is a reason to report a workflow as contained:
    containment does not run through the provider at all (provider.py), so a
    halt the provider never acknowledged leaves durable progress possibly
    continuing while the execution itself has already been destroyed.
    """


class ProviderProtocolError(OrchestrationError):
    """The provider returned something this package cannot interpret.

    A bug in the provider or a version skew, never a normal outcome. Raised
    rather than coerced, because a state Andyur cannot name is not one it may
    guess at -- guessing here would mean reporting a run's state wrongly.
    """

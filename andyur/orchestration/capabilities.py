"""What a provider guarantees, and what Andyur refuses to run without it.

Two rules shape this file, and they pull in opposite directions on purpose.

**A capability is a promise Andyur is willing to rely on.** Advertise
conservatively: claiming `durable_timers` means a scheduled wake will survive
the engine restarting, and something will be built on that belief. "Probably"
is `False`.

**Andyur's own semantics are never capabilities.** Whether an action needs
approval, whether authority may widen, whether a run may hold a credential --
none of that is a provider's to offer or withhold, so none of it appears below.
What a provider can change is how DURABLY an approval can be waited on, which is
why `durable_approval` is a workflow requirement built from durability
guarantees rather than an `approval_semantics` flag. A flag that is `True` for
every provider is not a capability; it is a reminder that the decision was made
somewhere else.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import ProviderCapabilityMissing


# --- what every provider must do, no exceptions -----------------------------

# NOT capabilities, because a provider that cannot do these is not a provider.
# Modelling them as optional would create a legal configuration in which the
# kill switch is advisory, and there is no such configuration.
#
#   halt          a halt request is accepted durably and progress stops
#   at_most_once  an admitted unit of work is dispatched to at most one
#                 executor at a time
#   replay_safe   a completed step is never re-executed on recovery
#
# The spike measured the third against Temporal directly (a worker killed
# mid-run replayed without repeating its completed activity) and it is the one
# property that makes durable execution worth adopting at all.
MANDATORY = frozenset({"halt", "at_most_once", "replay_safe"})


@dataclass(frozen=True)
class ProviderCapabilities:
    """Durability guarantees only. See the module docstring for what is absent.

    `activity_heartbeats` is deliberately NOT here despite being the obvious
    knob: it is Temporal's mechanism for keeping a long step alive and
    interruptible, and naming it would put a provider's vocabulary in Andyur's
    public type. What Andyur actually needs to know is whether a long step can
    be waited on at all, which is `long_running_waits`.
    """

    provider: str

    durable_execution: bool = False
    """Progress survives the loss of every worker, not just a graceful restart."""

    durable_timers: bool = False
    """A scheduled wake fires after an engine restart, at the time it was set."""

    durable_signals: bool = False
    """A signal delivered to a workflow that is not currently resident is not lost."""

    long_running_waits: bool = False
    """A workflow may wait days for a signal without holding a live process."""

    schedules: bool = False
    """The provider can own recurring triggers with Andyur's overlap rule
    (skip and retry soon -- never buffer a backlog). A provider whose native
    scheduler offers only buffer-or-skip must report False and let Andyur keep
    driving schedules itself, rather than substituting the nearest behaviour."""

    child_workflows: bool = False
    """Delegated work can be modelled as a child execution whose lifetime and
    cancellation are bound to its parent."""

    provider_failover: bool = False
    """The provider survives losing a node of its own. Deployment-dependent, so
    a provider implementation usually cannot claim this from code alone -- it
    is configuration, and it defaults to False for that reason."""

    def offered(self) -> frozenset[str]:
        return frozenset(
            name for name in _OPTIONAL
            if getattr(self, name)) | MANDATORY

    def missing_for(self, required: frozenset[str]) -> frozenset[str]:
        return frozenset(required) - self.offered()


_OPTIONAL = (
    "durable_execution", "durable_timers", "durable_signals",
    "long_running_waits", "schedules", "child_workflows", "provider_failover",
)

ALL_CAPABILITIES = MANDATORY | frozenset(_OPTIONAL)


# --- what each kind of work needs -------------------------------------------

# Keyed by workflow kind. A kind absent from here cannot be started: an unknown
# kind with no stated requirements would be admitted by every provider, which is
# the permissive failure and therefore the wrong default.
WORKFLOW_REQUIREMENTS: dict[str, frozenset[str]] = {
    # One agent, one run, start to finish. Needs nothing a single node cannot
    # do, which is what keeps the local provider a real option rather than a
    # demo: the quickstart path must never require durable execution.
    "single_agent": frozenset({"halt", "at_most_once"}),

    # A cron-driven agent. `schedules` only says WHO owns the trigger; Andyur's
    # skip-and-retry-soon semantics are required of either owner.
    "scheduled_agent": frozenset({"halt", "at_most_once", "schedules"}),

    # An agent whose work is re-driven after being deferred. Same shape as a
    # single agent -- the drain is Andyur's, not the provider's.
    "deferred_work": frozenset({"halt", "at_most_once"}),

    # A run that waits for a human to approve a consequential action. THIS is
    # where durability stops being a nicety: an approval that does not survive a
    # restart silently becomes a refusal, and an operator who approved something
    # is entitled to expect it happened.
    "durable_approval": frozenset({
        "halt", "at_most_once", "replay_safe",
        "durable_execution", "durable_signals", "long_running_waits",
    }),

    # Delegation modelled as child executions.
    "delegated_fanout": frozenset({
        "halt", "at_most_once", "replay_safe", "durable_execution",
        "child_workflows",
    }),
}


def requirements_for(workflow_kind: str) -> frozenset[str]:
    try:
        return WORKFLOW_REQUIREMENTS[workflow_kind]
    except KeyError:
        raise ValueError(
            f"unknown workflow kind '{workflow_kind}': a kind with no declared "
            "requirements would be accepted by every provider, so it is refused "
            "rather than defaulted") from None


def check(workflow_kind: str, capabilities: ProviderCapabilities) -> None:
    """Refuse the work, or return. There is no third outcome.

    NO DEGRADED PATH EXISTS HERE, and none may be added. The tempting version --
    run a durable approval on a provider without durable signals, polling
    instead -- produces a system that works in every test and loses an approval
    the one time the process restarts mid-wait. If a provider cannot offer the
    guarantee, the honest answer is that the workflow cannot run on it.
    """
    missing = capabilities.missing_for(requirements_for(workflow_kind))
    if missing:
        raise ProviderCapabilityMissing(
            workflow_kind, capabilities.provider, missing)

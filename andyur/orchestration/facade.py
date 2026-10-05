"""The one way the rest of Andyur asks for work to happen.

Before this, every caller that wanted a run called the coordinator directly.
That was fine while there was one engine, and it is exactly what makes a second
one impossible: pluggability is not achieved by having an interface, it is
achieved when the EXISTING path goes through it too. A server with one route to
the coordinator and another to a provider has two orchestrators, and the one
nobody is looking at is the one that drifts.

So this is deliberately thin. It performs Andyur's own decisions -- admission,
capability enforcement, governance -- and then tells the provider. It adds no
orchestration of its own, and if it ever grows a retry, a queue or a timer, that
logic is in the wrong place.

## What stays here and what goes to the provider

Admission is Andyur's and happens FIRST. `coordinator.wakeup_or_reason` decides
whether the agent may hold a run at all, and the provider is told only about
work that was already allowed. A provider is never in a position to admit.

Unhalting does not touch the provider at all. A halt stops an execution; there
is nothing to un-stop, and under a durable engine a terminated execution cannot
be resumed anyway -- new work would be a new execution. What unhalt actually
does is change Andyur's governance record so that new work may join the
workflow again, which is a platform decision with no provider component.

## The binding, and why it is not read from configuration

A workflow is bound to the engine that started it, in Andyur's own record, and
`bind_provider` refuses to move it. Configuration is the thing that changes: an
operator switching `ANDYUR_WORKFLOW_PROVIDER` is choosing where NEW work runs,
and must not thereby re-home work already running. Resolving the provider from
the environment at read time would do exactly that, silently.

## The window this opens, stated plainly

A run is admitted and then the provider is told. Between those two the run
exists and no engine knows about it. On the native provider that window is
empty, because `start` there only verifies -- admission and dispatchability are
the same act. Under a durable provider it is real, and if `start` fails the run
would hold its agent with nothing coming for it. So a failed start finishes the
run and frees the agent before re-raising. Persisting the binding so the window
is recoverable rather than merely compensated is Stage 6's job, not this one's.
"""

from __future__ import annotations

from ..server import coordinator
from . import capabilities, governance
from .models import (
    HaltOutcome,
    HaltRequest,
    ProviderWorkflowState,
    ScheduleHandle,
    ScheduleSpec,
    WorkflowStart,
)
from .provider import WorkflowProvider
from .registry import build_workflow_provider

# The kinds Andyur currently asks for, named so a call site says what it needs
# rather than repeating a string. `requirements_for` refuses an unknown kind, so
# a typo is caught either way -- these exist for the reader.
SINGLE_AGENT = "single_agent"
SCHEDULED_AGENT = "scheduled_agent"
DEFERRED_WORK = "deferred_work"


class OrchestrationFacade:
    """Andyur's semantic orchestration service."""

    def __init__(self, provider: WorkflowProvider | None = None):
        self._provider = provider or build_workflow_provider()

    @property
    def provider(self) -> WorkflowProvider:
        """The provider in use. Exposed for diagnostics and for tests that need
        to assert which one is configured -- NOT for callers to branch on. Code
        above this layer that asks which provider it has, and behaves
        differently, has reintroduced the coupling this exists to remove."""
        return self._provider

    # --- running work -------------------------------------------------------

    def request_agent_run(
        self, agent: str, reason: str, run_type: str = "work", *,
        workflow_kind: str = SINGLE_AGENT, **wakeup,
    ) -> tuple[str | None, str | None]:
        """Ask for one run of one agent. Returns `(run_id, refusal)`.

        THE SIGNATURE MIRRORS `coordinator.wakeup_or_reason`, positionally as
        well as by keyword, because every caller of this was calling that.
        Matching it is what makes the migration a change of address rather than
        a change of behaviour.

        The positional part is not incidental, and the first draft got it wrong:
        `run_type` is passed positionally by the trigger endpoint, so a
        keyword-only version type-errored on the busiest path in the platform.
        `test_the_facade_signature_still_mirrors_the_coordinator` pins it, so
        the next change to either signature fails loudly rather than at a call
        site.

        `coordinator.InputRefused` propagates unchanged: it means the agent's
        manifest requires an input this wakeup cannot supply, which is a
        permanent refusal callers already handle, and wrapping it would break
        that handling.
        """
        capabilities.check(workflow_kind, self._provider.capabilities())

        # WHO DISPATCHES THIS RUN is decided here, from the provider, and
        # written in the same INSERT that creates it: an engine-dispatched run
        # is never visible to the native assignment loop, not even for the
        # instant between admission and the provider's start.
        run_id, refusal = coordinator.wakeup_or_reason(
            agent, reason, run_type,
            dispatch="engine" if self._provider.dispatches_runs else None,
            orchestration_provider=self._provider.name,
            workflow_kind=workflow_kind,
            **wakeup)
        if run_id is None:
            return None, refusal

        # A RUN NEED NOT BELONG TO A WORKFLOW, which the first draft assumed it
        # did. `resolve_workflow` inherits the parent's workflow, so a run
        # parented to one that has none gets none either, and the platform
        # tolerates that deliberately -- `assign_runs` carries an explicit
        # `r.workflow_id IS NULL` branch, because such a run belongs to no
        # workflow and therefore cannot be halted by one.
        #
        # The provider still needs to hear about the execution, and still needs
        # a non-empty idempotency key, so a workflow-less run is its own unit of
        # work and the run id serves. The two cannot collide: workflow ids are
        # `wf-` prefixed and run ids are bare hex.
        workflow_id = _workflow_of(run_id) or run_id
        try:
            # A WORKFLOW DOES NOT MOVE BETWEEN ENGINES, and the check has to be
            # here rather than after `start` -- on a durable provider, starting
            # first would already have created an execution on the wrong one.
            # `bind_provider` checks again AS it writes -- a conditional UPDATE
            # that matches only an unbound row or one already on this provider
            # -- which catches two control planes binding the same workflow to
            # different engines at once. This read cannot; that one can. (This
            # comment made the same claim before the write was conditional, when
            # it was not true.)
            bound = governance.provider_of(workflow_id)
            if bound is not None and bound != self._provider.name:
                raise governance.ProviderMismatch(
                    f"workflow '{workflow_id}' is running on '{bound}', and this "
                    f"server is configured for '{self._provider.name}'")

            handle = self._provider.start(WorkflowStart(
                workflow_id=workflow_id, root_run_id=run_id,
                workflow_kind=workflow_kind,
                # Carried, not implied. `WorkflowStart` says the requirement
                # set travels with the request so a provider cannot silently
                # accept a kind it has never heard of -- and it was being sent
                # empty, which made that promise false.
                required_capabilities=capabilities.requirements_for(workflow_kind)))
            governance.bind_provider(
                workflow_id, self._provider.name,
                provider_workflow_id=handle.workflow_id,
                provider_ref=handle.provider_ref)
            coordinator.mark_provider_acked(run_id)
        except Exception:
            # The run is admitted and holding its agent, and nothing is coming
            # for it. Release it before re-raising, or a provider outage would
            # strand one agent per attempt until the queue backstop -- 24 hours
            # by default, which is indistinguishable from forever.
            # ONLY IF IT NEVER STARTED. A worker can claim and start this run
            # between its admission and the call above returning -- tiny on the
            # native provider, a network round-trip under a durable one -- and
            # compensating a RUNNING run would write an obituary for a
            # container still doing work and drop its credential mid-flight.
            coordinator.abandon_unstarted_run(
                run_id, "the workflow provider refused to start this run")
            raise

        return run_id, refusal

    def reoffer_unacknowledged(self, grace_seconds: float) -> list[str]:
        """EVENTUAL DELIVERY (provider draft R6.6). Offer again every committed
        engine run this provider never acknowledged.

        A crash between the admission commit and `start` returning left such a
        run `pending`, holding its agent, with nothing coming for it until the
        24 h queue backstop. Starting is idempotent on the run, so offering it
        again is always safe: the provider returns the execution it already has
        or creates the one that never was. A failure here is left for the next
        tick -- never compensated as a refusal, because the run was admitted and
        nothing has said it cannot run.
        """
        if not self._provider.dispatches_runs:
            return []
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(seconds=grace_seconds)).isoformat()
        actions = []
        for row in coordinator.unacknowledged_engine_runs(self._provider.name, cutoff):
            run_id = row["id"]
            workflow_id = row["workflow_id"] or run_id
            kind = row["workflow_kind"] or SINGLE_AGENT
            handle = self._provider.start(WorkflowStart(
                workflow_id=workflow_id, root_run_id=run_id, workflow_kind=kind,
                required_capabilities=capabilities.requirements_for(kind)))
            governance.bind_provider(
                workflow_id, self._provider.name,
                provider_workflow_id=handle.workflow_id,
                provider_ref=handle.provider_ref)
            coordinator.mark_provider_acked(run_id)
            actions.append(f"re-offered run {run_id} to {self._provider.name}: "
                           "its start was never acknowledged")
        return actions

    # --- the kill switch ----------------------------------------------------

    def halt_workflow(self, workflow_id: str, reason: str = "operator") -> HaltOutcome:
        """Stop a workflow. **Stops progress; destroys nothing.**

        Containment -- destroying the container the untrusted code runs in --
        does not pass through here or through the provider. Andyur condemns the
        run from its own record and the executor destroys it, which is what
        keeps the kill switch working when the orchestration engine is not.

        Halting a workflow nothing has joined yet is accepted rather than
        refused, and that is the operator-facing behaviour this platform
        already had: the workflow is recorded halted so that work naming it
        later is turned away.
        """
        # GOVERNANCE FIRST, AND IT IS ANDYUR'S. This was the bug: the facade
        # used to call only the provider, and the kill switch worked purely
        # because the native provider happened to write the governance halt
        # itself. A provider implementing `halt` exactly as provider.py
        # specifies -- stop durable progress, touch nothing of Andyur's --
        # left the workflow `active`, so `admit` kept admitting runs into it
        # while the endpoint answered {"state": "halted"}.
        #
        # Written BEFORE the provider is told, so that a provider that is
        # unreachable cannot leave the workflow admitting work. A kill switch
        # that depends on an engine being up is not a kill switch.
        coordinator.halt_workflow(workflow_id)

        # EVERY LIVE RUN, AND ONLY NOW. Executions are one per run, so the
        # provider needs the runs to reach, and they are read from Andyur's own
        # record rather than discovered from the engine -- whose listing is
        # eventually consistent and could miss a run that started a moment ago.
        # Read AFTER the governance write, so nothing admitted in between is
        # left out: the halt refuses admission first, then this names what is
        # still running.
        outcome = self._provider.halt(HaltRequest(
            workflow_id=workflow_id, reason=reason,
            run_ids=tuple(coordinator.live_run_ids(workflow_id))))
        # Cache what the engine now believes, for reads that should not cost a
        # call per row. Andyur's own `workflows.state` is what governance reads
        # and is already 'halted' by this point; this is diagnostics.
        governance.record_provider_state(workflow_id, outcome.state.value)
        return outcome

    def unhalt_workflow(self, workflow_id: str) -> bool:
        """Let new work join this workflow again.

        NO PROVIDER CALL, deliberately. A halt stopped an execution; there is
        nothing to resume, and under a durable engine a stopped execution
        cannot be resumed in any case -- later work is a new execution. What
        this changes is Andyur's governance record, which is the platform's
        alone.
        """
        return coordinator.unhalt_workflow(workflow_id)

    # --- reading ------------------------------------------------------------

    def describe(self, workflow_id: str) -> ProviderWorkflowState:
        """What the provider believes about a workflow.

        A belief about execution progress, never the record of what happened.
        Andyur's own rows are authoritative for that, and an audit reads those.

        The live runs come from that record, as they do for a halt: a provider
        that runs one execution per run has no execution named after the
        workflow at all.
        """
        return self._provider.describe(
            workflow_id, run_ids=tuple(coordinator.live_run_ids(workflow_id)))

    # --- recurring work -----------------------------------------------------

    @property
    def dispatches_runs(self) -> bool:
        """Whether the bound provider dispatches admitted runs, and fires
        schedules, itself (Architecture B+, ADR-014 D11)."""
        return self._provider.dispatches_runs

    def create_schedule(self, spec: ScheduleSpec) -> ScheduleHandle:
        return self._provider.create_schedule(spec)

    def delete_schedule(self, schedule_id: str) -> None:
        self._provider.delete_schedule(schedule_id)


def _workflow_of(run_id: str) -> str | None:
    from .. import db

    with db.connect() as conn:
        row = conn.execute(
            "SELECT workflow_id FROM runs WHERE id = ?", (run_id,)).fetchone()
    return row["workflow_id"] if row else None


# One instance, built on first use. The provider is chosen by configuration and
# does not change while the process runs, so rebuilding it per call would buy
# nothing and would mean a provider holding a connection could not hold one.
_FACADE: OrchestrationFacade | None = None


def facade() -> OrchestrationFacade:
    global _FACADE
    if _FACADE is None:
        _FACADE = OrchestrationFacade()
    return _FACADE


def reset_facade() -> None:
    """Drop the cached instance. For tests that change the configured provider;
    nothing in production calls this."""
    global _FACADE
    _FACADE = None

"""The native engine as a workflow provider.

Deliberately boring, and boring in a specific way: **nothing here decides
anything.** Every method delegates to the coordinator, the schedule service or
the database, all of which already existed and none of which changed. If this
file ever grows a policy, the policy is in the wrong place.

## What wrapping the native engine exposed

`start` is very nearly a no-op, and that is not laziness -- it is the most
useful thing this wrapper reveals.

In the native engine, **admitting a run and dispatching it are the same act.**
`maybe_wakeup` inserts a pending run, and the fact that the row exists is what
makes it eligible for a worker to claim. There is no separate "now begin"
instruction, because there is nothing to instruct: the engine is the database
and the loop that reads it.

A durable-execution provider splits those. Andyur admits, and then the engine is
told to begin. So `start` exists in the interface for the provider that needs
it, and here it verifies that what it was asked to start is real and returns a
handle to it.

That asymmetry is worth keeping in view during Stage 5. The facade will call
`start` on every path, and on this provider that call does nothing -- so a bug
where the facade forgets to call it would be invisible locally and appear only
under a durable provider. The conformance suite asserts `start` at least
validates, so the call is not merely decorative here.
"""

from __future__ import annotations

from ... import db
from ...server import coordinator, schedules as schedule_service
from ..capabilities import ProviderCapabilities
from ..errors import (
    HaltNotAcknowledged,
    ProviderCapabilityMissing,
    WorkflowNotFound,
)
from ..models import (
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

NAME = "local"


class LocalWorkflowProvider:
    """Andyur's built-in coordination, satisfying `WorkflowProvider`."""

    @property
    def name(self) -> str:
        return NAME

    @property
    def dispatches_runs(self) -> bool:
        return False    # the native assignment loop dispatches

    def capabilities(self) -> ProviderCapabilities:
        """Conservative on purpose. A capability is a promise something will be
        built on, and this provider's honest position is that durability stops
        at the database.

        `durable_timers` is FALSE even though a cron schedule genuinely does
        survive a restart -- the row carries `next_run_at` and the heartbeat
        catches up. What the capability means is the general case: a workflow
        waiting on an arbitrary timer, resumed later from where it paused.
        There is no local implementation of that at all, because there is no
        resumable workflow to pause. Claiming the capability because the narrow
        case works would be exactly the over-advertisement the model warns
        about; what this provider really offers there is `schedules`.

        `schedules` is TRUE and is a real claim: Andyur's own cron already
        implements the required overlap rule -- a tick that finds its agent busy
        is retried shortly, never buffered into a backlog and never dropped.
        """
        return ProviderCapabilities(
            provider=NAME,
            durable_execution=False,
            durable_timers=False,
            durable_signals=False,
            long_running_waits=False,
            schedules=True,
            child_workflows=False,
            provider_failover=False,
        )

    def health(self) -> ProviderHealth:
        """The native engine is healthy when its database answers.

        There is no separate service to be down: this provider IS the control
        plane. Reported rather than raised, per the interface.
        """
        try:
            with db.connect() as conn:
                conn.execute("SELECT 1").fetchone()
        except Exception as exc:                     # noqa: BLE001 - reported, not raised
            return ProviderHealth(
                provider=NAME, reachable=False, detail=f"{type(exc).__name__}: {exc}")
        return ProviderHealth(provider=NAME, reachable=True)

    # --- running work -------------------------------------------------------

    def start(self, request: WorkflowStart) -> WorkflowHandle:
        """Confirm the workflow exists and hand back a handle.

        Idempotent because there is nothing to repeat: the run was admitted
        before this was called, and admission is what made it eligible. See the
        module docstring for why that matters to the facade.

        Raises `WorkflowNotFound` when asked to start something that was never
        admitted, rather than inventing it. A provider that created a workflow
        here would be admitting work, which is Andyur's decision and not a
        provider's.
        """
        with db.connect() as conn:
            run = conn.execute(
                "SELECT workflow_id FROM runs WHERE id = ?", (request.root_run_id,)
            ).fetchone()
        if run is None:
            raise WorkflowNotFound(
                f"run '{request.root_run_id}' was never admitted, so there is "
                "nothing to start; admission is Andyur's and happens first")
        return WorkflowHandle(
            workflow_id=request.workflow_id, provider=NAME,
            provider_ref=request.root_run_id)

    def signal(self, workflow_id: str, signal: WorkflowSignal) -> None:
        """Refused. This provider has no signal delivery.

        NOT a stub and not a silent no-op, which is the tempting shape: a signal
        that appears to be delivered and is not would turn a durable approval
        into a wait that never ends. Every workflow kind requiring signals is
        already refused by the capability check before reaching here, so arriving
        at this method means something bypassed that check.

        Halting is deliberately not a signal in this interface -- it has its own
        method, for reasons in `provider.py`.
        """
        raise ProviderCapabilityMissing(
            f"signal:{signal.name}", NAME, frozenset({"durable_signals"}))

    def halt(self, request: HaltRequest) -> HaltOutcome:
        """Report that progress has stopped. **Writes no governance, destroys
        nothing.**

        THIS USED TO CALL `coordinator.halt_workflow` ITSELF, and that was the
        seam leaking: governance is Andyur's, so a provider writing it meant
        the kill switch only worked for THIS provider. The facade writes the
        halt before calling here; by the time this runs, the workflow is
        already recorded halted and its un-started work already cancelled.

        There is genuinely nothing left for the native engine to stop. Its
        durable progress IS the pending runs, and those are gone -- which is
        why this reports rather than acts, and why that is not laziness.

        A run already executing is untouched here, as everywhere: it is
        condemned, and the executor destroys it on its next beat.
        """
        state = coordinator.workflow_state(request.workflow_id)
        return HaltOutcome(
            workflow_id=request.workflow_id,
            accepted=True,
            state=WorkflowState.HALTED if state == "halted" else WorkflowState.HALTING,
            detail="durable progress stopped; execution is destroyed by "
                   "condemnation, which does not run through the provider")

    def describe(self, workflow_id: str,
                 run_ids: tuple[str, ...] = ()) -> ProviderWorkflowState:
        """What this provider believes about the workflow.

        A BELIEF ABOUT EXECUTION, not the record of what happened. Andyur's run
        rows are authoritative for the latter and an audit reads those; this
        reports only how far along the engine thinks things are.

        The mapping reads the workflow's runs because that is where the native
        engine keeps progress -- there is no other place. A workflow with a
        live run is RUNNING or QUEUED depending on whether anything has started
        it; one whose runs are all terminal takes its outcome from them.
        """
        state = coordinator.workflow_state(workflow_id)
        if state is None:
            raise WorkflowNotFound(workflow_id)
        if state == "halted":
            return ProviderWorkflowState(
                workflow_id=workflow_id, state=WorkflowState.HALTED, provider=NAME)

        with db.connect() as conn:
            rows = conn.execute(
                "SELECT state FROM runs WHERE workflow_id = ?", (workflow_id,)
            ).fetchall()
        states = [r["state"] for r in rows]

        if "running" in states:
            projected = WorkflowState.RUNNING
        elif "pending" in states:
            projected = WorkflowState.QUEUED
        elif not states:
            # Admitted as a workflow but carrying no run yet. REQUESTED rather
            # than SUCCEEDED: an empty workflow has not finished, and reporting
            # a terminal state here would let a caller free something early.
            projected = WorkflowState.REQUESTED
        else:
            # NO LIVE RUNS, AND THE WORKFLOW IS STILL OPEN. This reported a
            # terminal state derived from the runs' outcomes, and that was
            # wrong in a way this method's own comment warns against: an active
            # workflow accepts more work, so SUCCEEDED or CANCELLED here has
            # `is_terminal()` true for something that is not finished. The
            # operator halt-then-unhalt flow produces exactly that -- every run
            # cancelled, the workflow active again.
            #
            # The native engine has no notion of a workflow COMPLETING. A
            # workflow is open until it is halted, so "idle between runs" is
            # the honest answer, and WAITING is the only non-terminal state
            # that means it.
            projected = WorkflowState.WAITING

        return ProviderWorkflowState(
            workflow_id=workflow_id, state=projected, provider=NAME,
            detail=f"{len(states)} run(s); a workflow is open until halted")

    # --- recurring work -----------------------------------------------------

    def create_schedule(self, spec: ScheduleSpec) -> ScheduleHandle:
        """Delegate to Andyur's cron, honouring the whole spec.

        `spec.on_overlap` is checked rather than honoured, because there is only
        one behaviour here and it is the required one. A caller asking for
        anything else is asking for something this provider does not do, and
        silently giving it the behaviour it has instead is how a backlog appears
        where someone expected a drop.

        `schedule_id` and `paused` ARE honoured, and were silently dropped in
        the first draft: the service minted its own id, so the handle named
        something the caller had not asked for and `update_schedule` could not
        find its own row; and a spec created paused fired at its next slot.
        """
        if spec.on_overlap != "skip_and_retry_soon":
            raise ProviderCapabilityMissing(
                f"schedule overlap:{spec.on_overlap}", NAME, frozenset({"schedules"}))
        created = schedule_service.create_schedule(
            spec.agent, spec.cron, spec.reason,
            schedule_id=spec.schedule_id, paused=spec.paused)
        return ScheduleHandle(
            schedule_id=created["id"], provider=NAME, provider_ref=created["id"])

    def update_schedule(self, spec: ScheduleSpec) -> None:
        """Replace a schedule's definition, keeping its id.

        The native service has no update, so this is delete-then-create UNDER
        THE CALLER'S OWN ID. Keeping the id is the whole point: the first draft
        let the service mint a new one, so the second update deleted nothing and
        created another row -- after N updates the agent fired N+1 times per
        tick and `delete_schedule` could not stop any of them.

        Stated rather than hidden: the replacement is NOT atomic, and a crash
        between the two leaves the schedule absent rather than stale. Absent is
        the safer of the two -- a schedule that does not fire is visible, while
        one firing an old definition is not -- but a caller relying on
        atomicity would be wrong.
        """
        schedule_service.delete_schedule(spec.schedule_id)
        schedule_service.create_schedule(
            spec.agent, spec.cron, spec.reason,
            schedule_id=spec.schedule_id, paused=spec.paused)

    def delete_schedule(self, schedule_id: str) -> None:
        """Idempotent: the caller's intent is that it must not fire, and an
        absent schedule already satisfies that. A schedule the engine fires is
        not this provider's to remove, and is refused rather than dropped."""
        schedule_service.delete_native_schedule(schedule_id)

"""The workflow provider interface.

One sentence governs every method below:

    **Andyur decides whether the actor may act. The provider decides when work
    progresses.**

A provider is infrastructure. It schedules, it waits, it retries, it survives
restarts. It never decides whether a run is admitted, who it acts for, what
scope it carries, or whether an action still requires approval -- and it is
never the thing that destroys an execution.

## The interface is synchronous

Andyur's core is synchronous -- the coordinator, the schedule service, the
heartbeat's work, and even the HTTP endpoints, which Starlette runs in a
threadpool. The only async thing in the server is the heartbeat loop itself,
which calls its sync work directly.

This interface was async in its first draft, for one reason: a candidate
engine's client library is async. That is engine mechanics, and engine mechanics
belong inside a provider, alongside its task queues and its retry policies. An
async interface would have forced `create_task`, `send_message`, `fire_due`,
`_drain_one` and `trigger_agent` -- and everything calling them -- to become
async, which is a large behavioural change in service of one implementation's
convenience.

A provider whose engine is async owns a dedicated event loop internally and
bridges to it. That was measured rather than assumed, because the obvious bridge
does not work: `asyncio.run` inside a sync function is fine from a threadpool
endpoint and RAISES from `fire_due`, which the heartbeat loop calls
synchronously from inside a running loop. A dedicated loop in its own thread
works from both. Either way it is the provider's problem, contained where such
problems belong.

## Two absences, both deliberate

**There is no `cancel`.** The obvious SPI has one, and plan section 19 assumed
halt would be provider cancellation plus runtime termination. The Stage 2 spike
measured this against Temporal and it does not hold: cancelling a workflow
cancels the workflow's own execution, so any cleanup it tries to run afterwards
is cancelled with it. The containment step was never even scheduled -- the
history went straight from ACTIVITY_TASK_CANCEL_REQUESTED to
WORKFLOW_EXECUTION_CANCELED. Shielding did not help; the Python SDK has no
detached scope to put cleanup in. Worse, a step that does not heartbeat never
learns it was cancelled at all and runs to completion, which is exactly the
wedged-runner case a kill switch exists for.

So `halt` is what this interface offers, it means only "stop making durable
progress", and its contract is written so that no caller can mistake it for
containment.

**There is no `terminate` or `destroy`.** Containment -- destroying the
container the untrusted code runs in -- does not pass through this interface at
all. Andyur already owns that path: the platform condemns a run from its own
record and the executor destroys it. Routing containment through the provider
would make the kill switch depend on the availability of the engine, and the
whole point of a kill switch is that it works when things are going wrong.

The division, stated once:

    halt (this interface)   stop durable progress        orchestration
    condemnation (Andyur)   destroy the execution        containment

A provider that is down must not be able to keep a compromised agent alive.

## Idempotency

`start` is idempotent on `workflow_id`, and `halt` is idempotent on the same.
This is not politeness: a durable engine delivers at least once, and Andyur
itself retries. The spike measured what happens without it -- a step whose
effect landed before its acknowledgement was lost ran three times under a
three-attempt retry policy, which for a launch would mean three containers for
one admitted run. Providers implement the rule at the boundary; Andyur backs it
with the constraint that already refuses a second live run per agent.

## Conformance

The three capabilities in `capabilities.MANDATORY` are not self-declared. A
provider asserts them by passing the orchestration contract suite, which is
written against observable semantics precisely so that it can be run against any
provider. Advertising them in code proves nothing.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .capabilities import ProviderCapabilities
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
)


@runtime_checkable
class WorkflowProvider(Protocol):
    """What Andyur requires of anything that runs workflows.

    Implementations live in `andyur/orchestration/<name>/provider.py` and are
    the ONLY place a specific engine's SDK may be imported. Nothing in this
    package, and nothing above it, may import one.
    """

    @property
    def name(self) -> str:
        """Short, stable identifier -- "local", "temporal". Appears in stored
        state and in operator-facing output, so it does not change once work has
        been recorded against it."""
        ...

    @property
    def dispatches_runs(self) -> bool:
        """Whether THIS provider hands an admitted run to an executor itself.

        False: Andyur's native assignment loop dispatches the run and the
        provider only tracks its progress. True: the provider dispatches it,
        and the native loop must never select it -- the facade records which
        when the run is admitted, so the two cannot both claim one run.
        """
        ...

    def capabilities(self) -> ProviderCapabilities:
        """The durability guarantees this provider offers. Conservative: a
        capability is a promise something will be built on."""
        ...

    def health(self) -> ProviderHealth:
        """Whether the engine can currently accept work.

        Reports rather than raises, so the control plane can refuse new durable
        work while continuing to serve reads of Andyur's own record.
        """
        ...

    # --- running work -------------------------------------------------------

    def start(self, request: WorkflowStart) -> WorkflowHandle:
        """Begin one workflow, or return the handle of the one already running.

        IDEMPOTENT ON `workflow_id`. Starting the same id twice yields the same
        logical execution and must not produce a second one. Raise
        `WorkflowAlreadyExists` only when a genuinely DIFFERENT workflow holds
        the id, which is a programming error rather than a race.

        Raises `ProviderUnavailable` when the engine could not be reached --
        transient by contract, so callers may retry it.
        """
        ...

    def signal(self, workflow_id: str, signal: WorkflowSignal) -> None:
        """Deliver a named message to a running workflow.

        Delivery is at-least-once, so a workflow's handling of any signal must
        tolerate seeing it twice. Raises `WorkflowNotFound` if the provider has
        no such workflow; that is not the same as the workflow having finished,
        and a caller must not read it as an outcome.
        """
        ...

    def halt(self, request: HaltRequest) -> HaltOutcome:
        """Stop making durable progress on a workflow.

        **THIS DOES NOT DESTROY ANYTHING.** It does not stop a process, does not
        remove a container, and does not guarantee that a step already running
        will notice. A step that is wedged -- which is the case an operator
        reaches for the kill switch about -- may continue to completion after
        this returns successfully.

        Containment is Andyur's condemnation path and runs regardless of what
        this returns. Callers MUST NOT treat a successful halt as evidence that
        an agent has stopped, and must not skip condemnation because this
        succeeded.

        Idempotent: halting an already-halted or finished workflow is not an
        error and reports the current state.

        **A workflow the provider has never heard of is ALSO not an error.**
        There is no durable progress to stop, so the request is already
        satisfied. This is deliberately the opposite of `describe`, and the
        asymmetry is the kill switch's: refusing to halt something because the
        provider has not seen it yet would fail exactly when an operator is
        racing a workflow that is starting, which is when they most need it.
        Andyur's own governance halt is authoritative and takes effect either
        way -- the platform records the workflow halted so that work attempting
        to join it is refused, whether or not any execution exists yet.

        Raises `HaltNotAcknowledged` when the provider cannot confirm it has the
        request durably -- distinct from `ProviderUnavailable` because the
        operator needs to know the kill switch specifically was not accepted.
        """
        ...

    def describe(self, workflow_id: str,
                 run_ids: tuple[str, ...] = ()) -> ProviderWorkflowState:
        """What the provider believes about this workflow.

        `run_ids` are the workflow's live runs as Andyur's record names them,
        oldest first -- the same contract as `HaltRequest.run_ids`. A provider
        that runs one execution per run describes the newest; one that runs a
        single execution per workflow ignores them.

        Its belief, not the truth. Andyur's own record is authoritative for what
        happened; this is authoritative only for what is still executing. When
        they disagree, Andyur wins -- see `models.WorkflowState`.

        Raises `WorkflowNotFound` rather than inventing a terminal state for a
        workflow whose history the provider has forgotten.
        """
        ...

    # --- recurring work -----------------------------------------------------

    def create_schedule(self, spec: ScheduleSpec) -> ScheduleHandle:
        """Own a recurring trigger.

        Only offered by a provider advertising `schedules`, and only meaningful
        if it can honour Andyur's overlap rule: a tick that finds its agent busy
        is retried shortly, never buffered into a backlog and never silently
        dropped. A provider whose scheduler cannot express that must advertise
        `schedules=False` and leave the driving to Andyur.
        """
        ...

    def update_schedule(self, spec: ScheduleSpec) -> None:
        """Replace a schedule's definition, keyed on `schedule_id`."""
        ...

    def delete_schedule(self, schedule_id: str) -> None:
        """Remove a schedule. Idempotent: deleting an absent schedule is not an
        error, because the caller's intent -- that it should not fire -- is
        already satisfied."""
        ...

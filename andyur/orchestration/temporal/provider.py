"""Temporal as an Andyur workflow provider.

Synchronous, like the interface it implements: the asynchrony stops in
`client.py`, on a private event loop, because Andyur's core is synchronous and
one implementation's SDK is not a reason to make it otherwise.

## What this slice advertises, and what it does not

Capabilities are a promise something will be built on, so this claims only what
it implements today. Schedules and child workflows are **not** claimed -- the
first slice is one ordinary headless run -- which means a workflow kind
requiring them is refused by the capability check before it reaches here, rather
than reaching a method that would have to invent something.

`provider_failover` is False regardless of deployment. A single-node dev service
and a replicated cluster both answer this API, and code cannot tell them apart;
claiming it here would put a deployment's property in a build's mouth.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from ..capabilities import ProviderCapabilities
from ..errors import (
    HaltNotAcknowledged,
    ProviderCapabilityMissing,
    ProviderProtocolError,
    ProviderUnavailable,
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
from .client import TemporalConnection
from .config import TemporalConfig

NAME = "temporal"

HALT_SIGNAL = "halt"

# Temporal's own status names to Andyur's vocabulary. A status this map does not
# cover raises rather than being guessed at: a state Andyur cannot name is not
# one it may report wrongly, and reporting a run's state wrongly is how an agent
# gets freed while something is still running.
_STATUS = {
    "RUNNING": WorkflowState.RUNNING,
    "COMPLETED": WorkflowState.SUCCEEDED,
    "FAILED": WorkflowState.FAILED,
    "CANCELED": WorkflowState.CANCELLED,
    "TERMINATED": WorkflowState.CANCELLED,
    "CONTINUED_AS_NEW": WorkflowState.RUNNING,
    "TIMED_OUT": WorkflowState.FAILED,
}


def run_execution_id(run_id: str) -> str:
    """The engine execution that observes one Andyur RUN.

    ONE PER RUN, and it was one per WORKFLOW. An Andyur workflow holds many
    runs -- every delegated task or message joins its parent's -- and keying the
    execution by the workflow id meant only the first run was ever observed. A
    second run's start got the first run's live execution back (the conflict
    policy returns the existing one), or, once that had completed, a "started"
    reply naming a closed execution. Runs 2..N had no durable observation and
    nothing a halt signal could reach, and `describe()` reported the workflow
    finished while they were still running.

    Keyed by run, a duplicate start for the SAME run still collapses onto one
    execution, which is the idempotency the design rests on; different runs
    get different executions, which is what was missing.
    """
    return f"andyur-run-{run_id}"


class TemporalWorkflowProvider:
    """Andyur's workflow semantics, on a Temporal service."""

    def __init__(self, config: TemporalConfig | None = None,
                 connection: TemporalConnection | None = None) -> None:
        self._config = config or TemporalConfig.from_env()
        self._conn = connection or TemporalConnection(self._config)

    @property
    def name(self) -> str:
        return NAME

    @property
    def dispatches_runs(self) -> bool:
        # Architecture B+ when configured for it (ADR-014 D11); otherwise the
        # engine observes a run the native loop dispatches (Architecture A).
        return self._config.dispatch == "engine"

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=NAME,
            durable_execution=True,
            durable_timers=True,
            durable_signals=True,
            long_running_waits=True,
            # The engine owns the trigger, and Andyur's overlap rule is
            # preserved by the workflow it starts -- see ScheduledAgentRun.
            # Child workflows are still not claimed.
            schedules=True,
            child_workflows=False,
            # Deployment-dependent, and a build cannot know. See the docstring.
            provider_failover=False,
        )

    def health(self) -> ProviderHealth:
        """Reports rather than raises, so the control plane can refuse new
        durable work while continuing to serve reads of Andyur's own record.

        THE NAMESPACE IS PART OF HEALTH, and it was not. This asked
        `GetSystemInfo` alone, which is not scoped to a namespace, so a
        misspelled `ANDYUR_TEMPORAL_NAMESPACE` -- or one never registered --
        reported healthy. That mattered because the service answers a missing
        namespace with NOT_FOUND, the same code as a missing workflow, and halt
        treats a missing workflow as already halted: probed, every halt then
        returned "accepted, HALTED" against an engine that had never heard of
        the workflow, and nothing was red. Starts do fail loudly in that state;
        the kill switch did not.
        """
        try:
            from temporalio.api.workflowservice.v1 import (
                DescribeNamespaceRequest, GetSystemInfoRequest)
            client = self._conn.client()
            self._conn.run(client.workflow_service.get_system_info(
                GetSystemInfoRequest()))
        except Exception as exc:                  # noqa: BLE001 - reported
            return ProviderHealth(
                provider=NAME, reachable=False,
                detail=f"{self._config.describe()}: {type(exc).__name__}: {exc}")
        try:
            self._conn.run(client.workflow_service.describe_namespace(
                DescribeNamespaceRequest(namespace=self._config.namespace)))
        except Exception as exc:                  # noqa: BLE001 - reported
            return ProviderHealth(
                provider=NAME, reachable=False,
                detail=(f"{self._config.describe()}: the service answers, but "
                        f"namespace {self._config.namespace!r} does not: "
                        f"{type(exc).__name__}: {exc}"))
        return ProviderHealth(
            provider=NAME, reachable=True, detail=self._config.describe())

    # --- running work -------------------------------------------------------

    def start(self, request: WorkflowStart) -> WorkflowHandle:
        """Begin the workflow, or return the one already running.

        IDEMPOTENT ON `workflow_id`, which Temporal gives directly: starting an
        id that is already running returns that execution rather than a second
        one. That is the property the whole design rests on -- a duplicate
        delivery must not produce two executions for one admitted run.
        """
        from temporalio.common import (
            WorkflowIDConflictPolicy, WorkflowIDReusePolicy)
        from temporalio.exceptions import WorkflowAlreadyStartedError

        from .workflows import AndyurExecution, AndyurRun

        engine = self._config.dispatch == "engine"
        client = self._conn.client()
        try:
            handle = self._conn.run(client.start_workflow(
                # ENGINE DISPATCH: the execution workflow runs one
                # `execute_run(run_id)` Activity on the execution queue, where
                # only the execution worker listens (Architecture B+, D11).
                # Otherwise the observer, on the control plane's own queue.
                AndyurExecution.run if engine else AndyurRun.run,
                # `args=` RATHER THAN A BARE POSITIONAL, because the workflow
                # takes a second, defaulted parameter that continuations use to
                # carry the halt flag. The single-argument form is the typed
                # overload for a one-parameter run method, and it stops being
                # the right shape the moment that is not true.
                args=[request.root_run_id],
                id=run_execution_id(request.root_run_id),
                task_queue=(self._config.execution_queue if engine
                            else self._config.task_queue),
                # IDEMPOTENCY, DECIDED BY THE SERVER. `USE_EXISTING` means a
                # start for an id that is already running returns THAT
                # execution rather than failing -- which is exactly Andyur's
                # contract, settled atomically instead of by catching a race.
                # The first draft caught an exception instead, which is both
                # slower and wrong under concurrency.
                id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
                # A run id is used once -- which is now literally true, since
                # the execution is keyed by the run. Reuse is allowed only after
                # the previous execution did not complete: FAILED, and also
                # TERMINATED, CANCELED or TIMED_OUT, which an earlier version of
                # this comment left out. A completed run's execution is never
                # recycled into a second one.
                id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY,
            ))
        except WorkflowAlreadyStartedError as exc:
            # Reachable only when the policy above cannot apply (a completed
            # execution holding the id). The existing one is the answer, and
            # its run id comes from the error rather than from
            # `get_workflow_handle`, which returns a handle with none -- the
            # binding would otherwise record no engine reference for exactly
            # the workflows that already had one.
            return WorkflowHandle(
                workflow_id=run_execution_id(request.root_run_id), provider=NAME,
                provider_ref=getattr(exc, "run_id", None))
        except ProviderUnavailable:
            raise
        except Exception as exc:                  # noqa: BLE001 - normalized
            raise self._translate(exc, request.workflow_id) from exc

        return WorkflowHandle(
            workflow_id=run_execution_id(request.root_run_id), provider=NAME,
            provider_ref=getattr(handle, "result_run_id", None)
            or getattr(handle, "run_id", None))

    def signal(self, workflow_id: str, signal: WorkflowSignal) -> None:
        client = self._conn.client()
        handle = client.get_workflow_handle(workflow_id)
        # `args=[]` FOR AN EMPTY PAYLOAD, not a positional None. `payload`
        # defaults to `{}`, which is falsy, so `payload or None` passed an
        # explicit None ARGUMENT -- and the SDK delivers one value per payload
        # regardless of the handler's signature. Every signal handler in this
        # package takes no parameters, so they were called as `halt(self, None)`
        # and raised TypeError, failing the workflow task. The doorbell could
        # not be rung through the interface at all.
        args = [signal.payload] if signal.payload else []
        try:
            self._conn.run(handle.signal(signal.name, args=args))
        except Exception as exc:                  # noqa: BLE001 - normalized
            raise self._translate(exc, workflow_id) from exc

    def halt(self, request: HaltRequest) -> HaltOutcome:
        """Stop durable progress. **Destroys nothing.**

        A SIGNAL, not a cancellation, and the difference was measured: cancelling
        cancels the workflow's own cleanup, so the containment step is never
        scheduled, and a step that does not heartbeat never learns it was
        cancelled at all. Containment is Andyur's condemnation path and runs
        whether or not this succeeds.

        ## Every live run, named by Andyur

        Executions are one per RUN, so halting a workflow means signalling each
        of its live runs. The facade supplies them from Andyur's own record,
        AFTER writing the governance halt. Asking the engine to list them
        instead would read its visibility store, which is eventually consistent:
        a run started a moment ago might not be listed yet, and the kill switch
        would silently miss it.

        An execution the service has never heard of is ACCEPTED, not refused.
        There is no durable progress to stop, so the request is already
        satisfied -- and refusing would break the kill switch exactly when an
        operator is racing a run that is starting. The same holds for a workflow
        with no live runs at all.

        One failure mode, one error: `client()` is inside the `try`, so an
        unreachable service raises `HaltNotAcknowledged` whether this process
        connected an hour ago or never did.

        ALL RUNS AT ONCE, UNDER ONE BOUND. Signalling one run after another let
        a hung service hold the kill switch for N x the RPC timeout -- minutes,
        for the runaway fan-out a halt exists for. Every signal carries its own
        RPC deadline, so none outlives the call.

        A MISSING NAMESPACE IS NOT A MISSING RUN. The service answers both with
        NOT_FOUND; `_translate` tells them apart, and only a missing execution
        counts as already halted.
        """
        executions = [run_execution_id(r) for r in request.run_ids]
        if not executions:
            return HaltOutcome(
                workflow_id=request.workflow_id, accepted=True,
                state=WorkflowState.HALTED,
                detail="no live run to signal; Andyur's record is authoritative "
                       "and containment does not run through this provider")

        failures = []
        signalled = 0
        try:
            client = self._conn.client()
        except Exception as exc:                  # noqa: BLE001
            raise HaltNotAcknowledged(
                f"the halt of '{request.workflow_id}' was not accepted: the "
                f"workflow service is unreachable: {type(exc).__name__}: {exc}"
            ) from exc
        deadline = timedelta(seconds=self._config.rpc_timeout_seconds)

        async def signal_all():
            return await asyncio.gather(
                *(client.get_workflow_handle(e).signal(HALT_SIGNAL, rpc_timeout=deadline)
                  for e in executions),
                return_exceptions=True)

        try:
            results = self._conn.run(signal_all())
        except Exception as exc:                  # noqa: BLE001
            raise HaltNotAcknowledged(
                f"the halt of '{request.workflow_id}' was not accepted: signalling "
                f"{len(executions)} run(s) did not complete: "
                f"{type(exc).__name__}: {exc}") from exc
        for execution, result in zip(executions, results):
            if not isinstance(result, BaseException):
                signalled += 1
            elif isinstance(self._translate(result, execution), WorkflowNotFound):
                continue                          # already gone: nothing to stop
            else:
                failures.append(f"{execution}: {type(result).__name__}: {result}")

        if failures:
            raise HaltNotAcknowledged(
                f"the halt of '{request.workflow_id}' was not accepted for "
                f"{len(failures)} of {len(executions)} run(s): "
                + "; ".join(failures))

        return HaltOutcome(
            workflow_id=request.workflow_id, accepted=True,
            state=WorkflowState.HALTING if signalled else WorkflowState.HALTED,
            detail=(f"halt signalled to {signalled} run(s); the executions are "
                    "destroyed by condemnation, which does not run through the "
                    "provider"))

    def describe(self, workflow_id: str,
                 run_ids: tuple[str, ...] = ()) -> ProviderWorkflowState:
        # Executions are per RUN: given Andyur's live runs, the newest one's
        # execution is the workflow's current progress. Given none, the id is
        # an execution id already -- what `start` returned on the handle.
        target = run_execution_id(run_ids[-1]) if run_ids else workflow_id
        client = self._conn.client()
        handle = client.get_workflow_handle(target)
        try:
            desc = self._conn.run(handle.describe())
        except Exception as exc:                  # noqa: BLE001
            raise self._translate(exc, workflow_id) from exc

        raw = getattr(getattr(desc, "status", None), "name", None)
        state = _STATUS.get(raw)
        if state is None:
            raise ProviderProtocolError(
                f"the workflow service reported status {raw!r} for "
                f"'{workflow_id}', which Andyur has no name for")
        return ProviderWorkflowState(
            workflow_id=workflow_id, state=state, provider=NAME,
            provider_ref=getattr(desc, "run_id", None), detail=raw)

    # --- recurring work: not in this slice ----------------------------------

    def create_schedule(self, spec: ScheduleSpec) -> ScheduleHandle:
        """Hand the trigger to the engine, keeping Andyur's overlap rule.

        `SKIP` so executions never stack. It is NOT the whole rule: Andyur
        retries a tick whose agent was busy, and no native overlap policy says
        that -- buffering is the behaviour the rule forbids and skipping is the
        defect it was written to fix. The retry is a durable timer inside
        `ScheduledAgentRun`, which survives the worker dying mid-wait in a way
        the native engine's re-armed row does not.

        A caller asking for any other overlap is refused rather than quietly
        given this one.
        """
        from temporalio.client import (
            Schedule, ScheduleActionStartWorkflow, ScheduleOverlapPolicy,
            SchedulePolicy, ScheduleSpec as TemporalScheduleSpec, ScheduleState)

        from .workflows import ScheduledAgentRun

        if spec.on_overlap != "skip_and_retry_soon":
            raise ProviderCapabilityMissing(
                f"schedule overlap:{spec.on_overlap}", NAME, frozenset({"schedules"}))

        client = self._conn.client()
        action = ScheduleActionStartWorkflow(
            ScheduledAgentRun.run,
            # The schedule's own id rides along: admission refuses a tick
            # that does not name a schedule Andyur holds.
            args=[spec.agent, spec.reason, 30.0, 300.0, spec.schedule_id],
            id=f"sched-{spec.schedule_id}",
            task_queue=self._config.task_queue,
        )
        schedule = Schedule(
            action=action,
            spec=TemporalScheduleSpec(cron_expressions=[spec.cron]),
            policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
            # Created paused when asked, rather than created-then-paused: the
            # two-step version has a window in which a schedule the caller
            # asked to be paused can fire.
            state=ScheduleState(paused=spec.paused),
        )
        try:
            self._conn.run(client.create_schedule(
                spec.schedule_id, schedule, trigger_immediately=False))
        except Exception as exc:                  # noqa: BLE001
            if "AlreadyRunning" in type(exc).__name__ or "AlreadyExists" in str(exc):
                # Idempotent: the caller's intent is that this trigger exists.
                return ScheduleHandle(schedule_id=spec.schedule_id, provider=NAME,
                                      provider_ref=spec.schedule_id)
            raise self._translate(exc, spec.schedule_id) from exc

        return ScheduleHandle(schedule_id=spec.schedule_id, provider=NAME,
                              provider_ref=spec.schedule_id)

    def update_schedule(self, spec: ScheduleSpec) -> None:
        """Replace a schedule's definition, keeping its id.

        Delete-then-create under the caller's OWN id. The engine offers an
        in-place update, and it is not used here for one reason: the native
        provider cannot do an atomic replace either, and a contract that holds
        on one provider and not the other is not a contract. Both are
        non-atomic, and both leave the schedule ABSENT rather than stale if
        they are interrupted -- absent is visible, stale is not.
        """
        # VALIDATED BEFORE THE DELETE. Checking inside `create_schedule` meant
        # an update carrying an unsupported overlap deleted the existing
        # schedule and THEN refused -- so the agent's cron silently stopped
        # firing and nothing was put back. A refusal must cost nothing.
        if spec.on_overlap != "skip_and_retry_soon":
            raise ProviderCapabilityMissing(
                f"schedule overlap:{spec.on_overlap}", NAME, frozenset({"schedules"}))
        self.delete_schedule(spec.schedule_id)
        self.create_schedule(spec)

    def delete_schedule(self, schedule_id: str) -> None:
        """Idempotent: an absent schedule already satisfies "must not fire"."""
        client = self._conn.client()
        try:
            self._conn.run(client.get_schedule_handle(schedule_id).delete())
        except Exception as exc:                  # noqa: BLE001
            if isinstance(self._translate(exc, schedule_id), WorkflowNotFound):
                return
            raise self._translate(exc, schedule_id) from exc

    # --- error translation ---------------------------------------------------

    @staticmethod
    def _translate(exc: Exception, workflow_id: str) -> Exception:
        """A provider's own exceptions never leave this package.

        ON THE gRPC STATUS, NOT THE CLASS NAME, and the first version got that
        wrong. The SDK wraps every server-side refusal in one `RPCError` whose
        name says nothing -- so matching on "NotFound" in the class name never
        matched, and a workflow the service had never heard of came back as
        "unavailable". Stage 9 found it against a live service; nothing without
        one could have.

        The status is what the server actually said, so that is what this reads.
        """
        status = getattr(exc, "status", None)
        code = getattr(status, "name", None) or getattr(status, "value", None)

        if code in ("NOT_FOUND", 5) and _names_a_missing_namespace(exc):
            # The same code as a missing execution, and the opposite meaning:
            # nothing in this namespace can be reached, so it is a
            # configuration fault, never "already gone".
            return ProviderProtocolError(
                f"the workflow service has no such namespace: {exc}")
        if code in ("NOT_FOUND", 5):
            return WorkflowNotFound(workflow_id)
        if code in ("UNAVAILABLE", 14, "DEADLINE_EXCEEDED", 4):
            return ProviderUnavailable(f"{code}: {exc}")
        if code is not None:
            # A refusal the server named and Andyur has no meaning for. Reported
            # as a protocol error rather than folded into "unavailable", because
            # retrying an ALREADY_EXISTS or a PERMISSION_DENIED forever is worse
            # than failing loudly once.
            return ProviderProtocolError(
                f"the workflow service refused with {code}: {exc}")

        name = type(exc).__name__
        if "NotFound" in name:
            return WorkflowNotFound(workflow_id)
        return ProviderUnavailable(f"{name}: {exc}")


def _names_a_missing_namespace(exc: Exception) -> bool:
    """Whether a NOT_FOUND is about the namespace rather than an execution.

    The service attaches a typed failure detail -- `NamespaceNotFoundFailure`
    for a namespace, `NotFoundFailure` for an execution -- and that is what is
    read. The message is a fallback for a client that drops the details."""
    for detail in getattr(getattr(exc, "grpc_status", None), "details", None) or ():
        if "NamespaceNotFoundFailure" in getattr(detail, "type_url", ""):
            return True
    return "namespace" in str(exc).lower() and "not found" in str(exc).lower()

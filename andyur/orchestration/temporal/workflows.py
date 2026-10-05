"""The workflow itself: durable, deterministic, and deliberately uninformed.

It knows a run id and nothing else. It cannot see Andyur's database, holds no
credential, and makes no authority decision -- every question it needs answered
is asked through an activity, at the moment the answer matters.

## Halt is a signal, and that was measured

The obvious design is to cancel the workflow. A disposable spike against a real
Temporal service showed that cancelling cancels the workflow's own execution, so
any cleanup it attempts afterwards is cancelled with it -- the recorded history
went from the step being asked to cancel straight to the workflow reporting
itself cancelled, with the cleanup step never scheduled. Shielding did not help;
the Python SDK has no detached scope to put cleanup in. And a step that does not
heartbeat never learns it was cancelled at all and runs to completion, which is
the wedged-runner case a kill switch exists for.

So halt arrives as a SIGNAL. The workflow stays alive, handles it on its normal
control flow, records it, and stops waiting. **Containment is not its job** --
Andyur condemns the run from its own record and the executor destroys it,
which is what keeps the kill switch working when this service is not.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from .activities import (
        ActionRef, RunRef, ScheduledTrigger, admit_scheduled_run,
        note_halt, observe_state, read_action_decision)
    from ...registry.models import LIFETIME_CEILING_SECONDS

# How long between asking Andyur what the run is doing. Short enough that a
# finished run is noticed promptly, long enough that a long run does not fill
# its own history with polls -- every one of these is a durable event.
POLL = timedelta(seconds=5)

# The ceiling on one activity call. Not the run's lifetime: a run's deadline is
# Andyur's reaper, which is authoritative and does not need this to agree.
CALL_TIMEOUT = timedelta(seconds=30)

TERMINAL = {"done", "failed", "cancelled", "absent"}

# How many polls one EXECUTION may run before handing the run to a fresh one.
#
# History is durable and it only grows: every poll writes an activity's three
# events, a timer's two, and the workflow tasks that drive them -- call it ten.
# Temporal warns around 10,240 events and REFUSES around 51,200, so an
# unbounded loop at a five-second poll has a lifetime measured in hours. This
# platform exists for LONG-LIVED agents, so a run whose observation dies after
# an afternoon is not a limit, it is the product failing.
#
# 250 polls is about twenty minutes and roughly 2,500 events -- an order of
# magnitude below the warning, which leaves room for the estimate above to be
# wrong without the bound being wrong.
#
# It is the DEFAULT of a workflow argument rather than a constant the workflow
# reads, so the bound a run is observed under is recorded in its own history
# and replays identically. Anything read from the environment at run time
# would not be: a worker started with a different setting would replay someone
# else's run against a number that run never used, and replay divergence is
# the failure Temporal cannot recover from.
#
# An earlier version of this comment gave a different reason -- "the sandbox
# re-imports this module" -- and it was false when written. `andyur` was
# passed through the sandbox wholesale, so this module was never re-imported
# and its determinism checks were off; see `worker.build_worker`, which now
# passes through only the heavy leaves so that it IS re-imported and checked.
# The reason above never depended on the sandbox, and does not now.
MAX_POLLS_PER_EXECUTION = 250


@workflow.defn
class AndyurRun:
    """One ordinary headless run, observed durably.

    WHAT THIS SLICE DOES NOT DO, stated so nobody infers it: it does not launch
    the run. Launching is the worker daemon's, through the execution port, and
    moving it here is a later stage with its own evidence. What this provides
    today is durability around a run's lifecycle -- the wait survives the worker
    dying, the halt survives it too, and the guards on start and finish are
    exercised against at-least-once delivery.
    """

    def __init__(self) -> None:
        self._halted = False

    @workflow.signal
    def halt(self) -> None:
        """Delivered at least once. Setting a flag twice is the same as once,
        which is what makes that safe."""
        self._halted = True

    @workflow.query
    def halted(self) -> bool:
        return self._halted

    @workflow.run
    async def run(self, run_id: str, halted: bool = False,
                  max_polls: int = MAX_POLLS_PER_EXECUTION) -> str:
        ref = RunRef(run_id=run_id)

        # CARRIED ACROSS THE HANDOFF, because a continuation is a NEW execution
        # with a new instance of this class, so `self._halted` starts False
        # again. A halt signalled during the last wait before a handoff would
        # otherwise be dropped. Andyur's governance halt is the authoritative
        # one and condemnation would eventually make the run terminal anyway,
        # so the loss would self-correct -- but "corrects eventually" is not
        # the same as "is not lost", and the record of the halt would be gone.
        # KEEP A HALT THAT HAS ALREADY ARRIVED. The SDK applies the signals of
        # the first workflow task BEFORE `run` starts, so a halt delivered with
        # the start -- a kill switch pressed the moment a run began -- set the
        # flag, and this line then set it back to False: the halt was lost and
        # the workflow observed on as though nothing had happened. Timing-
        # dependent (a fast worker finishes the first task before the signal
        # lands), so it passed everywhere but a 2-CPU CI runner, where the
        # history showed WorkflowExecutionSignaled before the first
        # WorkflowTaskStarted and polling forever after.
        self._halted = self._halted or halted

        # THIS WORKFLOW DOES NOT START THE RUN, and an earlier version did.
        #
        # It called an activity that marked the run `running`, which read like
        # harmless bookkeeping and was in fact fatal: the worker daemon claims
        # runs `WHERE state = 'pending'`, so moving the run out of `pending`
        # meant it was NEVER ASSIGNED and never launched. The run sat in
        # `running` with nothing running, and this loop observed that state
        # forever. Under the native provider the same call was invisible,
        # because there `start` is a no-op -- admission and dispatchability are
        # the same act.
        #
        # The transition belongs to the RUN. `POST /runs/{id}/start` is
        # authenticated by the run's own SVID: the agent announces that it
        # started, and nothing else is entitled to say so on its behalf. This
        # workflow's job is durability around a lifecycle it observes and does
        # not drive -- which is what its own docstring says, and what the
        # activity contradicted.

        polls = 0
        while True:
            if self._halted:
                await workflow.execute_activity(
                    note_halt, ref, start_to_close_timeout=CALL_TIMEOUT)
                # NOT a terminal write. The run's outcome is recorded by
                # whatever actually ends it -- the condemnation path, or the
                # reaper. Writing "halted" here would be this workflow forming
                # an opinion about an execution it cannot see.
                return "halted"

            state = await workflow.execute_activity(
                observe_state, ref, start_to_close_timeout=CALL_TIMEOUT)
            if state in TERMINAL:
                return state

            polls += 1
            # TWO TRIGGERS, AND THE SECOND IS NOT REDUNDANT. The server's own
            # suggestion is the better signal -- it knows the limits actually
            # configured, which this module cannot -- but it is ADVICE from a
            # service, and a service that never sends it (misconfigured, or
            # older than the field) would leave the loop unbounded again with
            # nothing in the code to say so. The poll cap is the floor that
            # holds without the server's help, and it is what a test can force.
            #
            # Checked AFTER the terminal test, so a run that has just finished
            # completes here rather than being handed to a fresh execution that
            # would start, observe it terminal, and immediately exit.
            if (polls >= max_polls
                    or workflow.info().is_continue_as_new_suggested()):
                # Raises; nothing below runs. The flag and the bound go with
                # it: a continuation that fell back to the default would be a
                # different workflow from the one that started.
                workflow.continue_as_new(args=[run_id, self._halted, max_polls])

            # A DURABLE timer. It survives the worker dying, which is the whole
            # reason this workflow exists rather than a loop in the daemon.
            #
            # THE TIMEOUT IS THE ORDINARY CASE AND IT RAISES. `wait_condition`
            # throws `asyncio.TimeoutError` when nothing set the flag, which is
            # what happens on every poll of a run that is still going. Left
            # uncaught it escapes the workflow, and because it is not a
            # `FailureError` Temporal treats it as a WORKFLOW TASK FAILURE and
            # retries forever -- so the loop did advance, but only by failing
            # and replaying, once per poll, for the life of every run.
            #
            # It passed the campaign: replay re-ran `observe_state`, eventually
            # saw a terminal state, and the workflow completed. Green for the
            # wrong reason, with a task timeout in the history of every run.
            try:
                await workflow.wait_condition(lambda: self._halted, timeout=POLL)
            except asyncio.TimeoutError:
                pass


@workflow.defn
class ScheduledAgentRun:
    """One firing of a cron schedule, with Andyur's overlap rule.

    ## Why the retry lives here and not in the schedule

    Andyur's rule is that a tick finding its agent busy is RETRIED SHORTLY --
    never buffered into a backlog, never silently dropped. It exists because a
    tick used to be consumed before the wakeup was attempted, so one long
    conversation swallowed about sixty runs of a per-minute schedule and the
    only evidence was a log line.

    Temporal's schedule overlap policies are SKIP, BUFFER_ONE, BUFFER_ALL,
    CANCEL_OTHER, TERMINATE_OTHER and ALLOW_ALL. **None of them is
    skip-and-retry-soon.** Buffering is the behaviour the rule exists to
    prevent, and skipping is the defect it was written to fix.

    So the schedule is created with SKIP -- executions never stack -- and the
    retry is a durable timer in here. That is strictly better than the native
    engine's version, which re-arms a row and loses the attempt if the process
    dies: this one survives the worker being killed mid-wait.

    The window is bounded so a retry cannot outlive its own slot. If it does
    run long, SKIP means the next firing is dropped rather than queued behind
    it, which is the same answer Andyur gives when an agent is busy.
    """

    @workflow.run
    async def run(self, agent: str, reason: str,
                  retry_seconds: float = 30.0,
                  window_seconds: float = 300.0,
                  schedule_id: str | None = None) -> str | None:
        trigger = ScheduledTrigger(agent=agent, reason=reason, schedule_id=schedule_id)
        deadline = workflow.now().timestamp() + window_seconds

        while True:
            run_id = await workflow.execute_activity(
                admit_scheduled_run, trigger,
                start_to_close_timeout=CALL_TIMEOUT)
            if run_id:
                return run_id
            if workflow.now().timestamp() + retry_seconds >= deadline:
                # The tick is given up ON PURPOSE rather than carried into the
                # next slot: carrying it is the backlog this rule forbids.
                return None
            await workflow.sleep(retry_seconds)


@workflow.defn
class DurableApproval:
    """Wait for a human, for as long as it takes, and then ask Andyur.

    ## What the engine adds, and what it must not

    Approval SEMANTICS are Andyur's and exist on every provider: a request is
    recorded, an approver is authenticated, authority is revalidated, and the
    action is allowed or refused. Making "approval exists" a Temporal-only
    feature would mean the security story could only be tested where the engine
    is, which is the opposite of what a security story needs.

    What the engine adds is DURABILITY: a wait that survives the worker dying,
    the process restarting, and days passing. That is a real difference -- an
    approval that does not survive a restart silently becomes a refusal, and an
    operator who approved something is entitled to expect it happened.

    ## The signal is a doorbell, not evidence

    Anyone who can reach the service can send a signal. So the signal only ends
    the WAIT; what decides is the row, read back through an activity after the
    wake-up. A workflow that returned "approved" because it was signalled
    "approved" would have moved the authorization decision into the engine,
    where it would be replayed from history rather than re-evaluated -- and
    revocation exists precisely because that answer changes.
    """

    def __init__(self) -> None:
        self._woken = False

    @workflow.signal
    def decided(self) -> None:
        """Someone says there is news. Delivered at least once, and setting a
        flag twice is the same as once."""
        self._woken = True

    @workflow.run
    async def run(self, action_id: str, wait_seconds: float = 86400.0) -> str:
        ref = ActionRef(action_id=action_id)

        # A durable wait. Nothing is held open while this sleeps -- no process,
        # no connection, no thread -- which is what makes days reasonable.
        #
        # THE TIMEOUT IS NOT A FAILURE, and `wait_condition` raises rather than
        # returning when it expires. Nobody ringing the bell says nothing about
        # whether a decision was recorded: an operator may have decided without
        # ever touching the engine. So the expiry is caught and the row is read
        # exactly as it would have been.
        try:
            await workflow.wait_condition(lambda: self._woken, timeout=wait_seconds)
        except asyncio.TimeoutError:
            pass

        # ASKED AFTER THE WAKE-UP, EVERY TIME, including when the wait timed
        # out: a decision may have been recorded without anyone signalling, and
        # the row is the truth either way.
        return await workflow.execute_activity(
            read_action_decision, ref, start_to_close_timeout=CALL_TIMEOUT)


# `AndyurRunWithDeadline` used to be here and is deliberately gone. It claimed
# to impose a workflow-side ceiling and did not: it returned the FIRST
# `observe_state` reading and waited for nothing, while carrying a heartbeat
# timeout on an activity that heartbeats once. It was registered and reachable
# by name, so the claim was available to callers. A run's deadline is Andyur's
# reaper, which is authoritative; when a workflow kind genuinely needs its own
# ceiling it can be written then, against a requirement.
# --- Architecture B+: the engine dispatches the run ---------------------------

# The execution Activity, by NAME. Registered only by the execution worker, on
# the execution queue; the control plane's worker never imports the launcher,
# which needs Kubernetes permissions that worker does not hold.
EXECUTE_RUN = "execute_run"

# THE ENGINE'S BOUND, not the run's. A run's lifetime is Andyur's -- its reaper
# measures the granted deadline and condemns the run -- so this only has to
# exceed the longest run Andyur can grant, and a run it outlived would already
# have been condemned.
#
# DERIVED, not written down. It read a fixed 26 hours while the registry
# already permitted grants up to seven days: a longer run would have had its
# execution timed out by the engine mid-run. It is now the platform's lifetime
# CEILING -- which bounds every declared grant and the platform default alike
# (`granted_lifetime_seconds`) -- plus a margin that covers what follows the
# deadline: the reaper's grace, one launch, and the group's deletion.
# `tests/test_bplus_dispatch.py` holds the margin to those numbers.
EXECUTION_MARGIN = timedelta(hours=1)
EXECUTION_START_TO_CLOSE = timedelta(seconds=LIFETIME_CEILING_SECONDS) + EXECUTION_MARGIN

# Worker liveness: how soon a task held by a dead execution worker is retried
# on another. The Activity heartbeats far more often than this.
EXECUTION_HEARTBEAT = timedelta(seconds=60)


@workflow.defn
class AndyurExecution:
    """ONE admitted run, dispatched by the engine (ADR-014 D11).

    Carries the run id and nothing else: the execution worker fetches the run
    from Andyur, which alone decides whether it may execute, and launches or
    adopts it through Andyur's own launcher. The retry policy is the engine's
    half of the contract: a transient failure is retried on whichever worker is
    alive, and the run's fence turns that retry into an adoption, never a second
    runtime; Andyur's refusals are not retried at all.
    """

    def __init__(self) -> None:
        self._halted = False
        self._execution = None

    @workflow.signal
    def halt(self) -> None:
        """Stop durable progress: cancel the execution, whose cancellation
        destroys the runtime through Andyur's containment. Delivered at least
        once; a second cancel of a cancelled execution changes nothing. It is
        NOT the kill switch -- Andyur condemns the run from its own record
        whether or not this signal ever arrives."""
        self._halted = True
        if self._execution is not None and not self._execution.done():
            self._execution.cancel()

    @workflow.query
    def halted(self) -> bool:
        return self._halted

    @workflow.run
    async def run(self, run_id: str) -> dict:
        from temporalio.common import RetryPolicy
        from temporalio.exceptions import ActivityError, CancelledError
        from temporalio.workflow import ActivityCancellationType

        if self._halted:
            return {"run_id": run_id, "outcome": "halted"}
        self._execution = workflow.start_activity(
            EXECUTE_RUN, run_id,
            start_to_close_timeout=EXECUTION_START_TO_CLOSE,
            heartbeat_timeout=EXECUTION_HEARTBEAT,
            # The workflow waits for the Activity to FINISH cancelling -- that
            # is where the runtime is destroyed -- before it reports halted.
            cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=2), backoff_coefficient=2.0,
                maximum_interval=timedelta(seconds=60),
                non_retryable_error_types=["ExecutionRefused"]))
        try:
            return await self._execution
        except ActivityError as exc:
            if self._halted and isinstance(exc.cause, CancelledError):
                return {"run_id": run_id, "outcome": "halted"}
            raise


ALL_WORKFLOWS = [AndyurRun, ScheduledAgentRun, DurableApproval]

# The execution worker registers only this: it dispatches runs and nothing else.
EXECUTION_WORKFLOWS = [AndyurExecution]

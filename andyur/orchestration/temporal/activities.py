"""The steps that touch Andyur. Everything with a side effect lives here.

Activities run OUTSIDE the workflow sandbox, so they may import the platform and
talk to its database. Workflow code may not, and the reason is not style: a
workflow is re-executed on replay, so anything it reads directly would be read
again later, against different state, while history records the branch taken
against the first reading.

Two rules this file exists to keep.

**Payloads carry identifiers; authority is fetched here.** Every activity below
takes a `run_id` and asks the platform. Nothing receives a token, a scope or a
subject, because anything handed to a workflow is written into a durable history
whose retention Andyur does not control -- and because authority frozen at
creation is authority as it stood then, while revocation exists precisely
because the answer changes.

**No activity here moves a run through its lifecycle.** Two used to be able to.
`start_run` marked a run started, and under this provider that took it out of
the `pending` state the worker daemon claims, so the run was never launched.
`finish_run` could record a run's outcome, and nothing called it -- but an
activity is callable by anything that can schedule work on this task queue,
and at the time the engine authenticated every workload in the trust domain
while authorizing none of them. So it was a way to mark any run finished that
bypassed the run's own SVID-authenticated endpoint. Both transitions belong to
the RUN, which announces them itself; neither activity exists any more.

What remains observes, admits through the facade, or reads a decision.
Temporal delivers at least once, so each is safe to repeat: the reads are
reads, and admission is Andyur's own guarded path.
"""

from __future__ import annotations

from dataclasses import dataclass

from temporalio import activity


@dataclass(frozen=True)
class RunRef:
    """What crosses the boundary: an identifier, and nothing else."""

    run_id: str


# `start_run` USED TO BE HERE, and its absence is deliberate.
#
# It marked the run `running`, which took it out of the `pending` state the
# worker daemon claims -- so a run admitted under this provider was never
# assigned and never launched. The transition is the RUN's to announce, over
# `POST /runs/{id}/start`, authenticated by its own SVID. Nothing here is
# entitled to say a run started on its behalf, and an activity that can is a
# loaded gun whatever calls it today.

@activity.defn
async def observe_state(ref: RunRef) -> str:
    """The run's CURRENT state, read from Andyur.

    Read in an activity rather than in workflow code precisely because it
    changes: workflow code that read it would replay against a later value and
    take a branch history does not record.
    """
    from ... import db

    # Read directly because the platform has no accessor for a run's state --
    # `coordinator` exposes `run_is_live`, which collapses pending and running
    # into one bit and cannot distinguish `done` from `failed`. Kept to a
    # single column so the coupling is one name rather than a schema.
    activity.heartbeat(ref.run_id)
    with db.connect() as conn:
        row = conn.execute(
            "SELECT state FROM runs WHERE id = ?", (ref.run_id,)).fetchone()
    return row["state"] if row else "absent"


@activity.defn
async def note_halt(ref: RunRef) -> None:
    """Log that a halt reached this workflow.

    **This does not contain anything.** Destroying the execution is Andyur's
    condemnation path and runs whether or not this activity ever executes; see
    `orchestration/provider.py`.

    IT WRITES A LOG LINE, NOT A RECORD, and the docstring used to say otherwise
    -- that it existed "so the run's own record says the halt arrived". Nothing
    here touches Andyur's record. The authoritative fact that a workflow was
    halted is the governance row the facade writes BEFORE the engine is told,
    and that is where an auditor should look. This line, and the activity in
    the engine's history, only show that the signal was delivered.
    """
    activity.logger.info("halt signalled for run %s", ref.run_id)


@dataclass(frozen=True)
class ScheduledTrigger:
    """A schedule firing. Identifiers and the operator's own words, nothing else."""

    agent: str
    reason: str
    # The Andyur schedule this tick belongs to. Admission is refused without
    # one that exists, is enabled, is the engine's, and is for this agent.
    schedule_id: str | None = None


@activity.defn
async def admit_scheduled_run(trigger: ScheduledTrigger) -> str | None:
    """Ask Andyur to admit a scheduled run. Returns the run id, or None.

    ADMISSION IS ANDYUR'S, so this asks rather than decides. None is the
    ordinary answer when the agent is busy or paused -- not an error, and not
    something the workflow may override.

    THROUGH THE FACADE, and the first draft went around it. The reasoning was
    that the facade would ask a provider to start a workflow while this already
    is one -- but that is not recursion: the schedule's workflow admits a run,
    and the RUN gets its own, different workflow. Going around cost the
    scheduled path the capability check, the provider binding, and the
    compensation that frees an agent when a start fails. The architecture test
    caught it.

    A refusal that is Andyur's -- busy, paused, a cap -- comes back as None and
    the workflow retries. An orchestration failure propagates, so Temporal
    retries the activity rather than treating an outage as "the agent was
    busy".
    """
    from ...server import coordinator, schedules

    # The tick is checked and admitted by ANDYUR'S schedule service -- the same
    # check for every provider that owns schedules (provider draft R10.3).
    try:
        run_id, _refusal = schedules.admit_engine_tick(
            trigger.schedule_id, trigger.agent)
    except schedules.TickRefused as refused:
        activity.logger.warning("scheduled tick refused: %s", refused)
        return None
    except coordinator.InputRefused:
        # PERMANENT, so it must not become an activity failure. A schedule
        # carries no input and this agent's manifest requires one, so it can
        # NEVER fire -- and an activity that raises is retried by default
        # forever. The native path says the same thing in its own words: "no
        # 30s re-arm -- that would retry a permanent refusal ~2,880 times a
        # day."
        #
        # Returned as None, which the workflow reads as "not admitted". The
        # retry window then expires normally and the tick is given up, instead
        # of an unkillable activity hammering the control plane.
        activity.logger.warning(
            "schedule cannot fire for %s: its manifest requires an input a "
            "schedule cannot supply", trigger.agent)
        return None
    return run_id


@dataclass(frozen=True)
class ActionRef:
    """An action request, by id. Not its authority, and not its decision."""

    action_id: str


@activity.defn
async def read_action_decision(ref: ActionRef) -> str:
    """The AUTHORITATIVE decision, read from Andyur's own row.

    THE SIGNAL IS NOT THE ANSWER. A workflow waiting for approval is woken by a
    signal, and anyone who can reach the service can send one -- so the signal
    is a doorbell, never evidence. What decides is this row, written by
    `actionrequests.approve`, which re-evaluates current policy against the
    verified snapshot and atomically consumes the pending approval. Human
    consent cannot resurrect a finished run, extend an expired grant or
    override the PDP, and none of that protection lives in the engine.

    Returns the decision as Andyur recorded it, or "absent" when there is no
    such action -- never a guess, and never anything derived from who signalled.
    """
    from ...server import actionrequests

    row = actionrequests.get(ref.action_id)
    if row is None:
        return "absent"
    return row.get("decision") or "pending"


ALL_ACTIVITIES = [observe_state, note_halt, admit_scheduled_run,
                  read_action_decision]

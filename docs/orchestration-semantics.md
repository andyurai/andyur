# Orchestration semantics

What Andyur's orchestration guarantees, stated without reference to how the
current engine achieves it.

This document exists because the platform is likely to gain a second way of
running work — a durable-execution engine rather than the built-in coordinator,
worker daemon and server heartbeat loop. Before anything is replaced, the
behaviour has to be written down in terms a replacement could be held to. That
is what this is: not a description of the code, but the list of properties any
implementation has to provide.

Each property below is pinned by an executable test in
`tests/orchestration_contract/`. Where the current behaviour is awkward, it is
recorded as it actually is, with the awkwardness named.

---

## The division of responsibility

Orchestration decides **when work progresses**. It does not decide **whether the
actor is allowed to act**.

| Orchestration decides | Andyur decides |
|---|---|
| when a run is dispatched | whether the run is admitted at all |
| where durable wait state lives | who the run acts for |
| how work is redispatched after a failure | what scope it carries |
| how timers survive a restart | whether authority is still valid |
| how retries are scheduled | whether an action needs approval |

The right-hand column is not negotiable and is not delegated. A run's authority
is re-decided against current state at the moment it is used, never replayed
from a record of what was true when the work was created — because the point of
revocation is that the answer changes.

---

## Admission

**At most one live run per agent.** An agent holding a run that has not reached
a terminal state refuses another. This is the foundation: two live runs for one
agent means two live identities for one agent.

**Refusal is refusal, not a queue.** Work offered to a busy agent is declined.
It is not held behind the running work and released later. Work that should
survive the refusal is durable in its own right — a task or a message — and is
re-offered by the drain, which has its own bounds (below).

**Admission is per agent.** One busy agent does not block another.

**A paused agent is refused,** and pausing releases work that has not yet begun.

**Every terminal state frees the agent** — `done`, `failed` and `cancelled`
alike. An engine that frees the agent only on success strands it on every
failure.

## The life of a run

A run **starts once** and **finishes once**. Both transitions are guarded, and a
repeat is refused rather than applied. This matters more under an engine with
at-least-once delivery than under the current one: a duplicate start would re-arm
a run's clock and re-mint its identity, and a duplicate finish would overwrite a
recorded outcome with a later retry's.

**Failure is decided in one place,** from the presence of an error. Nothing
else forms an opinion about whether the work succeeded. In particular, a
process exiting 0 means the process completed, never that the work succeeded.

**A run may finish without ever starting.** Admitted work that could not be
dispatched still has to be endable.

## Halt, and why cancellation is not containment

Halting a workflow is an operator control and the threat model treats it as
such. It has two halves, and only the first is orchestration:

```
provider cancellation   stop making durable progress      orchestration
runtime termination     destroy the actual execution      containment
```

Every durable-execution engine has cancellation, and it is always cooperative:
it stops scheduling new steps and asks the current one to wind down. That is
useless against the thing halt exists for, because the agent being halted may be
compromised or wedged, and will not cooperate. **Asking a process to stop is a
request. Destroying the container it runs in is the guarantee.**

So:

- Halting **admits no new work** to the workflow, and **refuses to start** work
  already dispatched.
- Halting **releases agents** stranded on work that had not begun, and cancels
  that work.
- Halting **does not by itself mark an executing run terminal.** The execution
  is still out there. It is condemned, the executor destroys it, and the
  platform writes the outcome — never the dying run, which may not survive long
  enough and, if subverted, would be writing a lie.
- **An execution with no live run record is condemned** regardless of why it
  survived. Something unaccountable is running, and nothing will record what it
  does. Retries and replays create exactly this shape, so this case gets *more*
  important under a durable engine, not less.

Halt is reversible, but **unhalt does not resurrect what the halt tore down** —
otherwise reopening a workflow re-releases precisely the work the operator
stopped.

## Dispatch

Two properties, and almost nothing else is contract:

1. **An admitted run is held by at most one executor at a time.**
2. **A run whose executor dies becomes available again** rather than being lost.

With one boundary between them: **a run that has already started is not
reassigned when its executor goes quiet.** The process may well still be alive,
and handing it to a second executor produces two live agents — the exact failure
the recovery exists to prevent, caused by the recovery.

Everything else here — pull versus push, slot accounting, heartbeat intervals,
worker identity — is implementation.

**Which dispatcher holds a run is decided once, at admission**, and recorded
with the run: the native assignment loop, or the engine (ADR-014 D11). The two
never compete for a run: the native loop, the stale-worker requeue and the
CLI's no-daemon fallback all refuse an engine run, and the engine's claim
refuses a native one. Each meets the contract its own way:

| | native loop | engine dispatch |
|---|---|---|
| one executor | a guarded claim of `runs.worker` | the run fence: one generation per run, create-only |
| executor dies before start | requeued to another worker | the engine retries the execution on another worker |
| executor dies after start | not reassigned; the reaper bounds it | **adopted**: the retry presents the run's own generation and takes over the same runtime; a second is never launched |

The engine is told a run id and nothing else; whether the run may execute is
re-decided by Andyur, from its own record, every time the engine asks.

## Timers and schedules

**A due schedule fires exactly once,** however many schedulers are evaluating it.

**A tick refused because the agent was busy is re-armed, not consumed.** This is
written from a real defect: the tick used to be advanced to the next cron slot
before the wakeup was attempted, so one long-running conversation silently
swallowed about sixty runs of a per-minute schedule, and the only evidence was a
log line. Unattended operation is the platform's premise, so *"the agent was
busy"* must never mean *"the schedule stopped"*.

**A deferral does not accumulate a backlog.** Ten refused ticks release one run,
not ten. And a re-arm may only make a schedule more punctual — never later than
plain cron would have been.

**A schedule has one trigger.** Under engine dispatch it is a schedule in the
engine, under Andyur's id, and the native poller never fires it; otherwise the
poller fires it. Either way the firing only asks for a run: admission is
Andyur's, and a refused tick is re-armed as above.

## Deferred work

Delegation and messaging wake their target best-effort, so handing work to a
busy agent is normal. The work is durable, and the drain comes back for it.

**The offer is exactly once per item.** Both failure directions are real: work
never re-driven leaves an agent idle beside its own queue indefinitely, and work
always re-driven wakes a stuck agent every tick forever, burning a slot and a
model budget each time.

**The offer is consumed when a run starts, not when it is admitted.** A run is
the offer of the agent's whole waiting queue, and the queue is rendered into the
prompt at start. The distinction is the failure case: a run admitted and then
lost before it ever started showed the agent nothing, so its work must remain
re-drivable. An implementation that marked work at admission would silently drop
exactly the items belonging to runs its own dispatch failed to deliver — and
would look correct in every test where dispatch worked. Symmetrically, work
arriving *after* a run starts waits for the next one, because that prompt was
already built.

**The drain is a second path to admission, so every control that guards the
first guards it too** — pause, halt, and the caps. A kill switch the drain could
undo would be no kill switch.

## Authority carried across work

This is the part a provider should reproduce none of, because it should be
calling into it rather than reimplementing it.

**Workflow identity is inherited; depth counts the chain.** A child joins its
parent's workflow at depth + 1. A root seals a fresh workflow at depth 0, and
independent roots get distinct workflows.

**An unknown parent is refused, never rooted.** Falling back to a fresh depth-0
root would let any caller reset both the delegation depth and the work-item
budget by naming a parent that does not exist.

**The delegation chain is capped,** and the cap is enforced at admission.

**Subject provenance is read from the parent, never from the caller.** If a hop
could restate how its subject was established, delegation would be a laundering
step, and a subject nobody authenticated would emerge from one hop
indistinguishable from a real login.

**A run naming a different subject than its parent gets no credential.** The
credential and the identity it is for come from two different places, and a
disagreement about whose authority this is fails closed — with no token, the
downstream exchange refuses. A run acting for nobody holds nobody's credential
and claims no provenance.

**The work-item budget is per workflow** and counts live runs alongside open
tasks and unread messages, so reach cannot be widened by choosing a different
channel. Terminal runs stop counting; the budget bounds work in flight.

---

## Known gaps, stated rather than implied

Two, both characterized in the contract tests rather than fixed, and both are
things a durable-execution engine would supply directly.

**There is no direct cancel for a single run.** Andyur has no "cancel this run"
entry point. A run that can never be dispatched is released only by halting its
whole workflow or by pausing its agent — both blunter than the situation calls
for, because both affect more than the one run. Pausing to release one run also
stops the agent accepting any other work until it is unpaused.

**The backstop on undispatchable work is 24 hours.** That is the right order of
magnitude for what it is — a queue nobody is draining — but it is also the only
automatic release for a run that can never be dispatched, and 24 hours is
indistinguishable from forever to an operator watching a gate or a developer
whose agent is stuck.

Together these are the sharpest ergonomic edge in the current orchestration.
Neither is a correctness defect: nothing is lost and nothing escapes its bounds.
Both are recorded here so that the improvement is visible when it lands.

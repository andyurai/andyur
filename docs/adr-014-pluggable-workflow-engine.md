# ADR-014: orchestration behind a provider interface

Status: accepted for the seam only. The interface, the capability model and the
error and state vocabularies are IMPLEMENTED and nothing imports them yet:
`andyur/orchestration/` is definitions, and the coordinator, worker daemon and
server heartbeat loop remain exactly as they were. No behaviour changes with
this ADR, and no second provider exists.

What is decided is the shape of the boundary and, specifically, two things it
must not contain.

## Context

Andyur's coordination is about 2,700 lines: a per-agent admission state machine,
worker registration and assignment, liveness and requeue, cron schedules, a
deferred-work drain, TTL reaping and a queue backstop. It works, it is heavily
tested, and almost all of it is a small durable-execution system written by
hand.

Those semantics are the product. Owning the machinery is not. Durable timers,
at-least-once dispatch, lease expiry and cancellation are solved problems, and
two real defects in this area were of exactly the kind a durable engine
eliminates: a schedule that consumed its tick before attempting the wakeup, so a
busy agent silently lost about sixty runs of a per-minute schedule; and a run
that can never be dispatched holding its agent for the full 24-hour queue
backstop with no way to release just that run.

The risk of adopting an engine is the opposite one. Andyur's entire thesis is
that the agent is the compromised component, and the controls that follow from
that — per-run identity, containment, the credential relay, the kill switch —
must not become things an orchestration engine is trusted to provide.

## Decision

Orchestration goes behind `andyur/orchestration/`, a provider-neutral interface.
The existing engine becomes one provider; a durable-execution engine may become
another. One sentence governs the split:

> **Andyur decides whether the actor may act. The provider decides when work
> progresses.**

A provider schedules, waits, retries and survives restarts. It never decides
whether a run is admitted, who it acts for, what scope it carries, or whether an
action still requires approval.

`docs/orchestration-semantics.md` states the semantics a provider must
reproduce, and `tests/orchestration_contract/` pins them as executable tests
written against observable behaviour rather than mechanism, so the same test
bodies can be run against any provider.

## D1 — There is no `cancel`, because cancellation cannot contain

The obvious interface has one, and the obvious design for a kill switch is
"cancel the workflow, then destroy the container".

That was measured against a real durable engine before this interface was
written, and it does not hold. Cancelling a workflow cancels the workflow's own
execution, so any cleanup it attempts afterwards is cancelled along with it. In
the recorded history the containment step was never scheduled at all — the
events went from the step being asked to cancel, directly to the workflow
reporting itself cancelled, with nothing in between. Shielding the cleanup did
not help. Abrupt termination gave less still: the workflow ended immediately
with no opportunity to run anything.

Worse, a step that does not report liveness never learns it was cancelled and
runs to completion regardless. That is not an edge case for this platform. It is
the case the kill switch exists for: a wedged or subverted runner.

So the interface offers `halt`, it means only *stop making durable progress*,
and its contract says in as many words that it destroys nothing. A caller may
not treat a successful halt as evidence that an agent has stopped.

## D2 — Containment does not pass through the provider at all

Destroying the container the untrusted code runs in stays exactly where it is:
the platform condemns a run from its own record, and the executor destroys it.
The division, stated once:

```
halt          stop durable progress        orchestration
condemnation  destroy the execution        containment
```

Routing containment through the provider would make the kill switch depend on
the availability of the orchestration engine, and a kill switch that stops
working when infrastructure is unhealthy is not a control. **A provider that is
down must not be able to keep a compromised agent alive.**

This is why the interface has no `terminate` and no `destroy`, and why
containment is not a capability a provider can decline to offer. Modelling it as
optional would create a legal configuration in which the kill switch is
advisory. There is no such configuration.

## D3 — Payloads carry identifiers; authority is fetched at the boundary

Anything handed to a provider may be written into durable storage whose
retention Andyur does not control, and which may outlive the run, the
deployment and the credential. So payloads carry `run_id`, `workflow_id`,
`action_request_id` — and the provider's steps fetch what they need through the
platform's own paths.

The stronger reason is not secrets at rest. **Authority frozen into a payload is
authority as it stood when the work was created**, and the entire point of
revocation is that the answer changes. A durable engine re-executes workflow
code on recovery; a decision baked in at creation would be replayed unchanged
hours or days later. So every authority question is asked at the effect
boundary, where the answer is current.

This is enforced rather than documented. A type crossing the boundary that names
an authority-bearing field — a token, a scope, an acting user, a pin — fails at
import. The guard is a floor, not a ceiling: it matches names, and a field
called `detail` could still carry a token. The real defence is that steps fetch
rather than receive, and the architecture tests back both.

The guard is necessary because the runtime will not help. A workflow reading the
wall clock is refused loudly by the engine's determinism sandbox; a workflow
reading live platform state was allowed through silently. The silent one is the
dangerous one — correct in every test, wrong on replay.

## D4 — Capabilities describe durability, never Andyur's semantics

A provider advertises what it guarantees: durable execution, durable timers,
durable signals, long waits, schedules, child workflows, failover. Each workflow
kind declares what it requires, and a provider that cannot offer it **refuses**.
There is no degraded path and none may be added: the tempting version — running
a durable approval on a provider without durable signals, by polling — works in
every test and loses an approval the one time a process restarts mid-wait.

What never appears as a capability is anything of Andyur's own: whether an
action needs approval, whether authority may widen, whether a run may hold a
credential. A flag that is true for every provider is not a capability; it is a
reminder that the decision was made somewhere else. Approval *semantics* exist
regardless of provider. Only *durable* approval requires durability, which is
why it is a workflow requirement assembled from durability guarantees.

The practical consequence is that the ten-minute path must never require a
durable engine. Simple runs, schedules and deferred work are satisfiable by a
single-node provider, and that is a constraint on the design rather than an
accident of it.

## D5 — Idempotency is the interface's problem, and the platform's constraint

Starting a workflow is idempotent on its id, and halting is idempotent on the
same. A durable engine delivers at least once and the platform itself retries,
so this is not politeness.

The measurement that fixed this: a step whose effect landed before its
acknowledgement was lost ran three times under a three-attempt retry policy. For
a launch that is three containers for one admitted run — the one-live-run-per-
agent invariant broken by the orchestration layer rather than by the platform.

Recovery and retry are not the same thing, and the boundary is sharp. A step
that COMPLETED is never re-executed: a worker killed mid-run replays from
history without repeating its finished work. A step that FAILED is re-executed,
and an ambiguous failure duplicates whatever effect already landed. So every
irreversible step must be idempotent by construction or non-retryable, and the
constraint that already refuses a second live run per agent is what the launch
step consults rather than assumes.

## D6 — The provider's state is a belief, not the record

Providers report a normalized state, deliberately distinct from a run's state. A
run's state is governance: what the platform recorded and what an audit reads.
The provider's is only what the engine believes about execution progress, and
they can legitimately disagree — a halted run whose container is gone is
terminal here while the engine may still be winding down.

**When they disagree, the platform's record wins.** The provider is
authoritative for what is still executing, never for what happened. A provider
that has forgotten a workflow says so rather than inventing a terminal state.

## D7 — The execution port already existed, and is stronger than a new one (amendment, 2026-09-20)

There are two boundaries in this design and they are one word apart, so this
names them once:

```
orchestration   WHEN work progresses      WorkflowProvider, andyur/orchestration/
orchestrator    WHERE a run lands         Orchestrator,     andyur/daemon/
```

The second was there first. `daemon/orchestrator.py` has carried an `Orchestrator`
interface — launch, kill, list_running, sweep, cleanup, read_exec_completion,
describe — with four implementations (host, container, pod, Kubernetes) and a
one-place `select()` factory, and its own docstring states the intent: the
daemon's loop is orchestrator-agnostic, so a new runtime is a new class rather
than another if-statement threaded through launch, kill and reap.

**So no second port was added.** Wrapping it would have produced two
abstractions over one boundary, and the outer one would have been the weaker.
The shape that was considered keyed termination on a handle and offered neither
`list_running` nor `sweep`, and both of those are the difference between a kill
switch that survives a restart and one that does not:

- A restarted daemon holds **no handles**. `kill(run_ids)` works from the ids
  the server condemned, so it can destroy what it never launched — including an
  execution with no live run record, which is unaccountable by definition.
- `list_running()` reads the **runtime**, not this process's memory, which is
  how a daemon sees what it inherited.
- `sweep()` reconciles what `list_running` cannot name.

`tests/test_execution_port.py` pins that shape, per implementation, because the
two reconciliation methods have working defaults on the base class — so a shape
that forgets one reports nothing running and reconciles nothing, silently.

### The gap that table found, and its fix

**On Kubernetes, an orphaned agent Pod was not reconciled.** A run there is two
Pods, `component: proxy` and `component: agent`, and `list_running` selects
proxy Pods only. An agent Pod whose proxy was gone was therefore invisible to
adoption: nothing reported it as executing, so nothing condemned it, and the
deletion path that would remove the whole group correctly was never reached.

`sweep` is the mechanism for exactly this case, and the Kubernetes shape
inherited the base no-op while the Docker pod shape — same two-part structure —
implemented it. Nothing else bounded the orphan: the agent Pod has
`restartPolicy: Never`, no `activeDeadlineSeconds`, and no ownerReference to the
proxy, so Kubernetes would not collect it either.

`KubernetesOrchestrator.sweep` now closes it. It lists live agent Pods, matches
them against live proxy Pods by `(run, generation)`, and destroys any generation
whose agent has outlived its proxy.

Three properties make that safe to run on every heartbeat:

- **It cannot race a launch.** The agent Pod is created only after the proxy is
  ready — *"the agent is never created unless its only allowed destination is
  ready"* — so an agent with no live proxy means the proxy died, never that the
  run is half-built.
- **Identity is verified, never guessed.** Raw identity lives in annotations and
  is checked against the label digests, and the Pod name must be the canonical
  one for that identity. A Pod that fails either check is skipped and logged
  rather than deleted: acting on an identity that could not be confirmed would
  let a rewritten label aim the sweep at another run's generation.
- **A worker reconciles only its own generation**, for the same reason it may
  adopt only its own — in a shared namespace, sweeping another worker's
  workload is destroying a run nobody asked about.

A proxy in a terminal phase counts as gone, because the agent is single-homed on
it and can reach nothing else. An agent that has itself exited is left alone:
nothing is executing, and deleting it would race the reap path that reads its
exit code and logs.

`tests/test_execution_port.py` now asserts that **both** two-part shapes
reconcile, and that the single-unit shapes do not, so a third shape cannot be
added without answering the same question.

## D8 — Evidence is re-recorded when a change stales it (amendment, 2026-09-21)

Live evidence is never allowed to report STALE while work lands. When a change
stales an artifact, the gate that produced it is re-run: at Stage 5, when
routing through the facade staled the broker semantic-wire result, and at
Stage 6, when the governance columns staled the consequential-action one.
`test_no_shipped_evidence_is_stale` and its sibling enforce it, and they are
what makes the evidence claim worth anything.

The cost is a cluster campaign whenever a change touches what a gate hashes,
and it is paid in the order that keeps it to one campaign: batch the edits, run
the whole suite to surface every structural failure, then run the gates once.
Stages 15 and 16 re-ran the affected gates three times between them, twice
because a manifest edit landed in the middle of a campaign rather than before
it.

## D9 — Which mechanics stay, and why each is not a duplicate (amendment, 2026-09-21)

> **Amended by D11 (Architecture B+).** D9 describes Architecture A, in which
> the engine supervises and the native loop dispatches, and it stays true of
> the `local` provider and of a Temporal deployment with
> `ANDYUR_TEMPORAL_DISPATCH=native`. For engine-dispatched runs, D11 replaces
> native assignment with engine dispatch and moves their schedules into the
> engine; the text below is kept as the record of the decision it was.

Every removal must name its replacement (§90.12). These mechanics stay, each
for a stated reason:

- **Worker assignment, slot dispatch and stale redispatch** decide WHERE a run
  lands and what happens when the thing running it dies. That is the execution
  port (D7), a seam the engine does not touch. Stage 16 showed it from the
  other side: a workflow that took a run out of `pending` — the state the daemon
  claims — meant the run was never launched. The engine depends on these
  mechanics.

- **Schedule polling and retry timing** are how schedules fire, on both
  providers: `server/schedules.py` writes a row and `heartbeat` fires it
  through `fire_due`, which admits the run through the facade like any other.
  There is one firing path, so there is no double fire.

- **Queue timeout polling** is the deferred-work drain, which admits waiting
  work through the same facade.

`ScheduledAgentRun` and `DurableApproval` are registered with the worker and
exercised by the provider's own tests; a test pins which callers reach the
engine's schedule API, so a change there is a decision recorded here.

## D10 — What the adversarial review changed (amendment, 2026-09-21)

A seven-persona review ran over the lane after it was declared complete, with
each finding put to a refuter before it counted, and a second round ran over
the first round's fixes. The outcomes that are decisions rather than fixes
are recorded here.

**One execution per run.** Executions were keyed by the workflow id, so a
delegated run started inside a live workflow reused the parent's execution
(`USE_EXISTING`) and was never observed on its own. Each run now gets
`andyur-run-{run_id}` and the provider returns that id on the handle. Halt
and describe carry the workflow's live runs from Andyur's record, as
`run_ids`, because the engine has no execution named after the workflow: a
halt signals every live run at once under one deadline, and describe reads
the newest. A run the engine never saw is skipped; a missing NAMESPACE, which
the service reports with the same NOT_FOUND, is a refusal; and a signal that
fails is `HaltNotAcknowledged` rather than silence. Executions started under
the earlier naming are not addressed by it; each exits when its run reaches a
terminal state, which it observes on its next poll.

**The engine performs no run lifecycle transition.** `still_live` and
`finish_run` were registered activities, and `finish_run` was not called by any
workflow. An activity can be scheduled by anything that can reach the task
queue, so a registered activity that records an outcome is a way to record
ANY run's outcome without the run's own SVID-authenticated endpoint. Both are
gone, and `tests/redteam/test_iteration_02.py` asserts over every registered
activity rather than by name.

**Callers are authorized by SPIFFE ID, not by the trust bundle.** Requiring a
client certificate authenticated every workload in the trust domain and
authorized none; the NetworkPolicy was the only barrier. Temporal OSS has no
authorizer that reads a certificate's URI SAN, so the engine's only pod-network
listener is an Envoy sidecar that admits an exact allowlist — the control plane
and the registration Job — and every Temporal service binds loopback so none
is reachable around it. The allowlist is derived in a test from the identities
the cluster issues, and the shipped config is run in front of a real Temporal
in CI with one certificate per identity. The proxy connects upstream only
after a client has sent data, which is after the RBAC decision; handshakes are
bounded at ten seconds; TLS 1.3 only; and the listener waits for SPIRE's
certificate rather than opening without one.

Loopback has a price, accepted: `kubectl port-forward` to the engine Pod
reaches Temporal without TLS, as `kubectl exec` into it always could. Both
are cluster-administrator verbs in `andyur-system`, and the runbook says so.

**Retention is seven days, on a 50Gi volume.** Closed-execution storage grows
with run-seconds, because a live run hands off about 72 times a day. At thirty
days on 10Gi the database filled at about seven concurrently live runs; seven
days on 50Gi fills the disk near 150, so the working ceiling, with room for
WAL and the rest, is about 120. The arithmetic sits beside the volume in
`temporal.yaml`.

**One breaker for an unreachable engine.** The drain and the schedule phase
both admit a run and abandon it as failed when the engine cannot start it; the
drain backed off and the schedules did not. One breaker now covers both: the
first unreachable start trips it, nothing is claimed while it is open, and
only an admitted run closes it.

**A rotated certificate is swapped into the running worker.** The worker
reconnected on every SVID rotation by rebuilding itself, which dropped the
workflow cache about every seven minutes and replayed every live run. The new
client is handed to the running worker instead, and a worker that stops for
any reason is rebuilt rather than left dead in a Running container.

## D11 — Architecture B+: the engine dispatches admitted runs; Andyur executes and contains them (amendment, 2026-09-21)

**Temporal decides when an already-admitted run progresses. Andyur decides
whether it may execute, and owns the execution boundary.** In the production
deployment (`ANDYUR_TEMPORAL_DISPATCH=engine`), an admitted run is dispatched
by the engine to an Andyur execution worker, instead of by the native
assignment loop. The package default, the ten-minute path and the `local`
provider are unchanged: the native loop, slots, heartbeat assignment and the
schedule poller remain theirs.

### What moved, and where it lives

- **Who dispatches is recorded at admission**, in the `INSERT` that creates the
  run (`runs.dispatch`), from the bound provider. The native loop never selects
  an engine run and the dead-worker requeue excludes them, so one run cannot
  be dispatched twice.
- **The engine carries the run id and nothing else.** `AndyurExecution` runs
  one `execute_run(run_id)` Activity on the execution queue. The execution
  worker claims the run from Andyur (`POST /runs/{id}/execute`, only the
  `temporal-execution-worker` role): unknown, native, terminal, halted and
  unsealed runs are refused by name and never retried; the registry seal is
  re-checked before every launch; a pending run is credentialed through the
  same helper the native heartbeat uses; a started run is adopted and never
  re-credentialed.
- **The execution generation belongs to the run** (Gate A below). The first
  claim records it; every retry presents it; the Kubernetes run fence admits
  exactly that generation to adopt and refuses any other.
- **The launcher is the daemon's**, in an execution mode: the same governed
  Kubernetes launch, reaper, exec/v1 completion and kill path, with run-scoped
  generations. It is Kubernetes-only, because only there does the fence turn a
  retried launch into an adoption.
- **Schedules** created in such a deployment are Temporal Schedules under
  Andyur's own id, and the tick carries that id: `ScheduledAgentRun` admits
  through the facade only for an enabled engine schedule of that agent, with
  the reason read from Andyur's row, and the admitted run is dispatched like
  any other. The native poller skips them. A schedule created before engine
  dispatch was selected stays native. Deleting an engine schedule needs a
  provider that reaches the engine; the Local provider refuses it by name
  rather than dropping a row whose schedule would keep firing.
- **The execution worker** is its own workload and identity
  (`spiffe://.../temporal-execution-worker`), with no run-token signing key.
  In Kubernetes it has its own Role, narrower than the daemon's: what the
  shared launcher calls, and no `watch`, Lease listing or Lease collection
  delete. At the engine it is admitted by exact SPIFFE ID and then limited, per
  request, to a worker's calls -- polls, responses, heartbeats -- so it cannot
  start, signal, cancel or terminate a workflow or touch a schedule.
- **Production says so.** Under the production profile, a process configured
  for Temporal refuses to start unless `ANDYUR_TEMPORAL_DISPATCH=engine`; the
  server and the control plane's workflow worker apply the same rule, so a
  scheduled run and a triggered run cannot be dispatched differently.
  Capacity is its Activity concurrency (`ANDYUR_EXECUTION_CONCURRENCY`) times
  its replicas; Andyur's policy limits stay at admission.

### Retry classification for `execute_run`

| failure | treatment |
|---|---|
| claim, network, 5xx | transient: the engine retries, on whichever worker is alive |
| Andyur refused the claim | permanent: `ExecutionRefused`, never retried |
| the launch itself failed | the run's outcome: recorded as failed by name, as the daemon records it |
| launched, then the worker was lost | ambiguous: the retry ADOPTS through the fence |

### Containment does not depend on the engine

A halt writes Andyur's governance record first. Then two independent paths
converge on Andyur's own kill: the engine cancels the execution, and the
executing worker polls the server's condemnation.

A cancellation is not itself a halt. The SDK also cancels an Activity when its
worker shuts down, when its heartbeat times out and when the attempt has been
superseded, so on any cancellation the executor asks Andyur and destroys the
runtime only if Andyur condemns the run. With Andyur unreachable it acts on
the reason: a requested cancellation (the halt path's own) contains, anything
else detaches and leaves the runtime to the attempt that replaces it. That one
fail-closed case is an availability tradeoff, stated in the threat model: it
can end an execution early during a control-plane outage, and it can never
widen authority or create work.

**The engine's execution bound is derived, not chosen.** `execute_run`'s
start-to-close bound is the platform's lifetime ceiling
(`LIFETIME_CEILING_SECONDS`, seven days) plus a one-hour margin for what
follows a deadline -- the reaper's grace, a launch, the condemnation poll and
the group's delete. Every source of a run's wall clock is held to that same
ceiling: a declared grant is refused above it, and the platform default and
the conversation maximum are clamped below it. A test holds the margin to
those numbers, so raising the ceiling raises the engine's bound with it. Each is proved alone. If both are gone -- the engine down and the
execution worker dead -- the worker daemon, which reconciles from the runtime,
reports engine-launched runs for condemnation and destroys the exact
generation the server condemns.

One number had to change to make the engine path hold: an Activity learns of
its cancellation only when a heartbeat is actually sent, and the SDK throttles
sends to 80% of the heartbeat timeout -- 48 s. The execution worker caps the
throttle at 5 s.

The reconciler's view of engine runs spans every execution worker in the
namespace, so it is verified Pod by Pod: a Pod it cannot verify is named and
skipped, never destroyed, and never hides the others. Its bound is its own
(1,024 run proxies), not one daemon's adoption bound.

### Launch, adoption and outcome under retries

- A launch heartbeats while it blocks (every 10 s), so a slow launch -- up to
  a minute for the proxy and another for input delivery -- is not taken for a
  lost attempt and handed to another worker while it is still creating the
  run.
- An adopted run whose agent Pod does not exist yet has not exited: the fence
  is taken first and the agent created last, so absence counts as an exit
  only once a whole launch could have completed since adoption.
- A runner that exits without reporting has its outcome recorded BEFORE its
  runtime is cleaned up and its fence released; unconfirmed, the runtime stays
  and the report is retried. A retry therefore never finds a pending record
  with no fence and launches the run again.
- A run is claimable only through the orchestration provider it was admitted
  under: the provider is written into the admission INSERT with the dispatch
  mode, and the claim refuses any other (`not_bound`). An engine run admitted
  before the binding existed is Temporal's.
- An admitted engine run whose start the provider never acknowledged -- the
  server died between the admission commit and the start -- is offered again
  by the server's heartbeat once it is older than a grace period, until the
  provider acknowledges it or it ends. Starting is idempotent on the run, so
  offering again is always safe. Before this, such a run held its agent until
  the 24 h queue backstop.
- A failed launch records its failure BEFORE the run's fence is released. The
  rollback still deletes everything the launch created; the fence is released
  only once Andyur has acknowledged the failure, so an unacknowledged failure
  is adopted by the retry, not launched again.
- The controller's bootstrap -- containment checks, the execution-mode daemon,
  the executor's identity-bound client -- is provider-neutral
  (`engine_executor.hosted`); an orchestration adapter only names itself. The
  schedule-tick check likewise lives in Andyur's schedule service
  (`admit_engine_tick`), once for every provider that owns schedules.
- One dispatcher per run, enforced by the server: a daemon may not heartbeat
  under the engine's claim marker, the engine's finishes match engine runs
  only and a worker's finishes native runs only, and the CLI's no-daemon
  fallback is refused a run token for an engine run. Under the production
  profile the claim re-checks the registry seal whatever the worker reports.

### The gates

- **Gate A -- a retried launch adopts, never duplicates.**
  `infra/bplus-spike/gate_a.py`, against a real Temporal service, worker
  processes killed outright, and the production run fence on the live API:
  crash after launch adopts (one fence, one runtime); crash before launch
  launches once; a foreign generation, an invented run and a halted run are
  refused without a retry. Without the fence a crash leaves two runtimes; with
  a per-worker generation the retry is refused instead of adopted -- which is
  why the generation belongs to the run.
- **Gate B -- dispatch independence.** Against a real engine, with
  `assign_runs` raising if called, an admitted run is dispatched, launched
  under its own generation, and completes; in the cluster, the Goose governed
  workload runs end to end under engine dispatch and passes its full gate,
  trace included.
- **Gate C -- containment independence.**
  `infra/kubernetes/verify-bplus-containment.sh`: a real OpenSRE run was
  executing when the engine and the execution worker were scaled to zero; the
  halt destroyed its runtime six seconds later, by the worker daemon's
  reconciler, and the run ended failed.
- **Crash after launch, in the cluster.**
  `infra/kubernetes/verify-bplus-adoption.sh` deletes the execution worker's
  Pod with no grace period after it launched a real OpenSRE run; the engine
  retries on the replacement, which adopts under the original generation; the
  run's Pods never exceed one group and never change; the run completes.

### Gate D -- which mechanics each path uses

| mechanism | local provider | engine dispatch | shared |
|---|---|---|---|
| `assign_runs()` | keeps | bypassed (engine runs never selected) | no |
| worker slots / `slots_free` | keeps | replaced by Activity concurrency | no |
| heartbeat assignment | keeps | not used for dispatch | liveness and condemnation |
| stale-assignment requeue | keeps | replaced by the engine's retry and fence adoption | no |
| schedule poller | keeps | bypassed (engine schedules) | no |
| DB-observing `AndyurRun` and its continue-as-new | not used | not used for engine runs | Architecture A only |
| one-live-run-per-agent | keeps | keeps | yes |
| Kubernetes launcher, run fence, `kill`, `sweep`, `list_running` | keeps | keeps | yes |
| reaper and granted run lifetime | keeps | keeps | yes |
| audit, run record, completion authority | keeps | keeps | yes |

Production is simpler to reason about than Architecture A in the way that
matters: an engine run has exactly one dispatcher, one retry mechanism and one
generation, and the native loop's machinery is not on its path at all.

## What this gives up, stated so nobody discovers it later

An interface designed against one implementation tends to fit only that one. The
mitigation was to measure a real durable engine before fixing the shape, which
is where D1, D3 and D5 came from — but a second provider will still find
edges this ADR did not anticipate, and the interface will move when it does.

Two providers also means two behaviours. A contributor on the single-node
provider cannot exercise a durable approval at all, and the capability check
refuses it rather than approximating it. That is the honest outcome and it is
still a gap in what a local developer can test.

The durable provider is Temporal, one version of it, and it is the production
default: the conformance suite and the failure campaign run against a real
server, and the in-cluster gates run with it selected. The claims in D1, D3 and
D5 were shaped against that engine.

## Acceptance

- `andyur/orchestration/` imports no engine SDK, and a provider's SDK may be
  imported only inside that provider's own directory.
- No public type names an engine's vocabulary.
- A boundary type naming authority fails at import, with a planted value
  confirming the refusal still bites.
- Every workflow kind declares its requirements; an unknown kind is refused
  rather than defaulted.
- A provider with no engine behind it satisfies the interface.
- The semantics in `docs/orchestration-semantics.md` pass unchanged against the
  existing engine.

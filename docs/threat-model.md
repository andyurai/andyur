# Threat model

Andyur's premise is that **the agent is the compromised component**. An agent
runs code it was talked into running, so the controls here are mostly structural
— what is reachable — rather than advisory, which is what a prompt asks for.

This document says what is defended, what is assumed, and what is not yet
enforced. The last section is the one worth reading twice.

## The adversary

**Primary: a compromised agent run.** An attacker controls the agent's prompt
and therefore, in effect, its tool calls and its shell. They can read anything
the run can read and reach anything the run can reach. Prompt injection is
assumed to succeed; nothing here depends on it failing.

**Secondary: a malicious or buggy upstream workload.** Under `exec/v1` Andyur
executes unmodified third-party agent processes. Such a process is untrusted
code with a network and a config file.

**Also considered: a confused-deputy caller on a shared host**, and **a tenant
reaching across runs** — another run's mind, memory, tasks or credentials.

**Not defended against:** an attacker with the operator's credentials, root on
the host, or control of the cluster's admission path. A compromised control
plane is game over by construction; the design narrows what a compromised *run*
can do.

## What the boundaries are

| Boundary | Enforced by | Defeats |
|---|---|---|
| Run container | no host mounts, `--cap-drop ALL`, `no-new-privileges`, per-role seccomp, its own uid, a uid-drop wrapper that cannot branch back to root | the agent's shell reaching the host or the runner's memory |
| Network | internal-only per-run network; an `await-containment` init container that does not exit until the Kubernetes API **and** DNS are both refused | exfiltration, and a startup window in which a pod could still reach the internet |
| Identity | SPIFFE/SPIRE attestation; the control plane requires a JWT-SVID on every call and never trusts a self-declared name | a stolen token replayed from another container |
| Credentials | relay, not sharing: the provider key stops at the broker, the broker credential at the runner, tool credentials at the per-run sidecar | any model or tool credential entering the agent's environment |
| Authority | one server-side decision intersecting user entitlement, resource pin, agent ceiling and target audience, from a signature-verified registry snapshot | a run widening its own grant, or an agent rewriting its tool grants for later runs |
| Tool surface | `tools/list` and `tools/call` share one decision | an agent calling a tool it was not shown |
| Stop | workflow halt plus container destruction | a run that will not stop between tool calls |
| Workflow engine | callers admitted by exact SPIFFE ID; every engine service on loopback behind that authorizer; the engine carries run ids only, and every execution is re-decided by Andyur from its own record | an agent, or any other trust-domain workload, administering the engine; the engine inventing, resurrecting or widening a run |
| Stop, engine gone | Andyur's governance record, then Andyur's own kill from any of three paths -- the engine's cancellation, the executor's condemnation poll, the worker daemon's runtime reconciler | a halt that waits on, or is lost with, the engine or its execution worker |

The profile is what makes these binding rather than optional:
`ANDYUR_PROFILE=prod` refuses to start without sandbox, identity, egress
lockdown and the broker, and names each missing control.

## What it assumes

Stated because a control that rests on an unexamined assumption is not a control.

1. **The cluster's admission and CNI behave.** Containment assumes the CNI
   actually enforces NetworkPolicy and that admission prevents `hostNetwork`,
   privileged pods, unapproved images and label spoofing. Andyur verifies
   containment at runtime with a live probe and withdraws its own stamp on
   failure, but it cannot substitute for a certified cluster.
2. **SPIRE's node attestation is sound.** Every identity claim descends from it.
3. **The control plane is trusted.** It holds the authority decision.
4. **The operator's machine is trusted.** The CLI and console act as the
   operator.
5. **Registry snapshots are signed by a key the platform trusts**, and a
   launcher handed an incomplete snapshot refuses rather than falling back.
6. **The workflow engine is a scheduler, not an authority.** If it is
   compromised it can ask for any run id to be executed, retried or cancelled;
   it cannot make a run executable. Andyur refuses an id it never admitted for
   the engine, a halted or ended run, and a run whose registry seal no longer
   matches, and a retry can only adopt the runtime of the run's own recorded
   generation; under the production profile the seal is re-checked whatever
   the worker reports. The engine's cancellation destroys nothing Andyur has
   not condemned, with ONE deliberate exception, an availability tradeoff:
   while the control plane is unreachable, an explicitly requested cancellation
   of an execution (the halt path's own) contains that run's runtime, because
   Andyur cannot be asked and a halt must not wait on it. So during a
   control-plane outage an engine-side cancellation can end an execution early.
   It cannot widen any authority, mint a credential or create work: containment
   only destroys the one runtime the execution was already running, and the
   run's outcome is still Andyur's to record. The execution worker it talks to holds its own run-lifecycle
   Kubernetes Role and no signing key, never hands its identity to a run, and
   is limited at the engine to a worker's calls. That limit is by method, not
   by task queue: a worker identity can poll the control plane's queue. What
   runs there only reads Andyur's record, logs, or admits a scheduled run --
   and admission requires an enabled engine schedule Andyur holds for that
   agent, with the reason taken from Andyur's row.

## Residual risks, not yet closed

These are architectural, known, and tracked in [`../ROADMAP.md`](../ROADMAP.md).

**Delegated tokens are bearer tokens.** A run presents its X509-SVID on an
https reach, but no Andyur tool policy-enforcement point yet validates the peer
certificate against the token. Sender-binding is a two-party property; until the
resource checks it, a delegated token is bounded by audience and TTL and nothing
else. RFC 8705 or RFC 9449 validation at the resource is the exit criterion.

**A run row can hold a reusable upstream bearer.** The acting user's login token
is stored when an external authorization server is configured, and is returned by
exactly one endpoint that requires the run's own attested per-run SVID. It is not
narrowed to a run-bound intermediate at trigger time. Narrowing it is tracked.

**The credential audit is environment-only.** The runner asserts that the agent's
environment holds no forbidden credential. It does not check whether the selected
backend implies a credential *file* the agent could read — which it can under
`subscription` mode off-sandbox. Treat the off-sandbox dev path as unconfined.

**Off-sandbox, the model proxy is host loopback.** It attaches the broker
credential to whatever arrives, because its access control *is* the container
boundary. Off-sandbox that boundary is absent and any local process can spend the
platform's key. This is why the production profile refuses to start without a
sandbox rather than treating it as hardening. Adding a credential here would only
move the problem: whatever the agent must present, the agent can read.

**A per-run sidecar bound to `0.0.0.0` is reachable by sibling sidecars.** In pod
mode the sidecar is exposed on the sandbox network to the framework and to other
runs' sidecars — not to any agent. A compromised sibling sidecar could relay
inference on this run's broker token, bounded by that token's scope and TTL.

**Per-run SVID is not the default runtime path.** Proved under the harnesses and
in the Kubernetes path; the single-host default attests per role.

**Release signatures anchor to nothing.** `trust_anchor` is `NONE`. Signatures
prove integrity within a build and establish no external trust.

**Worker identity is self-asserted** for run assignment, and a worker restart can
orphan an in-flight `exec/v1` completion.

## How these claims stay honest

Each live control is exercised by a gate that attacks it, and each gate writes an
evidence artifact binding its result to digests of the source it ran against.
When that source changes the artifact goes stale and
`infra/rc/evidence_currency.py` reports it, so a security claim cannot outlive
the code it was made about. Refusal tests carry positive controls, because a
refusal proves nothing when a broken component refuses everything.

If you find something this document does not account for, see
[`../SECURITY.md`](../SECURITY.md).

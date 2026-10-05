# Roadmap

What is built, what is not, and what is deliberately not planned. Andyur's house
style is to state limits rather than imply them, so this document is written to
be useful to someone deciding whether to depend on the platform — not to flatter
it.

Version 0.x. Breaking changes are allowed and changelogged.

## What is built and verified

Each of these is exercised by the test suite, and the ones marked *live* are
additionally proved against real infrastructure by a gate that records a signed
evidence artifact bound to the source it ran.

- **Control plane** — agent registry, coordination, run records, self-healing,
  SQLite or Postgres with a pooled connection layer and load-balanced replicas
- **Agent runtime** — five-phase runner, sectioned prompt, versioned agent
  "mind" in object storage with history and rollback
- **Multi-agent collaboration** — cron schedules, task delegation, messaging
  and chat, all anchored to one distributed trace
- **Workload identity** *(live)* — SPIFFE/SPIRE JWT-SVID and mTLS, per-agent and
  per-run identities, container attestation
- **Containment** *(live)* — per-run container with no host mounts, capabilities
  dropped, its own uid, per-role seccomp profile, internal-only network, and an
  `await-containment` init container that does not exit until the Kubernetes API
  and DNS are both refused
- **Credential confinement** *(live)* — the provider key stops at the broker,
  the broker credential stops at the runner, tool credentials stop at the per-run
  sidecar; the agent's environment holds none of them
- **Per-run authority** — what a run may do is the intersection of the acting
  user's entitlement, the resource pin, the agent's ceiling and the target
  audience, computed server-side from a signed registry snapshot
- **Per-tool MCP authority** — `tools/list` and `tools/call` are backed by one
  decision, so the menu an agent sees is never wider than the calls it may make
- **`exec/v1`** *(live)* — an unmodified upstream agent runs under all of the
  above with no Andyur awareness, from a manifest and rendered configuration.
  Three unrelated upstream agents have run on it in a cluster (OpenSRE, Goose,
  Hermes Agent); the second and third cost no platform code, and two of them
  have asked for a consequential action the platform then decided and performed.
- **Observability** — one OpenTelemetry trace per flow across processes, and a
  standing rule that no feature is done until an operator can answer from the
  platform's own signals ([`docs/observability-exit-criteria.md`](docs/observability-exit-criteria.md))

## Known limits

These are real, current, and the reason to read this section before adopting.

| Limit | What it means today |
|---|---|
| **Per-run SVID is not the default runtime path** | Proved in harnesses and in the Kubernetes path; the single-host default still attests per-role rather than per-run. |
| **No metrics, alerting or budget enforcement** | The broker meters spend but nothing acts on it. There is no cost ceiling that stops a run. |
| **Redaction is pattern-based** | `redact.py` matches known credential shapes. It will not catch a secret that does not look like one. |
| **Conversational runs skip memory capture** | A chat-shaped run does not produce the entity/fact capture a scheduled run does. |
| **Runner logs are local files, unrotated** | Fine for one host, wrong for a fleet. |
| **No continuous agent-behaviour evaluation** | CI runs the suite and the attack harnesses; it does not evaluate whether agents behave well over time. |
| **Image provenance is not signed end to end** | The registry snapshot is signed; runner image provenance is not yet attested. |
| **`exec/v1` admits two model protocols** | Families of upstream agents speaking neither cannot run on it unmodified. |
| **The coordination ledger can lose writes under contention** | Observed, not yet fixed. Affects multi-writer coordination, not run correctness. |
| **Worker ownership is self-asserted** | A worker claims its own identity for run assignment rather than proving it. |
| **A worker restart can orphan an in-flight `exec/v1` completion** | The run is reaped rather than completed. |
| **Release artifacts are signed with an ephemeral key** | `trust_anchor` is `NONE`: signatures prove integrity within one build, and anchor to nothing outside it. |

## Next

Roughly in order. Nothing here has a date.

1. **Per-run SVID as the default runtime path**, so the authority model's
   assumptions hold in the default configuration and not only under the
   harnesses that prove them.
2. **A real trust anchor for releases**, replacing the ephemeral signing key.
   This is a prerequisite for any externally consumable release artifact.
3. **Sender-constrained tokens at the resource** — RFC 8705 certificate binding
   or RFC 9449 DPoP validated by the resource server, with replay-negative
   proof. Today a delegated token is a bearer token bounded by audience and TTL.
4. **A composed data plane.** Envoy or equivalent owning TLS, certificate
   rotation, HTTP correctness, pooling and streaming, leaving Andyur to expose
   narrow authorization and credential-exchange services.
5. **Narrowed run-bound credentials** so a run row never holds a reusable
   upstream bearer.
6. **Metrics, alerting and budget enforcement** on the broker that already
   meters.
7. **Multi-tenancy**, then per-request browser SSO for the console.
8. **Certified admission and CNI policy** as an explicit dependency, since the
   containment story currently rests on properties of the cluster it runs on.

## Not planned

Saying this plainly is more useful than leaving it implied.

- **Andyur is not an agent framework.** Bring your agent logic as instructions
  and MCP tools, or as an unmodified process over `exec/v1`. We do not intend to
  compete with LangGraph, CrewAI, AutoGen or PydanticAI.
- **Not a memory product.** The associative memory graph composes ideas from
  that space; it is not the point of the platform.
- **Not an enterprise governance suite.** The platform enforces authority for
  the runs it executes. It is not a policy console for an organisation.
- **No bespoke cryptography or protocols** where a standard exists. The
  direction of travel is consistently toward composing SPIFFE/SPIRE, MCP,
  OAuth token exchange, Transaction Tokens, AuthZEN and OpenTelemetry rather
  than reimplementing them.

## How to read a claim in this repository

Every property described as verified is backed by a gate that writes an evidence
artifact binding the claim to digests of the source it exercised. When that
source changes, the artifact goes **stale** and
`infra/rc/evidence_currency.py` says so, which means a claim cannot quietly
outlive the code it was made about. If you want to know whether something is
true today rather than true once, that is the tool to run.

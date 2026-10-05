# Documentation

Start with the [top-level README](../README.md) for what Andyur is and how to run
it. This directory holds the documents behind it.

Everything here describes what the platform **is**. Internal material — reviews,
plans, proposals, gap registries and feasibility records — is deliberately not
published, so a document in this directory can be read as current rather than
aspirational. Where a document is partly superseded it says so in its own header
and names what replaced it.

## Read these first

| Document | What it answers |
|---|---|
| [`../ROADMAP.md`](../ROADMAP.md) | What is built, what the known limits are, what is next, and what is deliberately not planned |
| [`threat-model.md`](threat-model.md) | What Andyur defends against, what it assumes, and which risks are still open |
| [`../CONCEPTS.md`](../CONCEPTS.md) | The vocabulary: agent, run, mind, workflow, authority |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | How the pieces fit together |
| [`DESIGN.md`](DESIGN.md) | The design decisions and their rationale |

## Authority and identity

The most load-bearing part of the system, and the part worth reading in order.

| Document | What it answers |
|---|---|
| [`authority-architecture.md`](authority-architecture.md) | Who decides what a run may do, and why the platform is not an authorization server |
| [`authority-flow-by-step.md`](authority-flow-by-step.md) | What must hold at each step, against the IETF and OpenID specifications that govern it |
| [`authority-runbook.md`](authority-runbook.md) | Operating the authority path |
| [`decisions.md`](decisions.md) | Settled decisions about identity, authority and tokens. Read before changing any of them |

## Contracts

Interfaces other people implement against. Changing these breaks users.

| Document | What it answers |
|---|---|
| [`agent-runtime-protocol-v1.md`](agent-runtime-protocol-v1.md) | The protocol an agent process speaks |
| [`adr-011-exec-v1-stock-process-contract.md`](adr-011-exec-v1-stock-process-contract.md) | How an unmodified upstream process runs under Andyur |
| [`extensions.md`](extensions.md) | How a separately installed package plugs in, and what an authorization policy can and cannot change |
| [`adr-008-byoa-agent-runtime.md`](adr-008-byoa-agent-runtime.md) | Bring-your-own-agent runtime contract |
| [`adr-009-run-event-plane.md`](adr-009-run-event-plane.md) | The run event plane |
| [`adr-012-oss-agent-certification.md`](adr-012-oss-agent-certification.md) | What certifying a third-party agent means |

## Architecture decisions

| Document | What it answers |
|---|---|
| [`adr-001-secrets.md`](adr-001-secrets.md) | Where secrets live and where they stop |
| [`adr-002-audience-identifiers.md`](adr-002-audience-identifiers.md) | Audience identifiers (partly superseded — read `authority-architecture.md` first) |
| [`adr-003-egress-topology.md`](adr-003-egress-topology.md) | The locked egress topology and its completion bar |
| [`adr-005-openbao-credential-custody.md`](adr-005-openbao-credential-custody.md) | Credential custody |
| [`network-topology.md`](network-topology.md) | What talks to what, and on which network |
| [`replaceable-components.md`](replaceable-components.md) | Which components Andyur composes rather than owns |

## Operating it

| Document | What it answers |
|---|---|
| [`observability.md`](observability.md) | Tracing, and what a run emits |
| [`observability-exit-criteria.md`](observability-exit-criteria.md) | Why no feature is done without a live trace proof |
| [`RELEASING.md`](RELEASING.md) | What a release is and what it must satisfy |

## Evidence

Claims in this repository are bound to the code they were made about. A gate that
verifies a property writes an artifact recording digests of the source it
exercised; when that source changes the artifact goes stale and
`infra/rc/evidence_currency.py` reports it. To check whether a documented
property holds *today* rather than held once, run that.

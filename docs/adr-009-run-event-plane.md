# ADR-009: Canonical Run Event Plane

Status: accepted for Phase A (contract only)

## Context

Andyur needs a stable semantic record of what the platform observed during a
run. Agent-originated data crosses an untrusted workload boundary, while policy,
authority, credential, runtime, and audit facts are meaningful only when emitted
by the platform component that enforces or observes them.

## Compose versus build decision

Phase A composes Python's standard immutable dataclasses/enums and JSON Schema's
standard transport vocabulary. Those mature components provide value typing,
serialization constraints, and compatibility tooling. Later phases must compose
the existing Andyur identity verifier, policy enforcement, database transaction,
HTTP/SSE, and PostgreSQL notification infrastructure at their real enforcement
points.

The custom code retained here is limited to Andyur-specific semantics that no
general library can supply: the event taxonomy, the allowed category/trust/
durability tuple for each event type, immutable provenance field names, and the
distinction between asserted workload observations and authoritative platform
facts. This phase does not implement cryptography, authenticate producers,
authorize viewers, persist events, redact arbitrary secrets, or carry network
traffic.

## Decision

- Define one versioned `RunEvent` contract under `andyur.events`.
- Treat a `RunEvent` as an already-recorded value. A future trusted publisher is
  the only API that may derive envelope fields from sealed run and producer
  context; workload adapters will submit a separate asserted input shape.
- Bind every known event type to exactly one category and a closed set of trust
  and durability classes. In particular, policy, authority, credential,
  delegation, runtime, and audit event types cannot be asserted.
- Keep provider names and raw framework records out of canonical semantics.
- Reject common credential-bearing key names, including case and separator
  variants, at every payload depth. Payload property names are printable ASCII,
  preventing Unicode case-fold ambiguity. This is defense in depth, not a secret or
  PII scanner: free-form values can still contain sensitive material. Producers
  must not place raw prompts, unsanitized model output, unsanitized user content,
  PII, credentials, or
  secret-bearing headers in `summary` or `payload`. Credential events carry
  non-secret references and metadata only. Closed event-specific payload
  schemas plus storage-boundary redaction remain required before those events
  are accepted from real producers. Content-bearing payload fields remain
  unavailable until those producer and projector enforcement points exist.
- Generate the checked-in JSON Schema from the Python enums, taxonomy, bounds,
  and prohibited-key constants. CI requires the artifact to equal the generated
  schema and exhaustively tests both accepted and rejected taxonomy tuples.
- Normalize both timestamps to UTC on serialization. `occurred_at` is advisory
  producer time and may be later than `recorded_at` because of clock skew; it is
  never an ordering or authority source.
- Define `sequence` as a trusted-store-assigned, strictly increasing value unique
  within `(tenant_id, run_id)`. Gaps are allowed, including where ephemeral
  events are not durably retained. Replay and display order use `sequence`, not
  timestamp. Transactional allocation and terminal-event rules belong to the
  publisher/store phase and are not enforced by this value object.
- Treat `event_id` as an opaque publisher-generated identifier that is globally
  unique in the event store. Parent-event existence and same-tenant/same-run
  binding require store enforcement in a later phase.
- Treat `classification` and `visibility` as sealed publisher-derived metadata,
  never workload assertions. They do not grant access by themselves; the future
  server projector must authorize the viewer and omit disallowed fields before
  serialization.
- Version the JSON representation independently from Python package versions.

## Enforcement proof and limits

Phase A proves only contract enforcement: invalid taxonomy tuples, unknown
fields, workload assertions of authoritative event types, and prohibited secret
field-name variants are rejected before a canonical value is produced. The
regression gate includes an externally executed exact guard mutation; the normal
test suite provides the positive and denial controls and must turn red under
that mutation.

Payloads are bounded by nesting depth, per-container count, string length,
property-name length, numeric magnitude, and a Python-ingress total-node budget. JSON Schema can
express every local bound but not a global aggregate node or byte budget. The
publisher/HTTP decoder must therefore add an aggregate serialized-byte limit at
the actual ingress boundary. Cyclic Python values fail through the finite depth
guard; JSON wire values cannot contain cycles.

Ingress validators must enable JSON Schema `date-time` format assertion; the
regex is only a structural UTC-form guard and cannot reject impossible calendar
dates by itself. JSON decoding must also reject non-standard `NaN` and infinity
tokens, and serialization must use an equivalent of `allow_nan=False`.

This is not proof of producer identity, tenant authorization, server-side
projection, transactional sequence allocation, parent binding, lifecycle
ordering, aggregate wire-size enforcement, or credential secrecy on the wire. Those claims
remain open until their later phases have live positive and denial tests at the
publisher, database, HTTP projection, and consumer enforcement points.

## Consequences

The console, transcripts, audit archive, and telemetry may project or correlate
with this contract, but they do not become parallel sources of RunEvent truth.
Adding a new event type is a schema change that requires an explicit taxonomy
entry and compatibility tests.

## Phase B local store slice

The local reference composition uses a run-bound `WorkloadRunEventPublisher`
plus `SQLiteRunEventStore`. Workload adapters submit an `EventDraft` with
semantic content only; tenant/run/agent/provenance come from a previously
verified `RunContextSnapshot`, source and asserted trust are fixed by the bound
publisher, and the store atomically
assigns event ID, recorded time, and a strictly increasing per-tenant/run
sequence. SQLite accepts durable events only, scopes every replay query by both
tenant and run, and rejects ordinary appends after a terminal run event.

There is deliberately no authoritative-event publisher in this slice. Policy,
authority, credential, runtime, audit, or terminal events cannot pass through
the workload publisher. This is still a local contract/reference slice. Binding
the context snapshot to authenticated sidecar/process identity, PostgreSQL concurrency,
ephemeral fanout, execution-independent failure policy, and live HTTP/SSE
projection remain later enforcement points and are not claimed here.
SQLite persists projected payload values as plaintext and is not a secret store;
closed event payload schemas plus storage-boundary sanitization/redaction are a
prerequisite before content-bearing producers are integrated.

The Python publisher/store objects are trusted-sidecar internals, not security
capabilities against arbitrary code executing inside that process. Leading
underscores prevent accidental API use; they are not an authentication boundary.
The untrusted agent process must receive only the bounded NDJSON/IPC ingress and
must never receive a Python publisher, writer, store, or context object. The
runtime-translation slice must prove that process boundary with a live negative
before this becomes a production security claim. Store terminality remains an
atomic invariant even though terminal producers are not introduced in this slice.

## Phase C sanitized translation slice

Run-scoped `RunEventTranslator.translate` consumes the existing sidecar-sanitized BYOA
shape and emits at most one coalesced asserted draft for output, operation
requests, and results. It copies no raw framework record, text, tool name/input/
result, error string, prompt, or credential into RunEvent. Payloads contain only
bounded counts and booleans with static summaries. These remain agent assertions,
not authoritative model, operation, policy, or authority facts.
Each run-scoped translator also caps accepted content drafts and emits exactly one
static warning only after the first excess draft is dropped. Its budget transition
is serialized so concurrent callbacks cannot exceed the cap or duplicate the marker.

The translator is not yet wired into the live sidecar consume loop. Until that
composition and its process-boundary positive/negative gate land, this slice
proves only deterministic privacy-preserving translation of already-sanitized
records.

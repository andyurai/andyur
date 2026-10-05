# ADR-008: Bring Your Own Agent — the framework-independent agent runtime

Status: accepted contract; phases C0/C1 and the production C2 launch path are
implemented. Packaging CLI and durable run-provenance persistence remain.

## Decision

Andyur becomes a secure agent runtime rather than a Claude harness. A
conforming third-party agent runs under Andyur without importing an Andyur
package, without receiving any Andyur, tool, or model credential, and without
knowing how Andyur implements identity or authorization. Andyur keeps what it
already owns — identity, authorization, credentials, model and MCP proxying,
audit, TTL/revocation/halt — and publishes exactly one new surface: a
versioned runtime protocol, `andyur-agent-runtime/v1`, plus a developer
`AgentManifest` that is compiled, under platform policy, into the existing
immutable `AgentResolution`.

The A/B container split is already the right seam. The privileged sidecar (A)
holds every credential and serves loopback services; the unprivileged agent
process (B) holds nothing. What is Claude-specific today is only the B-side
implementation (`andyur/agent/agent.py` imports the runner driver and drives
the Claude Agent SDK) and the runner's assumptions about B's event shapes.
BYOA generalizes that seam and nothing else. The security model does not
change; the set of parties who can satisfy it does.

## Compose versus build

Mature components carry everything they can (security gate rule 1):

- Transport is plain HTTP over loopback / a shared network namespace —
  implementable from any language's standard library, no Andyur SDK.
- Tool access stays MCP over streamable HTTP (`runner/toolservice.py`, the
  official MCP SDK). BYOA adds no tool protocol.
- Model access stays a protocol-compatible HTTP forwarder
  (`runner/modelproxy.py` or the gateway `/llm` route); any
  Anthropic/OpenAI-compatible client works unchanged.
- Container isolation stays the daemon's existing subtraction
  (`daemon/orchestrator.py`: netns join, unprivileged uid, cap-drop ALL,
  seccomp, zero mounts, filtered env).
- Artifact admission extends the `registry/governed.py` pattern (digest pin,
  cosign verification, deny list) to agent images through a runtime identity
  carried in the same verified registry snapshot.

The Andyur-specific code that must exist is authority logic and contract
enforcement: the manifest parser (fail closed), the narrowing compiler
(requested capabilities can never widen into granted authority), and the
conformance suite that proves the runtime contract at its enforcement points.

## D1 — The protocol is pull, and that is a deliberate deviation

The BYOA implementation design (external input document) proposed a push
model: the sidecar POSTs `/v1/run` into an HTTP server every agent must host,
with `GET /healthz` probing. The deployed topology is pull-shaped and already
works across containers: the agent dials the sidecar's channel, fetches its
context, and streams events back on one long request. Pull is kept because:

- A conforming agent needs only an HTTP client. No inbound listener, no port
  negotiation, no readiness race, in any language.
- "The agent never arrived" is already a first-class failure: the channel
  exposes a connected signal and the sidecar's watchdog fails the run closed.
- Cancellation is enforcement, not conversation. Halt, TTL, and revocation act
  out-of-band — the channel is severed and the container killed — so a push
  endpoint would add a *request* to stop, where Andyur already has the
  *ability* to stop. Constrain effects, not reasoning.
- Push implies a warm, reusable agent server. Andyur's unit is one run = one
  container = one credential envelope; warm reuse would break per-run
  identity, the TTL kill, and the structural-liveness argument the model
  proxy's design records.

Honesty constraint the spec carries: protocol v1 is one invocation per run.
Conversation runs are not split today, so v1 does not pretend to multi-turn
dispatch; a versioned turn extension is reserved for a future minor version
and must not be inferred from v1.

## D2 — Bootstrap is part of the public contract

Today the sidecar-spawned B receives the channel URL as argv and the channel
token as `ANDYUR_CHANNEL_TOKEN` — workable only because Andyur owns B's
entrypoint. A third-party image has an arbitrary entrypoint, so the contract
is exactly two environment variables, set by the platform, read by the agent:

    ANDYUR_RUNTIME_URL      base URL of the runtime endpoint
    ANDYUR_RUNTIME_TOKEN    optional bearer for that endpoint (absent when the
                            namespace boundary is the only control)

These are the ONLY environment variables the contract promises, and the only
ones a governed container is given. Everything else the agent needs arrives in
the context document. The builtin Claude adapter uses the same v1 routes and
document, but it is Andyur's own workload rather than a third party, so it
also receives the platform configuration it needs (run and agent ids, model
mode, CLI path, `HOME`, and the channel token under its internal name) and
keeps an internal argv bootstrap because Andyur owns that entrypoint. That
split is decided by the declared runtime type at launch, not inferred from
whether a command happens to be set: `RunGroupSpec.agent_runtime` chooses, and
`_agent_env` returns nothing for a container runtime. Passing the builtin's
variables to a BYOA workload would hand a third party the platform's model
configuration and `ANDYUR_CHANNEL_TOKEN`, which carries the same secret value
the contract already exposes as `ANDYUR_RUNTIME_TOKEN`.

## D3 — Neutral events; the sidecar never trusts agent-chosen kinds

`GET /v1/context` returns the run's immutable context: protocol version, run
and agent identifiers, the input, the loopback service endpoints (model base
URL, MCP URL and headers), limits (deadline, stream budgets), and trace
propagation. It never contains a run token, SVID material, broker credential,
gateway key, tool credential, or platform DB address. The production runner
constructs this projection directly; `/inputs` is only a migration alias to the
same handler, not a second document or enforcement path.

`POST /v1/events` is one NDJSON stream ending in a `done` sentinel carrying
exit status. There are exactly two event kinds, `msg` and `done`. A `msg`
event carries framework-neutral field groups — `texts` (assistant text),
`tools` (tool invocations), `results` (tool results), `result` (the final
outcome) — plus `record`, the framework's own opaque transcript record. The
platform classifies an event by which field groups are present, never by
inspecting `record`: introducing per-classification kinds was considered and
rejected because the receiver coerces and preserves the field groups anyway,
so a `kind` label would be a second source of the same truth. This contract
also retires the runner's habit of keying observability on Claude SDK type
names (`record.type == "AssistantMessage"`), which no other framework would
ever emit; the C2 consumer keys on field presence. The trust posture is
unchanged from `runner/protocol.py::sanitize`: every field from B
is coerced into a known shape on receipt, redacted on receipt, and used for
diagnostics and operator display only. No security decision reads an
agent-chosen value; a lying agent corrupts only its own transcript.

Claude-specific inputs (`max_turns`, `run_type`, mcp.json shaping) are
builtin-adapter parameters and stay out of `/v1/context`. Passthrough MCP
server configurations are delivered in context verbatim — passthrough means
Andyur does not touch that leg, and such entries are agent-held by
definition; the spec states this and notes stdio entries are unusable from a
container. The spec deliberately freezes nothing about actor identity;
`expected_actor` derivation is being resealed in the authorization lane.

## D4 — AgentManifest compiles into AgentResolution; authority only narrows

The developer-authored `AgentManifest` (metadata, runtime image + digest,
interface version, requested model, requested tools, I/O schemas) is a
request, never a grant. `andyur/agentspec/` compiles it with an explicit
typed policy input:

    compile_resolution(manifest, policy) -> CompiledAgent

`PlatformPolicy` is a parameter, not a second policy store: its values come
from the registry/server policy surface that already owns ceilings and
approved tools. The compiler intersects requested capabilities with approved
authority; anything requested but unapproved is refused or dropped per
policy, and nothing in a manifest can add an action, resource, tool, or model
the policy did not already permit. `CompiledAgent.resolution` is the frozen
registry type and carries the exact same `RuntimeResolution` object exposed by
the compatibility `CompiledAgent.runtime` view.

`approved_models` carries the ceiling tri-state deliberately: a set permits
exactly those models, `()` permits none, and `None` means "no model
restriction" (the manifest's charset-validated request is granted as-is).
`None` is the development-convenience default, not the secure default; a
platform enforcing a model policy passes the approved set or `()`. A model
name is never free text regardless -- the manifest parser anchors it to a
conservative charset, so a value carrying CR/LF or other injection into the
C2 model proxy fails at manifest validation.

`RuntimeResolution` (image reference and digest, interface version, command,
resources, manifest digest, policy revision, and the granted lifecycle) lives
in `registry.models` and is
an additive optional field on `AgentResolution`. Older authority-only artifacts
remain readable as `runtime=None`; the governed container launcher refuses that
value instead of substituting a worker-global image.

For governed OCI snapshots the wire carrier is deliberately overlay-only:
`runtime-resolutions.json` sits beside the authority manifests in the same
digest-pinned, cosign-verified artifact. Keys are canonical `agt_*` identifiers;
values are strict `RuntimeResolution` objects. The registry parses the overlay
after verification, excludes that reserved filename from the authority scan,
rejects unknown agents, and joins runtime to authority in memory. The
`andyur.agent-resolution/v1` authority document is not silently extended, so
old readers do not parse and then discard executable identity. A registry
publisher is the producer seam: it must emit the authority manifest and overlay
from one reviewed compilation transaction, then sign and publish that immutable
snapshot. Workers never write or re-resolve the overlay.

The parser lives in `registry/runtime_wire.py` and keeps the
`registry/manifest_registry.py` idiom — reject unknown fields, anchored
formats, explicit caps, no legal place for a secret value, digests mandatory in
governed mode. No new dependency.

One codec serves both readers of this document: the registry, which admits
every protocol the platform PUBLISHES, and the Kubernetes worker, which admits
only what it can LAUNCH and additionally requires an explicit command. Those
differences are arguments at each call site rather than two parser bodies, and
the codec refuses to import unless its field table matches the dataclass, so a
field cannot be added to the shape without reaching every wire crossing that
carries it. That check replaced an anti-drift test; the omission it guards
against is now unrepresentable rather than asserted.

## D5 — No second container launcher

The security-load-bearing agent-container launch in `daemon/orchestrator.py`
is composed, not duplicated. Phase C1 proves the contract
with a disposable conformance gate under `infra/byoa-spike/` (the
sender-binding-spike pattern: standalone harness, real components, dated
evidence artifact, mutation-tested controls) that stands up the real
`AgentChannel` and `ModelProxy`, and the real MCP streamable-HTTP transport
serving test tools (the production `ToolService` needs a live control plane,
so the gate uses the same transport with a stub tool server), and runs a
zero-Andyur-import reference agent against them, containerized with the
daemon's own subtraction flags. Production C2 carries the frozen runtime through
assignment and `RunSpec`; `GovernedKubernetesRuntime` refuses absent or malformed
runtime identity and supplies the digest-pinned image, manifest command,
resources, `ANDYUR_RUNTIME_URL`, and `ANDYUR_RUNTIME_TOKEN` to the existing Pod
generator. There is no worker-side registry lookup or global-image fallback.

The `runtime_type` branch in `GovernedKubernetesOrchestrator` is not an
`AgentRuntime` dispatcher and does not launch anything. It is a closed
translation from one validated frozen envelope into `RunGroupSpec`: a
third-party container supplies its digest-pinned image and explicit command;
the explicit `builtin-claude` selection supplies the platform-owned image and
the existing manifest generator's builtin command. Both branches immediately
terminate at the same `KubernetesRunController.launch`, which alone owns Pod
creation, credentials, rollback, adoption, networking, and teardown. A future
runtime type must extend this translation and the shared controller contract,
not add a launcher. This is the implemented replacement for the earlier C2
sketch of per-runtime `AgentRuntime` launch adapters, which would have violated
D5 by creating a second lifecycle authority.

## Phase C2 status and remaining boundary

- Done: production v1 context/events, builtin client migration, governed
  overlay parsing, assignment propagation, and digest-pinned Kubernetes launch.
- Done: persist the complete frozen runtime resolution into durable run
  provenance at admission (type, interface, manifest digest, image reference
  and digest, command, resources, policy revision, and lifecycle when one was
  granted). Kubernetes assignment
  re-resolves from the governed registry and refuses to claim the run unless
  the canonical resolution and registry digest both match. The exact missing-
  comparison mutation assigned every altered runtime; restoration refused all
  eight field mutations.
- Done: CLI `andyur agents init`, `validate`, and `package`. Packaging composes
  the existing strict manifest compiler plus production registry/overlay
  parsers; it emits authority documents and `runtime-resolutions.json` from the
  same frozen `CompiledAgent` objects, compares read-back semantics exactly,
  refuses an existing destination, and exposes it with one atomic rename. The
  secure CLI default approves no model.
- Done: `andyur agents conformance` pulls the manifest's digest-pinned image and
  runs the runtime-v1 positive/refusal/budget/kill/isolation gate against the
  workload production will actually launch: the manifest `command` replaces the
  image entrypoint in the gate exactly as it does in the Pod, and an external
  governed image without a command is refused rather than silently tested as
  its default entrypoint. It refuses to overwrite evidence, and the CLI accepts
  the artifact only through the same validator publication uses.
- Done: conformance evidence is bound to its producer and its subject. The
  artifact records `selected_image`, `selected_command`, and the sha256 of the
  gate and harness sources; publication recomputes those source hashes from the
  gate sources and matches image AND command against every container in the
  overlay. The gate lives in `infra/`, which is not part of the installed
  package, so publication runs from a source checkout or is pointed at those
  sources with `--conformance-gate-dir`. Evidence from an edited or older
  gate, for another image, or for another command cannot sign a snapshot.
  Publication validates and pushes one private copy of the snapshot, so the
  bytes ORAS signs are the bytes that were checked. ORAS's
  returned digest—not the tag—is then signed by cosign and is the only
  reference reported as success.
- Live (2026-08-21, `result-conformance-2026-08-21-darwin-arm64.json`): the
  selected image
  `localhost:5003/andyur/conformance@sha256:ab1eb4ffc1e5ff931d4b94ecfc516a4b3a2453dd0d18235a19e8a3c793f647dd`
  under command `["python", "/app/agent.py"]` passed 11/11, and that snapshot
  published and signed as
  `localhost:5003/andyur/snapshot@sha256:54b34dc9f3c075e2f28ea319d050ba5d241bb510d9615f2562e63218cb8b70ea`
  through real ORAS and cosign; the operator's own
  `agents package --publish-ref` path signed the same snapshot content as
  `sha256:9feea223753d025d1dfb5531f07a72f29fef106ec99256edef6e6956955ce768`.
  The same image under a non-conforming command scored 5/11, where the
  pre-change gate returned 11/11 for that image because it ran the entrypoint
  and never read the command — so that manifest would have published on
  evidence that never touched the workload it declares.
  Evidence carrying the previous gate's hash, and green evidence for the
  working-but-different command `["python", "-u", "/app/agent.py"]`, were both
  refused at publication.
- Live (earlier): the composed publisher/registry gate signed digest
  `sha256:d19ac9231179451ce8ab73ce38497b2392b0927b613f0d83c6013c793aa5f3ed`
  and the governed consumer accepted it while refusing tag-only, wrong-key,
  deny-listed, and unsigned snapshots.

## Multi-framework proof (done in C1)

The mission's strongest acceptance criterion — at least two independent
frameworks passing the same conformance/security suite — is met by the
framework gate (`infra/byoa-spike/framework_gate.py`). Two real third-party
agents, each its own container with its own dependency tree and no `andyur`,
run against the identical real components (`AgentChannel`, `ModelProxy`, the
real MCP transport):

- `demos/byoa-langgraph-agent/` — LangGraph, using `langchain-openai` for the
  model and `langchain-mcp-adapters` for tools;
- `demos/byoa-openai-agent/` — the OpenAI Agents SDK, using its own OpenAI
  model client and `agents.mcp` MCP client.

Each completes the full agentic loop (model → tool_call → granted MCP tool →
model → final) through its OWN framework machinery; the gate asserts the round
trip, secret absence by canary, and a `andyur`-free image. This is why the
model service now serves both the Anthropic and OpenAI-compatible surfaces
(the LiteLLM shape) — so a framework using either provider client works
unchanged.

## Acceptance (unchanged from the mission definition)

A third-party repository builds an agent against the published spec alone;
its image is digest-verified; it receives only the runtime protocol and
loopback endpoints; every existing per-tool, ceiling, pinning, cnf and audit
control still applies; run provenance names exactly which definition and
executable ran; at least two independent frameworks pass the same
conformance/security suite.

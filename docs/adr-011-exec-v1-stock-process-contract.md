# ADR-011: `exec/v1` — the stock-process contract for unmodified workloads

Status: accepted. D4 and D5 (the manifest surface and the closed reference
vocabulary) are IMPLEMENTED and validated fail-closed, and both blocks now REACH
the launch snapshot: `RuntimeResolution` carries `process` and `configuration`,
the compiler no longer discards them, and they cross all four wire boundaries
under the same closed vocabulary the parser enforces.

Carried is not consumed, and the difference is the rest of this ADR. The
launcher now acts on the `configuration` block (generated files, environment)
and on `process.input` (D10: the run's input reaches the process by the mode
the manifest declared, proven live for all three). **D3 completion is now built**
(not yet flipped on): a stock process reports nothing, so the daemon reads its
container exit at the one boundary it owns, maps it to run state via
`execlifecycle.exit_error` (exit 0 -> `done`, non-zero/absent -> `failed`),
bounds and redacts the captured output, and reports it through the
worker-authenticated `POST /runs/{id}/worker-finish` (the workload holds no run
token). The exec/v1 sidecar runs serve-only (`--serve-only`, keyed on the
server-supplied interface): it serves the model proxy and MCP but never arms the
channel connect-watchdog and never posts `/finish`, so the daemon is the sole
completer. `LAUNCHABLE_PROTOCOLS` admits `exec/v1` since the M1 flip: the stock
workload holds no runtime channel token by any Pod shape and the bearer it
declares -- the complete `Authorization` header value, `Bearer <token>` -- is
exactly what the serve-only proxy's `/mcp` accepts, kept true by an invariant
test and proven live by `infra/kubernetes/verify-exec-tool-call.py`. The
references cross UNRESOLVED by design (D4): all but the two workspace paths name
things that do not exist until a run does, and a resolution is signed once and
reused by every run of the agent. D8 conformance is built for `exec/v1`
(`infra/byoa-spike/exec_v1_gate.py`, checks E1-E7 below, evidence bound to the
gate source and the manifest and accepted by governed publication); D6's
writable-scratch-as-uid guarantee is proven by that gate's E7 on the docker
path and by the exec-input gate's file-mode check on Kubernetes.

Streams are NOT separable on the supported envelope: a container's stdout and
stderr are one combined log, captured under the stdout setting, so a manifest
that discards stdout while capturing stderr is refused at parse (D3).

Evidence base: the OpenSRE stock-image compatibility audit (23 Aug 2026) against
`ghcr.io/tracer-cloud/opensre@sha256:80e530dd06128d8b63016fbd371ac683c8744f1e187d14fbcfb5298ed4567cd2`.
The unmodified upstream image completed a full investigation as an unprivileged
process on a read-only root filesystem, holding no provider credential, reading
its task from stdin and writing JSON to stdout, exit 0. (This sentence used to
claim the audit also ran "on a network with no route off-subnet". That claim is
withdrawn, not because it is known false but because nothing in the tree records
which harness measured it, and the conformance gate that exists today leaves
containment unmeasured; the gate that exists NOW records it as **OBSERVED**
(see D11), which is a different run and cannot retroactively support the
withdrawn sentence. An evidence base may not assert a containment property no surviving run
bounded.) It never called `/v1/context` or `/v1/events` and never needed
to.

## Decision

Andyur publishes a second runtime interface, `exec/v1`, for workloads that know
nothing about Andyur. Where `andyur-agent-runtime/v1` is a protocol **the
workload speaks**, `exec/v1` is a contract **the platform speaks about the
workload**: the workload is an ordinary process, and every fact Andyur needs is
observed at boundaries Andyur already owns rather than reported by the thing
being governed.

A conforming `exec/v1` workload does nothing at all. It starts, reads its input
the way any Unix program does, does its work, writes to stdout, and exits.
Andyur supplies configuration, observes the model and tool legs at the proxy and
the MCP service, bounds the run, and destroys it.

This is not a compatibility shim for one project. It exists because the property
that made OpenSRE work — being a normal process — is the property most upstream
OSS agents already have, and the alternative is one adapter per project, which
the OSS programme forbids as a production path.

## Compose versus build

Almost nothing is new. `exec/v1` mostly declines to require things.

- Isolation, uid, read-only rootfs, cap-drop, egress confinement and the
  governed container lifecycle are ADR-008's and unchanged. `exec/v1` adds no
  launcher (ADR-008 D5 still holds).
- Model access stays the credential-injecting proxy. The workload reaches it
  because a variable points there, not because it asked.
- Tool access stays MCP over streamable HTTP at the sidecar, with the per-tool
  decision from `andyur/mcpwire.py`.
- Input and output are argv, stdin, files and exit status: POSIX, not a
  protocol Andyur has to define or version.

What must be built is Andyur-side and generic: the declarative configuration
surface, the completion mapping, and a conformance gate that proves the contract
at its enforcement points.

## D1 — The workload is not a participant, and that is the point

Runtime-v1 is a pull protocol. The agent fetches an immutable context and
streams neutral events back. That requires the agent to be Andyur-aware, which
most upstream projects are not and have no reason to become.

`exec/v1` inverts where knowledge lives. The workload holds no protocol
obligation, so there is nothing for it to implement, get wrong, or version.
Everything Andyur needs, it already sees:

| Fact | Runtime-v1 source | `exec/v1` source |
|---|---|---|
| the run started | channel connected | process spawned |
| model was called | agent's request through the proxy | identical |
| a tool was called | MCP request at the sidecar | identical |
| the call was authorized | sidecar decision | identical |
| the run ended | `done` sentinel | process exit |
| what the run concluded | `done` payload | **nothing authoritative — see D3** |

Only the last row is a real loss, and it is a loss the security model already
required us to accept: an agent's account of its own work was never evidence.

## D2 — An `exec/v1` workload holds strictly less than a runtime-v1 one

Worth stating plainly, because it reads like a weaker contract and is not.

A runtime-v1 agent receives `ANDYUR_RUNTIME_URL` and, usually, a bearer token
for the runtime channel. An `exec/v1` workload makes no control-plane calls at
all, so it receives **no runtime token and no channel**. It gets the
sidecar's service URLs (loopback in process mode; the proxy Pod's IP and
fixed ports on Kubernetes, the only destination its NetworkPolicy admits), a
throwaway model key, and whatever safe constants the manifest mapped. Nothing
else.

So the credential surface shrinks. The audit confirmed a real workload runs on
exactly that.

## D3 — Exit status is lifecycle completion, never task success

This is the decision most likely to be got wrong, so it is stated sharply.

`exit 0` means **the process completed**. It does not mean the work succeeded.
The audit is the proof: OpenSRE exited **0** having concluded *"Unable to
determine root cause."* A run that reaches no conclusion is a completed run with
a disappointing outcome, not a failed one.

    process exit 0        -> run state `done`
    process exit non-zero -> run state `failed`, exit code recorded
    TTL / deadline        -> platform terminates; failed, regardless of intent
    operator halt         -> platform termination is authoritative
    revocation            -> authority removed, then terminated
    sidecar failure       -> fail closed
    process vanishes      -> the daemon reads no exit code and fails the run
                             (exit_error maps a missing status to failed); the
                             deadline reaper is the backstop, not the primary
                             signal. The exec/v1 sidecar runs SERVE-ONLY and arms
                             NO connect watchdog -- a stock process never connects
                             a channel, so the daemon reading the container exit
                             is the completion signal, not a "never connected"
                             timeout (D3).

**There is no authoritative channel for task outcome under `exec/v1`, and none
will be added by parsing stdout.** Captured output is diagnostic: stored, shown
to the operator, never read by an authorization decision and never treated as
proof that anything happened. A workload that needs to assert a structured
result implements runtime-v1, where `done` carries a payload the platform
accepts as the agent's *claim* — still not as evidence.

The distinction matters because "completed successfully" is what an evidence
record will be read to mean. It must say `done`, and `done` must mean the
process exited cleanly.

## D4 — Configuration is a closed reference vocabulary, not a template engine

`exec/v1` needs to put values into a workload's environment and config files.
That is an injection surface, and prose like "only safe values are interpolated"
is not a control.

Every interpolable reference is **enumerated in code**, validated at parse time,
and anything else is refused — the same shape as `AuthorityMode`,
`LifecycleMode`, the OpenBao provider/kind vocabularies and the credential
adapter set.

The rule the vocabulary encodes: **a manifest may name the run's own capability
material; it may never name a downstream credential.**

Those are different categories and the distinction is the whole control. The
per-run MCP bearer resolves through this vocabulary because the workload cannot
call its own governed endpoint without it, and holding it grants nothing beyond
what the run already has — it is a capability scoped to this run, at the sidecar's own (loopback in process mode, the proxy Pod on Kubernetes)
service, that Andyur itself issued. A vendor API key is the opposite: authority
at a third party, outliving the run, which Andyur exists to keep out of the
workload. No reference resolves to one, so "put the Datadog key in the config
file" is not a thing a manifest can express, however it is written.

    services.model.base_url        the credential-injecting model proxy
    services.model.openai_base_url the OpenAI-compatible surface of the same
    services.model.name            the model the resolution granted
    services.tools.mcp_url         the governed MCP endpoint
    services.tools.mcp_headers.*   the per-run bearer as a complete header
                                   value (`Bearer <token>`)
    run.id / run.deadline_epoch    identity and bound
    run.input_path                 where the run's input lands (mode `file` only)
    workspace.home / workspace.tmp the writable scratch paths

A literal is always allowed. Anything not in the list is a manifest error, and
the error names the closed set rather than hinting at it.

## D5 — Schema: a `process` block, because `input` is taken

The manifest already has a top-level `input`, whose only permitted key is
`schema`, and the parser rejects unknown fields. Overloading it would give one
name two unrelated meanings.

```yaml
runtime:
  type: container
  image:  { ref: ..., digest: sha256:... }
  command: ["opensre", "investigate", "-i", "-"]
  interface:
    protocol: exec/v1
  lifecycle:
    mode: task
    max_seconds: 1800
  # process and configuration live UNDER runtime, beside command and interface.
  # An earlier draft put them at the top level, where the parser's closed key
  # set refuses them -- and adr-008's acceptance is that a developer builds
  # against the published spec ALONE, so a design document whose example does
  # not load is a defect in the design document. A test now parses this block.
  process:
    input:
      mode: stdin            # stdin | argv | file | none
      max_bytes: 262144
    output:
      stdout: capture
      stderr: capture
      max_bytes: 1048576

  configuration:
    env:
      LLM_PROVIDER:    { literal: openai }
      OPENAI_BASE_URL: { from: services.model.openai_base_url }
      OPENAI_API_KEY:  { literal: andyur-placeholder }
      HOME:            { from: workspace.home }
    files:
      - path: "${workspace.home}/.config/workload/config.yaml"
        template: |
          mcp_url: ${services.tools.mcp_url}
```

Fail closed throughout: unknown keys rejected, bounds required, every `from`
validated against D4's vocabulary, every generated file written only inside the
declared writable scratch.

## D6 — Writable scratch must be writable by the workload's uid

The runtime protocol promises "two writable, empty, ephemeral directories at
fixed paths." The audit showed that promise is incomplete. A root-owned mount
satisfies its letter, and a non-root workload dies inside itself:

    PermissionError: [Errno 13] Permission denied: '/home/opensre/.opensre/integrations.json'

So ownership joins the contract: the declared scratch paths are writable **by
the uid the workload actually runs as**. The Kubernetes path already has the
mechanism (`fsGroup` with `fsGroupChangePolicy`); what is missing is the stated
guarantee and a conformance check that creates, reads and deletes a file **as
that uid** rather than as root.

This is generic. It applies to every non-root workload, on both interfaces.

## D7 — Nothing refuses on the workload's behalf, so the digest carries more weight

A runtime-v1 agent refuses a context whose `protocol_version` it does not
implement, and gate check G3 proves it. An `exec/v1` workload cannot refuse
anything: it is a binary that will happily start under a configuration it does
not understand and fail in its own way, later, having perhaps already acted.

The compensating control is that compatibility is **proven, not declared**.
Conformance evidence binds to the exact image digest, the exact command and the
generated configuration. The audit already showed why: the repository's
`.env.example` documented an LLM provider (`custom-openai`) that the published
image rejects outright. A manifest asserting it would have been syntactically
perfect and wrong.

`interface.protocol` gains `exec/v1` as a second enum member. A resolution
naming an interface the platform does not serve is refused at publish, as today.

## D8 — Conformance: the same properties, observed differently

The existing gate proves runtime-v1 properties (G1–G6). `exec/v1` needs its own,
because three of those checks have no meaning here and the rest move.

| Property | Runtime-v1 | `exec/v1` |
|---|---|---|
| starts and completes | context fetched, `done` streamed | process spawned, exits 0 |
| model reached the proxy | agent sent the context's model | request observed at the proxy |
| a granted tool was called | observed on the MCP transport | unchanged |
| an ungranted tool is refused | unchanged | unchanged |
| no credential in the workload | env, argv, filesystem, transcript | env, argv, filesystem, **generated config files** |
| unsupported protocol refused | agent exits non-zero | **not applicable** — replaced by digest-bound evidence (D7) |
| budgets enforced | stream byte budget | output capture bound |
| killed workload fails closed | unchanged | unchanged |
| scratch writable | assumed | **create/read/delete as the workload uid** (D6) |

The credential-absence scan gains a target that runtime-v1 does not have:
`exec/v1` generates configuration files inside the workload, so those files are
now a place a secret could land and must be scanned.

## D9 — What this gives up, stated so nobody discovers it later

- **No progress.** Operator UX for an `exec/v1` run is captured stdout, which
  arrives when it arrives and is untrusted text. Runtime-v1 remains the right
  interface for a workload that wants a live operator experience.
- **No structured result.** D3.
- **No negotiation.** D7.
- **Weaker attribution inside the run.** Runtime-v1 events carry a shape the
  platform can attribute to a step; stdout is a stream of bytes. Traces still
  attribute the model and tool calls, which is where authority lives.

None of these weaken the security model, because none of them were ever load
bearing for it. They weaken the product experience, and that is the honest
trade for running software nobody wrote for us.

## D10 — Input: a task is a sealed run input, delivered by the declared mode

Until this decision the platform had no invocation input at all. A run carried
one task-shaped field, `reason`: free text, unbounded, rendered into a native
agent's prompt and consumed nowhere else. That is a wakeup, not an invocation,
and a stock process cannot be woken; it has to be handed its task.

**What a task is.** A run has two task fields. `reason` stays what it was, the
human *why*. `input` is new: one JSON value the trigger caller hands the run,
canonicalised (sorted keys, no insignificant whitespace), sealed into the same
INSERT as the scope and the pin, and delivered per interface:

    builtin-claude   a fenced "Run input" prompt section, after the wakeup
    runtime-v1       `input.data` in the context document (the reserved field)
    exec/v1          by `process.input.mode`, below

It is data, not authority (the PDP reads the pin, never the input), not
instruction (a native agent sees it fenced as untrusted, exactly as it sees
task detail), and not a credential (a credential-shaped input is refused at
the door, a footgun guard in the same family as the parser's). Only the
operator-gated trigger supplies it. Schedules, tasks and messages carry no
input; an input-taking `exec/v1` agent woken by any of them is refused by name
rather than launched.

**The door rule, and why it is at the door.** `maybe_wakeup` knows the
manifest, so it decides deliverability before the run exists: mode `none`
with an input, any other mode with *no* input, or an input over
`process.input.max_bytes`, is refused with the caller still on the line. The
second case is the one that matters. A container with `stdin` open and nobody
attaching does not read EOF; it blocks until the deadline reaper kills it
(probed: still blocked after 5 s with no attach). A refused trigger is a
better outcome than that in every way. The launcher re-checks the same rule
with the envelope in hand, through the same function, because an assignment
is untrusted input at the worker.

**Delivery.** The bytes a process reads are one rule: a JSON string is
delivered as its text (`goose run -i file`), anything else as its canonical
JSON (`opensre investigate -i -`).

    argv    appended as one last argument. Bounded by Linux MAX_ARG_STRLEN
            (131071 bytes) and refused above it by name, because past it
            execve fails inside the runtime and reports nothing about size.
            Visible in the Pod spec and the process cmdline: the same
            exposure class as a literal in `configuration.env`. ONE CAVEAT the
            manifest author owns: the input is appended as a POSITIONAL, and a
            stock tool that parses options will read an input that begins with
            `-` or `--` (`--config=...`, `--output=...`) as a FLAG, not a task
            -- classic argument injection. The platform cannot insert a `--`
            end-of-options guard on the author's behalf, because a tool that
            does not understand `--` would then receive it as literal data. So a
            manifest using `argv` for input MUST terminate its own options
            (end `command` with `--` where the tool supports it) or accept that
            a leading-dash input is tool-defined. Prefer `stdin` or `file`,
            which carry no such ambiguity; `argv` exists for tools that read
            their task only from a positional.
    stdin   the worker attaches to the WORKLOAD container after it is
            Running and writes the bytes; `stdinOnce` closes stdin when the
            attach ends, so the process reads EOF after exactly those bytes.
    file    the same attach, aimed at the platform's init container, which
            persists the bytes to the fixed path `/tmp/andyur/input`
            (`${run.input_path}`, 0600, the workload's uid) before the
            workload starts. One init container does this and the D5 file
            rendering; it exists when either is needed.

One primitive for stdin and file was the deciding factor. Rejected: a
ConfigMap or init-container env for file mode (a cluster object holding task
data, capped at 1 MiB below the manifest's 8 MiB bound); the init container
fetching from the proxy channel (a second transport and a channel token in
the init container); wrapping the command (already rejected under D7). The
attach is the official Kubernetes client over websocket; the worker's Role
gains `pods/attach` `create` in the runs namespace, which widens what it may
do to Pods it already creates and deletes there, not which Pods it reaches.

**The input is never a template.** Input bytes never pass through the
`${...}` resolver. That separation is a security property, not a tidiness
one: the init container holds this run's bearer whenever a declared file
names it, and a caller-controlled payload that read
`${services.tools.mcp_headers.Authorization}` must land as those characters.
It does, and a mutation that routes input through the resolver is caught.

**What this does not do.** It does not validate the input against the
manifest's `input.schema`; the schema file does not travel in the registry
artifact, so that is a packaging change first. It does not give schedules an
input. `reason` remains unbounded, which is the same class of problem this
decision fixed for input and is recorded as such.

## D11 — Third-party reach: allowed, brokered, never held by the workload (amendment, 2026-08-26)

This contract has been read as "an `exec/v1` workload may not reach a third
party". That was never decided. It is what the surface happens to do: the
reference vocabulary in D4 names a model leg and one MCP endpoint, so there is
nothing a manifest can say to point a workload at a tool, and the Kubernetes run
group gives the agent Pod no DNS and one egress rule. Silence is a poor place
for a position this load-bearing, especially once a stock image ships a vendor
SDK, as the SRE image already published under governance does.

The position, stated: **a stock workload may reach a third party, only through a
binding an approver accepted, and never holding the credential.** Undeclared
reach stays impossible by construction, which is what the no-DNS default buys.
Declared reach is a governed grant, not an exception to the model.

The mechanism is ADR-013, which extends D4 with exactly one reference family and
adds no template engine. Nothing about D1, D2 or D7 changes: the workload is
still not a participant, it still holds strictly less than a runtime-v1 agent,
and the digest still carries the weight.

Two consequences that belong in this contract rather than in ADR-013:

- **The conformance gate's network posture is part of the contract's evidence,
  and it is now MEASURED** (closed 2026-08-26, the production-gaps row on
  unmeasured absences). `E1` through `E7` observe what the workload did; `E8`
  bounds what it could reach. The workload runs on an internal docker network
  whose only peer is a relay forwarding the two harness ports, which is the
  shape the Kubernetes path already enforces with one egress rule to the proxy
  Pod. E8 then probes from inside that network, so the gate bounds the
  workload's network and records the destinations it saw, with a POSITIVE
  CONTROL, because a denial proves nothing when everything is refused. A report
  may now state containment as **OBSERVED** rather than as an absence
  (ADR-012 D10). (The state token is deliberate: a regression test compares it
  to the gate's live argv, so this paragraph cannot drift out of step with the
  code it describes, in either direction.)

  `--network none` is deliberately not the mechanism. The workload must reach
  the model front and the MCP service, so what this contract requires is a
  bounded route, not the absence of one.
- **`E3b` fails closed** (closed 2026-08-26). It read "the tool traffic, if
  any", which passed identically for a workload that authenticated correctly on
  every call and one that never tried, and the SRE image went green on
  `workload_mcp_requests=0`. It now fails when the manifest declares tool grants
  and the workload made no tool request, and records positive per-method counts
  either way, so zero is a measurement rather than a silence.

## Acceptance

`exec/v1` is done when:

1. An unmodified upstream image runs to completion under a manifest and
   configuration alone, with no adapter and no project-specific platform code,
   and its input reaches it by the declared mode, byte-identical (D10).
2. The credential-absence scan passes over environment, argv, filesystem and
   every generated configuration file.
3. Model traffic is observed only at the proxy and tool traffic only at the MCP
   boundary, with an ungranted tool refused.
4. Exit status maps to run state per D3, and no evidence record reports task
   success on the strength of `exit 0`.
5. TTL, halt and revocation terminate the workload, and a vanished process fails
   the run without waiting for the deadline.
6. Scratch is proven writable as the workload's uid.
7. Conformance evidence binds image digest, command and generated configuration.
8. **A second, unrelated upstream workload runs on the same primitives with no
   new platform code.** Per the OSS programme's stability rule this is what
   makes the abstraction real rather than OpenSRE-shaped; Goose is the intended
   second.

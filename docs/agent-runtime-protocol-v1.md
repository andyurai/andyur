# Andyur Agent Runtime Protocol — `andyur-agent-runtime/v1`

This document is the complete contract between the Andyur platform and an
agent workload. It is written for someone building an agent in any language,
with no access to Andyur source code and no Andyur SDK. If you implement what
is on this page, your agent runs under Andyur's identity, authorization,
credential, audit, and lifecycle controls without ever holding a credential.

Status: v1 is frozen by ADR-008. The conformance gate under
`infra/byoa-spike/` and the production `AgentChannel` serve and enforce this
contract today. Governed Kubernetes launches inject the bootstrap variables
and consume runtime identity from the verified registry snapshot. Nothing in
this document depends on how
Andyur implements identity or authorization, and that is deliberate.

## 1. The model in one paragraph

Your agent runs as an unprivileged workload beside a privileged Andyur
sidecar. The sidecar holds every credential and serves three local HTTP
services: the runtime endpoint (this protocol), a model API, and an MCP tool
endpoint. Your agent starts, reads two environment variables, fetches its run
context from the runtime endpoint, does its work using the model and tool
services, and streams events back on a single long-lived request ending with
a `done` line. Then it exits. One run is one invocation of one workload; the
platform destroys the workload when the run ends, whatever the reason.

Your agent owns prompting, planning, memory, and loop semantics. The platform
owns identity, authorization, credentials, egress, audit, and lifecycle. The
platform never trusts anything your agent sends: events are sanitized and
redacted on receipt and carry no authority.

## 2. Bootstrap

The platform sets exactly two environment variables for the agent workload:

| Variable | Meaning |
|---|---|
| `ANDYUR_RUNTIME_URL` | Base URL of the runtime endpoint, e.g. `http://127.0.0.1:8765`. |
| `ANDYUR_RUNTIME_TOKEN` | Optional bearer token for the runtime endpoint. May be unset when the network namespace boundary is the only access control. |

If `ANDYUR_RUNTIME_TOKEN` is set, send it as `Authorization: Bearer <token>`
on every runtime-endpoint request. Do not pass it to child processes; it
authorizes the runtime channel, which only the top-level workload should use.

"Exactly two" is a promise about what the platform ADDS, and it is enforced:
a governed container receives these and nothing else from Andyur. Whatever
your own image declares (its `PATH`, its language runtime's variables) is
still yours. If you find another `ANDYUR_*` variable in your environment, that
is a platform defect — report it rather than reading it, because anything not
listed here can be withdrawn without a version change.

No other environment variable is part of this contract. An agent that reads
anything else from its environment is depending on platform internals that
may not exist tomorrow.

The sidecar may still be starting when the agent comes up. Retry **connection
failures** to the runtime endpoint for a bounded period (the platform's own
reference agent uses 120 s). Do not retry HTTP error responses: a `401` is a
wrong token and a `409` is a duplicate stream, and both are decisions, not
cold starts.

## 3. `GET /v1/context`

Returns the run's immutable context document, JSON, `200`:

```json
{
  "protocol_version": "andyur-agent-runtime/v1",
  "run_id": "run_1f2e3d",
  "agent_id": "agt_fraud",
  "model": "claude-sonnet-4-5",
  "input": {
    "prompt": "Investigate ticket T-1041 and summarize the root cause."
  },
  "services": {
    "model_base_url": "http://127.0.0.1:9001",
    "mcp_url": "http://127.0.0.1:9002/mcp",
    "mcp_headers": {"Authorization": "Bearer per-run-opaque"},
    "extra_mcp_servers": {}
  },
  "limits": {
    "deadline": "2026-08-15T08:30:00Z",
    "max_line_bytes": 8388608,
    "max_stream_bytes": 67108864
  },
  "trace": {"traceparent": "00-..."}
}
```

Field semantics:

- `protocol_version` — reject the run (exit non-zero without streaming
  events) if this is not a version you implement. The platform likewise
  refuses to launch a workload whose manifest declares a version it does not
  serve.
- `model` — the effective model this run executes on, selected by the platform
  from the approved resolution (the manifest's requested model narrowed by
  policy, or the platform default). Send this model id to the model service.
  It is the model you were granted; sending a different one is against policy
  and enforced at the gateway per platform policy (section 6), not by the
  loopback proxy. `null` means "use the model service's own default." It is a
  single model id and is vendor-neutral from your side: the gateway maps it to
  a provider, so you may send a `claude-*` id through the OpenAI-compatible
  surface or vice versa.
- `input.prompt` — the task, as text.
- `input.data` — the run's input, present only when the trigger that
  created this run carried one: the caller's JSON value, canonicalised
  (sorted keys, no insignificant whitespace), of whatever shape your agent's
  own task format is. It is data, not instruction: nothing in the platform
  authorises on it, and your agent should treat it as it treats any
  caller-supplied payload. The platform does not validate it against a
  manifest's `input.schema` in v1; that declaration remains documentation of
  what your agent expects.
- `services.model_base_url` — see section 6.
- `services.mcp_url` / `services.mcp_headers` — see section 7. When
  `mcp_headers` is present, send every header on every MCP request.
- `services.extra_mcp_servers` — passthrough MCP server configurations from
  the agent's manifest, delivered **verbatim**. Passthrough means Andyur does
  not sit on that leg: anything in these entries (including any credential)
  is agent-held by definition and was declared by the agent's own manifest.
  Entries describing stdio servers are unusable from a container workload.
- `limits.deadline` — RFC 3339 UTC, or `null` when no per-run deadline is
  exposed (the platform's TTL and revocation still bound the run either way).
  When set, the platform enforces it by terminating the run; a well-behaved
  agent finishes and streams `done` before it.
- `limits.max_line_bytes` / `limits.max_stream_bytes` — the event-stream
  budgets (section 5). The whole-stream budget is the enforced backstop;
  stay within both.
- `trace.traceparent` — W3C trace context, or `null`. Propagate it if you
  emit traces; ignore it otherwise.

The context never contains: a run token, any SPIFFE SVID or private key, a
broker credential, a model gateway key, a tool OAuth or API credential, or a
platform database address. If you find one, that is a platform bug —
report it; do not use it.

Unknown fields may appear in any object; ignore them. That is how minor
versions add capability without breaking you.

## 4. `POST /v1/events`

One request per run, opened once, body streamed as newline-delimited JSON
(`Content-Type` is not inspected; the body is NDJSON). Each line is one
event. The last line is the `done` sentinel. Then close the request body.

The endpoint answers `200` after the stream completes, `401` for a bad
token, `409` if a stream is already open for this run (exactly one workload
streams per run), and `413` if a budget was exceeded — in which case the
platform has already failed the run.

If your agent crashes before sending `done`, the platform notices (the
stream ends without a sentinel, or the workload exits) and fails the run
closed. Silence is never success.

## 5. Events

There are exactly two kinds:

```json
{"kind": "msg", "record": {}, "texts": [], "tools": [], "results": [], "result": null}
{"kind": "done", "exit": 0, "error": null}
```

A `msg` event carries any subset of four field groups. The platform
classifies the event by **which groups are present** — it never interprets
`record`:

- `texts` — list of strings: assistant-visible text produced this turn.
  Shown to operators and used for run summaries.
- `tools` — list of `{"id": str, "name": str, "input": any}`: tool
  invocations the agent started. Used for tool-span tracing; `id` correlates
  with a later result.
- `results` — list of `{"tool_use_id": str, "content": str | [{"text": str}],
  "is_error": bool}`: completed tool calls, correlated by `tool_use_id`.
- `result` — a single object, at most once per run, carrying the final
  outcome: `{"result": str, "is_error": bool}` plus optional `num_turns`,
  `usage`, `session_id`, `total_cost_usd`. `result.result` is the run
  summary; `is_error: true` marks the run failed with `result.result` (or
  richer optional fields) as the diagnosis.
- `record` — your framework's own transcript record for this event, any JSON
  object. The platform redacts and stores it verbatim as the run transcript.
  It is yours: put your native message format here so your transcript is
  faithful to your framework.

The `done` sentinel ends the stream: `exit` is your process's intended exit
status (0 for success), `error` a short diagnosis or `null`. Send it exactly
once, last. An agent that has sent a `result` group still sends `done`.

Trust semantics you can rely on, and their limits: everything you send is
sanitized into a known shape and redacted on receipt. Your events drive
operator display, tracing, and your own transcript — never an authorization
decision. Lying in events corrupts only your own run's record; it grants
nothing, because the workload holds nothing.

Budgets: keep every line within `limits.max_line_bytes` and the whole stream
within `limits.max_stream_bytes`. The whole-stream budget is the enforced
backstop — exceeding it fails the run — so a conforming agent must respect it
regardless of line framing. Real runs are kilobytes to a few megabytes; the
budgets exist because the platform assumes the workload may be hostile.

## 6. The model service

`services.model_base_url` is an HTTP endpoint that fronts the model your
resolution granted. The platform forwards paths under it transparently, so it
serves the provider surface your client speaks:

- the **Anthropic Messages API** at `POST /v1/messages`, and
- the **OpenAI-compatible Chat Completions API** at `POST /v1/chat/completions`
  (the surface Andyur's LiteLLM gateway exposes).

Point any ordinary client at that base URL: an Anthropic SDK at
`model_base_url`, or an OpenAI-style client (including `langchain-openai` and
the OpenAI Agents SDK) at `model_base_url` + `/v1`. Both reach the same
credential-injecting proxy.

- Send **no** credential. `Authorization`, `x-api-key`, and similar headers
  are stripped and replaced by the platform on the outbound leg; nothing you
  send there survives. (Clients that require a key still need a placeholder;
  any string works — it is discarded.)
- The effective model is the one the platform selected from your approved
  resolution and told you in `model` (section 3). Send that. The platform's
  gateway carries the credential and enforces model-family, rate, and cost
  policy on its key; the loopback proxy in front of it injects the credential
  and streams your request through without rewriting the body, so it does not
  itself reject a different model id. Do not rely on sending another model —
  it is against policy, is audited on the platform's key, and what a
  policy-configured gateway does with it is out of your control. Send the
  model you were given.
- Responses stream normally; the platform does not buffer or rewrite bodies.

## 7. The MCP tool service

`services.mcp_url` is an MCP endpoint (streamable HTTP transport, JSON
responses) exposing exactly the tools this run may call. Use any MCP client.

- `tools/list` returns only tools your run is permitted to call.
  `tools/call` on anything else is refused. Both answers come from the same
  permitted-tools decision, so the list is never wider than the law.

  Scope of that promise, stated exactly: it holds where the binding a reviewer
  approved **enumerates** its tools. A binding approved at audience level names
  no tools, so there is nothing to filter against and the leg is authorized by
  audience, path and method alone -- the listing is then whatever the upstream
  serves. Ask for a binding whose grants are enumerated if you need the
  narrower guarantee.

  For a period this paragraph over-promised: the decision was reachable only on
  the optional dataplane, while the default path had no JSON-RPC awareness and
  an enumerated binding admitted every tool its upstream exposed. Both paths now
  import one function, so the drift that made the promise false cannot recur.
- Tool credentials, delegated tokens, and mutual-TLS identity live on the
  platform side of this endpoint. Your call is executed *as this run*, under
  its granted authority, and audited.
- Send `services.mcp_headers` on every request when present.

## 8. Lifecycle and termination

The platform terminates the workload on: run TTL expiry, operator halt,
revocation, deadline, budget overrun, sidecar failure, or protocol
violation. Termination is out-of-band — you will not receive a request
asking you to stop; the channel closes and the workload is destroyed. Design
your agent so that being killed at any moment leaves nothing worth cleaning
up outside its own scratch space (which is ephemeral and destroyed with the
workload).

That scratch space is concrete: your container's root filesystem is read-only,
and you get exactly two writable, empty, ephemeral directories at fixed paths
— `/tmp` and `/home/agent`. Both are destroyed with the workload and are
private to it: nothing you write there outlives the run or is visible to any
other run. Write nowhere else; the rest of the filesystem will refuse you.

Note that `HOME` is not one of the two variables the platform sets, so it is
whatever your own image declares — which may well be a path outside those two
directories and therefore read-only. If your language runtime or tooling
writes to `$HOME` (caches, config, lock files), either set `HOME=/home/agent`
in your image or point that tooling at one of the two paths above. This is the
most common way a working image fails only once it runs here.

v1 is one invocation per run. There is no warm reuse and no second task on
the same workload; a future minor version may add a turn-polling extension,
and its absence in your context means it does not exist for your run.

## 9. The AgentManifest

An agent is onboarded by publishing an `AgentManifest`. The manifest
**requests**; platform policy **grants**. Nothing you write in a manifest
can widen your authority — requested tools, models, and capabilities are
intersected with what policy approves, and the run executes under the
resulting immutable resolution.

YAML and JSON are equivalent serializations of one schema. Example:

```yaml
apiVersion: andyur.ai/v1
kind: Agent
metadata:
  id: agt_fraud
  name: fraud-investigator
  version: "1.4.2"
runtime:
  type: container
  image:
    ref: ghcr.io/acme/fraud-agent
    digest: sha256:8b2c62409b0a944b0d19b1b1c2589bbcdbc85358c9daa3d525d1051dc4e05fbd
  command: ["/app/agent"]
  interface:
    protocol: andyur-agent-runtime/v1
  resources:
    cpu: "2"
    memory: "4Gi"
instructions: >
  Investigate the assigned ticket, correlate telemetry, and report a root
  cause with evidence.
model:
  requested: claude-sonnet
  access: proxy
capabilities:
  tools:
    - server: tickets
      tools: [read_ticket, comment_ticket]
input:
  schema: schemas/input.schema.json
output:
  schema: schemas/output.schema.json
```

Rules the validator enforces, all fail-closed:

- Unknown fields are rejected everywhere (there are no namespaced
  extensions in v1).
- No secret is a legal value anywhere in a manifest: the schema has no
  field whose value is a credential, and the validator additionally refuses
  credential-shaped assignments in `runtime.command` and `instructions`. A
  manifest is a public, reviewable document.
- `instructions` is required for every runtime type. For `builtin-claude`
  the platform enforces it as the system prompt; for `container` it is
  delivered to the agent in the run context's input document — guidance the
  developer ships beside the agent, not a platform control.
- `runtime.type` is `container` or `builtin-claude`. Container runtimes
  require an immutable `image.digest` in governed mode (a tag alone is
  refused there) and must declare `interface.protocol`; builtin runtimes
  declare no `image`, `command`, `interface`, or `resources` — the platform
  owns the builtin runtime's packaging.
- `capabilities.tools` is a request list, non-authoritative by construction.
  Requests can be granted only against managed servers whose per-tool grants
  policy enumerates; passthrough servers are configuration
  (`extra_mcp_servers`), not authority requests.
- `interface.protocol` must name a protocol version the platform serves.

The authoritative machine-readable schema is
`andyur/agentspec/agent-manifest-v1.schema.json`, beside the parser in the
`andyur.agentspec` package (declared as package data so it ships in the
wheel). A repository test pins this document's example, the parser's field
sets, identifier and format patterns, numeric caps, and required-ness to that
schema, so the four cannot drift apart silently.

## 10. Conformance

An agent implementation is conforming when, run under the conformance gate
(`infra/byoa-spike/`):

1. It refuses (exits non-zero, no event stream) a context whose
   `protocol_version` it does not implement.
2. It completes a run using only `ANDYUR_RUNTIME_URL`/`ANDYUR_RUNTIME_TOKEN`
   and the context document — no other environment, no Andyur imports.
3. It performs a model call through `model_base_url` without sending a
   credential, and a granted MCP tool call through `mcp_url`.
4. It streams well-formed events and ends with exactly one `done` sentinel.
5. It stays within the advertised stream budgets.
6. Killed at an arbitrary point, it leaves the run failed-closed (the
   platform's job) and nothing dangling that outlives the workload (yours).

The platform side of the same gate proves the mirror image: no credential in
the context, environment, or filesystem; ungranted tools invisible and
refused; the alternate model refused; budgets enforced; a dead agent failing
the run closed.

## 11. Versioning

The protocol version string is `andyur-agent-runtime/<major>.<minor>` with
`/v1` meaning `1.0`. Minor versions only add optional context fields and
event capabilities; receivers ignore unknown fields. Anything that would
change the meaning of an existing field is a new major version, which is a
new context document an old agent will correctly refuse.

# ADR 003: separate tool and model egress

**Status:** Accepted 2026-08-08; runtime migration in progress.

## Decision

Andyur uses two deliberately different egress paths:

```text
untrusted agent
  | native MCP/HTTP, no credential
  v
per-run Andyur sidecar
  |-- tool request --> enterprise tool
  |      mTLS: run X509-SVID
  |      bearer: audience-scoped delegated token
  |      audience = manifest resource_id; route = manifest reach_url
  |
  `-- native Anthropic Messages/SSE --> shared LiteLLM --> model provider
         LiteLLM service key stays in the trusted sidecar
         provider key stays in LiteLLM
         model = immutable registry/context model
```

The per-run sidecar is Andyur code because it enforces Andyur facts: run
identity, the agent's ceiling and pin, immutable manifest bindings, lifecycle,
and credential isolation. LiteLLM is shared because provider routing, retries,
usage accounting, and model telemetry are fleet concerns.

agentgateway is not on either target data path. The per-run agentgateway tool
path and the Andyur ModelProxy/broker model path were transitional; both are
now removed. `infra/agentgateway/` is kept as measured historical research --
the security findings that shaped the sidecar (the unauthenticated admin
listener that dumped the run token, the `RUST_LOG=trace` policy leak) are why
the sidecar is built the way it is -- but nothing on any data path depends on
it, and no agentgateway binary is required to run Andyur.

**Migration: complete.** The per-run sidecar is the sole tool egress. The
`ANDYUR_TOOL_EGRESS` switch that once selected between it and agentgateway is
gone; the variable is read only to refuse a stale `agentgateway` value loudly
rather than silently ignore it. Both legs are proven live: the tool leg by the
SRE registry gate (`./run.sh sre-verify --full`), which now drives the full
reasoning run through the REAL external AS + IdP -- dana's real login, the
docker-attested run SVID as the RFC 8693 actor, the sealed OpenBao vault for the
model credential, and the tool PEPs accepting only AS-issued tokens -- and the
isolated external-AS exchange by `./run.sh actor-leg-verify`. The
model leg rides the sidecar's `/llm` to the shared LiteLLM gateway; no Andyur
broker process remains on the demo path.

## Boundaries

- The agent receives loopback URLs, never a provider key, LiteLLM service key,
  delegated tool token, run token, subject token, or SVID.
- A tool's `resource_id` is authorization identity. Its `reach_url` is routing.
  Neither is derived from the other.
- The sidecar strips caller credentials and identity headers before setting its
  own egress credentials.
- The sidecar refuses a missing, malformed, or different LLM model before any
  upstream bytes. It does not silently substitute a default.
- Native Anthropic Messages/SSE and W3C trace context cross the sidecar and
  LiteLLM unchanged. No Andyur protocol adapter sits in front of LiteLLM.
- Tool and model responses stream with cancellation and backpressure. Clients
  and connection pools live exactly as long as the run sidecar.
- Destroying the run sidecar structurally removes both egress paths.

## Replaceability without an adapter framework

LiteLLM is the one selected model gateway. Andyur does not define a Python
`LLMGateway` interface, generate competing vendor configurations, or call
LiteLLM administration APIs from runner code. Natural wire boundaries preserve
a future replacement option: configured base URL, native provider protocol,
opaque manifest model, W3C trace context, and OTLP GenAI telemetry. A second
implementation will justify an abstraction if and when one is actually needed.

## Verification bar

The migration is complete only when the real SRE demo proves:

1. tool calls traverse the per-run Andyur sidecar and never agentgateway;
2. model calls traverse the same sidecar and shared LiteLLM, with the manifest
   model visible in a joined distributed trace;
3. alternate/missing models are refused before LiteLLM;
4. agent environment, transcript, logs, and OTLP contain no credentials;
5. cross-audience tool use and post-run tool/model reuse fail;
6. request and response streaming are observed before upstream completion; and
7. no legacy ModelProxy/broker or workspace-tool fallback is used.

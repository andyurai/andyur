# Shared LLM gateway

Andyur uses one shared LiteLLM service for model calls. This component does not
proxy MCP or enterprise-tool traffic; those calls use the per-run Andyur
sidecar. The separation is intentional:

```text
agent -> per-run Andyur sidecar -> shared LiteLLM -> model provider
agent -> per-run Andyur sidecar -> enterprise tools
```

This is a deployment choice, not an Andyur adapter interface. The runtime speaks
the provider's native wire protocol. Claude Code sends Anthropic Messages/SSE to
`/v1/messages`; LiteLLM maps the manifest-selected public model to the provider.
There are no LiteLLM imports or admin request models in runner code.

The image is pinned to LiteLLM 1.95.0 by multi-architecture manifest digest in
`infra/docker-compose.yml`. Provider credentials exist only in the shared
gateway. LiteLLM's master key is a service credential, not Andyur run authority.
The runner integration contract requires the trusted per-run sidecar to hold it,
enforce the immutable manifest-selected model, and expose only a loopback
listener to its agent. The agent must receive neither the master key nor
`ANTHROPIC_API_KEY`; destroying the sidecar removes its route to LiteLLM. That
runner/sidecar handoff is owned by the concurrent sidecar migration and is not
implemented by this deployment-only change. We are deliberately not adding a
second broker or a virtual-key control plane in this phase.

Start the local service with:

```bash
export ANTHROPIC_API_KEY=...
export LITELLM_MASTER_KEY="$(openssl rand -hex 32)"
docker compose -f infra/docker-compose.yml --profile llm up -d litellm
```

The service listens on `http://localhost:4000`. Its OTLP spans go to Jaeger at
`http://jaeger:4318`; request and response bodies are excluded by default.
The agent manifest remains the only Andyur source for the model name.

Run the real Claude CLI/provider conformance check with:

```bash
ANTHROPIC_API_KEY=... infra/litellm/verify.sh
```

This test-only verifier uses an isolated Compose project and gives its disposable
Claude process the disposable test gateway key directly; that is not the
production credential handoff described above. It fails if the pinned image stops
accepting Claude Code's native `/v1/messages` stream or if the public model alias
no longer reaches Anthropic.

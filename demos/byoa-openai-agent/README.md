# byoa-openai-agent

A conforming Andyur agent built on the **OpenAI Agents SDK**, with **zero
Andyur imports**. The second independent framework in the ADR-008 acceptance
proof (two frameworks, one conformance/security suite).

It uses:
- `openai-agents` (the `agents` package: the `Agent` + `Runner` loop and its
  `agents.mcp` MCP client),
- `openai` (the `AsyncOpenAI` model client, pointed at the context's
  `model_base_url` + `/v1`),
- `httpx` (the `/v1` runtime-protocol calls).

It disables the SDK's tracing exporter (a confined BYOA agent has no egress or
key for it), attaches the granted MCP tools via `MCPServerStreamableHttp`,
sends a throwaway model key (the proxy injects the real one), and speaks
`andyur-agent-runtime/v1`. Its `requirements.txt` installs the OpenAI SDK and
not `andyur`.

Exercised by `infra/byoa-spike/framework_gate.py`. Build:

```sh
docker build -t byoa-openai-agent demos/byoa-openai-agent
```

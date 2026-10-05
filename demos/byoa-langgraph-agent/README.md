# byoa-langgraph-agent

A conforming Andyur agent built on **LangGraph**, with **zero Andyur imports**.
Part of the ADR-008 acceptance proof that Andyur is a runtime, not a framework:
a real LangGraph ReAct agent runs under Andyur's identity/authz/credential/
lifecycle controls without depending on any Andyur package.

It uses:
- `langgraph` (the graph / ReAct loop),
- `langchain-openai` (the model client, pointed at the context's
  `model_base_url` + `/v1` — Andyur's OpenAI-compatible proxy surface),
- `langchain-mcp-adapters` (LangChain's own MCP client, for the granted
  tools at `mcp_url`),
- `httpx` (the `/v1` runtime-protocol calls).

The agent sends a throwaway model key — the platform proxy injects the real
credential the agent never holds — and speaks `andyur-agent-runtime/v1`:
`GET /v1/context`, run the graph, stream neutral events to `POST /v1/events`,
end with `done`. Its `requirements.txt` is the proof by absence: framework
packages, no `andyur`.

Exercised by `infra/byoa-spike/framework_gate.py` against the real
`AgentChannel` / `ModelProxy` / MCP transport. Build:

```sh
docker build -t byoa-langgraph-agent demos/byoa-langgraph-agent
```

# byoa-hello-agent

The reference implementation of `andyur-agent-runtime/v1`
(`docs/agent-runtime-protocol-v1.md`): a complete, conforming Andyur agent in
one Python file with **zero Andyur imports and zero third-party
dependencies**. It exists to prove by running that a third-party agent needs
nothing from Andyur — no SDK, no package, no credential — to run under
Andyur's identity, authorization, and lifecycle controls.

What it does, which is the whole v1 lifecycle:

1. Reads `ANDYUR_RUNTIME_URL` / `ANDYUR_RUNTIME_TOKEN` — the only environment
   the contract promises.
2. Fetches `GET /v1/context`, retrying connection failures while the sidecar
   comes up. If the `protocol_version` is not one it implements, it exits
   with code 3 **without opening an event stream** — a conforming refusal is
   silent on the wire.
3. Calls the model through `services.model_base_url`, sending no credential.
4. Makes one granted MCP tool call through `services.mcp_url` — a real
   streamable-HTTP MCP handshake (initialize → initialized → tools/list →
   tools/call) hand-rolled over JSON-RPC in ~40 lines, no MCP SDK.
5. Streams events to `POST /v1/events` as chunked NDJSON while it works,
   ending with the `done` sentinel. Failures become the sentinel's `error`;
   the platform always learns why a run ended.

It streams incrementally because that is the idiomatic shape; buffering all
events and posting once is equally conforming. The `model` name it sends is a
placeholder — the platform enforces the effective model from the approved
resolution regardless of what any agent asks for.

## Running it

The agent is exercised by the fast-lane conformance tests
(`tests/test_byoa_protocol_conformance.py`) and, containerized, by the live
gate (`infra/byoa-spike/`). Both stand up the real platform components
(`AgentChannel`, `ModelProxy`, the real MCP transport) and run this agent
against them. CI asserts the import tree stays standard-library only.

To containerize:

```sh
docker build -t byoa-hello-agent demos/byoa-hello-agent
```

The image installs nothing; the Dockerfile's empty dependency step *is* part
of the proof.

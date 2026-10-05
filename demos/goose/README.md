# Goose on Andyur exec/v1 -- the second stock workload

Block's [Goose](https://github.com/block/goose) (`ghcr.io/block/goose`, 1.30.0,
digest-pinned in `agent.json`) runs on the exec/v1 stock-process contract with
NO change to the platform: this directory is a manifest, a policy input, a task
input and a rendered configuration file -- the same shape as `demos/opensre/`.

- **Input** arrives on stdin (`goose run -i -`): the platform delivers
  `input.json`'s canonical bytes; goose reads them as its instructions.
- **Model**: goose's OpenAI-compatible provider, `OPENAI_HOST` resolved from
  `services.model.base_url` (the run's front on the proxy Pod, which pins the
  granted model and refuses everything else) and `GOOSE_MODEL` from
  `services.model.name`. `OPENAI_API_KEY=andyur-front` is NOT a credential:
  the front drops `Authorization` before the model leg and the key means
  nothing to it; goose merely requires the variable to exist. The
  conformance gate's E4 scans literals in env for the run's real secrets --
  this value is not one of them, by design.
- **Tools**: goose's `streamable_http` MCP extension, configured through the
  rendered `~/.config/goose/config.yaml` (`configuration.files`), points at
  `services.tools.mcp_url` and sends `services.tools.mcp_headers.Authorization`
  -- the dedicated per-run bearer -- on every request. Goose's CLI flag
  `--with-streamable-http-extension` takes a URL only, so the file is the
  binding. Whether the model then CALLS a tool is the model's decision:
  the handshake (initialize, initialized, tools/list) is required and
  authenticated; a `tools/call` is observed if it happens (E3b).
- **Scratch**: goose keeps its config, session state and logs under `HOME`
  (`workspace.home`, writable as the workload uid -- E7).

Reproduce: `andyur agents conformance demos/goose/agent.json --evidence <new.json>
--input demos/goose/input.json` (Docker Desktop's context), then governed
publication with the evidence, then `infra/kubernetes/verify-exec-workload.sh`
for the in-cluster run. Plan and findings boundary: `docs/adr-011-exec-v1-stock-process-contract.md`.

# Hermes Agent on Andyur exec/v1 -- the third stock workload

Nous Research's [Hermes Agent](https://github.com/NousResearch/hermes-agent)
(`docker.io/nousresearch/hermes-agent`, v2026.9.11, digest-pinned in
`agent.json`) runs on the exec/v1 stock-process contract with NO change to the
platform: this directory is a manifest, a policy input, a task input and a
rendered configuration file -- the same shape as `demos/goose/` and
`demos/opensre/`.

- **Input** arrives on stdin (`hermes chat --query-file -`). A non-TTY stdin
  implies single-query mode: hermes answers once and exits.
- **Model**: hermes's `custom` provider, `base_url` resolved from
  `services.model.openai_base_url` (the run's front, which pins the granted
  model and refuses everything else) and `default` from `services.model.name`.
  `api_key: andyur-front` is NOT a credential: the front drops `Authorization`
  before the model leg. Hermes streams by default, and the front forwards
  streamed calls.
- **Tools**: one entry under `mcp_servers`, `andyur`, pointing at
  `services.tools.mcp_url` with `services.tools.mcp_headers.Authorization` as
  its header, rendered into `$HERMES_HOME/config.yaml`. `--toolsets andyur`
  gives hermes that server's tools and none of its built-in toolsets --
  no terminal, file, browser or web tools.
- **Scratch**: `HOME` and `HERMES_HOME` are `workspace.home`. Hermes keeps its
  config, session database and logs there.

## Four things about this image that are not obvious

1. **The command names the venv binary by absolute path**
   (`/opt/hermes/.venv/bin/hermes`). The image's entrypoint starts as root
   under s6-overlay and refuses any uid other than 0 or its own 10000, and
   the `hermes` on its PATH is a shim that tries to drop privileges the same
   way. The agent Pod runs as uid 1001 with a read-only root filesystem, so
   both are bypassed.
2. **HERMES_HOME is overridden** because the image sets it to `/opt/data`,
   which is on that read-only root filesystem.
3. **The granted model is `gemma4-andyur`, not `qwen3-andyur`.** Hermes
   refuses a context window below 64,000 tokens outright. `qwen3-andyur` is
   served at 32,768, and its base model declares 40,960, so raising it would
   be a window the model was not trained for. `gemma4-andyur` is `gemma4:31b`
   (native window 262,144) served at 65,536:

   ```bash
   printf 'FROM gemma4:31b\nPARAMETER num_ctx 65536\n' > Modelfile
   ollama create gemma4-andyur -f Modelfile
   ```

   `context_length: 65536` in the rendered config states that window, so
   hermes does not ask the endpoint how large it is. It still probes the
   endpoint at startup to work out what kind of server it is
   (`/api/v1/models`, `/api/tags`, `/v1/props`, `/props`, `/version`, then a
   `/v1/models` listing). The front refuses every one of them with a 404, and
   the run's trace records them as refused `execfront GET` spans. That is the
   pin working, not a fault: none of those paths is a model call.
4. **Not `-z`, and not `-Q`.** One-shot `-z` sets `HERMES_YOLO_MODE=1` and
   bypasses command approval; single-query mode keeps
   `approvals.single_query_mode`, which defaults to `deny`. Quiet `-Q` prints
   only the final answer, which is too short for the conformance gate to show
   output truncation (E5b); without it hermes prints the query label, the
   answer and an exit summary, and no banner.

The rendered config also turns off hermes's passive update check (a GitHub API
call the network policy refuses anyway), its memory and user-profile stores,
and its shared telemetry, which is off by default.

## The agent asks: `rollback-input.json`

The second input gives Hermes an incident and one action to take: call the
platform's `request_rollback` tool, which Hermes presents to its model as
`mcp__andyur__request_rollback`. `infra/kubernetes/verify-hermes-requested-action.sh`
runs the same gate Goose's rollback runs, with this demo as its data:

- a disposable Deployment with two revisions, in a namespace the gate owns;
- the run triggered with `files:read` and `deployments:rollback`, pinned to that
  Deployment, the model reading its target from the prompt and the platform
  reading it from the signed grant;
- the tool call made BY HERMES over MCP, never by the gate, which holds only an
  operator credential and which `POST /runs/{id}/actions` refuses outright;
- the platform's decision (`allowed`, `write_authorized`) recorded as a row and as
  an `action.decide` span, and the API server's own view of the pod template
  moving back a revision.

Hermes then reports what the tool answered and ends with
`ROLLBACK REQUESTED`. Evidence:
`infra/kubernetes/result-agent-requested-action-hermes-*.json`.

Reproduce: `andyur agents conformance demos/hermes/agent.json --evidence <new.json>
--input demos/hermes/input.json`, then governed publication with the evidence
and `--approved-model gemma4-andyur:latest`, then
`infra/kubernetes/verify-exec-hermes.sh` for the in-cluster run. Plan and
findings boundary: `docs/adr-011-exec-v1-stock-process-contract.md`.

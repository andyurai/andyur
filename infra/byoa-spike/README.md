# byoa-spike — the runtime-v1 conformance gate (ADR-008, phase C1)

Disposable evidence machinery for the BYOA runtime contract
(`docs/agent-runtime-protocol-v1.md`). It runs the containerized reference
agent (`demos/byoa-hello-agent/`, zero Andyur imports, zero dependencies)
against the **real** platform components on this machine and records dated
evidence JSON.

```sh
./verify-byoa.sh         # the stdlib reference agent: proves the contract's
                         # CONTROLS (limits, refusal, kill, secret absence)
./verify-frameworks.sh   # real LangGraph + OpenAI Agents SDK agents: proves
                         # two independent frameworks pass the same suite
```

`verify-byoa.sh` builds `byoa-hello-agent:gate`; `verify-frameworks.sh` builds
`byoa-langgraph-agent:gate` and `byoa-openai-agent:gate` (each pip-installs its
framework, so the first run needs network and takes a few minutes). Images are
left on the machine (rebuilt each run); remove with
`docker rmi byoa-hello-agent:gate byoa-langgraph-agent:gate byoa-openai-agent:gate`.
Run containers are always cleaned up, pass or fail.

The two gates are complementary. The stdlib gate uses the minimal agent to
exercise the platform's controls precisely (a real framework would obscure a
budget or kill test in its own machinery). The framework gate uses unmodified
real frameworks to prove the different thing: that they work under the
identical controls, each with its own model client and MCP client and no
`andyur` in the image.

## What is real and what is a double

Real, and the thing under test:

- `andyur.runner.agentchannel.AgentChannel` — authorization, sanitize on
  receipt, stream budgets, done semantics
- `andyur.runner.modelproxy.ModelProxy` — credential injection on the
  outbound model leg
- the MCP streamable-HTTP transport (the real MCP SDK session manager)
- a real OCI container, digest-pinned base, launched with the daemon's
  subtraction: cap-drop ALL, no-new-privileges, read-only rootfs,
  unprivileged uid, no mounts, exactly two environment variables

Labeled test doubles (in `runtime_v1.py`), never security decision points:

- the upstream model gateway (records what authorization it received; holds
  the canary)
- the MCP tool server behind the real transport (an `echo` tool)
- the `/v1` path shim, which maps the public route names onto the channel's
  current internal paths and adds nothing — it dies when the production
  channel adopts the v1 names (ADR-008 C2)

Secret absence is proven **by value**: a canary gateway key must arrive at
the stub gateway (the proxy injected it) and must never appear in the
context document, the container environment, or anything the agent emitted.

## Checks

| # | Property | Positive control |
|---|---|---|
| G1 | containerized round trip: context → model → granted tool → events → result → done | is itself the positive control for G3/G4/G6 |
| G2 | launch config is the subtraction: exactly the two contract env vars, no host mounts, read-only rootfs, all capabilities dropped, unprivileged uid, and exactly the two ephemeral scratch paths the contract promises (`/tmp`, `/home/agent`) — inspected under the governed command | image builds and runs in G1 |
| G3 | workload fetches a v99 context, then refuses it: non-zero exit, no stream, nothing on the wire | G1, plus the context fetch itself |
| G4 | over-budget stream refused at the enforcement point, run failed closed | in-budget stream accepted |
| G5 | no Python in the image can import `andyur`: `python`, `python3`, and every Python interpreter the governed command names (including one wrapped in a shell) are all probed | the same interpreter imports the stdlib. Absence is concluded only when docker reports no such executable; a probe that failed for any other reason is inconclusive and FAILS, so an unanswered question never certifies an image |
| G6 | killed agent fails the run closed (synthesized failure done) | G1 |

Scope, honestly: per-tool authority filtering (`tools/list` vs `tools/call`)
is the data-plane gateway's control with its own Slice 2b evidence; image
signature/digest **admission** is the C2 governed-registry extension. This
gate proves the runtime contract, not those neighbors.

## Running it against a governed image

`./verify-byoa.sh` builds and tests the local reference agent. To certify a
governed image instead, run it through the CLI, which sets the environment for
you and validates the artifact it produces:

```
andyur agents conformance path/to/agent.json --evidence result.json
```

The gate reads exactly three variables, all set by that command:

| Variable | Meaning |
|---|---|
| `ANDYUR_CONFORMANCE_IMAGE` | pull and test this digest-pinned image instead of building the reference agent |
| `ANDYUR_CONFORMANCE_COMMAND` | JSON array: the manifest command to run in that image, replacing its entrypoint exactly as the production Pod does. Required whenever the image is set — evidence for a command production will not run proves nothing |
| `ANDYUR_CONFORMANCE_EVIDENCE` | write the artifact here, refusing to overwrite an existing one |

A misconfiguration (an image with no command) exits **2** with a `[gate]`
message, distinct from **1**, which means the gate ran and something was RED.
Nothing else in the environment changes what the gate proves: the channel
budgets G4 exercises are assigned by the gate, not inherited.

The artifact records the sha256 of `byoa_gate.py` and `runtime_v1.py`.
`andyur agents package --publish-ref` recomputes those from the gate sources
and refuses evidence that does not match, so evidence from an older or edited
gate cannot sign a snapshot. Because the gate ships only in the source tree,
publishing from an installed package needs `--conformance-gate-dir`.

G5's known limit, deferred deliberately rather than overlooked: an interpreter
reached under a name that does not look like Python is still not probed, so a
wrapper script inside the image or a renamed binary can hide one. That is a
redesign, not a one-line fix, and it must land before any marketplace or
untrusted-publisher scope opens.

Content binding answers "which gate produced this?", never "who produced it?":
the digests it compares are of files any reader can hash. If you need the
second question answered — before opening publication to anyone but the
operator — sign the artifact and require the signature:

```
andyur agents conformance agent.json --evidence result.json \
  --sign-evidence cosign.key --disable-transparency-log
andyur agents package ... --conformance-evidence result.json \
  --conformance-key cosign.pub
```

Both flags are optional and off by default, so the getting-started path needs
no keys. Signing writes a Sigstore bundle beside the artifact and needs cosign
v3 or newer; `--disable-transparency-log` keeps the artifact's hash off the
public log, and without it cosign publishes that hash.

## Findings this gate has produced

- 2026-08-21: conformance ran the image's own entrypoint and never the
  governed manifest `command`, so a manifest could publish on evidence that
  never touched the workload it declares. Proven by running the pre-change
  gate from git against an image whose manifest command scores 5/11: it
  returned 11/11. The gate now substitutes the command as the Pod does.
- 2026-08-21: the command words were split on whitespace, so the party the
  check polices could switch it off by QUOTING: `exec '/venv/bin/python'
  agent.py` yields a word whose basename is `python'`, matching no
  interpreter, so the venv was never probed and the verdict fell back to
  PATH's clean python. Proven against an image hiding andyur in exactly that
  venv: the pre-fix gate returned PASS, the fixed gate returns FAIL
  ("/venv/bin/python: import andyur exit=0 IMPORTABLE"). Ruled RC0 by the
  freeze owner, because the untrusted party supplies the command (adr-008
  D-206) and a gate its own subject can disable reports PASS for precisely the
  images it exists to catch.
  The fix unions BOTH tokenizers instead of swapping one for the other, and
  that mattered: parsing shell words alone consumes backslashes, so a real
  interpreter at `/opt/we\ird/python3` resolves to a path that does not exist
  and probes as absent. A quoting bypass traded for an escaping one is not a
  fix. Dedupe is first-seen ordered rather than a set, because probe order is
  recorded in the evidence artifact and set iteration order varies between
  processes, which would make two identical runs write different artifacts.
- 2026-08-21: G5 probed only `python` on `PATH`, so an image whose governed
  command names its own interpreter (`["/venv/bin/python", "/app/agent.py"]`)
  could carry andyur inside that venv and pass. Proven with an image built
  exactly that way: PATH-only probe PASS, command-interpreter probe FAIL
  ("IMPORTABLE"). A command may also hide the interpreter inside a shell
  (`["/bin/sh","-c","exec /venv/bin/python /app/agent.py"]`), so every word of
  the command is considered, not just its first argument.
- 2026-08-21: the gate's scratch space was mounted `noexec` while a Kubernetes
  emptyDir is exec-capable. Measured: `cp /bin/echo /tmp/e && /tmp/e` is
  "Permission denied" under Docker's default `--tmpfs` and succeeds with
  `:exec`. An agent that unpacks and runs something from its own scratch space
  would have gone red here and worked in production.
- 2026-08-21: the gate asserted ZERO mounts while the production Pod grants
  `/home/agent` and `/tmp` emptyDirs and section 8 of the spec promises the
  agent "its own scratch space". The gate was stricter than the cluster, so an
  agent using the scratch space it is entitled to could go red here and run
  fine in production. The gate now grants and asserts exactly those two paths.
- 2026-08-21: G5 probed only the name `python` and treated any non-zero exit
  as "no Python here, not applicable". Debian, Ubuntu and Alpine ship `python3`
  with no `python` alias, so a distro-based image with andyur installed was
  waved through. Proven with a debian:12-slim image carrying andyur under
  python3: pre-fix PASS ("no usable python entrypoint"), post-fix FAIL
  ("python3: import andyur exit=0 IMPORTABLE"). It now probes both names and
  fails closed when a probe does not answer (exit 126/125), rather than
  reading any failure as proof of absence.- 2026-08-21: two checks still launched the image default after the command
  substitution landed. G2 created its inspection container without it, so an
  image with no ENTRYPOINT or CMD — which is what an image built FOR governed
  launch looks like — failed `docker create` with "no command specified". G5
  failed any image without Python on exit 127 rather than treating the Python
  import probe as inapplicable, which made every Go, Rust or Node agent
  unpublishable. Both proven against a busybox image carrying neither.
- 2026-08-21: G3's refusal check ("exited non-zero, stayed silent") was also
  satisfied by a container that never started. It now requires the context
  fetch first, so the workload must run and then refuse. A live workload
  exiting non-zero without fetching turns it red.
- 2026-08-15: the channel's per-line budget is bypassed by a complete
  oversized line arriving inside one ASGI receive chunk (the cap is checked
  on the residual buffer only). Bounded by the whole-stream budget; handed
  to the session owning `agentchannel.py` with a repro (see
  `.session-sync.md`). G4 asserts the stream budget, which enforces
  reliably at any chunk boundary.

## exec_v1_gate.py — the exec/v1 conformance gate (ADR-011 D8)

The sibling gate for stock workloads that speak no protocol at all. It is
selected automatically by `andyur agents conformance` when the manifest's
interface is `exec/v1`, launches the manifest's exact image + command with the
process/configuration blocks resolved through the real parser and resolver,
and stands in for the run's proxy Pod (`/llm/*` model path, `/mcp` boundary).
Checks E1–E7 and the evidence contract are described in the script's
docstring. Evidence records `exec_gate_sha256` (this script) and
`manifest_sha256` (checked by the RC currency checker), and the publisher binds
what it seals to what the gate proved: image digest, command, interface, input
mode and the granted model, and refuses runtime-v1 evidence for an exec/v1
runtime. Run it from Docker Desktop's context (the harness is reached via
`host.docker.internal`):

```sh
andyur agents conformance demos/opensre/agent.json \
  --evidence demos/opensre/evidence/result-exec-v1-<date>-<os>-<arch>.json \
  --input demos/opensre/alert.json
```

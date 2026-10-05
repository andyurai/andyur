# SOC bundle

Three security-operations agents you can install into Andyur. Each is one
`andyur.agent-resolution/v1` file carrying its own instructions, tool bindings,
authority ceiling, and card.

## Install

A bundle is a subdirectory of the agent registry. Point Andyur at the directory
that *contains* the bundles, not at the bundle itself:

```sh
andyur bundle install demos/bundles/soc
andyur registry list
andyur agents create my-triage --registry-agent-id agt_soc_triage
```

The ceiling comes from the bundle, so `--scope` is ignored on a registry
launch. That is the point: the reviewed authority is the one that binds.

## The three agents

| Agent | Ceiling | Reaches |
|---|---|---|
| `soc-exposure` | `vulns:read` | OSV MCP `:8810` |
| `soc-triage` | `cases:read`, `alerts:read` | TheHive MCP `:8812`, Wazuh MCP `:8811` |
| `soc-response` | `cases:read`, `cases:write`, **`deployments:rollback:with-approval`** | TheHive MCP `:8812` |

**`soc-exposure`** looks up the packages you name, at their exact versions, and
reports the advisories against them and the earliest version that fixes each.
It runs with no backend of its own — OSV MCP queries a public API — so it is
the one to start with.

**`soc-triage`** reads the alert from the case system, then builds context
around it: the current alert picture, what the rule that fired asserts, and what
the host was doing (processes, ports, whether its agent still reports). It
answers TRUE POSITIVE / FALSE POSITIVE / NEEDS A HUMAN with the single piece of
evidence that decided it. It cannot change anything.

**`soc-response`** decides whether to roll a deployment back, requests it, waits
for a human to approve or refuse, and records the outcome on the case. It is
the only agent here that can change anything, and the one to run if you want to
see the platform rather than the agents.

## Prerequisites, in detail

The ports are this bundle's convention. What is *not* convention is the
transport — two of these three servers speak stdio, and Andyur binds tools over
HTTP:

- **`StacklokLabs/osv-mcp`** (Apache-2.0) on `:8810`. Natively HTTP, but it
  defaults to SSE on port 8080, so run it with `MCP_TRANSPORT=streamable-http`
  and `MCP_PORT=8810`.
- **`gbrigandi/mcp-server-wazuh`** (MIT) on `:8811`, plus a Wazuh deployment
  behind it. It speaks **stdio** unless built with `--features http`; otherwise
  front it with `sparfenyuk/mcp-proxy` (MIT), which bridges stdio to streamable
  HTTP.
- **`gbrigandi/mcp-server-thehive`** (MIT) on `:8812`, plus TheHive behind it.
  **stdio only** — it needs the proxy.

`soc-response` additionally needs **an approver**: its rollback is gated, and
the run waits for a decision.

The conditional grant is the enforcement boundary; instructions to ask a human
are not authorization. Do not also grant `deployments:rollback`: that is the
unconditional permission and takes precedence. Inspect `action.decide` with
`andyur.action_decision=approval_required` and
`andyur.action_reason=approval_policy`; no `action.perform` should exist until
approval. The resulting action row records the approver and observed outcome.

### Running soc-triage without a SIEM

`fixtures/wazuh.recorded.json` holds real responses captured from
`gbrigandi/mcp-server-wazuh` v0.3.0, driven over stdio against a real
`wazuh-docker` single-node v4.14.0, with alerts produced by Wazuh's own ruleset.
Serve them instead of standing Wazuh up:

```sh
python demos/bundles/soc/replay_wazuh.py --port 8811
```

It is **recorded, not simulated**, and that distinction is the point: payloads
written by hand would pass against agents also written by hand and prove
nothing. It is honest about its limits — it serves only the five tools it has
recordings for, it ignores your arguments and returns the one recorded response
every time, and it says both of those things in every tool description, so the
model reading them cannot believe it filtered by an `agent_id` it did not.

What it demonstrates is the **platform**: the ceilings, the request, the
approval, the audit trail. It demonstrates nothing about whether the live Wazuh
integration works — for that, run the real server.

The rollback itself needs nothing installed. `request_rollback` is a *platform*
tool, served by the run's own tool service, which is why it appears in a ceiling
with no tool binding.

## Running it

Use the deployment shape the other registry agents already run under: a
dev-profile control plane with `ANDYUR_AGENT_AUTH=on` and containerised runs.
`infra/spire/docker/verify-sre-registry.sh` (`./run.sh sre-demo`) builds exactly
that and is the reference to copy -- real server and runner images, per-run
container SVIDs, and `ANDYUR_LLM=ollama` by default or `api` with an
`ANTHROPIC_API_KEY`.

That is why these `reach_url`s name the host gateway over plain http, the same
as `demos/agent-registry/oncall-ollama.json`: under the dev profile the runner
rewrites host-local URLs to `host.docker.internal`, and the tool servers run on
your machine.

### If you run a production profile instead

Two things change, and neither is a defect:

* Plaintext `http` reach_urls are refused -- the sidecar attaches the run's
  delegated token to that hop.
* Runs sit on an internal network with no route to the host, so a tool server
  must be a service ON that network, addressed by name.

`tls_front.py` and `serve-tools.sh` exist for that case: the front holds an
X509-SVID so the tool server can present one, because the runner verifies
against the SPIFFE trust bundle and would refuse a public-CA or self-signed
certificate just as firmly as it refuses http. They are **not** needed for the
dev-profile path above.

## Three decisions worth knowing

**Each agent carries its own ceiling, and only one of the three can change
anything.** A triage agent talked into recommending a rollback still cannot
perform one — it holds no authority to exercise, whatever its prompt was
persuaded to say. `tests/test_soc_bundle.py` asserts this by name.

**Every granted tool name was read off its server's own documentation.** An
earlier version of this bundle invented them, and every one validated cleanly:
the registry checks a grant against the agent's ceiling and cannot know whether
a remote server has a tool by that name. It would have failed on the first tool
call. The test suite now pins each name against a published inventory.

**A bundle declares what it needs and never starts it.** `card.requires` is
prose for a person to provision against; nothing in the platform consumes those
strings. A bundle is a file installed from elsewhere, and one that could
describe a process to launch would be arbitrary code execution against the
component whose whole job is deciding what may run.

## What was dropped, and why

Hunt, search and malware-analysis agents were written and then removed, because
the servers they needed do not exist:

- **No Sigma MCP server** and **no usably-licensed MITRE ATT&CK MCP server**
  exist, which left the hunt agent without a rule corpus.
- **Cortex's MCP server analyses observables only** — IPs, domains, URLs,
  emails. It has no file analysis and no detonation, so a malware agent that
  does static analysis, sandboxes a sample and writes a YARA rule had no
  backing at all.
- The search agent overlapped triage once it turned out Wazuh's MCP offers
  fixed summaries and a manager-log search rather than a general query tool.

They are worth building when the servers exist, or when someone writes thin
adapters over `yara-python`, `flare-capa` and `pysigma` — all of which are on
PyPI. Shipping them now would have meant shipping agents that cannot run.

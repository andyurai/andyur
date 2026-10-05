# Contributing to Andyur

Andyur is in pre-release. Until the first public release the process below is
provisional, but it is the bar the codebase is already held to.

## Development setup

```bash
./run.sh setup          # creates .venv and installs requirements
./run.sh test           # full test suite (fast tests need no infrastructure)
```

Or as an installable package:

```bash
pip install -e ".[dev]"
pytest
```

Some integration suites need local infrastructure and skip themselves when it
is absent (the skip reason names what to start): SPIRE for identity tests
(`./run.sh spire-setup`, `spire-server`, `spire-agent`), Docker for the
containerized gates (`./run.sh spire-docker up`), and an Ollama or Anthropic
model for the end-to-end demos (`./run.sh sre-demo`).

## The bar for changes

- **Fix causes, not symptoms.** If a fix needs a special case bolted on, the
  design is wrong; change the design.
- **Every bug fix carries a regression test that CI runs**, and the test must
  actually fail when the bug is reintroduced (mutation-check it: inject the
  bug, watch the test go red, restore, watch it go green).
- **Refusal tests need positive controls.** A refusal alone proves nothing
  when a broken server refuses everything. Test in the configuration where
  the control is active.
- **Documentation must be true.** READMEs and docs describe what the code
  does today, not what it will do; if your change makes a doc false, the doc
  change belongs in the same commit.
- **No temporary code.** Nothing ships with "TODO", "for now", or a stand-in
  left beside its replacement. One source of truth for every fact.
- **Comments explain why, not what.** Match the idiom of the surrounding
  code.

## Tests that pass alone and fail in the suite

Two suites call `importlib.reload(config)`, which rebinds that module's classes.
A test that captures an exception class at module import time holds the stale
one and stops matching, while source modules resolving it per call raise the new
one. Resolve such classes inside the test body. The full explanation, with the
right and wrong forms, is at the top of `tests/conftest.py`.

## Invariants a change may not break

These hold across the platform. A change that makes one false is wrong even if
it passes review on its own merits, so check your diff against them before
submitting. `CONCEPTS.md` explains the model they protect.

1. No OSS project name becomes a runtime type, an authority semantic, a
   credential path or a lifecycle mode. Support a workload with manifest and
   config, never with a branded code path.
2. A manifest is a request. Policy and the compiler own the approved definition,
   and the intersection can only narrow.
3. Effective run authority stays server-owned. A caller may not supply its own
   ceiling; `authority_for()` reads it from the registry instead.
4. Enforcement points enforce a precomputed decision rather than reconstructing
   it. Many enforcement points are fine; a second place that decides is not.
5. `tools/list` and `tools/call` are backed by the same permitted-tool decision,
   so the menu an agent is shown never exceeds the calls it may make.
6. An enumerated MCP binding keeps a closed method vocabulary. Every method
   reaches the same upstream over the same credential, so an open vocabulary is
   a side door around the reviewed grant.
7. `exec/v1` stays a small stock-process contract. Security-sensitive capability
   lives outside the process, at an Andyur boundary.
8. Downstream credentials stay outside the workload. If Andyur can hold it
   behind a governed boundary, the workload does not get it.
9. Conformance evidence is bound to the exact executable and configuration that
   ran. Evidence that outlives its source is not evidence.
10. A new high-level abstraction waits for a real second workload or protocol.
    One instance is not a pattern.

## Security-relevant changes

Anything touching identity, token exchange, delegation, sandboxing, or egress
gets adversarial review: assume the untrusted component is fully compromised
and try to refute your own change before submitting it. Vulnerability reports
go to security@andyur.ai (see SECURITY.md), not the issue tracker.

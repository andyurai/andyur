# Changelog

Notable changes to Andyur. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is semver
with the 0.x caveat that **minor releases may break compatibility**, and a
release that does will say so here explicitly.

Entries describe what changed for someone *using* Andyur. The reasoning behind a
change lives in its commit message and, where it was a decision, in an ADR under
[`docs/`](docs/README.md).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-10-05

The first public release. See [`ROADMAP.md`](ROADMAP.md) for what is built, what
the known limits are, and what is next. The entries below are relative to the
private development tree, so "changed" and "fixed" describe how this release
differs from what its early users ran, not from an earlier public version.

### Added
- `ROADMAP.md`: what is built and verified, the known limits as a table, what is
  next, and what is deliberately not planned.
- [`docs/threat-model.md`](docs/threat-model.md): the adversary model, the
  boundaries, what the controls assume, and the residual risks.
- [`docs/README.md`](docs/README.md): an index for the documentation.
- `SUPPORT.md` and `CODE_OF_CONDUCT.md`.
- [`demos/hermes/`](demos/hermes/README.md): Nous Research's Hermes Agent as a
  third stock `exec/v1` workload, with no platform change. It needs a model
  served with at least a 64K-token context window; the demo uses
  `gemma4-andyur` (`gemma4:31b` at 65,536). Its rollback scenario has Hermes
  request a consequential action through the platform's MCP tool service,
  which the platform decides and performs
  (`infra/kubernetes/verify-hermes-requested-action.sh`).
- `./run.sh spire-fetch` and `./run.sh spire-build`: SPIRE is pinned at 1.11.2
  and acquired for you. Upstream publishes no macOS binaries, so `spire-build`
  builds the pinned tag from source there.

### Changed
- **Releases are signed with a published key.** `docs/release-signing-key.pub`
  is the public half, also served from `https://andyur.ai/cosign.pub`;
  SECURITY.md says how to verify an artifact against it and what that proves.
- **`pip install andyur` is a stated contract**: the package is the command and
  its modules, and it operates a deployment rather than containing one. An
  installed copy keeps state under `$XDG_STATE_HOME/andyur` instead of inside
  the interpreter's library, and its "nothing to talk to" messages no longer
  point at a `run.sh` the wheel does not ship. An installed copy does not read
  a `.env` file.
- An empty `ANDYUR_DATA_DIR` now means unset. It used to mean the working
  directory.
- `LICENSE` is the full Apache License 2.0 text; it had been the notice alone.
  The package's licence expression is `Apache-2.0 AND OFL-1.1`, because the
  console's fonts ship in the wheel.
- **The AgentManifest contract moved from `andyur.io/v1` to `andyur.ai/v1`**, and
  the schema `$id` with it. `andyur.io` was never a domain this project owned.
  Manifests written against the old `apiVersion` must be updated. The
  `config-sha256` annotation on the telemetry pod templates moved with it, so
  the first `kubectl apply` of this release rolls those Deployments once.
- `./run.sh docker-up` is now the documented quickstart. The native host path is
  development only, as the production profile has always enforced.
- The packaged `andyur` command now explains what is wrong when no deployment is
  reachable, instead of raising a traceback. `ANDYUR_DEBUG=1` restores it.

### Fixed
- `./run.sh up` on a fresh clone no longer waits 20 seconds and then fails inside
  a JSON parser. It names the missing SPIRE binaries and acquires or builds them.
- `deploy.sh` reports a missing PyYAML accurately instead of reporting
  "no value for registry", which described the wrong problem entirely.
- Two `mktemp` calls used a template GNU `mktemp` rejects, so two gates could
  never run on Linux.
- The exec/v1 conformance gate failed any workload that streams its model
  calls. Its model stub answered `stream: true` with a single JSON body, which
  an OpenAI-shaped client reads as an empty stream, so the workload retried and
  exited non-zero. The stub now answers with SSE chunks ending in `[DONE]`.

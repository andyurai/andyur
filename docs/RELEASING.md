# Releasing Andyur

Status: 0.1.0 is the first tagged release. This document defines the process a
release follows.

## Support policy

The latest minor release receives security and correctness fixes; anything
older is best-effort. Between releases a fix lands on `main` first. This
section is the single source for the support statement; SECURITY.md restates
it as a table and must not contradict it.

## What a release is

A release is a commit on `main` that satisfies, in order:

1. **Green everything**: the full test suite passes in a clean environment
   (extract the tree, fresh venv, `pip install ".[dev]"`, then `pytest` --
   BARE, from `agentic-platform`: `pytest tests/` is a strict SUBSET and would
   verify a release against fewer tests than CI ran),
   and the end-to-end gates pass on the real stack:
   `./run.sh sre-demo` (22/22) and the Kubernetes gate.
2. **Docs are true**: README and ARCHITECTURE describe the commit being
   released, not an earlier or intended state.
3. **Version bump**: `version` in `pyproject.toml`, semver. Pre-1.0, minor
   bumps may break compatibility; the release notes must say so explicitly.
4. **Tag and notes**: annotated tag `vX.Y.Z`; notes list changes, migration
   steps (config, env vars, database), and any security fixes with credit.
5. **Artifacts**: sdist + wheel built from the tag, and the
   server/daemon/runner container images built from the same commit. This is
   mechanical, not manual: `infra/rc/build_release.py` builds all five, records
   what was actually produced, and writes a `release-manifest.json` binding them
   to one frozen commit.

   It **fails closed**. A dirty working tree, live-gate evidence that no longer
   describes the source, or a ledger claiming a commit landed whose content is
   not in the release will all refuse to produce a manifest. A release artifact
   carrying a warning is a warning nobody reads.

   There is exactly one escape hatch, and it is named here because a document
   that describes only the refusal is not true: `--allow-dirty` builds from an
   uncommitted tree for throwaway local runs. It is never a release path. The
   artifacts then contain uncommitted changes and are NOT reproducible from the
   commit the manifest names, so the manifest records `tree_state.clean: false`,
   `artifacts_match_frozen_commit: false`, the exact uncommitted paths, and a
   warning saying it must not be used as provenance. The build also prints that
   warning to stderr. Without this the build produced a *signed* manifest
   asserting a commit its artifacts did not match, with nothing recording the
   discrepancy: a consumer who verified the signature and read `frozen_commit`
   was told the wheel was that commit while it contained uncommitted files.

   **SBOMs.** CycloneDX, two tools because one is not enough. `cyclonedx-py`
   covers the declared Python dependency graph. `syft` scans each built image,
   which is the only way to see the base-OS layer: the shipped server image
   contains 137 packages, 87 of them Debian, against 17 declared Python
   dependencies. A Python-only SBOM would omit the majority of what ships.

   **Signatures.** `cosign sign-blob` over every artifact and SBOM, **and over
   `release-manifest.json` itself**. The manifest is written and signed inside
   the signing key's lifetime, because signing the artifacts while leaving the
   document that describes them unsigned protects only the parts nobody needed
   to forge: `frozen_commit`, `tree_state`, the digests and the gate results all
   live in that file.

   The build then *verifies* each signature before recording it, because cosign
   exiting zero says it wrote a file, not that the file verifies. Note what that
   check does and does not establish: it proves a bundle matches its artifact,
   never that the artifact came from this build.

   Transparency-log upload is disabled and the build refuses any bundle that
   carries a tlog entry: this repository is private, and the public log would
   publish the digest of everything we ship.

   **What the default signatures are worth: nothing, to a third party.** The
   default key is ephemeral, generated per build and destroyed with it, and its
   public half is written into the output directory beside the artifacts it
   verifies. Anyone who can replace an artifact can replace its bundle and that
   public key too, and produce a self-consistent set that reports `Verified OK`.
   That is integrity within one directory, not provenance. The manifest says so
   in its `trust_anchor` field rather than leaving a reader to work it out.
   It is fine for a local release-candidate smoke test and is not fine for
   anything anyone else consumes. For that, pass `--signing-key` with a key
   whose public half is published out of band.

   **The release key.** A published release is built with `--signing-key`
   pointing at the project's cosign private key, with `COSIGN_PASSWORD` in the
   environment. Its public half is `docs/release-signing-key.pub`
   (SHA-256 `2d13df6ee88d2e9712512ba2aca09c20a9897d9352ec29a8448299443b9b1958`),
   also served from <https://andyur.ai/cosign.pub>; SECURITY.md tells a user
   how to verify against it. The private key and its password are held by the
   maintainer, outside every repository. Before tagging, check that the three
   copies of the public key agree -- the one beside the private key, the one
   in this tree, and the one on the website -- because a release signed with a
   key nobody can find the public half of is unsigned in practice.

   **Image identifiers** are image IDs (the sha256 of the image config), not
   registry digests. A locally built image has no repository digest until it is
   pushed, and the manifest says which it is rather than letting a reader assume.

   Release tooling (`build`, `cyclonedx-py`, `syft`, `cosign`) is deliberately
   NOT a runtime, build, or test dependency. It lives in a separate
   `.venv-release` and on the release machine's PATH, so it never perturbs the
   environment the test suite was certified in, and a contributor cloning the
   repo never installs an SBOM generator they will not invoke.

   **Create that environment with `./infra/rc/release-env.sh`.** It builds
   `.venv-release` from `requirements-release.txt` (pinned, unlike
   `requirements.txt`, because a release toolchain wants the same inputs
   producing the same artifact rather than weekly upstream drift), proves that
   `build` and `cyclonedx-py` actually run, and reports whether `syft` and
   `cosign` are on PATH without installing them. Until this existed the
   directory was gitignored, nothing created it and no file declared its
   contents, so the release built on exactly one machine -- which is not a
   release that anyone else can reproduce.

   The sdist and wheel are published to PyPI as `andyur`. The package is the
   command and its modules, not a deployment (README, "pip install andyur"),
   and `tests/test_installed_package.py` holds that contract against a package
   laid out as an installer leaves it, while the `install-gate` CI job holds it
   against the wheel pip builds. The image registry is decided at the first public release and
   recorded here when real.

## Upgrade and rollback

Every release documents: what state it migrates (database schema, config
keys, registry manifests), whether the migration is reversible, and the
tested rollback path. A release whose rollback is untested is not done
(gap G17 exit criteria).

## Cadence

No fixed cadence pre-1.0. Security fixes release as soon as verified.

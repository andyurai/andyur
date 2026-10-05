#!/usr/bin/env python3
"""Assemble a release candidate and bind every artifact to one frozen commit.

The point of a release candidate is that a single commit can be named, and
everything shipped can be traced back to it. That only holds if the binding is
mechanical, so this builds the artifacts and records what was actually produced
rather than what was intended:

  * sdist and wheel built from the frozen tree, with their sha256
  * a CycloneDX SBOM of the Python dependency graph
  * the server, worker and runner images built from the frozen tree, with the
    immutable image ID docker reports after the build
  * a CycloneDX SBOM per image, which covers the base OS packages that a
    Python-only SBOM cannot see
  * a cosign signature over every one of the above
  * the evidence-currency and ledger-audit results for that same commit

FAIL CLOSED. A manifest is only worth something if it cannot be produced for a
tree that does not match the commit it names. So a dirty working tree, stale
live-gate evidence, or a ledger claim whose content is missing all refuse to
produce a manifest rather than producing one with a warning attached. A warning
in a release artifact is a warning nobody reads.

IMAGE IDS, NOT REGISTRY DIGESTS. A locally built image has no repository digest
until it is pushed, and inventing one would be worse than omitting it. What is
recorded is the image ID, the sha256 of the image config, which is immutable and
is the same identifier the existing live gates already attest. The manifest says
which it is, so nobody reads it as a registry digest later.

The signing key is ephemeral by default: generated into a temporary directory,
used, and destroyed with the process. It proves the signing path works end to
end without standing up key custody. Pass --signing-key to use a real one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLATFORM_ROOT = HERE.parents[1]
REPO_ROOT = HERE.parents[2]

IMAGES = (
    ("andyur-server", "Dockerfile.server"),
    ("andyur-worker", "Dockerfile.daemon"),
    ("andyur-runner", "Dockerfile.runner"),
)


class ReleaseRefused(RuntimeError):
    """The tree cannot produce an honest release candidate."""


def run(*argv: str, cwd: Path | None = None, env: dict | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                            env={**os.environ, **(env or {})})
    if result.returncode != 0:
        raise ReleaseRefused(
            f"{' '.join(argv[:3])} failed ({result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[:400]}")
    return result.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Artifact:
    name: str
    kind: str
    sha256: str = ""
    image_id: str = ""
    sbom: str = ""
    signature: str = ""
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------- preconditions

def frozen_commit(repo: Path, allow_dirty: bool) -> tuple[str, str, dict]:
    """The commit being released, and whether the tree actually matches it.

    Returns the tree state as well as the commit, because --allow-dirty used to
    produce a SIGNED manifest asserting `frozen_commit` for artifacts that
    demonstrably were not that commit, with nothing anywhere recording the
    discrepancy. A consumer who verified the signature and read frozen_commit
    was told the wheel was that commit when it contained uncommitted files. The
    escape hatch is fine; silently misattributing provenance is not
    (PR #8 re-review, MED).
    """
    # SCOPED TO WHAT IS BUILT. This asked git about the WHOLE repository, and
    # this repository holds more than the platform: a stray tarball or a
    # scratch directory beside it made the release unbuildable, on a machine
    # where those files are never going away. An untracked file INSIDE the
    # platform can absolutely change what is built -- a stray module on the
    # path, an evidence artifact a gate just wrote -- so that is still refused;
    # one outside it cannot, and refusing on it is a check that fails for a
    # reason unrelated to its own question.
    status = run("git", "status", "--porcelain", "--",
                 str(PLATFORM_ROOT.relative_to(repo)) if repo in PLATFORM_ROOT.parents
                 else ".", cwd=repo).strip()
    uncommitted = status.splitlines() if status else []
    if uncommitted and not allow_dirty:
        changed = "\n  ".join(uncommitted[:10])
        raise ReleaseRefused(
            "the working tree has uncommitted changes, so no commit describes "
            f"what would be built:\n  {changed}\n"
            "commit them or pass --allow-dirty for a throwaway build")
    sha = run("git", "rev-parse", "HEAD", cwd=repo).strip()
    subject = run("git", "log", "-1", "--format=%s", cwd=repo).strip()
    tree_state = {
        "clean": not uncommitted,
        "artifacts_match_frozen_commit": not uncommitted,
        "uncommitted": uncommitted,
    }
    if uncommitted:
        tree_state["warning"] = (
            "BUILT FROM A DIRTY TREE via --allow-dirty. The artifacts contain "
            "uncommitted changes and are NOT reproducible from frozen_commit. "
            "This manifest must not be used as provenance for a release.")
    return sha, subject, tree_state


def refuse_if_vacuous(currency: dict) -> None:
    """A gate that inspected nothing is not a gate that found nothing.

    Pointed at a tree with no evidence the checker truthfully reports "0 stale",
    exits 0, and reading only the STALE list turned that into "both clean". A
    release could then be assembled with no live-gate evidence binding it to
    anything at all (PR #8 final review, (a)).
    """
    artifacts = currency.get("artifacts") or {}
    if not artifacts:
        raise ReleaseRefused(
            "the evidence-currency check found NO artifacts at all, so it proves "
            "nothing about this tree; expected the shipped result-*.json evidence")
    if not [n for n, e in artifacts.items() if e.get("verdict") == "CURRENT"]:
        raise ReleaseRefused(
            "no evidence artifact is CURRENT, so nothing binds this release to "
            "its live gates")


def gate_results(repo: Path, ref: str) -> dict:
    """Run the two RC gates and refuse on anything they call a problem.

    Reuses the existing tools rather than reimplementing their rules, so there is
    one definition of "evidence is current" and one of "the ledger is honest".
    """
    # Both gates use exit 1 to mean "I found a problem", which is a result, not a
    # crash. Running them through the generic checked runner would turn their
    # designed signal into a tool failure and bury the finding in a stack of JSON.
    currency_proc = subprocess.run(
        (sys.executable, str(HERE / "evidence_currency.py"), "--json",
         "--root", str(PLATFORM_ROOT)), capture_output=True, text=True)
    if currency_proc.returncode not in (0, 1) or not currency_proc.stdout.strip():
        raise ReleaseRefused(
            f"evidence currency check failed to run: {currency_proc.stderr[:300]}")
    currency = json.loads(currency_proc.stdout)
    refuse_if_vacuous(currency)
    stale = [name for name, entry in currency["artifacts"].items()
             if entry["verdict"] == "STALE"]
    if stale:
        raise ReleaseRefused(
            "live-gate evidence does not describe this tree; re-run the gates "
            f"that produced: {', '.join(stale)}")

    audit_proc = subprocess.run(
        (sys.executable, str(HERE / "ancestor_audit.py"), "--json",
         "--repo", str(repo), "--ref", ref),
        capture_output=True, text=True)
    if not audit_proc.stdout.strip():
        raise ReleaseRefused(f"ledger audit produced no output: {audit_proc.stderr[:300]}")
    audit = json.loads(audit_proc.stdout)
    if not audit.get("ledgers_read"):
        raise ReleaseRefused(
            "no ledger file was readable, so the landed-claim audit is vacuous")
    absent = [f["sha"] for f in audit["findings"] if f["verdict"] == "ABSENT"]
    if absent:
        raise ReleaseRefused(
            "the ledgers claim these landed but their content is not in the "
            f"release: {', '.join(absent)}")
    # Not a refusal: `.session-sync.md` is gitignored and machine-local, so it is
    # legitimately absent from a clean clone, from CI, and from any worktree.
    # But a partial audit must never look like a complete one.
    missing = audit.get("ledgers_absent") or []
    if missing:
        print(f"  NOTE: ledger(s) not present and therefore not audited: "
              f"{', '.join(missing)}", file=sys.stderr)
    return {"evidence_currency": currency, "ledger_audit": audit}


# ------------------------------------------------------------------- artifacts

def build_python(root: Path, out: Path, python: Path) -> list[Artifact]:
    """Build the sdist and wheel into a directory THIS run creates and owns.

    `python -m build` does not clean its outdir, and this used to iterate
    everything in it. So a file that merely happened to be sitting in dist/ was
    picked up, listed in the manifest, and cosign-signed, on a clean tree with a
    manifest asserting artifacts_match_frozen_commit. Reproduced with a planted
    andyur-9.9.9 wheel that verified OK (PR #8 final review, HIGH-1).

    tree_state could never have caught this: it describes the SOURCE tree, and
    the planted file is in the OUTPUT directory. Refusing a non-empty dist is
    the check that actually covers it, and taking only what the build produced
    means a later file cannot slip in either.
    """
    dist = out / "dist"
    if dist.exists() and any(dist.iterdir()):
        raise ReleaseRefused(
            f"{dist} already contains files. A release build must own its "
            "output directory, or anything left there is signed and published "
            f"as if this build produced it: {sorted(p.name for p in dist.iterdir())[:5]}")
    dist.mkdir(parents=True, exist_ok=True)

    before = {p.name for p in dist.iterdir()}
    run(str(python), "-m", "build", "--outdir", str(dist), str(root))
    produced = sorted(p for p in dist.iterdir() if p.name not in before)

    artifacts = []
    for built in produced:
        kind = "wheel" if built.suffix == ".whl" else "sdist"
        artifacts.append(Artifact(name=built.name, kind=kind,
                                  sha256=sha256_file(built)))
    if not artifacts:
        raise ReleaseRefused("python -m build produced no artifacts")
    return artifacts


def sbom_python(root: Path, out: Path, release_python: Path) -> Path:
    """CycloneDX over the declared Python dependency graph."""
    target = out / "sbom-python.cdx.json"
    run(str(release_python.parent / "cyclonedx-py"), "requirements",
        str(root / "requirements.txt"),
        "--output-format", "JSON", "--output-file", str(target))
    return target


def build_image(root: Path, dockerfile: str, tag: str) -> str:
    run("docker", "build", "-f", str(root / dockerfile), "-t", tag, str(root))
    image_id = run("docker", "image", "inspect", tag, "--format", "{{.Id}}").strip()
    if not image_id.startswith("sha256:"):
        raise ReleaseRefused(f"{tag}: docker reported no image ID")
    return image_id


def push_image(tag: str, registry: str) -> str:
    """Push one image and return its REPOSITORY digest.

    Until now this file recorded image IDs and said why in its own header: a
    locally built image has no repository digest until it is pushed, and
    inventing one would be worse than omitting it. That was right, and it also
    meant the three images existed only on the build machine. A partner who is
    not given the source cannot deploy from an image ID.

    FAIL CLOSED. The digest is read back from the daemon AFTER the push and must
    name this registry. A push that "succeeded" without producing a digest we
    can quote is not a push we will record.
    """
    remote = f"{registry}/{tag}"
    run("docker", "tag", tag, remote)
    run("docker", "push", remote)
    digests = json.loads(run("docker", "image", "inspect", remote,
                             "--format", "{{json .RepoDigests}}") or "[]")
    # THE REPOSITORY, NOT JUST THE REGISTRY. This matched on `{registry}/` and
    # took the first hit -- and RepoDigests belongs to an IMAGE ID, not to a
    # name. Two repositories built from the same Dockerfile are the same image,
    # so `andyur-worker` and a gate's `andyur-exec-input` carry each other's
    # digests, both begin `localhost:5000/`, and the release recorded the
    # worker as pullable from `localhost:5000/andyur-exec-input@...`.
    #
    # That is the release lying about what it built, in the one document a
    # deployer pulls from. On the build machine both repositories exist so
    # nothing fails; a partner gets a reference to a repository this release
    # never published, and the failure is an image pull that names something
    # they have never heard of.
    repository = f"{registry}/{tag.rsplit(':', 1)[0]}"
    matching = sorted({d for d in digests if d.startswith(f"{repository}@")})
    if not matching:
        raise ReleaseRefused(
            f"{remote}: pushed, but the daemon reports no repository digest for "
            f"{repository}. Refusing to record a reference nobody can pull.")
    if len(matching) > 1:
        # One repository cannot honestly have two digests for one push.
        raise ReleaseRefused(
            f"{remote}: the daemon reports {len(matching)} digests for "
            f"{repository} ({', '.join(matching)}); refusing to guess which "
            "one this push produced")
    return matching[0]


# THE MANIFESTS A DEPLOYER APPLIES BESIDE THE CONTROL PLANE, and the reason
# they are here rather than assumed.
#
# control-plane.yaml REFERENCES all of them: it validates user tokens against
# `andyur-keycloak.andyur-system.svc` and exports telemetry to
# `otel-collector.andyur-system.svc`. Shipping the control plane alone gave a
# party holding the bundle a manifest whose server exits at boot looking for an
# identity provider that is not in the box. Nothing in the bundle said so and
# nothing checked.
#
# Copied verbatim, not rendered: neither carries a placeholder, and both pin
# every image by digest.
# THE RUN NAMESPACE SHIPS TOO. run-isolation.yaml creates `andyur-runs`, the
# worker's Role in it and the per-run SPIFFE identity. Without it a partner
# deployed a control plane with no namespace to launch into -- and the
# failure surfaced as the worker's NetworkPolicy-stamp refusal, which names
# something else entirely. Found by making the deploy gate run the installer
# rather than one hand-picked manifest (2026-08-30 review, item 2).
# temporal.yaml SHIPS BECAUSE control-plane.yaml CANNOT START WITHOUT IT. The
# server Pod mounts the `andyur-temporal-spiffe-helper` ConfigMap, which only
# temporal.yaml defines, and the production manifest binds the Temporal
# provider. It was missing from this tuple: a bundle deploy left andyur-server-0
# in ContainerCreating, and every gate passed anyway because the engine had
# been applied BY HAND on the machine that ran them.
COMPANION_MANIFESTS = ("idp.yaml", "observability.yaml", "run-isolation.yaml",
                       "temporal.yaml")
# The installer a partner RUNS. Signed like everything else, and more important
# that it is signed than any manifest: a manifest is applied, this is executed.
INSTALLER = "deploy.sh"
# The PUBLIC verification key for the governed agent catalog. Public, so it
# ships; required, because the server cosign-verifies the catalog before
# pulling it and a deployer without the source tree has no other copy.
CATALOG_KEY = "agent-catalog-cosign.pub"


# The Collector's and Jaeger's configuration. `apply-observability.sh` turns
# each into a ConfigMap the Deployment mounts, from a single source file -- and
# that script is in the SOURCE TREE, which a deployer does not have.
OBSERVABILITY_CONFIGS = (
    ("otel-collector-config", "infra/observability/otel-collector.yaml"),
    ("andyur-jaeger-config", "infra/observability/jaeger.yaml"),
)


def _configmap_documents(root: Path) -> str:
    """The two telemetry ConfigMaps, as YAML to append to observability.yaml.

    THE BUNDLE SHIPPED DEPLOYMENTS THAT COULD NOT START. observability.yaml
    carries the Collector's and Jaeger's Deployments, Services and
    NetworkPolicies, and neither ConfigMap: those were created by
    `apply-observability.sh` from the source tree. On any cluster where a
    developer had run that script the ConfigMaps already existed, so the bundle
    looked complete for as long as it was only ever deployed onto one.

    It is not a subtle failure. Without the ConfigMap the Collector sits in
    ContainerCreating on `configmap "otel-collector-config" not found`, the
    control plane's telemetry export has nowhere to go, and `/ready` times out
    -- so the CONTROL PLANE never becomes Ready either, for a reason that names
    telemetry and not the missing file.

    Found by tearing the cluster down between two RC passes, which is the whole
    argument for doing that: pass 1 was green on a cluster prepared by hand.
    """
    documents = []
    for name, relative in OBSERVABILITY_CONFIGS:
        source = root / relative
        if not source.is_file():
            raise ReleaseRefused(
                f"{relative} is missing: the telemetry Deployments mount it as "
                "a ConfigMap and cannot start without it")
        # Written as a literal block scalar, indented, rather than through a
        # YAML dumper: the config files carry comments a deployer may need to
        # read, and round-tripping them through a loader would drop every one.
        body = "\n".join("    " + line if line else ""
                          for line in source.read_text().splitlines())
        documents.append(
            "---\n"
            "# Rendered by the release from " + relative + ". Its single source\n"
            "# is that file; edit it there, not here.\n"
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            f"  name: {name}\n"
            "  namespace: andyur-system\n"
            "data:\n"
            "  config.yaml: |\n"
            + body + "\n")
    return "\n".join(documents)


# Which Deployment mounts which configuration, for the hash below.
CONFIG_OWNERS = {"otel-collector": "infra/observability/otel-collector.yaml",
                 "andyur-jaeger": "infra/observability/jaeger.yaml"}


def _stamp_config_hashes(root: Path, text: str) -> str:
    """A changed configuration restarts the Pods that read it.

    A ConfigMap is read at start. Applying a new one changed nothing running,
    so an upgrade that fixed the Collector's relabelling kept dropping every
    Temporal metric until the Collector happened to restart. The hash of each
    source goes on its Deployment's pod template: a different config is a
    different template, and `kubectl apply` rolls it.
    """
    import hashlib

    for app, relative in CONFIG_OWNERS.items():
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        before = f"    metadata:\n      labels: {{app: {app}}}\n"
        if text.count(before) != 1:
            raise ReleaseRefused(
                f"observability.yaml has no single pod template for {app}; the "
                "config hash that rolls it on a change cannot be stamped")
        text = text.replace(before, before +
                            f"      annotations: {{andyur.ai/config-sha256: \"{digest}\"}}\n")
    return text


def copy_companions(root: Path, out: Path) -> list[Path]:
    """The companion manifests, into the release output so they are SIGNED.

    A deployer is asked to trust these exactly as much as the control plane, so
    they get the same signature and the same place in the manifest of what was
    built. An unsigned YAML beside a signed one is a document anyone can edit.
    """
    copied = []
    installer = Path(__file__).parent / INSTALLER
    target = out / INSTALLER
    shutil.copy(installer, target)
    target.chmod(0o755)
    copied.append(target)
    for name in COMPANION_MANIFESTS:
        source = root / "infra" / "kubernetes" / name
        if not source.is_file():
            raise ReleaseRefused(
                f"{source} is missing: the control plane references what it "
                "deploys, so a bundle without it cannot come up")
        target = out / name
        shutil.copy(source, target)
        # The telemetry manifest gets the two ConfigMaps its Deployments mount,
        # so the bundle can bring the telemetry path up on a cluster nobody
        # prepared. See _configmap_documents.
        if name == "observability.yaml":
            target.write_text(_stamp_config_hashes(root, target.read_text()))
            with target.open("a") as handle:
                handle.write("\n" + _configmap_documents(root))
        copied.append(target)
    return copied


def emit_deployment(root: Path, out: Path, pushed: dict[str, str],
                    registry_ref: str = "", registry_allow_http: bool = False,
                    registry_ignore_tlog: bool = False) -> Path:
    """Render the Kubernetes manifest with the digests that were actually pushed.

    infra/kubernetes/control-plane.yaml ships as a TEMPLATE: every andyur image
    in it reads `registry.example/<name>@sha256:aaaa...`. That is not a
    deployment, and verify-macos.sh:59 already refuses any image that is still
    `registry.example/*` or is not digest-pinned -- so the gate has always
    demanded this substitution and nothing performed it.

    REFUSES IF ANY PLACEHOLDER SURVIVES. A manifest that is half-substituted
    would deploy the real control plane beside an image nobody can pull, and the
    failure would appear at runtime in someone else's cluster.
    """
    src = root / "infra" / "kubernetes" / "control-plane.yaml"
    text = src.read_text()
    for name, digest in pushed.items():
        text = re.sub(rf"registry\.example/{re.escape(name)}@sha256:[a-f0-9]+",
                      digest, text)
    # THE FOURTH PLACEHOLDER, and the reason --push-to could not complete on any
    # tree until now. control-plane.yaml pins FOUR references and this build
    # produces THREE: andyur-registry is not one of our images, it is the
    # GOVERNED AGENT CATALOG -- an OCI artifact published and cosign-signed by
    # `andyur agents package --publish-ref`, whose content is the adopter's
    # agents rather than our platform. Building it here would be this file
    # inventing an agent catalog; omitting it left a placeholder that the
    # (correct) refusal below then rejected, so every --push-to run died at the
    # last step. It is an INPUT, named on the command line, and its absence is
    # refused with the command that produces one.
    if registry_ref:
        text = re.sub(r"registry\.example/andyur-registry@sha256:[a-f0-9]+",
                      registry_ref, text)
    leftover = sorted(set(re.findall(r"registry\.example/[a-z-]+@sha256:[a-f0-9]+", text)))
    if leftover:
        hint = ""
        if any("andyur-registry@" in ref for ref in leftover):
            hint = ("\n         andyur-registry is the governed agent catalog, not "
                    "one of our images. Publish one and pass its digest:\n"
                    "           andyur agents package <spec> --publish-ref "
                    "<registry>/andyur-registry:<tag> --cosign-key <key> "
                    "--conformance-evidence <evidence>\n"
                    "           build_release.py ... --registry-ref "
                    "<the pinned digest it prints>")
        raise ReleaseRefused(
            "the deployment manifest still contains placeholder images that this "
            "release did not build or push: " + ", ".join(leftover) +
            ". Supply them or this bundle cannot be deployed by anyone." + hint)
    # HOW THE SNAPSHOT IS VERIFIED IS A PROPERTY OF THE REGISTRY, not of the
    # platform, so it is rendered here beside the reference rather than shipped
    # as a guess. The manifest's defaults are the strict ones -- HTTPS, and a
    # signature in the transparency log -- and they are correct for a
    # production registry.
    #
    # They are also unsatisfiable for the local registry the reference cluster
    # uses: its snapshot is signed with a local key and was never in a public
    # log, so `cosign verify` reaches out to the Sigstore TUF mirror, the
    # server's NetworkPolicy (correctly) refuses the egress, and the agent
    # registry is 503 "unavailable". That is what the shipped manifest did on a
    # real cluster; the evidence that said otherwise was recorded against a
    # hand-edited deployment, which is the same defect as the profile.
    for flag, on in (("ANDYUR_REGISTRY_ALLOW_HTTP", registry_allow_http),
                     ("ANDYUR_REGISTRY_COSIGN_IGNORE_TLOG", registry_ignore_tlog)):
        if on:
            text = text.replace(
                '{name: %s, value: "off"}' % flag,
                '{name: %s, value: "on"}' % flag)
    target = out / "control-plane.yaml"
    target.write_text(text)
    return target


def sbom_image(tag: str, out: Path) -> Path:
    target = out / f"sbom-{tag.replace(':', '-').replace('/', '_')}.cdx.json"
    # Syft reads the image from the local daemon; scanning the built image is
    # what catches base-OS packages no dependency file mentions.
    run("syft", f"docker:{tag}", "-o", f"cyclonedx-json={target}", "-q")
    return target


# --------------------------------------------------------------------- signing

def make_key(workdir: Path) -> tuple[Path, str]:
    """An ephemeral cosign keypair, created outside the repository."""
    password = "andyur-rc"          # ephemeral: the key dies with this process
    run("cosign", "generate-key-pair", cwd=workdir,
        env={"COSIGN_PASSWORD": password})
    key = workdir / "cosign.key"
    if not key.is_file():
        raise ReleaseRefused("cosign did not produce a key pair")
    return key, password


def sign(path: Path, key: Path, password: str, out: Path) -> str:
    """Sign one artifact, returning the bundle filename.

    cosign v3 deprecated --output-signature in favour of a bundle, which carries
    the signature together with the verification material rather than leaving a
    bare base64 blob whose provenance has to be reconstructed.

    --tlog-upload=false is not an optimisation. This repository is permanently
    private, and the public Sigstore transparency log would publish a record of
    every artifact digest we sign. Signing must not leak what we are shipping.
    """
    bundle = out / (path.name + ".cosign-bundle.json")
    # --use-signing-config=false is required alongside --tlog-upload=false in
    # cosign v3: the default signing config names a transparency-log service and
    # refuses the combination otherwise.
    run("cosign", "sign-blob", "--key", str(key), "--yes",
        "--use-signing-config=false", "--tlog-upload=false",
        "--bundle", str(bundle), str(path),
        env={"COSIGN_PASSWORD": password})
    if not bundle.is_file():
        raise ReleaseRefused(f"{path.name}: cosign produced no bundle")

    # A signature the builder never checks is just a file. cosign exiting zero
    # says it wrote something, not that the something verifies against the
    # artifact, so the release proves its own signatures before claiming them.
    run("cosign", "verify-blob", "--key", str(key.parent / "cosign.pub"),
        "--bundle", str(bundle), "--insecure-ignore-tlog", str(path))

    # Nothing may have reached the public log: this repository is private and a
    # tlog entry would publish the digest of everything we ship.
    recorded = json.loads(bundle.read_text())
    if recorded.get("verificationMaterial", {}).get("tlogEntries"):
        raise ReleaseRefused(
            f"{path.name}: the signature bundle carries a transparency-log entry, "
            "so the artifact digest was published; refusing")
    return bundle.name


# ---------------------------------------------------------------------- driver

# WHAT A DEPLOYER MUST HAVE BEFORE ANY OF THIS APPLIES.
#
# Written because the honest answer to "can someone without the codebase bring
# this up?" was no, and the reasons were invisible: the bundle carried a
# manifest that references a Secret it does not create, CRDs it does not
# install, and services it does not deploy. Every one of those is a pod that
# never starts, with an error about the wrong thing.
#
# It is a text file rather than automation on purpose, for now: the questions
# below have no defaults that are safe to guess, and a script that guessed them
# would be a script that deployed something nobody chose.
PREREQUISITES = """# Before you apply anything

This bundle does not install a cluster, an identity plane, or a registry. It
assumes four things exist. Each one is a pod that never starts if it does not.

## 1. SPIRE, at a release name this manifest depends on

`control-plane.yaml` declares `ClusterSPIFFEID` resources with

    className: spire-system-andyur-spire

which is `<namespace>-<release name>`. **If you install SPIRE under a different
release name or namespace, the controller ignores every one of them, no SVID is
ever issued, and nothing says so** -- the pods simply never become ready. It is
the quietest failure in this bundle, so it is the first thing written down.

Installed here as two Helm charts, pinned:

    spire-crds  0.6.0
    spire       0.30.0        (SPIRE 1.14.5)
    release     andyur-spire
    namespace   spire-system

with these values:

    global:
      spire:
        trustDomain: andyur.local        # must equal ANDYUR_TRUST_DOMAIN below
        clusterName: <your cluster>      # yours, not ours
        caSubject: {commonName: andyur.local, country: US, organization: Andyur}
        strictMode: true
        namespaces: {create: false}
    spiffe-oidc-discovery-provider:
      enabled: false

The trust domain appears in every SPIFFE ID in `control-plane.yaml`. Changing
it means changing both, together.

## 2. Two Secrets, which this bundle deliberately does not contain

(There is a third, `andyur-registry-cosign`. It is a PUBLIC verification key, it
ships in this bundle, and `deploy.sh` creates it for you -- see section 4. It is
listed apart from these two because these two are credentials and it is not.)

    kubectl create namespace andyur-system

    kubectl -n andyur-system create secret generic andyur-secrets \\
      --from-literal=run-token-secret="$(openssl rand -hex 32)"

    kubectl -n andyur-system create secret generic andyur-idp-secrets \\
      --from-literal=admin-password="$(openssl rand -hex 24)" \\
      --from-literal=db-password="$(openssl rand -hex 24)"

    # the workflow engine's own database
    kubectl -n andyur-system create secret generic andyur-temporal-secrets \\
      --from-literal=db-password="$(openssl rand -hex 24)"

No credential ships in a release artifact. The control plane, Keycloak and the
workflow engine all refuse to boot without theirs rather than coming up
unauthenticated.

## 3. A registry your nodes can pull from

Every image in these manifests is pinned by digest, including Keycloak,
Postgres, Envoy and the collector. The Andyur images name the registry they
were pushed to; if your nodes cannot reach it, the same digests must be pushed
somewhere they can. Do not re-tag -- a digest is the identity.

`control-plane.yaml` also carries a NetworkPolicy egress rule to the registry
as an **ipBlock**, because NetworkPolicy cannot select by DNS name. If your
registry is not at the address rendered there, that rule must change or the
server cannot fetch the agent catalog.

## 4. A governed agent catalog -- which now comes WITH the bundle

`ANDYUR_REGISTRY_REF` names a signed OCI snapshot of the agents this deployment
may run. Without one the server has no agents, so no run can be started.

`release-manifest.json` records the exact catalog this bundle was rendered
against (`"kind": "agent-catalog"`), and `agent-catalog-cosign.pub` beside it is
the public key the server verifies that catalog with. `deploy.sh` offers the
recorded reference as the default answer to question 3 and creates the
`andyur-registry-cosign` Secret from the shipped key, so neither is something
you have to obtain from us separately any more.

The catalog itself lives in a registry and is pulled by digest, like every
image here. If your nodes and control plane cannot reach the registry it was
published to, push the same artifact somewhere they can -- and do not re-tag.

## Apply order -- but use ./deploy.sh

`deploy.sh` applies these in this order, after asking what only you can answer
and checking every precondition it can check before changing anything. The list
is here so you know what it does, not so you do it by hand:

    kubectl apply -f idp.yaml            # the identity provider the profile requires
    kubectl apply -f observability.yaml  # the collector the control plane exports to
    kubectl apply -f run-isolation.yaml  # the namespace runs launch into
    kubectl apply -f control-plane.yaml

## And the worker starts

Every run launch requires a NetworkPolicy verification stamp under 600 seconds
old. Until this release nothing in the bundle refreshed it and the verifier was
in the source tree, so the control plane served and runs never launched -- and
that was written here as a known limitation.

`control-plane.yaml` now deploys `andyur-netpol-reconciler`. It re-PROVES
containment inside your run namespace on a timer -- an isolated Pod that must
reach its own run's proxy and must NOT reach the other run, the Kubernetes API,
the internet, the metadata address, the collector or DNS -- and stamps only when
every one of those holds. When one does not, it WITHDRAWS the stamp and the
worker stops launching. It does not run the release gate's allow-all mutation
proof: that deliberately breaks containment, which is not something to do
unattended in your cluster. The stamp records which checks it ran.
"""


def write_bundle(out: Path, manifest: dict, ephemeral_key: bool) -> Path:
    """Assemble the PARTNER BUNDLE: what a deployer receives, and nothing else.

    `verify_bundle.py` proves a bundle is deployable and carries no source, and
    it requires three files -- the deployment manifest, the release manifest and
    VERIFY.md. NOTHING PRODUCED ANY OF THEM AS A BUNDLE. The release wrote its
    artifacts into one directory containing the wheel and the sdist, and a human
    was implicitly expected to hand-copy the right subset into a new directory
    and write the verification instructions themselves. A distribution step that
    exists only as an instruction to be careful is the failure this whole lane
    is about, and it is why the gate had never been run against a real bundle.

    So the build assembles it, and the sdist and wheel are structurally
    incapable of ending up here: this copies an explicit list into a fresh
    directory rather than pruning one.
    """
    bundle = out / "bundle"
    bundle.mkdir(exist_ok=True)
    for name in ("control-plane.yaml", *COMPANION_MANIFESTS, INSTALLER,
                 "release-manifest.json"):
        for f in (name, name + ".cosign-bundle.json"):
            shutil.copy(out / f, bundle / f)
    # The catalog's verification key, when the release built one. Copied
    # unsigned-by-us on purpose: it is itself a verification key, so signing it
    # with the release key would make the release key the root of trust for the
    # catalog too, and the whole point of a separate catalog key is that it is
    # not. Its sha256 IS in the signed release-manifest.json, which is the
    # binding that matters.
    if (out / CATALOG_KEY).is_file():
        shutil.copy(out / CATALOG_KEY, bundle / CATALOG_KEY)
    (bundle / INSTALLER).chmod(0o755)
    if ephemeral_key:
        shutil.copy(out / "cosign.pub", bundle / "cosign.pub")
    (bundle / "PREREQUISITES.md").write_text(PREREQUISITES)

    images = [a for a in manifest["artifacts"] if a["kind"] == "container-image"]
    pullable = "\n".join(
        f"  {a['name']}\n      {a.get('extra', {}).get('pullable_as', 'NOT PUSHED')}"
        for a in images)
    key_line = (
        "cosign.pub ships in this bundle, so these signatures prove only that "
        "this directory is internally consistent: anyone who can replace a file "
        "can replace its signature and this key. They are NOT provenance. Ask "
        "for a release signed with a key whose public half you received "
        "separately before you rely on them."
        if ephemeral_key else
        "This release was signed with an operator-supplied key. Obtain its "
        "public half OUT OF BAND -- not from this bundle -- and verify with it.")
    (bundle / "VERIFY.md").write_text(f"""# Verify and deploy Andyur {manifest['frozen_commit'][:9]}

This bundle is images plus a deployment manifest. It deliberately contains no
source: you deploy what was built and signed, and you do not build it yourself.

## 1. What you have

    control-plane.yaml          the Kubernetes manifest, image digests pinned
    release-manifest.json       what was built, from which commit, and its gates
    *.cosign-bundle.json        a signature for each of the two above

Images, pinned by repository digest and pulled from the registry named in them:

{pullable}

## 2. Verify before you deploy

    cosign verify-blob --key <public key> \\
      --bundle release-manifest.json.cosign-bundle.json \\
      --insecure-ignore-tlog=true release-manifest.json

    cosign verify-blob --key <public key> \\
      --bundle control-plane.yaml.cosign-bundle.json \\
      --insecure-ignore-tlog=true control-plane.yaml

TRUST ANCHOR: {key_line}

The signatures are not in a public transparency log on purpose -- publishing one
would publish a record of every digest shipped -- so `--insecure-ignore-tlog`
is expected here and is not a weakening of the key check.

## 3. Deploy

    kubectl apply -f control-plane.yaml

Your cluster must be able to pull the digests above. They name the registry they
were pushed to; if that registry is not reachable from your nodes, re-push the
same digests somewhere that is, and do not re-tag -- a digest is the identity.

## 4. The run namespace must stay verified -- and now it does that itself

The daemon refuses to start, and refuses to launch, unless the namespace it
launches runs into carries a NetworkPolicy verification stamp recorded in the
last 600 seconds. It is a fail-closed control: it will not run an agent in a
namespace whose isolation nobody has checked recently.

Until this release nothing in the bundle could renew that stamp -- the verifier
was a script in the source tree -- so `andyur-worker` crash-looped while the
control plane served normally, and this section told you that was expected.

`control-plane.yaml` now deploys `andyur-netpol-reconciler`. Every 240 seconds
it launches an isolated Pod in your run namespace under the same NetworkPolicies
a run gets, and requires that the Pod CAN reach its own run's proxy (the
positive control: without it, every denial below could just be a Pod that never
got a network) and CANNOT reach the other run, the Kubernetes API, the public
internet, the metadata address, the collector, or cluster DNS. It stamps only
when every one of those holds, and WITHDRAWS the stamp when one does not -- so a
cluster whose containment regresses stops launching runs rather than continuing
on a stale claim. `kubectl get namespace andyur-runs -o yaml` shows the stamp
and, in its annotations, exactly which checks it ran.

It deliberately does not run one proof the release gate runs: applying an
allow-all NetworkPolicy to show the probe CAN go red, then removing it and
showing enforcement returns. That breaks containment on purpose, which is not
something to do unattended in your cluster. The stamp says so too.

## 5. The profile this deploys in

`control-plane.yaml` sets `ANDYUR_PROFILE=prod` with `ANDYUR_USER_AUTH=on`, and
`idp.yaml` deploys the Keycloak that makes prod bootable -- with a demo realm,
which is a starting point and not an identity provider you should keep. Point
`ANDYUR_OIDC_ISSUER`, `ANDYUR_OIDC_JWKS`, `ANDYUR_OIDC_AUDIENCE` and
`ANDYUR_ADMIN_ROLE` at yours; `./deploy.sh --ask` asks for all four when you
answer `external` to question 4, and then does not deploy the bundled one.

Per-run SPIFFE identity is required, agent-auth is on, and the NetworkPolicies
are unchanged in every case.

## 6. What this bundle does not give you

The source, a build, or a way to reproduce the images yourself. If you need to
verify what is IN them, `release-manifest.json` names an SBOM for each image and
each is signed alongside it.

The `andyur agents package` tooling that produces a governed agent catalog is
also source-side. This bundle names the catalog it was built against and ships
the public key to verify it (section 4 of PREREQUISITES.md), which is enough to
RUN the agents in that catalog; publishing a catalog of your own is not
something these images can do.
""")
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a release candidate.")
    parser.add_argument("--out", type=Path, required=True,
                        help="directory to write artifacts and the manifest into")
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    parser.add_argument("--ref", default="origin/main",
                        help="ref the ledger audit checks against")
    parser.add_argument("--release-python", type=Path,
                        default=PLATFORM_ROOT / ".venv-release" / "bin" / "python",
                        help="the release-tooling interpreter, holding `build` and "
                             "cyclonedx-py. Deliberately NOT the project venv: "
                             "release tools must not perturb the environment the "
                             "test suite was certified in")
    parser.add_argument("--signing-key", type=Path,
                        help="a real cosign key; default is an ephemeral one")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="throwaway build from an uncommitted tree")
    parser.add_argument("--skip-images", action="store_true",
                        help="skip image builds and their SBOMs; recorded in the manifest")
    parser.add_argument("--registry-allow-http", action="store_true",
                        help="the agent registry is plain HTTP (a local "
                             "registry). Off by default, because a production "
                             "registry is not")
    parser.add_argument("--registry-ignore-tlog", action="store_true",
                        help="the registry snapshot is signed with a local key "
                             "and is not in a public transparency log, so "
                             "cosign must not try to reach one. Off by default")
    parser.add_argument("--registry-cosign-pub", metavar="FILE", default="",
                        help="the PUBLIC half of the key the agent catalog was "
                             "signed with. It ships in the bundle: it is a public "
                             "key, the server cannot verify the catalog without "
                             "it, and a deployer who does not have the source "
                             "tree has no other way to obtain it")
    parser.add_argument("--registry-ref", metavar="REF", default="",
                        help="the governed agent-registry snapshot to deploy "
                             "against, as a pinned digest reference produced by "
                             "`andyur agents package --publish-ref`. Required "
                             "with --push-to, because control-plane.yaml pins it "
                             "and this build does not produce it")
    parser.add_argument("--push-to", metavar="REGISTRY",
                        help="push the built images to this registry (e.g. "
                             "ghcr.io/OWNER) and record their REPOSITORY digests, "
                             "then render a deployable control-plane.yaml. Without "
                             "this the manifest carries image IDs, which are "
                             "local-only and cannot be pulled by anyone else")
    args = parser.parse_args(argv)

    for tool in ("docker", "syft", "cosign", "git"):
        if not shutil.which(tool):
            print(f"refused: {tool} is not on PATH", file=sys.stderr)
            return 2

    # Checked here rather than left to a traceback deep in the build: running
    # from a git worktree is the normal case for release work, and a worktree
    # has no .venv of its own, so the defaults will not resolve there.
    if not args.release_python.is_file():
        # Name the command, because the refusal used to be a dead end. Nothing
        # in the repo created this environment and no file declared what went
        # in it, so the only way to satisfy this was to already know.
        print(f"refused: --release-python {args.release_python} does not exist "
              "(a git worktree has no venv of its own; pass the real one)\n"
              "         create it with:  ./infra/rc/release-env.sh\n"
              "         or point --release-python at an existing one",
              file=sys.stderr)
        return 2
    if not (args.release_python.parent / "cyclonedx-py").is_file():
        print(f"refused: cyclonedx-py is not installed beside "
              f"{args.release_python}; it is release tooling and belongs in a "
              "separate venv, not the project one", file=sys.stderr)
        return 2

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    try:
        sha, subject, tree_state = frozen_commit(args.repo, args.allow_dirty)
        short = sha[:9]
        print(f"frozen commit {short}  {subject}")
        if not tree_state["clean"]:
            # Loud, on stderr, every time. A throwaway build is legitimate; one
            # that looks like a real release candidate is not.
            print(f"  WARNING: {tree_state['warning']}", file=sys.stderr)
            print(f"  {len(tree_state['uncommitted'])} uncommitted path(s)",
                  file=sys.stderr)

        print("running the release gates...")
        gates = gate_results(args.repo, args.ref)
        print("  evidence currency and ledger audit both clean")

        artifacts: list[Artifact] = []

        print("building the python artifacts...")
        artifacts.extend(build_python(PLATFORM_ROOT, out, args.release_python))
        python_sbom = sbom_python(PLATFORM_ROOT, out, args.release_python)
        for artifact in artifacts:
            artifact.sbom = python_sbom.name
        print(f"  {', '.join(a.name for a in artifacts)}")

        skipped = []
        if args.skip_images:
            skipped = [name for name, _ in IMAGES]
            print("skipping image builds (--skip-images)")
        else:
            pushed: dict[str, str] = {}
            for name, dockerfile in IMAGES:
                tag = f"{name}:{short}"
                print(f"building {tag}...")
                image_id = build_image(PLATFORM_ROOT, dockerfile, tag)
                sbom = sbom_image(tag, out)
                extra = {"id_is": "image config sha256, not a registry digest; "
                                  "a repository digest requires a push"}
                if args.push_to:
                    digest = push_image(tag, args.push_to)
                    pushed[name] = digest
                    extra = {"pullable_as": digest,
                             "id_is": "image config sha256; pullable_as is the "
                                      "repository digest and is what a deployer uses"}
                    print(f"  pushed {digest}")
                artifacts.append(Artifact(
                    name=tag, kind="container-image", image_id=image_id,
                    sbom=sbom.name, extra=extra))
                print(f"  {image_id[:26]}...")
            if args.push_to:
                # The bundle a partner receives is images + this manifest, never
                # source. Rendering it here means the digests in it are the ones
                # this run actually pushed rather than ones a human transcribed.
                dep = emit_deployment(PLATFORM_ROOT, out, pushed,
                                      args.registry_ref,
                                      args.registry_allow_http,
                                      args.registry_ignore_tlog)
                artifacts.append(Artifact(
                    name=dep.name, kind="deployment-manifest",
                    sha256=sha256_file(dep)))
                print(f"  rendered {dep.name} with {len(pushed)} pushed digests")
                for companion in copy_companions(PLATFORM_ROOT, out):
                    artifacts.append(Artifact(
                        name=companion.name,
                        kind=("installer" if companion.name == INSTALLER
                              else "deployment-manifest"),
                        sha256=sha256_file(companion)))
                print(f"  bundled {', '.join(COMPANION_MANIFESTS)}, {INSTALLER}")
                # THE AGENT CATALOG, IN THE DELIVERY PATH.
                #
                # The bundle has always REFERENCED a governed catalog -- it is
                # what ANDYUR_REGISTRY_REF names, and without one the server has
                # no agents and no run can start. But nothing put it in the
                # release: PREREQUISITES.md told the deployer it "comes from us
                # with the bundle", and it did not. So the release now records
                # WHICH catalog this bundle was built against, and ships the
                # PUBLIC half of the key it was signed with -- the one thing the
                # server needs to verify it and the one thing a deployer without
                # the source tree cannot obtain.
                #
                # The catalog IMAGE itself is not copied into the bundle: it is
                # an OCI artifact in a registry, pulled by digest exactly like
                # every other image here, and a digest in a signed manifest is a
                # stronger delivery than a tarball.
                if args.registry_ref:
                    artifacts.append(Artifact(
                        name=args.registry_ref, kind="agent-catalog",
                        extra={"is": "the governed agent catalog this bundle was "
                                     "rendered against; ANDYUR_REGISTRY_REF names "
                                     "it and the server cosign-verifies it before "
                                     "pulling",
                               "verify_with": (CATALOG_KEY if args.registry_cosign_pub
                                               else "NOT SHIPPED -- pass "
                                                    "--registry-cosign-pub")}))
                if args.registry_cosign_pub:
                    source = Path(args.registry_cosign_pub)
                    if not source.is_file():
                        raise ReleaseRefused(
                            f"--registry-cosign-pub {source} does not exist")
                    body = source.read_text()
                    if "PRIVATE KEY" in body:
                        # A private key in a partner bundle is the worst single
                        # thing this script could do, so it is refused by
                        # inspection rather than by naming convention.
                        raise ReleaseRefused(
                            f"{source} contains a PRIVATE key; only the public "
                            "half may ship")
                    target = out / CATALOG_KEY
                    target.write_text(body)
                    artifacts.append(Artifact(
                        name=CATALOG_KEY, kind="public-key",
                        sha256=sha256_file(target)))
                    print(f"  bundled {CATALOG_KEY} (the catalog's verification key)")
                elif args.registry_ref:
                    print("  NOTE: no --registry-cosign-pub, so the bundle names a "
                          "catalog the deployer cannot verify")

        print("signing...")
        # The manifest is written and signed INSIDE the key's lifetime. It used
        # to be written after the tempdir was destroyed, so every provenance
        # claim it makes -- frozen_commit, tree_state, digests, gate results --
        # sat in a plain JSON file anyone could edit, while RELEASING.md told
        # operators it was signed (PR #8 final review, HIGH-2). Signing the
        # artifacts and leaving the document that describes them unsigned
        # protects the parts nobody needed to forge.
        with tempfile.TemporaryDirectory(prefix="andyur-rc-key-") as keydir:
            if args.signing_key:
                key, password = args.signing_key, os.environ.get("COSIGN_PASSWORD", "")
                key_kind = f"operator-supplied ({key.name})"
                anchor = ("operator-supplied key; the verifier must obtain the "
                          "public half out of band")
            else:
                key, password = make_key(Path(keydir))
                key_kind = "ephemeral, generated for this build and destroyed with it"
                shutil.copy(Path(keydir) / "cosign.pub", out / "cosign.pub")
                # Said plainly in the artifact itself. cosign.pub ships in the
                # SAME directory as the things it verifies, so anyone who can
                # replace an artifact can replace its bundle and this key and
                # produce a self-consistent set that verifies. That is integrity
                # within one directory, never provenance (PR #8 final review, (d)).
                anchor = ("NONE. The public key ships beside the artifacts it "
                          "verifies, so these signatures prove only that this "
                          "directory is internally consistent. They anchor "
                          "nothing and MUST NOT be relied on by a third party. "
                          "Use --signing-key with a key published out of band "
                          "for anything anyone else consumes.")
            for artifact in artifacts:
                # WHERE each artifact actually lives. The wheel and sdist are in
                # dist/, an image is represented by its SBOM, and the rendered
                # deployment manifest sits at the top of the output directory --
                # `emit_deployment` writes it there. Signing it as `dist/
                # control-plane.yaml` looked for a file that was never written,
                # so the first real --push-to run would have died at signing
                # even after the placeholder was supplied. Found by running it.
                if artifact.kind == "agent-catalog":
                    # NOT A FILE. It is an OCI reference to an artifact in a
                    # registry, which carries its own cosign signature and its
                    # own public key (agent-catalog-cosign.pub, beside this).
                    # Its integrity here is the DIGEST recorded in the release
                    # manifest, and the release manifest is signed. Falling
                    # through to the `dist/` branch below made the signer look
                    # for a file named `registry/andyur-registry@sha256:...`,
                    # and the whole release died at signing with no message.
                    continue
                if artifact.kind == "container-image":
                    signed = out / artifact.sbom
                elif artifact.kind in ("deployment-manifest", "installer", "public-key"):
                    signed = out / artifact.name
                else:
                    signed = out / "dist" / artifact.name
                # SAY WHICH FILE, rather than handing cosign a path that does
                # not exist. The `else` above is an ASSUMPTION about where a
                # kind lives, and a new kind that does not live there produced a
                # failure naming neither the artifact nor the kind.
                if not signed.is_file():
                    raise ReleaseRefused(
                        f"nothing to sign for {artifact.name!r} (kind "
                        f"{artifact.kind!r}): expected it at "
                        f"{signed.relative_to(out)}, which does not exist")
                artifact.signature = sign(signed, key, password, out)

            manifest = {
                "schema": "andyur.release-manifest/v1",
                "frozen_commit": sha,
                "frozen_subject": subject,
                "audited_against": args.ref,
                "tree_state": tree_state,
                "signing_key": key_kind,
                "trust_anchor": anchor,
                "artifacts": [
                    {k: v for k, v in vars(a).items() if v not in ("", {}, None)}
                    for a in artifacts],
                "skipped_images": skipped,
                "ledgers_audited": gates["ledger_audit"].get("ledgers_read", []),
                "ledger_claims_audited": gates["ledger_audit"].get("cited", 0),
                "gates": gates,
            }
            manifest_path = out / "release-manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
            manifest_signature = sign(manifest_path, key, password, out)

        print(f"\nwrote {manifest_path}")
        print(f"  signed as {manifest_signature}")
        if args.push_to:
            # Only when there is a deployable manifest to bundle. Without
            # --push-to the images are local-only, so there is nothing a partner
            # could pull and a "bundle" would be a directory that cannot deploy.
            bundle = write_bundle(out, manifest, not args.signing_key)
            print(f"  partner bundle in {bundle.relative_to(out)}/ "
                  f"({len(list(bundle.iterdir()))} files, no source)")
        print(f"  {len(artifacts)} artifacts, "
              f"{len(skipped)} images skipped, frozen at {short}")
        print(f"  ledger audit covered {manifest['ledger_claims_audited']} claims "
              f"from {', '.join(manifest['ledgers_audited']) or 'NOTHING'}")
        if not args.signing_key:
            print("  NOTE: ephemeral key; these signatures anchor nothing "
                  "(see trust_anchor in the manifest)", file=sys.stderr)
        return 0

    except ReleaseRefused as exc:
        print(f"\nRELEASE REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

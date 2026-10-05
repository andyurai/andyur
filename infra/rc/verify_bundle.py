#!/usr/bin/env python3
"""Prove a partner bundle is deployable and contains NO SOURCE.

Andyur is distributed to design partners as images plus a deployment manifest.
The codebase is not shared. That claim is worth nothing unless something checks
it, which is the defect this repository has now found five times in one day: a
credential-confinement check run against a deleted container, a demo gate that
piped pytest into `tee` with no pipefail, a SPIRE gate whose `bad()` only
printed, an unconditional `ok` with no assertion behind it, and a release that
built on one machine. Each was a claim with nothing behind it.

So this asserts BOTH directions, because only asserting the positive is how
"no source" quietly stops being true:

  positively   the bundle holds the deployment manifest, the release manifest,
               a signature bundle for each, and verification instructions
  negatively   the bundle holds NO sdist, NO wheel, NO .py from the tree, and
               no archive of it

The negative half has a positive control of its own: `--self-test` plants an
sdist in a temporary bundle and REQUIRES the scan to find it. A scan that cannot
detect a planted source tarball proves nothing about one that arrives by
accident.
"""
from __future__ import annotations

import argparse
import re
import sys
import tarfile
import tempfile

import yaml
from pathlib import Path

# EVERY manifest a deployer applies, plus the two documents that tell them how.
#
# This required only the control plane, so a bundle that could not possibly come
# up -- no identity provider, no collector, and no statement of what must exist
# first -- passed as "deployable". The check was true about its own list and the
# list was wrong.
REQUIRED = ("control-plane.yaml", "idp.yaml", "observability.yaml",
            "run-isolation.yaml", "deploy.sh",
            "release-manifest.json", "VERIFY.md", "PREREQUISITES.md")
# The ones a partner is asked to TRUST, so each must arrive with its signature.
SIGNED = ("control-plane.yaml", "idp.yaml", "observability.yaml",
          "run-isolation.yaml", "deploy.sh", "release-manifest.json")
# Extensions that ARE source, or that carry it. .whl is bytecode rather than
# source, but it is trivially decompiled and it is not something a deployer
# needs when the images are pulled -- so it is excluded from the bundle too.
SOURCE_SUFFIXES = {".py", ".pyc", ".whl", ".tar.gz", ".tgz", ".zip", ".tar"}


def images_in(text: str) -> list[tuple[str, str]]:
    """(where, image) for every image a manifest actually runs.

    Two places, because Kubernetes has two: a container's `image`, and an env
    var naming an image the platform launches later -- the run proxy and agent
    are started by the daemon from ANDYUR_KUBERNETES_*_IMAGE, so a tag there is
    exactly as unpinned as one in a Pod spec and nothing in the manifest's
    container list would show it.
    """
    found: list[tuple[str, str]] = []
    for document in yaml.safe_load_all(text):
        for node in _walk(document):
            if not isinstance(node, dict):
                continue
            if isinstance(node.get("image"), str) and "name" in node:
                found.append((f"container {node['name']}", node["image"]))
            name, value = node.get("name"), node.get("value")
            if isinstance(name, str) and isinstance(value, str) \
                    and name.endswith("_IMAGE"):
                found.append((name, value))
    return found


def _walk(node):
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def source_like(path: Path) -> str | None:
    """Why this file is source, or None. Named so the failure says WHICH rule."""
    name = path.name
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return "an archive, which may carry the tree"
    if path.suffix == ".py":
        return "a Python source file"
    if path.suffix == ".pyc":
        return "compiled Python from the tree"
    if path.suffix == ".whl":
        return "a wheel; the deployer pulls images and needs no distribution"
    if path.suffix in {".zip", ".tar"}:
        return "an archive, which may carry the tree"
    return None


def check(bundle: Path) -> list[str]:
    problems: list[str] = []
    if not bundle.is_dir():
        return [f"{bundle} is not a directory"]

    present = {p.name for p in bundle.iterdir()}
    for required in REQUIRED:
        if required not in present:
            problems.append(f"missing required file: {required}")

    # A signature for each thing a partner is asked to trust. A manifest whose
    # own signature is absent is a document anyone can edit.
    for signed in SIGNED:
        if signed in present and f"{signed}.cosign-bundle.json" not in present:
            problems.append(f"{signed} ships without its signature bundle")

    for path in sorted(bundle.rglob("*")):
        if path.is_dir():
            continue
        why = source_like(path)
        if why:
            problems.append(f"SOURCE IN BUNDLE: {path.relative_to(bundle)} is {why}")

    # EVERY image, in every manifest, pinned by digest. A tag is a name someone
    # else can repoint, so a manifest that carries one has an identity that is
    # not its own -- and this bundle's whole claim is that what a deployer runs
    # is what was built and signed. Checked across all the manifests rather than
    # only the Andyur images: the identity provider shipped tag-pinned for a day
    # because nothing looked at anything but our own.
    #
    # PARSED, not grepped. The first version matched `image: (\S+)` over raw
    # text and refused a perfectly good bundle because a COMMENT contained the
    # words "image: `brokerstate_server". A check that reads YAML as prose finds
    # things that are not there.
    for name in SIGNED:
        manifest = bundle / name
        if manifest.suffix not in (".yaml", ".yml") or not manifest.is_file():
            continue
        for where, image in images_in(manifest.read_text()):
            if "registry.example" in image:
                problems.append(f"PLACEHOLDER IMAGE: {name} still names {image}")
            elif "@sha256:" not in image:
                problems.append(
                    f"UNPINNED IMAGE: {name} runs {image} ({where}), which is a tag")
    return problems


def self_test() -> int:
    """The negative control: plant an sdist and require the scan to find it."""
    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "bundle"
        bundle.mkdir()
        for required in REQUIRED:
            (bundle / required).write_text("placeholder\n")
        for signed in SIGNED:
            (bundle / f"{signed}.cosign-bundle.json").write_text("{}\n")

        clean = check(bundle)
        if clean:
            print("SELF-TEST FAILED: a clean bundle did not pass:", file=sys.stderr)
            for problem in clean:
                print(f"  {problem}", file=sys.stderr)
            return 1

        planted = bundle / "andyur-0.1.0.tar.gz"
        with tarfile.open(planted, "w:gz") as tar:
            src = Path(tmp) / "andyur" / "server" / "app.py"
            src.parent.mkdir(parents=True)
            src.write_text("# the codebase\n")
            tar.add(src, arcname="andyur/server/app.py")

        found = [p for p in check(bundle) if "SOURCE IN BUNDLE" in p]
        if not found:
            print("SELF-TEST FAILED: a planted sdist was NOT detected. This scan "
                  "proves nothing.", file=sys.stderr)
            return 1
        print("self-test ok: a clean bundle passes, and a planted sdist is caught")
        print(f"  {found[0]}")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", nargs="?", type=Path,
                        help="the partner bundle directory to check")
    parser.add_argument("--self-test", action="store_true",
                        help="prove the source scan can detect a planted sdist")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.bundle:
        parser.error("give a bundle directory, or --self-test")

    problems = check(args.bundle)
    if problems:
        print(f"BUNDLE REFUSED: {args.bundle}", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"bundle ok: {args.bundle} is deployable and carries no source")
    return 0


if __name__ == "__main__":
    sys.exit(main())

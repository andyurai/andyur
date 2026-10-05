#!/usr/bin/env python3
"""Put an RC verdict in the tree, beside the tag it certifies.

WHY THIS EXISTS. The gate writes its verdict into gitignored `data/rc/` on
purpose: the verdict binds the sha256 of every gate script it ran, so a verdict
committed into the tree is release-blocking evidence that goes STALE the moment
any of those gates is edited -- including by the very next commit. Leaving it
gitignored keeps the tree from being permanently red; leaving it ONLY there
means the record of why a tag was cut lives in a directory nobody clones.

So it is published deliberately, at tag time, under the tag's own name. From
then on it is exactly what it should be: a claim about ONE commit, which
staleness against later commits does not touch, because the file names the
commit it is about.

    python3 infra/rc/publish-verdict.py data/rc/result-rc-gate-....json v0.1.0-rc1

Refusals, all of them because publishing the wrong thing is worse than
publishing nothing:

  NO-GO           a verdict that is not GO is not a release record
  wrong commit    the tag must point at the commit the gate froze
  already there   a published verdict is never silently overwritten
  stale binding   a gate the verdict names has changed since it ran, so the
                  verdict is no longer a claim about the programs in this tree

It prints the tag annotation to use, including the two facts the review found
missing from the last one: how many lines, and whether it was one pass.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLISHED = ROOT / "docs" / "releases"


def die(message: str) -> None:
    sys.exit(f"REFUSED: {message}")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True).stdout.strip()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return int(bool(sys.stderr.write(
            "usage: publish-verdict.py <verdict.json> <tag>\n")) or 2)
    verdict_path, tag = Path(argv[1]), argv[2]
    if not verdict_path.is_file():
        die(f"{verdict_path} does not exist")
    doc = json.loads(verdict_path.read_text())

    if doc.get("verdict") != "GO":
        die(f"the verdict is {doc.get('verdict')!r}; only a GO is a release record")

    sha = doc.get("frozen_commit") or ""
    tagged = git("rev-list", "-n", "1", tag)
    if not tagged:
        die(f"no tag named {tag!r} in this repository")
    if tagged != sha:
        die(f"{tag} points at {tagged[:12]}, but this verdict certifies "
            f"{sha[:12]}; a verdict published under a tag it does not describe "
            "is worse than no verdict")

    # THE BINDING, RE-CHECKED AT PUBLISH TIME. The verdict names the sha256 of
    # every gate it ran. If one of those files has changed since, the verdict
    # describes programs that are no longer here -- which is exactly the
    # staleness rule the rest of this repository enforces, applied to the
    # artifact that sits above all of them.
    stale = []
    for path, recorded in sorted((doc.get("source_sha256") or {}).items()):
        target = ROOT / path
        if not target.is_file():
            stale.append(f"{path} (gone)")
        elif hashlib.sha256(target.read_bytes()).hexdigest() != recorded:
            stale.append(f"{path} (changed)")
    if stale:
        die("the verdict binds gates that have since changed, so it is no "
            "longer a claim about this tree:\n  " + "\n  ".join(stale) +
            "\n  re-run the gate on the tagged commit")

    PUBLISHED.mkdir(parents=True, exist_ok=True)
    out = PUBLISHED / f"{tag}.rc-gate.json"
    if out.exists():
        die(f"{out.relative_to(ROOT)} already exists; a published verdict is "
            "never silently replaced")
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")

    declared = doc.get("declared_lines", doc.get("passed"))
    single = doc.get("single_pass")
    print(f"wrote {out.relative_to(ROOT)}")
    print("\ncommit it, then use this annotation (it says the two things the")
    print("last one did not -- how many lines, and whether it was one pass):\n")
    print(f"  {tag}")
    print(f"  RC gate GO: {doc.get('passed')} of {declared} lines, "
          f"frozen at {sha[:12]}.")
    if single is True:
        print("  One pass, from a clean start.")
    elif single is False:
        merged = ", ".join(doc.get("lines_merged_from_an_earlier_run") or []) or "unrecorded"
        print(f"  NOT one pass: {merged} came from an earlier run of this commit.")
    else:
        print("  (this verdict predates the resumed/single-pass record)")
    print(f"  Verdict: docs/releases/{out.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

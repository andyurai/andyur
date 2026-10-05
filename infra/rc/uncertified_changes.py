#!/usr/bin/env python3
"""Which uncommitted changes this RC run has NOT already accounted for.

Prints one path per line; empty output means the tree is certifiable.

A green RC run leaves the tree dirty by design -- the live gate lines write
evidence into it, and that evidence is the record of the commit's behaviour.
So a resumed pass would refuse on the previous pass's own output unless
something knows the difference between "the gate wrote this" and "somebody
edited this". That is the whole job here.

The allowance is deliberately narrow: only when RESUMING, only for paths the
artifact for THIS EXACT COMMIT recorded as evidence it produced. A source edit,
a stray file, or a resume across commits is still an uncertified change,
because what "one frozen tree" forbids is certifying two different trees as one.
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys

# What an evidence artifact LOOKS like. The allowance requires both this and a
# record in the previous run's `evidence_produced`, because those two are
# different claims: the record says the gate wrote it, and this says it is the
# kind of file a gate is allowed to write. Without the second, a source file
# that happened to land in the recorder's list would be certified as unchanged
# -- which is not a hole anyone would notice until it mattered.
EVIDENCE_SHAPES = ("*/result-*.json", "result-*.json", "*/evidence/*")


def _looks_like_evidence(path: str) -> bool:
    return any(fnmatch.fnmatch(path, shape) for shape in EVIDENCE_SHAPES)


def uncertified(here: str, artifact: str, sha: str, only: str) -> list[str]:
    changed = [
        line[3:] for line in subprocess.run(
            ["git", "status", "--porcelain", "--", "."], cwd=here,
            capture_output=True, text=True, check=True).stdout.splitlines()
        if line.strip()
    ]
    allowed: set[str] = set()
    if only and os.path.exists(artifact):
        previous = json.load(open(artifact))
        # The commit is the whole point of the check, so it is the whole point
        # of the exception too.
        if previous.get("frozen_commit") == sha:
            allowed = set(previous.get("evidence_produced", []))
    return [path for path in changed
            if not (path in allowed and _looks_like_evidence(path))]


if __name__ == "__main__":
    here, artifact, sha, only = (sys.argv + ["", "", "", ""])[1:5]
    print("\n".join(uncertified(here, artifact, sha, only)))

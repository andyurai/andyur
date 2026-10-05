#!/usr/bin/env python3
"""Check that every commit the ledgers call "landed" is really in the release.

`CONTEXT.md` and `.session-sync.md` cite commit SHAs and say things like
"landed/pushed". Several of those claims turned out to be true only on a branch
that was never merged, which is how an OPA fix sat outside `main` for a day
while the ledger said it had shipped. Before a freeze means anything, every such
claim has to be checked against the commit actually being released.

WHY THIS IS NOT `git merge-base --is-ancestor`. That was the first version of
this check and it is wrong, because it answers a question about commit IDENTITY
when the thing that matters is commit CONTENT. Squash and cherry-pick both put
the content on `main` under a new hash and orphan the original, so a pure
ancestry test reports a false alarm for every one of them. On the tree this was
written against, 22 cited commits were not ancestors and only a handful of those
were real gaps.

So each cited commit is classified by how its content reached the release:

  LANDED       an ancestor of the release ref; nothing more to prove
  CHERRY-PICKED  same patch-id as a commit on the release ref
  PENDING      not on the release ref, but its content is on a known branch
               (usually an open PR); correctly absent, named so it can be tracked
  SUPERSEDED   orphaned, but the lines it added are present on the release ref,
               which is what a squash merge or a later rename looks like
  ABSENT       orphaned and its added lines are nowhere; a ledger that calls this
               one "landed" is making a claim the release cannot support

SUPERSEDED and ABSENT are separated by a line-presence heuristic, and it IS a
heuristic. Two structural effects made the first version report four false
ABSENTs, and both are corrected here rather than special-cased:

  1. A rebased branch orphans its old commits, so the pre-rebase versions of the
     Curity work matched nothing on `main` while their content sat safely on the
     open PR branch under new hashes. Presence is therefore checked against every
     known ref, not just the release ref, before anything is called missing.

  2. `38ae2b7` renamed Colony to Andyur across the whole tree, so every 2026-08-08
     commit's added lines stopped matching verbatim even though they landed. Line
     comparison is normalised through that one documented global rename.

The score is always printed rather than hidden behind the verdict. The tool
narrows 900 commits to a handful worth reading; it does not replace reading them.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SHA_RE = re.compile(r"\b[0-9a-f]{7,40}\b")

# An added line has to carry some signal before its presence means anything.
# Bare punctuation, `else:`, and short fragments appear in every file and would
# make any commit look present.
MIN_LINE_LEN = 12

# Below this fraction of added lines found on the release ref, the commit is
# reported ABSENT for a human to read. Chosen so a squash merge (which lands the
# lines verbatim) passes comfortably while a genuinely missing commit does not.
PRESENCE_THRESHOLD = 0.60

# One documented tree-wide rename, `38ae2b7 rename: Colony -> Andyur across
# agentic-platform + CI workflow`. Commits predating it added lines that are
# still on the release ref under the new name, so a verbatim comparison scores
# them as missing. Normalising through the rename is the difference between
# "this 2026-08-08 commit vanished" and "this commit landed and was renamed".
# Keep this list to renames that actually happened, each with its commit.
GLOBAL_RENAMES: tuple[tuple[str, str], ...] = (
    ("colony", "andyur"),
)


def normalise(line: str) -> str:
    """Compare lines through the documented global renames, case-insensitively."""
    text = line.strip().lower()
    for old, new in GLOBAL_RENAMES:
        text = text.replace(old, new)
    return text


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(("git",) + args, cwd=cwd, capture_output=True,
                          text=True).stdout


def git_ok(*args: str, cwd: Path) -> bool:
    return subprocess.run(("git",) + args, cwd=cwd,
                          capture_output=True).returncode == 0


@dataclass
class Finding:
    sha: str
    subject: str = ""
    verdict: str = ""
    detail: str = ""
    presence: float | None = None
    branches: list[str] = field(default_factory=list)


def cited_shas(repo: Path, sources: list[Path]) -> tuple[list[str], dict]:
    """Every hex token in the ledgers that actually resolves to a commit.

    Also reports WHICH ledgers were read. `.session-sync.md` is gitignored and
    machine-local, so it is absent from a fresh clone, from CI, and from any git
    worktree. Auditing only `CONTEXT.md` there silently cut coverage from 283
    cited commits to 92, and the run looked identical. A gate that quietly
    inspects a third of its input reads exactly like one that inspected all of
    it, so coverage is recorded rather than assumed.
    """
    seen: set[str] = set()
    coverage = {"read": [], "absent": []}
    for source in sources:
        if not source.is_file():
            coverage["absent"].append(source.name)
            continue
        coverage["read"].append(source.name)
        for token in SHA_RE.findall(source.read_text(errors="replace")):
            seen.add(token)
    resolved = []
    for token in sorted(seen):
        if git("cat-file", "-t", token, cwd=repo).strip() == "commit":
            resolved.append(token)
    return resolved, coverage


def patch_id_map(repo: Path, ref: str) -> dict[str, str]:
    """patch-id -> commit, for every commit reachable from the release ref.

    Built once. This is what catches cherry-picks, where the content landed
    under a different hash.
    """
    out = git("log", "--format=%H", ref, cwd=repo).split()
    mapping: dict[str, str] = {}
    for commit in out:
        diff = subprocess.run(("git", "diff-tree", "-p", commit), cwd=repo,
                              capture_output=True, text=True).stdout
        if not diff:
            continue
        pid = subprocess.run(("git", "patch-id", "--stable"), input=diff,
                             cwd=repo, capture_output=True, text=True).stdout.split()
        if pid:
            mapping[pid[0]] = commit
    return mapping


def commit_patch_id(repo: Path, sha: str) -> str | None:
    diff = subprocess.run(("git", "diff-tree", "-p", sha), cwd=repo,
                          capture_output=True, text=True).stdout
    if not diff:
        return None
    pid = subprocess.run(("git", "patch-id", "--stable"), input=diff, cwd=repo,
                         capture_output=True, text=True).stdout.split()
    return pid[0] if pid else None


def added_lines(repo: Path, sha: str) -> dict[str, list[str]]:
    """Meaningful lines the commit added, per file."""
    diff = git("show", "--format=", "--unified=0", sha, cwd=repo)
    per_file: dict[str, list[str]] = {}
    current = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            per_file.setdefault(current, [])
        elif line.startswith("+") and not line.startswith("+++") and current:
            text = line[1:].strip()
            if len(text) >= MIN_LINE_LEN:
                per_file[current].append(text)
    return {path: lines for path, lines in per_file.items() if lines}


def presence_on_ref(repo: Path, sha: str, ref: str) -> tuple[float | None, str]:
    """Fraction of the commit's added lines that appear on the given ref."""
    per_file = added_lines(repo, sha)
    if not per_file:
        return None, "commit adds no substantive lines to compare"
    total = found = 0
    missing_files = []
    for path, lines in per_file.items():
        blob = git("show", f"{ref}:{path}", cwd=repo)
        if not blob:
            missing_files.append(path)
            total += len(lines)
            continue
        haystack = {normalise(line) for line in blob.splitlines()}
        total += len(lines)
        found += sum(1 for line in lines if normalise(line) in haystack)
    detail = f"{found}/{total} added lines present"
    if missing_files:
        detail += f"; file(s) not on ref: {', '.join(sorted(missing_files)[:3])}"
    return (found / total if total else None), detail


def ever_present_on(repo: Path, sha: str, ref: str) -> tuple[str, str] | None:
    """Did this commit's added lines ever exist on the ref, even if gone now?

    Uses git's pickaxe over the commit's most distinctive added lines. A hit
    means the content reached the ref and something later removed it, which is a
    deliberate deletion rather than a claim the release cannot support. Returns
    Returns one commit that changed that content's occurrences on the ref, as
    evidence the content was there, or None if it never appeared at all. This
    deliberately does NOT claim to name the removal: it samples a few lines, so
    the commit it returns is a witness that the content existed, not necessarily
    the one that deleted it.
    """
    per_file = added_lines(repo, sha)
    for path, lines in per_file.items():
        # Longest lines first: the most distinctive, least likely to collide.
        for line in sorted(lines, key=len, reverse=True)[:3]:
            out = git("log", "--format=%H%x00%s", "-S", line, ref, "--", path,
                      cwd=repo).strip()
            if out:
                newest = out.splitlines()[0]
                commit, _, subject = newest.partition("\x00")
                return commit, subject
    return None


def candidate_refs(repo: Path, release_ref: str) -> list[str]:
    """Every remote branch, so a rebased-but-pending commit is not called missing."""
    refs = [line.strip() for line in
            git("for-each-ref", "--format=%(refname:short)",
                "refs/remotes/origin", cwd=repo).splitlines() if line.strip()]
    return [r for r in refs if r != release_ref and not r.endswith("/HEAD")]


def classify(repo: Path, sha: str, ref: str, pids: dict[str, str]) -> Finding:
    finding = Finding(sha=sha,
                      subject=git("log", "-1", "--format=%s", sha, cwd=repo).strip())

    if git_ok("merge-base", "--is-ancestor", sha, ref, cwd=repo):
        finding.verdict = "LANDED"
        return finding

    pid = commit_patch_id(repo, sha)
    if pid and pid in pids:
        finding.verdict = "CHERRY-PICKED"
        finding.detail = f"same patch-id as {pids[pid][:9]} on {ref}"
        return finding

    branches = [b.strip().lstrip("* +") for b in
                git("branch", "-a", "--contains", sha, cwd=repo).splitlines()
                if b.strip() and not b.strip().startswith("(")]
    finding.branches = branches
    if branches:
        finding.verdict = "PENDING"
        finding.detail = "on " + ", ".join(sorted(set(branches))[:3])
        return finding

    score, detail = presence_on_ref(repo, sha, ref)
    finding.presence = score
    finding.detail = detail
    if score is not None and score >= PRESENCE_THRESHOLD:
        finding.verdict = "SUPERSEDED"
        return finding

    # Not on the release ref. Before calling it missing, look everywhere else: a
    # rebased branch orphans its old commits while the content sits on the open
    # PR under a new hash, and that is pending work, not a lost fix.
    for other in candidate_refs(repo, ref):
        other_score, other_detail = presence_on_ref(repo, sha, other)
        if other_score is not None and other_score >= PRESENCE_THRESHOLD:
            finding.verdict = "PENDING"
            finding.presence = other_score
            finding.detail = f"content on {other} ({other_detail}); orphaned pre-rebase hash"
            return finding

    # Still nowhere in the current trees. One honest possibility remains: the
    # content landed and was later deliberately DELETED. `85f4806` is the case
    # that forced this branch -- it landed as `6c8bd6a` and `3c7fe9f` removed it
    # when the transitional agentgateway path was retired. The ledger's "landed"
    # claim was true, so calling it ABSENT would manufacture a phantom finding.
    removed_by = ever_present_on(repo, sha, ref)
    if removed_by:
        finding.verdict = "LANDED-THEN-REMOVED"
        finding.detail = (f"content was on {ref}; witnessed by "
                          f"{removed_by[0][:9]} {removed_by[1][:48]}")
        return finding

    finding.verdict = "ABSENT"
    return finding


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify ledger 'landed' claims against the release commit.")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--ref", default="origin/main",
                        help="the release ref to audit against")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    sources = [repo / "CONTEXT.md", repo / ".session-sync.md"]
    shas, coverage = cited_shas(repo, sources)
    if not shas:
        print("no commit SHAs found in the ledgers", file=sys.stderr)
        return 2

    pids = patch_id_map(repo, args.ref)
    findings = [classify(repo, sha, args.ref, pids) for sha in shas]
    interesting = [f for f in findings if f.verdict != "LANDED"]
    absent = [f for f in findings if f.verdict == "ABSENT"]

    if args.json:
        print(json.dumps({"ref": args.ref, "cited": len(findings),
                          "ledgers_read": coverage["read"],
                          "ledgers_absent": coverage["absent"],
                          "findings": [vars(f) for f in interesting]},
                         indent=2, sort_keys=True))
        return 1 if absent else 0

    print(f"audited {len(findings)} cited commits against {args.ref}")
    print(f"  ledgers read: {', '.join(coverage['read']) or 'NONE'}")
    if coverage["absent"]:
        print(f"  ledgers ABSENT (not audited): {', '.join(coverage['absent'])}")
    print()
    for verdict in ("CHERRY-PICKED", "PENDING", "SUPERSEDED", "LANDED-THEN-REMOVED", "ABSENT"):
        group = [f for f in interesting if f.verdict == verdict]
        if not group:
            continue
        print(f"--- {verdict} ({len(group)})")
        for f in group:
            score = "" if f.presence is None else f" [{f.presence:.0%}]"
            print(f"  {f.sha}{score}  {f.subject[:64]}")
            if f.detail:
                print(f"      {f.detail}")
        print()

    landed = len(findings) - len(interesting)
    print(f"{landed} landed, {len(interesting)} need explanation, "
          f"{len(absent)} ABSENT")
    if absent:
        print("\nABSENT commits are cited by the ledgers but their content is not on "
              f"{args.ref}. Read each one before freezing.")
    return 1 if absent else 0


if __name__ == "__main__":
    sys.exit(main())

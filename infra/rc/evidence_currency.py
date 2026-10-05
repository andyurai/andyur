#!/usr/bin/env python3
"""Bind every live-gate evidence artifact to the source tree it was produced from.

A release candidate has to answer one question about each `result-*.json` in the
tree: does this evidence still describe THIS source, or does it describe source
that has since changed? Andyur's live gates already record the answer. Each gate
writes the sha256 of the exact files it exercised into its result, and per-gate
currency tests re-check those hashes. This tool generalises that discipline into
one tree-wide check, so the release candidate does not depend on someone
remembering to write a currency test for each new artifact.

Evidence is bound to per-file hashes rather than to a commit SHA on purpose. A
commit SHA would mark every artifact stale on every unrelated merge, which
trains people to ignore the signal. File hashes go stale only when the code the
gate actually exercised changes, which is exactly when the gate must be re-run.

WHY THERE IS A REGISTRY BELOW, AND NOT INFERENCE. The gates were written
independently and do not share one convention. `verify-network-policy.sh:268`
keys its map by BASENAME; `verify-broker-semantic-wire.py:203` keys the same
field by repo-relative PATH. `gate_sha256` means `infra/byoa-spike/byoa_gate.py`
in a BYOA result but means the gate hashing ITSELF in
`infra/sender-binding-spike/phase1_gate.py:547`. And some `*_sha256` fields are
not source bindings at all: the semantic-wire `config_sha256` hashes Envoy
configs generated into a temp directory, and `verify-actor-proof.sh:523` keys
`mutation_source_sha256` by MUTATION NAME over files in an ephemeral work dir.
Inferring a convention from field names therefore produces confident, wrong
staleness claims. The convention belongs to the gate that wrote the artifact, so
it is declared here, per gate, with the line it was derived from.

Four outcomes, all reported, because a check that quietly ignores what it cannot
inspect reads like a pass:

  CURRENT     every binding resolved and matched the tree
  STALE       a binding RESOLVED and its hash disagreed, or a file the
              convention DECLARES to be tree source has vanished; the gate that
              produced this artifact MUST be re-run before release. A file that
              merely fails to resolve is UNBOUND, not STALE (see below)
  UNBOUND     the artifact records no binding, records one this tool cannot
              resolve to a tree file, or records a scalar hash whose file is not
              declared in the registry; coverage debt, listed by name
  HISTORICAL  superseded exploration evidence, explicitly declared out of the
              release-candidate set below with the reason

A STALE verdict is only ever reported when a file was actually resolved and its
hash actually differed. An unresolvable binding is never reported as stale,
because absence of proof that evidence is current is not proof that it is stale.

Exit status is non-zero when anything is STALE.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

_HEX_LEN = 64


@dataclass(frozen=True)
class Convention:
    """How one gate family records the source it exercised.

    map_base   directory that basename-keyed `*_sha256` maps resolve against;
               None means the keys are already repo-relative paths
    scalars    scalar `*_sha256` field -> the repo-relative file it hashes,
               or an ARTIFACT-relative one (`../agent.json`): resolved from
               the artifact's own directory, so one convention serves every
               `demos/<name>/evidence/` without a line per demo
    ignore     `*_sha256` fields that are NOT source bindings, mapped to WHY.
               The reason is mandatory and machine-checked. `ignore` is the
               fail-open lever for this whole tool, because anything named here
               stops being verified by anything. HISTORICAL carries reasons and
               is ratcheted; a bare set let a field be exempted by adding one
               word, with a test whose name promised a reason check it could not
               perform (PR #8 re-review, LOW).
    """

    map_base: str | None = None
    scalars: dict[str, str] = field(default_factory=dict)
    ignore: dict[str, str] = field(default_factory=dict)


# Keyed by glob over the repo-relative artifact path. The FIRST match wins, so
# order from most specific to least. Every entry cites the line it was derived
# from; none of it is inferred from field names.
REGISTRY: tuple[tuple[str, Convention], ...] = (
    # verify-network-policy.sh:268 keys by basename; all three live here.
    ("infra/kubernetes/result-network-policy-*.json",
     Convention(map_base="infra/kubernetes")),

    # verify-broker-semantic-wire.py:203 keys by repo-relative path.
    ("infra/kubernetes/result-broker-semantic-wire-*.json",
     Convention(ignore={
         "config_sha256": "hashes Envoy configs generated into a temp dir "
                          "(verify-broker-semantic-wire.py:103), so it describes "
                          "gate inputs, never tree source",
         "registry_sha256": "lives under positive.state: a field of the "
                            "broker-state payload the gate OBSERVED, not a file",
     })),

    # exec_v1_gate.py (ADR-011 D8) binds its artifact to ITS OWN source and to
    # the manifest it ran; input_sha256 hashes the delivered run input, a value
    # the gate produced, and image/command are named, not hashed here. ONE
    # convention for every stock-workload demo (demos/<name>/evidence/), the
    # manifest being the sibling agent.json -- OpenSRE, Goose, the next one.
    ("demos/*/evidence/result-exec-v1-*.json",
     Convention(scalars={"exec_gate_sha256": "infra/byoa-spike/exec_v1_gate.py",
                         "manifest_sha256": "../agent.json"},
                ignore={"input_sha256": "hashes the run INPUT the gate delivered "
                                        "(exec_v1_gate.py), a produced value"})),

    # verify-exec-input.py keys source_sha256 and executed_source_sha256 by
    # repo-relative path (the default). expected_sha256 is NOT a file: it hashes
    # the run's INPUT payload the gate delivered, a value the gate produced.
    ("infra/kubernetes/result-exec-input-*.json",
     Convention(ignore={
         "expected_sha256": "hashes the run INPUT payload the gate delivered "
                            "(verify-exec-input.py), a produced value not a tree file",
     })),

    # verify-run-singleton.py:264 and verify-broker-lifecycle.py:278,286 both
    # key by repo-relative path, which is the default convention.
    ("infra/kubernetes/result-*.json",
     Convention(ignore={
         "api_server_sha256": "identifies the CLUSTER the gate ran against, "
                              "not a file in this tree",
     })),

    # deny_only_envoy_gate.py:276 keys by repo-relative path.
    ("infra/authorization-broker/result-*.json",
     Convention(ignore={
         "secure_config_sha256": "hashes the Envoy config the gate renders "
                                 "(deny_only_envoy_gate.py:276), not tree source",
     })),

    # bplus-spike/gate_a.py records source_sha256 by repo-relative path, the
    # default; api_server_sha256 identifies the cluster it ran against.
    ("infra/bplus-spike/result-*.json",
     Convention(ignore={
         "api_server_sha256": "identifies the CLUSTER the gate ran against, "
                              "not a file in this tree",
     })),

    # verify-rfc7523.py:446-448 keys by repo-relative path, the default.
    ("infra/curity/result-*.json", Convention()),

    # verify-rc-gate.sh records source_sha256 by repo-relative path for the
    # EVERY GATE SCRIPT IT RAN, so an RC verdict goes stale the moment any
    # gate it executed changes. That is the point of the binding: the verdict
    # is a claim about those programs, and a claim about a program that has
    # since changed is not evidence.
    ("infra/rc/result-rc-gate-*.json", Convention()),

    # The BYOA gates record their scalars, resolved by hashing the tree and
    # matching the recorded digests rather than by reading the field names.
    # agent_py/dockerfile come from byoa_gate.py:641-644 over AGENT_DIR
    # (:109 = demos/byoa-hello-agent). Both are null when the gate ran an
    # EXTERNAL_IMAGE, and a null is not a digest, so on those artifacts they
    # bind nothing rather than binding the wrong file.
    ("infra/byoa-spike/result-*.json",
     Convention(scalars={"gate_sha256": "infra/byoa-spike/byoa_gate.py",
                         "harness_sha256": "infra/byoa-spike/runtime_v1.py",
                         "exec_gate_sha256": "infra/byoa-spike/exec_v1_gate.py",
                         "agent_py_sha256": "demos/byoa-hello-agent/agent.py",
                         "dockerfile_sha256": "demos/byoa-hello-agent/Dockerfile"})),
)

# Explicitly out of the release-candidate evidence set. Each entry names WHY, and
# nothing is classified historical by inference: an artifact must be listed here
# by name. This is the one place the RC's evidence scope is narrowed, so the
# narrowing can be reviewed rather than discovered.
HISTORICAL: dict[str, str] = {
    "infra/result-actor-proof-2026-08-14-macos-arm64.json":
        "actor-proof feasibility spike; verify-actor-proof.sh:523 keys its "
        "mutation hashes by mutation name over Go sources built in an ephemeral "
        "work dir, so nothing in it binds to the shipped tree",
    "infra/oauth-client-bakeoff/result-2026-08-14-macos-arm64.json":
        "one-off client-library bake-off recorded for the ADR; exercises "
        "third-party libraries, not Andyur source",
    "infra/sender-binding-spike/result-2026-08-14-macos-arm64.json":
        "sender-binding phase-1 spike, superseded by the shipped DPoP/mTLS path",
    "infra/sender-binding-spike/result-envoy-feasibility-2026-08-14-macos-arm64.json":
        "Envoy feasibility spike that preceded the shipped broker composition",
    "infra/sender-binding-spike/result-envoy-runtime-2026-08-14-macos-arm64.json":
        "Envoy runtime spike that preceded the shipped broker composition",
    "infra/sender-binding-spike/result-phase2a-2026-08-14-macos-arm64.json":
        "sender-binding phase-2a spike, superseded by the shipped path",
    "infra/sender-binding-spike/result-phase2b-2026-08-14-macos-arm64.json":
        "sender-binding phase-2b spike, superseded by the shipped path",
    "infra/byoa-spike/result-frameworks-2026-08-15.json":
        "framework survey recorded for adr-008; exercises third-party agent "
        "frameworks, not Andyur source",
}


def convention_for(name: str) -> Convention | None:
    for pattern, convention in REGISTRY:
        if fnmatch.fnmatch(name, pattern):
            return convention
    return None


def _is_digest(value: object) -> bool:
    return (isinstance(value, str) and len(value) == _HEX_LEN
            and all(c in "0123456789abcdef" for c in value))


@dataclass
class Binding:
    """One recorded hash and the file it claims to describe.

    `path` is None when the artifact records a scalar hash whose file the
    registry does not declare. Such a binding must surface as UNBOUND: dropping
    it silently let an artifact report CURRENT while a hash it recorded was
    never checked by anything.
    """

    field_name: str
    path: str | None
    recorded: str


def bindings_in(node: object, convention: Convention) -> Iterator[Binding]:
    """Yield every source binding an artifact records under its convention.

    Recurses, because gates nest their inputs: the BYOA gates record theirs
    under an `inputs` object and a top-level-only walk would miss them.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key.endswith("_sha256") and key in convention.ignore:
                continue
            if key.endswith("_sha256") and isinstance(value, dict):
                for raw, digest in value.items():
                    if not isinstance(raw, str) or not _is_digest(digest):
                        continue
                    path = (f"{convention.map_base}/{raw}"
                            if convention.map_base else raw)
                    yield Binding(key, path, digest)
                continue
            if key.endswith("_sha256") and _is_digest(value):
                # A scalar hash names no file, so the registry must say which
                # one it is. Unregistered means unverifiable, and unverifiable
                # must be reported rather than dropped.
                yield Binding(key, convention.scalars.get(key), value)
                continue
            yield from bindings_in(value, convention)
    elif isinstance(node, list):
        for item in node:
            yield from bindings_in(item, convention)


@dataclass
class Verdict:
    verdict: str
    checked: int = 0
    reasons: list[str] = field(default_factory=list)
    note: str = ""


def classify(artifact: Path, root: Path) -> Verdict:
    name = str(artifact.relative_to(root))
    if name in HISTORICAL:
        return Verdict("HISTORICAL", note=HISTORICAL[name])

    convention = convention_for(name)
    if convention is None:
        return Verdict("UNBOUND", note="no recorded convention for this gate")

    try:
        decoded = json.loads(artifact.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        # Unreadable evidence cannot be shown to describe this tree, and for a
        # release that is indistinguishable from evidence that disagrees.
        return Verdict("STALE", reasons=[f"unreadable ({exc})"])

    found = list(bindings_in(decoded, convention))
    if not found:
        return Verdict("UNBOUND", note="records no source binding")

    reasons: list[str] = []
    unresolved: list[str] = []
    for binding in found:
        if binding.path is None:
            unresolved.append(f"{binding.field_name} (scalar hash, no file "
                              "declared for it in REGISTRY)")
            continue
        if binding.path.startswith(("./", "../")):
            # artifact-relative (the demo's own manifest beside its evidence)
            target = (artifact.parent / binding.path).resolve()
            shown = str(target.relative_to(root.resolve())) if target.is_relative_to(root.resolve()) else binding.path
        else:
            target = root / binding.path
            shown = binding.path
        if not target.is_file():
            # Only a binding the convention says IS tree source can be stale by
            # absence. Anything else is a gap in this tool's knowledge, and is
            # reported as unresolved rather than asserted to be stale.
            if convention.map_base is not None or binding.path in convention.scalars.values():
                reasons.append(f"{shown}: recorded by {binding.field_name} "
                               "but absent from the tree")
            else:
                unresolved.append(f"{binding.path} (from {binding.field_name})")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != binding.recorded:
            reasons.append(f"{shown}: {binding.field_name} recorded "
                           f"{binding.recorded[:12]}, tree has {actual[:12]}")

    if reasons:
        return Verdict("STALE", checked=len(found), reasons=reasons)
    if unresolved:
        return Verdict("UNBOUND", checked=len(found),
                       note="unresolvable bindings: " + ", ".join(unresolved))
    return Verdict("CURRENT", checked=len(found))


def find_artifacts(root: Path) -> list[Path]:
    """Every artifact THE TREE SHIPS.

    Gitignored paths are not shipped, and scanning them produces confident
    nonsense: the RC gate writes its verdict into the gitignored data
    directory, and this reported it UNBOUND -- "evidence nobody can check"
    about a file nobody receives. A run's scratch output is not a claim the
    release makes.

    Asked of git rather than pattern-matched, so it stays true when .gitignore
    changes and needs no second copy of what is ignored here.
    """
    found = sorted(p for p in root.rglob("result-*.json")
                   if ".venv" not in p.parts and "node_modules" not in p.parts)
    if not found:
        return []
    ignored = subprocess.run(
        ["git", "check-ignore", "--stdin"], cwd=root, text=True,
        input="\n".join(str(p) for p in found), capture_output=True)
    # `check-ignore` exits 1 when nothing matched, which is not an error here.
    skip = {line.strip() for line in ignored.stdout.splitlines() if line.strip()}
    return [p for p in found if str(p) not in skip and str(p.resolve()) not in skip]


def build_report(root: Path) -> dict[str, Verdict]:
    return {str(a.relative_to(root)): classify(a, root) for a in find_artifacts(root)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check live-gate evidence against the current source tree.")
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[2],
                        help="the agentic-platform root (default: inferred)")
    parser.add_argument("--json", action="store_true",
                        help="emit the classification for the release manifest")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    report = build_report(root)
    by = lambda v: [n for n, r in report.items() if r.verdict == v]  # noqa: E731

    if args.json:
        print(json.dumps({
            "artifacts": {n: {"verdict": r.verdict, "bindings": r.checked,
                              "reasons": r.reasons, "note": r.note}
                          for n, r in report.items()},
            "summary": {v.lower(): len(by(v)) for v in
                        ("CURRENT", "STALE", "UNBOUND", "HISTORICAL")},
        }, indent=2, sort_keys=True))
        # UNBOUND is a FAILURE too (R, PR #25): an artifact whose bindings cannot be
        # resolved -- a source it names is absent from the tree -- is evidence nobody
        # can check, and exiting 0 on it made this gate fail OPEN. That is how a
        # board artifact naming a gate script from another branch reached a PR.
        return 1 if (by("STALE") or by("UNBOUND")) else 0

    for name in by("CURRENT"):
        print(f"CURRENT     {name}  ({report[name].checked} bindings)")
    for name in by("HISTORICAL"):
        print(f"HISTORICAL  {name}\n              {report[name].note}")
    for name in by("UNBOUND"):
        print(f"UNBOUND     {name}\n              {report[name].note}")
    for name in by("STALE"):
        print(f"STALE       {name}")
        for reason in report[name].reasons:
            print(f"              {reason}")

    print(f"\n{len(by('CURRENT'))} current, {len(by('STALE'))} stale, "
          f"{len(by('UNBOUND'))} unbound, {len(by('HISTORICAL'))} historical, "
          f"{len(report)} artifacts")
    if by("STALE"):
        print("\nre-run the gates that produced the STALE artifacts before releasing")
    if by("UNBOUND"):
        print("\nan UNBOUND artifact names a source this tree does not have: it is "
              "evidence nobody can check")
    return 1 if (by("STALE") or by("UNBOUND")) else 0


if __name__ == "__main__":
    sys.exit(main())

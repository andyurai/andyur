"""The release-candidate evidence binding rules.

`infra/rc/evidence_currency.py` decides whether each live-gate artifact still
describes the tree it is committed beside. These tests cover the decision, not
the helper: a checker that is merely runnable proves nothing, and one that
reports everything stale is as useless as one that reports nothing stale. So
every refusal here is paired with a positive control that must stay green.

The load-bearing case is `test_unresolvable_binding_is_never_reported_stale`.
The first version of the checker inferred a binding convention from field names
and confidently reported six artifacts stale that were not: it read
`gate_sha256` in a sender-binding result as if it named the BYOA gate, and read
temp-directory config hashes as if they named tree source. Absence of proof that
evidence is current is not proof that it is stale, and an RC gate that cries
wolf gets waived. That distinction is what these tests pin.
"""

from pathlib import Path
import hashlib
import importlib.util
import json
import sys

import pytest

ROOT = Path(__file__).parents[1]


def _load(name: str):
    """Load a tool from infra/rc/ without putting that directory on sys.path.

    `sys.path.insert` would be a global mutation that outlives this module and
    could shadow imports for every test that runs after it, which is precisely
    the mutable-global pollution the order-randomised suite check exists to
    catch. The tools are scripts, not an installed package, so load by path.

    The module still has to be registered in `sys.modules` before it executes:
    `@dataclass` resolves `cls.__module__` through that table, and without the
    entry the decorator raises during import. Registering one uniquely-named
    module is bounded; adding a directory to the import path is not.
    """
    spec = importlib.util.spec_from_file_location(name, ROOT / "infra" / "rc" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ec = _load("evidence_currency")


def _write(tmp_path: Path, name: str, payload: dict) -> Path:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))
    return target


def _sha_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Deliberately EMPTY, and it stays that way.
#
# This existed for one entry while C's PR #9 was in flight. The operator
# directed that the freeze carry no stale-evidence allowance at all, which is
# the same standard L applied to B's PR #7 follow-ups, so keeping one for L's
# own convenience was never defensible.
#
# Adding an entry here is not a way to make the board green. It is a way to
# declare that the release candidate ships live-gate evidence which does not
# describe the code being released, and it needs the operator's agreement, not
# just a passing test run. The assertions below are a ratchet in both
# directions: a new stale artifact fails, and an entry left here after it is
# fixed also fails.
KNOWN_STALE: dict[str, str] = {}


def test_no_shipped_evidence_is_stale():
    """The whole point of the checker, asserted against the REAL tree.

    Without this, the checker could report two stale artifacts while the board
    stayed green, because the other tests either run on synthetic tmp_path
    fixtures or count STALE as an acceptable verdict. An RC could then ship with
    live-gate evidence that does not describe the code being released, which is
    precisely what this module exists to prevent (PR #8 review, HIGH-1).
    """
    report = ec.build_report(ROOT)
    stale = {name for name, v in report.items() if v.verdict == "STALE"}

    unexpected = stale - set(KNOWN_STALE)
    assert not unexpected, (
        "live-gate evidence no longer describes this tree; re-run the gates that "
        f"produced: {sorted(unexpected)}")

    # The ratchet. Once an entry is genuinely fixed it must leave the list, so
    # the exemption cannot outlive the problem it was granted for.
    resolved = set(KNOWN_STALE) - stale
    assert not resolved, (
        f"no longer stale, delete from KNOWN_STALE: {sorted(resolved)}")


def test_an_unknown_gate_is_unbound_not_silently_accepted():
    """The fail-open: an artifact whose convention is unknown must not pass.

    `test_every_release_candidate_artifact_is_classified` asserts that NOTHING is
    UNBOUND, so it gets *greener* if unknown conventions start being treated as
    fine. It therefore cannot catch that specific fail-open, and this pins it
    from the other side (PR #8 review, MED-2).
    """
    unknown = "infra/some-new-gate/result-whatever-2026-01-01.json"
    assert ec.convention_for(unknown) is None, (
        "an unregistered gate path resolved to a convention; unknown gates must "
        "stay unknown so their evidence is reported rather than assumed fine")


def test_an_unknown_gate_classifies_as_unbound(tmp_path):
    """The same fail-open at the classify() level, on a real artifact."""
    artifact = _write(tmp_path, "infra/some-new-gate/result-x.json",
                      {"source_sha256": {"whatever.py": "0" * 64}})
    assert ec.classify(artifact, tmp_path).verdict == "UNBOUND"


def test_an_unregistered_scalar_hash_is_reported_not_dropped(tmp_path):
    """A recorded hash nobody checks must never leave the artifact CURRENT.

    Scalar `*_sha256` fields outside the registry used to be dropped on the
    floor, so an artifact could record a binding, have it verified by nothing,
    and still report CURRENT (PR #8 review, MED-1).
    """
    gate = tmp_path / "infra" / "byoa-spike" / "byoa_gate.py"
    gate.parent.mkdir(parents=True)
    gate.write_text("print('gate')\n")
    artifact = _write(tmp_path, "infra/byoa-spike/result-byoa-x.json",
                      {"inputs": {"gate_sha256": _sha_of(gate),
                                  "mystery_sha256": "0" * 64}})
    verdict = ec.classify(artifact, tmp_path)
    assert verdict.verdict == "UNBOUND"
    assert "mystery_sha256" in verdict.note


def test_every_declared_ignore_has_a_stated_reason():
    """`ignore` is how a hash stops being checked, so it must stay reviewable.

    This test used to assert only that the field name ended in `_sha256`, so it
    stayed GREEN under its own named bug: a field could be exempted from all
    verification by adding one word to a set, with no reason anywhere. `ignore`
    is the fail-open lever for the entire tool, and it now carries a mandatory
    reason the way HISTORICAL does (PR #8 re-review, LOW).
    """
    assert ec.REGISTRY, "the registry is empty, so this test proves nothing"
    checked = 0
    for pattern, convention in ec.REGISTRY:
        assert isinstance(convention.ignore, dict), (
            f"{pattern}: ignore must map each field to why it is exempt, so a "
            "field cannot be silently exempted by adding it to a set")
        for field_name, reason in convention.ignore.items():
            assert field_name.endswith("_sha256"), (
                f"{pattern}: {field_name} is not a hash field")
            assert reason and reason.strip(), (
                f"{pattern}: {field_name} is exempted from verification with no "
                "stated reason")
            assert len(reason.strip()) >= 20, (
                f"{pattern}: {field_name}'s reason is too short to review: "
                f"{reason!r}")
            checked += 1
    assert checked >= 4, (
        f"expected the shipped exemptions to be checked, saw {checked}")


def test_every_release_candidate_artifact_is_classified():
    """No artifact may fall through unclassified.

    UNBOUND is the verdict for a gate whose convention this tool does not know.
    A new gate landing with an unrecognised convention must show up here rather
    than be silently counted as fine.
    """
    report = ec.build_report(ROOT)
    assert report, "no result-*.json artifacts were discovered at all"
    unbound = [name for name, v in report.items() if v.verdict == "UNBOUND"]
    assert not unbound, (
        "these artifacts record a binding convention evidence_currency.py cannot "
        f"resolve; declare it in REGISTRY or HISTORICAL: {unbound}")


def test_known_bindable_artifacts_are_actually_bound():
    """Positive control for the whole discovery path.

    If REGISTRY silently stopped matching, every artifact would become UNBOUND
    or HISTORICAL and the suite above would still pass while proving nothing.
    """
    report = ec.build_report(ROOT)
    bound = {n: v for n, v in report.items() if v.verdict in ("CURRENT", "STALE")}
    assert len(bound) >= 5, f"expected the shipped gate evidence to bind: {report}"
    assert all(v.checked > 0 for v in bound.values())


def test_matching_hash_is_current(tmp_path):
    """Positive control: a binding that resolves and agrees is CURRENT."""
    source = tmp_path / "infra" / "kubernetes" / "verify-network-policy.sh"
    source.parent.mkdir(parents=True)
    source.write_text("#!/bin/sh\ntrue\n")
    artifact = _write(tmp_path, "infra/kubernetes/result-network-policy-x.json",
                      {"source_sha256": {"verify-network-policy.sh": _sha_of(source)}})
    verdict = ec.classify(artifact, tmp_path)
    assert verdict.verdict == "CURRENT"
    assert verdict.checked == 1


def test_mismatched_hash_is_stale(tmp_path):
    """The negative this tool exists for: resolved file, disagreeing hash."""
    source = tmp_path / "infra" / "kubernetes" / "verify-network-policy.sh"
    source.parent.mkdir(parents=True)
    source.write_text("#!/bin/sh\ntrue\n")
    artifact = _write(tmp_path, "infra/kubernetes/result-network-policy-x.json",
                      {"source_sha256": {"verify-network-policy.sh": "0" * 64}})
    verdict = ec.classify(artifact, tmp_path)
    assert verdict.verdict == "STALE"
    assert "verify-network-policy.sh" in verdict.reasons[0]


def test_declared_source_file_that_vanished_is_stale(tmp_path):
    """A file the convention says IS tree source, now missing, is stale."""
    (tmp_path / "infra" / "kubernetes").mkdir(parents=True)
    artifact = _write(tmp_path, "infra/kubernetes/result-network-policy-x.json",
                      {"source_sha256": {"gone.sh": "0" * 64}})
    verdict = ec.classify(artifact, tmp_path)
    assert verdict.verdict == "STALE"
    assert "absent from the tree" in verdict.reasons[0]


def test_unresolvable_binding_is_never_reported_stale(tmp_path):
    """Regression: the over-claiming bug.

    Under the repo-relative convention a key that does not resolve to a tree
    file is a gap in this tool's knowledge, not proof the evidence decayed.
    Reporting it STALE is what made the first version claim six false positives.
    """
    (tmp_path / "infra" / "kubernetes").mkdir(parents=True)
    artifact = _write(tmp_path, "infra/kubernetes/result-broker-lifecycle-x.json",
                      {"source_sha256": {"some/unknown/path.py": "0" * 64}})
    verdict = ec.classify(artifact, tmp_path)
    assert verdict.verdict == "UNBOUND", (
        "an unresolvable binding must not be asserted stale")
    assert "unresolvable" in verdict.note


def test_ignored_field_is_not_a_source_binding(tmp_path):
    """`config_sha256` hashes configs generated into a temp dir, not tree source.

    Without the ignore list these keys resolve to nothing and the artifact would
    be downgraded on every run for a field that never described the tree.
    """
    (tmp_path / "infra" / "kubernetes").mkdir(parents=True)
    artifact = _write(
        tmp_path, "infra/kubernetes/result-broker-semantic-wire-x.json",
        {"config_sha256": {"egress.json": "0" * 64},
         "source_sha256": {"andyur/x.py": "1" * 64}})
    convention = ec.convention_for("infra/kubernetes/result-broker-semantic-wire-x.json")
    fields = {b.field_name for b in ec.bindings_in(json.loads(artifact.read_text()),
                                                  convention)}
    assert "config_sha256" not in fields
    assert "source_sha256" in fields


def test_scalar_binding_is_scoped_to_the_gate_that_wrote_it(tmp_path):
    """`gate_sha256` means different files in different gates.

    `infra/sender-binding-spike/phase1_gate.py:547` hashes ITSELF under that
    name, while a BYOA result means `infra/byoa-spike/byoa_gate.py`. A global
    field-name registry conflates them, which is how the first version produced
    false staleness for the sender-binding artifacts.
    """
    byoa = ec.convention_for("infra/byoa-spike/result-byoa-x.json")
    assert byoa is not None
    assert byoa.scalars["gate_sha256"] == "infra/byoa-spike/byoa_gate.py"

    # Unconditional: whether the sender-binding gates get their own entry later
    # or keep having none, `gate_sha256` there must never resolve to the BYOA
    # gate. Guarding this behind `if entry is not None` would make it a test
    # that cannot fail, which is the exact defect it exists to catch.
    payload = {"inputs": {"gate_sha256": "0" * 64}}
    other = ec.convention_for("infra/sender-binding-spike/result-x.json")
    resolved = set() if other is None else {
        b.path for b in ec.bindings_in(payload, other)}
    assert "infra/byoa-spike/byoa_gate.py" not in resolved

    # And no registry entry may claim that mapping outside byoa-spike.
    for pattern, convention in ec.REGISTRY:
        if convention.scalars.get("gate_sha256") == "infra/byoa-spike/byoa_gate.py":
            assert pattern.startswith("infra/byoa-spike/"), (
                f"{pattern} maps gate_sha256 to the BYOA gate outside byoa-spike")


def test_nested_inputs_are_discovered(tmp_path):
    """The BYOA gates record bindings under `inputs`, not at the top level."""
    gate = tmp_path / "infra" / "byoa-spike" / "byoa_gate.py"
    gate.parent.mkdir(parents=True)
    gate.write_text("print('gate')\n")
    artifact = _write(tmp_path, "infra/byoa-spike/result-byoa-x.json",
                      {"inputs": {"gate_sha256": _sha_of(gate)}})
    verdict = ec.classify(artifact, tmp_path)
    assert verdict.verdict == "CURRENT"
    assert verdict.checked == 1


def test_historical_must_be_declared_by_name(tmp_path):
    """Nothing is classified historical by inference.

    HISTORICAL is the one verdict that narrows the RC evidence set, so it has to
    be reviewable: an artifact earns it only by being listed with a reason.
    """
    (tmp_path / "infra" / "kubernetes").mkdir(parents=True)
    artifact = _write(tmp_path, "infra/kubernetes/result-network-policy-x.json",
                      {"source_sha256": {"gone.sh": "0" * 64}})
    assert ec.classify(artifact, tmp_path).verdict != "HISTORICAL"
    for name, reason in ec.HISTORICAL.items():
        assert reason.strip(), f"{name} is declared historical with no reason"
        assert (ROOT / name).is_file(), f"{name} is declared historical but absent"


def test_unreadable_artifact_is_stale(tmp_path):
    """Evidence that cannot be parsed cannot be shown to describe this tree."""
    (tmp_path / "infra" / "kubernetes").mkdir(parents=True)
    artifact = tmp_path / "infra" / "kubernetes" / "result-network-policy-x.json"
    artifact.write_text("{not json")
    assert ec.classify(artifact, tmp_path).verdict == "STALE"


@pytest.mark.parametrize("value", ["", "z" * 64, "abc", "0" * 63, None, 5])
def test_non_digest_values_are_not_bindings(value, tmp_path):
    """`agent_py_sha256: null` and friends must not become bindings."""
    payload = {"source_sha256": {"x.sh": value}}
    convention = ec.convention_for("infra/kubernetes/result-network-policy-x.json")
    assert list(ec.bindings_in(payload, convention)) == []


# --------------------------------------------------------------------------
# ancestor_audit: the ledger claim checker
# --------------------------------------------------------------------------

aa = _load("ancestor_audit")


def test_rename_normalisation_matches_pre_rename_lines():
    """`38ae2b7` renamed Colony to Andyur tree-wide.

    Without this, every 2026-08-08 commit scores near zero and is reported as a
    vanished fix. With it, a line that landed and was renamed still matches.
    """
    before = 'COLONY_TOOL_EGRESS="${COLONY_TOOL_EGRESS:-agentgateway}"'
    after = 'ANDYUR_TOOL_EGRESS="${ANDYUR_TOOL_EGRESS:-agentgateway}"'
    assert aa.normalise(before) == aa.normalise(after)


def test_normalisation_does_not_collapse_unrelated_lines():
    """Positive control: normalising must not make everything match everything."""
    assert aa.normalise("the agent refused the request") != aa.normalise(
        "the agent accepted the request")


def test_only_substantive_added_lines_are_compared():
    """Short and punctuation-only lines appear everywhere.

    Counting them would make any commit look present on any ref, which turns the
    presence score into noise that always clears the threshold.
    """
    assert aa.MIN_LINE_LEN >= 12
    short = ["}", "else:", "return", "pass"]
    assert all(len(line) < aa.MIN_LINE_LEN for line in short)


def test_every_declared_rename_actually_happened():
    """The rename table narrows what counts as a match, so it stays reviewable.

    An entry here can hide a genuinely missing fix by making its lines match
    something unrelated, so each pair must be a rename the repo really performed.
    """
    assert aa.GLOBAL_RENAMES == (("colony", "andyur"),)


def test_presence_threshold_is_a_declared_constant():
    """A squash lands lines verbatim and must clear the bar; a lost fix must not."""
    assert 0.5 <= aa.PRESENCE_THRESHOLD <= 0.9


def test_sha_pattern_ignores_short_and_non_hex_tokens():
    """The ledgers are prose; only real-looking SHAs may be picked up."""
    found = set(aa.SHA_RE.findall(
        "landed abc123 and ed609af and zzzzzzz and 0014a00 plus deadbee"))
    assert "ed609af" in found and "0014a00" in found and "deadbee" in found
    assert "abc123" not in found      # too short
    assert "zzzzzzz" not in found     # not hex


# --------------------------------------------------------------------------
# build_release: the release candidate assembler
# --------------------------------------------------------------------------

br = _load("build_release")


def _tiny_repo(tmp_path: Path) -> Path:
    import subprocess
    subprocess.run(("git", "init", "-q"), cwd=tmp_path, check=True)
    subprocess.run(("git", "config", "user.email", "rc@test"), cwd=tmp_path, check=True)
    subprocess.run(("git", "config", "user.name", "rc"), cwd=tmp_path, check=True)
    (tmp_path / "a.txt").write_text("one\n")
    subprocess.run(("git", "add", "-A"), cwd=tmp_path, check=True)
    subprocess.run(("git", "commit", "-qm", "seed"), cwd=tmp_path, check=True)
    return tmp_path


def test_a_dirty_tree_cannot_produce_a_release(tmp_path):
    """A manifest names a commit, so the tree must match that commit.

    Otherwise the manifest claims provenance for content that was never
    committed, which is the one thing it exists to rule out.
    """
    repo = _tiny_repo(tmp_path)
    (repo / "uncommitted.txt").write_text("drift\n")
    with pytest.raises(br.ReleaseRefused) as caught:
        br.frozen_commit(repo, allow_dirty=False)
    assert "uncommitted" in str(caught.value)


def test_a_clean_tree_resolves_its_commit(tmp_path):
    """Positive control: refusing every tree would satisfy the test above."""
    repo = _tiny_repo(tmp_path)
    sha, subject, _ = br.frozen_commit(repo, allow_dirty=False)
    assert len(sha) == 40 and subject == "seed"


def test_allow_dirty_is_an_explicit_opt_in(tmp_path):
    """The escape hatch must exist and must require asking for it."""
    repo = _tiny_repo(tmp_path)
    (repo / "uncommitted.txt").write_text("drift\n")
    sha, _, _state = br.frozen_commit(repo, allow_dirty=True)
    assert len(sha) == 40


def test_declared_images_have_real_dockerfiles():
    """A manifest that names an image nobody can build is a lie in waiting."""
    for name, dockerfile in br.IMAGES:
        assert (ROOT / dockerfile).is_file(), f"{name}: {dockerfile} missing"


def test_artifact_digests_are_real_sha256(tmp_path):
    blob = tmp_path / "artifact.bin"
    blob.write_bytes(b"andyur release candidate")
    assert br.sha256_file(blob) == hashlib.sha256(
        b"andyur release candidate").hexdigest()


def test_a_dirty_build_records_that_it_is_dirty(tmp_path):
    """--allow-dirty must never produce a manifest that silently misattributes.

    The escape hatch is legitimate for throwaway local builds. What is not
    legitimate is a SIGNED manifest asserting `frozen_commit` for artifacts that
    contain uncommitted changes, with nothing recording it: a consumer verifying
    the signature and reading frozen_commit would be told the wheel is that
    commit when it demonstrably is not (PR #8 re-review, MED).
    """
    repo = _tiny_repo(tmp_path)
    (repo / "uncommitted.py").write_text("marker = 1\n")

    sha, _, tree_state = br.frozen_commit(repo, allow_dirty=True)

    assert len(sha) == 40
    assert tree_state["clean"] is False
    assert tree_state["artifacts_match_frozen_commit"] is False
    assert any("uncommitted.py" in line for line in tree_state["uncommitted"])
    assert "dirty" in tree_state["warning"].lower()
    assert "provenance" in tree_state["warning"].lower()


def test_a_clean_build_records_that_it_is_clean(tmp_path):
    """Positive control.

    A tree_state that reported "dirty" unconditionally would satisfy the test
    above while telling every real release it is untrustworthy.
    """
    repo = _tiny_repo(tmp_path)
    _, _, tree_state = br.frozen_commit(repo, allow_dirty=False)
    assert tree_state["clean"] is True
    assert tree_state["artifacts_match_frozen_commit"] is True
    assert tree_state["uncommitted"] == []
    assert "warning" not in tree_state


def test_a_release_refuses_a_prepopulated_output_directory(tmp_path):
    """The planted-artifact hole: a release must own its output directory.

    `python -m build` does not clean its outdir, and the builder used to iterate
    everything in it. A file merely sitting in dist/ was listed in the manifest
    and cosign-signed, on a clean tree, with the manifest asserting
    artifacts_match_frozen_commit. It verified OK, because a valid signature
    over a planted file is still a valid signature (PR #8 final review, HIGH-1).

    tree_state cannot cover this: it describes the SOURCE tree, and the planted
    file is in the OUTPUT directory.
    """
    out = tmp_path / "out"
    (out / "dist").mkdir(parents=True)
    (out / "dist" / "andyur-9.9.9-py3-none-any.whl").write_text("PLANTED")

    with pytest.raises(br.ReleaseRefused) as caught:
        br.build_python(ROOT, out, Path(sys.executable))
    assert "own its output directory" in str(caught.value)
    assert "andyur-9.9.9" in str(caught.value)


def test_an_empty_currency_report_is_refused_not_treated_as_clean():
    """Zero artifacts inspected is not zero problems found."""
    with pytest.raises(br.ReleaseRefused) as caught:
        br.refuse_if_vacuous({"artifacts": {}})
    assert "NO artifacts" in str(caught.value)


def test_a_report_with_no_current_artifact_is_refused():
    """Everything historical binds the release to nothing."""
    with pytest.raises(br.ReleaseRefused):
        br.refuse_if_vacuous({"artifacts": {"a.json": {"verdict": "HISTORICAL"}}})


def test_a_real_currency_report_passes_the_vacuity_check():
    """Positive control: refusing every report would satisfy both tests above."""
    br.refuse_if_vacuous({"artifacts": {"a.json": {"verdict": "CURRENT"}}})


def test_the_shipped_tree_passes_the_vacuity_check():
    """And the actual tree must clear it, not just a hand-made dict."""
    br.refuse_if_vacuous({"artifacts": {
        n: {"verdict": v.verdict} for n, v in ec.build_report(ROOT).items()}})


def test_one_evidence_convention_serves_every_stock_workload_demo(tmp_path):
    """demos/<name>/evidence binds manifest_sha256 to the SIBLING agent.json
    (artifact-relative `../agent.json`), so OpenSRE, Goose and the next
    workload share one convention line: the right manifest is checked, and
    editing it stales exactly that demo's evidence."""
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location(
        "evidence_currency", ROOT / "infra" / "rc" / "evidence_currency.py")
    ec = importlib.util.module_from_spec(spec)
    sys.modules["evidence_currency"] = ec
    spec.loader.exec_module(ec)
    gate = ROOT / "infra" / "byoa-spike" / "exec_v1_gate.py"
    (tmp_path / "infra" / "byoa-spike").mkdir(parents=True)
    (tmp_path / "infra" / "byoa-spike" / "exec_v1_gate.py").write_bytes(gate.read_bytes())
    for name in ("alpha", "beta"):
        demo = tmp_path / "demos" / name
        (demo / "evidence").mkdir(parents=True)
        (demo / "agent.json").write_text(json.dumps({"name": name}))
        (demo / "evidence" / "result-exec-v1-2026-08-26-x.json").write_text(json.dumps({
            "gate": "exec-v1-conformance", "ok": True,
            "inputs": {"exec_gate_sha256": hashlib.sha256(gate.read_bytes()).hexdigest(),
                       "manifest_sha256": hashlib.sha256((demo / "agent.json").read_bytes()).hexdigest(),
                       "input_sha256": "0" * 64}}))
    report = ec.build_report(tmp_path)
    verdicts = {k: v.verdict for k, v in report.items() if k.startswith("demos/")}
    assert verdicts == {"demos/alpha/evidence/result-exec-v1-2026-08-26-x.json": "CURRENT",
                        "demos/beta/evidence/result-exec-v1-2026-08-26-x.json": "CURRENT"}
    (tmp_path / "demos" / "beta" / "agent.json").write_text(json.dumps({"name": "beta", "edited": True}))
    report = ec.build_report(tmp_path)
    assert report["demos/alpha/evidence/result-exec-v1-2026-08-26-x.json"].verdict == "CURRENT"
    stale = report["demos/beta/evidence/result-exec-v1-2026-08-26-x.json"]
    assert stale.verdict == "STALE" and "demos/beta/agent.json" in stale.reasons[0]
def test_the_currency_check_fails_closed_on_an_unresolvable_binding(tmp_path, capsys):
    """R (PR #25): an artifact that names a source the tree does not have is
    evidence nobody can verify, and the RC check used to exit 0 on it -- which
    is how a board artifact binding another branch's gate script reached a PR.
    UNBOUND now exits non-zero, like STALE."""
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location(
        "evidence_currency_exit", ROOT / "infra" / "rc" / "evidence_currency.py")
    ec = importlib.util.module_from_spec(spec)
    sys.modules["evidence_currency_exit"] = ec
    spec.loader.exec_module(ec)
    (tmp_path / "infra" / "kubernetes").mkdir(parents=True)
    (tmp_path / "infra" / "kubernetes" / "result-exec-opensre-2026-08-26-x.json").write_text(json.dumps({
        "gate": "exec-opensre-in-cluster", "ok": True,
        "source_sha256": {"infra/kubernetes/a-script-this-tree-does-not-have.sh": "a" * 64}}))
    assert ec.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "UNBOUND" in out

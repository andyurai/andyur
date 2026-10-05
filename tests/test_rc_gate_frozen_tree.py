"""What the RC gate will and will not certify.

The gate answers one question about one commit, so the thing most worth pinning
is when it REFUSES. Every case below is one the gate got wrong on a real run.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "infra" / "rc"))
import uncertified_changes as uc                              # noqa: E402


@pytest.fixture
def repo(tmp_path):
    """A real git repository, because the thing under test shells out to git.

    In its OWN subdirectory: the first version of this put the repo at tmp_path
    and the fake artifact beside it, so the artifact itself showed up as an
    untracked change and every assertion was about the fixture."""
    tmp_path = tmp_path / "repo"
    tmp_path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "src.py").write_text("x = 1\n")
    (tmp_path / "result-live.json").write_text("{}\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)
    return tmp_path


def _sha(repo):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          capture_output=True, text=True, check=True).stdout.strip()


def _artifact(path, sha, produced):
    path.write_text(json.dumps({"frozen_commit": sha, "evidence_produced": produced}))
    return str(path)


def test_a_clean_tree_is_certifiable(repo, tmp_path):
    assert uc.uncertified(str(repo), str(tmp_path / "none.json"), _sha(repo), "") == []


def test_an_edited_source_file_is_never_certifiable(repo, tmp_path):
    (repo / "src.py").write_text("x = 2\n")
    artifact = _artifact(tmp_path / "a.json", _sha(repo), ["src.py"])
    # Even listed as "evidence produced", and even when resuming: the list is a
    # record of what the gate wrote, not a licence to certify a source edit.
    assert uc.uncertified(str(repo), artifact, _sha(repo), "suite") == ["src.py"]


def test_evidence_the_gate_produced_is_tolerated_when_resuming(repo, tmp_path):
    """THE DEFECT THIS FIXES. A green run leaves the tree dirty by design --
    the live lines write evidence into it -- so the second pass refused on the
    first pass's own output and the resume feature was unusable."""
    (repo / "result-live.json").write_text('{"ran": true}\n')
    artifact = _artifact(tmp_path / "a.json", _sha(repo), ["result-live.json"])
    assert uc.uncertified(str(repo), artifact, _sha(repo), "suite,currency") == []


def test_that_tolerance_does_not_apply_to_a_first_pass(repo, tmp_path):
    """Without ANDYUR_RC_ONLY this is not a resume, so there is no previous
    pass whose output could be tolerated -- and a dirty tree at the START of a
    full run is exactly what the check exists for."""
    (repo / "result-live.json").write_text('{"ran": true}\n')
    artifact = _artifact(tmp_path / "a.json", _sha(repo), ["result-live.json"])
    assert uc.uncertified(str(repo), artifact, _sha(repo), "") == ["result-live.json"]


def test_a_resume_across_commits_is_refused(repo, tmp_path):
    """What "one frozen tree" forbids is certifying two different trees as one,
    so the tolerance is keyed to the exact commit and nothing else."""
    (repo / "result-live.json").write_text('{"ran": true}\n')
    artifact = _artifact(tmp_path / "a.json", "0" * 40, ["result-live.json"])
    assert uc.uncertified(str(repo), artifact, _sha(repo), "suite") == ["result-live.json"]


def test_an_untracked_file_the_gate_did_not_write_is_refused(repo, tmp_path):
    (repo / "stray.tar.gz").write_text("junk\n")
    artifact = _artifact(tmp_path / "a.json", _sha(repo), ["result-live.json"])
    assert uc.uncertified(str(repo), artifact, _sha(repo), "suite") == ["stray.tar.gz"]


def test_the_allowance_needs_BOTH_a_record_and_an_evidence_shape(repo, tmp_path):
    """Two different claims: the record says the gate wrote it, the shape says
    it is the kind of file a gate is allowed to write. Requiring only the first
    would certify a source edit as unchanged if it ever landed in the
    recorder's list -- not a hole anyone would notice until it mattered.

    (Caught by the test above, in the first version of this code.)"""
    evidence = repo / "result-live.json"
    evidence.write_text('{"ran": true}\n')
    (repo / "src.py").write_text("x = 3\n")
    artifact = _artifact(tmp_path / "a.json", _sha(repo),
                         ["result-live.json", "src.py"])
    assert uc.uncertified(str(repo), artifact, _sha(repo), "suite") == ["src.py"]
    assert uc._looks_like_evidence("infra/kubernetes/result-exec-goose-x.json")
    assert uc._looks_like_evidence("demos/opensre/evidence/result-exec-v1-x.json")
    assert not uc._looks_like_evidence("andyur/server/app.py")


# --- what the currency checker considers SHIPPED ---------------------------

def test_gitignored_artifacts_are_not_shipped_evidence(tmp_path):
    """The RC gate writes its verdict into the gitignored data directory, and
    the currency checker called it "evidence nobody can check" -- about a file
    nobody receives. A run's scratch output is not a claim the release makes.

    Asked of git rather than pattern-matched, so it stays true when .gitignore
    changes and needs no second copy of what is ignored."""
    sys.path.insert(0, str(ROOT / "infra" / "rc"))
    import evidence_currency as ec

    repo = tmp_path / "repo"
    (repo / "data" / "rc").mkdir(parents=True)
    (repo / "infra").mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".gitignore").write_text("data/\n")
    shipped = repo / "infra" / "result-shipped-2026-01-01.json"
    shipped.write_text("{}\n")
    scratch = repo / "data" / "rc" / "result-rc-gate-2026-01-01.json"
    scratch.write_text("{}\n")

    found = [p.name for p in ec.find_artifacts(repo)]
    assert shipped.name in found
    assert scratch.name not in found, "a gitignored artifact was treated as shipped"

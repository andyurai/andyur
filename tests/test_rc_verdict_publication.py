"""The RC verdict as a record somebody else can read.

Two things the 2026-08-30 review found missing. First, the artifact could not
say whether a GO was one pass from a clean start or several partial runs of the
same commit merged together -- both produced an identical "RC GATE GO". Those
are different claims, and only one of them is the one the operator asked for.
Second, the verdict lives in a gitignored directory (deliberately: it binds the
sha256 of every gate it ran, so committing it makes the tree red on the next
edit to any of them), which meant the record of why a tag was cut existed
nowhere a reader could find it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "infra" / "rc" / "verify-rc-gate.sh"
PUBLISH = ROOT / "infra" / "rc" / "publish-verdict.py"


# --- the gate says which kind of pass it was --------------------------------

def test_the_verdict_counts_its_lines_rather_than_hard_coding_them():
    """`len(passed) == 12`, with 12 written in three places, meant that adding a
    thirteenth line would produce a GO on twelve of thirteen -- silently, in the
    one artifact whose whole purpose is not to be believed on trust."""
    text = GATE.read_text()
    assert "declared = int(os.environ.get(\"RC_DECLARED\")" in text
    assert "len(passed) == declared" in text
    # Comment lines are where the old rule is EXPLAINED; what matters is that
    # no line of code still applies it.
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"len\(passed\) == \d", code)


def test_every_declared_line_increments_the_count_before_only_can_skip_it():
    """The counter must sit ABOVE the ANDYUR_RC_ONLY early return, or a resumed
    pass would declare only the lines it re-ran and reach GO on a subset."""
    text = GATE.read_text()
    body = text[text.index("line() {"):]
    counted = body.index("DECLARED=$((DECLARED + 1))")
    filtered = body.index('if [ -n "$ONLY" ]; then')
    assert counted < filtered


def test_the_gate_records_whether_the_pass_was_resumed():
    text = GATE.read_text()
    for field in ('"resumed": resumed', '"single_pass"',
                  '"lines_merged_from_an_earlier_run"'):
        assert field in text, f"the verdict does not record {field}"
    # And says it out loud, not only in the JSON.
    assert "one pass, from a clean start" in text
    assert "NOT one pass from a clean start" in text


# --- publication -------------------------------------------------------------

@pytest.fixture
def repo(tmp_path):
    """A throwaway repository with one commit and one tag."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name, value in (("user.email", "t@t"), ("user.name", "t")):
        subprocess.run(["git", "-C", str(tmp_path), "config", name, value], check=True)
    (tmp_path / "gate.sh").write_text("#!/usr/bin/env bash\ntrue\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "one"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "tag", "v9.9.9-rc1"], check=True)
    return tmp_path


def _verdict(repo, **overrides):
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    doc = {"gate": "rc", "verdict": "GO", "ok": True, "frozen_commit": sha,
           "passed": 13, "declared_lines": 13, "resumed": False,
           "single_pass": True, "lines_merged_from_an_earlier_run": [],
           "source_sha256": {"gate.sh": hashlib.sha256(
               (repo / "gate.sh").read_bytes()).hexdigest()}}
    doc.update(overrides)
    path = repo / "verdict.json"
    path.write_text(json.dumps(doc))
    return path


def _publish(repo, verdict, tag):
    """Run the real publisher with the throwaway repo as its root."""
    script = PUBLISH.read_text().replace(
        'ROOT = Path(__file__).resolve().parents[2]', f'ROOT = Path({str(repo)!r})')
    runner = repo / "publish.py"
    runner.write_text(script)
    return subprocess.run([sys.executable, str(runner), str(verdict), tag],
                          capture_output=True, text=True, cwd=repo)


def test_a_go_verdict_is_published_under_the_tag_it_certifies(repo):
    result = _publish(repo, _verdict(repo), "v9.9.9-rc1")
    assert result.returncode == 0, result.stderr
    published = repo / "docs" / "releases" / "v9.9.9-rc1.rc-gate.json"
    assert published.is_file()
    assert json.loads(published.read_text())["verdict"] == "GO"
    # The annotation carries the two facts the last tag's did not.
    assert "13 of 13 lines" in result.stdout
    assert "One pass, from a clean start." in result.stdout


def test_a_resumed_pass_says_so_in_the_annotation(repo):
    verdict = _verdict(repo, single_pass=False, resumed=True,
                       lines_merged_from_an_earlier_run=["opensre", "console"])
    result = _publish(repo, verdict, "v9.9.9-rc1")
    assert result.returncode == 0, result.stderr
    assert "NOT one pass" in result.stdout and "opensre, console" in result.stdout


def test_a_no_go_verdict_is_never_published(repo):
    result = _publish(repo, _verdict(repo, verdict="NO-GO", ok=False), "v9.9.9-rc1")
    assert result.returncode != 0
    assert "only a GO is a release record" in result.stderr
    assert not (repo / "docs" / "releases").exists()


def test_a_verdict_for_another_commit_is_refused(repo):
    result = _publish(repo, _verdict(repo, frozen_commit="0" * 40), "v9.9.9-rc1")
    assert result.returncode != 0
    assert "does not describe" in result.stderr


def test_a_verdict_whose_gates_have_changed_since_is_refused(repo):
    """The staleness rule the whole tree enforces, applied to the artifact that
    sits above all of them: a verdict is a claim about programs, and a claim
    about a program that has since changed is not evidence."""
    verdict = _verdict(repo)
    (repo / "gate.sh").write_text("#!/usr/bin/env bash\nfalse\n")
    result = _publish(repo, verdict, "v9.9.9-rc1")
    assert result.returncode != 0
    assert "gate.sh (changed)" in result.stderr
    assert "re-run the gate" in result.stderr


def test_a_published_verdict_is_never_silently_replaced(repo):
    assert _publish(repo, _verdict(repo), "v9.9.9-rc1").returncode == 0
    second = _publish(repo, _verdict(repo), "v9.9.9-rc1")
    assert second.returncode != 0 and "already exists" in second.stderr


def test_an_unknown_tag_is_refused(repo):
    result = _publish(repo, _verdict(repo), "v0.0.0-nope")
    assert result.returncode != 0 and "no tag named" in result.stderr

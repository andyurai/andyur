"""Documentation that drifts is worse than none: it is confidently wrong.

These assert the SHAPE of the truth rather than its wording, so they survive
rewording and fail on drift. Each exists because the drift already happened.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_every_run_sh_command_appears_in_its_own_help():
    """`./run.sh help` must list everything `./run.sh` accepts.

    Thirteen commands had accumulated unlisted, including two added the same
    afternoon this test was written. Nobody omits them on purpose -- you add a
    dispatch arm, you test the arm, and the help block is three hundred lines
    away. So it is checked here instead of remembered.
    """
    src = (ROOT / "run.sh").read_text(encoding="utf-8")
    body = src[src.index("case "):]
    commands: set[str] = set()
    for m in re.finditer(r"^  ([a-z][a-z0-9|-]*)\)", body, re.M):
        commands.update(m.group(1).split("|"))

    help_text = subprocess.run(
        ["bash", str(ROOT / "run.sh"), "help"],
        capture_output=True, text=True, cwd=ROOT, timeout=120).stdout

    # Membership must be a LISTED command, not a substring of the help blob:
    # a plain `c not in help_text` let `up` count as present because it appears
    # inside `docker-up`, `server` inside `spire-server`, etc -- so a command
    # could lose its help row undetected. Require the name to head a help line
    # (leading space, the exact token, then whitespace or end). (Red-team A4.)
    def _listed(cmd: str) -> bool:
        return bool(re.search(rf"^\s+{re.escape(cmd)}(\s|$)", help_text, re.M))

    missing = sorted(c for c in commands if not _listed(c))
    assert not missing, (
        f"./run.sh accepts these but never mentions them: {missing}. "
        "An operator's only map of this repo is that help text.")


def test_the_help_does_not_advertise_a_command_that_does_not_exist():
    """The other direction, and the more damaging one: a command in the help
    that the dispatcher does not accept sends a reader to a usage error."""
    src = (ROOT / "run.sh").read_text(encoding="utf-8")
    body = src[src.index("case "):]
    commands: set[str] = set()
    for m in re.finditer(r"^  ([a-z][a-z0-9|-]*)\)", body, re.M):
        commands.update(m.group(1).split("|"))

    help_text = subprocess.run(
        ["bash", str(ROOT / "run.sh"), "help"],
        capture_output=True, text=True, cwd=ROOT, timeout=120).stdout

    # Only the two-space-indented "  name  description" lines are command rows;
    # the surrounding prose is not.
    advertised = {m.group(1) for m in
                  re.finditer(r"^  ([a-z][a-z0-9-]{2,})\s{2,}\S", help_text, re.M)}
    phantom = sorted(advertised - commands)
    assert not phantom, (
        f"the help offers commands ./run.sh does not accept: {phantom}")


def test_no_identifier_is_minted_under_a_domain_the_project_does_not_own():
    """Every identifier this project publishes -- a manifest `apiVersion`, a
    schema `$id`, a Kubernetes annotation key -- is namespaced under the one
    domain it controls. A key under any other domain is a name somebody else
    can register and then speak for, and it cannot be renamed once a deployer
    has written it down. The changelog is exempt because it records the move."""
    import pytest

    foreign = "andyur." + "io"
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                            capture_output=True)
    if listed.returncode != 0:
        pytest.skip("not a git checkout, so the tracked tree cannot be "
                    "enumerated and the domain sweep did not run")
    tracked = [ROOT / name for name in listed.stdout.decode().split("\0") if name]
    assert tracked, "git listed no tracked files; the sweep would pass on nothing"

    offenders = []
    for path in tracked:
        if path.name == "CHANGELOG.md" or not path.is_file():
            continue
        if foreign.encode() in path.read_bytes():
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, (
        f"{foreign} is not a domain this project owns, and these files name "
        f"it: {offenders}")


def test_the_release_key_the_docs_name_is_the_key_in_the_tree():
    """SECURITY.md and RELEASING.md each print the public key's digest so a
    user can compare the copy in the repository with the copy on the website.
    A digest that is not this file's sends every such check wrong, in the one
    place a reader is told to stop if it does not match."""
    import hashlib

    key = ROOT / "docs" / "release-signing-key.pub"
    text = key.read_text()
    assert text.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert text.rstrip().endswith("-----END PUBLIC KEY-----")
    assert "PRIVATE" not in text
    digest = hashlib.sha256(key.read_bytes()).hexdigest()
    for doc in ("SECURITY.md", "docs/RELEASING.md"):
        body = (ROOT / doc).read_text()
        assert digest in body, f"{doc} does not carry the release key's digest"
        assert "docs/release-signing-key.pub" in body
        printed = set(re.findall(r"\b[0-9a-f]{64}\b", body))
        assert printed == {digest}, (
            f"{doc} prints a 64-hex digest that is not the release key's: "
            f"{printed - {digest}}")


def test_the_version_being_packaged_is_a_release_the_docs_admit_to():
    """The first public tree was tagged-ready in every respect but its own
    words: the changelog filed 0.1.0 under "Unreleased", and three documents
    said no version had been tagged. A package whose changelog does not list
    its own version tells a reader they are holding something unfinished."""
    import tomllib

    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert re.search(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
                     changelog, re.M), (
        f"CHANGELOG.md has no dated section for {version}, the version "
        "pyproject.toml packages")
    for doc in ("SECURITY.md", "CONTRIBUTING.md", "docs/RELEASING.md"):
        body = (ROOT / doc).read_text().lower()
        for stale in ("pre-release", "no versions have been tagged",
                      "until the first tagged release", "until the first public release"):
            assert stale not in body, f"{doc} still says {stale!r}"
    minor = ".".join(version.split(".")[:2])
    assert f"| {minor}.x" in (ROOT / "SECURITY.md").read_text(), (
        f"SECURITY.md's supported-versions table does not name {minor}.x")

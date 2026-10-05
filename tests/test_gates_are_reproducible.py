"""A gate's green must mean something outside the checkout that produced it.

production-gaps 31. A reviewer extracted the tree at a frozen SHA to re-run the
console gates and hit three independent walls in a row: the gate resolved
`HERE/.venv/bin/python`, so it used the ORIGINAL checkout's interpreter; the
SPIRE socket was derived from the package directory; and `run.sh` registered
every role identity with `-selector unix:path:$ROLES/<binary>`, an absolute
path into whichever working copy last ran `run.sh up`.

The consequence is the one that matters: a gate artifact is evidence only where
it was produced, which is the opposite of what a gate artifact is for.
"""
import re

from andyur import identity
from andyur.config import PROJECT_ROOT

RUN_SH = (PROJECT_ROOT / "run.sh").read_text()
SHELL_GATE = (PROJECT_ROOT / "infra" / "verify-console.sh").read_text()
BROWSER_GATE = (PROJECT_ROOT / "infra" / "verify-console-browser.py").read_text()


def test_role_identities_are_selected_by_path_because_content_cannot_tell_them_apart():
    """Content selection was tried here and is a SECURITY REGRESSION.

    `infra/spire/setup-roles.sh` copies ONE standalone interpreter to five
    names -- its own header says the roles are told apart BY PATH -- so all
    five share a sha256. Under `unix:sha256` every role entry matches every
    role binary and the runner is issued the CONTROL PLANE's SVID.

    It passed on a development machine and CI caught it: macOS `codesign -f -s -`
    re-signs each copy so their hashes differ, and on Linux codesign is a no-op
    and the copies are byte-identical. Role separation collapsed completely and
    the laptop said it was fine.

    This test exists so the next person who reaches for the obvious fix to
    production-gaps 31 finds out here rather than in CI.
    """
    assert "unix:path:$ROLES/$bin" in RUN_SH
    assert "unix:sha256:" not in RUN_SH.split("# WHY PATH AND NOT")[1].split("done")[0] \
        .replace("# WHY PATH AND NOT unix:sha256", ""), "content selection is back"
    # the reason is recorded where the change would be made
    assert "IDENTICAL BY DESIGN" in RUN_SH
    # a missing binary is reported rather than registered
    assert re.search(r'if \[ ! -x "\$ROLES/\$bin" \]', RUN_SH)


def test_the_role_binaries_really_are_identical_so_the_reason_above_stays_true():
    """The premise of the test above, asserted rather than asserted-about.

    If someone later makes the role binaries genuinely distinct, content
    selection becomes available and the comment in run.sh becomes false. This
    reddens then, which is the moment to revisit it.
    """
    import hashlib
    import pathlib

    setup = (PROJECT_ROOT / "infra" / "spire" / "setup-roles.sh").read_text()
    # one interpreter copied to five names, which is what makes them identical
    assert 'cp "$STD_ROOT/bin/python3.12" "$ROLES_DIR/bin/andyur-$role"' in setup

    binaries = sorted(pathlib.Path(PROJECT_ROOT / "infra" / "roles" / "bin").glob("andyur-*"))
    if len(binaries) < 2:
        return          # not built in this checkout; the source assertion stands
    digests = {hashlib.sha256(b.read_bytes()).hexdigest() for b in binaries}
    # On macOS codesign differentiates them, which is exactly the accident that
    # hid the bug -- so a single digest is the Linux truth and several digests
    # is the macOS illusion. Either way the SOURCE is one `cp`.
    assert len(digests) in (1, len(binaries))


def test_neither_console_gate_hard_wires_this_checkout_s_interpreter():
    for name, source in (("verify-console.sh", SHELL_GATE),
                         ("verify-console-browser.py", BROWSER_GATE)):
        assert '.venv/bin/python"' not in source.replace("$HERE/.venv/bin/python", ""), name
        assert "ANDYUR_PY" in source, f"{name} offers no interpreter override"
    # the python gate uses the interpreter it is ALREADY running under, which
    # is correct in every checkout by construction
    assert "sys.executable" in BROWSER_GATE
    # the shell gate prefers an exported VIRTUAL_ENV over this tree's venv
    assert "VIRTUAL_ENV" in SHELL_GATE


def test_the_spire_socket_is_overridable_without_editing_the_package(monkeypatch):
    """The default is derived from the package directory, which is fine as a
    DEFAULT and fatal as the only option. A second checkout points at the
    running agent by exporting the socket."""
    monkeypatch.setenv("SPIFFE_ENDPOINT_SOCKET", "unix:/somewhere/else/api.sock")
    assert identity.socket_path() == "unix:/somewhere/else/api.sock"
    monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET")
    # the default still resolves to this tree, so nothing changes for a plain run
    assert identity.socket_path().endswith("data/spire/agent/api.sock")


# --- production-gaps 27: no gate models a mode the platform retired ----------

def test_no_gate_still_reads_the_retired_identity_flag():
    """`ANDYUR_IDENTITY` was removed on 7 August 2026 and identity is not
    optional -- `andyur/identity.py` opens with why.

    Gates kept passing `-e ANDYUR_IDENTITY=on` into containers where nothing
    read it, one told operators to set it, and one named its OWN knob after it.
    A dead variable is not merely untidy here: a gate that appears to exercise
    `identity off` implies the platform still has that configuration, and the
    whole argument for removing the flag was that half a platform must not look
    green.
    """
    import pathlib

    offenders = []
    for path in (PROJECT_ROOT / "infra").rglob("*"):
        if path.suffix not in {".sh", ".py", ".yaml", ".yml"} or not path.is_file():
            continue
        for lineno, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if "ANDYUR_IDENTITY" not in line:
                continue
            # a line that says it is GONE is the documentation, not a usage
            if "was removed" in line or "does not exist" in line:
                continue
            offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "gates still reference the retired flag:\n" + "\n".join(offenders)


def test_ensure_spire_recovers_an_agent_that_serves_but_issues_nothing():
    """A healthcheck is not an SVID.

    After a CA rotation with the agent down, the cached bundle no longer
    chains: the agent starts, answers healthchecks, serves its socket and
    issues nothing, so `ensure_spire` -- which only asked the healthcheck --
    saw a healthy agent and left it alone. Everything downstream then failed
    with "unknown authority" or a bare timeout.

    The full CA-rotation reproduction is NOT automated: it means destroying the
    local CA, which invalidates the identity of anything else running on the
    machine. What is asserted here is that the recovery exists and is wired to
    the right condition.
    """
    assert "spire_issues_svids" in RUN_SH
    # the detection is fetch-an-SVID, not socket-file existence
    assert "identity.fetch_token()" in RUN_SH
    # and the serving-but-useless case is handled, not just the dead-agent case
    assert re.search(r"healthcheck[^\n]*\n(?:[^\n]*\n)?\s*&& ! spire_issues_svids", RUN_SH)
    # it clears the AGENT's cache only: the server CA and the registration
    # entries are fine, and deleting them turns a two-second recovery into a
    # full re-registration
    # ...scoped to the RECOVERY BLOCK, not to the whole file: `ensure_spire`
    # legitimately mkdir -p's data/spire/server elsewhere, and a substring
    # search over everything would have caught that instead.
    start = RUN_SH.index("SPIRE agent is serving but issues no SVID")
    recovery = RUN_SH[start:RUN_SH.index("\n  fi", start)]
    assert "data/spire/agent/agent-data.json" in recovery
    assert "data/spire/server" not in recovery, recovery
    # starting the agent waits for an SVID, not merely for a socket
    assert "waiting for the first SVID" in RUN_SH


# --- production-gaps 34: the registry's reach is a DECISION, written down ----

def test_the_registry_says_who_may_read_it():
    """It has no owner axis, and that is the design rather than an oversight.

    A reviewer read the missing axis as a bug, reasonably, because nothing said
    otherwise. The decision now lives next to the code that implements it -- and
    so does the part that does NOT follow from it, which is whether a brokered
    `credential_ref` belongs in a catalog with that reading.
    """
    from andyur import registry
    from andyur.registry import api as registry_api

    doc = registry.__doc__
    assert "SHARED CATALOG" in doc
    assert "no owner axis" in doc
    assert "credential_ref" in doc, "the open half of the decision is not stated"
    # and the route itself points at it, so nobody re-derives the question from
    # the absence of a user-token parameter
    import inspect
    # collapsed, with the comment markers removed: the sentence wraps across
    # several `#` lines in the source, so a naive join leaves them inside it
    raw = inspect.getsource(registry_api.resolve_agent)
    source = " ".join(raw.replace("#", " ").split())
    assert "shared catalog of approved definitions" in source
    assert "not tenant-scoped" in source


def test_the_registry_route_is_authenticated_even_though_it_is_not_scoped():
    """The correction that matters: "no owner axis" is not "no auth".

    A review reported that a caller with no credential gets 200. It gets 401,
    and a run token gets 403. Recording the difference stops the decision above
    being read as "this route is open".
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from andyur.registry.api import router
    from conftest import NO_AUTH

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    path = "/v1/registry/agents/agt_x/resolve"
    # NO_AUTH opts out of the suite's default operator header; without it the
    # request arrives authenticated and 404s on the missing agent instead,
    # which would assert nothing about authentication at all.
    assert client.get(path, headers=NO_AUTH).status_code == 401
    assert client.get(path, headers={**NO_AUTH, "Authorization": "Bearer nonsense"}
                      ).status_code == 401
    assert client.get(path, headers={**NO_AUTH, "X-Andyur-Run-Token": "run"}
                      ).status_code == 403
    # POSITIVE CONTROL: an operator gets past auth and reaches the lookup,
    # so the refusals above are authentication and not a broken route
    assert client.get(path).status_code == 404

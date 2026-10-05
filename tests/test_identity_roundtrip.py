"""Slice 4: the server validates a runner's container-attested per-run SVID.
Unit-covers the SVID parsing and the /identity/whoami surface; the full live
round-trip (containerized server validating a runner container) is proven by
infra/spire/docker/verify-roundtrip.sh."""

from pathlib import Path

import conftest
from fastapi.testclient import TestClient

from andyur import identity
from andyur.server.app import app


ROUNDTRIP_GATE = (Path(__file__).resolve().parent.parent / "infra" / "spire" /
                  "docker" / "verify-roundtrip.sh")
FULL_TRACE_GATE = ROUNDTRIP_GATE.with_name("verify-full-trace.sh")


# -- parse a per-run SVID back to (agent, run_id) ------------------------------

def test_parse_per_run_svid():
    assert identity.parse_agent_run(
        "spiffe://andyur.local/agent/scout/run/run-42"
    ) == ("scout", "run-42")


def test_parse_rejects_non_run_svids():
    # a bare agent identity, a role identity, and junk are all (None, None)
    assert identity.parse_agent_run("spiffe://andyur.local/agent/scout") == (None, None)
    assert identity.parse_agent_run("spiffe://andyur.local/control-plane") == (None, None)
    assert identity.parse_agent_run("spiffe://andyur.local/agent/scout/run/") == (None, None)
    assert identity.parse_agent_run("spiffe://other.example/agent/a/run/b") == (None, None)


def test_parse_is_not_foolable_by_adversarial_shapes():
    p = identity.parse_agent_run
    assert p("spiffe://andyur.local/agent//run/x") == (None, None)      # empty agent
    assert p("spiffe://andyur.local/agent/a/b/run/c") == (None, None)   # extra segment
    assert p("spiffe://andyur.local/agent/a/run/c/run/d") == (None, None)  # doubled
    assert p("spiffe://andyur.local/agent/run/run/x") == ("run", "x")   # agent named 'run'
    # trailing slash on a valid id still parses (rstrip), no misattribution
    assert p("spiffe://andyur.local/agent/scout/run/run-9/") == ("scout", "run-9")


def test_parse_roundtrips_with_the_registrar_id():
    from andyur import spire_registrar as reg
    svid = reg.run_spiffe_id("run-9", "planner")
    assert identity.parse_agent_run(svid) == ("planner", "run-9")


# -- /identity/whoami: the validation surface ----------------------------------

# `test_whoami_reports_disabled_when_identity_off` was here. It asserted that an
# unauthenticated caller gets 200 with {"identity": "disabled"}. Deleted with the
# mode it described: whoami has nothing to report but a validated SVID.


def test_whoami_401_without_a_token(monkeypatch):
    # NO_AUTH suppresses the suite's default operator identity. Without it this
    # test would send a valid SVID and assert 401 against a server that was
    # never asked the question.
    r = TestClient(app).get("/identity/whoami", headers=conftest.NO_AUTH)
    assert r.status_code == 401


def test_whoami_validates_and_parses_a_run_svid(monkeypatch):
    # stub validation to return a per-run SVID; assert the endpoint reads back
    # the agent/run it proves (no self-declared name involved)
    monkeypatch.setattr(
        identity, "validate_token",
        lambda tok: "spiffe://andyur.local/agent/scout/run/run-7",
    )
    r = TestClient(app).get("/identity/whoami", headers={"Authorization": "Bearer x"})
    body = r.json()
    assert body["agent"] == "scout" and body["run_id"] == "run-7"
    assert body["spiffe_id"].endswith("/agent/scout/run/run-7")
    assert body["role"] is None   # per-run SVID: last segment is the run, not a role


def test_whoami_reports_role_for_a_non_run_identity(monkeypatch):
    monkeypatch.setattr(identity, "validate_token",
                        lambda tok: "spiffe://andyur.local/operator")
    r = TestClient(app).get("/identity/whoami", headers={"Authorization": "Bearer x"})
    body = r.json()
    assert body["role"] == "operator" and body["agent"] is None


def test_whoami_401_on_invalid_token(monkeypatch):

    def _bad(tok):
        raise ValueError("bad signature")

    monkeypatch.setattr(identity, "validate_token", _bad)
    r = TestClient(app).get("/identity/whoami", headers={"Authorization": "Bearer x"})
    assert r.status_code == 401


def test_live_roundtrip_tokenless_probe_reaches_the_server_without_an_svid():
    script = ROUNDTRIP_GATE.read_text()
    probe = script.split(
        'say "5. a caller presenting NO SVID is rejected by the server (401)"', 1
    )[1].split("# --- Enforcement:", 1)[0]

    assert 'httpx.get("http://andyur-server:8642/identity/whoami"' in probe
    executable = "\n".join(
        line for line in probe.splitlines() if not line.lstrip().startswith("#")
    )
    assert "identity.auth_header" not in executable
    assert 'grep -q "^401"' in probe


def test_live_roundtrip_assertion_failures_terminate_the_gate():
    script = ROUNDTRIP_GATE.read_text()
    assertion_failures = [
        line for line in script.splitlines()
        if line.lstrip().startswith("else bad ")
    ]

    assert len(assertion_failures) == 5
    assert all("exit 1" in line for line in assertion_failures)
    assert 'bad "round-trip did not return the attested agent/run"; echo "     $out"; exit 1' in script
    assert 'bad "could not scaffold runs/tokens"; echo "$toks"; exit 1' in script


def test_full_trace_required_evidence_failures_terminate_the_gate():
    script = FULL_TRACE_GATE.read_text()

    assert 'fail(){ bad "$@"; exit 1; }' in script
    assert '[ "$state" = "done" ] && ok "run completed" || fail ' in script
    assert '|| fail "trace $TRACE_ID not readable from Jaeger: $readback"' in script
    for span in ("auth.require_run", "auth.bind", "runner"):
        assert f'|| fail "no {span} span' in script


def test_full_trace_daemon_readiness_requires_completed_initialization():
    script = FULL_TRACE_GATE.read_text()
    daemon = script.split('say "4. worker daemon', 1)[1].split(
        'say "5. operator creates', 1)[0]

    assert 'case "$daemon_logs" in *"worker "*" up,"*) daemon_up=1' in daemon
    assert 'if [ "$daemon_up" = 1 ] &&' in daemon
    assert "{{.State.Running}}" in daemon
    assert daemon.count("-e ANDYUR_PROFILE=dev") == 1
    assert 'MODEL="${ANDYUR_AGENT_MODEL:-llama3.2}"' in script

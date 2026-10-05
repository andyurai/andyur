"""Per-run SPIRE registration (Slice 3): the daemon binds each run's SVID to its
container's Docker label, so identity is unforgeable by the agent inside. These
cover the argv the registrar builds and the gating (off unless the SPIRE stack is
deployed); the mechanism itself is proven live by infra/spire/docker/verify-slice3.sh."""

import pytest

from andyur import identity, spire_registrar as reg


# -- the entry binds the run's SVID to its container label ----------------------

def test_register_argv_keys_the_svid_on_the_container_labels():
    argv = reg.register_argv("run-42", "scout", expiry=1234567890)
    joined = " ".join(argv)
    assert "entry create" in joined
    # per-run identity: the agent id with the run appended (not just per-agent)
    assert "-spiffeID spiffe://andyur.local/agent/scout/run/run-42" in joined
    # BOTH container labels required (F1 hardening), NOT a uid/path
    assert "-selector docker:label:andyur.run_id:run-42" in joined
    assert "-selector docker:label:andyur.agent:scout" in joined
    assert "-parentID spiffe://andyur.local/agent/node" in joined
    assert "-entryExpiry 1234567890" in joined   # leaked entries self-expire (F3)
    ttl = int(argv[argv.index("-jwtSVIDTTL") + 1])
    # The agent serves cached JWT-SVIDs down to half TTL, so half the entry TTL
    # must still cover a full run plus the runner's refresh margin.
    assert ttl // 2 >= reg._RUN_TTL + 60


def test_two_concurrent_runs_of_one_agent_get_distinct_identities():
    a = reg.run_spiffe_id("run-a", "scout")
    b = reg.run_spiffe_id("run-b", "scout")
    assert a != b and a.endswith("/run/run-a") and b.endswith("/run/run-b")


def test_server_cmd_defaults_to_docker_exec_and_is_overridable(monkeypatch):
    monkeypatch.delenv("ANDYUR_SPIRE_SERVER_CMD", raising=False)
    monkeypatch.delenv("ANDYUR_SPIRE_SERVER_CONTAINER", raising=False)
    assert reg._server_cmd()[:3] == ["docker", "exec", "andyur-spire-server"]
    monkeypatch.setenv("ANDYUR_SPIRE_SERVER_CMD", "/opt/spire/bin/spire-server")
    assert reg._server_cmd() == ["/opt/spire/bin/spire-server"]


# -- gating: nothing runs unless identity + sandbox + registrar are all on ------

def test_disabled_by_default(monkeypatch):
    monkeypatch.setenv("ANDYUR_SANDBOX", "on")
    monkeypatch.delenv("ANDYUR_SPIRE_REGISTRAR", raising=False)
    assert not reg.enabled()   # registrar opt-in missing


def test_enabled_only_with_all_three(monkeypatch):
    monkeypatch.setenv("ANDYUR_SANDBOX", "on")
    monkeypatch.setenv("ANDYUR_SPIRE_REGISTRAR", "on")
    assert reg.enabled()


def test_disabled_without_sandbox(monkeypatch):
    monkeypatch.setenv("ANDYUR_SANDBOX", "off")
    monkeypatch.setenv("ANDYUR_SPIRE_REGISTRAR", "on")
    assert not reg.enabled()


def test_register_and_unregister_are_noops_when_disabled(monkeypatch):
    monkeypatch.setattr(reg, "enabled", lambda: False)
    called = {"n": 0}
    monkeypatch.setattr(reg, "_run", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    reg.register_run("r", "scout")
    reg.unregister_run("r")
    assert called["n"] == 0   # never shelled out to spire-server


# -- unregister finds entries by the label selector, then deletes each id -------

def test_unregister_deletes_every_matching_entry(monkeypatch):
    monkeypatch.setattr(reg, "enabled", lambda: True)
    calls = []

    def fake_run(argv, capture=False):
        calls.append(argv)
        if capture:  # the `entry show` lookup
            return '{"entries": [{"id": "e1"}, {"id": "e2"}]}'
        return ""

    monkeypatch.setattr(reg, "_run", fake_run)
    reg.unregister_run("run-42")
    deletes = [a for a in calls if "delete" in a]
    assert len(deletes) == 2
    assert ["-entryID", "e1"] == deletes[0][-2:]
    assert ["-entryID", "e2"] == deletes[1][-2:]


def test_unregister_tolerates_malformed_show_output(monkeypatch):
    monkeypatch.setattr(reg, "enabled", lambda: True)
    monkeypatch.setattr(reg, "_run", lambda argv, capture=False: "not json" if capture else "")
    reg.unregister_run("run-42")   # must not raise


# -- the daemon mounts the SPIRE socket into the container when the registrar is on

def test_sandbox_argv_mounts_spire_socket_when_registrar_on(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setattr(orchestrator.spire_registrar, "enabled", lambda: True)
    argv = orchestrator._sandbox_argv("scout", "run-7", run_token="tok")
    joined = " ".join(argv)
    assert "andyur-spire-sockets:/run/spire/sockets:ro" in joined
    assert "SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock" in joined
    assert "andyur.run_id=run-7" in joined   # the label the entry is keyed on


def test_sandbox_argv_no_spire_socket_when_registrar_off(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setattr(orchestrator.spire_registrar, "enabled", lambda: False)
    argv = orchestrator._sandbox_argv("scout", "run-7", run_token="tok")
    assert "SPIFFE_ENDPOINT_SOCKET" not in " ".join(argv)


# -- a failed container launch rolls back the run's SPIRE entry (F3) ------------

def test_launch_failure_unregisters_the_entry(monkeypatch, tmp_path):
    from andyur.daemon import daemon as daemon_mod
    from andyur.daemon import orchestrator
    monkeypatch.setattr(daemon_mod, "RUNLOG_DIR", tmp_path)
    events = []
    monkeypatch.setattr(orchestrator.spire_registrar, "register_run",
                        lambda rid, ag, ttl=None: events.append(("register", rid, ttl)))
    monkeypatch.setattr(orchestrator.spire_registrar, "unregister_run",
                        lambda rid: events.append(("unregister", rid)))

    def boom(*a, **k):
        raise OSError("docker not found")

    monkeypatch.setattr(orchestrator.subprocess, "Popen", boom)
    d = daemon_mod.Daemon()
    d.orch = orchestrator.ContainerOrchestrator()
    with pytest.raises(OSError):
        d.launch("run-9", "scout")
    # registered, then rolled back when the launch failed -- no leaked entry
    # The third element is the run's granted wall clock, threaded so the SPIRE
    # entry is sized for THIS run rather than the platform default.
    assert [(kind, rid) for kind, rid, *_ in events] == [
        ("register", "run-9"), ("unregister", "run-9")]
    assert "run-9" not in d.procs


# --- per-run entry sizing: R's MED, previously zero coverage ---------------

def test_the_entry_is_sized_for_the_runs_own_grant():
    """The module default is sized from the DAEMON's platform TTL. A run
    granted longer got an entry too short to cover it, and its first tool call
    was refused fail-closed on an SVID that could not outlive the run."""
    from andyur import spire_registrar as reg
    assert reg._entry_ttl_for(7200) == str(2 * 7200 + 300)
    assert reg._entry_ttl_for(None) == reg.ENTRY_JWT_TTL
    assert reg._entry_max_age_for(7200) >= 7200


def test_a_grant_beyond_the_ca_ceiling_is_clamped_and_reported(capsys):
    """A JWT-SVID cannot outlive the CA that signs it. Asking for more yields a
    SHORTER token than requested, the runner's freshness check refuses it, and
    every managed tool call is withheld WHILE THE RUN KEEPS GOING -- the
    delegation disappears and nothing says so.

    So the ask is clamped and the shortfall is reported with the exact numbers,
    because an operator seeing the symptom has no route back to this ceiling
    without them.
    """
    from andyur import spire_registrar as reg
    ttl = reg._entry_ttl_for(7 * 24 * 3600)
    assert ttl == str(reg.MAX_ENTRY_JWT_TTL)
    out = capsys.readouterr().out
    assert "actor identity will expire" in out
    assert str(reg.MAX_ENTRY_JWT_TTL) in out


def test_the_argv_carries_the_per_run_ttl_not_the_module_default():
    """The value has to reach the actual `entry create`, not merely be
    computed."""
    from andyur import spire_registrar as reg
    argv = reg.register_argv("r", "a", 123, 7200)
    assert argv[argv.index("-jwtSVIDTTL") + 1] == str(2 * 7200 + 300)

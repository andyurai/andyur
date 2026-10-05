"""The two-container pod: what each half gets, and what it must not get.

The whole security argument of the split is a SUBTRACTION, and a subtraction is
invisible: nothing fails when a credential is passed to the container that was
supposed to hold none. These tests read both commands back and assert what is
absent as carefully as what is present.
"""

import importlib

import pytest


@pytest.fixture
def orch(monkeypatch):
    import andyur.daemon.orchestrator as mod
    importlib.reload(mod)
    return mod


def sidecar_argv(orch, **kw):
    return orch._sandbox_argv("alice", "run-1", pod=True, **kw)


def agent_argv(orch, **kw):
    return orch._agent_argv("alice", "run-1", **kw)


def _env(argv):
    return [argv[i + 1] for i, v in enumerate(argv) if v == "-e"]


# --- the pod is actually a pod ---------------------------------------------

def test_the_agent_is_single_homed_on_its_own_per_run_network(orch):
    """O1 (F3 remediation): the agent gets its OWN netns on this run's internal
    network, NOT the sidecar's netns. That is what makes it a true sink -- it no
    longer inherits the sidecar's egress to the control plane. It must NOT carry
    a `container:` netns share, and its network is the per-run network."""
    a = agent_argv(orch)
    # EXACTLY ONE --network, and it is the per-run net -- so appending a second
    # --network (e.g. andyur-runs, the dual-homing that would re-expose the
    # agent) reddens this, not just a wrong first value.
    assert a.count("--network") == 1
    assert a[a.index("--network") + 1] == orch.run_network("run-1") == "andyur-net-run-1"
    assert not any(str(v).startswith("container:") for v in a)


def test_the_two_containers_have_distinct_non_overlapping_names(orch):
    """A prefix, not a suffix, deliberately: `docker ps --filter
    name=^andyur-run-` must match sidecars and ONLY sidecars, or the agent half
    of run X is adopted as a phantom run called "X-agent" -- reported executing,
    subtracted from free slots, and condemned forever."""
    assert orch.run_container("run-1") == "andyur-run-run-1"
    assert orch.agent_container("run-1") == "andyur-agent-run-1"
    assert not orch.agent_container("run-1").startswith(orch.RUN_PREFIX)


def test_the_agent_is_pointed_at_the_channel_port_the_sidecar_binds(orch):
    """Both halves must agree on the port without talking first, since the agent
    starts before the sidecar is listening. Under O1 the agent addresses the
    sidecar by its per-run-network alias, not loopback, and the sidecar is told
    to advertise that alias."""
    from andyur import config
    a = agent_argv(orch)
    assert f"http://{orch.SIDECAR_ALIAS}:{config.CHANNEL_PORT}" in a
    assert "http://127.0.0.1:" + str(config.CHANNEL_PORT) not in a
    env = _env(sidecar_argv(orch))
    assert f"ANDYUR_CHANNEL_PORT={config.CHANNEL_PORT}" in env
    assert f"ANDYUR_ADVERTISE_HOST={orch.SIDECAR_ALIAS}" in env


# --- O1: the per-run network lifecycle --------------------------------------

def test_launch_creates_a_per_run_network_and_connects_the_sidecar_by_alias(orch, monkeypatch):
    """O1: before the agent starts there must be a per-run internal network with
    the sidecar attached under the alias the agent addresses it by. Prove the
    orchestration performs create -> (sidecar up) -> connect(alias), in order."""
    calls = []
    monkeypatch.setattr(orch, "_net_rm", lambda name: calls.append(("rm", name)))
    monkeypatch.setattr(orch, "_net_create",
                        lambda name: calls.append(("create", name)) or True)
    monkeypatch.setattr(orch, "_net_connect",
                        lambda name, container, alias: calls.append(("connect", name, container, alias)) or True)
    monkeypatch.setattr(orch.PodOrchestrator, "_wait_until_running",
                        lambda self, name, deadline, proc=None: True)
    # super().launch and the agent Popen are the parts that touch real docker;
    # stub them so we test only the network orchestration.
    monkeypatch.setattr(orch.ContainerOrchestrator, "launch",
                        lambda self, spec, logfile: object())
    monkeypatch.setattr(orch.subprocess, "Popen", lambda *a, **k: object())

    from andyur.daemon.orchestrator import RunSpec
    pod = orch.PodOrchestrator()
    spec = RunSpec(agent="alice", run_id="run-1", run_type="headless")
    pod.launch(spec, logfile=None)

    net = orch.run_network("run-1")
    assert ("create", net) in calls
    assert ("connect", net, orch.run_container("run-1"), orch.SIDECAR_ALIAS) in calls
    # create must precede connect
    assert calls.index(("create", net)) < calls.index(
        ("connect", net, orch.run_container("run-1"), orch.SIDECAR_ALIAS))


def test_cleanup_removes_the_per_run_network(orch, monkeypatch):
    removed = []
    monkeypatch.setattr(orch, "_net_rm", lambda name: removed.append(name))
    monkeypatch.setattr(orch.subprocess, "run",
                        lambda *a, **k: __import__("types").SimpleNamespace(returncode=0, stdout="", stderr=""))
    pod = orch.PodOrchestrator()
    pod.cleanup("run-1")
    assert orch.run_network("run-1") in removed


def test_sweep_reaps_orphan_run_networks_but_keeps_live_ones(orch, monkeypatch):
    """The create/cleanup comments promise sweep reaps leaked per-run networks
    (the daemon-restart / adopted-run leak that would exhaust Docker's address
    pool). Prove it: an orphan network (no live sidecar) is removed, a live one
    is kept."""
    removed = []
    monkeypatch.setattr(orch, "_net_rm", lambda name: removed.append(name))
    monkeypatch.setattr(orch.subprocess, "run",
                        lambda *a, **k: __import__("types").SimpleNamespace(returncode=0, stdout="", stderr=""))
    # run-1 is live (its sidecar container is up); run-2 is not.
    monkeypatch.setattr(orch.PodOrchestrator, "_list_names",
                        lambda self, prefix: ["run-1"] if prefix == orch.RUN_PREFIX else [])
    monkeypatch.setattr(orch, "_list_run_networks",
                        lambda: [orch.run_network("run-1"), orch.run_network("run-2")])
    orch.PodOrchestrator().sweep()
    assert orch.run_network("run-2") in removed          # orphan reaped
    assert orch.run_network("run-1") not in removed      # live one kept


def test_sweep_reaps_nothing_when_it_cannot_ask_which_sidecars_are_live(orch, monkeypatch):
    """A transient `docker ps` failure must not read every network as an orphan
    and tear them out from under healthy pods."""
    removed = []
    monkeypatch.setattr(orch, "_net_rm", lambda name: removed.append(name))
    monkeypatch.setattr(orch.PodOrchestrator, "_list_names",
                        lambda self, prefix: None if prefix == orch.RUN_PREFIX else [])
    monkeypatch.setattr(orch, "_list_run_networks",
                        lambda: [orch.run_network("run-1"), orch.run_network("run-2")])
    orch.PodOrchestrator().sweep()
    assert removed == []                                 # safety: destroy nothing


def test_advertise_host_picks_the_alias_in_docker_pod_and_pod_ip_in_k8s(monkeypatch):
    import importlib
    from andyur import config
    from andyur.runner import runner as r
    importlib.reload(r)
    # docker pod: ANDYUR_ADVERTISE_HOST drives it
    monkeypatch.setattr(r.config, "DEPLOYMENT", "docker")
    monkeypatch.setenv("ANDYUR_ADVERTISE_HOST", "sidecar")
    assert r._advertise_host() == "sidecar"
    # loopback shapes: no advertise
    monkeypatch.delenv("ANDYUR_ADVERTISE_HOST", raising=False)
    assert r._advertise_host() == ""
    # k8s: the pod IP, required
    monkeypatch.setattr(r.config, "DEPLOYMENT", "kubernetes")
    monkeypatch.setenv("ANDYUR_POD_IP", "10.1.2.3")
    assert r._advertise_host() == "10.1.2.3"


# --- what the agent container must NOT hold ---------------------------------

def test_the_agent_container_gets_no_run_token_and_no_broker_token(orch):
    """The point of the whole split. The agent runs untrusted code; it must have
    nothing to steal."""
    a = agent_argv(orch, channel_token="chtok")
    joined = " ".join(a)
    assert "ANDYUR_RUN_TOKEN" not in joined
    assert "ANDYUR_BROKER_TOKEN" not in joined
    assert "ANDYUR_RUN_TOKEN_SECRET" not in joined


def test_the_agent_container_gets_no_control_plane_address(orch):
    """It never calls the control plane -- it calls the sidecar, which does. Not
    handing it the address keeps that true by construction."""
    assert "ANDYUR_SERVER_URL" not in " ".join(agent_argv(orch))


def test_the_agent_container_gets_no_spire_socket(orch, monkeypatch):
    """The identity root stays in the trusted half. With no Workload API socket
    the agent cannot attest as anything, so it holds no identity and cannot ask
    for one."""
    monkeypatch.setattr(orch.spire_registrar, "enabled", lambda: True)
    a = agent_argv(orch)
    assert "-v" not in a
    assert "SPIFFE_ENDPOINT_SOCKET" not in " ".join(a)
    # ...while the sidecar does get it
    assert "SPIFFE_ENDPOINT_SOCKET" in " ".join(sidecar_argv(orch))


def test_the_agent_container_mounts_no_host_filesystem(orch):
    assert "-v" not in agent_argv(orch)


# --- the uid split is retired, not merely unused ----------------------------

def test_the_agent_container_runs_unprivileged_from_pid_1(orch):
    a = agent_argv(orch)
    assert a[a.index("--user") + 1] == f"{orch.AGENT_UID}:{orch.AGENT_UID}"


def test_the_agent_container_cannot_drop_or_gain_privilege(orch):
    """It starts unprivileged, so it needs no capability to drop to a lower uid,
    and no-new-privileges stops it climbing."""
    a = agent_argv(orch)
    assert a[a.index("--cap-drop") + 1] == "ALL"
    assert "--cap-add" not in a
    assert "no-new-privileges" in a


def test_the_setpriv_wrapper_is_disabled_in_the_agent_container(orch):
    """The wrapper exists to drop a ROOT runner's child to the agent uid. There
    is no root runner in this container, so the SDK must spawn the real CLI
    directly. Blanked rather than left unset, because the image's own ENV would
    otherwise supply it."""
    assert "ANDYUR_AGENT_CLI=" in _env(agent_argv(orch))


def test_the_sidecar_keeps_setuid_because_it_still_spawns_the_cli(orch):
    """A NARROWER claim than the one first written here, corrected because the
    wider one broke things silently. The pod retires the uid split for the
    HEADLESS agent, which is the untrusted code and now lives in its own
    container. But two paths still spawn the Claude CLI inside the SIDECAR --
    conversational runs and graph capture -- and without CAP_SETUID the setpriv
    wrapper fails closed, so dropping it made every conversational run fail and
    made graph capture silently return nothing."""
    for argv in (sidecar_argv(orch), orch._sandbox_argv("alice", "run-1", pod=False)):
        added = {argv[i + 1] for i, v in enumerate(argv) if v == "--cap-add"}
        assert added == {"SETUID", "SETGID"}
    # ...while the agent container, which runs the untrusted agent, gets none
    assert "--cap-add" not in agent_argv(orch)


# --- what the sidecar keeps -------------------------------------------------

def test_the_sidecar_holds_both_credentials(orch):
    env = _env(sidecar_argv(orch, run_token="RT", broker_token="BT",
                            channel_token="CT"))
    assert "ANDYUR_RUN_TOKEN=RT" in env
    assert "ANDYUR_BROKER_TOKEN=BT" in env
    assert "ANDYUR_CHANNEL_TOKEN=CT" in env


def test_both_halves_share_the_channel_credential(orch):
    """The daemon mints it and gives each half a copy: the sidecar to check
    against, the agent to present. A mismatch here means the agent can never
    connect, which looks exactly like a hung run."""
    assert "ANDYUR_CHANNEL_TOKEN=CT" in _env(sidecar_argv(orch, channel_token="CT"))
    assert "ANDYUR_CHANNEL_TOKEN=CT" in _env(agent_argv(orch, channel_token="CT"))


def test_the_split_mode_reaches_the_container_in_every_shape(orch, monkeypatch):
    """It used to be injected only in the pod branch, so
    `ANDYUR_SANDBOX=on ANDYUR_AGENT_SPLIT=process` started a container whose
    runner saw no split variable and quietly ran the SINGLE-PROCESS shape: the
    documented "two processes, one container" did not exist under sandboxing."""
    from andyur import config
    monkeypatch.setattr(config, "AGENT_SPLIT_MODE", "process")
    assert "ANDYUR_AGENT_SPLIT=process" in _env(orch._sandbox_argv("a", "r", pod=False))
    monkeypatch.setattr(config, "AGENT_SPLIT_MODE", "off")
    assert "ANDYUR_AGENT_SPLIT=off" in _env(orch._sandbox_argv("a", "r", pod=False))
    # pod always says pod, whatever the daemon's own mode string is
    assert "ANDYUR_AGENT_SPLIT=pod" in _env(orch._sandbox_argv("a", "r", pod=True))


def test_pod_without_the_sandbox_is_refused(orch, monkeypatch):
    """It used to fall through to the HOST shape while the runner still believed
    it was a pod sidecar: an unauthenticated channel bound on the host's loopback
    serving the run's prompt, then a full connect-timeout wait for a container
    nobody would start."""
    from andyur import config
    monkeypatch.setattr(config, "DEPLOYMENT", "docker")
    monkeypatch.setattr(config, "SANDBOX", False)
    monkeypatch.setattr(config, "AGENT_SPLIT_POD", True)
    with pytest.raises(config.InsecureProfile, match="needs ANDYUR_SANDBOX=on"):
        orch.select()


def test_the_sidecar_is_told_it_is_a_pod_sidecar(orch):
    """Without this it would spawn its own agent PROCESS as well as waiting for
    the agent CONTAINER, and the run would have two agents."""
    assert "ANDYUR_AGENT_SPLIT=pod" in _env(sidecar_argv(orch))


def test_both_halves_are_resource_bounded(orch):
    for argv in (sidecar_argv(orch), agent_argv(orch)):
        for flag in ("--memory", "--cpus", "--pids-limit"):
            assert flag in argv, flag


def test_both_halves_are_labelled_for_the_run(orch):
    for argv in (sidecar_argv(orch), agent_argv(orch)):
        joined = " ".join(argv)
        assert "andyur.run_id=run-1" in joined
        assert "andyur.agent=alice" in joined


# --- lifecycle --------------------------------------------------------------

def test_kill_destroys_both_halves_in_one_call(orch):
    pod = orch.PodOrchestrator()
    assert pod._names_to_kill(["r1", "r2"]) == [
        "andyur-run-r1", "andyur-agent-r1",
        "andyur-run-r2", "andyur-agent-r2",
    ]


def test_a_sidecar_that_never_starts_tears_the_pod_down(orch, monkeypatch, tmp_path):
    """The agent cannot join a namespace that does not exist. Rather than leave
    half a pod running until the TTL, the launch fails and cleans up."""
    killed = []
    monkeypatch.setattr(orch.subprocess, "Popen",
                        lambda *a, **k: type("P", (), {"pid": 1, "poll": lambda s: None})())
    monkeypatch.setattr(orch.subprocess, "run",
                        lambda argv, **k: killed.append(argv) or type("R", (), {"stdout": "", "returncode": 0})())
    monkeypatch.setattr(orch.PodOrchestrator, "_wait_until_running",
                        lambda self, name, deadline, proc=None: False)
    pod = orch.PodOrchestrator()
    with pytest.raises(RuntimeError, match="did not start"):
        pod.launch(orch.RunSpec(run_id="r1", agent="alice"), open(tmp_path / "l", "w"))
    # both halves were targeted for destruction
    flat = " ".join(" ".join(c) for c in killed)
    assert "andyur-run-r1" in flat and "andyur-agent-r1" in flat


def test_cleanup_destroys_the_agent_container(orch, monkeypatch):
    """The sidecar exiting means the run is over, but the agent container has its
    own lifetime and would otherwise keep running against a dead namespace."""
    calls = []
    monkeypatch.setattr(orch.subprocess, "run",
                        lambda argv, **k: calls.append(argv) or type("R", (), {"stdout": "", "returncode": 0})())
    monkeypatch.setattr(orch.spire_registrar, "unregister_run", lambda rid: None)
    orch.PodOrchestrator().cleanup("r1")
    assert any("andyur-agent-r1" in c for c in calls)


def test_the_agent_half_is_never_reported_as_a_run(orch, monkeypatch):
    """list_running feeds the worker's capacity report and the kill switch. An
    agent container counted as a run would occupy a slot forever and be condemned
    as a run that does not exist."""
    class _Res:
        stdout = "andyur-run-abc123\n"
        returncode = 0

    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return _Res()

    monkeypatch.setattr(orch.subprocess, "run", fake_run)
    assert orch.PodOrchestrator().list_running() == ["abc123"]
    # it asked only for sidecars
    assert f"name=^{orch.RUN_PREFIX}" in seen["argv"]


def test_sweep_refuses_to_act_when_it_cannot_tell_which_sidecars_are_alive(orch, monkeypatch):
    """The destructive-action rule. sweep() kills agent containers whose sidecar
    is absent, and 'the query failed' used to arrive as an empty list -- so ONE
    transient `docker ps` timeout would have read every healthy pod on the worker
    as an orphan and killed the agent half of all of them. An orphan costs a
    container until the next beat; this mistake costs every run in flight."""
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if "--filter" in argv and f"name=^{orch.AGENT_PREFIX}" in argv:
            return type("R", (), {"stdout": "andyur-agent-live1\nandyur-agent-live2\n",
                                  "returncode": 0})()
        # asking which SIDECARS are alive times out
        raise __import__("subprocess").TimeoutExpired(cmd="docker ps", timeout=10)

    monkeypatch.setattr(orch.subprocess, "run", fake_run)
    orch.PodOrchestrator().sweep()
    assert not [c for c in calls if c[:2] == ["docker", "kill"]], \
        "swept live pods on the strength of a failed query"


def test_sweep_also_refuses_when_docker_answers_with_an_error(orch, monkeypatch):
    """A non-zero exit is the daemon answering, but not with an answer. Same rule."""
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if "--filter" in argv and f"name=^{orch.AGENT_PREFIX}" in argv:
            return type("R", (), {"stdout": "andyur-agent-live1\n", "returncode": 0})()
        return type("R", (), {"stdout": "", "returncode": 1})()

    monkeypatch.setattr(orch.subprocess, "run", fake_run)
    orch.PodOrchestrator().sweep()
    assert not [c for c in calls if c[:2] == ["docker", "kill"]]


def test_sweep_kills_agent_containers_whose_sidecar_is_gone(orch, monkeypatch):
    """The case cleanup() cannot cover: a daemon that died and restarted holds no
    memory of the pod, so the sidecar is adopted and killable while its agent
    would linger forever with nothing able to name it."""
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if "--filter" in argv and f"name=^{orch.AGENT_PREFIX}" in argv:
            return type("R", (), {"stdout": "andyur-agent-live1\nandyur-agent-orphan\n",
                                  "returncode": 0})()
        return type("R", (), {"stdout": "andyur-run-live1\n", "returncode": 0})()

    monkeypatch.setattr(orch.subprocess, "run", fake_run)
    orch.PodOrchestrator().sweep()
    kills = [c for c in calls if c[:2] == ["docker", "kill"]]
    assert kills, "no kill was issued for the orphan"
    flat = " ".join(kills[0])
    assert "andyur-agent-orphan" in flat
    assert "andyur-agent-live1" not in flat, "killed an agent whose sidecar is alive"


# --- selection --------------------------------------------------------------

def test_select_returns_the_shape_the_configuration_asks_for(orch, monkeypatch):
    from andyur import config
    monkeypatch.setattr(config, "DEPLOYMENT", "native")
    assert isinstance(orch.select(), orch.HostOrchestrator)
    monkeypatch.setattr(config, "DEPLOYMENT", "docker")
    monkeypatch.setattr(config, "SANDBOX", True)
    monkeypatch.setattr(config, "AGENT_SPLIT_POD", False)
    assert type(orch.select()) is orch.ContainerOrchestrator
    monkeypatch.setattr(config, "AGENT_SPLIT_POD", True)
    assert isinstance(orch.select(), orch.PodOrchestrator)


def test_a_sidecar_that_exited_is_noticed_immediately(orch):
    """Launches are serialised inside one heartbeat, so burning the full ready
    timeout per doomed launch (a missing image exits in milliseconds) spent
    minutes inside a single beat and the control plane declared the worker dead.
    A handle that has already exited is a decision, not something to wait out."""
    import time
    dead = type("P", (), {"poll": lambda s: 125})()
    pod = orch.PodOrchestrator()
    start = time.monotonic()
    # a deadline far in the future: only the exited handle can end this early
    assert pod._wait_until_running("nope", time.monotonic() + 30, dead) is False
    assert time.monotonic() - start < 1.0

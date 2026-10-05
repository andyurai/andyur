"""Per-container agent isolation: the agent runs under its own uid (so it cannot
read the runner's /proc and lift the run token), and Andyur refuses the config
where an agent sharing the runner's uid could exec a peer role's binary."""

import pytest

from andyur import identity
from andyur.runner import driver


# -- the uid split: spawn the CLI through the drop-privileges wrapper -----------

def test_spawn_opts_route_through_wrapper_when_image_supports_it(monkeypatch, tmp_path):
    wrapper = tmp_path / "andyur-agent-claude"
    wrapper.write_text("#!/bin/sh\n")
    monkeypatch.setattr(driver, "AGENT_CLI", str(wrapper))
    assert driver._uid_split_on()
    assert driver._spawn_opts() == {"cli_path": str(wrapper)}
    # the agent uid owns its own HOME; the CLI writes config/cache there
    assert driver._agent_env()["HOME"] == driver.AGENT_HOME


def test_no_uid_split_off_sandbox(monkeypatch):
    monkeypatch.setattr(driver, "AGENT_CLI", "")
    assert not driver._uid_split_on()
    assert driver._spawn_opts() == {}   # SDK uses its own CLI resolution
    assert driver._agent_env() == {}    # runner's HOME, unchanged


def test_missing_wrapper_does_not_enable_the_split(monkeypatch):
    # a stale ANDYUR_AGENT_CLI must not silently point the SDK at nothing
    monkeypatch.setattr(driver, "AGENT_CLI", "/nonexistent/andyur-agent-claude")
    assert not driver._uid_split_on()
    assert driver._spawn_opts() == {}


def test_scratch_is_opened_for_the_agent_uid_only_when_split(monkeypatch, tmp_path):
    import os
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    monkeypatch.setattr(driver, "AGENT_CLI", "")
    driver._open_scratch(scratch)
    assert os.stat(scratch).st_mode & 0o777 == 0o700  # untouched without the split

    wrapper = tmp_path / "andyur-agent-claude"
    wrapper.write_text("#!/bin/sh\n")
    monkeypatch.setattr(driver, "AGENT_CLI", str(wrapper))
    driver._open_scratch(scratch)
    # the agent runs as another uid, so its cwd must be writable by it
    assert os.stat(scratch).st_mode & 0o777 == 0o777


# -- the guard: refuse identity-on + unsandboxed (exec-peer-role escalation) ----

def test_refuses_identity_on_without_sandbox(monkeypatch):
    monkeypatch.delenv("ANDYUR_SANDBOX", raising=False)
    monkeypatch.delenv("ANDYUR_ALLOW_UNISOLATED_AGENT", raising=False)
    with pytest.raises(RuntimeError, match="ANDYUR_SANDBOX"):
        identity.assert_agent_isolation()


def test_sandbox_satisfies_the_guard(monkeypatch):
    monkeypatch.setenv("ANDYUR_SANDBOX", "on")
    identity.assert_agent_isolation()  # no raise


def test_explicit_ack_satisfies_the_guard(monkeypatch):
    monkeypatch.delenv("ANDYUR_SANDBOX", raising=False)
    monkeypatch.setenv("ANDYUR_ALLOW_UNISOLATED_AGENT", "on")
    identity.assert_agent_isolation()  # knowingly accepted


def test_the_guard_is_never_inert(monkeypatch):
    """Replaces `test_guard_is_inert_with_identity_off`, which asserted that an
    unsandboxed run is allowed when identity is off.

    That test encoded the hole. The ONE configuration where the agent shares the
    runner's uid and can exec a peer role's binary was also the configuration
    where the guard returned early and never looked. There is no identity-off
    mode now, so the guard has no inert case, and this asserts the absence."""
    monkeypatch.delenv("ANDYUR_SANDBOX", raising=False)
    monkeypatch.delenv("ANDYUR_ALLOW_UNISOLATED_AGENT", raising=False)
    with pytest.raises(RuntimeError, match="ANDYUR_SANDBOX"):
        identity.assert_agent_isolation()


# -- the guard is actually WIRED into both launch paths (not just defined) ------

def test_daemon_run_calls_the_isolation_guard(monkeypatch):
    # if someone drops the guard call from Daemon.run, this fails
    import asyncio
    from andyur.daemon import daemon as daemon_mod
    called = {"n": 0}

    def _boom():
        called["n"] += 1
        raise RuntimeError("guard fired")

    monkeypatch.setattr(daemon_mod.identity, "assert_agent_isolation", _boom)
    with pytest.raises(RuntimeError, match="guard fired"):
        asyncio.run(daemon_mod.Daemon().run())
    assert called["n"] == 1  # run() consulted the guard before doing any work


def test_cli_local_run_calls_the_isolation_guard():
    # the guard call must sit on the local-run path in cmd_trigger
    import inspect
    from andyur import cli
    src = inspect.getsource(cli.cmd_trigger)
    assert "assert_agent_isolation()" in src


# -- extract_graph stays runnable for the agent uid under the split (M1) --------

def test_extract_graph_gets_agent_writable_cwd_under_split(monkeypatch, tmp_path):
    # under the uid split the extractor's cwd must be a dir the agent uid owns,
    # else the CLI's cwd writes fail and capture silently returns nothing
    captured = {}

    class _FakeClient:
        def __init__(self, options=None):
            captured["options"] = options
        async def __aenter__(self): raise RuntimeError("stop before real spawn")
        async def __aexit__(self, *a): return False

    wrapper = tmp_path / "andyur-agent-claude"
    wrapper.write_text("#!/bin/sh\n")
    monkeypatch.setattr(driver, "AGENT_CLI", str(wrapper))
    monkeypatch.setattr(driver, "AGENT_HOME", "/home/agent")
    monkeypatch.setattr(driver, "ClaudeSDKClient", _FakeClient)

    import asyncio
    asyncio.run(driver.extract_graph("purpose", "some transcript"))
    opts = captured["options"]
    assert str(opts.cwd) == "/home/agent"       # agent-owned, writable
    assert opts.cli_path == str(wrapper)          # still runs under the split


def test_extract_graph_sets_no_cwd_without_split(monkeypatch):
    captured = {}

    class _FakeClient:
        def __init__(self, options=None):
            captured["options"] = options
        async def __aenter__(self): raise RuntimeError("stop before real spawn")
        async def __aexit__(self, *a): return False

    monkeypatch.setattr(driver, "AGENT_CLI", "")   # no split
    monkeypatch.setattr(driver, "ClaudeSDKClient", _FakeClient)
    import asyncio
    asyncio.run(driver.extract_graph("purpose", "t"))
    assert captured["options"].cwd is None          # SDK default, unchanged


# -- the container carries per-run labels (what a container-attested entry keys on)

def test_sandbox_argv_labels_the_container_per_run(monkeypatch):
    from andyur.daemon import orchestrator
    argv = orchestrator._sandbox_argv("scout", "run-42", run_token="tok")
    joined = " ".join(argv)
    assert "andyur.run_id=run-42" in joined
    assert "andyur.agent=scout" in joined
    # only the two caps needed to drop to the agent uid are restored
    assert "--cap-drop ALL" in joined
    assert "SETUID" in joined and "SETGID" in joined
    assert "no-new-privileges" in joined


def test_sandbox_argv_attaches_network_when_set(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setattr(orchestrator, "SANDBOX_NETWORK", "andyur-spire-net")
    argv = orchestrator._sandbox_argv("scout", "run-1", run_token="tok")
    assert "--network" in argv and "andyur-spire-net" in argv
    monkeypatch.setattr(orchestrator, "SANDBOX_NETWORK", "")
    assert "--network" not in orchestrator._sandbox_argv("scout", "run-1", run_token="tok")

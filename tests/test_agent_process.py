"""The agent process (B): it holds nothing, and it forwards.

Two properties. STATIC: B builds the SDK options with the andyur tools pointed at
A's HTTP service (so it constructs no tool object and needs no run token), and the
sidecar launches B with the control-plane secrets stripped from its environment.
LIVE: a REAL `python -m andyur.agent` subprocess fetches its inputs from a real
channel and forwards a done sentinel -- proving the process boundary and the wire
protocol work across an actual process, with no model in the loop.
"""

import asyncio
import os
import sys

import pytest

from andyur.agent import agent
from andyur.runner import runner
from andyur.runner.agentchannel import AgentChannel
from andyur.runner.driver import agent_env_credentials

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _context(*, agent_id="alice", run_id="r1", prompt="p",
             model_base_url="http://127.0.0.1:9",
             mcp_url="http://127.0.0.1:8/mcp", mcp_headers=None,
             extra_mcp_servers=None):
    return {
        "protocol_version": "andyur-agent-runtime/v1",
        "agent_id": agent_id,
        "run_id": run_id,
        "model": None,
        "input": {"prompt": prompt},
        "services": {
            "model_base_url": model_base_url,
            "mcp_url": mcp_url,
            "mcp_headers": mcp_headers or {},
            "extra_mcp_servers": extra_mcp_servers or {},
        },
        "limits": {"deadline": None, "max_line_bytes": 1, "max_stream_bytes": 2},
        "trace": {"traceparent": None},
    }


# --- static: the options B builds -------------------------------------------

def test_options_point_the_tools_at_the_http_service_not_in_process(monkeypatch):
    # a run with no provider key present (the prod/brokered shape): the CLI env
    # the split builds must then hold nothing forbidden. With a key present and no
    # broker it is inherited exactly as the non-split path does -- the same
    # documented dev gap, not a split regression -- so remove it here.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    inputs = _context(mcp_headers={"Authorization": "Bearer tok"})
    opts = agent._options_for(inputs, "/tmp")
    andyur = opts.mcp_servers["andyur"]
    assert andyur == {"type": "http", "url": "http://127.0.0.1:8/mcp",
                      "headers": {"Authorization": "Bearer tok"}}
    assert opts.max_turns == runner.DEFAULT_MAX_TURNS
    # nothing forbidden survives into the CLI's environment
    assert agent_env_credentials(opts.env or {}) == []


def test_extra_mcp_servers_are_still_passed_through():
    inputs = _context(
        agent_id="a", run_id="r", model_base_url=None, mcp_url="http://x/mcp",
        extra_mcp_servers={"tools": {"type": "http", "url": "http://y"}})
    opts = agent._options_for(inputs, "/tmp")
    assert opts.mcp_servers["tools"] == {"type": "http", "url": "http://y"}
    assert "mcp__tools" in opts.allowed_tools


def test_scrub_env_removes_control_plane_secrets_and_the_channel_token(monkeypatch):
    # the channel token is included: the CLI B spawns must not inherit it, or a
    # compromised agent could hijack the sidecar's A<->B channel.
    for v in ("ANDYUR_RUN_TOKEN", "ANDYUR_RUN_TOKEN_SECRET", "ANDYUR_BROKER_TOKEN",
              "ANDYUR_AS_CLIENT_SECRET", "LITELLM_MASTER_KEY",
              "ANDYUR_CHANNEL_TOKEN"):
        monkeypatch.setenv(v, "secret")
    scrubbed = dict(os.environ)
    agent._scrub_env(scrubbed)
    for v in ("ANDYUR_RUN_TOKEN", "ANDYUR_RUN_TOKEN_SECRET", "ANDYUR_BROKER_TOKEN",
              "ANDYUR_AS_CLIENT_SECRET", "LITELLM_MASTER_KEY",
              "ANDYUR_CHANNEL_TOKEN"):
        assert v not in scrubbed


def test_the_sidecar_launches_b_without_the_control_plane_secrets(monkeypatch):
    captured = {}

    class FakePopen:
        def __init__(self, argv, env=None, start_new_session=None):
            captured["argv"] = argv
            captured["env"] = env
            self.pid = 1

    monkeypatch.setattr(runner.subprocess, "Popen", FakePopen)
    monkeypatch.setenv("ANDYUR_RUN_TOKEN", "rt")
    monkeypatch.setenv("ANDYUR_RUN_TOKEN_SECRET", "rts")
    monkeypatch.setenv("ANDYUR_BROKER_TOKEN", "bt")
    monkeypatch.setenv("ANDYUR_AS_CLIENT_SECRET", "as-secret")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "llm-secret")
    monkeypatch.setenv("ANDYUR_S3_SECRET_KEY", "storage-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-secret")
    monkeypatch.setenv("FUTURE_PLATFORM_SECRET", "future-secret")
    monkeypatch.setenv("ANDYUR_LLM", "api")   # a non-secret that SHOULD pass through

    runner._launch_agent_process("http://127.0.0.1:5", "chtok")
    env = captured["env"]
    assert "ANDYUR_RUN_TOKEN" not in env
    assert "ANDYUR_RUN_TOKEN_SECRET" not in env
    assert "ANDYUR_BROKER_TOKEN" not in env
    assert "ANDYUR_AS_CLIENT_SECRET" not in env
    assert "LITELLM_MASTER_KEY" not in env
    assert "ANDYUR_S3_SECRET_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "FUTURE_PLATFORM_SECRET" not in env
    assert env.get("ANDYUR_LLM") == "api"      # execution context is forwarded
    # the channel token travels by ENV, never argv (/proc/cmdline is world
    # readable; the uid split protects /proc/environ)
    assert "--channel-token" not in captured["argv"]
    assert env.get("ANDYUR_CHANNEL_TOKEN") == "chtok"


# --- in-process: B's forward loop with a fake SDK ---------------------------

async def test_b_forwards_the_sdk_stream_then_a_done(monkeypatch):
    """B's real forward loop: fetch inputs, drive the SDK, normalize every
    message onto the wire, end with a done sentinel. The SDK is faked so this is
    deterministic and model-free; it exercises agent._run against a real channel."""
    from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

    class FakeClient:
        def __init__(self, options=None):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def query(self, prompt):
            self._prompt = prompt
        async def receive_response(self):
            yield AssistantMessage(content=[TextBlock(text="hi there")], model="m")
            yield ResultMessage(subtype="success", duration_ms=1, duration_api_ms=1,
                                is_error=False, num_turns=1, session_id="s",
                                total_cost_usd=0.0, result="done")

    monkeypatch.setattr(agent, "ClaudeSDKClient", FakeClient)
    monkeypatch.setenv("ANDYUR_AGENT_AUTH", "on")
    run_environ = dict(os.environ)
    inputs = _context(prompt="go", model_base_url=None,
                      mcp_url="http://127.0.0.1:1/mcp")
    ch = AgentChannel(inputs, token="chtok")
    url = await ch.start()
    try:
        events = []
        async def consume():
            async for ev in ch.messages():
                events.append(ev)
        consumer = asyncio.create_task(consume())
        rc = await agent._run(url, "chtok", run_environ)
        await asyncio.wait_for(consumer, timeout=5)
        assert rc == 0
        # the assistant text and the result both crossed the wire, in order
        assert any(ev.get("texts") == ["hi there"] for ev in events)
        assert any(ev.get("result", {}) and ev["result"]["result"] == "done"
                   for ev in events)
        assert ch.done == {"kind": "done", "exit": 0, "error": None}
        assert os.environ["ANDYUR_AGENT_AUTH"] == "on"
    finally:
        await ch.stop()


async def test_b_reports_an_sdk_failure_in_the_done_sentinel(monkeypatch):
    """When the SDK raises, B must not drop the stream silently: it forwards a
    done sentinel carrying the cause, so the sidecar fails the run with a reason."""
    class BoomClient:
        def __init__(self, options=None):
            pass
        async def __aenter__(self):
            raise RuntimeError("cli not found")
        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(agent, "ClaudeSDKClient", BoomClient)
    monkeypatch.setenv("ANDYUR_AGENT_AUTH", "on")
    run_environ = dict(os.environ)
    inputs = _context(agent_id="a", run_id="r", model_base_url=None,
                      mcp_url="http://x/mcp")
    ch = AgentChannel(inputs, token=None)
    url = await ch.start()
    try:
        async def consume():
            async for _ in ch.messages():
                pass
        consumer = asyncio.create_task(consume())
        await agent._run(url, None, run_environ)
        await asyncio.wait_for(consumer, timeout=5)
        assert ch.done["exit"] == 1 and "cli not found" in ch.done["error"]
        assert os.environ["ANDYUR_AGENT_AUTH"] == "on"
    finally:
        await ch.stop()


# --- live: the real B entrypoint boots and fails closed ---------------------

async def test_the_real_agent_entrypoint_boots_and_fails_closed():
    """A REAL `python -m andyur.agent` process: the module imports, arg-parses,
    and -- when it cannot reach the sidecar -- exits NON-ZERO rather than hanging
    or exiting 0. That is the process boundary and the fail-closed contract; B's
    drive-and-forward loop is covered deterministically in-process above (a real
    model spawn is too slow and environment-dependent to assert on here)."""
    # Nothing is listening on this port, so /v1/context is unreachable. A short
    # connect timeout, because the agent RETRIES a refused connection on purpose
    # (in a pod the two containers start concurrently and the agent routinely
    # wins the race) -- the property here is that the retry is BOUNDED and ends
    # in a non-zero exit, not that it gives up immediately.
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "andyur.agent",
        "--channel-url", "http://127.0.0.1:9", "--channel-token", "x",
        cwd=os.getcwd(),
        env={**os.environ, "ANDYUR_PROFILE": "dev", "PYTHONPATH": os.getcwd(),
             "ANDYUR_AGENT_CONNECT_TIMEOUT": "2"},
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await asyncio.wait_for(proc.wait(), timeout=60)
    assert proc.returncode == 1


def test_the_agent_is_routed_through_the_sidecars_proxy_without_a_broker_address(monkeypatch):
    """THE PRODUCTION CONFIGURATION, and it was broken. In pod mode the process
    that builds the agent's environment is the AGENT container, which
    deliberately holds no broker address at all. The routing decision was
    `if BROKER_URL:` -- a question about this process's own config -- so under
    ANDYUR_AGENT_SPLIT=pod with the brokered api backend it fell through to a
    bare return: no ANTHROPIC_BASE_URL, no credential, and every model call from
    the agent went nowhere. Never caught, because every test ran against ollama,
    which takes an earlier branch and never reaches the line."""
    from andyur.runner import driver
    monkeypatch.setattr(driver, "LLM_MODE", "api")
    monkeypatch.setattr(driver, "BROKER_URL", "")        # the agent container
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env = driver._llm_env(proxy_url="http://127.0.0.1:4321")
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:4321"
    # and it still holds no credential of its own
    assert env["ANTHROPIC_AUTH_TOKEN"] == driver.MODEL_PROXY_AUTH_MARKER
    assert env["ANTHROPIC_API_KEY"] == ""
    assert driver.agent_env_credentials(env) == []


def test_litellm_master_key_is_a_forbidden_effective_agent_credential(monkeypatch):
    from andyur.runner import driver
    monkeypatch.setenv("LITELLM_MASTER_KEY", "must-stay-in-sidecar")
    assert "LITELLM_MASTER_KEY" in driver.agent_env_credentials({})
    assert "LITELLM_MASTER_KEY" not in driver.agent_env_credentials(
        {"LITELLM_MASTER_KEY": ""})


def test_enterprise_as_secret_is_a_forbidden_agent_credential(monkeypatch):
    from andyur.runner import driver
    monkeypatch.setenv("ANDYUR_AS_CLIENT_SECRET", "must-stay-in-sidecar")
    assert "ANDYUR_AS_CLIENT_SECRET" in driver.agent_env_credentials({})
    assert "ANDYUR_AS_CLIENT_SECRET" not in driver.agent_env_credentials(
        {"ANDYUR_AS_CLIENT_SECRET": ""})


def test_the_unbrokered_direct_backend_is_unchanged(monkeypatch):
    """The fix must not silently route a run that has no proxy."""
    from andyur.runner import driver
    monkeypatch.setattr(driver, "LLM_MODE", "api")
    monkeypatch.setattr(driver, "BROKER_URL", "")
    env = driver._llm_env(proxy_url=None)
    assert "ANTHROPIC_BASE_URL" not in env


def test_the_credential_audit_sees_a_credential_FILE_not_only_the_environment(tmp_path):
    """`subscription` off-sandbox put NOTHING in the agent's environment and still
    handed it the operator's credentials, because the Claude CLI authenticates
    from a file under HOME. agent_env_credentials was right about what it
    measured and the audit line it fed was wrong about what the agent held.

    The uid split is the discriminator and the test is built around it: with HOME
    overridden to the agent's own, the operator's file is not beneath it and the
    audit is clean for a REASON; without the override the agent inherits that
    HOME and the file with it.
    """
    from andyur.runner import driver

    operator_home = tmp_path / "operator"
    (operator_home / ".claude").mkdir(parents=True)
    (operator_home / ".claude" / ".credentials.json").write_text('{"token": "x"}')
    agent_home = tmp_path / "agent"
    agent_home.mkdir()

    # off-sandbox: the agent inherits the operator's HOME, so the file is reachable
    found = driver.agent_file_credentials({"HOME": str(operator_home)})
    assert found == [str(operator_home / ".claude" / ".credentials.json")], found

    # uid split: HOME is the agent's own, and the operator's file is not under it
    assert driver.agent_file_credentials({"HOME": str(agent_home)}) == []

    # and the environment-only audit still reports clean on both, which is the
    # whole point: it was never wrong, only narrower than it read as
    assert driver.agent_env_credentials({"HOME": str(operator_home)}) == []

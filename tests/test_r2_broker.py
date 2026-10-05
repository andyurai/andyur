"""R2 secret isolation: the model broker holds the provider key (the agent never
sees it), and the runner scrubs credentials from the agent subprocess env."""

import pytest
from fastapi.testclient import TestClient

from andyur import broker
from andyur.runner import driver


# -- the broker injects its held key and strips the client's auth --------------

def test_broker_injects_held_key_and_strips_client_auth(monkeypatch):
    monkeypatch.setattr(broker, "_API_KEY", "sk-ant-REAL-SECRET")
    # even if the agent tries to send its own auth, it is dropped and replaced
    out = broker._forward_headers({
        "x-api-key": "client-attempt",
        "authorization": "Bearer client-token",
        "content-type": "application/json",
        "host": "broker.local",
    })
    assert out["x-api-key"] == "sk-ant-REAL-SECRET"   # broker's key, injected
    assert "authorization" not in out                  # client auth dropped
    assert "host" not in out                           # hop-by-hop dropped
    assert out["content-type"] == "application/json"   # normal headers pass
    assert out["anthropic-version"]                    # required header supplied


@pytest.mark.parametrize("header", [
    "connection", "keep-alive", "te", "upgrade", "proxy-authorization", "expect",
])
def test_hop_by_hop_headers_are_not_forwarded_upstream(header, monkeypatch):
    """RFC 9110 hop-by-hop headers describe THIS connection, not the next one.

    proxy-authorization is the one that matters most: it is a credential
    addressed to the proxy, so forwarding it hands the provider something it was
    never meant to see. The rest let the agent influence a connection it is not
    party to.
    """
    monkeypatch.setattr(broker, "_API_KEY", "sk-ant-REAL-SECRET")
    out = broker._forward_headers({header: "x", "content-type": "application/json"})
    assert header not in {k.lower() for k in out}


@pytest.mark.parametrize("header", ["date", "server"])
def test_the_upstream_date_and_server_are_not_forwarded(header):
    """RFC 9110 makes Date a singleton, and uvicorn generates its own.

    Forwarding the upstream's produced two of each at the client, compounding
    per hop (agent -> model proxy -> broker -> provider). The commit that fixed
    this said the header work was "asserted by a test"; the test covered only
    the REQUEST side, so reverting either _DROP_RESP left the whole suite green.
    """
    from andyur.runner import modelproxy
    assert header in broker._DROP_RESP
    assert header in modelproxy._DROP_RESP


def test_the_response_filter_actually_removes_them():
    """...and not merely that the constant lists them: the filter is a
    comprehension in two files, and a test on the constant alone would pass if
    someone stopped applying it."""
    from andyur.runner import modelproxy
    upstream = {"date": "Mon, 01 Jan 2035 00:00:00 GMT", "server": "upstream/1.0",
                "content-type": "application/json", "content-encoding": "gzip"}
    for dropped in (broker._DROP_RESP, modelproxy._DROP_RESP):
        kept = {k: v for k, v in upstream.items() if k.lower() not in dropped}
        assert "date" not in kept and "server" not in kept
        assert "content-encoding" not in kept       # body is handed back decoded
        assert kept["content-type"] == "application/json"


def test_both_proxies_drop_the_same_hop_by_hop_set():
    """The two hops must agree. A header the first forwards is one the second
    has to decide about again, and the answer should not depend on which."""
    from andyur.runner import modelproxy
    hop = {"connection", "keep-alive", "te", "trailer", "transfer-encoding",
           "upgrade", "proxy-authorization", "proxy-connection", "expect"}
    assert hop <= broker._DROP_REQ
    assert hop <= modelproxy._DROP_REQ


def test_broker_with_no_key_configured_injects_nothing(monkeypatch):
    monkeypatch.setattr(broker, "_API_KEY", "")
    out = broker._forward_headers({"content-type": "application/json"})
    assert "x-api-key" not in out


def test_broker_health():
    assert TestClient(broker.app).get("/healthz").json() == {"ok": True}


# -- the runner scrubs secrets from the agent subprocess -----------------------

def test_brokered_api_mode_removes_key_from_agent(monkeypatch):
    monkeypatch.setattr(driver, "LLM_MODE", "api")
    monkeypatch.setattr(driver, "BROKER_URL", "http://broker.local:8643")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")

    env = driver._llm_env()

    assert env["ANTHROPIC_BASE_URL"] == "http://broker.local:8643"
    assert env["ANTHROPIC_API_KEY"] == ""             # blanked for the subprocess
    assert env["ANDYUR_RUN_TOKEN"] == ""              # token scrubbed too
    import os
    assert "ANTHROPIC_API_KEY" not in os.environ      # popped from the runner as well


def test_unbrokered_api_mode_still_scrubs_the_run_token(monkeypatch):
    monkeypatch.setattr(driver, "LLM_MODE", "api")
    monkeypatch.setattr(driver, "BROKER_URL", "")
    env = driver._llm_env()
    assert env["ANDYUR_RUN_TOKEN"] == ""
    assert env["ANDYUR_RUN_TOKEN_SECRET"] == ""
    assert "ANTHROPIC_BASE_URL" not in env  # no broker: unchanged model routing


# -- the EFFECTIVE agent env, under the SDK's real merge semantics -------------
# The SDK spawns the CLI with {**os.environ, **options.env} (overrides win), so
# a credential in the runner's environment reaches the agent unless the
# overrides blank it. Testing _llm_env's dict alone missed exactly that: the
# broker token was never in the dict, and therefore always in the agent.

def test_agent_never_inherits_the_broker_credential(monkeypatch):
    monkeypatch.setattr(driver, "LLM_MODE", "api")
    monkeypatch.setattr(driver, "BROKER_URL", "http://broker.local:8643")
    # what the daemon delivers into the runner's environment for every run
    monkeypatch.setenv("ANDYUR_BROKER_TOKEN", "brk-SECRET")
    monkeypatch.setenv("ANDYUR_RUN_TOKEN", "run-SECRET")

    held = driver.agent_env_credentials(driver._llm_env("http://127.0.0.1:5"))

    assert held == [], f"agent subprocess would hold: {held}"


def test_agent_env_audit_reports_an_inherited_key(monkeypatch):
    # The audit must be falsifiable: plant a credential the overrides do NOT
    # blank and it must be reported. An audit that cannot name a leak would be
    # the vacuous e2e check all over again, one layer down.
    monkeypatch.setattr(driver, "LLM_MODE", "subscription")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    held = driver.agent_env_credentials({})
    assert held == ["ANTHROPIC_API_KEY"]


def test_ollama_placeholder_is_not_reported_as_a_credential(monkeypatch):
    monkeypatch.setattr(driver, "LLM_MODE", "ollama")
    for var in driver._AGENT_ENV_FORBIDDEN:
        monkeypatch.delenv(var, raising=False)
    held = driver.agent_env_credentials(driver._llm_env())
    assert held == []


def test_the_run_token_leaves_the_environment_entirely(monkeypatch):
    """Scrubbing the override dict is not enough, because not every spawn uses
    it.

    The SDK runs a version check before the real launch, `open_process([cli, -v])`
    with NO env argument, so that child inherits os.environ verbatim -- and under
    the uid split `cli` is the setpriv wrapper that drops to the AGENT's uid. So
    a process ran as the agent holding the control-plane run token, twice per
    run, while the audit correctly reported the audited spawn held nothing.
    """
    import os
    from andyur import identity

    monkeypatch.setattr(identity, "_sealed_run_token", None)
    monkeypatch.setenv("ANDYUR_RUN_TOKEN", "run-SECRET")

    identity.seal_run_token()

    assert "ANDYUR_RUN_TOKEN" not in os.environ, "an unenveloped spawn would inherit it"
    # ...and the runner can still authenticate as itself
    assert identity.run_token_header()["X-Andyur-Run-Token"] == "run-SECRET"


def test_the_sdk_version_check_spawn_is_disabled(monkeypatch):
    """The guard the SDK reads is os.environ, not options.env, so it can only be
    set here. Pinned because the pop above and this flag close the same hole from
    two sides, and a future SDK could add another unenveloped spawn."""
    import inspect
    import os
    from claude_agent_sdk._internal.transport import subprocess_cli
    from andyur import identity

    # the SDK still spawns without an env argument -- if this stops being true,
    # this test should be revisited rather than deleted
    src = inspect.getsource(subprocess_cli.SubprocessCLITransport._check_claude_version)
    assert "open_process(" in src and "env=" not in src

    monkeypatch.delenv("CLAUDE_AGENT_SDK_SKIP_VERSION_CHECK", raising=False)
    identity.seal_run_token()
    assert os.environ.get("CLAUDE_AGENT_SDK_SKIP_VERSION_CHECK") == "1"


def test_runner_pops_broker_token_from_its_own_environ(monkeypatch):
    import os
    from andyur.runner import runner as runner_mod
    monkeypatch.setenv("ANDYUR_BROKER_TOKEN", "brk-SECRET")
    # ollama mode: the proxy is not started, but the credential must STILL be
    # removed from the environment every subprocess inherits from
    monkeypatch.setattr(runner_mod, "LLM_MODE", "ollama")
    runner_mod._start_model_proxy()
    assert "ANDYUR_BROKER_TOKEN" not in os.environ


# -- the runner role env never carries secrets it doesn't need -----------------

def test_runner_role_env_strips_signing_secret_and_storage_creds():
    from andyur import identity
    base = {
        "ANDYUR_RUN_TOKEN_SECRET": "hmac-signing-key",  # forges tokens for ANY agent
        "ANDYUR_S3_SECRET_KEY": "storage-secret",
        "ANDYUR_S3_ACCESS_KEY": "storage-access",
        "ANDYUR_NEO4J_PASSWORD": "graph-pw",
        "ANDYUR_SERVER_URL": "http://server:8642",       # this the runner DOES need
        "PATH": "/usr/bin",
    }
    env = identity.role_env("runner", base=base)
    assert "ANDYUR_RUN_TOKEN_SECRET" not in env   # can't forge other agents' tokens
    assert "ANDYUR_S3_SECRET_KEY" not in env       # can't reach object storage directly
    assert "ANDYUR_S3_ACCESS_KEY" not in env
    assert "ANDYUR_NEO4J_PASSWORD" not in env
    assert env["ANDYUR_SERVER_URL"] == "http://server:8642"  # what it needs stays
    assert env["PATH"] == "/usr/bin"


def test_server_role_env_keeps_the_signing_secret():
    from andyur import identity
    base = {"ANDYUR_RUN_TOKEN_SECRET": "hmac-signing-key"}
    env = identity.role_env("server", base=base)
    assert env["ANDYUR_RUN_TOKEN_SECRET"] == "hmac-signing-key"  # server mints/verifies


# -- the sandbox never passes the provider key into a brokered container --------

def test_sandbox_argv_omits_provider_key_when_brokered(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setattr(orchestrator, "BROKER_URL", "http://127.0.0.1:8643")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    argv = orchestrator._sandbox_argv("scout", "run-1", run_token="tok")
    joined = " ".join(argv)
    assert "sk-ant-real" not in joined                 # key never enters the container
    assert "ANTHROPIC_API_KEY" not in joined
    assert "ANDYUR_BROKER_URL=http://host.docker.internal:8643" in joined  # routed


def test_sandbox_argv_forwards_key_when_unbrokered(monkeypatch):
    from andyur.daemon import orchestrator
    monkeypatch.setattr(orchestrator, "BROKER_URL", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    argv = orchestrator._sandbox_argv("scout", "run-1", run_token="tok")
    assert "ANTHROPIC_API_KEY=sk-ant-real" in " ".join(argv)  # documented fallback


# -- both non-sandbox launch sites (daemon, cli) share one env builder ----------

def test_runner_launch_env_drops_key_when_brokered_and_stamps_token(monkeypatch):
    from andyur import identity
    monkeypatch.setenv("ANDYUR_BROKER_URL", "http://broker:8643")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    monkeypatch.setenv("ANDYUR_RUN_TOKEN_SECRET", "hmac-key")
    env = identity.runner_launch_env(run_token="tok-xyz")
    assert "ANTHROPIC_API_KEY" not in env       # brokered: key stays out of runner /proc
    assert "ANDYUR_RUN_TOKEN_SECRET" not in env  # runner-deny still applied
    assert env["ANDYUR_RUN_TOKEN"] == "tok-xyz"  # identity stamped


def test_runner_launch_env_keeps_key_when_unbrokered(monkeypatch):
    from andyur import identity
    monkeypatch.delenv("ANDYUR_BROKER_URL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    env = identity.runner_launch_env()
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-real"  # unbrokered: runner needs the key

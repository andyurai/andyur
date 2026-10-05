"""The container a run actually gets (single-container mode).

`_sandbox_argv` is the single place the isolation of a run is decided, and it is
a list of strings, so nothing type-checks it and a dropped flag looks like
nothing at all. These tests read the command back and assert the properties that
flag is there to provide -- especially the ones whose absence is silent: a run
still starts, still works, and is simply less contained than the design says.
"""

import importlib

import pytest

from andyur import config


@pytest.fixture
def daemon(monkeypatch):
    # The container argv moved to daemon/orchestrator.py when the daemon grew a
    # second shape (the two-container pod). Same assertions, same behaviour; the
    # fixture follows the module. Reloaded so the module-level env constants pick
    # up whatever a test monkeypatched.
    import andyur.daemon.orchestrator as mod
    importlib.reload(mod)
    return mod


def argv(daemon, **kw):
    return daemon._sandbox_argv("alice", "run-1", **kw)


# --- isolation properties ---------------------------------------------------

def test_all_capabilities_are_dropped(daemon):
    a = argv(daemon)
    assert "--cap-drop" in a and a[a.index("--cap-drop") + 1] == "ALL"


def test_only_the_two_capabilities_needed_to_drop_privilege_are_restored(daemon):
    """SETUID/SETGID exist solely so the runner can drop the untrusted agent to
    its own uid. Anything else added here would be a capability the agent's
    process tree inherits."""
    a = argv(daemon)
    added = {a[i + 1] for i, v in enumerate(a) if v == "--cap-add"}
    assert added == {"SETUID", "SETGID"}


def test_privilege_cannot_be_regained(daemon):
    a = argv(daemon)
    assert "no-new-privileges" in a


def test_no_host_filesystem_is_mounted(daemon, monkeypatch):
    """The mind lives behind the control plane over HTTP, so a run needs zero
    host access. A stray -v is how that stops being true."""
    monkeypatch.setattr(daemon.spire_registrar, "enabled", lambda: False)
    assert "-v" not in argv(daemon)


def test_resources_are_bounded(daemon):
    a = argv(daemon)
    for flag in ("--memory", "--cpus", "--pids-limit"):
        assert flag in a, flag


def test_the_container_is_named_for_the_run(daemon):
    """The kill switch destroys `andyur-run-<id>`. If this name drifts, halting
    a run silently does nothing to the container."""
    a = argv(daemon)
    assert a[a.index("--name") + 1] == "andyur-run-run-1"


def test_the_run_is_labelled_for_per_run_attestation(daemon):
    labels = {v for i, v in enumerate(argv(daemon)) if argv(daemon)[i - 1] == "--label"}
    assert "andyur.run_id=run-1" in labels
    assert "andyur.agent=alice" in labels


# --- credentials ------------------------------------------------------------

def test_the_two_credentials_are_distinct_and_both_arrive(daemon):
    """The run token acts on the control plane and is kept from the agent; the
    broker token is read BY the agent's model client. Sending one where the
    other belongs would either break model calls or hand the agent the platform
    credential."""
    a = argv(daemon, run_token="RUNTOK", broker_token="BROKTOK")
    env = [a[i + 1] for i, v in enumerate(a) if v == "-e"]
    assert "ANDYUR_RUN_TOKEN=RUNTOK" in env
    assert "ANDYUR_BROKER_TOKEN=BROKTOK" in env


def test_the_provider_key_is_not_passed_when_brokered(daemon, monkeypatch):
    """The whole point of the broker: the key never enters the container."""
    monkeypatch.setattr(daemon, "BROKER_URL", "http://broker:8643")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-travel")
    a = argv(daemon)
    assert not any("ANTHROPIC_API_KEY" in x for x in a)


def test_litellm_configuration_reaches_only_the_trusted_runner(daemon, monkeypatch):
    monkeypatch.setattr(daemon, "LITELLM_URL", "http://127.0.0.1:4000")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sidecar-only")
    trusted = _envs(argv(daemon, pod=True))
    untrusted = _envs(daemon._agent_argv("alice", "run-1"))
    assert trusted["ANDYUR_LITELLM_URL"] == "http://host.docker.internal:4000"
    assert trusted["LITELLM_MASTER_KEY"] == "sidecar-only"
    assert "ANDYUR_LITELLM_URL" not in untrusted
    assert "LITELLM_MASTER_KEY" not in untrusted


def test_the_sandbox_is_declared_to_the_agent_runtime(daemon):
    """Without IS_SANDBOX the CLI builds its own bash sandbox, which fails closed
    to a read-only filesystem under our dropped capabilities and blocks the
    agent's writes. A containment flag that breaks the product gets removed."""
    a = argv(daemon)
    assert "IS_SANDBOX=1" in [a[i + 1] for i, v in enumerate(a) if v == "-e"]


# --- the profile difference -------------------------------------------------

def test_production_gives_the_run_no_route_to_the_host(daemon, monkeypatch):
    """A route to the host is a route to everything the host can reach. In
    production the run lives on an internal network and reaches named services
    on it; the gateway alias would only paper over that."""
    monkeypatch.setattr(config, "PROD", True)
    assert "--add-host" not in argv(daemon)


def test_dev_keeps_the_host_gateway_for_local_convenience(daemon, monkeypatch):
    monkeypatch.setattr(config, "PROD", False)
    assert "--add-host" in argv(daemon)


def test_production_does_not_rewrite_service_urls_to_the_host(daemon, monkeypatch):
    monkeypatch.setattr(config, "PROD", True)
    assert daemon._container_url("http://127.0.0.1:8642") == "http://127.0.0.1:8642"


def test_dev_rewrites_loopback_to_the_docker_host(daemon, monkeypatch):
    monkeypatch.setattr(config, "PROD", False)
    assert daemon._container_url("http://127.0.0.1:8642") == \
        "http://host.docker.internal:8642"


def test_the_run_joins_the_configured_network(daemon, monkeypatch):
    monkeypatch.setattr(daemon, "SANDBOX_NETWORK", "andyur-runs")
    a = argv(daemon)
    assert a[a.index("--network") + 1] == "andyur-runs"


# --- the adopter's authorization server reaches the sidecar, and only it -----

def _envs(a: list) -> dict:
    """The -e VAR=VALUE pairs of a docker argv, as a dict."""
    out = {}
    for i, tok in enumerate(a):
        if tok == "-e" and i + 1 < len(a) and "=" in a[i + 1]:
            k, _, v = a[i + 1].partition("=")
            out[k] = v
    return out


def test_framework_default_forwards_the_collector_to_the_run_container(
        monkeypatch):
    monkeypatch.delenv("ANDYUR_OTEL", raising=False)
    monkeypatch.setenv("ANDYUR_OTEL_ENDPOINT", "http://localhost:4318")
    import andyur.daemon.orchestrator as mod
    importlib.reload(mod)
    monkeypatch.setattr(mod.otel, "OTEL_ON", True)
    assert _envs(argv(mod))["ANDYUR_OTEL_ENDPOINT"] == (
        "http://host.docker.internal:4318")


def test_explicit_development_opt_out_does_not_configure_a_collector(
        monkeypatch):
    monkeypatch.setenv("ANDYUR_OTEL", "off")
    monkeypatch.setenv("ANDYUR_OTEL_ENDPOINT", "http://localhost:4318")
    import andyur.daemon.orchestrator as mod
    importlib.reload(mod)
    monkeypatch.setattr(mod.otel, "OTEL_ON", False)
    env = _envs(argv(mod))
    assert env["ANDYUR_OTEL"] == "off"
    assert "ANDYUR_OTEL_ENDPOINT" not in env


def test_explicit_payload_capture_choice_reaches_only_the_runner(monkeypatch):
    monkeypatch.setenv("ANDYUR_OTEL_TOOL_PAYLOADS", "on")
    import andyur.daemon.orchestrator as mod
    importlib.reload(mod)
    assert _envs(argv(mod))["ANDYUR_OTEL_TOOL_PAYLOADS"] == "on"
    assert "ANDYUR_OTEL_TOOL_PAYLOADS" not in _envs(
        mod._agent_argv("alice", "run-1"))


@pytest.fixture
def external_as(monkeypatch):
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "http://localhost:8683/token")
    monkeypatch.setattr(config, "AS_ISSUER", "http://localhost:8683")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "client_one")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "gateway-secret")
    monkeypatch.setattr(config, "AS_JWKS_URL", "http://localhost:8683/jwks")
    monkeypatch.setattr(config, "AS_PROVIDER", "okta")
    monkeypatch.setattr(config, "AS_CAPABILITY", "core")
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", "api://tool/.default")
    monkeypatch.setattr(config, "AS_PRODUCT_VERSION", "managed")
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", "")
    monkeypatch.setattr(config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", "")


def test_the_as_config_reaches_the_sidecar(daemon, external_as):
    """Production-gaps blocker: the host verified the exchange and the container
    never had the variables to attempt it. All four must arrive, because the
    runner builds the gateway's exchange config from exactly these."""
    e = _envs(argv(daemon))
    assert e["ANDYUR_AS_TOKEN_ENDPOINT"].endswith("/token")
    assert e["ANDYUR_AS_ISSUER"] == "http://localhost:8683"
    assert e["ANDYUR_AS_CLIENT_ID"] == "client_one"
    assert e["ANDYUR_AS_CLIENT_SECRET"] == "gateway-secret"
    assert e["ANDYUR_AS_JWKS"].endswith("/jwks")
    assert e["ANDYUR_AS_PROVIDER"] == "okta"
    assert e["ANDYUR_AS_CAPABILITY"] == "core"
    assert e["ANDYUR_AS_RESOURCE_SCOPE"] == "api://tool/.default"
    assert e["ANDYUR_AS_PRODUCT_VERSION"] == "managed"


def test_signed_certification_files_are_proxy_only_read_only_mounts(
        daemon, external_as, tmp_path, monkeypatch):
    evidence = tmp_path / "certification.json"
    public_key = tmp_path / "certifier.pub"
    evidence.write_text('{"signed":true}')
    public_key.write_text("PUBLIC KEY")
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", str(evidence))
    monkeypatch.setattr(
        config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", str(public_key))
    command = argv(daemon)
    mounts = [command[i + 1] for i, value in enumerate(command) if value == "-v"]
    assert f"{evidence.resolve()}:/run/secrets/andyur-as/certification.json:ro" in mounts
    assert f"{public_key.resolve()}:/run/secrets/andyur-as/certifier.pub:ro" in mounts
    env = _envs(command)
    assert env["ANDYUR_AS_CERTIFICATION_FILE"].endswith("/certification.json")
    assert env["ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE"].endswith("/certifier.pub")
    agent = _envs(daemon._agent_argv("alice", "run-1"))
    assert "ANDYUR_AS_CERTIFICATION_FILE" not in agent


def test_the_endpoint_is_rewritten_for_the_container_and_the_issuer_is_not(
        daemon, external_as, monkeypatch):
    """The token endpoint is a network ADDRESS: a host-local one must be
    rewritten or the container dials its own loopback and finds nothing. The
    issuer is an IDENTIFIER compared byte-for-byte against the token's `iss`
    claim: rewriting it makes every validation fail while the network path
    works perfectly, which is the worse failure because it looks like the AS
    is broken."""
    monkeypatch.setattr(config, "PROD", False)
    e = _envs(argv(daemon))
    assert e["ANDYUR_AS_TOKEN_ENDPOINT"] == "http://host.docker.internal:8683/token"
    assert e["ANDYUR_AS_ISSUER"] == "http://localhost:8683"


def test_the_as_secret_never_reaches_the_agent_container(daemon, external_as):
    """_AGENT_FORWARD's short list IS the security claim: the agent container
    carries no credential, no server URL, no SPIRE socket -- and no AS client
    secret. A secret in the agent's environment is a secret in the process an
    injection speaks for."""
    e = _envs(daemon._agent_argv("alice", "run-1"))
    assert not any(k.startswith("ANDYUR_AS_") for k in e), \
        f"AS config leaked into the agent container: {sorted(e)}"


def test_no_as_configured_means_no_as_variables(daemon, monkeypatch):
    """The default path must not change: an empty string exported into the
    container would OVERRIDE a config baked into the image, and 'unset' and
    'empty' are different answers to config.AS_TOKEN_ENDPOINT."""
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "")
    e = _envs(argv(daemon))
    assert not any(k.startswith("ANDYUR_AS_") for k in e)

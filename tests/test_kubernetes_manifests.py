"""Executable contract for the Kubernetes two-Pod run group."""

import dataclasses
import json

import pytest

from andyur.daemon.kubernetes_manifests import (
    ClusterPeer,
    RunGroupSpec,
    build_run_group,
    run_group_names,
)


IMAGE = "registry.example/andyur@sha256:" + "a" * 64
AGENT_IMAGE = "registry.example/agent@sha256:" + "b" * 64
ENVOY_IMAGE = "registry.example/envoy@sha256:" + "c" * 64


def _spec(run_id="run-one"):
    return RunGroupSpec(
        namespace="andyur-runs",
        run_id=run_id,
        generation="worker-a-assignment-one",
        agent_id="runtime-oncall",
        registry_agent_id="agt_oncall",
        proxy_image=IMAGE,
        agent_image=AGENT_IMAGE,
        as_token_endpoint="https://as.example/token",
        as_issuer="https://as.example",
        as_jwks_url="https://as.example/jwks",
        as_client_id="andyur",
        as_provider="reference",
        as_capability="contextual",
        proxy_egress=(
            ClusterPeer("andyur-system", {"app": "andyur-server"}, 8642),
            ClusterPeer("andyur-system", {"app": "andyur-litellm"}, 4000),
            ClusterPeer("enterprise-tools", {"app": "tickets"}, 8798),
        ),
    )


def _broker_spec():
    peer = ClusterPeer(
        "andyur-system", {"app": "andyur-broker-state"}, 9443)
    return dataclasses.replace(
        _spec("d" * 32), broker_enabled=True,
        broker_envoy_image=ENVOY_IMAGE,
        broker_state_host="andyur-broker-state.andyur-system.svc",
        broker_state_port=9443,
        broker_state_peer=peer,
        proxy_egress=(*_spec().proxy_egress, peer),
    )


def _by_kind(resources, kind):
    return [item for item in resources if item["kind"] == kind]


def _pod(resources, component):
    return next(item for item in _by_kind(resources, "Pod")
                if item["metadata"]["labels"]["app.kubernetes.io/component"] == component)


def _env(container):
    return {item["name"]: item for item in container.get("env", [])}


def test_singleton_lease_is_run_scoped_with_128_bit_name_digest():
    old = run_group_names(dataclasses.replace(_spec(), generation="old"))
    new = run_group_names(dataclasses.replace(_spec(), generation="new"))
    other = run_group_names(_spec("run-two"))
    assert old["lease"] == new["lease"]
    assert old["lease"] != other["lease"]
    assert len(old["lease"].removeprefix("andyur-run-").removesuffix("-owner")) == 32
    assert old["proxy"] != new["proxy"]


def test_identity_and_authority_exist_only_in_the_trusted_proxy():
    resources = build_run_group(_spec())
    proxy_resource = _pod(resources, "proxy")
    proxy = proxy_resource["spec"]
    agent = _pod(resources, "agent")["spec"]
    proxy_container, agent_container = proxy["containers"][0], agent["containers"][0]

    assert proxy["automountServiceAccountToken"] is False
    assert proxy_resource["metadata"]["annotations"] == {
        "andyur.agent/id-raw": "runtime-oncall",
        "andyur.run/id-raw": "run-one",
        "andyur.run/generation-raw": "worker-a-assignment-one",
    }
    assert agent["automountServiceAccountToken"] is False
    assert proxy["volumes"][0] == {
        "name": "spiffe-workload-api",
        "csi": {"driver": "csi.spiffe.io", "readOnly": True},
    }
    assert proxy_container["volumeMounts"][0]["mountPath"] == "/spiffe-workload-api"
    assert {v["name"] for v in agent["volumes"]} == {"agent-home", "agent-tmp"}
    assert {v["mountPath"] for v in agent_container["volumeMounts"]} == {
        "/home/agent", "/tmp"}

    proxy_env, agent_env = _env(proxy_container), _env(agent_container)
    names = run_group_names(_spec())
    assert proxy_env["SPIFFE_ENDPOINT_SOCKET"]["value"] == (
        "unix:///spiffe-workload-api/spire-agent.sock"
    )
    assert proxy_env["ANDYUR_SPIFFE_ID"]["value"] == (
        "spiffe://andyur.local/agent/runtime-oncall/run/run-one"
    )
    assert proxy_env["ANDYUR_OTEL"]["value"] == "on"
    assert proxy_env["ANDYUR_POD_IP"]["valueFrom"] == {
        "fieldRef": {"fieldPath": "status.podIP"},
    }
    assert proxy_env["ANDYUR_MCP_PORT"]["value"] == "8766"
    assert proxy_env["ANDYUR_RUN_TOKEN"]["valueFrom"]["secretKeyRef"]["name"] == (
        names["runtime_secret"])
    assert proxy_env["LITELLM_MASTER_KEY"]["valueFrom"]["secretKeyRef"]["name"] == (
        names["runtime_secret"])
    assert agent_env["ANDYUR_CHANNEL_TOKEN"]["valueFrom"]["secretKeyRef"]["name"] == (
        names["channel_secret"])
    assert "SPIFFE_ENDPOINT_SOCKET" not in agent_env
    assert "ANDYUR_RUN_TOKEN" not in agent_env
    assert "LITELLM_MASTER_KEY" not in agent_env
    assert proxy_env["ANDYUR_AS_TOKEN_ENDPOINT"]["value"] == "https://as.example/token"
    assert proxy_env["ANDYUR_AS_JWKS"]["value"] == "https://as.example/jwks"
    assert proxy_env["ANDYUR_AS_PROVIDER"]["value"] == "reference"
    assert proxy_env["ANDYUR_AS_CAPABILITY"]["value"] == "contextual"
    assert proxy_env["ANDYUR_AS_CLIENT_SECRET"]["valueFrom"]["secretKeyRef"][
        "key"] == "as-client-secret"
    assert proxy_env["ANDYUR_AS_CLIENT_SECRET"]["valueFrom"]["secretKeyRef"][
        "optional"] is True
    for secret_name in ("ANDYUR_AS_CLIENT_SECRET", "ANDYUR_AS_TOKEN_ENDPOINT",
                        "ANDYUR_AS_JWKS", "ANDYUR_AS_PROVIDER",
                        "ANDYUR_AS_CAPABILITY"):
        assert secret_name not in agent_env
    assert set(agent_env) == {
        "ANDYUR_RUN_ID", "ANDYUR_AGENT_ID", "ANDYUR_AGENT_CLI", "ANDYUR_LLM", "HOME",
        "ANDYUR_CHANNEL_TOKEN",
    }
    assert agent_env["ANDYUR_AGENT_CLI"]["value"] == "/usr/bin/claude"


def test_byoa_container_gets_only_the_two_published_contract_variables():
    """docs/agent-runtime-protocol-v1.md section 2 promises a third-party
    workload EXACTLY two environment variables, and the controller adds both
    once the proxy's Pod IP is known. Everything this file sets is the BUILTIN
    agent's own configuration, so a BYOA container must receive none of it.

    The one that matters most is ANDYUR_CHANNEL_TOKEN: it carries the SAME
    secret value the contract already exposes as ANDYUR_RUNTIME_TOKEN. Two
    names for one bearer invites an agent to depend on the undocumented name
    and widens what a compromised third-party workload can read, for no
    benefit to it.
    """
    byoa = dataclasses.replace(
        _spec(), agent_runtime="container", ollama_url="http://ollama:11434",
        agent_args=("/app/agent", "serve"))
    agent = _pod(build_run_group(byoa), "agent")["spec"]["containers"][0]
    assert agent.get("env", []) == []
    assert agent["command"] == ["/app/agent", "serve"]

    # positive control: the builtin runtime still receives its configuration,
    # so this asserts a CHOICE and not a globally emptied env block.
    builtin = dataclasses.replace(_spec(), ollama_url="http://ollama:11434")
    builtin_agent = _pod(build_run_group(builtin),
                         "agent")["spec"]["containers"][0]
    assert set(_env(builtin_agent)) == {
        "ANDYUR_RUN_ID", "ANDYUR_AGENT_ID", "ANDYUR_AGENT_CLI", "ANDYUR_LLM",
        "ANDYUR_OLLAMA_URL", "HOME", "ANDYUR_CHANNEL_TOKEN",
    }


def test_byoa_container_still_gets_the_scratch_space_the_spec_promises():
    """Section 8 tells agent authors their workload has "its own scratch space
    (which is ephemeral and destroyed with the workload)". A read-only rootfs
    with nothing writable would make that false, so the emptyDirs stay for
    BYOA -- only the builtin's ENV is withheld."""
    byoa = dataclasses.replace(_spec(), agent_runtime="container",
                               agent_args=("/app/agent",))
    pod = _pod(build_run_group(byoa), "agent")["spec"]
    mounts = {m["mountPath"] for m in pod["containers"][0]["volumeMounts"]}
    assert mounts == {"/home/agent", "/tmp"}
    assert all(volume.get("emptyDir") is not None
               for volume in pod["volumes"]
               if volume["name"] in {"agent-home", "agent-tmp"})


def test_signed_as_evidence_is_mounted_read_only_into_proxy_only():
    resources = build_run_group(dataclasses.replace(
        _spec(), as_product_version="managed", as_certified=True))
    proxy = _pod(resources, "proxy")["spec"]
    agent = _pod(resources, "agent")["spec"]
    proxy_container = proxy["containers"][0]
    env = _env(proxy_container)
    assert env["ANDYUR_AS_PRODUCT_VERSION"]["value"] == "managed"
    assert env["ANDYUR_AS_CERTIFICATION_FILE"]["value"].endswith(
        "/certification.json")
    assert env["ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE"]["value"].endswith(
        "/certifier.pub")
    mount = next(m for m in proxy_container["volumeMounts"]
                 if m["name"] == "as-certification")
    assert mount["readOnly"] is True
    volume = next(v for v in proxy["volumes"]
                  if v["name"] == "as-certification")
    assert {item["key"] for item in volume["secret"]["items"]} == {
        "as-certification", "as-certification-public-key"}
    assert "as-certification" not in {v["name"] for v in agent["volumes"]}


def test_ollama_agent_gets_numeric_url_and_only_the_exact_model_peer():
    model_peer = ClusterPeer("andyur-system", {"app": "andyur-ollama"}, 11434)
    resources = build_run_group(dataclasses.replace(
        _spec(), llm_mode="ollama", ollama_url="http://10.43.147.32:11434",
        agent_model_egress=model_peer))
    agent_env = _env(_pod(resources, "agent")["spec"]["containers"][0])
    assert agent_env["ANDYUR_LLM"]["value"] == "ollama"
    assert agent_env["ANDYUR_OLLAMA_URL"]["value"] == "http://10.43.147.32:11434"
    policy = next(p for p in _by_kind(resources, "NetworkPolicy")
                  if p["metadata"]["name"].endswith("-agent"))
    assert policy["spec"]["egress"][1] == {
        "to": [{
            "namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": "andyur-system"}},
            "podSelector": {"matchLabels": {"app": "andyur-ollama"}},
        }],
        "ports": [{"protocol": "TCP", "port": 11434}],
    }
    assert "'port': 53" not in repr(policy)


def test_real_runtime_commands_and_writable_mounts_are_shipped():
    resources = build_run_group(_spec())
    proxy = _pod(resources, "proxy")["spec"]
    agent = _pod(resources, "agent")["spec"]
    [proxy_container], [agent_container] = proxy["containers"], agent["containers"]
    assert proxy_container["command"][:3] == ["python", "-m", "andyur.runner"]
    assert agent_container["command"][:3] == ["python", "-m", "andyur.agent"]
    assert "--channel-url" in agent_container["command"]
    assert proxy_container["readinessProbe"]["httpGet"] == {
        "path": "/ready", "port": "proxy", "scheme": "HTTP"}
    assert proxy_container["ports"] == [
        {"name": "proxy", "containerPort": 8765},
        {"name": "mcp", "containerPort": 8766},
    ]
    assert {v["mountPath"] for v in proxy_container["volumeMounts"]} == {
        "/spiffe-workload-api", "/app/data", "/tmp"}


def test_broker_mode_uses_native_sidecars_that_end_with_the_runner():
    resources = build_run_group(_broker_spec())
    proxy = _pod(resources, "proxy")["spec"]
    containers = {item["name"]: item for item in [
        *proxy["containers"], *proxy["initContainers"]]}
    assert set(containers) == {"proxy", "deny-broker", "broker-state-envoy"}
    assert [item["name"] for item in proxy["containers"]] == ["proxy"]
    assert [item["name"] for item in proxy["initContainers"]] == [
        "deny-broker", "broker-state-envoy"]
    assert all(item["restartPolicy"] == "Always"
               for item in proxy["initContainers"])
    assert containers["broker-state-envoy"]["image"] == ENVOY_IMAGE
    expected_helper_resources = {
        "cpu": "250m", "memory": "256Mi", "ephemeral-storage": "128Mi"}
    for name in ("deny-broker", "broker-state-envoy"):
        assert containers[name]["resources"] == {
            "requests": expected_helper_resources,
            "limits": expected_helper_resources,
        }
    assert containers["deny-broker"]["readinessProbe"]["exec"]["command"] == [
        "python", "-m", "andyur.dataplane.denybroker", "--check"]
    assert proxy["securityContext"] == {
        "runAsNonRoot": True, "fsGroup": 1000,
        "fsGroupChangePolicy": "OnRootMismatch"}

    runner_mounts = {item["name"] for item in containers["proxy"]["volumeMounts"]}
    assert "broker-state-uds" not in runner_mounts
    assert "broker-authz-uds" not in runner_mounts
    broker_mounts = {
        item["name"] for item in containers["deny-broker"]["volumeMounts"]}
    assert {"spiffe-workload-api", "broker-state-uds", "broker-authz-uds"} \
        <= broker_mounts
    envoy_mounts = {
        item["name"] for item in containers["broker-state-envoy"]["volumeMounts"]}
    assert {"spiffe-workload-api", "broker-state-uds", "broker-envoy-config"} \
        <= envoy_mounts
    assert "runtime-tmp" not in broker_mounts | envoy_mounts
    assert "broker-tmp" not in envoy_mounts
    assert "broker-envoy-tmp" not in broker_mounts

    [config] = _by_kind(resources, "ConfigMap")
    bootstrap = json.loads(config["data"]["bootstrap.json"])
    listener = bootstrap["static_resources"]["listeners"][0]
    assert listener["address"]["pipe"]["path"] == "/run/andyur-state/state.sock"
    cluster = bootstrap["static_resources"]["clusters"][1]
    assert cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0][
        "endpoint"]["address"]["socket_address"] == {
            "address": "andyur-broker-state.andyur-system.svc",
            "port_value": 9443,
        }
    assert cluster["common_http_protocol_options"] == {
        "max_requests_per_connection": 1}


def test_off_mode_has_no_broker_process_socket_config_or_network_peer():
    resources = build_run_group(_spec())
    proxy = _pod(resources, "proxy")["spec"]
    assert [item["name"] for item in proxy["containers"]] == ["proxy"]
    assert _by_kind(resources, "ConfigMap") == []
    assert not any("broker" in volume["name"] for volume in proxy["volumes"])
    assert "andyur-broker-state" not in repr(resources)


@pytest.mark.parametrize("changes, message", [
    ({"broker_envoy_image": "envoy:latest"}, "pinned"),
    ({"broker_state_host": ""}, "DNS"),
    ({"broker_state_port": 0}, "1..65535"),
    ({"proxy_egress": _spec().proxy_egress}, "explicit proxy egress"),
])
def test_broker_mode_refuses_incomplete_or_unbounded_composition(changes, message):
    with pytest.raises(ValueError, match=message):
        build_run_group(dataclasses.replace(_broker_spec(), **changes))


@pytest.mark.parametrize("host", [
    "andyur-broker-state-.andyur-system.svc",
    "andyur-broker-state..andyur-system.svc",
    "andyur-broker-state.andyur-system.svc.",
    "a" * 64 + ".andyur-system.svc",
])
def test_broker_mode_refuses_noncanonical_dns_names(host):
    with pytest.raises(ValueError, match="canonical DNS"):
        build_run_group(dataclasses.replace(_broker_spec(), broker_state_host=host))


def test_broker_mode_refuses_a_different_peer_on_the_same_port():
    wrong = ClusterPeer("other", {"app": "not-the-broker"}, 9443)
    with pytest.raises(ValueError, match="explicit proxy egress"):
        build_run_group(dataclasses.replace(
            _broker_spec(), proxy_egress=(*_spec().proxy_egress, wrong)))


def test_litellm_url_and_key_exist_only_in_the_kubernetes_proxy():
    resources = build_run_group(dataclasses.replace(
        _spec(), litellm_url="http://andyur-litellm.andyur-system.svc:4000"))
    proxy_env = _env(_pod(resources, "proxy")["spec"]["containers"][0])
    agent_env = _env(_pod(resources, "agent")["spec"]["containers"][0])
    assert proxy_env["ANDYUR_LITELLM_URL"]["value"].endswith(":4000")
    assert "LITELLM_MASTER_KEY" in proxy_env
    assert "ANDYUR_LITELLM_URL" not in agent_env
    assert "LITELLM_MASTER_KEY" not in agent_env


def test_both_pods_are_hardened_and_images_are_immutable():
    resources = build_run_group(_spec())
    for pod in _by_kind(resources, "Pod"):
        assert pod["spec"]["securityContext"]["runAsNonRoot"] is True
        assert pod["spec"]["automountServiceAccountToken"] is False
        [container] = pod["spec"]["containers"]
        security = container["securityContext"]
        assert security["runAsNonRoot"] is True
        assert security["allowPrivilegeEscalation"] is False
        assert security["readOnlyRootFilesystem"] is True
        assert security["capabilities"] == {"drop": ["ALL"]}
        assert security["seccompProfile"] == {"type": "RuntimeDefault"}
        assert "@sha256:" in container["image"]
        assert container["resources"]["requests"] == container["resources"]["limits"]
        assert set(container["resources"]["limits"]) == {
            "cpu", "memory", "ephemeral-storage",
        }


def test_agent_network_policy_allows_only_its_exact_proxy_without_dns():
    resources = build_run_group(_spec())
    policies = _by_kind(resources, "NetworkPolicy")
    agent = next(p for p in policies if p["metadata"]["name"].endswith("-agent"))
    assert agent["spec"]["ingress"] == []
    assert len(agent["spec"]["egress"]) == 1
    [proxy] = agent["spec"]["egress"]
    [peer] = proxy["to"]
    selector = peer["podSelector"]["matchLabels"]
    assert selector["app.kubernetes.io/component"] == "proxy"
    assert selector["andyur.run/id"] == _pod(
        resources, "agent")["metadata"]["labels"]["andyur.run/id"]
    assert selector["andyur.run/generation"] == _pod(
        resources, "agent")["metadata"]["labels"]["andyur.run/generation"]
    assert proxy["ports"] == [
        {"protocol": "TCP", "port": 8765},
        {"protocol": "TCP", "port": 8766},
    ]
    serialized = repr(agent)
    assert "0.0.0.0/0" not in serialized
    assert "ipBlock" not in serialized
    assert "'port': 53" not in serialized


def test_proxy_policy_is_explicit_and_cross_run_selection_is_impossible():
    one, two = build_run_group(_spec("run-one")), build_run_group(_spec("run-two"))
    one_proxy = _pod(one, "proxy")["metadata"]["labels"]["andyur.run/id"]
    two_proxy = _pod(two, "proxy")["metadata"]["labels"]["andyur.run/id"]
    assert one_proxy != two_proxy

    policies = _by_kind(one, "NetworkPolicy")
    proxy = next(p for p in policies if p["metadata"]["name"].endswith("-proxy"))
    [ingress] = proxy["spec"]["ingress"]
    [source] = ingress["from"]
    labels = source["podSelector"]["matchLabels"]
    assert labels["app.kubernetes.io/component"] == "agent"
    assert labels["andyur.run/id"] == one_proxy
    assert labels["andyur.run/generation"] == _pod(
        one, "proxy")["metadata"]["labels"]["andyur.run/generation"]
    assert len(proxy["spec"]["egress"]) == 4  # DNS + 3 explicit peers
    assert all("ipBlock" not in repr(rule) for rule in proxy["spec"]["egress"])


def test_service_selects_only_the_exact_run_proxy():
    resources = build_run_group(_spec())
    [service] = _by_kind(resources, "Service")
    selector = service["spec"]["selector"]
    assert selector["app.kubernetes.io/component"] == "proxy"
    assert selector["andyur.run/id"] == _pod(
        resources, "proxy")["metadata"]["labels"]["andyur.run/id"]
    assert selector["andyur.run/generation"] == _pod(
        resources, "proxy")["metadata"]["labels"]["andyur.run/generation"]


def test_a_new_assignment_generation_cannot_select_or_delete_an_old_one():
    old = build_run_group(_spec())
    new = build_run_group(dataclasses.replace(_spec(), generation="worker-b-new"))
    old_labels = _pod(old, "proxy")["metadata"]["labels"]
    new_labels = _pod(new, "proxy")["metadata"]["labels"]
    assert old_labels["andyur.run/id"] == new_labels["andyur.run/id"]
    assert old_labels["andyur.run/generation"] != new_labels["andyur.run/generation"]
    [old_service] = _by_kind(old, "Service")
    [new_service] = _by_kind(new, "Service")
    assert old_service["metadata"]["name"] != new_service["metadata"]["name"]
    assert old_service["spec"]["selector"] != new_service["spec"]["selector"]


@pytest.mark.parametrize("field", ["proxy_image", "agent_image"])
def test_mutable_images_are_rejected(field):
    values = dataclasses.asdict(_spec())
    values[field] = "registry.example/andyur:latest"
    values["proxy_egress"] = _spec().proxy_egress
    with pytest.raises(ValueError, match="sha256"):
        build_run_group(RunGroupSpec(**values))


def test_invalid_or_ambient_egress_inputs_are_rejected():
    with pytest.raises(ValueError, match="at least one pod label"):
        build_run_group(dataclasses.replace(
            _spec(), proxy_egress=(ClusterPeer("default", {}, 443),)))
    with pytest.raises(ValueError, match="1..65535"):
        build_run_group(dataclasses.replace(_spec(), proxy_port=0))
    with pytest.raises(ValueError, match="pod-label value"):
        build_run_group(dataclasses.replace(
            _spec(), proxy_egress=(ClusterPeer("default", {"app": "*"}, 443),)))


# ---------------------------------------------------------------------------
# C1 (R PR#17): Pod-level assertions for D's exec/v1 surface. build_run_group /
# _agent_pod, each with a positive control and written to kill R's mutants.
# ---------------------------------------------------------------------------
import pytest as _pytest
from andyur.registry.models import (RUNTIME_PROTOCOL_EXEC_V1, RUNTIME_PROTOCOL_V1,
                                    ConfigurationSpec, ConfigFile, EnvVar)
from andyur.daemon.kubernetes_manifests import _security_context, run_group_names
from andyur.execconfig import MCP_PATH, FACTS_ENV, BEARER_ENV, TEMPLATES_FILE

# THE CONFIG-RENDER INIT CONTAINER, BY NAME. The agent Pod also carries
# `await-containment`, which must run first and always (it holds the workload
# until its NetworkPolicy is actually in force). These tests are about
# materialising configuration, so they select the container they mean instead
# of assuming it is the only one, or the first.
def _config_init(pod_spec):
    inits = pod_spec.get("initContainers", [])
    named = [c for c in inits if c["name"] == "materialize-config"]
    assert len(named) <= 1, f"more than one materialize-config: {[c['name'] for c in inits]}"
    return named[0] if named else None


def _config_inits(pod_spec):
    return [c for c in pod_spec.get("initContainers", [])
            if c["name"] == "materialize-config"]


_BEARER_REF = "services.tools.mcp_headers.Authorization"


def _exec_spec(files=True, bearer=True, **over):
    env = [EnvVar(name="LLM_PROVIDER", literal="openai")]
    if bearer:
        env.append(EnvVar(name="MCP_AUTH", reference=_BEARER_REF))
    fs = ()
    if files:
        tmpl = "mcp: ${services.tools.mcp_url}\n" + (f"auth: ${{{_BEARER_REF}}}\n" if bearer else "")
        fs = (ConfigFile(path="${workspace.home}/cfg", template=tmpl),)
    return dataclasses.replace(
        _spec(), agent_interface=RUNTIME_PROTOCOL_EXEC_V1, agent_runtime="container",
        agent_args=("/app/tool", "-i", "-"),
        exec_configuration=ConfigurationSpec(env=tuple(env), files=fs), **over)


def _agent(spec):
    return _pod(build_run_group(spec), "agent")["spec"]


def _env_by_name(container):
    return {e["name"]: e for e in container.get("env", [])}


def test_exec_bearer_env_is_a_secretkeyref_to_the_dedicated_mcp_token_not_a_literal():
    """Mutants 1 & 2 + M1/ADR-011 D2: a bearer-backed env is a secretKeyRef to the
    run's DEDICATED MCP token (runtime_secret / "mcp-token") -- never a literal
    value (which would put the token in the Pod spec), never the wrong secret/key,
    and NEVER the channel secret (a third-party image must not hold the channel
    bearer; the serve-only tool service accepts exactly this mcp-token)."""
    agent = _agent(_exec_spec())
    env = _env_by_name(agent["containers"][0])
    ref = env["MCP_AUTH"]["valueFrom"]["secretKeyRef"]
    names = run_group_names(_exec_spec())
    # the HEADER-VALUE spelling (`Bearer <token>`): the reference names the
    # Authorization header, and a stock tool sends what it is given verbatim.
    assert ref == {"name": names["runtime_secret"], "key": "mcp-authorization"}
    assert ref["name"] != names["channel_secret"]
    assert "value" not in env["MCP_AUTH"]
    # positive control: a literal env keeps its literal value
    assert env["LLM_PROVIDER"]["value"] == "openai"


def test_exec_bearer_env_never_appears_as_a_literal_value():
    """Mutant 1 (over-broad): no env VALUE on the agent container is the bearer
    reference resolved to a token; bearer names are secretKeyRef only."""
    agent = _agent(_exec_spec())
    mcp_auth = [e for e in agent["containers"][0]["env"] if e["name"] == "MCP_AUTH"]
    # The entry must exist, or the assertion below would pass vacuously if a
    # mutant dropped or renamed the bearer env (R nit).
    assert len(mcp_auth) == 1
    assert "value" not in mcp_auth[0]                          # never a resolved literal
    assert "secretKeyRef" in mcp_auth[0].get("valueFrom", {})  # bearer is secretKeyRef only


def test_init_container_gets_bearer_env_only_when_a_template_names_it():
    """Mutant 3: BEARER_ENV present iff a template references the bearer."""
    init = _config_init(_agent(_exec_spec(files=True, bearer=True)))
    assert BEARER_ENV in _env_by_name(init)
    # positive/negative control: templates that name no secret -> no BEARER_ENV
    init2 = _config_init(_agent(_exec_spec(files=True, bearer=False)))
    assert BEARER_ENV not in _env_by_name(init2)


def test_exec_config_configmap_is_immutable_and_holds_the_unrendered_template():
    """Mutant 5: the ConfigMap is immutable and carries the LITERAL ${...}
    template (rendering happens in the init container, never at build time, so
    the bearer never becomes a cluster object)."""
    cms = _by_kind(build_run_group(_exec_spec()), "ConfigMap")
    exec_cm = [c for c in cms if c["metadata"]["name"] == run_group_names(_exec_spec())["exec_config"]]
    assert len(exec_cm) == 1
    cm = exec_cm[0]
    assert cm["immutable"] is True
    blob = json.dumps(cm["data"])
    assert "${services.tools.mcp_url}" in blob            # literal, not resolved
    assert "http://" not in blob                          # nothing rendered
    # The data is keyed by TEMPLATES_FILE and nothing else, and that key is
    # exactly what the agent Pod's exec-config volume mounts by items[].key --
    # so a reshape to {path: template} (which would mount nothing) reddens here
    # rather than failing silently at runtime (R nit).
    assert set(cm["data"]) == {TEMPLATES_FILE}
    declared = json.loads(cm["data"][TEMPLATES_FILE])
    assert declared and all(set(entry) == {"path", "template"} for entry in declared)
    exec_vol = next(v for v in _agent(_exec_spec())["volumes"]
                    if v["name"] == "exec-config")
    assert exec_vol["configMap"]["items"][0]["key"] in cm["data"]


def test_init_container_is_absent_for_an_env_only_manifest_present_for_files():
    """Mutant 6: an env-only exec/v1 manifest gets a Pod shape identical to a
    native agent's (no init container, no ConfigMap); a files manifest gets the
    init container + ConfigMap."""
    env_only = _agent(_exec_spec(files=False))
    assert not _config_inits(env_only)
    assert not _by_kind(build_run_group(_exec_spec(files=False)), "ConfigMap")
    with_files = _agent(_exec_spec(files=True))
    assert len(_config_inits(with_files)) == 1
    assert _by_kind(build_run_group(_exec_spec(files=True)), "ConfigMap")


def test_init_container_runs_as_the_locked_down_uid_1001_security_context():
    """Mutant 7: the init container's securityContext is the platform's
    locked-down one (non-root uid 1001, caps dropped, ro rootfs), not degraded."""
    init = _config_init(_agent(_exec_spec()))
    assert init["securityContext"] == _security_context(1001)


def test_build_refuses_exec_configuration_on_a_non_exec_interface():
    """Mutant 12 / C2 builder guard: a runtime-v1 spec carrying exec_configuration
    is refused -- it must never be shaped into an init container + bearer."""
    bad = dataclasses.replace(_exec_spec(), agent_interface=RUNTIME_PROTOCOL_V1)
    with _pytest.raises(ValueError, match=r"applies only to the exec/v1 interface"):
        build_run_group(bad)
    # positive control: the same configuration under exec/v1 builds fine
    assert build_run_group(_exec_spec())


def test_exec_v1_proxy_runs_serve_only_and_runtime_v1_does_not():
    """H2: the sidecar must be told, by the SERVER-supplied interface alone, that
    this is a stock exec/v1 workload -- so it serves the model proxy + MCP but
    never arms the connect watchdog or posts /finish (the daemon does). Restoring
    the watchdog path (dropping --serve-only for exec/v1) reddens here."""
    exec_cmd = _pod(build_run_group(_exec_spec()), "proxy")[
        "spec"]["containers"][0]["command"]
    assert exec_cmd[:3] == ["python", "-m", "andyur.runner"]
    assert "--serve-only" in exec_cmd

    # A runtime-v1 container hosts a real channel and DOES self-report, so it
    # must NOT get the flag -- else its own finish would be suppressed.
    rtv1_cmd = _pod(build_run_group(_spec()), "proxy")[
        "spec"]["containers"][0]["command"]
    assert "--serve-only" not in rtv1_cmd


def test_the_proxy_receives_the_granted_model_for_exec_v1_and_nothing_for_runtime_v1():
    """R MED-1: ONE source for the model the front pins -- the assignment's
    grant, delivered to the sidecar as ANDYUR_EXEC_MODEL (the same value the
    workload's services.model.name resolves to). A runtime-v1 sidecar reads
    its model from the run's context and gets no such variable."""
    spec = dataclasses.replace(_exec_spec(), exec_model_name="qwen3-andyur:latest")
    env = _env_by_name(_pod(build_run_group(spec), "proxy")["spec"]["containers"][0])
    assert env["ANDYUR_EXEC_MODEL"] == {"name": "ANDYUR_EXEC_MODEL", "value": "qwen3-andyur:latest"}
    # no grant travels as an EMPTY value: the front then refuses every model call
    empty = _env_by_name(_pod(build_run_group(_exec_spec()), "proxy")["spec"]["containers"][0])
    assert empty["ANDYUR_EXEC_MODEL"]["value"] == ""
    v1 = _env_by_name(_pod(build_run_group(_spec()), "proxy")["spec"]["containers"][0])
    assert "ANDYUR_EXEC_MODEL" not in v1


def test_the_renderer_refuses_direct_model_egress_on_an_exec_v1_group():
    """The launcher never grants it (R MED-A); the renderer refuses it too, so
    the invariant does not live in one caller (R LOW)."""
    peer = ClusterPeer(namespace="andyur-system", labels={"app": "andyur-ollama"}, port=11434)
    with pytest.raises(ValueError, match="no direct model egress"):
        list(build_run_group(dataclasses.replace(_exec_spec(), agent_model_egress=peer)))
    # positive control: a runtime-v1 group may carry it
    assert list(build_run_group(dataclasses.replace(_spec(), agent_model_egress=peer)))



def test_the_exec_v1_workload_carries_no_platform_variable():
    """R LOW: the grant travels to the SIDECAR as ANDYUR_EXEC_MODEL; the
    workload sees only what its reviewed manifest declared. Rendering any
    ANDYUR_* name onto the workload would hand a third-party image platform
    configuration the contract never promised -- the live gate's E4 catches
    it, and now so does this. The init container is the PLATFORM's own
    materializer (platform image), so it carries exactly its two inputs."""
    spec = dataclasses.replace(_exec_spec(files=True, bearer=True),
                               exec_model_name="qwen3-andyur:latest")
    agent = _agent(spec)
    [workload] = agent["containers"]
    names = [e["name"] for e in workload["env"]]
    assert "MCP_AUTH" in names                                   # not vacuous
    assert not [n for n in names if n.startswith("ANDYUR_")], names
    init = _config_init(agent)
    assert sorted(n for n in (e["name"] for e in init["env"]) if n.startswith("ANDYUR_")) == sorted(
        (FACTS_ENV, BEARER_ENV))
    # positive control: the same group's proxy DOES carry the grant
    proxy = _env_by_name(_pod(build_run_group(spec), "proxy")["spec"]["containers"][0])
    assert proxy["ANDYUR_EXEC_MODEL"]["value"] == "qwen3-andyur:latest"


def test_a_collector_peer_on_the_proxy_never_reaches_the_workload_policy():
    """The Collector trusts its network (observability.yaml): the run PROXY may
    export to it, the untrusted WORKLOAD may not. Adding the collector to the
    proxy egress peer list must leave the rendered agent policy proxy-only --
    a mutant that spreads proxy_egress onto the agent policy reddens here."""
    collector = ClusterPeer(namespace="andyur-system", labels={"app": "otel-collector"}, port=4318)
    spec = dataclasses.replace(_exec_spec(), proxy_egress=(collector,), otel_mode="on",
                               otel_endpoint="http://otel-collector.andyur-system.svc:4318")
    docs = build_run_group(spec)
    policies = {d["metadata"]["name"]: d for d in docs if d["kind"] == "NetworkPolicy"}
    names = run_group_names(spec)
    agent = policies[f"{names['base']}-agent"]["spec"]
    proxy = policies[f"{names['base']}-proxy"]["spec"]

    def targets(policy):
        return [(t.get("namespaceSelector"), t.get("podSelector"), [p["port"] for p in r["ports"]])
                for r in policy["egress"] for t in r["to"]]
    assert any(t[1] == {"matchLabels": {"app": "otel-collector"}} and t[2] == [4318] for t in targets(proxy))
    assert all(t[0] is None and t[1] == {"matchLabels": {"app.kubernetes.io/component": "proxy",
                                                        **{k: v for k, v in t[1]["matchLabels"].items()
                                                           if k != "app.kubernetes.io/component"}}}
               for t in targets(agent))
    assert not any("otel-collector" in json.dumps(t) for t in targets(agent))
    # and the sidecar carries the endpoint the peer rule exists for
    env = _env_by_name(_pod(docs, "proxy")["spec"]["containers"][0])
    assert env["ANDYUR_OTEL"]["value"] == "on"
    assert env["ANDYUR_OTEL_ENDPOINT"]["value"] == "http://otel-collector.andyur-system.svc:4318"

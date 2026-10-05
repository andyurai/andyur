"""Lifecycle properties of the Kubernetes run-group controller."""

import dataclasses

import pytest

from andyur.daemon.kubernetes_controller import (
    KubernetesRunController,
    LeaseClaim,
    PodSnapshot,
    RunCredentials,
)
from andyur.daemon.kubernetes_manifests import ClusterPeer, RunGroupSpec


IMAGE = "registry.example/andyur@sha256:" + "a" * 64
ENVOY_IMAGE = "registry.example/envoy@sha256:" + "b" * 64
CREDENTIALS = RunCredentials("CHANNEL-SECRET-VALUE", "RUN-TOKEN-VALUE", "LLM-KEY-VALUE")


def _spec(**changes):
    spec = RunGroupSpec(
        namespace="andyur-runs",
        run_id="run-one",
        generation="worker-a-generation-one",
        agent_id="sre-oncall",
        registry_agent_id="agt_sre_oncall",
        proxy_image=IMAGE,
        agent_image=IMAGE,
    )
    if changes.get("broker_enabled"):
        peer = ClusterPeer(
            "andyur-system", {"app": "andyur-broker-state"}, 9443)
        changes = {
            "run_id": "a" * 32,
            "broker_envoy_image": ENVOY_IMAGE,
            "broker_state_host": "andyur-broker-state.andyur-system.svc",
            "broker_state_port": 9443,
            "broker_state_peer": peer,
            "proxy_egress": (peer,),
            **changes,
        }
    return dataclasses.replace(spec, **changes)


class FakeApi:
    def __init__(self):
        self.applied = []
        self.deleted = []
        self.ready = True
        self.phase = "Running"
        self.exit_code = 0
        self.pods = []
        self.fail_kind = None
        self.ip = "10.42.0.7"
        self.claim_ok = True
        self.isolation_checks = 0
        self.isolation_error = None
        self.released = []
        self.leases = {}
        self.lease_serial = [0]

    def assert_isolation_ready(self, namespace):
        self.isolation_checks += 1
        if self.isolation_error:
            raise self.isolation_error
        self.isolation_namespace = namespace

    def claim_run_singleton(self, namespace, name, labels, owner):
        self.claimed = (namespace, name, labels, owner)
        if not self.claim_ok or (namespace, name) in self.leases:
            return None
        self.lease_serial[0] += 1
        claim = LeaseClaim(
            name, f"uid-{self.lease_serial[0]}",
            f"rv-{self.lease_serial[0]}", owner)
        self.leases[(namespace, name)] = (claim, dict(labels))
        return claim

    def read_run_singleton(self, namespace, name, labels, owner, timeout):
        stored = self.leases.get((namespace, name))
        if not stored:
            return None
        claim, stored_labels = stored
        return claim if claim.holder == owner and stored_labels == labels else None

    def release_run_singleton(self, namespace, claim, timeout):
        self.released.append((namespace, claim, timeout))
        stored = self.leases.get((namespace, claim.name))
        if not stored or stored[0] != claim:
            raise RuntimeError("singleton precondition failed")
        del self.leases[(namespace, claim.name)]

    def apply(self, resource):
        if resource["kind"] == self.fail_kind:
            raise RuntimeError("injected apply failure")
        self.applied.append(resource)

    def wait_pod_ready(self, namespace, name, timeout):
        self.waited = (namespace, name, timeout)
        return self.ready

    def pod_phase(self, namespace, name):
        self.phase_pod = name
        return self.phase

    def read_container_exit(self, namespace, name, container):
        return self.exit_code

    def pod_ip(self, namespace, name):
        return self.ip

    def list_pods(self, namespace, selector, timeout, limit):
        self.listed = (namespace, selector, timeout, limit)
        return self.pods

    def delete_run_group(self, namespace, selector, timeout):
        self.deleted.append((namespace, selector, timeout))


def _component(resource):
    return resource["metadata"]["labels"].get("app.kubernetes.io/component")


def test_proxy_is_ready_before_the_agent_is_created():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    handle = controller.launch(_spec(), CREDENTIALS)

    assert _component(api.applied[-2]) == "proxy"
    assert _component(api.applied[-1]) == "agent"
    assert api.waited[0] == "andyur-runs"
    agent_command = api.applied[-1]["spec"]["containers"][0]["command"]
    url_index = agent_command.index("--channel-url") + 1
    assert agent_command[url_index] == "http://10.42.0.7:8765"
    assert handle.poll() is None
    api.phase = "Succeeded"
    assert handle.poll() == 0
    assert api.phase_pod.endswith("-agent")


def test_byoa_pod_as_applied_carries_only_the_two_contract_variables():
    """The env of the Pod actually SUBMITTED to the API server.

    The manifest builder withholds the builtin's configuration from a
    container runtime, but the controller appends to that same env block after
    the proxy is ready -- so the manifest-level test cannot see a leak added
    here, and "only the two variables it is promised" would ship green while
    being false. This asserts the applied object, which is the thing the
    cluster receives.

    Both halves, because a refusal proves nothing without a positive control:
    every non-contract name ABSENT, and the two promised names PRESENT.
    """
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    byoa = dataclasses.replace(
        _spec(), agent_runtime="container", agent_args=("/app/agent", "serve"),
        ollama_url="http://ollama:11434")
    controller.launch(byoa, CREDENTIALS)

    applied_agent = next(item for item in reversed(api.applied)
                         if _component(item) == "agent")
    env = applied_agent["spec"]["containers"][0].get("env", [])
    names = [item["name"] for item in env]
    assert sorted(names) == ["ANDYUR_RUNTIME_TOKEN", "ANDYUR_RUNTIME_URL"]

    # Named explicitly rather than inferred from the sorted list above: these
    # are the leaks that would matter, and naming them makes a future addition
    # of any one of them fail here by name.
    for leaked in ("ANDYUR_CHANNEL_TOKEN", "ANDYUR_RUN_TOKEN",
                   "ANDYUR_BROKER_TOKEN", "ANDYUR_LITELLM_KEY",
                   "ANDYUR_AS_CLIENT_SECRET", "ANDYUR_AGENT_CLI",
                   "ANDYUR_LLM", "ANDYUR_OLLAMA_URL", "HOME"):
        assert leaked not in names, f"{leaked} reached a third-party workload"

    # No credential may appear as a literal value either, under any name.
    literals = [item.get("value") for item in env]
    for secret in (CREDENTIALS.run_token, CREDENTIALS.litellm_key,
                   CREDENTIALS.channel_token):
        assert secret not in literals

    # Positive control: the two promised variables are present and usable --
    # the URL resolved to the ready proxy, the token by secret reference.
    by_name = {item["name"]: item for item in env}
    assert by_name["ANDYUR_RUNTIME_URL"]["value"] == "http://10.42.0.7:8765"
    assert "secretKeyRef" in by_name["ANDYUR_RUNTIME_TOKEN"]["valueFrom"]


def test_builtin_pod_as_applied_still_receives_its_own_configuration():
    """The positive control for the test above at the same enforcement point:
    the builtin agent is Andyur's own workload, not a third party, so
    withholding its configuration would break it. This is what proves the
    container case withholds by CHOICE rather than emptying the block."""
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    controller.launch(dataclasses.replace(_spec(), ollama_url="http://o:11434"),
                      CREDENTIALS)
    applied_agent = next(item for item in reversed(api.applied)
                         if _component(item) == "agent")
    names = {item["name"]
             for item in applied_agent["spec"]["containers"][0]["env"]}
    assert {"ANDYUR_RUN_ID", "ANDYUR_AGENT_ID", "ANDYUR_AGENT_CLI",
            "ANDYUR_LLM", "ANDYUR_OLLAMA_URL", "HOME", "ANDYUR_CHANNEL_TOKEN",
            "ANDYUR_RUNTIME_URL", "ANDYUR_RUNTIME_TOKEN"} == names


def test_each_launch_rechecks_expiring_isolation_before_any_write():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    assert api.isolation_checks == 1
    api.isolation_error = RuntimeError("verification expired")
    with pytest.raises(RuntimeError, match="expired"):
        controller.launch(_spec(), CREDENTIALS)
    assert api.isolation_checks == 2
    assert api.applied == []
    assert not hasattr(api, "claimed")


def test_credentials_are_immutable_owned_objects_not_pod_literals():
    api = FakeApi()
    KubernetesRunController(api, "andyur-runs").launch(_spec(), CREDENTIALS)
    secrets = [r for r in api.applied if r["kind"] == "Secret"]
    assert len(secrets) == 2
    assert all(secret["immutable"] is True for secret in secrets)
    assert {value for secret in secrets for value in secret["stringData"].values()} == {
        "CHANNEL-SECRET-VALUE", "RUN-TOKEN-VALUE", "LLM-KEY-VALUE",
    }
    pods = [r for r in api.applied if r["kind"] == "Pod"]
    assert all(value not in repr(pods) for value in dataclasses.astuple(CREDENTIALS)
               if value)


def test_broker_token_is_secret_backed_and_absent_by_default():
    api = FakeApi()
    credentials = dataclasses.replace(CREDENTIALS, broker_token="BROKER-TOKEN")
    KubernetesRunController(api, "andyur-runs").launch(
        _spec(broker_enabled=True), credentials)
    runtime = next(r for r in api.applied if r["kind"] == "Secret"
                   and _component(r) == "runtime")
    assert runtime["stringData"]["broker-token"] == "BROKER-TOKEN"
    with pytest.raises(ValueError, match="exactly one explicit broker token"):
        KubernetesRunController(FakeApi(), "andyur-runs").launch(
            _spec(broker_enabled=True), CREDENTIALS)
    with pytest.raises(ValueError, match="exactly one explicit broker token"):
        KubernetesRunController(FakeApi(), "andyur-runs").launch(
            _spec(), credentials)
    ordinary_api = FakeApi()
    KubernetesRunController(ordinary_api, "andyur-runs").launch(_spec(), CREDENTIALS)
    ordinary = next(r for r in ordinary_api.applied if r["kind"] == "Secret"
                    and _component(r) == "runtime")
    assert "broker-token" not in ordinary["stringData"]


def test_certification_evidence_is_secret_backed_and_both_files_are_required():
    api = FakeApi()
    credentials = dataclasses.replace(
        CREDENTIALS, as_certification='{"signed":true}',
        as_certification_public_key="PUBLIC KEY")
    KubernetesRunController(api, "andyur-runs").launch(
        _spec(as_certified=True), credentials)
    runtime = next(r for r in api.applied if r["kind"] == "Secret"
                   and _component(r) == "runtime")
    assert runtime["stringData"]["as-certification"] == '{"signed":true}'
    assert runtime["stringData"]["as-certification-public-key"] == "PUBLIC KEY"

    with pytest.raises(ValueError, match="requires certification"):
        KubernetesRunController(FakeApi(), "andyur-runs").launch(
            _spec(as_certified=True), CREDENTIALS)


def test_a_losing_generation_claim_does_not_apply_or_delete_winner_resources():
    api = FakeApi()
    api.claim_ok = False
    controller = KubernetesRunController(api, "andyur-runs")
    with pytest.raises(RuntimeError, match="already owned"):
        controller.launch(_spec(), CREDENTIALS)
    assert api.applied == []
    assert api.deleted == []


def test_two_generations_of_one_run_contend_for_the_same_singleton_name():
    old_api = FakeApi()
    KubernetesRunController(old_api, "andyur-runs").launch(
        _spec(generation="old"), CREDENTIALS)
    new_api = FakeApi()
    new_api.leases = old_api.leases
    new_api.lease_serial = old_api.lease_serial
    with pytest.raises(RuntimeError, match="run 'run-one' is already owned"):
        KubernetesRunController(new_api, "andyur-runs").launch(
            _spec(generation="new"), CREDENTIALS)
    assert old_api.claimed[1] == new_api.claimed[1]
    assert old_api.claimed[3] != new_api.claimed[3]
    assert new_api.applied == [] and new_api.deleted == []


def test_cleanup_failure_retains_the_singleton_fence():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    controller.launch(spec, CREDENTIALS)
    api.delete_run_group = lambda *_: (_ for _ in ()).throw(
        TimeoutError("old workload still present"))
    with pytest.raises(TimeoutError, match="still present"):
        controller.delete(spec)
    assert api.released == []


def test_successful_cleanup_releases_the_exact_claim_last():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    controller.launch(spec, CREDENTIALS)
    controller.delete(spec)
    assert len(api.deleted) == 1
    [(namespace, claim, timeout)] = api.released
    assert namespace == "andyur-runs"
    assert claim == LeaseClaim(
        api.claimed[1], "uid-1", "rv-1", spec.generation)
    assert 0 < timeout <= controller.DELETE_TIMEOUT


def test_release_failure_retains_claim_for_a_successful_retry():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    controller.launch(spec, CREDENTIALS)
    release = api.release_run_singleton
    attempts = [0]

    def fail_once(*args):
        attempts[0] += 1
        if attempts[0] == 1:
            raise TimeoutError("ambiguous Lease delete")
        return release(*args)

    api.release_run_singleton = fail_once
    with pytest.raises(TimeoutError, match="ambiguous"):
        controller.delete(spec)
    assert (spec.run_id, spec.generation) in controller._claims
    controller.delete(spec)
    assert (spec.run_id, spec.generation) not in controller._claims


def test_stale_claim_cannot_release_a_recreated_singleton():
    api = FakeApi()
    name = "andyur-run-example-owner"
    labels = {"andyur.run/id": "a", "andyur.run/generation": "b"}
    stale = api.claim_run_singleton("runs", name, labels, "old")
    api.release_run_singleton("runs", stale, 1)
    current = api.claim_run_singleton("runs", name, labels, "new")
    assert current.uid != stale.uid and current.resource_version != stale.resource_version
    with pytest.raises(RuntimeError, match="precondition"):
        api.release_run_singleton("runs", stale, 1)
    assert api.leases[("runs", name)][0] == current


def test_restart_observes_exact_singleton_but_cannot_release_it():
    api = FakeApi()
    original = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    original.launch(spec, CREDENTIALS)
    proxy = next(r for r in api.applied
                 if r["kind"] == "Pod" and _component(r) == "proxy")
    meta = proxy["metadata"]
    api.pods = [PodSnapshot(
        meta["name"], "Running", meta["labels"], meta["annotations"])]
    restarted = KubernetesRunController(
        api, "andyur-runs", owner_generation=spec.generation)
    assert restarted.list_running_generations() == [(spec.run_id, spec.generation)]
    restarted.delete_generation(spec.run_id, spec.generation)
    assert api.leases, "restart observation must not grant Lease release authority"


def test_live_adopted_pod_without_singleton_fails_closed():
    api = FakeApi()
    original = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    original.launch(spec, CREDENTIALS)
    proxy = next(r for r in api.applied
                 if r["kind"] == "Pod" and _component(r) == "proxy")
    meta = proxy["metadata"]
    api.pods = [PodSnapshot(
        meta["name"], "Running", meta["labels"], meta["annotations"])]
    api.leases.clear()
    restarted = KubernetesRunController(
        api, "andyur-runs", owner_generation=spec.generation)
    with pytest.raises(RuntimeError, match="lacks its singleton fence"):
        restarted.list_running_generations()


@pytest.mark.parametrize("failure", ["readiness", "agent-apply"])
def test_any_partial_launch_is_rolled_back_by_exact_generation(failure):
    api = FakeApi()
    if failure == "readiness":
        api.ready = False
    else:
        api.fail_kind = "Pod"
        # Fail only the agent, after the proxy has been applied.
        seen_pod = False

        def apply(resource):
            nonlocal seen_pod
            if resource["kind"] == "Pod":
                if seen_pod:
                    raise RuntimeError("injected agent failure")
                seen_pod = True
            api.applied.append(resource)
        api.apply = apply

    controller = KubernetesRunController(api, "andyur-runs")
    with pytest.raises(RuntimeError):
        controller.launch(_spec(), CREDENTIALS)
    [(namespace, selector, timeout)] = api.deleted
    assert namespace == "andyur-runs"
    assert selector["andyur.run/id"]
    assert selector["andyur.run/generation"]
    assert timeout == controller.DELETE_TIMEOUT
    assert len(api.released) == 1
    assert api.leases == {}
    if failure == "readiness":
        assert not any(
            resource["kind"] == "Pod"
            and _component(resource) == "agent"
            for resource in api.applied)


def test_delete_marks_the_local_handle_terminal_before_daemon_fallback():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    handle = controller.launch(spec, CREDENTIALS)
    controller.delete(spec)
    assert handle.poll() == 137


def test_external_proxy_deletion_is_terminal_instead_of_stranding_a_slot():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    handle = controller.launch(_spec(), CREDENTIALS)
    api.phase = None
    assert handle.poll() == 1


def test_deleting_one_run_does_not_mark_another_run_terminal():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    old = _spec()
    new = _spec(run_id="run-two", generation="new-generation")
    old_handle = controller.launch(old, CREDENTIALS)
    new_handle = controller.launch(new, CREDENTIALS)
    controller.delete(old)
    assert old_handle.poll() == 137
    assert new_handle.poll() is None


def test_adoption_requires_valid_raw_identity_and_matching_hashes():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    controller.launch(spec, CREDENTIALS)
    proxy = next(
        r for r in api.applied if r["kind"] == "Pod" and _component(r) == "proxy")
    meta = proxy["metadata"]
    good = PodSnapshot(meta["name"], "Running", meta["labels"], meta["annotations"])
    done = PodSnapshot(meta["name"], "Succeeded", meta["labels"], meta["annotations"])
    api.pods = [good, done]
    assert controller.list_running() == ["run-one"]
    assert controller.list_running_generations() == [
        ("run-one", "worker-a-generation-one")]


@pytest.mark.parametrize("mutation", ["raw", "run-label", "generation-label"])
def test_active_owned_proxy_identity_corruption_is_fatal(mutation):
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    controller.launch(spec, CREDENTIALS)
    proxy = next(r for r in api.applied
                 if r["kind"] == "Pod" and _component(r) == "proxy")
    meta = proxy["metadata"]
    labels, annotations = dict(meta["labels"]), dict(meta["annotations"])
    if mutation == "raw": annotations["andyur.run/id-raw"] = "../../escape"
    elif mutation == "run-label": labels["andyur.run/id"] = "0" * 16
    else: labels["andyur.run/generation"] = "0" * 16
    api.pods = [PodSnapshot(meta["name"], "Running", labels, annotations)]
    with pytest.raises(RuntimeError, match="identity"):
        controller.list_running_generations()


@pytest.mark.parametrize("phase", ["Unknown", "", None, "EvictedMaybe"])
def test_ambiguous_owned_proxy_phase_is_fatal(phase):
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    controller.launch(spec, CREDENTIALS)
    proxy = next(r for r in api.applied
                 if r["kind"] == "Pod" and _component(r) == "proxy")
    meta = proxy["metadata"]
    api.pods = [PodSnapshot(
        meta["name"], phase, meta["labels"], meta["annotations"])]
    with pytest.raises(RuntimeError, match="ambiguous phase"):
        controller.list_running_generations()


def test_adoption_query_is_scoped_to_this_workers_stable_generation():
    api = FakeApi()
    controller = KubernetesRunController(
        api, "colony-runs", owner_generation="worker-a-generation-one")
    controller.list_running_generations()
    assert api.listed[1]["andyur.run/generation"] == controller.selector(
        _spec())["andyur.run/generation"]
    assert api.listed[2:] == (controller.ADOPTION_TIMEOUT,
                              controller.MAX_ADOPTED_PODS + 1)


@pytest.mark.parametrize("duplicate_name", ["arbitrary-proxy", None])
def test_adoption_refuses_noncanonical_or_duplicate_proxy(duplicate_name):
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _spec()
    controller.launch(spec, CREDENTIALS)
    proxy = next(r for r in api.applied
                 if r["kind"] == "Pod" and _component(r) == "proxy")
    meta = proxy["metadata"]
    canonical = PodSnapshot(
        meta["name"], "Running", meta["labels"], meta["annotations"])
    second = PodSnapshot(
        duplicate_name or meta["name"], "Running",
        meta["labels"], meta["annotations"])
    api.pods = [canonical, second]
    match = "noncanonical" if duplicate_name else "duplicate"
    with pytest.raises(RuntimeError, match=match):
        controller.list_running_generations()


def test_an_adopted_generation_is_deleted_by_both_identity_hashes():
    api = FakeApi()
    controller = KubernetesRunController(api, "colony-runs")
    controller.delete_generation("run-one", "worker-old")

    [(namespace, selector, timeout)] = api.deleted
    assert namespace == "colony-runs"
    assert selector == {
        "app.kubernetes.io/managed-by": "andyur-worker",
        "andyur.run/id": controller.selector(_spec())["andyur.run/id"],
        "andyur.run/generation": controller.selector(
            _spec(generation="worker-old"))["andyur.run/generation"],
    }
    assert timeout == controller.DELETE_TIMEOUT


def test_namespace_mismatch_is_refused_before_any_api_call():
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    with pytest.raises(ValueError, match="namespace"):
        controller.launch(_spec(namespace="other"), CREDENTIALS)
    assert api.applied == []


# ---------------------------------------------------------------------------
# C1 (R PR#17): the controller's exec/v1 late-binding. _bind_exec_configuration
# composes the run's facts and writes them into the init container; the bearer
# must never become a Pod-visible value.
# ---------------------------------------------------------------------------
import json as _json
from andyur.registry.models import (RUNTIME_PROTOCOL_EXEC_V1, ConfigurationSpec,
                                    ConfigFile, EnvVar)
from andyur.daemon.kubernetes_manifests import run_group_names
from andyur.execconfig import MCP_PATH, FACTS_ENV

_BEARER_REF = "services.tools.mcp_headers.Authorization"


def _exec_launch_spec():
    return _spec(
        agent_interface=RUNTIME_PROTOCOL_EXEC_V1, agent_runtime="container",
        agent_args=("/app/tool", "-i", "-"),
        exec_configuration=ConfigurationSpec(
            env=(EnvVar(name="LLM_PROVIDER", literal="openai"),
                 EnvVar(name="MCP_AUTH", reference=_BEARER_REF)),
            files=(ConfigFile(path="${workspace.home}/cfg",
                              template=f"mcp: ${{services.tools.mcp_url}}\nauth: ${{{_BEARER_REF}}}\n"),)))


def _applied_init(api):
    agent = next(item for item in reversed(api.applied)
                 if _component(item) == "agent")
    return _config_init(agent["spec"])


def test_exec_facts_compose_the_mcp_url_from_the_proxy_ip_mcp_port_and_path():
    """Mutant 4: services.tools.mcp_url is the proxy Pod IP, the MCP port and
    MCP_PATH -- not the LLM port, not localhost, not missing the path."""
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _exec_launch_spec()
    controller.launch(spec, EXEC_CREDENTIALS)
    facts = _json.loads(next(e["value"] for e in _applied_init(api)["env"]
                             if e["name"] == FACTS_ENV))
    assert facts["services.tools.mcp_url"] == f"http://{api.ip}:{spec.mcp_port}{MCP_PATH}"
    # facts is facts.public(); the bearer field is never serialized into it, so
    # a mutant that folds mcp_bearer back into the public map reddens here (R nit).
    assert "mcp_bearer" not in facts


def test_the_channel_token_appears_in_no_applied_object_except_its_secret():
    """Mutant 8: FACTS_ENV carries facts.public() only, and the bearer reaches
    the init container by secretKeyRef -- so the channel token's literal value
    is nowhere in the applied objects except the Secret's stringData."""
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    spec = _exec_launch_spec()
    controller.launch(spec, EXEC_CREDENTIALS)
    token = CREDENTIALS.channel_token
    channel_secret = run_group_names(spec)["channel_secret"]
    for obj in api.applied:
        blob = _json.dumps(obj)
        if (obj["kind"] == "Secret"
                and obj["metadata"]["name"] == channel_secret
                and token in _json.dumps(obj.get("stringData", {}))):
            continue                     # ONLY the run's channel Secret may hold it
        assert token not in blob, f"channel token leaked into a {obj['kind']}"


from andyur import identity
from andyur.daemon.governed_kubernetes import LAUNCHABLE_PROTOCOLS
from andyur.registry.models import RUNTIME_PROTOCOL_V1 as _RUNTIME_V1
from andyur.execconfig import BEARER_ENV as _BEARER_ENV

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


# exec/v1 credentials carry the DEDICATED per-run MCP bearer the governed
# launcher mints; the plain CREDENTIALS (runtime-v1) has none.
EXEC_CREDENTIALS = RunCredentials(
    "CHANNEL-SECRET-VALUE", "RUN-TOKEN-VALUE", "LLM-KEY-VALUE",
    mcp_bearer="MCP-BEARER-VALUE")


def _launch(spec, credentials):
    api = FakeApi()
    KubernetesRunController(api, "andyur-runs").launch(spec, credentials)
    return api


def _agent_of(api):
    return next(o for o in reversed(api.applied) if _component(o) == "agent")


def _refs_secret(container_env, secret_name):
    return any(e.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
               == secret_name for e in container_env)


def test_exec_v1_agent_carries_no_runtime_channel_token():
    """M1 / ADR-011 D2: the controller adds ANDYUR_RUNTIME_TOKEN/URL to a
    runtime-v1 container (its published contract), and must NOT add them to a
    stock exec/v1 one -- a third-party image never holds the channel bearer."""
    exec_agent = _agent_of(_launch(_exec_launch_spec(), EXEC_CREDENTIALS))
    names = {e["name"] for e in exec_agent["spec"]["containers"][0].get("env", [])}
    assert "ANDYUR_RUNTIME_TOKEN" not in names
    assert "ANDYUR_RUNTIME_URL" not in names
    # positive control: a runtime-v1 container DOES receive both.
    rt_agent = _agent_of(_launch(_spec(), CREDENTIALS))
    rt = {e["name"] for e in rt_agent["spec"]["containers"][0].get("env", [])}
    assert {"ANDYUR_RUNTIME_TOKEN", "ANDYUR_RUNTIME_URL"} <= rt


def test_exec_v1_bearer_is_the_dedicated_mcp_token_by_every_path():
    """M1: the workload's MCP bearer is the dedicated per-run mcp-token, and the
    serve-only proxy accepts exactly that. No delivery path (agent env, rendered
    file) hands the workload the channel secret."""
    api = _launch(_exec_launch_spec(), EXEC_CREDENTIALS)
    names = run_group_names(_exec_launch_spec())
    rt_secret = next(o for o in api.applied if o["kind"] == "Secret"
                     and o["metadata"]["name"] == names["runtime_secret"])
    assert rt_secret["stringData"]["mcp-token"] == "MCP-BEARER-VALUE"
    assert rt_secret["stringData"]["mcp-token"] != EXEC_CREDENTIALS.channel_token
    # ONE minted value, two spellings: the bare token the proxy compares, and
    # the complete header value the workload sends -- and the guard's own
    # parser maps the second back to the first.
    assert rt_secret["stringData"]["mcp-authorization"] == "Bearer MCP-BEARER-VALUE"
    assert identity.bearer_token(rt_secret["stringData"]["mcp-authorization"]) \
        == rt_secret["stringData"]["mcp-token"]

    agent = _agent_of(api)
    agent_env = agent["spec"]["containers"][0].get("env", [])
    init_env = _config_init(agent["spec"]).get("env", [])
    # NEITHER the workload container NOR its config-render init references the
    # channel Secret; both bearer paths point at runtime_secret/mcp-authorization.
    assert not _refs_secret(agent_env, names["channel_secret"])
    assert not _refs_secret(init_env, names["channel_secret"])
    bearer = next(e for e in init_env if e["name"] == _BEARER_ENV)
    assert bearer["valueFrom"]["secretKeyRef"] == {
        "name": names["runtime_secret"], "key": "mcp-authorization"}
    declared = next(e for e in agent_env if e["name"] == "MCP_AUTH")
    assert declared["valueFrom"]["secretKeyRef"] == {
        "name": names["runtime_secret"], "key": "mcp-authorization"}

    # the serve-only proxy accepts the SAME token.
    proxy = next(o for o in reversed(api.applied) if _component(o) == "proxy")
    mcp = next(e for e in proxy["spec"]["containers"][0]["env"]
               if e["name"] == "ANDYUR_MCP_TOKEN")
    assert mcp["valueFrom"]["secretKeyRef"] == {
        "name": names["runtime_secret"], "key": "mcp-token"}


def _secret_references(pod: dict) -> set[tuple[str, str]]:
    """Every (Secret name, key) the Pod's processes can READ, in every shape
    Kubernetes offers, with "*" for a whole-Secret shape: env secretKeyRef,
    envFrom secretRef, secret volumes, projected secret sources -- on init and
    main containers alike. A property of the whole Pod, not of one env list
    (R MED-1, PR #21: an envFrom or a volume mount of the channel Secret left
    the env-only check green)."""
    refs: set[tuple[str, str]] = set()
    spec = pod["spec"]
    for c in (*spec.get("initContainers", []), *spec.get("containers", [])):
        for e in c.get("env", []):
            ref = e.get("valueFrom", {}).get("secretKeyRef")
            if ref:
                refs.add((ref["name"], ref["key"]))
        for ef in c.get("envFrom", []):
            if "secretRef" in ef:
                refs.add((ef["secretRef"]["name"], "*"))
    for v in spec.get("volumes", []):
        if "secret" in v:
            refs.add((v["secret"]["secretName"], "*"))
        for src in v.get("projected", {}).get("sources", []):
            if "secret" in src:
                refs.add((src["secret"]["name"], "*"))
    return refs


def _minted_bearers(monkeypatch, n: int = 2):
    """Drive the REAL governed launcher n times for exec/v1 and capture the
    credentials it handed the controller, against the REAL LAUNCHABLE_PROTOCOLS
    (exec/v1 is launchable since the flip; if it is ever removed again this
    helper refuses at launch_governed and the invariant's mint clause reads
    False, which is the honest answer)."""
    from andyur.daemon import governed_kubernetes as gk
    from andyur.daemon.orchestrator import RunSpec
    from andyur.registry.models import ProcessSpec, RuntimeResolution
    from andyur.registry.runtime_wire import encode_runtime
    monkeypatch.setenv("ANDYUR_KUBERNETES_PROXY_IMAGE", "proxy@sha256:" + "11" * 32)
    monkeypatch.setenv("LITELLM_MASTER_KEY", "service-key")
    monkeypatch.setenv("ANDYUR_KUBERNETES_PROXY_EGRESS", "[]")
    monkeypatch.delenv("ANDYUR_KUBERNETES_AGENT_MODEL_EGRESS", raising=False)
    runtime = encode_runtime(RuntimeResolution(
        runtime_type="container", interface_version=RUNTIME_PROTOCOL_EXEC_V1,
        manifest_digest="sha256:" + "44" * 32, image_ref="ghcr.io/x/tool",
        image_digest="sha256:" + "33" * 32, command=("tool",),
        process=ProcessSpec(input_mode="none", input_max_bytes=1024)))

    class Capture:
        namespace = "andyur-runs"
        credentials = None
        def launch(self, spec, credentials):
            self.credentials = credentials
            return object()
        def list_running_generations(self):
            return []
        def delete_generation(self, *_):
            pass

    out = []
    for i in range(n):
        ctl = Capture()
        spec = RunSpec(run_id=f"run-{i}", agent="stock",
                       run_token=f"run-token-{i}", channel_token=f"channel-token-{i}",
                       generation="worker-0", registry_agent_id="agt_stock")
        gk.GovernedKubernetesOrchestrator(controller=ctl).launch_governed(
            spec, runtime, None)
        out.append((ctl.credentials, spec))
    return out


def _m1_clauses(monkeypatch) -> dict[str, bool]:
    """M1, clause by clause, each a whole-object property of what the REAL
    controller applies and what the REAL launcher mints. Every clause must be
    load-bearing on its own (see test_M1_holds_on_this_tree)."""
    api = _launch(_exec_launch_spec(), EXEC_CREDENTIALS)
    agent = _agent_of(api)
    names = run_group_names(_exec_launch_spec())
    serialized = _json.dumps(agent)
    proxy = next(o for o in reversed(api.applied) if _component(o) == "proxy")
    proxy_mcp = next(e for e in proxy["spec"]["containers"][0]["env"]
                     if e["name"] == "ANDYUR_MCP_TOKEN")["valueFrom"]["secretKeyRef"]
    minted = _minted_bearers(monkeypatch)
    bearers = [c.mcp_bearer for c, _ in minted]
    return {
        # (a) the WHOLE agent Pod, serialised: the channel Secret is named
        #     nowhere, and no runtime/channel token variable exists.
        "channel_secret_named_nowhere": names["channel_secret"] not in serialized,
        "no_runtime_or_channel_token_env": (
            "ANDYUR_RUNTIME_TOKEN" not in serialized
            and "ANDYUR_RUNTIME_URL" not in serialized
            and "ANDYUR_CHANNEL_TOKEN" not in serialized),
        # (b) every Secret the Pod can read, by ANY shape, is exactly the
        #     runtime Secret's header-value key -- never run-token, litellm-key,
        #     the bare mcp-token, a whole-Secret envFrom, or a Secret volume.
        "only_the_bearer_key_is_readable": (
            _secret_references(agent) == {(names["runtime_secret"], "mcp-authorization")}),
        # (c) the declared bearer is minted by the LAUNCHER as a fresh dedicated
        #     secret per launch: non-empty, unguessable, not any other credential
        #     or identifier of the run, and different across launches.
        "bearer_is_fresh_and_dedicated": (
            all(b and len(b) >= 32 for b in bearers)
            and all(b not in {c.channel_token, c.run_token, c.litellm_key,
                              c.broker_token, s.run_id, s.agent}
                    for (c, s), b in zip(minted, bearers))
            and len(set(bearers)) == len(bearers)),
        # (d) the serve-only proxy accepts exactly that token: its
        #     ANDYUR_MCP_TOKEN is the bare-token spelling of the same Secret.
        "proxy_accepts_the_same_token": (
            proxy_mcp == {"name": names["runtime_secret"], "key": "mcp-token"}),
    }


def test_M1_holds_on_this_tree(monkeypatch):
    """Each M1 clause on its own, so a mutant reddens BY NAME (the invariant
    below only says whether the flip may stand). Written before the flip so the
    clauses were load-bearing while exec/v1 was unlaunchable; kept because a
    named clause is a better failure than a boolean."""
    clauses = _m1_clauses(monkeypatch)
    failed = sorted(name for name, ok in clauses.items() if not ok)
    assert not failed, f"M1 clauses violated: {failed}"


def test_exec_v1_is_not_launchable_unless_M1_holds(monkeypatch):
    """R's flip gate, as an invariant that lives past the flip: exec/v1 may be
    in LAUNCHABLE_PROTOCOLS (it is, since the flip) ONLY while M1 holds -- as a
    WHOLE-POD property plus the launcher's mint (R MED-1: an envFrom.secretRef
    or a Secret volume of the channel Secret, or a bearer pointed at
    runtime/run-token, reddens this). Un-flipping is the only other way to make
    it pass; test_M1_holds_on_this_tree names the broken clause either way."""
    launchable = RUNTIME_PROTOCOL_EXEC_V1 in LAUNCHABLE_PROTOCOLS
    m1_holds = all(_m1_clauses(monkeypatch).values())
    assert (not launchable) or m1_holds


def test_an_exec_v1_group_without_a_bearer_is_refused_by_name():
    """The Pod would otherwise reference a Secret key that does not exist and
    sit in CreateContainerConfigError until READY_TIMEOUT (R, PR #21)."""
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    with pytest.raises(ValueError, match="mcp_bearer"):
        controller.launch(_exec_launch_spec(), CREDENTIALS)      # no bearer
    assert api.applied == []                                     # nothing created
    # positive control: the same group WITH a bearer launches
    controller.launch(_exec_launch_spec(), EXEC_CREDENTIALS)
    assert any(_component(o) == "agent" for o in api.applied)


def test_a_runtime_v1_group_carrying_a_bearer_is_refused():
    """A runtime-v1 sidecar mints its own tool-service token; a bearer on that
    group is a credential nothing reads, sitting in a Secret (R LOW, PR #21)."""
    api = FakeApi()
    controller = KubernetesRunController(api, "andyur-runs")
    with pytest.raises(ValueError, match="only an exec/v1"):
        controller.launch(_spec(), EXEC_CREDENTIALS)
    assert api.applied == []
    controller.launch(_spec(), CREDENTIALS)                      # positive control
    assert any(_component(o) == "agent" for o in api.applied)


def test_a_launch_failure_is_always_reported_as_a_rolled_back_launch():
    """The refusal shape is a contract: "run-group launch failed (<cause>)" means
    the group was rolled back. It must hold with a SILENT proxy too -- the bare
    cause used to escape when pod_logs returned "" (it returned a bytes-repr
    "b''" before PR #20 H3, which is why nothing saw it); the broker-lifecycle
    gate's refusal check then failed by shape, not by behaviour."""
    api = FakeApi()
    api.ready = False
    controller = KubernetesRunController(api, "andyur-runs")
    controller.READY_TIMEOUT = 0.01
    with pytest.raises(RuntimeError) as silent:
        controller.launch(_spec(run_id="silent"), CREDENTIALS)
    message = str(silent.value)
    assert message.startswith(
        "run-group launch failed (Kubernetes proxy for run silent was not ready within")
    assert message.endswith("proxy produced no output")
    assert isinstance(silent.value.__cause__, RuntimeError)
    assert api.deleted, "the group was not rolled back"

    # positive control: WITH proxy output, the tail is carried in the same shape
    api = FakeApi()
    api.ready = False
    api.pod_logs = lambda ns, name, tail_lines=80, limit_bytes=None: "boot: refused\n"
    controller = KubernetesRunController(api, "andyur-runs")
    controller.READY_TIMEOUT = 0.01
    with pytest.raises(RuntimeError, match=r"^run-group launch failed \(.*\); proxy tail:\nboot: refused") as loud:
        controller.launch(_spec(run_id="loud"), CREDENTIALS)
    assert "proxy produced no output" not in str(loud.value)


def test_a_proxy_that_exited_is_named_not_reported_as_a_timeout():
    """wait_pod_ready returns at once for a Pod in phase Failed; the refusal
    must say so (R LOW: a sidecar that exited 1 read as "not ready within 60s",
    the cause only in the proxy tail)."""
    api = FakeApi()
    api.ready = False
    api.phase = "Failed"
    controller = KubernetesRunController(api, "andyur-runs")
    with pytest.raises(RuntimeError, match=r"exited before it was ready \(Pod phase Failed\)") as exc:
        controller.launch(_spec(run_id="dead"), CREDENTIALS)
    assert "not ready within" not in str(exc.value)
    assert api.deleted                                          # still rolled back


def test_the_engine_controller_keeps_the_fence_until_a_failed_launch_is_recorded():
    """RUN EXECUTION DRAFT R4 on the launch-failure path (F-2). The rollback
    still deletes everything it created, but the engine's run-scoped controller
    keeps the run's fence: released first, a failure whose report then failed
    let the engine's retry launch the run a second time. The fence goes only
    through `release_fence`, after the outcome is recorded."""
    api = FakeApi()
    api.ready = False
    controller = KubernetesRunController(api, "andyur-runs")
    controller.retain_fence_on_failed_launch = True
    spec = _spec()
    with pytest.raises(RuntimeError, match="run-group launch failed"):
        controller.launch(spec, CREDENTIALS)
    assert len(api.deleted) == 1, "the partial group was not deleted"
    assert api.released == [] and len(api.leases) == 1, "the fence was released first"

    with pytest.raises(RuntimeError, match="already owned"):
        controller.launch(spec, CREDENTIALS)       # a retry cannot relaunch

    controller.release_fence(spec.run_id, spec.generation)
    assert api.leases == {} and len(api.released) == 1
    controller.release_fence(spec.run_id, spec.generation)   # idempotent
    assert len(api.released) == 1


def test_the_run_scoped_orchestrator_turns_fence_retention_on_and_the_daemon_does_not():
    from andyur.daemon.orchestrator import KubernetesOrchestrator
    engine = KubernetesRunController(FakeApi(), "andyur-runs")
    KubernetesOrchestrator(controller=engine, run_scoped_generations=True)
    daemon = KubernetesRunController(FakeApi(), "andyur-runs", owner_generation="worker-a")
    KubernetesOrchestrator(controller=daemon)
    assert engine.retain_fence_on_failed_launch is True
    assert daemon.retain_fence_on_failed_launch is False

from types import SimpleNamespace

import pytest

from andyur import config
from andyur.daemon.governed_kubernetes import GovernedKubernetesOrchestrator
from andyur.daemon.kubernetes_controller import (
    KubernetesRunController,
    LeaseClaim,
    RunCredentials,
)
from andyur.daemon.kubernetes_manifests import RunGroupSpec, run_group_names
from andyur.daemon.orchestrator import RunSpec


PROXY_DIGEST = "sha256:" + "11" * 32
PLATFORM_AGENT_DIGEST = "sha256:" + "22" * 32
BYOA_DIGEST = "sha256:" + "33" * 32
MANIFEST_DIGEST = "sha256:" + "44" * 32


class CapturingController:
    namespace = "andyur-runs"

    def __init__(self):
        self.spec = None
        self.credentials = None

    def launch(self, spec, credentials):
        self.spec = spec
        self.credentials = credentials
        return SimpleNamespace(pid=0)

    def list_running_generations(self):
        return []

    def delete_generation(self, _run_id, _generation):
        pass


def _runtime(command=None, lifecycle=None):
    """Built through the REAL serializer, not by hand.

    The hand-rolled version of this dict never carried `lifecycle`, so 95 BYOA
    tests passed while every lifecycle-granted agent was unlaunchable on this
    very path -- the stale-stand-in trap, one file over from where it had
    already been diagnosed and fixed. Going through the real codec means a
    field added to RuntimeResolution appears here automatically.
    """
    from andyur.registry.models import LifecycleSpec, RuntimeResolution
    from andyur.registry.runtime_wire import encode_runtime
    from andyur.registry.models import ResourceSpec
    return encode_runtime(RuntimeResolution(
        runtime_type="container",
        interface_version="andyur-agent-runtime/v1",
        manifest_digest=MANIFEST_DIGEST,
        image_ref="ghcr.io/acme/customer-agent",
        image_digest=BYOA_DIGEST,
        command=tuple(command if command is not None else ["/app/agent", "serve"]),
        resources=ResourceSpec(cpu="750m", memory="768Mi"),
        policy_revision="review-42",
        lifecycle=(LifecycleSpec(*lifecycle) if lifecycle else None),
    ))


def _builtin_runtime():
    """Built through the REAL codec, like _runtime above.

    This was the last hand-written envelope dict in the file -- eight keys,
    no lifecycle -- one function below the one whose docstring warns that a
    hand-built stand-in silently loses every field added after it was written.
    """
    from andyur.registry.models import RuntimeResolution
    from andyur.registry.runtime_wire import encode_runtime
    return encode_runtime(RuntimeResolution(
        runtime_type="builtin-claude",
        interface_version=None,
        manifest_digest=MANIFEST_DIGEST,
        policy_revision="review-42",
    ))


def _run_spec():
    return RunSpec(
        run_id="run-123",
        agent="customer-agent",
        run_token="run-token",
        channel_token="channel-token",
        generation="worker-0",
        registry_agent_id="agt_customer",
    )


def _orchestrator(monkeypatch, controller=None):
    monkeypatch.setenv("ANDYUR_KUBERNETES_PROXY_IMAGE", "proxy@" + PROXY_DIGEST)
    # Deliberately a different image: a BYOA container must not use it.
    monkeypatch.setenv(
        "ANDYUR_KUBERNETES_AGENT_IMAGE", "platform-agent@" + PLATFORM_AGENT_DIGEST)
    monkeypatch.setenv("LITELLM_MASTER_KEY", "service-key")
    monkeypatch.setenv("ANDYUR_KUBERNETES_PROXY_EGRESS", "[]")
    monkeypatch.delenv("ANDYUR_KUBERNETES_AGENT_MODEL_EGRESS", raising=False)
    return GovernedKubernetesOrchestrator(
        controller=controller or CapturingController())


def test_byoa_kubernetes_uses_governed_image_command_and_resources(monkeypatch):
    controller = CapturingController()
    orch = _orchestrator(monkeypatch, controller)

    orch.launch_governed(_run_spec(), _runtime(), None)

    launched = controller.spec
    assert launched.agent_image == "ghcr.io/acme/customer-agent@" + BYOA_DIGEST
    assert launched.agent_image != "platform-agent@" + PLATFORM_AGENT_DIGEST
    assert launched.agent_args == ("/app/agent", "serve")
    assert launched.agent_cpu == "750m"
    assert launched.agent_memory == "768Mi"
    # The launch must DECLARE what it is launching. The manifest builder
    # withholds the builtin's environment from a third-party workload on the
    # strength of this field, so a translation that stops passing it hands the
    # BYOA container ANDYUR_CHANNEL_TOKEN and the platform's model config
    # again -- with every other assertion here still green.
    assert launched.agent_runtime == "container"


def test_builtin_and_byoa_translate_into_the_same_controller(monkeypatch):
    byo_controller = CapturingController()
    builtin_controller = CapturingController()

    _orchestrator(monkeypatch, byo_controller).launch_governed(
        _run_spec(), _runtime(), None)
    _orchestrator(monkeypatch, builtin_controller).launch_governed(
        _run_spec(), _builtin_runtime(), None)

    assert isinstance(byo_controller.spec, RunGroupSpec)
    assert isinstance(builtin_controller.spec, RunGroupSpec)
    # Same controller, different declared runtime: that difference is what the
    # published two-variable contract rests on.
    assert byo_controller.spec.agent_runtime == "container"
    assert builtin_controller.spec.agent_runtime == "builtin-claude"
    assert byo_controller.spec.agent_image == \
        "ghcr.io/acme/customer-agent@" + BYOA_DIGEST
    assert builtin_controller.spec.agent_image == \
        "platform-agent@" + PLATFORM_AGENT_DIGEST


def test_byoa_kubernetes_refuses_missing_runtime_instead_of_global_fallback(monkeypatch):
    """An assignment carrying NO runtime and one carrying a malformed runtime
    are different field events, and the operator has to be able to tell them
    apart: the first is missing governance, the second is corrupt transport.
    Collapsing them sends whoever is on call hunting the wrong fault."""
    orch = _orchestrator(monkeypatch)
    with pytest.raises(config.InsecureProfile,
                       match="assignment carried none"):
        orch.launch_governed(_run_spec(), None, None)
    with pytest.raises(config.InsecureProfile,
                       match="runtime envelope must be an object"):
        orch.launch_governed(_run_spec(), "not-an-object", None)


def test_byoa_kubernetes_refuses_missing_command_instead_of_andyur_entrypoint(monkeypatch):
    orch = _orchestrator(monkeypatch)
    runtime = _runtime()
    runtime["command"] = None
    with pytest.raises(config.InsecureProfile, match="requires an explicit command"):
        orch.launch_governed(_run_spec(), runtime, None)


def test_byoa_kubernetes_refuses_bad_protocol(monkeypatch):
    orch = _orchestrator(monkeypatch)
    runtime = _runtime()
    runtime["interface_version"] = "andyur-agent-runtime/v2"
    with pytest.raises(config.InsecureProfile, match="andyur-agent-runtime/v1"):
        orch.launch_governed(_run_spec(), runtime, None)


def test_byoa_kubernetes_refuses_mutable_or_rewritten_image(monkeypatch):
    orch = _orchestrator(monkeypatch)
    runtime = _runtime()
    runtime["image_ref"] = "ghcr.io/acme/customer-agent@sha256:" + "55" * 32
    with pytest.raises(config.InsecureProfile, match="unpinned OCI"):
        orch.launch_governed(_run_spec(), runtime, None)


@pytest.mark.parametrize("mutate,match", [
    (lambda runtime: runtime.update(image_ref="GHCR.IO/acme/agent"), "unpinned OCI"),
    (lambda runtime: runtime["resources"].update(cpu="lots"), "resource quantity"),
    (lambda runtime: runtime.update(command=["/app/agent", "token=secret"]),
     "command"),
])
def test_worker_reuses_registry_runtime_validation_rules(monkeypatch, mutate, match):
    runtime = _runtime()
    mutate(runtime)

    with pytest.raises(config.InsecureProfile, match=match):
        _orchestrator(monkeypatch).launch_governed(_run_spec(), runtime, None)


def test_legacy_kubernetes_launch_entrypoint_is_closed(monkeypatch):
    orch = _orchestrator(monkeypatch)
    with pytest.raises(config.InsecureProfile, match="assignment runtime envelope"):
        orch.launch(_run_spec(), None)


class RecordingApi:
    def __init__(self):
        self.applied = []

    def assert_isolation_ready(self, _namespace):
        pass

    def apply(self, resource):
        self.applied.append(resource)

    def wait_pod_ready(self, _namespace, _name, _timeout):
        return True

    def pod_ip(self, _namespace, _name):
        return "10.7.0.42"

    def claim_run_singleton(self, _namespace, name, _labels, owner):
        return LeaseClaim(name=name, uid="lease-uid", resource_version="1", holder=owner)

    def release_run_singleton(self, _namespace, _claim, _timeout):
        pass

    def read_run_singleton(self, _namespace, _name, _labels, _owner, _timeout):
        return None

    def pod_phase(self, _namespace, _name):
        return "Running"

    def list_pods(self, _namespace, _selector, _timeout, _limit):
        return []

    def delete_run_group(self, _namespace, _selector, _timeout):
        pass


def test_agent_pod_gets_public_runtime_url_and_token_aliases():
    api = RecordingApi()
    controller = KubernetesRunController(api, "andyur-runs", "worker-0")
    spec = RunGroupSpec(
        namespace="andyur-runs",
        run_id="run-123",
        generation="worker-0",
        agent_id="customer-agent",
        registry_agent_id="agt_customer",
        proxy_image="proxy@" + PROXY_DIGEST,
        agent_image="ghcr.io/acme/customer-agent@" + BYOA_DIGEST,
        agent_args=("/app/agent", "serve"),
        server_url="https://control-plane.example",
        litellm_url="https://litellm.example",
    )
    controller.launch(
        spec, RunCredentials("channel-token", "run-token", "service-key"))

    agent_pod = next(
        item for item in api.applied
        if item.get("kind") == "Pod"
        and item["metadata"]["labels"].get("app.kubernetes.io/component") == "agent"
    )
    [container] = agent_pod["spec"]["containers"]
    env = {item["name"]: item for item in container["env"]}

    assert container["command"] == ["/app/agent", "serve"]
    assert env["ANDYUR_RUNTIME_URL"]["value"] == "http://10.7.0.42:8765"
    expected_secret = run_group_names(spec)["channel_secret"]
    assert env["ANDYUR_RUNTIME_TOKEN"]["valueFrom"]["secretKeyRef"] == {
        "name": expected_secret,
        "key": "token",
    }


def test_a_lifecycle_granted_agent_is_launchable_on_the_governed_path():
    """HIGH-1, reproduced as a regression.

    The envelope validator's key set was restated by hand and never widened
    when `lifecycle` was added, so a lifecycle-granted agent was REFUSED here
    with "unknown fields ['lifecycle']" -- on the only governed BYOA launcher,
    which is the one path the whole feature was built for. The failure was
    silent: the launch failed, the run stayed pending, and it was reaped later
    as "never started".

    The positive control matters as much as the negative: an agent WITHOUT a
    lifecycle must still be accepted, or this test would pass against a
    validator that accepted everything.
    """
    from andyur.daemon.governed_kubernetes import validate_runtime_envelope

    validate_runtime_envelope(_runtime())                       # no lifecycle
    validate_runtime_envelope(_runtime(lifecycle=("task", 3600)))

    rejected = _runtime()
    rejected["genuinely_unknown"] = 1
    with pytest.raises(Exception, match="unknown fields"):
        validate_runtime_envelope(rejected)


def test_the_granted_wall_clock_reaches_the_agent_pod_environment():
    """HIGH-3. The F4 fix carried no behavioural test at all, so the thing it
    claimed to close was asserted nowhere: the run TTL reaches the runner only
    if it is actually rendered into the pod the controller creates."""
    from andyur.daemon.kubernetes_manifests import RunGroupSpec, build_run_group

    def _env_of(spec):
        group = build_run_group(spec)
        out = {}
        for doc in group:
            if doc.get("kind") != "Pod":
                continue
            for container in doc["spec"].get("containers", []):
                for entry in container.get("env", []):
                    if "value" in entry:
                        out[entry["name"]] = entry["value"]
        return out

    pinned = f"ghcr.io/acme/img@{BYOA_DIGEST}"
    common = dict(namespace="ns", run_id="r", generation="g", agent_id="a",
                  registry_agent_id="agt_x",
                  proxy_image=pinned, agent_image=pinned)
    granted = _env_of(RunGroupSpec(**common, run_ttl_seconds=7200))
    assert granted.get("ANDYUR_RUN_TTL_SECONDS") == "7200", (
        "the granted wall clock must reach the pod, or the runner arms its own "
        "timeout from the built-in default and kills a long agent early")

    ungranted = _env_of(RunGroupSpec(**common))
    assert "ANDYUR_RUN_TTL_SECONDS" not in ungranted, (
        "an agent that declared nothing must not be handed an override")


def _exec_runtime():
    """An exec/v1 envelope through the REAL codec, like _runtime/_builtin_runtime
    above. input_mode 'none' keeps this focused on completion tracking rather
    than the input-delivery path (which has its own tests)."""
    from andyur.registry.models import (
        ProcessSpec, ResourceSpec, RuntimeResolution)
    from andyur.registry.runtime_wire import encode_runtime
    return encode_runtime(RuntimeResolution(
        runtime_type="container",
        interface_version="exec/v1",
        manifest_digest=MANIFEST_DIGEST,
        image_ref="ghcr.io/tracer-cloud/opensre",
        image_digest=BYOA_DIGEST,
        command=("opensre", "investigate"),
        resources=ResourceSpec(cpu="750m", memory="768Mi"),
        policy_revision="review-42",
        process=ProcessSpec(
            input_mode="none", input_max_bytes=1024,
            stdout="capture", stderr="discard", output_max_bytes=8192),
    ))


def test_exec_v1_launch_is_tracked_so_the_daemon_can_own_its_completion(monkeypatch):
    # Written before the flip against a widened LAUNCHABLE_PROTOCOLS; now the
    # REAL set admits exec/v1 (gated on M1), so this drives the launcher as is.
    controller = CapturingController()
    orch = _orchestrator(monkeypatch, controller)
    orch.launch_governed(_run_spec(), _exec_runtime(), None)

    assert "run-123" in orch._exec_runs
    info = orch._exec_runs["run-123"]
    # the agent container of THIS run group is what the daemon will read the
    # exit and logs from, with the manifest's output bounds and capture modes.
    assert info.pod == run_group_names(controller.spec)["agent"]
    assert info.container == "agent"
    assert info.output_max_bytes == 8192
    assert info.capture_stdout == "capture"
    assert info.capture_stderr == "discard"


def test_a_runtime_v1_launch_is_not_tracked_for_daemon_owned_completion(monkeypatch):
    orch = _orchestrator(monkeypatch)
    orch.launch_governed(_run_spec(), _runtime(), None)
    # runtime-v1 reports its own completion from inside the run, so the daemon
    # holds nothing for it and read_exec_completion stays None.
    assert "run-123" not in orch._exec_runs
    assert orch._exec_runs == {}
    assert orch.read_exec_completion("run-123") is None


def test_the_exec_v1_bearer_is_minted_fresh_per_launch_and_never_for_runtime_v1(monkeypatch):
    """Pins the MINT (R, PR #21: a mutant setting mcp_bearer = channel_token
    survived because every test built its own credentials). Two exec/v1
    launches: each bearer is non-empty and unguessable, is none of the run's
    other credentials or identifiers, and the two differ. A runtime-v1 launch
    carries none."""
    seen = []
    for run_id in ("run-a", "run-b"):
        controller = CapturingController()
        spec = RunSpec(run_id=run_id, agent="customer-agent", run_token=f"rt-{run_id}",
                       channel_token=f"ct-{run_id}", generation="worker-0",
                       registry_agent_id="agt_customer")
        _orchestrator(monkeypatch, controller).launch_governed(spec, _exec_runtime(), None)
        creds = controller.credentials
        assert creds.mcp_bearer and len(creds.mcp_bearer) >= 32
        assert creds.mcp_bearer not in {creds.channel_token, creds.run_token,
                                        creds.litellm_key, run_id, "customer-agent"}
        seen.append(creds.mcp_bearer)
    assert seen[0] != seen[1]
    # runtime-v1: no bearer (the sidecar mints its own over the channel)
    controller = CapturingController()
    _orchestrator(monkeypatch, controller).launch_governed(_run_spec(), _runtime(), None)
    assert controller.credentials.mcp_bearer == ""


def test_the_granted_model_reaches_the_exec_v1_facts_and_no_other(monkeypatch):
    """services.model.name for a stock workload is the model the assignment
    carried (the registry's grant); it resolved to nothing before, which failed
    every manifest naming it at launch. runtime-v1 reads its model from
    /context, so its group carries none."""
    controller = CapturingController()
    spec = RunSpec(run_id="run-m", agent="customer-agent", run_token="rt", channel_token="ct",
                   generation="worker-0", registry_agent_id="agt_customer",
                   model="qwen3-andyur:latest")
    _orchestrator(monkeypatch, controller).launch_governed(spec, _exec_runtime(), None)
    assert controller.spec.exec_model_name == "qwen3-andyur:latest"
    controller = CapturingController()
    _orchestrator(monkeypatch, controller).launch_governed(
        RunSpec(run_id="run-v1", agent="customer-agent", run_token="rt", channel_token="ct",
                generation="worker-0", registry_agent_id="agt_customer", model="qwen3-andyur:latest"),
        _runtime(), None)
    assert controller.spec.exec_model_name == ""


def test_an_exec_v1_workload_gets_no_direct_model_egress(monkeypatch):
    """Local-model mode grants a builtin/runtime-v1 AGENT direct egress to the
    model service; a stock exec/v1 workload reaches the model only through
    its proxy Pod's front, which pins the endpoint set and the model (R MED-A,
    PR #22). The launcher therefore grants it no model egress of its own."""
    monkeypatch.setenv("ANDYUR_KUBERNETES_AGENT_MODEL_EGRESS",
                       '{"namespace":"andyur-system","labels":{"app":"andyur-ollama"},"port":11434}')
    controller = CapturingController()
    orch = _orchestrator(monkeypatch, controller)
    monkeypatch.setenv("ANDYUR_KUBERNETES_AGENT_MODEL_EGRESS",
                       '{"namespace":"andyur-system","labels":{"app":"andyur-ollama"},"port":11434}')
    orch.launch_governed(_run_spec(), _exec_runtime(), None)
    assert controller.spec.agent_model_egress is None
    # positive control: a runtime-v1 agent keeps it
    controller = CapturingController()
    orch = _orchestrator(monkeypatch, controller)
    monkeypatch.setenv("ANDYUR_KUBERNETES_AGENT_MODEL_EGRESS",
                       '{"namespace":"andyur-system","labels":{"app":"andyur-ollama"},"port":11434}')
    orch.launch_governed(_run_spec(), _runtime(), None)
    assert controller.spec.agent_model_egress is not None
    assert controller.spec.agent_model_egress.port == 11434


def test_a_granted_model_outside_the_identifier_charset_is_refused_at_launch(monkeypatch):
    controller = CapturingController()
    spec = RunSpec(run_id="run-m", agent="customer-agent", run_token="rt", channel_token="ct",
                   generation="worker-0", registry_agent_id="agt_customer",
                   model="qwen3 andyur;rm -rf")
    with pytest.raises(config.InsecureProfile, match="not a valid model identifier"):
        _orchestrator(monkeypatch, controller).launch_governed(spec, _exec_runtime(), None)
    assert controller.spec is None


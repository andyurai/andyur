"""Daemon integration contract for the production Kubernetes runtime."""

import json
from types import SimpleNamespace

import pytest

from andyur import config
from andyur.daemon import orchestrator
from andyur.daemon.orchestrator import RunSpec
from andyur.registry.models import ResourceSpec, RuntimeResolution
from andyur.server import coordinator


IMAGE = "registry.example/andyur@sha256:" + "a" * 64
ENVOY_IMAGE = "registry.example/envoy@sha256:" + "b" * 64


class FakeController:
    namespace = "andyur-runs"

    def __init__(self):
        self.launched = []
        self.deleted = []
        self.running = []

    def launch(self, spec, credentials):
        self.launched.append((spec, credentials))
        return SimpleNamespace(pid=0, poll=lambda: None)

    def list_running_generations(self):
        return list(self.running)

    def delete_generation(self, run_id, generation):
        self.deleted.append((run_id, generation))


@pytest.fixture
def kube(monkeypatch):
    monkeypatch.setenv("ANDYUR_KUBERNETES_PROXY_IMAGE", IMAGE)
    monkeypatch.setenv("ANDYUR_KUBERNETES_AGENT_IMAGE", IMAGE)
    monkeypatch.setenv("ANDYUR_KUBERNETES_BROKER_ENVOY_IMAGE", ENVOY_IMAGE)
    monkeypatch.setenv(
        "ANDYUR_KUBERNETES_BROKER_STATE_HOST",
        "andyur-broker-state.andyur-system.svc")
    monkeypatch.setenv("ANDYUR_KUBERNETES_BROKER_STATE_PORT", "9443")
    monkeypatch.setenv(
        "ANDYUR_KUBERNETES_BROKER_STATE_PEER",
        '{"namespace":"andyur-system",'
        '"labels":{"app":"andyur-broker-state"},"port":9443}')
    monkeypatch.setenv("LITELLM_MASTER_KEY", "service-key")
    monkeypatch.setenv("ANDYUR_LLM", "ollama")
    monkeypatch.setattr(config, "AS_TOKEN_ENDPOINT", "https://as.example/token")
    monkeypatch.setattr(config, "AS_ISSUER", "https://as.example")
    monkeypatch.setattr(config, "AS_JWKS_URL", "https://as.example/jwks")
    monkeypatch.setattr(config, "AS_CLIENT_ID", "andyur")
    monkeypatch.setattr(config, "AS_CLIENT_SECRET", "as-secret")
    monkeypatch.setattr(config, "AS_PROVIDER", "reference")
    monkeypatch.setattr(config, "AS_CAPABILITY", "contextual")
    monkeypatch.setattr(config, "AS_RESOURCE_SCOPE", "")
    monkeypatch.setattr(config, "AS_PRODUCT_VERSION", "")
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", "")
    monkeypatch.setattr(config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", "")
    monkeypatch.setenv(
        "ANDYUR_OLLAMA_URL", "http://andyur-ollama.andyur-system.svc:11434",
    )
    monkeypatch.setenv(
        "ANDYUR_KUBERNETES_PROXY_EGRESS",
        '[{"namespace":"andyur-system","labels":{"app":"andyur-server"},'
        '"port":8642},{"namespace":"andyur-system",'
        '"labels":{"app":"andyur-ollama"},"port":11434}]',
    )
    controller = FakeController()
    return orchestrator.KubernetesOrchestrator(controller), controller


def _spec(**changes):
    values = {
        "run_id": "run-one",
        "agent": "oncall",
        "run_token": "run-token",
        "channel_token": "channel-token",
        "generation": "worker-one",
        "registry_agent_id": "agt_oncall",
    }
    values.update(changes)
    return RunSpec(**values)


def test_launch_translates_the_daemon_assignment_without_weak_defaults(kube):
    runtime, controller = kube
    handle = runtime.launch(_spec(), None)

    [(group, credentials)] = controller.launched
    assert handle.pid == 0
    assert group.namespace == "andyur-runs"
    assert group.run_id == "run-one"
    assert group.generation == "worker-one"
    assert group.agent_id == "oncall"
    assert group.registry_agent_id == "agt_oncall"
    assert group.proxy_image == IMAGE
    assert group.agent_image == IMAGE
    assert group.llm_mode == "ollama"
    assert group.ollama_url == "http://andyur-ollama.andyur-system.svc:11434"
    assert group.as_token_endpoint == "https://as.example/token"
    assert group.as_jwks_url == "https://as.example/jwks"
    assert group.as_provider == "reference"
    assert group.as_capability == "contextual"
    assert group.broker_state_peer is None
    assert [(peer.namespace, peer.labels, peer.port, peer.protocol)
            for peer in group.proxy_egress] == [
        ("andyur-system", {"app": "andyur-server"}, 8642, "TCP"),
        ("andyur-system", {"app": "andyur-ollama"}, 11434, "TCP"),
    ]
    assert credentials.channel_token == "channel-token"
    assert credentials.run_token == "run-token"
    assert credentials.litellm_key == "service-key"
    assert credentials.as_client_secret == "as-secret"


def test_broker_capability_is_explicitly_handed_to_group_and_credentials(kube):
    runtime, controller = kube
    runtime.launch(_spec(broker_enabled=True, broker_token="broker-token"), None)
    [(group, credentials)] = controller.launched
    assert group.broker_enabled is True
    assert group.broker_envoy_image == ENVOY_IMAGE
    assert group.broker_state_host == "andyur-broker-state.andyur-system.svc"
    assert group.broker_state_port == 9443
    assert group.broker_state_peer is not None
    assert group.broker_state_peer.port == 9443
    assert credentials.broker_token == "broker-token"


def test_broker_peer_is_required_only_for_brokered_runs(kube, monkeypatch):
    runtime, controller = kube
    monkeypatch.delenv("ANDYUR_KUBERNETES_BROKER_STATE_PEER")
    with pytest.raises(config.InsecureProfile, match="BROKER_STATE_PEER"):
        runtime.launch(
            _spec(broker_enabled=True, broker_token="broker-token"), None)
    assert controller.launched == []

    runtime.launch(_spec(), None)
    [(group, _)] = controller.launched
    assert all(peer.port != 9443 for peer in group.proxy_egress)


def test_certified_launch_copies_exact_evidence_to_proxy_secret(
        kube, tmp_path, monkeypatch):
    runtime, controller = kube
    evidence = tmp_path / "certification.json"
    public_key = tmp_path / "certifier.pub"
    evidence.write_text('{"signed":true}')
    public_key.write_text("PUBLIC KEY")
    monkeypatch.setattr(config, "AS_PRODUCT_VERSION", "managed")
    monkeypatch.setattr(config, "AS_CERTIFICATION_FILE", str(evidence))
    monkeypatch.setattr(
        config, "AS_CERTIFICATION_PUBLIC_KEY_FILE", str(public_key))

    runtime.launch(_spec(), None)
    [(group, credentials)] = controller.launched
    assert group.as_product_version == "managed"
    assert group.as_certified is True
    assert credentials.as_certification == '{"signed":true}'
    assert credentials.as_certification_public_key == "PUBLIC KEY"


@pytest.mark.parametrize("field", [
    "run_token", "channel_token", "generation", "registry_agent_id",
])
def test_missing_assignment_security_context_fails_before_api_use(kube, field):
    runtime, controller = kube
    with pytest.raises(config.InsecureProfile, match="requires"):
        runtime.launch(_spec(**{field: None}), None)
    assert controller.launched == []


def test_adopted_generation_is_deleted_exactly(kube):
    runtime, controller = kube
    controller.running = [("run-adopted", "worker-old")]

    assert runtime.list_running() == ["run-adopted"]
    runtime.kill(["run-adopted"])

    assert controller.deleted == [("run-adopted", "worker-old")]


def test_cleanup_never_broadens_to_a_logical_run_id(kube):
    runtime, controller = kube
    runtime.launch(_spec(), None)
    runtime.cleanup("run-one")

    assert controller.deleted == [("run-one", "worker-one")]


def test_invalid_proxy_egress_fails_closed_before_api_use(kube, monkeypatch):
    runtime, controller = kube
    monkeypatch.setenv("ANDYUR_KUBERNETES_PROXY_EGRESS", "not-json")

    with pytest.raises(config.InsecureProfile, match="PROXY_EGRESS"):
        runtime.launch(_spec(), None)

    assert controller.launched == []


def test_explicit_kubernetes_selection_never_consults_local_shapes(monkeypatch):
    selected = object()
    monkeypatch.setattr(config, "DEPLOYMENT", "kubernetes")
    monkeypatch.setattr(
        orchestrator, "KubernetesOrchestrator",
        lambda owner_generation=None: (selected, owner_generation),
    )
    monkeypatch.setattr(
        orchestrator, "HostOrchestrator",
        lambda: pytest.fail("fell back to host execution"),
    )
    monkeypatch.setattr(
        orchestrator, "ContainerOrchestrator",
        lambda: pytest.fail("fell back to Docker execution"),
    )

    assert orchestrator.select("stable-worker") == (selected, "stable-worker")


def test_kubernetes_assignment_skips_agents_without_registry_identity(env, monkeypatch):
    from andyur import db
    from andyur.registry import service as registry_service

    # The REAL frozen dataclass, not a namespace. A hand-built stand-in silently
    # loses every field added to RuntimeResolution after it was written, and the
    # failure surfaces as an AttributeError deep in the serializer rather than
    # as "this fake is out of date".
    runtime = RuntimeResolution(
        runtime_type="container",
        interface_version="andyur-agent-runtime/v1",
        manifest_digest="sha256:" + "c" * 64,
        image_ref="registry.example/customer-agent",
        image_digest="sha256:" + "d" * 64,
        command=("/app/agent", "serve"),
        resources=ResourceSpec(cpu="1", memory="1Gi"),
        policy_revision="test",
    )
    resolution = SimpleNamespace(
        registry_digest="sha256:" + "e" * 64,
        runtime=runtime,
        model="model-granted",
    )
    registry = SimpleNamespace(resolve=lambda agent_id: resolution)
    monkeypatch.setattr(registry_service, "configured_registry", lambda: registry)

    env.agent("bound")
    env.agent("unbound")
    with db.connect() as conn:
        conn.execute(
            "UPDATE agents SET registry_agent_id = ? WHERE name = ?",
            ("agt_bound", "bound"),
        )
    unbound = coordinator.maybe_wakeup("unbound", "test")
    bound = coordinator.maybe_wakeup("bound", "test")

    assigned = coordinator.assign_runs(
        "kubernetes-worker", 2, require_registry=True)

    assert unbound is not None and bound is not None
    assert [run["id"] for run in assigned] == [bound]
    assert assigned[0]["registry_agent_id"] == "agt_bound"
    assert assigned[0]["runtime"]["image_ref"] == "registry.example/customer-agent"
    assert assigned[0]["runtime"]["command"] == ["/app/agent", "serve"]
    # the GRANTED model rides the assignment for the exec/v1 launcher
    assert assigned[0]["model"] == "model-granted"
    with db.connect() as conn:
        persisted = conn.execute(
            "SELECT runtime_resolution FROM runs WHERE id = ?", (bound,),
        ).fetchone()["runtime_resolution"]
    assert json.loads(persisted) == assigned[0]["runtime"]


@pytest.mark.parametrize("field,replacement", [
    ("runtime_type", "builtin-claude"),
    ("interface_version", "andyur-agent-runtime/v2"),
    ("manifest_digest", "sha256:" + "1" * 64),
    ("image_ref", "registry.example/substituted"),
    ("image_digest", "sha256:" + "2" * 64),
    ("command", ("/app/substituted",)),
    # A SimpleNamespace here for six commits, in the same file whose test
    # above warns against exactly that. It serialized fine because the old
    # encoder walked attributes; the codec refuses anything that is not the
    # frozen registry type, which is what makes a stale fake announce itself.
    ("resources", ResourceSpec(cpu="2", memory="2Gi")),
    ("policy_revision", "replacement-policy"),
])
def test_kubernetes_assignment_refuses_runtime_changed_since_admission(
        env, monkeypatch, field, replacement):
    """Every executable-identity field is sealed, not just image/registry."""
    from andyur import db
    from andyur.registry import service as registry_service

    admitted_runtime = RuntimeResolution(
        runtime_type="container",
        interface_version="andyur-agent-runtime/v1",
        manifest_digest="sha256:" + "c" * 64,
        image_ref="registry.example/customer-agent",
        image_digest="sha256:" + "d" * 64,
        command=("/app/agent", "serve"),
        resources=ResourceSpec(cpu="1", memory="1Gi"),
        policy_revision="admitted-policy",
    )
    resolution = SimpleNamespace(
        registry_digest="sha256:" + "e" * 64,
        runtime=admitted_runtime,
        model=None,
    )
    registry = SimpleNamespace(resolve=lambda agent_id: resolution)
    monkeypatch.setattr(registry_service, "configured_registry", lambda: registry)
    env.agent("sealed-runtime")
    with db.connect() as conn:
        conn.execute(
            "UPDATE agents SET registry_agent_id = ? WHERE name = ?",
            ("agt_sealed", "sealed-runtime"),
        )
    run_id = coordinator.maybe_wakeup("sealed-runtime", "seal executable")
    assert run_id is not None

    admitted_json = coordinator._canonical_runtime_resolution(admitted_runtime)
    with db.connect() as conn:
        conn.execute(
            "UPDATE runs SET runtime_resolution = NULL WHERE id = ?", (run_id,),
        )
    assert coordinator.assign_runs(
        "kubernetes-worker", 1, require_registry=True,
    ) == []
    with db.connect() as conn:
        conn.execute(
            "UPDATE runs SET runtime_resolution = ? WHERE id = ?",
            (admitted_json, run_id),
        )

    resolution.runtime = SimpleNamespace(**{
        **vars(admitted_runtime), field: replacement,
    })
    assert coordinator.assign_runs(
        "kubernetes-worker", 1, require_registry=True,
    ) == []
    with db.connect() as conn:
        row = conn.execute(
            "SELECT worker, runtime_resolution FROM runs WHERE id = ?", (run_id,),
        ).fetchone()
    assert row["worker"] is None
    assert row["runtime_resolution"] == admitted_json

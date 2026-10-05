"""Static cluster contract for Kubernetes RBAC and SPIFFE registration."""

from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import time

import pytest
import yaml


ROOT = Path(__file__).parents[1]


def _documents():
    return list(yaml.safe_load_all(
        (ROOT / "infra/kubernetes/run-isolation.yaml").read_text()))


def _control_plane_documents():
    return list(yaml.safe_load_all(
        (ROOT / "infra/kubernetes/control-plane.yaml").read_text()))


def test_namespace_enforces_restricted_pod_security():
    namespace = next(d for d in _documents() if d["kind"] == "Namespace")
    labels = namespace["metadata"]["labels"]
    assert labels["pod-security.kubernetes.io/enforce"] == "restricted"


def test_worker_rbac_is_namespaced_and_has_no_secret_or_cluster_authority():
    documents = _documents()
    role = next(d for d in documents if d["kind"] == "Role")
    assert role["metadata"]["namespace"] == "andyur-runs"
    resources = {resource for rule in role["rules"] for resource in rule["resources"]}
    assert resources == {
        "pods", "services", "serviceaccounts", "networkpolicies", "secrets", "leases",
        # exec/v1 input delivery writes a run's input by attach (a GET ws
        # upgrade -> verb get), and the run group emits an exec-config ConfigMap
        # that apply/list/delete need a rule for.
        "pods/attach", "configmaps",
        # exec/v1 completion reads the stock workload's output via GET
        # pods/{name}/log -- the pods/log subresource, distinct from pods and
        # pods/attach. Without it every summary is stored empty (403 swallowed).
        "pods/log",
    }
    assert all(d["kind"] != "ClusterRole" for d in documents)
    broad = {"create", "get", "list", "watch", "patch", "delete", "deletecollection"}
    for rule in role["rules"]:
        assert set(rule["verbs"]) <= broad
        if "secrets" in rule["resources"]:
            assert "watch" not in rule["verbs"]
        if "pods/attach" in rule["resources"]:
            assert rule["resources"] == ["pods/attach"]
            # GET ws-upgrade attach authorizes as `get`; `create` kept for
            # SPDY/POST clients and KEP-4006 (v1.35+ needs both). A create-only
            # rule cannot attach -- the defect this assertion now forbids.
            assert "get" in rule["verbs"] and set(rule["verbs"]) <= {"create", "get"}
        if "pods/log" in rule["resources"]:
            # Read-only, its own rule: the daemon reads output, never writes or
            # streams. get-only so this cannot be widened into exec/attach.
            assert rule["resources"] == ["pods/log"]
            assert rule["verbs"] == ["get"]
        if "configmaps" in rule["resources"]:
            # Pin the SET, not just "no watch": a create/get-only rule 403s
            # every teardown (list/deletecollection) again (R L1). Mirrors
            # secrets exactly.
            assert set(rule["verbs"]) == {
                "create", "get", "list", "patch", "delete", "deletecollection"}
            assert "watch" not in rule["verbs"]
    assert not any(sub in resources for sub in ("pods/exec", "pods/portforward", "pods/proxy"))


def test_the_execution_worker_has_its_own_narrower_run_role():
    """B+ ADVERSARIAL REVIEW (identity, H6): the execution worker shared the
    daemon's Role. It runs the same launcher, so it keeps what that launcher
    calls, and loses what only the daemon uses: no `watch` anywhere, and its
    fence is taken, read and released BY NAME -- no Lease list or collection
    delete, since it runs no sweep."""
    documents = _documents()
    roles = {d["metadata"]["name"]: d for d in documents if d["kind"] == "Role"}
    bindings = {d["metadata"]["name"]: d for d in documents if d["kind"] == "RoleBinding"}
    engine, daemon = roles["andyur-engine-run-controller"], roles["andyur-run-controller"]

    def granted(role):
        return {(res, verb) for rule in role["rules"]
                for res in rule["resources"] for verb in rule["verbs"]}
    assert granted(engine) < granted(daemon), "not strictly narrower than the daemon's"
    assert not any(verb == "watch" for _, verb in granted(engine))
    assert {v for r, v in granted(engine) if r == "leases"} == {"create", "get", "delete"}
    subjects = {(b["roleRef"]["name"], s["name"]) for b in bindings.values()
                for s in b["subjects"]}
    assert ("andyur-engine-run-controller", "andyur-temporal-execution-worker") in subjects
    assert ("andyur-run-controller", "andyur-temporal-execution-worker") not in subjects
    assert ("andyur-engine-run-controller", "andyur-worker") not in subjects


def test_spire_registration_selects_only_the_trusted_proxy():
    registration = next(d for d in _documents() if d["kind"] == "ClusterSPIFFEID")
    labels = registration["spec"]["podSelector"]["matchLabels"]
    assert labels == {
        "app.kubernetes.io/name": "andyur-run",
        "app.kubernetes.io/managed-by": "andyur-worker",
        "app.kubernetes.io/component": "proxy",
    }
    template = registration["spec"]["spiffeIDTemplate"]
    assert "andyur.agent/id-raw" in template
    assert "andyur.run/id-raw" in template
    # Generation is deliberately not part of the logical run identity. It is
    # still mandatory in hashed Pod selectors for exact-generation ownership.
    assert "andyur.run/generation" not in template
    assert registration["spec"]["namespaceSelector"]["matchLabels"] == {
        "kubernetes.io/metadata.name": "andyur-runs",
    }


def test_control_plane_is_single_instance_persistent_and_digest_pinned():
    documents = _control_plane_documents()
    namespace = next(d for d in documents if d["kind"] == "Namespace")
    assert namespace["metadata"]["name"] == "andyur-system"
    assert namespace["metadata"]["labels"][
        "pod-security.kubernetes.io/enforce"] == "restricted"
    workloads = [d for d in documents if d["kind"] == "StatefulSet"]
    assert {d["metadata"]["name"] for d in workloads} == {
        "andyur-server", "andyur-worker"}
    assert all(d["spec"]["replicas"] == 1 for d in workloads)
    assert all("@sha256:" in d["spec"]["template"]["spec"]["containers"][0]["image"]
               for d in workloads)
    server = next(d for d in workloads if d["metadata"]["name"] == "andyur-server")
    volumes = server["spec"]["template"]["spec"]["volumes"]
    assert any(v.get("persistentVolumeClaim", {}).get("claimName") ==
               "andyur-server-data" for v in volumes)
    verifier = (ROOT / "infra/kubernetes/verify-macos.sh").read_text()
    assert ".status.containerStatuses[0].imageID" in verifier
    assert "does not match declared" in verifier


def test_ollama_ingress_admits_only_run_proxy_and_agent_pods():
    policies = [d for d in _control_plane_documents()
                if d["kind"] == "NetworkPolicy"]
    policy = next(d for d in policies if d["metadata"]["name"] == "ollama")
    [rule] = policy["spec"]["ingress"]
    assert {peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
            for peer in rule["from"]} == {"proxy", "agent"}
    assert rule["ports"] == [{"protocol": "TCP", "port": 11434}]


def test_worker_uses_in_cluster_rbac_and_explicit_runtime_configuration():
    documents = _control_plane_documents()
    worker = next(d for d in documents
                  if d["kind"] == "StatefulSet"
                  and d["metadata"]["name"] == "andyur-worker")
    pod = worker["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "andyur-worker"
    env = {item["name"]: item for item in pod["containers"][0]["env"]}
    assert env["ANDYUR_DEPLOYMENT"]["value"] == "kubernetes"
    assert env["ANDYUR_KUBERNETES_NAMESPACE"]["value"] == "andyur-runs"
    assert env["ANDYUR_WORKER_ID"]["value"] == "andyur-worker-0"
    assert "ANDYUR_KUBECONFIG" not in env
    assert "andyur-server" in env["ANDYUR_KUBERNETES_PROXY_EGRESS"]["value"]
    assert "andyur-ollama" in env["ANDYUR_KUBERNETES_PROXY_EGRESS"]["value"]
    assert "9443" not in env["ANDYUR_KUBERNETES_PROXY_EGRESS"]["value"]
    assert env["ANDYUR_KUBERNETES_BROKER_ENVOY_IMAGE"]["value"].startswith(
        "docker.io/envoyproxy/envoy@sha256:")
    assert env["ANDYUR_KUBERNETES_BROKER_STATE_PORT"]["value"] == "9443"
    assert "andyur-server" in env[
        "ANDYUR_KUBERNETES_BROKER_STATE_PEER"]["value"]
    worker_policy = next(d for d in documents
                         if d["kind"] == "NetworkPolicy"
                         and d["metadata"]["name"] == "worker")
    serialized = repr(worker_policy["spec"]["egress"])
    assert "192.168.64.2/32" in serialized
    assert "6443" in serialized
    assert "0.0.0.0/0" not in serialized
    preflight = next(d for d in documents
                     if d["kind"] == "ClusterRole"
                     and d["metadata"]["name"] ==
                     "andyur-worker-isolation-preflight")
    assert preflight["rules"] == [{
        "apiGroups": [""], "resources": ["namespaces"],
        "resourceNames": ["andyur-runs"], "verbs": ["get"],
    }]
    assert not any("create" in rule["verbs"] or "patch" in rule["verbs"]
                   or "delete" in rule["verbs"] for rule in preflight["rules"])


def test_broker_state_ingress_is_private_mtls_uds_composition():
    documents = _control_plane_documents()
    server = next(d for d in documents if d["kind"] == "StatefulSet"
                  and d["metadata"]["name"] == "andyur-server")
    pod = server["spec"]["template"]["spec"]
    inits = {item["name"]: item for item in pod["initContainers"]}
    # THE SVID COMES FIRST, and the order is asserted rather than assumed: the
    # workflow worker and the server both read their client certificate from
    # disk at startup, so a bootstrap that ran second would be a race they lose
    # intermittently.
    assert [i["name"] for i in pod["initContainers"]] == [
        "temporal-svid-bootstrap", "broker-ingress-config"]
    assert inits["broker-ingress-config"]["command"] == [
        "python", "-m", "andyur.dataplane.brokertransport",
        "--write-ingress-config"]
    containers = {item["name"]: item for item in pod["containers"]}
    # The workflow worker runs HERE rather than in its own Deployment because
    # the activities read Andyur's database directly, and in this shape that is
    # SQLite on the server's own ReadWriteOnce volume -- a second Pod could not
    # mount it. On a Postgres deployment it becomes its own Deployment.
    assert set(containers) == {
        "server", "broker-state-backend", "broker-state-ingress",
        "temporal-svid-rotate", "workflow-worker"}
    assert containers["workflow-worker"]["command"] == [
        "python", "-m", "andyur.orchestration.temporal.worker"]
    backend = containers["broker-state-backend"]
    assert backend["command"] == [
        "python", "-m", "andyur.server.brokerstate_server"]
    assert not any("containerPort" in port for port in backend.get("ports", []))
    # The probe is DELIBERATELY not the serving module: `--check` imported the
    # whole application to make one request to a unix socket, which OOMKilled
    # this container and, under load, outlived its own timeout and got a
    # healthy process killed. See tests/test_brokerstate_check.py.
    check = ["python", "-m", "andyur.server.brokerstate_check"]
    assert backend["readinessProbe"]["exec"]["command"] == check
    assert backend["livenessProbe"]["exec"]["command"] == check
    ingress = containers["broker-state-ingress"]
    assert ingress["image"].startswith(
        "docker.io/envoyproxy/envoy@sha256:")
    assert ingress["ports"] == [{"name": "broker-state", "containerPort": 9443}]
    assert ingress["securityContext"]["runAsUser"] == 1337
    # A TCP CONNECT, NOT AN httpGet ON THE ADMIN PORT. This asserted
    # `httpGet: {host: 127.0.0.1, port: 9902}`, which can never pass: `host` on
    # an httpGet probe is dialled from the NODE's network namespace, while
    # Envoy's admin endpoint is bound to loopback inside the CONTAINER, exactly
    # as it should be. The kubelet got "connection refused" forever, the
    # container was never Ready, and every in-cluster gate's `kubectl wait`
    # timed out on this pod. The test passed throughout, because it asserted
    # the probe's SHAPE and never that the probe could succeed.
    assert ingress["readinessProbe"]["tcpSocket"] == {"port": "broker-state"}
    assert "httpGet" not in ingress["readinessProbe"]
    assert pod["securityContext"]["fsGroup"] == 1000
    mounts = {item["name"] for item in ingress["volumeMounts"]}
    assert {"broker-envoy-config", "broker-state-backend",
            "broker-ingress-tmp", "spiffe-workload-api"} == mounts

    service = next(d for d in documents if d["kind"] == "Service"
                   and d["metadata"]["name"] == "andyur-server")
    assert {item["name"]: item["port"] for item in service["spec"]["ports"]} == {
        "http": 8642, "broker-state": 9443}
    policy = next(d for d in documents if d["kind"] == "NetworkPolicy"
                  and d["metadata"]["name"] == "server")
    broker_rule = next(rule for rule in policy["spec"]["ingress"]
                       if rule["ports"] == [{"protocol": "TCP", "port": 9443}])
    assert broker_rule["from"] == [{
        "namespaceSelector": {"matchLabels": {
            "kubernetes.io/metadata.name": "andyur-runs"}},
        "podSelector": {"matchLabels": {
            "app.kubernetes.io/component": "proxy"}},
    }]


def test_every_control_plane_policy_rule_uses_the_correct_direction():
    policies = [d for d in _control_plane_documents()
                if d["kind"] == "NetworkPolicy"]
    for policy in policies:
        for rule in policy["spec"].get("ingress", []):
            assert "to" not in rule
            assert set(rule) <= {"from", "ports"}
        for rule in policy["spec"].get("egress", []):
            assert "from" not in rule
            assert set(rule) <= {"to", "ports"}


def test_live_gate_runs_active_positive_backed_cni_probes_not_a_stale_label():
    verifier = (ROOT / "infra/kubernetes/verify-macos.sh").read_text()
    probe = (ROOT / "infra/kubernetes/verify-network-policy.sh").read_text()
    assert "verify-network-policy.sh" in verifier
    assert "network-policy/verified" not in verifier
    for evidence in ("same-run allow", "cross-run", "DNS", "API", "internet"):
        assert evidence in probe


def test_live_gate_deadline_kills_a_term_ignoring_process_group():
    bounded = ROOT / "infra/kubernetes/bounded_exec.py"
    started = time.monotonic()
    result = subprocess.run([
        sys.executable, str(bounded), "0.1", sys.executable, "-c",
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
    ], timeout=7, check=False)
    assert result.returncode == 124
    assert time.monotonic() - started < 6


def test_control_plane_workloads_have_distinct_spiffe_roles():
    registrations = [d for d in _control_plane_documents()
                     if d["kind"] == "ClusterSPIFFEID"]
    assert {d["spec"]["spiffeIDTemplate"] for d in registrations} == {
        "spiffe://andyur.local/control-plane",
        "spiffe://andyur.local/worker",
        "spiffe://andyur.local/operator",
        # Architecture B+ (ADR-014 D11): the engine's execution worker, its
        # own identity rather than the daemon's.
        "spiffe://andyur.local/temporal-execution-worker",
    }
    assert all(d["spec"]["namespaceSelector"]["matchLabels"] == {
        "kubernetes.io/metadata.name": "andyur-system"}
        for d in registrations)
    assert all(d["spec"]["className"] == "spire-system-andyur-spire"
               for d in registrations)



def _live_result(prefix: str) -> dict:
    """The ONE artifact a live gate most recently produced, found by prefix.

    Pinned by exact filename before -- date, OS and arch -- so re-running a
    gate on a different day, or on a machine that names itself `darwin` rather
    than `macos`, broke the test that reads it with FileNotFoundError. The name
    is not the claim; the contents are. More than one is an error, because two
    artifacts for one gate means nobody knows which is current."""
    found = sorted((ROOT / "infra" / "kubernetes").glob(f"result-{prefix}-*.json"))
    assert found, f"no live evidence for {prefix}: the gate has never been recorded"
    assert len(found) == 1, (
        f"{len(found)} artifacts for {prefix} ({[f.name for f in found]}); "
        "one gate, one current result")
    return json.loads(found[0].read_text())

def test_live_exec_input_result_is_current_and_proves_verbatim_delivery():
    """The exec/v1 input-delivery gate, held to the same bar as its siblings:
    ok=True, every mode byte-identical AND its bearer-reference-survives-verbatim
    control, the file+templates two-sided control (bearer rendered into the
    declared file while the input stays literal), the negative control still
    blocked, and source-hash currency. Without this the security property the
    gate exists to prove could ship with ok:false or a hand-stubbed result and
    only test_no_shipped_evidence_is_stale (a currency check) would notice."""
    result = _live_result("exec-input")
    assert result["gate"] == "exec-input-delivery"
    assert result["ok"] is True
    for mode in ("stdin", "file", "argv", "file_with_templates"):
        m = result["modes"][mode]
        assert m["ok"] is True, mode
        assert m["byte_identical"] is True, mode
        assert m["reference_survived_verbatim"] is True, mode
        assert m["bearer_absent_from_input"] is True, mode
    ft = result["modes"]["file_with_templates"]
    assert ft["bearer_rendered_into_declared_file"] is True
    assert ft["file_private_to_workload_uid"] is True
    assert result["no_delivery_control"]["still_blocked"] is True
    # H5/H6 read path, proven both ways THROUGH the worker SA: the real SA reads
    # the workload's stdout byte-identical (the pods/log grant + limitBytes head
    # window), and an SA whose Role lacks pods/log gets 403 -- so the grant is
    # load-bearing, not decoration.
    orr = result["output_read_rbac"]
    assert orr["ok"] is True
    assert orr["granted_read_byte_identical"] is True
    assert orr["ungranted_read_403"] is True
    # currency binding: recorded hashes are sha256 of the CURRENT source
    src = result["source_sha256"]
    assert src and all(
        v == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name, v in src.items())


def test_live_run_singleton_result_is_current_and_proves_mutation_restoration():
    result = _live_result("run-singleton")
    assert result["second_claim_refused"] is True
    assert result["generation_name_mutation_red"]["winners"] == 2
    mutation_names = result["generation_name_mutation_red"]["lease_names"]
    assert len(mutation_names) == len(set(mutation_names)) == 2
    assert result["restored_run_scoped_winners"] == 1
    assert result["stale_release_refused"] is True
    assert result["stale_release_status"] == 409
    assert result["lease_duration_absent"] is True
    assert result["teardown_absent"] is True
    assert result["started_at"] < result["finished_at"]
    assert set(result["cluster"]) == {
        "context", "api_server_sha256", "kubernetes_git_version",
        "namespace_uid",
    }
    assert len(result["cluster"]["api_server_sha256"]) == 64
    assert result["cluster"]["namespace_uid"]
    expected = {
        "andyur/daemon/kubernetes_api.py",
        "andyur/daemon/kubernetes_controller.py",
        "andyur/daemon/kubernetes_manifests.py",
        "infra/kubernetes/bounded_exec.py",
        "infra/kubernetes/verify-run-singleton.py",
        "infra/kubernetes/verify-run-singleton.sh",
    }
    assert set(result["source_sha256"]) == expected
    assert result["source_sha256"] == {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in expected}


def test_live_broker_lifecycle_result_is_current_and_closes_h2_h3():
    result = _live_result("broker-lifecycle")
    assert result["cluster_version"].startswith("v1.29.")
    assert result["adopted_directory"] == "2750 1000 1000 socket=660"
    assert result["rebound_socket_connect"] == "connected"
    assert "sha256:" in result["image_id"]
    assert result["executed_source_sha256"] == {
        name: result["source_sha256"][name]
        for name in result["executed_source_sha256"]
    }
    assert result["broker_restart_count"] >= 1
    assert result["native_sidecars"] == ["broker-restart", "envoy-shape"]
    assert result["pod_phase_after_runner_exit"] == "Succeeded"
    assert result["controller_rollback"] == {
        "positive_ready_launch": True,
        "positive_teardown_absent": True,
        "permanent_refusal": result["controller_rollback"]["permanent_refusal"],
        "refused_agent_absent_after_rollback": True,
        "refused_generation_absent": True,
        "refused_lease_released": True,
        "ready_timeout_seconds": 5.0,
        "positive_lease": result["controller_rollback"]["positive_lease"],
        "surrogate_image": result["controller_rollback"]["surrogate_image"],
    }
    refusal = result["controller_rollback"]["permanent_refusal"]
    assert "was not ready" in refusal
    assert "rollback also failed" not in refusal
    assert "@sha256:" in result["controller_rollback"]["surrogate_image"]
    assert result["teardown_absent"] is True
    expected = {
        "andyur/daemon/kubernetes_api.py",
        "andyur/daemon/kubernetes_controller.py",
        "andyur/dataplane/denybroker.py",
        "andyur/dataplane/brokeruds.py",
        "andyur/daemon/kubernetes_manifests.py",
        "infra/kubernetes/verify-broker-lifecycle.py",
        "infra/kubernetes/verify-broker-lifecycle.sh",
    }
    assert set(result["source_sha256"]) == expected
    assert result["source_sha256"] == {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in expected}


def test_live_broker_semantic_wire_result_is_current_and_complete():
    from andyur.dataplane.brokertransport import (
        BrokerIngressTransport, BrokerTransport,
        build_egress_bootstrap, build_ingress_bootstrap)

    result = json.loads((ROOT / "infra/kubernetes/"
        "result-broker-semantic-wire-2026-08-20-macos-arm64.json").read_text())
    assert result["positive"]["status"] == 200
    assert result["positive"]["forged_xfcc_sanitized"] is True
    assert result["wrong_peer_replay"] == {
        "captured_jwt_replayed": True, "status": 403}
    assert result["identity_mutation_red_restored"] == {
        "forged_peer_accepted_status": 200,
        "mutation_applied": True,
        "restored_refusal_status": 403,
    }
    assert result["sds_rotation"]["rotated"] is True
    assert result["sds_rotation"]["before"] != result["sds_rotation"]["after"]
    assert result["saturation"]["requests"] == 96
    assert result["saturation"]["authenticated_positive_status"] == 200
    assert result["saturation"]["refused"] == 96
    assert result["saturation"]["status_distribution"]
    assert sum(result["saturation"]["status_distribution"].values()) == 96
    assert "200" not in result["saturation"]["status_distribution"]
    assert result["saturation"]["recovered_status"] == 200
    assert result["halt_replay"] == {"run_state": "failed", "status": 401}
    assert result["teardown"] == {
        "containers_absent": True, "spire_down": True, "volumes_absent": True}
    assert result["envoy_image"].startswith(
        "docker.io/envoyproxy/envoy@sha256:")
    assert result["server_image_id"].startswith("sha256:")
    executed_expected = {
        "andyur/dataplane/brokertransport.py",
        "andyur/server/brokerstate_server.py",
        "andyur/server/auth.py",
        "andyur/server/app.py",
    }
    assert set(result["executed_source_sha256"]) == executed_expected
    assert result["executed_source_sha256"] == {
        path: result["source_sha256"][path] for path in executed_expected}
    expected = {
        "andyur/dataplane/brokertransport.py",
        "andyur/server/brokerstate_server.py",
        "andyur/server/auth.py",
        "andyur/server/app.py",
        "infra/kubernetes/verify-broker-semantic-wire.py",
        "infra/kubernetes/verify-broker-semantic-wire.sh",
        "infra/spire/docker/agent.conf",
        "infra/spire/docker/server.conf",
    }
    assert result["source_sha256"] == {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in expected}
    context = result["run_context"]
    assert result["positive"]["state"]["run_id"] == context["run_id"]
    assert result["positive"]["state"]["agent"] == context["agent"]
    assert context["expected_actor"] == (
        f"spiffe://andyur.local/agent/{context['agent']}/run/{context['run_id']}")
    assert result["positive"]["state"]["expected_actor"] == context["expected_actor"]
    assert context["wrong_actor"] == (
        f"spiffe://andyur.local/agent/{context['agent']}/run/{context['wrong_run_id']}")
    good = BrokerTransport(
        context["expected_actor"], context["control_plane"], "andyur.local",
        "/run/egress/state.sock", "andyur-wire-ingress", 9443,
        "/run/backend/socket/state.sock", "/run/spire/sockets/api.sock")
    wrong = BrokerTransport(
        context["wrong_actor"], context["control_plane"], "andyur.local",
        "/run/egress/state.sock", "andyur-wire-ingress", 9443,
        "/run/backend/socket/state.sock", "/run/spire/sockets/api.sock")
    ingress = BrokerIngressTransport(
        context["control_plane"], "andyur.local", 9443,
        "/run/backend/socket/state.sock", "/run/spire/sockets/api.sock")
    configs = {
        "egress.json": build_egress_bootstrap(good),
        "wrong.json": build_egress_bootstrap(wrong),
        "ingress.json": build_ingress_bootstrap(ingress),
    }
    assert result["config_sha256"] == {
        name: hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        for name, config in configs.items()}


def test_broker_lifecycle_gate_requires_explicit_current_source_image():
    verifier = (ROOT / "infra/kubernetes/verify-broker-lifecycle.py").read_text()
    assert 'os.environ.get("ANDYUR_BROKER_LIFECYCLE_IMAGE", "").strip()' in verifier
    assert "andyur-broker-lifecycle:cad7959-h234" not in verifier


def test_live_run_singleton_reserves_cleanup_before_outer_watchdog():
    script = (ROOT / "infra/kubernetes/verify-run-singleton.py").read_text()
    wrapper = (ROOT / "infra/kubernetes/verify-run-singleton.sh").read_text()
    assert "WORK_BUDGET_SECONDS = 150" in script
    assert "CLEANUP_BUDGET_SECONDS = 30" in script
    assert "bounded_exec.py 210" in wrapper
    assert script.count("require_work_budget(work_deadline") >= 5


def test_macos_gate_runs_nonexecutable_network_probe_via_bash():
    gate = (ROOT / "infra/kubernetes/verify-macos.sh").read_text()
    assert 'bounded_exec.py" 180 bash "$network_gate"' in gate


def test_network_probe_uses_a_fresh_unisolated_positive_control_namespace():
    gate = (ROOT / "infra/kubernetes/verify-network-policy.sh").read_text()
    assert 'CONTROL_NS="$PREFIX-control"' in gate
    assert "uuid.uuid4().hex" in gate
    assert '"andyur.probe/nonce": sys.argv[2]' in gate
    assert '"$current_nonce" == "$NONCE"' in gate
    assert '"$current_uid" == "$CONTROL_UID"' in gate
    assert 'for wait_pid in "${wait_pids[@]}"' in gate
    assert 'probe_kubectl exec' in gate
    assert 'connection probe did not execute' in gate
    assert 'DNS probe did not execute' in gate
    assert 'strict_cleanup || fail' in gate
    assert '--ignore-not-found -o name --request-timeout=2s' in gate
    assert 'namespace_remaining' in gate
    assert 'trap - EXIT HUP INT TERM' in gate
    assert "kubectl create -f - -o jsonpath='{.metadata.uid}'" in gate
    assert 'kubectl delete namespace "$CONTROL_NS"' in gate
    assert 'tcp "$CONTROL_NS" "$PREFIX-control" "$api_ip" 443 allow' in gate
    assert 'tcp "$CONTROL_NS" "$PREFIX-control" 1.1.1.1 443 allow' in gate
    assert 'kubectl exec -n "$CONTROL_NS" "$PREFIX-control"' in gate
    assert 'tcp "$SYSTEM_NS" "$PREFIX-control"' not in gate
    assert 'kubectl exec -n "$SYSTEM_NS" "$PREFIX-control"' not in gate
    assert '169.254.169.254 80 deny' in gate
    assert '"andyur.probe/mutation": "allow-all"' in gate
    assert '"ingress": [{}], "egress": [{}]' in gate
    assert 'mutation_count' in gate and '== 2' in gate
    assert gate.count('eventually_tcp "$RUN_NS" "$PREFIX-a-agent" "$ip_b"') == 2
    assert 'mutation_removed_and_denials_restored' in gate
    assert 'probe_resources_absent' in gate
    assert 'refusing to overwrite evidence' in gate


def test_live_network_policy_result_is_current():
    """The recorded target-cluster network-policy evidence must be bound to the
    CURRENT gate source, exactly like the broker-wire / lifecycle / release
    evidence beside it. Without this the sibling discipline is not applied to the
    fourth evidence file: verify-network-policy.sh could change while the recorded
    hashes go stale and nothing turns red -- the precise decay these source-bound
    tests exist to prevent (audit finding, production-review-closure review).

    The evidence keys are basenames of files that all live in infra/kubernetes/.

    FOUND BY THE RC GATE: this named the artifact by its DATE, so re-running the
    probe -- which writes a file named for the day it ran -- broke the test with
    a FileNotFoundError about a file nobody expected to still exist. The gate
    that must be re-run before every release had a test that only passed while
    it was not. Globbed now, and the single-match unpacking is the property the
    RC gate's recorder maintains: one gate, one current record.
    """
    [path] = sorted((ROOT / "infra/kubernetes").glob("result-network-policy-*.json"))
    result = json.loads(path.read_text())
    assert result["gate"] == "target-cluster-network-policy"
    assert result["ok"] is True
    # every recorded assertion is a real, passing check (not an empty/false stub)
    assert result["assertions"] and all(
        v is True for v in result["assertions"].values())
    # the two properties this gate exists to prove: isolation holds, and it is
    # ENFORCED (a permissive mutation opens it, removing the mutation restores it)
    assert result["assertions"]["cross_run_deny"] is True
    assert result["assertions"]["allow_all_mutation_applied"] is True
    assert result["assertions"]["mutation_removed_and_denials_restored"] is True
    # currency binding: the recorded hashes are sha256 of the CURRENT source
    expected = {"verify-network-policy.sh", "bounded_exec.py", "run-isolation.yaml"}
    assert set(result["source_sha256"]) == expected
    assert result["source_sha256"] == {
        name: hashlib.sha256(
            (ROOT / "infra/kubernetes" / name).read_bytes()).hexdigest()
        for name in result["source_sha256"]}


def test_runner_image_pins_mcp_to_the_same_range_as_requirements():
    """The runner image installs its dependencies by hand (no requirements.txt
    in the build), so the mcp pin has to be repeated there and kept identical:
    an unpinned build took mcp 2.x, under which runner/toolservice.py cannot
    import (mcp.server.fastmcp is gone), so the image could serve no tools --
    found only when the exec/v1 tool-call gate ran the REAL image."""
    import re
    req = (ROOT / "requirements.txt").read_text()
    docker = (ROOT / "Dockerfile.runner").read_text()
    pin = re.search(r"^mcp(>=[^\s#]+)$", req, re.M)
    assert pin, "requirements.txt no longer pins mcp"
    assert f'"mcp{pin.group(1)}"' in docker, (
        f"Dockerfile.runner must pin mcp{pin.group(1)} exactly as requirements.txt does")
    assert "<2" in pin.group(1)                      # the 1.x server API the tool service uses


def test_live_exec_tool_call_result_is_current_and_proves_the_declared_bearer_opens_mcp():
    """The M1 flip gate's live half (ADR-011 acceptance #3), held to the same bar
    as its siblings: ok=True, every workload-side probe with its negative, the
    readiness negative (no front -> rolled back), the launch under the worker
    SA, and source-hash currency. Without this the property the flip rests on
    could ship with ok:false or a hand-stubbed result."""
    result = _live_result("exec-tool-call")
    assert result["gate"] == "exec-tool-call"
    assert result["ok"] is True
    assert result["controller_identity"].startswith("system:serviceaccount:")
    checks = result["tool_call"]["checks"]
    for name in ("declared_bearer_is_a_header_value", "rendered_file_matches_env",
                 "declared_initialized_and_listed_the_real_registry",
                 "declared_tool_call_reached_the_tool_body", "undeclared_tool_refused",
                 "wrong_bearer_401", "no_bearer_401", "channel_token_as_bearer_401",
                 "bare_token_without_scheme_401", "front_ready_200_on_proxy_port",
                 # the front's policy, live (R HIGH-1 on PR #22): granted endpoint
                 # + model passes policy (503: no model leg in this gate), wrong
                 # model 403, listing/management endpoints 404 by name
                 "front_granted_call_passes_policy_503_no_upstream", "front_wrong_model_403",
                 "front_case_variant_model_key_403",
                 "front_model_listing_404", "front_model_delete_404",
                 "credentials_absent_from_workload", "workload_completed",
                 "resources_absent", "group_delete_prompt",
                 # telemetry ON, live (PR #24): the trusted proxy reaches the
                 # Collector within a bound, the workload is refused -- sustained,
                 # after its positive control -- and the trace is read back by id
                 "collector_from_proxy_allowed_within_bound",
                 "collector_from_agent_denied_sustained_after_proxy_allow",
                 "trace_read_back_by_id",
                 # PR B: the decisions are in the trace by the code the body carried
                 "trace_front_refusals_by_name", "trace_mcp_bearer_rejected",
                 "trace_serve_exit_by_name"):
        assert checks[name] is True, name
    tc = result["tool_call"]
    assert 0.0 <= tc["collector_from_proxy_seconds"] < tc["collector_from_proxy_bound_seconds"] == 15.0
    agent_probe = tc["probes"]["collector_from_agent"]
    assert agent_probe["after_positive_control"] is True
    assert agent_probe["attempts"] >= 5 and agent_probe["denied"] == agent_probe["attempts"]
    assert re.fullmatch(r"[0-9a-f]{32}", tc["trace"]["trace_id"])
    assert "exec-tool-call-gate.serve" in tc["trace"]["span_names"]
    assert tc["trace"]["services"] == ["andyur-runner"]
    assert result["otel"]["mode"] == "on" and result["otel"]["endpoint"].endswith(":4318")
    assert result["tool_call"]["proxy_command_is_the_real_serve_only_services"] is True
    assert result["no_front_rollback"]["ok"] is True
    assert result["no_front_rollback"]["launched"] is False
    # MED-0 live, and MED-B: only a readiness refusal counts, within the bound
    assert result["no_front_rollback"]["refused_for_readiness"] is True
    assert 0.0 <= result["no_front_rollback"]["rollback_seconds"] < 5.0
    assert result["tool_call"]["delete_seconds"] < 5.0
    # the artifact itself names the leg it does NOT cover (the server-side
    # scope refusal), so 14/14 cannot be read as full coverage
    assert "scope refusal" in result["not_covered"]
    # currency binding: recorded hashes are sha256 of the CURRENT source, and
    # the image executed THIS checkout's sidecar code
    src = result["source_sha256"]
    assert src and all(
        v == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name, v in src.items())
    for name, v in result["executed_source_sha256"].items():
        assert v == src[name], name


def test_server_image_pins_cosign_and_oras_by_version_and_checksum():
    """The governed registry shells out to cosign and oras inside the server
    Pod; the image must carry both, pinned by version AND per-arch checksum
    (an unverified download is not a trust anchor)."""
    import re
    docker = (ROOT / "Dockerfile.server").read_text()
    for tool in ("COSIGN", "ORAS"):
        assert re.search(rf"^ARG {tool}_VERSION=\d+\.\d+\.\d+$", docker, re.M), tool
        for arch in ("AMD64", "ARM64"):
            assert re.search(rf"^ARG {tool}_SHA256_{arch}=[0-9a-f]{{64}}$", docker, re.M), (tool, arch)
    assert "sha256sum -c -" in docker
    assert "/usr/local/bin/cosign version" in docker and "/usr/local/bin/oras version" in docker


def test_worker_image_installs_starlette_for_the_launcher_import_chain():
    """kubernetes_manifests -> dataplane.brokertransport -> envoyconfig ->
    extauthz imports starlette; a fresh Dockerfile.daemon build without it
    could not import the controller (found rolling the worker in-cluster).
    The exec-input gate's in-image probe imports the controller for real."""
    docker = (ROOT / "Dockerfile.daemon").read_text()
    assert '"starlette>=' in docker
    gate = (ROOT / "infra/kubernetes/verify-exec-input.py").read_text()
    assert "from andyur.daemon import kubernetes_controller" in gate


STOCK_WORKLOADS = {
    # demo dir, artifact glob, agent name, granted model, expected output substring
    "opensre": ("result-exec-opensre-*.json", "opensre-sre", "qwen3-andyur:latest", "root_cause"),
    "goose": ("result-exec-goose-*.json", "goose-agent", "qwen3-andyur:latest", "GOOSE DONE"),
    # gemma4-andyur, not qwen3-andyur: hermes refuses a window below 64K tokens
    "hermes": ("result-exec-hermes-*.json", "hermes-agent", "gemma4-andyur:latest", "HERMES DONE"),
}


@pytest.mark.parametrize("demo", sorted(STOCK_WORKLOADS))
def test_live_stock_workload_result_proves_acceptance_1_with_its_trace(demo):
    """ADR-011 acceptance #1, live, for EVERY stock workload (OpenSRE, and Goose
    as the second one with zero platform change): the unmodified upstream image
    ran to `done` through the in-cluster control plane on the governed
    registry, its report captured by the daemon, the run group gone afterwards;
    the node pulled exactly the manifest's digest; images pinned; and one run =
    one trace read back by id AFTER delivery completed with every expected
    decision present, the forwarded model calls naming the grant."""
    glob, agent, model, expect = STOCK_WORKLOADS[demo]
    [path] = sorted((ROOT / "infra/kubernetes").glob(glob))
    result = json.loads(path.read_text())
    assert result["gate"] == f"exec-{demo}-in-cluster" and result["ok"] is True
    assert result["demo"] == f"demos/{demo}"
    assert result["state"] == "done" and result["error"] is None
    assert result["run_resources_gone"] is True
    assert result["expected_output_substring"] == expect and result["expected_output_present"] is True
    assert expect in result["summary_excerpt"] or result["summary_bytes"] > 400
    manifest = json.loads((ROOT / "demos" / demo / "agent.json").read_text())
    assert result["workload_image"] == {"manifest_digest": manifest["runtime"]["image"]["digest"],
                                        "node_pulled_digest": manifest["runtime"]["image"]["digest"],
                                        "pinned": True}
    images = result["images"]
    assert images["registry"] == "governed" and "@sha256:" in images["registry_ref"]
    assert all("@sha256:" in images[k] for k in ("server", "worker", "proxy"))
    assert images["require_run_svid"] == "on"
    assert images["otel"] == {"mode": "on", "server_mode": "on",
                              "endpoint": "http://otel-collector.andyur-system.svc:4318"}
    assert "exec/v1 completion reported (done)" in result["worker_log_tail"]
    trace = result["trace"]
    assert result["trace_ok"] is True and trace["expected_present"] is True
    assert trace["expected_missing"] == [] and trace["dangling_parent_spans"] == []
    assert re.fullmatch(r"[0-9a-f]{32}", trace["trace_id"])
    assert set(trace["span_names"]) >= {
        f"run {agent}", "server.start_run", "server.worker_finish_run", "daemon.launch",
        "daemon.exec_completion", "daemon.cleanup", "controller.wait_ready", "controller.delete",
        f"runner {agent}", "runner.execute", "runner.prepare", "runner.prompt", "runner.serve", "execfront POST"}
    # THE ENGINE'S HALF OF THE RUN IS IN THE TRACE. The durable provider is the
    # production default, and its workflow worker emitted nothing until it was
    # given the tracing interceptor and telemetry setup; the run's trace then
    # had a gap exactly where the engine was. Its spans are now part of it.
    #
    # UNDER ENGINE DISPATCH (ADR-014 D11, the production manifest's selection)
    # the execution worker hosts both the run's workflow and the activity that
    # launches it, so it IS the engine's half and the launcher at once; the
    # worker daemon only reconciles and emits nothing for a healthy run. The
    # gate records which launcher it read, and that must agree.
    if result.get("dispatch") == "engine":
        assert result["launcher"] == "deployment/andyur-temporal-execution-worker"
        assert trace["services"] == ["andyur-execution-worker", "andyur-runner",
                                     "andyur-server"]
    else:
        assert trace["services"] == ["andyur-daemon", "andyur-runner", "andyur-server",
                                     "andyur-workflow-worker"]
    # ONE root, and the run inside it. This read `== [f"run {agent}"]`, which
    # was true when the control plane had no request instrumentation: the
    # trigger's own HTTP call produced no span, so the run was the root. It now
    # produces `server.request POST`, so the trace begins at the API call that
    # started the run -- more of the story, not less.
    #
    # What must stay true is what the assertion was protecting: EXACTLY ONE
    # root, because a second root means a parent link was lost, and that is
    # indistinguishable from two unrelated traces. `dangling_parent_spans`
    # above is the other half of the same property.
    assert len(trace["root_spans"]) == 1, trace["root_spans"]
    assert trace["root_spans"][0] in (f"run {agent}", "server.request POST")
    # The user the run acts FOR is on the run span. Under user-auth this is the
    # IdP-authenticated subject, which is the whole point of the prod profile:
    # a production run inherits an enterprise-authenticated user rather than an
    # asserted or absent one.
    run_span = next(s for s in trace["spans"] if s["name"] == f"run {agent}")
    if result["images"].get("profile") == "prod":
        assert run_span["attributes"].get("andyur.user"), (
            "a prod-profile run carries no user: user-auth is on, so the run "
            "must have inherited an authenticated subject")
    forwarded = [s for s in trace["spans"] if s["name"] == "execfront POST"
                 and s["attributes"].get("andyur.decision") == "forwarded"]
    assert forwarded and all(s["attributes"]["gen_ai.request.model"] == model for s in forwarded)
    assert any(s["name"] == "runner.serve" and s["attributes"].get("andyur.serve.exit") == "sigterm"
               for s in trace["spans"])
    assert any(s["name"] == "daemon.exec_completion" and s["attributes"].get("andyur.finish") == "confirmed"
               for s in trace["spans"])
    # tool calls are observed, never required (the model decides); refusals at
    # the MCP boundary would be a finding by method
    assert isinstance(result["tool_calls_observed"], list)
    assert result["mcp_refusals_observed"] == []
    src = result["source_sha256"]
    assert src and all(
        v == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name, v in src.items())
    for name in ("infra/kubernetes/verify-exec-workload.sh", f"demos/{demo}/agent.json",
                 "infra/observability/trace_readback.py", "infra/kubernetes/observability.yaml"):
        assert name in src, name



# --- the telemetry path (observability-exit-criteria.md 7; production-gaps 21) ---

def _observability_documents():
    return list(yaml.safe_load_all(
        (ROOT / "infra/kubernetes/observability.yaml").read_text()))


COLLECTOR_IMAGE = ("docker.io/otel/opentelemetry-collector-contrib@sha256:"
                   "1f2c54a30e713fac6b3ae77a1ec84010c2007e29ced8ec666214fc2f6739c1cc")
JAEGER_IMAGE = ("cr.jaegertracing.io/jaegertracing/jaeger@sha256:"
                "46a886260e04002d8f45e213fc39063fa11a50446048fdaa64786fc0840cb9f8")
COLLECTOR_ENDPOINT = "http://otel-collector.andyur-system.svc:4318"


def _containers(doc):
    return doc["spec"]["template"]["spec"]["containers"]


def test_the_deployed_profile_ships_with_telemetry_on_and_the_collector_endpoint():
    """Criterion 7: telemetry ON is the default of the deployed profile. Every
    control-plane container exports to the in-cluster Collector; the worker's
    value is what every run sidecar inherits (governed_kubernetes.py ->
    kubernetes_manifests.py), so `off` anywhere here darkens the run path."""
    seen = {}
    for doc in _control_plane_documents():
        if doc["kind"] not in {"StatefulSet", "Deployment"}:
            continue
        for container in _containers(doc):
            env = {e["name"]: e.get("value") for e in container.get("env", [])}
            if "ANDYUR_OTEL" in env:
                seen[(doc["metadata"]["name"], container["name"])] = (
                    env["ANDYUR_OTEL"], env.get("ANDYUR_OTEL_ENDPOINT"))
    assert set(seen) == {("andyur-operator", "operator"), ("andyur-server", "server"),
                         ("andyur-server", "broker-state-backend"),
                         ("andyur-server", "workflow-worker"),
                         ("andyur-worker", "worker"),
                         ("andyur-temporal-execution-worker", "execution-worker")}
    assert all(v == ("on", COLLECTOR_ENDPOINT) for v in seen.values()), seen


def test_run_sidecars_may_reach_the_collector_and_nothing_else_new():
    """The proxy egress peer list is what a run sidecar's NetworkPolicy admits:
    server, the model service, and now the Collector on 4318 -- no other port,
    no Jaeger (spans reach Jaeger only through the Collector)."""
    worker = next(d for d in _control_plane_documents()
                  if d["kind"] == "StatefulSet" and d["metadata"]["name"] == "andyur-worker")
    env = {e["name"]: e.get("value") for e in _containers(worker)[0]["env"]}
    peers = json.loads(env["ANDYUR_KUBERNETES_PROXY_EGRESS"])
    assert {(p["labels"]["app"], p["port"]) for p in peers} == {
        ("andyur-server", 8642), ("andyur-ollama", 11434), ("otel-collector", 4318)}
    assert all(p["namespace"] == "andyur-system" for p in peers)


def test_control_plane_policies_admit_the_collector_and_the_operator_reads_jaeger():
    """Each component's default-deny policy opens exactly the telemetry egress it
    needs: everyone -> collector:4318; the operator (the gates' vantage point)
    additionally -> jaeger:16686 (query) and collector:9464 (metrics)."""
    policies = {d["metadata"]["name"]: d for d in _control_plane_documents()
                if d["kind"] == "NetworkPolicy"}

    def egress(name):
        out = set()
        for rule in policies[name]["spec"].get("egress", []):
            for to in rule["to"]:
                app = to.get("podSelector", {}).get("matchLabels", {}).get("app")
                if app:
                    out |= {(app, p["port"]) for p in rule["ports"]}
        return out
    for name in ("operator", "worker", "server"):
        assert ("otel-collector", 4318) in egress(name), name
    assert {("andyur-jaeger", 16686), ("otel-collector", 9464)} <= egress("operator")
    assert not {("andyur-jaeger", 16686), ("otel-collector", 9464)} & (egress("worker") | egress("server"))


def test_observability_manifests_are_digest_pinned_restricted_and_single_sourced():
    docs = _observability_documents()
    deployments = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Deployment"}
    assert set(deployments) == {"otel-collector", "andyur-jaeger"}
    assert _containers(deployments["otel-collector"])[0]["image"] == COLLECTOR_IMAGE
    assert _containers(deployments["andyur-jaeger"])[0]["image"] == JAEGER_IMAGE
    for name, doc in deployments.items():
        pod = doc["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False, name
        assert pod["securityContext"]["runAsNonRoot"] is True, name
        [container] = _containers(doc)
        sc = container["securityContext"]
        assert sc["allowPrivilegeEscalation"] is False and sc["capabilities"] == {"drop": ["ALL"]}
        assert sc["readOnlyRootFilesystem"] is True
        assert "memory" in container["resources"]["limits"], name
    env = {e["name"]: e["value"] for e in _containers(deployments["otel-collector"])[0]["env"]}
    assert env["GOMEMLIMIT"] == "300MiB"                # ~80 % of the 384Mi limit
    # one source per configuration: the Deployments mount ConfigMaps the apply
    # script generates from the files verify-config.sh validates
    volumes = {v["name"]: v for v in deployments["otel-collector"]["spec"]["template"]["spec"]["volumes"]}
    assert volumes["config"]["configMap"]["name"] == "otel-collector-config"
    volumes = {v["name"]: v for v in deployments["andyur-jaeger"]["spec"]["template"]["spec"]["volumes"]}
    assert volumes["config"]["configMap"]["name"] == "andyur-jaeger-config"
    apply = (ROOT / "infra/kubernetes/apply-observability.sh").read_text()
    assert 'configmap otel-collector-config "$ROOT/infra/observability/otel-collector.yaml"' in apply
    assert 'configmap andyur-jaeger-config "$ROOT/infra/observability/jaeger.yaml"' in apply
    verify = (ROOT / "infra/observability/verify-config.sh").read_text()
    assert f'COLLECTOR_IMAGE="{COLLECTOR_IMAGE}"' in verify and f'JAEGER_IMAGE="{JAEGER_IMAGE}"' in verify
    assert "jaeger.yaml:/etc/jaeger/config.yaml:ro" in verify
    # the Collector's exporter block is the adopter's seam: Jaeger is reached
    # only through it, and the same digest runs locally
    assert env["ANDYUR_TELEMETRY_BACKEND_OTLP_ENDPOINT"] == "http://andyur-jaeger:4318"
    compose = (ROOT / "infra/docker-compose.yml").read_text()
    assert JAEGER_IMAGE in compose and "all-in-one" not in compose
    assert "./observability/jaeger.yaml:/etc/jaeger/config.yaml:ro" in compose


def test_the_collector_trusts_its_network_so_ingest_admits_proxies_and_never_agents():
    """OTLP ingest is unauthenticated: whoever reaches 4318 writes into every
    run's trace. The ingress selects the control plane and the trusted run
    PROXY sidecar (in a namespace that passed the isolation probe) -- the
    agent/workload selector must never appear, on any port."""
    docs = _observability_documents()
    policies = {d["metadata"]["name"]: d for d in docs if d["kind"] == "NetworkPolicy"}
    assert set(policies) == {"otel-collector", "andyur-jaeger"}
    for policy in policies.values():
        assert policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
        for rule in policy["spec"].get("ingress", []):
            assert "to" not in rule and set(rule) <= {"from", "ports"}
            for peer in rule["from"]:
                labels = peer.get("podSelector", {}).get("matchLabels", {})
                assert labels.get("app.kubernetes.io/component") != "agent", rule
        for rule in policy["spec"].get("egress", []):
            assert "from" not in rule and set(rule) <= {"to", "ports"}
    collector = policies["otel-collector"]["spec"]
    ingest = next(r for r in collector["ingress"] if r["ports"] == [{"protocol": "TCP", "port": 4318}])
    apps = {p["podSelector"]["matchLabels"].get("app") for p in ingest["from"] if "namespaceSelector" not in p}
    assert apps == {"andyur-server", "andyur-worker", "andyur-operator",
                    "andyur-temporal-execution-worker"}
    [run_peer] = [p for p in ingest["from"] if "namespaceSelector" in p]
    assert run_peer == {
        "namespaceSelector": {"matchLabels": {"andyur.network-policy/verified": "true"}},
        "podSelector": {"matchLabels": {"app.kubernetes.io/component": "proxy"}}}
    metrics = next(r for r in collector["ingress"] if r["ports"] == [{"protocol": "TCP", "port": 9464}])
    assert metrics["from"] == [{"podSelector": {"matchLabels": {"app": "andyur-operator"}}}]
    jaeger = policies["andyur-jaeger"]["spec"]
    assert jaeger["egress"] == []
    assert {(r["from"][0]["podSelector"]["matchLabels"]["app"], r["ports"][0]["port"])
            for r in jaeger["ingress"]} == {("otel-collector", 4318), ("andyur-operator", 16686)}
    for r in jaeger["ingress"]:
        assert len(r["from"]) == 1
    # and the live probes exist: the synthetic agent and the REAL rendered agent
    np_gate = (ROOT / "infra/kubernetes/verify-network-policy.sh").read_text()
    assert 'collector_ip' in np_gate and '4318 deny' in np_gate
    tool_gate = (ROOT / "infra/kubernetes/verify-exec-tool-call.py").read_text()
    assert "collector_from_agent_denied_sustained_after_proxy_allow" in tool_gate
    assert "collector_from_proxy_allowed_within_bound" in tool_gate


def test_the_kubernetes_idp_is_the_same_realm_the_docker_stack_imports():
    """The reference IdP exists twice -- composed for Docker, and a manifest for
    Kubernetes -- and the realm is EMBEDDED in the second because a bundle a
    partner receives cannot reference a file from a checkout they do not have.
    Two copies of one fact drift; this is the check that says when.
    """
    import yaml

    docs = [d for d in yaml.safe_load_all(
        (ROOT / "infra/kubernetes/idp.yaml").read_text()) if d]
    realm_cm = next(d for d in docs
                    if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "andyur-idp-realm")
    embedded = json.loads(realm_cm["data"]["realm-andyur.json"])
    source = json.loads((ROOT / "infra/keycloak/realm-andyur.json").read_text())
    assert embedded == source, (
        "infra/kubernetes/idp.yaml's embedded realm has drifted from "
        "infra/keycloak/realm-andyur.json")


def test_the_control_plane_is_wired_to_an_idp_it_actually_deploys():
    """THE DEFECT THIS PAIR EXISTS FOR: control-plane.yaml shipped
    ANDYUR_PROFILE=prod, prod refuses to start without ANDYUR_USER_AUTH=on, and
    no identity provider was deployed anywhere -- so the reference deployment
    exited 3 at boot and every cluster that ran did so on a hand-edit in
    nobody's manifest.

    Each half is asserted against the other: the issuer the server validates
    must be the issuer the IdP mints, spelled identically, or logins validate
    against an issuer nobody issued.
    """
    import yaml

    idp = [d for d in yaml.safe_load_all(
        (ROOT / "infra/kubernetes/idp.yaml").read_text()) if d]
    keycloak = next(d for d in idp
                    if d["kind"] == "Deployment" and d["metadata"]["name"] == "andyur-keycloak")
    kc_env = {e["name"]: e.get("value")
              for e in keycloak["spec"]["template"]["spec"]["containers"][0]["env"]}
    minted_issuer = kc_env["KC_HOSTNAME"].rstrip("/") + "/realms/andyur"

    control = [d for d in yaml.safe_load_all(
        (ROOT / "infra/kubernetes/control-plane.yaml").read_text()) if d]
    profiled = []
    for doc in control:
        if doc["kind"] not in ("StatefulSet", "Deployment"):
            continue
        for container in doc["spec"]["template"]["spec"]["containers"]:
            env = {e["name"]: e.get("value") for e in container.get("env", [])}
            if "ANDYUR_PROFILE" not in env:
                continue
            profiled.append((doc["metadata"]["name"], container["name"], env))

    assert profiled, "no container declares a profile"
    for name, container, env in profiled:
        where = f"{name}/{container}"
        if env["ANDYUR_PROFILE"] != "prod":
            continue
        # assert_profile: prod requires user-auth; assert_user_auth: user-auth
        # requires BOTH an issuer and an audience, because without the audience
        # a token minted for another client in the same realm is trusted for
        # authority.
        assert env.get("ANDYUR_USER_AUTH") == "on", f"{where} runs prod without user-auth"
        assert env.get("ANDYUR_OIDC_AUDIENCE"), f"{where} has no OIDC audience"
        assert env.get("ANDYUR_OIDC_ISSUER") == minted_issuer, (
            f"{where} validates {env.get('ANDYUR_OIDC_ISSUER')!r} but the IdP "
            f"mints {minted_issuer!r}")


# --- prod means the same thing in every container that declares it ----------

def test_every_prod_container_that_checks_the_profile_can_actually_start():
    """`config.assert_profile()` refuses ANDYUR_PROFILE=prod unless USER_AUTH
    and REQUIRE_RUN_SVID are both on. It is the first thing `daemon.run` does.

    The worker declared prod and carried only USER_AUTH, so the reference
    deployment's worker crash-looped on

        ANDYUR_PROFILE=prod requires: ANDYUR_REQUIRE_RUN_SVID=on

    -- an accurate message in a component nothing else reports on, so what an
    operator saw was a control plane that served and never launched a run.

    Checked here for EVERY container that declares the profile rather than for
    the worker, because the next component to declare prod will be written by
    someone who never read this."""
    import yaml

    manifest = ROOT / "infra" / "kubernetes" / "control-plane.yaml"
    docs = [d for d in yaml.safe_load_all(manifest.read_text()) if d]
    # Containers whose process is one that calls assert_profile at startup.
    # `sleep infinity` (the operator's shell) and the broker-state server do
    # not, and are exempt BY NAME so the exemption is visible rather than
    # implied by whatever the check happens not to look at.
    exempt = {"broker-state-backend", "broker-state-ingress"}
    checked = 0
    for doc in docs:
        if doc.get("kind") not in ("StatefulSet", "Deployment"):
            continue
        for container in doc["spec"]["template"]["spec"]["containers"]:
            env = {e.get("name"): e.get("value") for e in container.get("env", [])}
            if env.get("ANDYUR_PROFILE") != "prod":
                continue
            if container["name"] in exempt:
                continue
            where = f"{doc['metadata']['name']}/{container['name']}"
            assert env.get("ANDYUR_USER_AUTH") == "on", f"{where}: prod needs USER_AUTH"
            assert env.get("ANDYUR_REQUIRE_RUN_SVID") == "on", (
                f"{where}: declares ANDYUR_PROFILE=prod but not "
                "ANDYUR_REQUIRE_RUN_SVID=on, so assert_profile() refuses to start it")
            checked += 1
    assert checked >= 3, "this check found almost nothing; the manifest shape changed"


def test_that_requirement_is_the_one_the_code_actually_enforces():
    """Pinned against config.assert_profile itself, so the test cannot drift
    into asserting a rule the platform no longer has -- or miss one it gains."""
    import inspect

    from andyur import config

    source = inspect.getsource(config.assert_profile)
    assert "ANDYUR_REQUIRE_RUN_SVID=on" in source
    assert "ANDYUR_USER_AUTH=on" in source


def test_every_workload_that_exports_telemetry_is_admitted_by_the_collector():
    """A component that exports to the collector and is not in its ingress
    policy has its spans dropped at the network, silently, and the run's trace
    shows a hole where that component worked. The engine's execution worker
    shipped that way. Checked for EVERY exporting workload, so the next new
    component cannot."""
    obs = [d for d in yaml.safe_load_all((ROOT / "infra/kubernetes/observability.yaml").read_text()) if d]
    policy = next(d for d in obs if d["kind"] == "NetworkPolicy"
                  and d["spec"]["podSelector"].get("matchLabels", {}).get("app") == "otel-collector")
    admitted = {peer.get("podSelector", {}).get("matchLabels", {}).get("app")
                for rule in policy["spec"].get("ingress", [])
                for peer in rule.get("from", [])}

    exporting = set()
    for doc in _control_plane_documents():
        if doc["kind"] not in {"StatefulSet", "Deployment"}:
            continue
        for container in _containers(doc):
            env = {e["name"]: e.get("value") for e in container.get("env", [])}
            if env.get("ANDYUR_OTEL") == "on" and env.get("ANDYUR_OTEL_ENDPOINT"):
                exporting.add(doc["spec"]["template"]["metadata"]["labels"]["app"])

    assert exporting, "no exporting workload was found; the scan is not reading the manifest"
    assert exporting <= admitted, (
        f"{sorted(exporting - admitted)} export telemetry but the collector's "
        "ingress does not admit them; their spans are dropped at the network")


def test_the_production_deployment_dispatches_through_the_engine_and_the_package_does_not():
    """ADR-014 D11, Step 17. The official manifest selects Temporal AND engine
    dispatch for every process that admits or executes runs; the Python package
    defaults stay native, so `pip install andyur` and the ten-minute path need
    no engine. The choice lives in the deployment, not in a profile default."""
    from andyur.orchestration.temporal.config import TemporalConfig

    seen = {}
    for doc in _control_plane_documents():
        if doc["kind"] not in {"StatefulSet", "Deployment"}:
            continue
        for container in _containers(doc):
            env = {e["name"]: e.get("value") for e in container.get("env", [])}
            if env.get("ANDYUR_WORKFLOW_PROVIDER") == "temporal":
                seen[(doc["metadata"]["name"], container["name"])] = env.get(
                    "ANDYUR_TEMPORAL_DISPATCH")
    assert seen == {("andyur-server", "server"): "engine",
                    ("andyur-server", "workflow-worker"): "engine",
                    ("andyur-temporal-execution-worker", "execution-worker"): "engine"}, seen
    assert TemporalConfig().dispatch == "native", "the package default must stay native"

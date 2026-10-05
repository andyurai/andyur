#!/usr/bin/env python3
"""Live proof for the run-scoped create-only Kubernetes fence."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from kubernetes import client, config

from andyur.daemon import kubernetes_controller as controller_module
from andyur.daemon.kubernetes_api import OfficialKubernetesApi
from andyur.daemon.kubernetes_controller import (
    KubernetesRunController,
    RunCredentials,
)
from andyur.daemon.kubernetes_manifests import RunGroupSpec, run_group_names_for_identity


ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "andyur/daemon/kubernetes_api.py",
    "andyur/daemon/kubernetes_controller.py",
    "andyur/daemon/kubernetes_manifests.py",
    "infra/kubernetes/bounded_exec.py",
    "infra/kubernetes/verify-run-singleton.py",
    "infra/kubernetes/verify-run-singleton.sh",
)
IMAGE = "example.invalid/andyur@sha256:" + "1" * 64
CREDS = RunCredentials("channel", "run", "llm")
WORK_BUDGET_SECONDS = 150
CLEANUP_BUDGET_SECONDS = 30


def require_work_budget(deadline: float, required: float) -> None:
    if deadline - time.monotonic() < required:
        raise TimeoutError("singleton evidence work budget exhausted")


def labels(run_id: str, holder: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/managed-by": "andyur-worker",
        "andyur.run/id": hashlib.sha256(run_id.encode()).hexdigest()[:16],
        "andyur.run/generation": hashlib.sha256(holder.encode()).hexdigest()[:16],
    }


def spec(namespace: str, run_id: str, holder: str) -> RunGroupSpec:
    return RunGroupSpec(
        namespace=namespace, run_id=run_id, generation=holder,
        agent_id="scout", registry_agent_id="scout",
        proxy_image=IMAGE, agent_image=IMAGE,
        proxy_args=("true",), agent_args=("true",),
    )


def historical_generation_names(run_id: str, holder: str) -> dict[str, str]:
    """Exact former naming expression used by the mutation phase."""
    digest = lambda value, size: hashlib.sha256(value.encode()).hexdigest()[:size]
    base = f"andyur-run-{digest(run_id, 12)}-{digest(holder, 8)}"
    names = run_group_names_for_identity(run_id, holder)
    return {**names, "lease": base}


class ClaimOnlyLiveApi:
    """Exercise the real controller and live Lease API, stopping before Pods."""

    def __init__(self) -> None:
        self.live = OfficialKubernetesApi()
        self.applied = 0

    def assert_isolation_ready(self, namespace):
        return None

    def claim_run_singleton(self, namespace, name, selector, owner):
        return self.live.claim_run_singleton(namespace, name, selector, owner)

    def release_run_singleton(self, namespace, claim, timeout):
        return self.live.release_run_singleton(namespace, claim, timeout)

    def apply(self, resource):
        self.applied += 1

    def wait_pod_ready(self, namespace, name, timeout):
        return True

    def pod_ip(self, namespace, name):
        return "127.0.0.1"

    def delete_run_group(self, namespace, selector, timeout):
        return None


def cluster_provenance(namespace: str) -> dict[str, str]:
    kubeconfig = os.environ["ANDYUR_KUBECONFIG"]
    _, active = config.list_kube_config_contexts(config_file=kubeconfig)
    config.load_kube_config(config_file=kubeconfig)
    api_client = client.ApiClient()
    version = client.VersionApi(api_client).get_code(_request_timeout=(3, 7))
    ns = client.CoreV1Api(api_client).read_namespace(
        namespace, _request_timeout=(3, 7))
    return {
        "context": active["name"],
        "api_server_sha256": hashlib.sha256(
            api_client.configuration.host.encode()).hexdigest(),
        "kubernetes_git_version": version.git_version,
        "namespace_uid": ns.metadata.uid,
    }


def main() -> None:
    started = datetime.now(timezone.utc)
    work_deadline = time.monotonic() + WORK_BUDGET_SECONDS
    namespace = os.environ.get("ANDYUR_RUN_NAMESPACE", "andyur-runs")
    require_work_budget(work_deadline, 25)
    provenance = cluster_provenance(namespace)
    run_id = uuid.uuid4().hex
    holder_a, holder_b = "live-holder-old", "live-holder-new"
    correct_name = run_group_names_for_identity(run_id, holder_a)["lease"]
    assert correct_name == run_group_names_for_identity(run_id, holder_b)["lease"]
    barrier = threading.Barrier(2)
    controllers: list[tuple[KubernetesRunController, ClaimOnlyLiveApi, str]] = []
    cleanup: list[tuple[OfficialKubernetesApi, object]] = []
    cleanup_lock = threading.Lock()

    def contender(holder: str):
        live = ClaimOnlyLiveApi()
        controller = KubernetesRunController(live, namespace)
        barrier.wait(timeout=10)
        try:
            controller.launch(spec(namespace, run_id, holder), CREDS)
        except RuntimeError as exc:
            assert "already owned" in str(exc)
            return None
        contender_claim = controller._claims[(run_id, holder)]
        with cleanup_lock:
            cleanup.append((live.live, contender_claim))
        controllers.append((controller, live, holder))
        return contender_claim

    try:
        require_work_budget(work_deadline, 20)
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(contender, (holder_a, holder_b)))
        winners = [item for item in claims if item is not None]
        assert len(winners) == 1
        claim = winners[0]
        winner_controller, winner_api, winner_holder = controllers[0]
        assert claim.name == correct_name and winner_api.applied > 0
    except BaseException as primary_error:
        cleanup_errors = []
        for cleanup_api, cleanup_claim in cleanup:
            try:
                cleanup_api.release_run_singleton(namespace, cleanup_claim, 5)
            except Exception as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            raise RuntimeError(
                f"initial singleton race failed and cleanup had "
                f"{len(cleanup_errors)} error(s)") from primary_error
        raise
    loser_holder = holder_b if winner_holder == holder_a else holder_a
    primary_cleanup = (winner_api.live, claim)
    replacement = None
    mutation_claims = []
    restored_winners = []
    result = None
    stale_release_status = None
    original_namer = controller_module.run_group_names
    try:
        require_work_budget(work_deadline, 45)
        winner_controller.delete(spec(namespace, run_id, winner_holder))
        cleanup.remove(primary_cleanup)
        replacement_api = OfficialKubernetesApi()
        replacement_labels = labels(run_id, loser_holder)
        replacement = replacement_api.claim_run_singleton(
            namespace, correct_name, replacement_labels, loser_holder)
        assert replacement is not None and replacement.uid != claim.uid
        cleanup.append((replacement_api, replacement))
        try:
            replacement_api.release_run_singleton(namespace, claim, 10)
        except client.ApiException as exc:
            assert exc.status == 409, exc
            stale_release_status = exc.status
        else:
            raise AssertionError("stale singleton claim deleted its replacement")
        assert replacement_api.read_run_singleton(
            namespace, correct_name, replacement_labels,
            loser_holder, 10) == replacement

        mutation_run = uuid.uuid4().hex
        mutation_holders = ("mutation-a", "mutation-b")
        controller_module.run_group_names = lambda item: historical_generation_names(
            item.run_id, item.generation)
        assert controller_module.run_group_names(
            spec(namespace, mutation_run, mutation_holders[0]))["lease"] \
            == historical_generation_names(mutation_run, mutation_holders[0])["lease"]
        mutation_names = []
        for holder in mutation_holders:
            require_work_budget(work_deadline, 15)
            live = ClaimOnlyLiveApi()
            mutated_controller = KubernetesRunController(live, namespace)
            mutated_controller.launch(spec(namespace, mutation_run, holder), CREDS)
            mutated = mutated_controller._claims[(mutation_run, holder)]
            mutation_claims.append(mutated)
            mutation_names.append(mutated.name)
            cleanup.append((live.live, mutated))
        assert len(set(mutation_names)) == 2
        assert all(name != run_group_names_for_identity(
            mutation_run, holder)["lease"]
            for name, holder in zip(mutation_names, mutation_holders))
        controller_module.run_group_names = original_namer
        assert controller_module.run_group_names(
            spec(namespace, mutation_run, mutation_holders[0]))["lease"] \
            == run_group_names_for_identity(mutation_run, mutation_holders[0])["lease"]

        restored_run = uuid.uuid4().hex
        restored_barrier = threading.Barrier(2)

        def restored_contender(holder: str):
            live = ClaimOnlyLiveApi()
            restored_controller = KubernetesRunController(live, namespace)
            restored_barrier.wait(timeout=10)
            try:
                restored_controller.launch(
                    spec(namespace, restored_run, holder), CREDS)
            except RuntimeError as exc:
                assert "already owned" in str(exc)
                return None
            restored_claim = restored_controller._claims[(restored_run, holder)]
            with cleanup_lock:
                cleanup.append((live.live, restored_claim))
            return restored_claim

        require_work_budget(work_deadline, 20)
        with ThreadPoolExecutor(max_workers=2) as pool:
            restored_claims = list(pool.map(
                restored_contender, ("restored-a", "restored-b")))
        restored_winners = [item for item in restored_claims if item is not None]
        assert len(restored_winners) == 1
        assert run_group_names_for_identity(restored_run, "restored-a")["lease"] \
            == run_group_names_for_identity(restored_run, "restored-b")["lease"]

        result = {
            "namespace": namespace, "lease": claim.name,
            "uid": claim.uid, "resource_version": claim.resource_version,
            "winner": claim.holder, "second_claim_refused": True,
            "lease_duration_absent": True, "stale_release_refused": True,
            "stale_release_status": stale_release_status,
            "generation_name_mutation_red": {
                "winners": 2, "lease_names": mutation_names},
            "restored_run_scoped_winners": len(restored_winners),
            "platform": platform.platform(),
            "started_at": started.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "cluster": provenance,
            "source_sha256": {
                path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                for path in SOURCES},
        }
    finally:
        controller_module.run_group_names = original_namer
        cleanup_errors = []
        cleanup_deadline = time.monotonic() + CLEANUP_BUDGET_SECONDS
        for cleanup_api, cleanup_claim in cleanup:
            try:
                remaining = cleanup_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("singleton evidence cleanup deadline expired")
                cleanup_api.release_run_singleton(
                    namespace, cleanup_claim, min(5, remaining))
            except Exception as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            raise RuntimeError(
                f"singleton evidence cleanup had {len(cleanup_errors)} error(s)") \
                from cleanup_errors[0]
    assert result is not None
    verify_api = OfficialKubernetesApi()
    for released in [replacement, *mutation_claims, *restored_winners]:
        assert released is not None
        released_run = (mutation_run if released.holder.startswith("mutation-")
                        else restored_run if released.holder.startswith("restored-")
                        else run_id)
        released_labels = labels(released_run, released.holder)
        assert verify_api.read_run_singleton(
            namespace, released.name, released_labels,
            released.holder, 10) is None
    result["teardown_absent"] = True
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

"""Transport-contract tests for the official Kubernetes adapter."""

from types import SimpleNamespace

import pytest

from andyur.daemon.kubernetes_api import OfficialKubernetesApi, _selector
from andyur.daemon import kubernetes_api


class Resource:
    def __init__(self, remaining=0):
        self.patch_calls = []
        self.delete_calls = []
        self.remaining = remaining
        self.create_calls = []

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        body = kwargs["body"]
        return SimpleNamespace(
            metadata=SimpleNamespace(
                name=body["metadata"]["name"], namespace=body["metadata"]["namespace"],
                labels=body["metadata"]["labels"], uid="lease-uid-1",
                resourceVersion="17"),
            spec=SimpleNamespace(holderIdentity=body["spec"]["holderIdentity"]))

    def patch(self, **kwargs):
        self.patch_calls.append(kwargs)

    def delete(self, **kwargs):
        self.delete_calls.append(kwargs)

    def get(self, **kwargs):
        return SimpleNamespace(items=[object()] * self.remaining)


class Resources:
    def __init__(self):
        self.found = []

    def get(self, api_version, kind):
        resource = Resource()
        self.found.append((api_version, kind, resource))
        return resource


def _api():
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    api._dynamic = SimpleNamespace(resources=Resources())
    api._run_resources = tuple(
        api._dynamic.resources.get(api_version=version, kind=kind)
        for version, kind in kubernetes_api._KINDS)
    api._lease_resource = api._dynamic.resources.get(
        api_version="coordination.k8s.io/v1", kind="Lease")
    return api


def test_apply_is_server_side_and_never_force_steals_fields():
    api = _api()
    body = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "p", "namespace": "runs"},
    }
    api.apply(body)
    _, _, resource = api._dynamic.resources.found[-1]
    [call] = resource.patch_calls
    assert call["body"] is body
    assert call["content_type"] == "application/apply-patch+yaml"
    assert call["field_manager"] == "andyur-worker"
    assert call["force"] is False
    assert call["_request_timeout"] == (3, 10)


def test_singleton_claim_is_create_only_and_release_is_preconditioned():
    api = _api()
    claim = api.claim_run_singleton(
        "runs", "andyur-run-abc-owner", {"andyur.run/id": "abc"}, "worker-1")
    assert claim == kubernetes_api.LeaseClaim(
        "andyur-run-abc-owner", "lease-uid-1", "17", "worker-1")
    [create] = api._lease_resource.create_calls
    assert create["body"]["spec"] == {"holderIdentity": "worker-1"}
    assert "leaseDurationSeconds" not in create["body"]["spec"]

    api.release_run_singleton("runs", claim, 10)
    [delete] = api._lease_resource.delete_calls
    assert delete["name"] == claim.name
    assert delete["body"] == {"preconditions": {
        "uid": "lease-uid-1", "resourceVersion": "17"}}


@pytest.mark.parametrize("mutation", [
    "name", "namespace", "labels", "holder", "duration", "uid", "version",
])
def test_singleton_refuses_any_admission_rewrite_or_incomplete_identity(mutation):
    labels = {"andyur.run/id": "abc", "andyur.run/generation": "def"}
    metadata = SimpleNamespace(
        name="lease", namespace="runs", labels=dict(labels), uid="uid", resourceVersion="9")
    spec = SimpleNamespace(holderIdentity="worker")
    if mutation == "name": metadata.name = "lease-worker"
    elif mutation == "namespace": metadata.namespace = "other"
    elif mutation == "labels": metadata.labels = {**labels, "extra": "rewrite"}
    elif mutation == "holder": spec.holderIdentity = "other-worker"
    elif mutation == "duration": spec.leaseDurationSeconds = 30
    elif mutation == "uid": metadata.uid = ""
    else: metadata.resourceVersion = ""
    with pytest.raises(RuntimeError, match="rewritten"):
        OfficialKubernetesApi._validated_claim(
            SimpleNamespace(metadata=metadata, spec=spec),
            "runs", "lease", labels, "worker")


def test_delete_uses_the_exact_generation_for_every_owned_kind():
    api = _api()
    selector = {"andyur.run/id": "abc", "andyur.run/generation": "def"}
    api.delete_run_group("runs", selector, 1)
    assert len(api._run_resources) == 6
    assert ("v1", "ConfigMap") in [
        (version, kind) for version, kind, _ in api._dynamic.resources.found
    ]
    for resource in api._run_resources:
        [call] = resource.delete_calls
        assert call["namespace"] == "runs"
        assert call["label_selector"] == (
            "andyur.run/generation=def,andyur.run/id=abc")
        assert call["body"] == {"propagationPolicy": "Foreground"}
        assert sum(call["_request_timeout"]) <= 1


def test_delete_timeout_is_one_total_deadline_including_delete_calls(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(kubernetes_api.time, "monotonic", lambda: now[0])

    class SlowResource(Resource):
        def delete(self, **kwargs):
            super().delete(**kwargs)
            now[0] += 0.4

    class SlowResources(Resources):
        def get(self, api_version, kind):
            resource = SlowResource()
            self.found.append((api_version, kind, resource))
            return resource

    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    api._dynamic = SimpleNamespace(resources=SlowResources())
    api._run_resources = tuple(
        api._dynamic.resources.get(api_version=version, kind=kind)
        for version, kind in kubernetes_api._KINDS)
    api._lease_resource = api._dynamic.resources.get(
        api_version="coordination.k8s.io/v1", kind="Lease")
    with pytest.raises(TimeoutError, match="within 1.0s"):
        api.delete_run_group("runs", {"andyur.run/id": "a"}, 1.0)
    calls = sum(len(resource.delete_calls)
                for _, _, resource in api._dynamic.resources.found)
    assert calls == 3, "the fourth delete must not start after the total deadline"


def test_delete_attempts_later_secret_and_lease_after_middle_failure():
    api = _api()
    failing = api._run_resources[1]

    def fail(**_kwargs):
        raise OSError("transient service delete failure")

    failing.delete = fail
    with pytest.raises(RuntimeError, match="1 delete error"):
        api.delete_run_group("runs", {"andyur.run/id": "a"}, 1.0)
    assert api._run_resources[4].delete_calls
    assert api._run_resources[4].delete_calls


def test_isolation_readiness_requires_fresh_namespace_bound_live_proof(monkeypatch):
    api = _api()
    metadata = SimpleNamespace(
        uid="cluster-ns-1",
        labels={"andyur.network-policy/verified": "true"},
        annotations={"andyur.network-policy/verified-at": "1000",
                     "andyur.network-policy/namespace-uid": "cluster-ns-1"},
    )
    api._core = SimpleNamespace(
        read_namespace=lambda *_args, **_kwargs: SimpleNamespace(metadata=metadata))
    monkeypatch.setattr(kubernetes_api.time, "time", lambda: 1500)
    api.assert_isolation_ready("runs")
    metadata.annotations["andyur.network-policy/verified-at"] = "899"
    with pytest.raises(RuntimeError, match="maximum age 600s"):
        api.assert_isolation_ready("runs")
    metadata.annotations["andyur.network-policy/verified-at"] = "1500"
    metadata.annotations["andyur.network-policy/namespace-uid"] = "other-cluster"
    with pytest.raises(RuntimeError, match="namespace-bound"):
        api.assert_isolation_ready("runs")


@pytest.mark.parametrize("key,value", [
    ("app", "x,y"), ("app=bad", "x"), ("app", "!x"),
])
def test_selector_injection_is_refused(key, value):
    with pytest.raises(ValueError, match="unsafe"):
        _selector({key: value})

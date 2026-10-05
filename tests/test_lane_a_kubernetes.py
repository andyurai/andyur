"""The adapter between Andyur's rollback logic and a real Kubernetes API.

`andyur.rollback` is pure logic over the API's JSON shape and is tested with no
cluster; the live gate proves the whole path against real k3s. This file covers
the layer between them -- the three decisions the adapter makes that neither of
those two would catch, because a fixture is always nicer than a cluster and a
live gate cannot easily arrange a hostile neighbour.
"""

import json

import pytest

from andyur.server import kubernetes_deployments as kd


def _rs(uid="dep-uid", kind="Deployment", name="rs-1"):
    return {"metadata": {"name": name, "ownerReferences": [
        {"kind": kind, "name": "checkout", "uid": uid, "controller": True}]}}


DEPLOYMENT = {"metadata": {"name": "checkout", "uid": "dep-uid",
                           "resourceVersion": "42", "generation": 2},
              "spec": {"selector": {"matchLabels": {"app": "checkout"}}}}


class FakeApps:
    """The two AppsV1Api calls the adapter makes, returning raw JSON bodies as
    `_preload_content=False` does."""

    def __init__(self, replicasets):
        self._replicasets = replicasets
        self.patches = []
        self.selectors = []
        self.patch_kwargs = []
        self.reads = 0

    class _Raw:
        def __init__(self, payload):
            self.data = json.dumps(payload).encode()

    def read_namespaced_deployment(self, name, namespace, **kw):
        self.reads += 1
        return self._Raw(DEPLOYMENT)

    def list_namespaced_replica_set(self, namespace, label_selector=None, **kw):
        self.selectors.append(label_selector)
        return self._Raw({"items": self._replicasets})

    def patch_namespaced_deployment(self, name, namespace, body, **kw):
        self.patches.append((namespace, name, body))
        self.patch_kwargs.append(kw)
        return self._Raw(DEPLOYMENT)


def _api(replicasets):
    api = kd.DeploymentsApi.__new__(kd.DeploymentsApi)   # no cluster, no kubeconfig
    api._apps = FakeApps(replicasets)
    return api


def test_a_neighbours_replicaset_is_never_part_of_this_deployments_history():
    """THE ONE THAT MATTERS. Two deployments in a namespace can select
    overlapping labels, so a selector query alone returns a neighbour's
    ReplicaSets -- and rolling one deployment back onto another's pod template
    is a WRONG CONSEQUENTIAL ACTION, which this lane treats as a trigger rather
    than a bug. Ownership is by UID."""
    api = _api([_rs(), _rs(uid="other-deployment-uid", name="rs-neighbour"),
                {"metadata": {"name": "rs-orphan"}}])
    owned = api.list_replicasets("prod", "checkout", owner=DEPLOYMENT)
    assert [rs["metadata"]["name"] for rs in owned] == ["rs-1"]


def test_ownership_is_by_uid_and_kind_not_by_name():
    """A name is reusable and a UID is not: delete a Deployment and recreate it
    with the same name and the old ReplicaSets still carry the old UID."""
    assert kd.owned_by(_rs(), DEPLOYMENT)
    assert not kd.owned_by(_rs(uid="recreated-with-the-same-name"), DEPLOYMENT)
    assert not kd.owned_by(_rs(kind="ReplicaSet"), DEPLOYMENT)
    assert not kd.owned_by(_rs(), {"metadata": {"name": "checkout"}})   # no uid
    noncontroller = _rs()
    noncontroller["metadata"]["ownerReferences"][0]["controller"] = False
    assert not kd.owned_by(noncontroller, DEPLOYMENT)


def test_the_query_is_narrowed_by_the_deployments_own_selector():
    api = _api([_rs()])
    api.list_replicasets("prod", "checkout", owner=DEPLOYMENT)
    assert api._apps.selectors == ["app=checkout"]
    assert api._apps.reads == 0, "history must not reread a different incarnation"


def test_the_pod_template_hash_is_stripped_before_it_is_written_back():
    """`pod-template-hash` identifies a ReplicaSet, not a desired pod template.
    Writing it back would pin the deployment's template to a hash describing the
    OLD ReplicaSet; `kubectl rollout undo` strips it for the same reason."""
    template = {"metadata": {"labels": {"app": "checkout",
                                        kd.POD_TEMPLATE_HASH: "6f9c"}},
                "spec": {"containers": [{"name": "app", "image": "checkout:1.0"}]}}
    stripped = kd.strip_template_hash(template)
    assert stripped["metadata"]["labels"] == {"app": "checkout"}
    assert stripped["spec"] == template["spec"]
    # The caller's object is not mutated: the same template is also the evidence
    # a test or a gate asserts against afterwards.
    assert kd.POD_TEMPLATE_HASH in template["metadata"]["labels"]


def test_a_template_with_no_labels_is_left_alone_rather_than_grown():
    assert kd.strip_template_hash({"spec": {}}) == {"spec": {}}


def test_the_patch_carries_one_object_and_one_field():
    """Not a general Kubernetes client: a general client on the control plane's
    credential is the generic executor this MVP refuses at the tool layer,
    reintroduced one level down."""
    api = _api([_rs()])
    api.patch_deployment_template(
        "prod", "checkout",
        {"metadata": {"labels": {kd.POD_TEMPLATE_HASH: "6f9c"}}, "spec": {"x": 1}},
        expected=DEPLOYMENT)
    (namespace, name, body), = api._apps.patches
    assert (namespace, name) == ("prod", "checkout")
    assert body[:2] == [
        {"op": "test", "path": "/metadata/uid", "value": "dep-uid"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "42"}]
    assert body[2] == {"op": "replace", "path": "/spec/template",
                       "value": {"metadata": {"labels": {}}, "spec": {"x": 1}}}
    assert api._apps.patch_kwargs[0]["_content_type"] == "application/json-patch+json"


@pytest.mark.parametrize("missing", ["uid", "resourceVersion"])
def test_missing_snapshot_precondition_refuses_without_writing(missing):
    expected = json.loads(json.dumps(DEPLOYMENT))
    del expected["metadata"][missing]
    api = _api([])
    with pytest.raises(ValueError, match="rollback_snapshot_missing_identity"):
        api.patch_deployment_template("prod", "checkout", {"spec": {}},
                                      expected=expected)
    assert api._apps.patches == []


def test_the_adapter_exposes_the_three_calls_a_rollback_needs_and_no_fourth():
    """A guard against the drift this file exists to prevent: every public
    method here is one `andyur.rollback` calls, so a fourth verb cannot be added
    to the control plane's cluster credential without a test saying so."""
    public = {name for name in vars(kd.DeploymentsApi) if not name.startswith("_")}
    assert public == {"read_deployment", "list_replicasets",
                      "patch_deployment_template"}


# --- the live gate's evidence is bound to the source it exercised ----------

def test_the_live_consequential_action_result_is_current_and_complete():
    """The artifact `verify-consequential-action.py` writes says the three
    outcomes held against a real cluster. That claim is about SOURCE, so it goes
    stale the moment any of the source it exercised changes -- and then the gate
    must be re-run before the claim is made again.

    Also asserts the SUBSTANCE, not just the hashes: an artifact whose `ok` is
    true but whose denied leg never checked the cluster would be a green
    carrying no information.
    """
    import hashlib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    results = sorted(root.glob("infra/kubernetes/result-consequential-action-*.json"))
    assert results, "no live consequential-action evidence is shipped"
    result = json.loads(results[-1].read_text())

    assert result["ok"] is True and result["failures"] == []
    assert result["cluster_version"].startswith("v1.")
    # DENY: decided by name, and the cluster verified UNCHANGED afterwards --
    # the assertion a "denied" badge is worth nothing without.
    denied = result["denied"]
    assert denied["row"]["decision"] == "denied"
    assert denied["row"]["decision_reason"] == "no_write_authority"
    assert denied["row"]["result"] == "not_attempted"
    assert denied["cluster_unchanged"] is True and denied["before"] == denied["after"]
    # ALLOW: the cluster moved, and the recorded detail names the revision the
    # API server reported rather than one we chose.
    allowed = result["allowed"]
    assert allowed["row"]["result"] == "succeeded"
    assert allowed["before"]["revision"] != allowed["after"]["revision"]
    assert allowed["after"]["revision"] in allowed["row"]["result_detail"]
    assert allowed["after"]["image"] == result["images"]["good"]
    # APPROVAL: held with the cluster untouched, then moved only after a human
    # consented, with the approver's provenance recorded beside their name.
    approval = result["approval_required"]
    assert approval["row"]["decision"] == "approval_required"
    assert approval["cluster_unchanged_while_waiting"] is True
    assert approval["approved"]["approved_by_asserted_by"] == "operator_api"
    assert approval["approved"]["result"] == "succeeded"
    assert approval["before"]["revision"] != approval["after"]["revision"]
    # The decisions are in the trace, by name, each on its own span.
    assert sorted(result["otel"]["decisions_on_spans"]) == [
        "allowed", "approval_required", "denied"]
    assert {"action.decide", "action.approve", "action.perform", "kubernetes.cleanup"} <= set(
        result["otel"]["span_names"])
    assert result["otel"]["rollback_reasons"] == [
        "rollback_applied", "rollback_target_changed"]
    assert result["owned_cleanup_complete"] is True
    assert all(result["atomic_preconditions"][field]["status"] in (409, 422)
               and result["atomic_preconditions"][field]["unchanged"] is True
               for field in ("uid", "resourceVersion"))
    assert result["cancelled_approval"]["cluster_unchanged"] is True
    assert result["cancelled_approval"]["row"]["decision_reason"] == "run_inactive"
    assert result["concurrent_release"]["row"]["result"] == "failed"
    assert allowed["after"]["template"] == approval["after"]["template"]

    expected = {
        "andyur/actions.py",
        "andyur/rollback.py",
        "andyur/server/actionrequests.py",
        "andyur/server/kubernetes_deployments.py",
        "andyur/server/runtoken.py",
        "andyur/server/pdp.py",
        "andyur/db.py",
        "andyur/observability.py",
        "infra/kubernetes/action_gate_resources.py",
        "infra/kubernetes/verify-consequential-action.py",
    }
    assert set(result["source_sha256"]) == expected
    assert result["source_sha256"] == {
        path: hashlib.sha256((root / path).read_bytes()).hexdigest()
        for path in expected}

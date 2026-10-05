"""Andyur's own Kubernetes credential, used for exactly one remediation.

THE SEPARATION THIS FILE EXISTS TO KEEP. The agent never holds a Kubernetes
credential and has no route to the API server -- its NetworkPolicy grants one
egress peer, which is the model/tool front, not the cluster. It REQUESTS a
rollback; the control plane, holding its own ServiceAccount, decides and then
acts. That is the MVP's whole differentiated claim, and it is a property of
WHERE this code runs, not of anything the agent is asked not to do.

The credential is narrowed by RBAC: see
`infra/kubernetes/rbac-consequential-action.yaml`, which grants get/patch on
deployments and get/list on replicasets, in one namespace, and nothing else --
so ordinary API calls cannot delete a namespace or read a Secret. The control
plane remains TRUSTED: permission to patch a pod template can indirectly expose
Secrets or ServiceAccounts. RBAC alone does not contain a compromised server;
that stronger boundary requires independent admission restrictions.

Plain dicts, not client model objects, because `andyur.rollback` is pure logic
over the API's own JSON shape and is unit-tested with no cluster. `_preload_content=False`
is what keeps the two the same shape: the adapter returns exactly what the API
server sent, so a fixture cannot drift from the wire by being nicer than it.
"""

from __future__ import annotations

import json
import os

# The pod-template-hash label is the deployment controller's own bookkeeping: it
# identifies a ReplicaSet, not a desired pod template. `kubectl rollout undo`
# strips it when it restores a template, and a rollback that wrote it back would
# pin the deployment's template to a hash that describes the OLD ReplicaSet.
POD_TEMPLATE_HASH = "pod-template-hash"

# Bounded like every other outbound call on a request path (connect, read).
TIMEOUT = (3, 10)


def strip_template_hash(template: dict) -> dict:
    """A pod template as a DESIRED state rather than as a record of a past one."""
    template = json.loads(json.dumps(template))         # never mutate the input
    labels = (template.get("metadata") or {}).get("labels")
    if isinstance(labels, dict):
        labels.pop(POD_TEMPLATE_HASH, None)
    metadata = template.get("metadata")
    if isinstance(metadata, dict):
        # ReplicaSet history may serialize this absent field as null. It is
        # not part of the desired PodTemplateSpec; preserve all other fields.
        if metadata.get("creationTimestamp") is None:
            metadata.pop("creationTimestamp", None)
        if not metadata:
            template.pop("metadata")
    return template


def owned_by(replicaset: dict, deployment: dict) -> bool:
    """Is this ReplicaSet this Deployment's own history?

    By owner UID, never by label selector alone. Two deployments in a namespace
    can select overlapping labels, and rolling one back onto another's template
    is a wrong consequential action -- the failure class this lane treats as a
    trigger rather than a bug.
    """
    uid = (deployment.get("metadata") or {}).get("uid")
    if not uid:
        return False
    owners = (replicaset.get("metadata") or {}).get("ownerReferences") or []
    return any(owner.get("uid") == uid and owner.get("kind") == "Deployment"
               and owner.get("controller") is True
               for owner in owners)


class DeploymentsApi:
    """The three calls one rollback needs, and no fourth.

    Deliberately not a general Kubernetes client. A general client on the
    control plane's credential is the generic executor this MVP refuses at the
    tool layer, reintroduced one level down.
    """

    def __init__(self) -> None:
        from kubernetes import client, config

        kubeconfig = os.environ.get("ANDYUR_KUBECONFIG")
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig)
        else:
            # Production defaults to the Pod's ServiceAccount identity. An
            # operator must opt into a host kubeconfig explicitly.
            config.load_incluster_config()
        self._apps = client.AppsV1Api(client.ApiClient())

    @staticmethod
    def _json(response) -> dict:
        return json.loads(response.data)

    def read_deployment(self, namespace: str, deployment: str) -> dict:
        return self._json(self._apps.read_namespaced_deployment(
            deployment, namespace, _preload_content=False,
            _request_timeout=TIMEOUT))

    def list_replicasets(self, namespace: str, deployment: str, *, owner: dict) -> list:
        """This deployment's own ReplicaSets: its selector, then its UID.

        The selector narrows the query at the API server; the ownership check is
        what makes the answer correct. A selector alone would happily return a
        neighbour's ReplicaSets.
        """
        # Use the SAME snapshot the rollback will conditionally patch. Reading
        # again could silently switch to a replacement object's history.
        match = ((owner.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
        selector = ",".join(f"{key}={value}" for key, value in sorted(match.items()))
        listed = self._json(self._apps.list_namespaced_replica_set(
            namespace, label_selector=selector, _preload_content=False,
            _request_timeout=TIMEOUT))
        return [rs for rs in listed.get("items", []) if owned_by(rs, owner)]

    def patch_deployment_template(self, namespace: str, deployment: str,
                                  template: dict, *, expected: dict) -> dict:
        """Atomically restore exactly the template on the snapshot we read.

        Kubernetes evaluates JSON Patch tests and replacement in one operation.
        A conflict refuses without retry: re-reading would change the action
        being authorized. Strategic merge would retain newly added containers,
        env vars and serviceAccountName from the faulty release.
        """
        metadata = expected.get("metadata") or {}
        uid, version = metadata.get("uid"), metadata.get("resourceVersion")
        if not isinstance(uid, str) or not uid or not isinstance(version, str) or not version:
            raise ValueError("rollback_snapshot_missing_identity")
        response = self._apps.patch_namespaced_deployment(
            deployment, namespace,
            [{"op": "test", "path": "/metadata/uid", "value": uid},
             {"op": "test", "path": "/metadata/resourceVersion", "value": version},
             {"op": "replace", "path": "/spec/template",
              "value": strip_template_hash(template)}],
            _content_type="application/json-patch+json",
            _preload_content=False, _request_timeout=TIMEOUT,
            field_manager="andyur-server",
        )
        return self._json(response)

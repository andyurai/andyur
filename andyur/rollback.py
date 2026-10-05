"""Roll a Kubernetes Deployment back to its previous revision, and PROVE it did.

Lane A's execution half. The decision (`andyur.actions`) says whether this may
run; this performs it and then establishes whether the cluster actually changed.

TWO PROPERTIES THIS MODULE EXISTS FOR, and the second is the one that is easy to
get wrong:

1. ANDYUR HOLDS THE CREDENTIAL. This runs in the platform, never in the agent's
   Pod, and the agent has no route to the API server -- its NetworkPolicy grants
   one egress peer. The agent asks; this acts.
2. `succeeded` IS AN OBSERVATION, NOT AN ACKNOWLEDGEMENT. A patch returning 200
   means the API accepted a write, not that the workload rolled back. So the
   original UID, restored template and controller-observed generation are
   checked with the revision. A result derived from our own
   request would be a green carrying no information -- the failure family this
   codebase has found three times this week.

The mechanic is `kubectl rollout undo`'s: a Deployment's history lives in the
ReplicaSets it owns, each carrying its revision in an annotation, so rolling
back means finding the previous one and restoring its pod template.
"""

from __future__ import annotations

import dataclasses
import time

from .server.kubernetes_deployments import strip_template_hash

# How long the read-back waits for the cluster to show the rollback.
#
# THE PATCH IS SYNCHRONOUS AND THE CONSEQUENCE IS NOT. `kubectl` returns as soon
# as the API server accepts the new pod template; the Deployment controller then
# creates or re-scales a ReplicaSet and writes the new revision annotation. A
# read taken immediately after the write therefore sees the OLD revision, and
# reporting that as `failed` is as wrong as reporting the accepted write as
# `succeeded` -- both describe our own request rather than the cluster.
#
# Found by the live gate, not reasoned about: two identical rollbacks, one read
# back fast enough and one not, so the same action reported `succeeded` and
# `failed` on consecutive runs (infra/kubernetes/verify-consequential-action.py).
# The fix is to keep observing, bounded, and to say how long we observed for
# when nothing happened.
OBSERVE_SECONDS = 60.0
_POLL_SECONDS = 0.5

REVISION = "deployment.kubernetes.io/revision"
REASONS = frozenset({"rollback_applied", "deployment_replaced",
                     "rollback_target_changed", "controller_not_observed",
                     "no_previous_revision", "cluster_error"})


@dataclasses.dataclass(frozen=True)
class RollbackOutcome:
    """What actually happened, in terms the console can render without inferring.

    `observed_revision` is the value read back FROM THE CLUSTER after the write.
    It is the evidence for `changed`, and it is what makes the console's
    "rollback succeeded" a claim about Kubernetes rather than about us.
    """

    changed: bool
    from_revision: str | None
    observed_revision: str | None
    detail: str
    reason: str


class NoPreviousRevision(Exception):
    """There is nothing to roll back to.

    A distinct failure, not a generic error: a deployment on its first revision
    is a legitimate state, and reporting it as a failed rollback would tell an
    operator the cluster refused when in fact there was nowhere to go.
    """


def _revision_of(obj) -> str | None:
    annotations = ((obj or {}).get("metadata") or {}).get("annotations") or {}
    return annotations.get(REVISION)


def previous_replicaset(deployment: dict, replicasets: list) -> dict:
    """The ReplicaSet holding the revision immediately before the current one.

    Sorted NUMERICALLY, not lexically. Revisions are stringified integers, so a
    lexical sort puts "9" after "10" and would roll a deployment FORWARD on its
    tenth release -- a wrong consequential action, which is one of the nine
    triggers rather than a cosmetic bug.
    """
    current = _revision_of(deployment)
    if not isinstance(current, str) or not current.isdecimal() or int(current) < 1:
        raise NoPreviousRevision("current_revision_unknown")
    owned = []
    for rs in replicasets:
        rev = _revision_of(rs)
        if rev is None:
            continue
        try:
            owned.append((int(rev), rs))
        except ValueError:
            # A revision that is not an integer is not one this code wrote.
            # Skipping it is safer than ordering around it.
            continue
    if not owned:
        raise NoPreviousRevision("the deployment owns no revisioned ReplicaSet")
    owned.sort(key=lambda pair: pair[0])
    current_n = int(current)
    earlier = [pair for pair in owned if pair[0] < current_n]
    if not earlier:
        raise NoPreviousRevision(
            f"deployment is at revision {current}; there is no earlier revision")
    return earlier[-1][1]


def rollback(client, namespace: str, deployment: str, *,
             observe_seconds: float = OBSERVE_SECONDS,
             sleep=time.sleep, clock=time.monotonic) -> RollbackOutcome:
    """Perform the rollback and report what the CLUSTER says happened.

    `client` is the platform's Kubernetes adapter, injected so this is testable
    without a cluster -- the live gate proves it against real k3s, and these
    two forms of evidence answer different questions.
    """
    before = client.read_deployment(namespace, deployment)
    from_revision = _revision_of(before)
    uid = (before.get("metadata") or {}).get("uid")
    target = previous_replicaset(before, client.list_replicasets(
        namespace, deployment, owner=before))
    template = (target.get("spec") or {}).get("template")
    if not template:
        raise NoPreviousRevision("the previous ReplicaSet carries no pod template")

    desired = strip_template_hash(template)
    patched = client.patch_deployment_template(namespace, deployment, desired,
                                               expected=before)
    generation = (patched.get("metadata") or {}).get("generation")
    if (not isinstance(uid, str) or not uid
            or (patched.get("metadata") or {}).get("uid") != uid
            or type(generation) is not int or generation < 1):
        raise ValueError("rollback_patch_identity_unverifiable")

    # THE READ-BACK. Everything above is a request; this is the evidence.
    #
    # Bounded and repeated, because the consequence is asynchronous (see
    # OBSERVE_SECONDS). One read is enough when the controller is quick and is a
    # coin toss when it is not, and a result that depends on how busy the
    # cluster was is not an observation of anything.
    deadline = clock() + observe_seconds
    while True:
        after = client.read_deployment(namespace, deployment)
        observed = _revision_of(after)
        metadata = after.get("metadata") or {}
        actual = strip_template_hash((after.get("spec") or {}).get("template") or {})
        acknowledged = (after.get("status") or {}).get("observedGeneration")
        changed = False
        if metadata.get("uid") != uid:
            reason = "deployment_replaced"
            break
        if actual != desired or metadata.get("generation") != generation:
            reason = "rollback_target_changed"
            break
        changed = (isinstance(observed, str) and observed.isdecimal()
                   and observed != from_revision and type(acknowledged) is int
                   and acknowledged >= generation)
        reason = "rollback_applied" if changed else "controller_not_observed"
        if changed or clock() >= deadline:
            break
        sleep(_POLL_SECONDS)
    if changed:
        detail = (f"revision {from_revision} -> {observed}; rollback_applied: "
                  "intended template observed; application health not assessed")
    else:
        # Deliberately NOT an exception. The write was accepted and the cluster
        # did not move within the time we watched; that is a real outcome an
        # operator must see, and raising here would render it as a failure to
        # dispatch. The duration is named, because "it did not happen" and "it
        # had not happened yet when we stopped looking" are different claims.
        detail = (f"{reason}: after {observe_seconds:g}s observed revision "
                  f"{observed}; the intended deployment did not roll back")
    return RollbackOutcome(changed=changed, from_revision=from_revision,
                           observed_revision=observed, detail=detail, reason=reason)

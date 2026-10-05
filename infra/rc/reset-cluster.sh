#!/usr/bin/env bash
# TEAR THE DEPLOYMENT DOWN, so the next RC pass starts where a stranger would.
#
# The operator's exit criterion for this release is two full RC passes on one
# frozen commit "with the environment torn down and rebuilt between them". The
# reason is specific rather than ceremonial: every false green this repository
# has found was a gate reading state something EARLIER had left -- a stamp, a
# Secret, an agent row, a namespace, a running pod carrying an image nobody
# rebuilt. A second pass against a cluster the first pass warmed up proves the
# gates are repeatable and proves nothing about the artifact.
#
#   ./infra/rc/reset-cluster.sh          delete everything Andyur put here
#   ./infra/rc/reset-cluster.sh --check  say what is still standing, change nothing
#
# WHAT IT DOES NOT DELETE, on purpose:
#   SPIRE            a prerequisite, not part of the deployment. PREREQUISITES.md
#                    says the deployer installs it; a gate that reinstalls it is
#                    testing a cluster nobody has.
#   the registry     the images the release pushed are the artifact under test.
#   the two Secrets  they are the deployer's, and PREREQUISITES.md says to make
#                    them once. They are recreated below ONLY if absent, so a
#                    torn-down cluster can be brought back without hand steps --
#                    and never overwritten, because rotating a run-token secret
#                    under a running deployment invalidates every live token.
set -uo pipefail
SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
RUN_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"
# The consequential action's target namespace, created by that gate.
TARGET_NS="${ANDYUR_ACTION_TARGET_NAMESPACE:-prod}"
# SPIRE is a prerequisite this script must leave working; named so the check
# below can prove that rather than assume it.
SPIRE_NAMESPACE="${ANDYUR_PARTNER_SPIRE_NAMESPACE:-spire-system}"
SPIRE_RELEASE="${ANDYUR_PARTNER_SPIRE_RELEASE:-andyur-spire}"
SPIRE_SERVER_SA="${ANDYUR_SPIRE_SERVER_SA:-$SPIRE_RELEASE-server}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok(){  printf '  \033[32mok\033[0m    %s\n' "$*"; }
note(){ printf '        %s\n' "$*"; }

if [ "${1:-}" = "--check" ]; then
  say "what is still standing"
  for ns in "$SYSTEM_NS" "$RUN_NS" "$TARGET_NS"; do
    if kubectl get namespace "$ns" >/dev/null 2>&1; then
      printf '  \033[33mPRESENT\033[0m  namespace %s (%s objects)\n' "$ns" \
        "$(kubectl get all -n "$ns" -o name 2>/dev/null | wc -l | tr -d ' ')"
    else
      ok "namespace $ns is gone"
    fi
  done
  kubectl get clusterspiffeids.spire.spiffe.io -o name 2>/dev/null | grep -c andyur \
    | sed 's/^/  ClusterSPIFFEIDs still declared: /'
  exit 0
fi

say "tearing down"
# THE CLUSTER-SCOPED OBJECTS, BY NAME, FROM THE MANIFESTS THAT DEFINE THEM.
#
# A namespace delete does not touch them, and a ClusterSPIFFEID left behind
# keeps declaring identities for Pods that no longer exist -- which the next
# deploy re-applies over, hiding whether the apply worked. So they have to go.
#
# THEY ARE NOT SELECTED BY SUBSTRING. This loop was
#
#     kubectl get clusterroles -o name | grep -E 'andyur'
#
# and SPIRE is installed here as the Helm release `andyur-spire`. So a teardown
# whose header promises "SPIRE: a prerequisite, not part of the deployment"
# deleted SPIRE's own ClusterRoles. The controller-manager lost `list pods` at
# cluster scope, created no registration entries, and TWO HOURS LATER the
# symptom was `JwtSourceError: Timeout waiting for the first update` in a
# worker that could not get an SVID -- a message about the workload API, in a
# component that was not the one broken.
#
# A destructive operation must not match by prefix. The names come from the
# manifests this script is the counterpart to, so what is deleted is exactly
# what was applied, and anything sharing a prefix with it survives.
manifest_names() {   # kind  file...
  "${ANDYUR_PY:-python3}" - "$1" "${@:2}" <<'NAMES'
import sys, yaml
kind = sys.argv[1]
for path in sys.argv[2:]:
    try:
        documents = list(yaml.safe_load_all(open(path)))
    except OSError:
        continue
    for document in documents:
        if document and document.get("kind") == kind:
            print(document["metadata"]["name"])
NAMES
}
# temporal.yaml is here because it declares two ClusterSPIFFEIDs, which are
# cluster-scoped and survive the namespace deletions below. Read by NAME from
# the manifest like the rest -- never by prefix: a prefix match on `andyur` once
# deleted SPIRE's own RBAC, because its Helm release is `andyur-spire`.
HERE_MANIFESTS="$ROOT/infra/kubernetes/control-plane.yaml $ROOT/infra/kubernetes/rbac-consequential-action.yaml $ROOT/infra/kubernetes/run-isolation.yaml $ROOT/infra/kubernetes/temporal.yaml"
for kind in ClusterRoleBinding ClusterRole ClusterSPIFFEID; do
  lower="$(printf '%s' "$kind" | tr 'A-Z' 'a-z')"
  for name in $(manifest_names "$kind" $HERE_MANIFESTS); do
    kubectl delete "$lower" "$name" --ignore-not-found >/dev/null 2>&1
  done
done
# The engine-authorizer gate's probe identity, also by name: it is created and
# deleted by that gate, and only survives if the gate was killed outright.
kubectl delete clusterspiffeid andyur-engine-authz-probe --ignore-not-found >/dev/null 2>&1
ok "cluster-scoped objects this deployment defines (by name, never by prefix)"
# Proof, not assumption: SPIRE is a PREREQUISITE and must still be able to
# issue identities after this script has run. Checked here rather than
# discovered later as a worker that cannot start.
if kubectl get crd clusterspiffeids.spire.spiffe.io >/dev/null 2>&1; then
  if kubectl auth can-i list pods \
       --as="system:serviceaccount:$SPIRE_NAMESPACE:$SPIRE_SERVER_SA" \
       >/dev/null 2>&1; then
    ok "SPIRE still holds its own cluster permissions"
  else
    printf '  \033[31mNO\033[0m    SPIRE lost its cluster permissions in this teardown\n'
    note "restore them with:  helm get manifest $SPIRE_RELEASE -n $SPIRE_NAMESPACE | kubectl apply -f -"
    note "nothing will get an SVID until you do, and the symptom will be a worker"
    note "reporting 'Timeout waiting for the first update' from the workload API"
  fi
fi
# THE SECRETS ARE SAVED BEFORE THE NAMESPACE GOES, and restored after. They are
# the deployer's, made once, and the alternative -- regenerating them -- rotates
# the run-token secret between two passes that are supposed to be the same
# deployment twice.
saved="$(mktemp -d "${TMPDIR:-/tmp}/andyur-reset-XXXXXX")"
for secret in andyur-secrets andyur-idp-secrets andyur-temporal-secrets; do
  kubectl get secret "$secret" -n "$SYSTEM_NS" -o yaml 2>/dev/null \
    | grep -v 'resourceVersion:\|uid:\|creationTimestamp:\|namespace:' \
    > "$saved/$secret.yaml" || true
  [ -s "$saved/$secret.yaml" ] && ok "saved $secret"
done
for ns in "$TARGET_NS" "$RUN_NS" "$SYSTEM_NS"; do
  kubectl delete namespace "$ns" --ignore-not-found --wait=true --timeout=300s >/dev/null 2>&1
  ok "namespace $ns deleted"
done

say "putting back only what a deployer would already have"
kubectl create namespace "$SYSTEM_NS" >/dev/null 2>&1 || true
for secret in andyur-secrets andyur-idp-secrets andyur-temporal-secrets; do
  if [ -s "$saved/$secret.yaml" ]; then
    kubectl apply -n "$SYSTEM_NS" -f "$saved/$secret.yaml" >/dev/null 2>&1 \
      && ok "restored $secret"
  fi
done
# EACH ONE CHECKED ON ITS OWN. This used to generate both only when fewer than
# two had been restored -- which, with a third secret, would have restored the
# first two and silently never created the engine's, leaving its database with
# no password and the engine unable to start. Absent means a first run or a
# teardown that lost it; generated here because PREREQUISITES.md's
# `kubectl create secret` lines are the deployer's, and this script stands in
# for a deployer who already ran them.
exists() { kubectl get secret "$1" -n "$SYSTEM_NS" >/dev/null 2>&1; }
exists andyur-secrets || { kubectl -n "$SYSTEM_NS" create secret generic andyur-secrets \
    --from-literal=run-token-secret="$(openssl rand -hex 32)" >/dev/null 2>&1 \
    && note "generated andyur-secrets (there was none to restore)"; }
exists andyur-idp-secrets || { kubectl -n "$SYSTEM_NS" create secret generic andyur-idp-secrets \
    --from-literal=admin-password="$(openssl rand -hex 24)" \
    --from-literal=db-password="$(openssl rand -hex 24)" >/dev/null 2>&1 \
    && note "generated andyur-idp-secrets (there was none to restore)"; }
exists andyur-temporal-secrets || { kubectl -n "$SYSTEM_NS" create secret generic andyur-temporal-secrets \
    --from-literal=db-password="$(openssl rand -hex 24)" >/dev/null 2>&1 \
    && note "generated andyur-temporal-secrets (there was none to restore)"; }
rm -rf "$saved"

say "torn down"
note "the next RC pass deploys from the bundle, as a stranger would:"
note "  bash infra/rc/verify-partner-deploy.sh <release-out>/bundle"
note "SPIRE, the local registry and the images the release pushed are untouched."

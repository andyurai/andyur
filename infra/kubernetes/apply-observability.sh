#!/usr/bin/env bash
# Apply the telemetry path (infra/kubernetes/observability.yaml) to andyur-system.
#
# The Collector's and Jaeger's configuration each have ONE source under
# infra/observability/; this script turns them into the ConfigMaps the
# Deployments mount and restarts the two Deployments so a changed file is
# what runs. Validate the files first: infra/observability/verify-config.sh
# runs both in the same digest-pinned images the cluster pulls.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
# control-plane.yaml creates the namespace; this path lives inside it.
kubectl get namespace "$NS" >/dev/null 2>&1 \
  || { echo "namespace $NS absent: apply infra/kubernetes/control-plane.yaml first" >&2; exit 1; }

configmap() {   # name file -> apply a ConfigMap whose single key is config.yaml
  kubectl create configmap "$1" -n "$NS" --from-file="config.yaml=$2" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  echo "configmap/$1 <- ${2#"$ROOT/"}"
}
configmap otel-collector-config "$ROOT/infra/observability/otel-collector.yaml"
configmap andyur-jaeger-config "$ROOT/infra/observability/jaeger.yaml"
kubectl apply -f "$HERE/observability.yaml"
kubectl -n "$NS" rollout restart deployment/otel-collector deployment/andyur-jaeger >/dev/null
kubectl -n "$NS" rollout status deployment/andyur-jaeger --timeout=180s
kubectl -n "$NS" rollout status deployment/otel-collector --timeout=180s
echo "telemetry path ready: ANDYUR_OTEL_ENDPOINT=http://otel-collector.$NS.svc:4318"
echo "trace UI: kubectl -n $NS port-forward svc/andyur-jaeger 16686:16686  ->  http://localhost:16686"

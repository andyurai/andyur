#!/usr/bin/env bash
set -euo pipefail

SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
RUN_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"
AGENT="${ANDYUR_KUBERNETES_VERIFY_AGENT:-kubernetes-smoke}"
EXPECTED="${ANDYUR_KUBERNETES_VERIFY_EXPECTED:-ANDYUR KUBERNETES MODEL RUN PASSED}"
TIMEOUT="${ANDYUR_KUBERNETES_VERIFY_TIMEOUT:-600}"

fail() { echo "kubernetes verification FAILED: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "$1 is required"; }
need kubectl
need python3

operator() {
  kubectl exec -n "$SYSTEM_NS" deployment/andyur-operator -- \
    python -m andyur.cli "$@"
}

run_json() { operator api GET "/runs/$1"; }
json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]) or "")' "$1"
}
wait_run() {
  local run_id="$1" deadline=$((SECONDS + TIMEOUT)) body state
  while (( SECONDS < deadline )); do
    body="$(run_json "$run_id")" || true
    state="$(printf '%s' "$body" | json_field state 2>/dev/null || true)"
    case "$state" in done|failed|cancelled) printf '%s' "$body"; return 0;; esac
    sleep 2
  done
  fail "run $run_id did not finish within ${TIMEOUT}s"
}
wait_no_run_resources() {
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if ! kubectl get pods,services,secrets,networkpolicies,serviceaccounts,leases \
      -n "$RUN_NS" -l app.kubernetes.io/managed-by=andyur-worker \
      -o name | grep -q .; then
      return 0
    fi
    sleep 2
  done
  fail "per-run resources remained after cleanup"
}

context="$(kubectl config current-context)"
[[ "$context" == rancher-desktop ]] || fail \
  "current context is '$context', expected rancher-desktop (override by selecting it explicitly)"
kubectl wait --for=condition=Ready pod --all --field-selector=status.phase!=Succeeded,status.phase!=Failed -n "$SYSTEM_NS" --timeout=120s >/dev/null
kubectl wait --for=condition=Ready pod --all --field-selector=status.phase!=Succeeded,status.phase!=Failed -n spire-system --timeout=120s >/dev/null
network_gate="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify-network-policy.sh"
python3 "$(dirname "$network_gate")/bounded_exec.py" 180 bash "$network_gate"

for workload in statefulset/andyur-server statefulset/andyur-worker deployment/andyur-operator; do
  [[ "$(kubectl get -n "$SYSTEM_NS" "$workload" -o jsonpath='{.spec.replicas}')" == 1 ]] || \
    fail "$workload must have exactly one replica"
  image="$(kubectl get -n "$SYSTEM_NS" "$workload" -o jsonpath='{.spec.template.spec.containers[0].image}')"
  [[ "$image" == *@sha256:* && "$image" != registry.example/* ]] || \
    fail "$workload is not pinned to a rendered digest: $image"
  app="${workload#*/}"
  pod="$(kubectl get pod -n "$SYSTEM_NS" -l "app=$app" \
    -o jsonpath='{.items[0].metadata.name}')"
  [[ -n "$pod" ]] || fail "$workload has no running Pod"
  image_id="$(kubectl get pod -n "$SYSTEM_NS" "$pod" \
    -o jsonpath='{.status.containerStatuses[0].imageID}')"
  digest="${image##*@}"
  [[ "$image_id" == *@"$digest" ]] || \
    fail "$workload runtime imageID $image_id does not match declared $digest"
done
wait_no_run_resources

echo "[1/4] registry-backed model run"
trigger="$(operator trigger "$AGENT" --reason \
  "Your complete final summary must be exactly one line: $EXPECTED. /no_think" --no-wait)"
run_id="$(printf '%s' "$trigger" | awk '/^run / {print $2}')"
[[ -n "$run_id" ]] || fail "could not read the triggered run id: $trigger"
result="$(wait_run "$run_id")"
[[ "$(printf '%s' "$result" | json_field state)" == done ]] || fail "$result"
[[ "$(printf '%s' "$result" | json_field summary)" == "$EXPECTED" ]] || fail \
  "run $run_id returned the wrong summary: $result"
wait_no_run_resources

echo "[2/4] operator halt and exact-generation cleanup"
trigger="$(operator trigger "$AGENT" --reason 'automated halt gate' --no-wait)"
halt_run="$(printf '%s' "$trigger" | awk '/^run / {print $2}')"
deadline=$((SECONDS + 90))
workflow=""
while (( SECONDS < deadline )); do
  body="$(run_json "$halt_run")" || true
  workflow="$(printf '%s' "$body" | json_field workflow_id 2>/dev/null || true)"
  [[ "$(printf '%s' "$body" | json_field state 2>/dev/null || true)" == running && -n "$workflow" ]] && break
  sleep 2
done
[[ -n "$workflow" ]] || fail "halt run $halt_run never entered running"
operator halt "$workflow" >/dev/null
halted="$(wait_run "$halt_run")"
[[ "$(printf '%s' "$halted" | json_field error)" == "halted: destroyed by the operator kill switch" ]] || \
  fail "halt did not record the kill-switch reason: $halted"
wait_no_run_resources

echo "[3/4] server restart persistence"
old_uid="$(kubectl get pod -n "$SYSTEM_NS" andyur-server-0 -o jsonpath='{.metadata.uid}')"
kubectl delete pod -n "$SYSTEM_NS" andyur-server-0 --wait=true >/dev/null
kubectl rollout status -n "$SYSTEM_NS" statefulset/andyur-server --timeout=120s >/dev/null
new_uid="$(kubectl get pod -n "$SYSTEM_NS" andyur-server-0 -o jsonpath='{.metadata.uid}')"
[[ "$old_uid" != "$new_uid" ]] || fail "server Pod was not replaced"
deadline=$((SECONDS + 60))
while (( SECONDS < deadline )); do
  persisted="$(run_json "$run_id" 2>/dev/null || true)"
  [[ "$(printf '%s' "$persisted" | json_field summary 2>/dev/null || true)" == "$EXPECTED" ]] && break
  sleep 2
done
[[ "$(printf '%s' "$persisted" | json_field summary 2>/dev/null || true)" == "$EXPECTED" ]] || \
  fail "completed run did not survive server restart"

echo "[4/4] focused TTL, isolation, manifest and controller regressions"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ -x "$ROOT/.venv/bin/python" ]] || fail "run ./run.sh setup before this gate"
PYTHONPATH="$ROOT" "$ROOT/.venv/bin/python" -m pytest -q \
  "$ROOT/tests/test_agent_split.py" \
  "$ROOT/tests/test_kubernetes_controller.py" \
  "$ROOT/tests/test_kubernetes_manifests.py" \
  "$ROOT/tests/test_kubernetes_packaging.py"

echo "KUBERNETES MACOS VERIFICATION PASSED (model=$run_id halt=$halt_run)"

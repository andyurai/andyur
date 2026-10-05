#!/usr/bin/env bash
# Architecture B+ Gate C, live: a halted engine-dispatched run is destroyed with
# the ENGINE DOWN and its EXECUTION WORKER DEAD (ADR-014 D11).
#
# A real governed run is triggered and dispatched by the engine -- the OpenSRE
# demo by default, because it works for minutes (Goose finished between two
# polls of an earlier version of this gate, so it never had a running Pod to
# contain).
# Once its agent Pod is Running, the engine and the execution worker are both
# scaled to zero -- nothing that dispatched or is watching the run is left --
# and the workflow is halted through the operator API. The only thing still
# able to destroy the runtime is Andyur's own reconciler: the worker daemon,
# which reports the engine-launched run from the RUNTIME and destroys the exact
# generation the server condemns. Asserted on what exists afterwards:
#
#   runtime_destroyed   the run's Pods are gone
#   not_completed       the run did not finish `done` -- it was killed, not
#                       allowed to complete
#   engine_down         the engine and the execution worker really were at
#                       zero replicas while this happened
#
# Both are restored to one replica on exit, whatever happens.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
RUN_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"
AGENT="${ANDYUR_CONTAINMENT_AGENT:-opensre-sre}"
DEMO="${ANDYUR_CONTAINMENT_DEMO:-demos/opensre}"
INPUT_FILE="${ANDYUR_CONTAINMENT_INPUT:-alert.json}"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
. "$HERE/lib/gate.sh"

restore() {
  kubectl -n "$SYSTEM_NS" scale deployment/andyur-temporal --replicas=1 >/dev/null 2>&1 || true
  kubectl -n "$SYSTEM_NS" scale deployment/andyur-temporal-execution-worker --replicas=1 >/dev/null 2>&1 || true
}
trap restore EXIT

input="$(cat "$ROOT/$DEMO/$INPUT_FILE")"
trigger="$(operator api POST "/agents/$AGENT/trigger" --data "$(python3 -c 'import json,sys; print(json.dumps({"reason": "bplus containment gate", "input": json.loads(sys.argv[1])}))' "$input")")"
run_id="$(printf '%s' "$trigger" | json_field run_id)"
workflow_id="$(operator api GET "/runs/$run_id" | json_field workflow_id)"
dispatch="$(operator api GET "/runs/$run_id" | json_field dispatch)"
echo "run $run_id (workflow $workflow_id, dispatch=$dispatch)" >&2
# The run's Pods carry a DIGEST of its id as a label (kubernetes_manifests).
run_label="$(cd "$ROOT" && .venv/bin/python -c 'import sys; from andyur.daemon.kubernetes_manifests import _digest; print(_digest(sys.argv[1]))' "$run_id")"

# The agent Pod RUNNING: the run is executing untrusted code right now.
for _ in $(seq 1 300); do
  running="$(kubectl get pods -n "$RUN_NS" -l "app.kubernetes.io/component=agent,andyur.run/id=$run_label" \
    --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  [ "${running:-0}" -gt 0 ] && break
  sleep 2
done
[ "${running:-0}" -gt 0 ] || { echo "the run's agent Pod never ran" >&2; exit 1; }

# Everything that dispatched or is watching the run: gone.
kubectl -n "$SYSTEM_NS" scale deployment/andyur-temporal --replicas=0 >/dev/null
kubectl -n "$SYSTEM_NS" scale deployment/andyur-temporal-execution-worker --replicas=0 >/dev/null
kubectl -n "$SYSTEM_NS" wait --for=delete pod -l app=andyur-temporal --timeout=120s >/dev/null 2>&1 || true
kubectl -n "$SYSTEM_NS" wait --for=delete pod -l app=andyur-temporal-execution-worker --timeout=120s >/dev/null 2>&1 || true
engine_pods="$(kubectl get pods -n "$SYSTEM_NS" -l 'app in (andyur-temporal,andyur-temporal-execution-worker)' --no-headers 2>/dev/null | wc -l | tr -d ' ')"

# Halt. The engine cannot hear it; Andyur's governance write lands regardless.
operator api POST "/workflows/$workflow_id/halt" >/dev/null 2>&1 || true
halted_at=$SECONDS

gone=false
for _ in $(seq 1 60); do
  left="$(kubectl get pods -n "$RUN_NS" -l "andyur.run/id=$run_label" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  if [ "${left:-0}" -eq 0 ]; then gone=true; break; fi
  sleep 3
done
took=$((SECONDS - halted_at))
state="$(operator api GET "/runs/$run_id" | json_field state)"

VERDICT=PASS
[ "$dispatch" = engine ] || VERDICT=FAIL
[ "$engine_pods" = 0 ] || VERDICT=FAIL
[ "$gone" = true ] || VERDICT=FAIL
[ "$state" != done ] || VERDICT=FAIL

.venv/bin/python - "$VERDICT" "$run_id" "$dispatch" "$engine_pods" "$gone" "$state" "$took" "$STARTED" <<'PY'
import hashlib, json, platform, subprocess, sys
from datetime import datetime, timezone
verdict, run_id, dispatch, engine_pods, gone, state, took, started = sys.argv[1:9]
sources = ("infra/kubernetes/verify-bplus-containment.sh",
           "andyur/daemon/orchestrator.py", "andyur/daemon/daemon.py",
           "andyur/daemon/kubernetes_controller.py", "andyur/server/coordinator.py",
           "andyur/daemon/engine_executor.py")
server = subprocess.run(["kubectl", "config", "view", "--minify", "-o",
                         "jsonpath={.clusters[0].cluster.server}"],
                        capture_output=True, text=True).stdout
print(json.dumps({
    "gate": "bplus-containment-engine-down", "verdict": verdict, "run_id": run_id,
    "dispatch": dispatch, "engine_down": engine_pods == "0",
    "runtime_destroyed": gone == "true", "run_state_after": state,
    "not_completed": state != "done", "seconds_halt_to_destroyed": int(took),
    "platform": platform.platform(), "started_at": started,
    "finished_at": datetime.now(timezone.utc).isoformat(),
    "api_server_sha256": hashlib.sha256(server.encode()).hexdigest(),
    "source_sha256": {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in sources},
}, indent=2, sort_keys=True))
PY
[ "$VERDICT" = PASS ]

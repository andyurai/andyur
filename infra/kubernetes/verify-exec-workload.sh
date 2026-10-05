#!/usr/bin/env bash
# Live proof that an UNMODIFIED upstream image runs to `done` on the exec/v1
# path through the in-cluster control plane: governed registry, the worker
# under its Role + SPIRE, the serve-only sidecar fronting the platform's model
# leg, the daemon reading the container exit and capturing the report -- and,
# with telemetry ON, the run's trace read back by id with every expected
# decision present. ONE script for every stock workload (ADR-011 acceptance
# #1 for OpenSRE, the second-workload proof for Goose): what differs is data,
# passed in the environment below. Prints one JSON line on stdout.
#
#   ANDYUR_WORKLOAD_DEMO          repo-relative demo dir (demos/opensre, demos/goose)
#   ANDYUR_WORKLOAD_AGENT         the agent's name on the server (opensre-sre)
#   ANDYUR_WORKLOAD_REGISTRY_ID   the governed registry id (agt_opensre)
#   ANDYUR_WORKLOAD_INPUT         the run input file inside the demo dir (alert.json)
#   ANDYUR_WORKLOAD_EXPECT        substring the captured output must contain (root_cause)
#   ANDYUR_WORKLOAD_MODEL         the granted model every forwarded call must name
#   ANDYUR_WORKLOAD_GATE          the artifact's gate name (exec-opensre-in-cluster)
#   ANDYUR_WORKLOAD_EXPECTED_SPANS optional: override the expected span set
#   ANDYUR_WORKLOAD_TIMEOUT       seconds to wait for the run (900)
set -euo pipefail
SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
RUN_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"
DEMO="${ANDYUR_WORKLOAD_DEMO:?demos/<name>}"
AGENT="${ANDYUR_WORKLOAD_AGENT:?agent name}"
REGISTRY_AGENT_ID="${ANDYUR_WORKLOAD_REGISTRY_ID:?registry agent id}"
INPUT_FILE="${ANDYUR_WORKLOAD_INPUT:?input file name}"
EXPECT="${ANDYUR_WORKLOAD_EXPECT:?expected output substring}"
MODEL="${ANDYUR_WORKLOAD_MODEL:?granted model}"
GATE="${ANDYUR_WORKLOAD_GATE:?gate name}"
TIMEOUT="${ANDYUR_WORKLOAD_TIMEOUT:-900}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
fail() { echo "$GATE FAILED: $*" >&2; exit 1; }
# THE USER TOKEN, when the deployment has user-auth on.
#
# The reference deployment runs ANDYUR_PROFILE=prod, which requires
# ANDYUR_USER_AUTH=on, which means every owner-gated call carries an END USER's
# OIDC token as well as the caller's SVID: the SVID says which component is
# calling, the token says which human it calls for, and ownership and admin are
# read from the second. Without it this gate's first `api GET /agents` is a 401.
#
# Fetched by ROPC from the reference IdP the deployment ships, as the realm's
# admin user. A deployment pointed at a real IdP sets ANDYUR_GATE_USER_TOKEN and
# this block is skipped -- nothing here assumes the reference realm exists.
# stderr from the operator CLI, so a refusal can be quoted by the failure that
# names it rather than vanishing into the gate's own output.
# PORTABLE mktemp: a TEMPLATE with X's, not `-t PREFIX`. BSD mktemp treats the
# -t argument as a prefix and appends randomness; GNU mktemp treats it as a
# template and REFUSES one with fewer than three X's -- "mktemp: too few X's".
# So `mktemp -t andyur-...` worked on the author's macOS and failed every time
# this gate ran on a Linux CI runner.
WORK_ERR="$(mktemp "${TMPDIR:-/tmp}/andyur-workload-err-XXXXXX")"
trap 'rm -f "$WORK_ERR"' EXIT
# The operator client, the user token and its refresh, and the one-field JSON
# reader: shared with every other in-cluster gate (infra/kubernetes/lib/gate.sh)
# rather than copied, because a token-refresh rule in two places is a rule in
# one place and a bug in the other.
. "$HERE/lib/gate.sh"

[[ "$(kubectl config current-context)" == rancher-desktop ]] || fail "expected the rancher-desktop context"
[[ -f "$ROOT/$DEMO/agent.json" && -f "$ROOT/$DEMO/$INPUT_FILE" ]] || fail "$DEMO lacks agent.json or $INPUT_FILE"
manifest_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runtime"]["image"]["digest"])' "$ROOT/$DEMO/agent.json")"
# The worker refuses to START, and to launch, unless the run namespace carries a
# NetworkPolicy verification stamp younger than 600 s, so the live CNI probe
# runs FIRST -- exactly as kubernetes-verify does -- and a worker that crashed
# on a stale stamp is restarted after it. The probe's evidence goes to a
# scratch path: the stamp is what this gate needs, not a second artifact.
# TERMINATED PODS ARE EXCLUDED, and leaving them in was a latent bug this gate
# carried until a Job in andyur-system exposed it. A pod in `Succeeded` holds
# Ready=False for as long as it exists, so `--all` waited the full timeout for
# something that can never become ready and then reported the gate as failed --
# naming a pod that had finished its work correctly. Any Job in either
# namespace does it; the workflow engine's namespace registration merely
# happened to be the first.
kubectl wait --for=condition=Ready pod --all --field-selector=status.phase!=Succeeded,status.phase!=Failed -n spire-system --timeout=120s >/dev/null
# Same portability fix as WORK_ERR above. Also removes the file mktemp really
# created: appending `.json` to its NAME means `rm -f "$stamp_evidence"` was
# deleting a path that did not exist yet and leaking the one that did. What
# this line wants is a unique path ending .json that nothing has created.
stamp_evidence="$(mktemp "${TMPDIR:-/tmp}/andyur-np-stamp-XXXXXX").json"
rm -f "${stamp_evidence%.json}"
ANDYUR_NETWORK_POLICY_EVIDENCE="$stamp_evidence" python3 "$HERE/bounded_exec.py" 180 bash "$HERE/verify-network-policy.sh" >/dev/null \
  || fail "network-policy probe (the namespace stamp) failed"
rm -f "$stamp_evidence"
if ! kubectl -n "$SYSTEM_NS" wait --for=condition=Ready pod/andyur-worker-0 --timeout=20s >/dev/null 2>&1; then
  kubectl -n "$SYSTEM_NS" delete pod andyur-worker-0 --wait=false >/dev/null 2>&1 || true
fi
kubectl wait --for=condition=Ready pod --all --field-selector=status.phase!=Succeeded,status.phase!=Failed -n "$SYSTEM_NS" --timeout=180s >/dev/null
started=$(date +%s)
images=$(python3 - "$SYSTEM_NS" <<'PY'
import json, subprocess, sys
ns = sys.argv[1]
def jp(kind, path): return subprocess.run(["kubectl","get","-n",ns,kind,"-o",f"jsonpath={path}"],capture_output=True,text=True).stdout
env = json.loads(jp("statefulset/andyur-worker", "{.spec.template.spec.containers[0].env}") or "[]")
senv = json.loads(jp("statefulset/andyur-server", "{.spec.template.spec.containers[0].env}") or "[]")
e = {i["name"]: i.get("value") for i in env}; s = {i["name"]: i.get("value") for i in senv}
print(json.dumps({"otel": {"mode": e.get("ANDYUR_OTEL"), "endpoint": e.get("ANDYUR_OTEL_ENDPOINT"),
                           "server_mode": s.get("ANDYUR_OTEL")},
                  "server": jp("statefulset/andyur-server", "{.spec.template.spec.containers[0].image}"),
                  "worker": jp("statefulset/andyur-worker", "{.spec.template.spec.containers[0].image}"),
                  "proxy": e.get("ANDYUR_KUBERNETES_PROXY_IMAGE"), "llm_mode": e.get("ANDYUR_LLM"),
                  "profile": e.get("ANDYUR_PROFILE"), "require_run_svid": e.get("ANDYUR_REQUIRE_RUN_SVID"),
                  "registry": s.get("ANDYUR_REGISTRY"), "registry_ref": s.get("ANDYUR_REGISTRY_REF")}))
PY
)
# the agent exists and is bound to the governed resolution (the operator image
# ships the operator CLI subset, so everything goes over `api`)
# CAPTURED, then parsed. Piping the CLI straight into `json.load(sys.stdin)`
# turns any non-JSON answer into a bare JSONDecodeError traceback with no
# mention of what was being done -- which is what an RC gate run produced when
# the operator Deployment happened to be mid-rollout, `kubectl exec` hit a
# terminating pod, the user token came back empty and the call was a 401. The
# gate reported "Expecting value: line 1 column 1" about a run it never made.
agents_json="$(operator api GET /agents 2>"$WORK_ERR")"
if [ -z "$agents_json" ]; then
  fail "GET /agents returned nothing.$(
    [ -z "$USER_TOKEN" ] && printf '%s' ' No user token was obtained, so an owner-gated call is a 401 -- see the token note above.'
  ) stderr: $(tail -3 "$WORK_ERR" | tr '\n' ' ')"
fi
if ! printf '%s' "$agents_json" | python3 -c 'import json,sys; sys.exit(0 if any(a.get("name")==sys.argv[1] for a in json.load(sys.stdin)) else 1)' "$AGENT" 2>/dev/null; then
  operator api POST /agents --data "$(python3 -c 'import json,sys; print(json.dumps({"name": sys.argv[1], "registry_agent_id": sys.argv[2], "description": sys.argv[3] + " (exec/v1) from the governed snapshot"}))' "$AGENT" "$REGISTRY_AGENT_ID" "$DEMO")" >/dev/null
fi
# Run-labelled resources present BEFORE the trigger are not this run's (an
# orphan from an earlier failed rollback, say); the cleanup check below is
# scoped to what appears during this run, and pre-existing ones are reported.
run_resources() { kubectl get pods,services,secrets,networkpolicies,serviceaccounts,leases,configmaps -n "$RUN_NS" -l "andyur.run/id" -o name 2>/dev/null | sort; }
preexisting="$(run_resources)"
input="$(cat "$ROOT/$DEMO/$INPUT_FILE")"
trigger="$(operator api POST "/agents/$AGENT/trigger" --data "$(python3 -c 'import json,sys; print(json.dumps({"reason": sys.argv[2] + " exec/v1 gate", "input": json.loads(sys.argv[1])}))' "$input" "$GATE")")"
run_id="$(printf '%s' "$trigger" | json_field run_id)" || fail "the trigger did not answer with a run: $trigger"
[[ -n "$run_id" ]] || fail "could not read the run id: $trigger"
deadline=$((SECONDS + TIMEOUT)); body=""; state=""; pulled_digest=""
while (( SECONDS < deadline )); do
  body="$(operator api GET "/runs/$run_id" 2>/dev/null || true)"
  state="$(printf '%s' "$body" | json_field state 2>/dev/null || true)"
  # the node-pulled digest of the WORKLOAD image, sampled while its Pod exists
  # (the group is deleted at completion): must equal the manifest's digest
  if [[ -z "$pulled_digest" ]]; then
    pulled_digest="$(kubectl get pods -n "$RUN_NS" -l "app.kubernetes.io/component=agent" \
      -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{end}' 2>/dev/null \
      | grep -o 'sha256:[0-9a-f]\{64\}' | head -1 || true)"
  fi
  case "$state" in done|failed|cancelled) break;; esac
  sleep 3
done
finished=$(date +%s)
summary="$(printf '%s' "$body" | json_field summary)" || fail "could not read the run's summary"
error="$(printf '%s' "$body" | json_field error)" || fail "could not read the run's error field"
# THIS run's resources gone after completion (the daemon deletes the group
# after reporting the finish; a leftover here would be a reaper defect)
gone=false; leftover=""
for i in $(seq 1 60); do
  leftover="$(comm -13 <(printf '%s\n' "$preexisting") <(run_resources))"
  if [[ -z "$leftover" ]]; then gone=true; break; fi
  sleep 2
done
# THE LAUNCHER THE RUN RECORD NAMES. Under engine dispatch (ADR-014 D11) the
# Temporal execution worker launched and reaped this run, not the worker
# daemon; reading the daemon's log would find nothing and read as a failure.
dispatch="$(printf '%s' "$body" | json_field dispatch 2>/dev/null || true)"
if [[ "$dispatch" == "engine" ]]; then launcher="deployment/andyur-temporal-execution-worker"; container="execution-worker"
else launcher="statefulset/andyur-worker"; container="worker"; fi
worker_log="$(kubectl logs -n "$SYSTEM_NS" "$launcher" -c "$container" --since=15m 2>/dev/null | grep -F "$run_id" | tail -12 || true)"
# ONE RUN = ONE TRACE (observability-exit-criteria.md 7): the server anchored
# the run's trace and stored its traceparent on the run record; read that trace
# back by id from Jaeger, from the operator (the vantage point its query port
# admits), through the gates' shared helper, WAITING for the whole expected set
# (delivery is batched three times over). Absent is a failure by name. The set
# is what an exec/v1 run emits on the instrumented stack (PR #24/#25): the
# server's run, the daemon's launch/completion/cleanup, the controller's waits,
# the serve-only runner up to its park, and the front's forwarded model calls.
# `mcp.tool <name>` is OBSERVED, never required: whether the model calls a tool
# is the model's decision.
EXPECTED_SPANS="${ANDYUR_WORKLOAD_EXPECTED_SPANS:-run $AGENT,server.start_run,server.worker_finish_run,daemon.launch,daemon.exec_completion,controller.wait_ready,controller.delete,runner $AGENT,runner.prepare,runner.prompt,runner.execute,runner.serve,execfront POST}"
trace_ctx="$(printf '%s' "$body" | json_field trace_ctx)" || fail "could not read the run's trace context"
if [[ -n "$trace_ctx" ]]; then
  trace="$(kubectl exec -i -n "$SYSTEM_NS" deployment/andyur-operator -- python - "http://andyur-jaeger:16686" "$trace_ctx" --wait 90 --expect "$EXPECTED_SPANS" \
             < "$ROOT/infra/observability/trace_readback.py" 2>/dev/null | tail -1 || true)"
else
  trace='{"error": "no_trace_ctx_on_run_record"}'
fi
python3 - "$ROOT" "$DEMO" "$INPUT_FILE" "$GATE" "$MODEL" "$EXPECT" "$manifest_digest" "$pulled_digest" "$run_id" "$state" "$summary" "$error" "$images" "$started" "$finished" "$gone" "$worker_log" "$preexisting" "$leftover" "$trace" "$dispatch" "$launcher" <<'PY'
import hashlib, json, pathlib, platform, sys
(root, demo, input_file, gate, model, expect, manifest_digest, pulled_digest, run_id, state, summary, error,
 images, started, finished, gone, worker_log, preexisting, leftover, trace,
 dispatch, launcher) = sys.argv[1:]
try:
    trace = json.loads(trace or "{}")
except ValueError:
    trace = {"error": "readback_failed", "raw": trace[-300:]}
spans = trace.get("spans", [])
forwarded = [s for s in spans if s.get("name") == "execfront POST"
             and s.get("attributes", {}).get("andyur.decision") == "forwarded"]
tool_calls = sorted({s["name"] for s in spans if s.get("name", "").startswith("mcp.tool ")})
mcp_refusals = sorted({s["attributes"].get("andyur.refusal") for s in spans
                       if s.get("name", "").startswith("mcp ") and s["attributes"].get("andyur.refusal") not in (None, "none")})
trace_ok = (not trace.get("error") and trace.get("expected_present") is True
            and bool(forwarded) and all(s["attributes"].get("gen_ai.request.model") == model for s in forwarded)
            and any(s.get("name") == "runner.serve" and s["attributes"].get("andyur.serve.exit") == "sigterm" for s in spans))
ROOT = pathlib.Path(root)
sources = ["infra/kubernetes/verify-exec-workload.sh", "infra/kubernetes/lib/gate.sh",
           "infra/kubernetes/control-plane.yaml",
           "infra/kubernetes/run-isolation.yaml", f"{demo}/agent.json", f"{demo}/{input_file}",
           "andyur/daemon/governed_kubernetes.py", "andyur/daemon/kubernetes_controller.py",
           "andyur/daemon/kubernetes_manifests.py", "andyur/daemon/daemon.py",
           "andyur/runner/runner.py", "andyur/runner/execfront.py", "andyur/modelpolicy.py",
           "infra/kubernetes/observability.yaml", "infra/observability/otel-collector.yaml",
           "infra/observability/jaeger.yaml", "infra/observability/trace_readback.py"]
image_pinned = bool(pulled_digest) and pulled_digest == manifest_digest
ok = state == "done" and gone == "true" and expect in summary and trace_ok and image_pinned
print(json.dumps({
    "gate": gate, "adr": "adr-011", "acceptance": "#1", "demo": demo,
    "run_id": run_id, "state": state, "error": error or None,
    "summary_excerpt": summary[:400], "summary_bytes": len(summary.encode()),
    "expected_output_substring": expect, "expected_output_present": expect in summary,
    "workload_image": {"manifest_digest": manifest_digest, "node_pulled_digest": pulled_digest or None,
                       "pinned": image_pinned},
    "elapsed_seconds": int(finished) - int(started), "run_resources_gone": gone == "true",
    "run_resources_leftover": [l for l in leftover.splitlines() if l],
    "preexisting_run_resources": [l for l in preexisting.splitlines() if l],
    "images": json.loads(images), "worker_log_tail": worker_log[-1500:],
    "dispatch": dispatch or None, "launcher": launcher,
    "trace": trace, "trace_ok": trace_ok,
    "tool_calls_observed": tool_calls, "mcp_refusals_observed": mcp_refusals,
    "host": platform.platform(),
    "source_sha256": {s: hashlib.sha256((ROOT / s).read_bytes()).hexdigest() for s in sources},
    "started_at_epoch": int(started), "finished_at_epoch": int(finished),
    "ok": ok}, sort_keys=True))
sys.exit(0 if ok else 1)
PY

#!/usr/bin/env bash
set -euo pipefail

SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
RUN_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"
NONCE="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
PREFIX="andyur-cni-probe-$NONCE"
CONTROL_NS="$PREFIX-control"
CONTROL_UID=""
WORK_DEADLINE=$((SECONDS + 145))
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE="${ANDYUR_NETWORK_POLICY_EVIDENCE:-$HERE/result-network-policy-$(date +%Y-%m-%d)-$(uname -s | tr A-Z a-z)-$(uname -m).json}"

fail() { echo "network-policy probe FAILED: $*" >&2; exit 1; }
[[ ! -e "$EVIDENCE" ]] || fail "refusing to overwrite evidence $EVIDENCE"
cleanup() {
  cleanup_pids=()
  kubectl delete pod,networkpolicy -n "$RUN_NS" -l "andyur.probe/id=$PREFIX" \
    --ignore-not-found --wait=false --request-timeout=2s \
    >/dev/null 2>&1 & cleanup_pids+=("$!")
  current="$(kubectl get namespace "$CONTROL_NS" \
      -o go-template='{{.metadata.uid}}:{{index .metadata.labels "andyur.probe/nonce"}}' \
      --request-timeout=2s 2>/dev/null || true)"
  current_uid="${current%%:*}"
  current_nonce="${current#*:}"
  if [[ "$current_nonce" == "$NONCE" \
        && ( -z "$CONTROL_UID" || "$current_uid" == "$CONTROL_UID" ) ]]; then
    kubectl delete namespace "$CONTROL_NS" --wait=false --request-timeout=2s \
      >/dev/null 2>&1 & cleanup_pids+=("$!")
  fi
  for cleanup_pid in "${cleanup_pids[@]}"; do wait "$cleanup_pid" || true; done
}
strict_cleanup() {
  cleanup
  local deadline=$((SECONDS + 14)) remaining=""
  while (( SECONDS < deadline )); do
    remaining="$(kubectl get pod,networkpolicy -n "$RUN_NS" \
      -l "andyur.probe/id=$PREFIX" -o name --request-timeout=2s \
      2>/dev/null || echo lookup-failed)"
    namespace_remaining="$(kubectl get namespace "$CONTROL_NS" \
      --ignore-not-found -o name --request-timeout=2s \
      2>/dev/null || echo lookup-failed)"
    if [[ -z "$remaining" && -z "$namespace_remaining" ]]; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' HUP INT
trap 'trap - EXIT; cleanup; exit 143' TERM

image="$(kubectl get statefulset/andyur-worker -n "$SYSTEM_NS" \
  -o jsonpath='{.spec.template.spec.containers[0].image}')"
[[ "$image" == *@sha256:* ]] || fail "worker probe image is not digest pinned"
CONTROL_UID="$(python3 - "$CONTROL_NS" "$NONCE" <<'PY' | \
  kubectl create -f - -o jsonpath='{.metadata.uid}'
import json, sys
print(json.dumps({"apiVersion": "v1", "kind": "Namespace", "metadata": {
    "name": sys.argv[1], "labels": {"andyur.probe/nonce": sys.argv[2]}}}))
PY
)"
[[ -n "$CONTROL_UID" ]] || fail "control namespace has no UID"

python3 - "$RUN_NS" "$CONTROL_NS" "$PREFIX" "$image" <<'PY' | kubectl apply -f - >/dev/null
import json, sys
run_ns, system_ns, prefix, image = sys.argv[1:]

def security():
    return {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"}}

def pod(name, namespace, labels, command, port=None):
    container = {"name": "probe", "image": image, "imagePullPolicy": "IfNotPresent",
                 "command": ["python", "-c", command], "securityContext": security(),
                 "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}
    if port:
        container["ports"] = [{"name": "probe", "containerPort": port}]
        container["readinessProbe"] = {"tcpSocket": {"port": "probe"},
                                       "periodSeconds": 1, "timeoutSeconds": 1}
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace,
                         "labels": {**labels, "andyur.probe/id": prefix}},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                     "terminationGracePeriodSeconds": 1,
                     "securityContext": {"runAsNonRoot": True,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container], "volumes": [{"name": "tmp", "emptyDir": {}}]}}

server = "import http.server; http.server.ThreadingHTTPServer(('0.0.0.0',8765),http.server.SimpleHTTPRequestHandler).serve_forever()"
client = "import time; time.sleep(300)"
docs = []
for run in ("a", "b"):
    common = {"andyur.probe/run": run}
    docs.append(pod(f"{prefix}-{run}-proxy", run_ns,
                    {**common, "andyur.probe/role": "proxy"}, server, 8765))
    docs.append(pod(f"{prefix}-{run}-agent", run_ns,
                    {**common, "andyur.probe/role": "agent"}, client))
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                 "metadata": {"name": f"{prefix}-{run}", "namespace": run_ns,
                              "labels": {"andyur.probe/id": prefix}},
                 "spec": {"podSelector": {"matchLabels": {"andyur.probe/run": run}},
                          "policyTypes": ["Ingress", "Egress"],
                          "ingress": [{"from": [{"podSelector": {"matchLabels": {
                              "andyur.probe/run": run, "andyur.probe/role": "agent"}}}],
                                       "ports": [{"protocol": "TCP", "port": 8765}]}],
                          "egress": [{"to": [{"podSelector": {"matchLabels": {
                              "andyur.probe/run": run, "andyur.probe/role": "proxy"}}}],
                                      "ports": [{"protocol": "TCP", "port": 8765}]}]}})
docs.append(pod(f"{prefix}-control", system_ns,
                {"andyur.probe/role": "control"}, client))
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": docs}))
PY

remaining=$((WORK_DEADLINE - SECONDS))
(( remaining > 0 )) || fail "work deadline expired before Pod readiness"
wait_pids=()
for pod in "$PREFIX-a-proxy" "$PREFIX-b-proxy"; do
  kubectl wait -n "$RUN_NS" --for=condition=Ready "pod/$pod" \
    --timeout="${remaining}s" >/dev/null & wait_pids+=("$!")
done
for pod in "$PREFIX-a-agent" "$PREFIX-b-agent"; do
  kubectl wait -n "$RUN_NS" --for=jsonpath='{.status.phase}'=Running "pod/$pod" \
    --timeout="${remaining}s" >/dev/null & wait_pids+=("$!")
done
kubectl wait -n "$CONTROL_NS" --for=jsonpath='{.status.phase}'=Running \
  "pod/$PREFIX-control" --timeout="${remaining}s" >/dev/null & wait_pids+=("$!")
wait_status=0
for wait_pid in "${wait_pids[@]}"; do wait "$wait_pid" || wait_status=$?; done
(( wait_status == 0 )) || fail "one or more probe Pods did not become ready"

probe_kubectl() {
  local remaining=$((WORK_DEADLINE - SECONDS - 15))
  (( remaining > 0 )) || fail "work deadline expired before live probes"
  python3 "$HERE/bounded_exec.py" "$remaining" kubectl "$@"
}

ip_a="$(probe_kubectl get pod -n "$RUN_NS" "$PREFIX-a-proxy" -o jsonpath='{.status.podIP}')"
ip_b="$(probe_kubectl get pod -n "$RUN_NS" "$PREFIX-b-proxy" -o jsonpath='{.status.podIP}')"
api_ip="$(probe_kubectl get service kubernetes -n default -o jsonpath='{.spec.clusterIP}')"
# The telemetry path is part of the contract now (observability.yaml): OTLP
# ingest is unauthenticated, so an isolated agent must not reach it.
collector_ip="$(probe_kubectl get service otel-collector -n "$SYSTEM_NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
[[ -n "$collector_ip" ]] || fail "service otel-collector absent in $SYSTEM_NS: apply infra/kubernetes/apply-observability.sh"

tcp() {
  local namespace="$1" pod="$2" host="$3" port="$4" expected="$5"
  actual="$(probe_kubectl exec -n "$namespace" "$pod" -- python -c \
    "import socket
try:
 s=socket.create_connection(('$host',$port),2); s.close(); print('allow')
except OSError:
 print('deny')")" || fail "$pod connection probe did not execute"
  [[ "$actual" == allow || "$actual" == deny ]] || \
    fail "$pod connection probe returned an invalid sentinel: $actual"
  [[ "$actual" == "$expected" ]] || fail "$pod -> $host:$port was $actual, expected $expected"
}

# Positive-backed enforcement at the actual CNI consumer.
tcp "$RUN_NS" "$PREFIX-a-agent" "$ip_a" 8765 allow
tcp "$RUN_NS" "$PREFIX-a-agent" "$ip_b" 8765 deny
tcp "$CONTROL_NS" "$PREFIX-control" "$api_ip" 443 allow
tcp "$RUN_NS" "$PREFIX-a-agent" "$api_ip" 443 deny
tcp "$CONTROL_NS" "$PREFIX-control" 1.1.1.1 443 allow
tcp "$RUN_NS" "$PREFIX-a-agent" 1.1.1.1 443 deny
tcp "$RUN_NS" "$PREFIX-a-agent" 169.254.169.254 80 deny
tcp "$RUN_NS" "$PREFIX-a-agent" "$collector_ip" 4318 deny

dns_check='import socket
socket.setdefaulttimeout(3)
try:
 socket.getaddrinfo("kubernetes.default.svc",443); print("resolved")
except OSError:
 print("denied")'
control_dns="$(probe_kubectl exec -n "$CONTROL_NS" "$PREFIX-control" -- \
  python -c "$dns_check")" || fail "positive-control DNS probe did not execute"
[[ "$control_dns" == resolved ]] || fail "positive-control DNS lookup failed"
agent_dns="$(probe_kubectl exec -n "$RUN_NS" "$PREFIX-a-agent" -- \
  python -c "$dns_check")" || fail "isolated DNS probe did not execute"
[[ "$agent_dns" == denied ]] || fail "isolated agent unexpectedly resolved cluster DNS"

# Exact mutation: Kubernetes combines matching NetworkPolicies additively. An
# injected allow-all policy is therefore the admission defect that defeats the
# generated per-run policies without editing them. Prove it applied and turns
# the protected paths red, delete it, then prove the original enforcement is
# restored at the CNI consumer.
python3 - "$RUN_NS" "$PREFIX" <<'PY' | kubectl apply -f - >/dev/null
import json, sys
namespace, prefix = sys.argv[1:]
items = []
for run in ("a", "b"):
    items.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                  "metadata": {"name": f"{prefix}-{run}-mutation",
                               "namespace": namespace,
                               "labels": {"andyur.probe/id": prefix,
                                          "andyur.probe/mutation": "allow-all"}},
                  "spec": {"podSelector": {"matchLabels": {"andyur.probe/run": run}},
                           "policyTypes": ["Ingress", "Egress"],
                           "ingress": [{}], "egress": [{}]}})
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
PY
mutation_count="$(probe_kubectl get networkpolicy -n "$RUN_NS" \
  -l "andyur.probe/id=$PREFIX,andyur.probe/mutation=allow-all" \
  -o jsonpath='{.items[*].metadata.name}' | wc -w | tr -d ' ')"
[[ "$mutation_count" == 2 ]] || fail "allow-all mutation did not apply exactly twice"

eventually_tcp() {
  local namespace="$1" pod="$2" host="$3" port="$4" expected="$5"
  local deadline=$((SECONDS + 15)) actual=""
  while (( SECONDS < deadline )); do
    actual="$(probe_kubectl exec -n "$namespace" "$pod" -- python -c \
      "import socket
try:
 s=socket.create_connection(('$host',$port),2); s.close(); print('allow')
except OSError:
 print('deny')")" || fail "$pod mutation probe did not execute"
    [[ "$actual" == "$expected" ]] && return 0
    sleep 0.25
  done
  fail "$pod -> $host:$port remained $actual, expected $expected"
}
eventually_tcp "$RUN_NS" "$PREFIX-a-agent" "$ip_b" 8765 allow
eventually_tcp "$RUN_NS" "$PREFIX-a-agent" "$api_ip" 443 allow
eventually_tcp "$RUN_NS" "$PREFIX-a-agent" 1.1.1.1 443 allow

probe_kubectl delete networkpolicy -n "$RUN_NS" \
  -l "andyur.probe/id=$PREFIX,andyur.probe/mutation=allow-all" --wait=true >/dev/null
eventually_tcp "$RUN_NS" "$PREFIX-a-agent" "$ip_b" 8765 deny
eventually_tcp "$RUN_NS" "$PREFIX-a-agent" "$api_ip" 443 deny
eventually_tcp "$RUN_NS" "$PREFIX-a-agent" 1.1.1.1 443 deny
eventually_tcp "$RUN_NS" "$PREFIX-a-agent" 169.254.169.254 80 deny

# The worker has namespace-get but no namespace-patch authority. Only this
# positive-backed operator preflight emits the short-lived admission stamp.
namespace_uid="$(probe_kubectl get namespace "$RUN_NS" -o jsonpath='{.metadata.uid}')"
verified_at="$(date +%s)"
probe_kubectl label namespace "$RUN_NS" andyur.network-policy/verified=true --overwrite >/dev/null
probe_kubectl annotate namespace "$RUN_NS" \
  "andyur.network-policy/verified-at=$verified_at" \
  "andyur.network-policy/namespace-uid=$namespace_uid" --overwrite >/dev/null

strict_cleanup || fail "probe resources were not absent after bounded cleanup"
context="$(kubectl config current-context)"
server_version="$(kubectl version -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')"
cni_objects="$(kubectl get daemonset -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' | sort | tr '\n' ',')"
python3 - "$EVIDENCE" "$context" "$server_version" "$namespace_uid" \
  "$verified_at" "$cni_objects" "$HERE/verify-network-policy.sh" \
  "$HERE/bounded_exec.py" "$HERE/run-isolation.yaml" <<'PY'
import hashlib, json, platform, sys, time
out, context, version, namespace_uid, verified_at, cni, *sources = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
document = {
    "gate": "target-cluster-network-policy", "ok": True,
    "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "host": platform.platform(),
    "cluster": {"context": context, "server_version": version,
                "run_namespace_uid": namespace_uid,
                "cni_daemonsets": [item for item in cni.split(",") if item]},
    "admission_stamp": {"verified_at": int(verified_at),
                        "namespace_uid": namespace_uid},
    "assertions": {
        "same_run_allow": True, "cross_run_deny": True,
        "kubernetes_api_deny": True, "public_internet_deny": True,
        "metadata_ip_deny": True, "dns_deny": True,
        "collector_ingest_deny": True,
        "allow_all_mutation_applied": True,
        "mutation_cross_run_api_internet_allowed": True,
        "mutation_removed_and_denials_restored": True,
        "probe_resources_absent": True,
    },
    "source_sha256": {path.rsplit("/", 1)[-1]: sha(path) for path in sources},
}
with open(out + ".tmp", "x") as handle:
    json.dump(document, handle, indent=2)
    handle.write("\n")
__import__("os").replace(out + ".tmp", out)
PY
trap - EXIT HUP INT TERM
echo "NETWORK POLICY LIVE PROBE PASSED (mutation red/restored; same-run allow; cross-run/DNS/API/internet/metadata/collector deny); evidence $EVIDENCE"

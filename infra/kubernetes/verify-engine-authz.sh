#!/usr/bin/env bash
# Live proof that the workflow engine authorizes callers by SPIFFE ID, with the
# NETWORK taken out of the argument.
#
# A probe Pod is given an identity the cluster issues but the engine's
# authorizer does not list (spiffe://andyur.local/engine-authz-probe) AND a
# NetworkPolicy route to the engine on 7233. So the only thing left that can
# refuse it is the authorizer -- which is the point: before the authorizer,
# a Pod in exactly this position had full engine administration.
#
# Four things are recorded, and a refusal alone is not one of them:
#   route_open         the probe's TCP connect to 7233 SUCCEEDED, so a refusal
#                      afterwards is not the NetworkPolicy's
#   probe_refused      its mTLS call with its own SVID failed
#   refusal_logged     the authorizer logged the probe's SPIFFE ID as denied --
#                      which also proves the handshake completed and the
#                      certificate came from SPIRE over SDS, not a file
#   control_plane_polling  the control plane is polling the task queue right
#                      now, through the same authorizer: the positive control
#
# Everything created is deleted BY NAME on exit, and its absence is checked.
set -euo pipefail
cd "$(dirname "$0")/../.."
NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
TOOLS="docker.io/temporalio/admin-tools@sha256:f048113e98748c6b902e1962e3225082f42a4760467aaeda139e67c4aa692231"
HELPER="ghcr.io/spiffe/spiffe-helper@sha256:1c92e5998ad3621e3323f25aabe40f5a88ba730ee0edb248aa8c943ca504e8a2"
PROBE_ID="spiffe://andyur.local/engine-authz-probe"
NAME=andyur-engine-authz-probe
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cleanup() {
  kubectl delete pod "$NAME" -n "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete networkpolicy "$NAME" "$NAME-ingress" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete clusterspiffeid "$NAME" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

CLASS="$(kubectl get clusterspiffeid andyur-temporal -o jsonpath='{.spec.className}')"
# Without a class the controller ignores the probe's identity, the probe gets
# no certificate, and its call fails for a reason that is not the authorizer.
[ -n "$CLASS" ] || { echo "the engine's ClusterSPIFFEID has no className" >&2; exit 1; }
kubectl apply -f - >/dev/null <<YAML
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata: {name: $NAME}
spec:
  className: $CLASS
  spiffeIDTemplate: $PROBE_ID
  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $NS}}
  podSelector: {matchLabels: {app: $NAME}}
  ttl: 1h
---
# The ROUTE, granted on purpose: policies are additive, so this admits the
# probe to the engine without touching the engine's own policy.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: $NAME-ingress, namespace: $NS}
spec:
  podSelector: {matchLabels: {app: andyur-temporal}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: $NAME}}}]
      ports: [{protocol: TCP, port: 7233}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: $NAME, namespace: $NS}
spec:
  podSelector: {matchLabels: {app: $NAME}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress:
    - to:
        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
          podSelector: {matchLabels: {k8s-app: kube-dns}}
      ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
    - to: [{podSelector: {matchLabels: {app: andyur-temporal}}}]
      ports: [{protocol: TCP, port: 7233}]
---
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
  namespace: $NS
  labels: {app: $NAME}
spec:
  restartPolicy: Never
  serviceAccountName: andyur-temporal
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile: {type: RuntimeDefault}
  initContainers:
    - name: svid-bootstrap
      image: $HELPER
      args: ["-config", "/conf/helper.conf", "-daemon-mode=false"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}, readOnlyRootFilesystem: true}
      volumeMounts:
        - {name: svid, mountPath: /svid}
        - {name: conf, mountPath: /conf, readOnly: true}
        - {name: spiffe-workload-api, mountPath: /spiffe-workload-api, readOnly: true}
  containers:
    - name: probe
      image: $TOOLS
      command: ["/bin/sh", "-c"]
      args:
        - |
          # Its own address, printed: a finished Pod's status loses its IP, and
          # the refusal is matched to this probe by the address it came from.
          echo "ADDR \$(hostname -i)"
          if nc -z -w 5 andyur-temporal 7233; then echo "ROUTE open"; else echo "ROUTE closed"; fi
          TLS="--tls --tls-cert-path /svid/tls.crt --tls-key-path /svid/tls.key --tls-ca-path /svid/ca.crt"
          if temporal operator namespace describe --namespace andyur --address andyur-temporal:7233 \$TLS >/tmp/out 2>&1; then
            echo "CALL admitted"
          else
            echo "CALL refused: \$(tail -1 /tmp/out | cut -c1-160)"
          fi
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}, readOnlyRootFilesystem: true}
      volumeMounts:
        - {name: svid, mountPath: /svid, readOnly: true}
        - {name: tmp, mountPath: /tmp}
  volumes:
    - {name: svid, emptyDir: {}}
    - {name: tmp, emptyDir: {}}
    - name: conf
      configMap: {name: andyur-temporal-spiffe-helper}
    - name: spiffe-workload-api
      csi: {driver: csi.spiffe.io, readOnly: true}
YAML

phase=""
for _ in $(seq 1 60); do
  phase="$(kubectl get pod "$NAME" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = Succeeded ] || [ "$phase" = Failed ] && break
  sleep 3
done
case "$phase" in
  Succeeded|Failed) ;;
  *) echo "the probe never finished (phase: ${phase:-none})" >&2; exit 1 ;;
esac
OUT="$(kubectl logs "$NAME" -n "$NS" -c probe 2>&1 || true)"
echo "$OUT" >&2
PROBE_IP="$(echo "$OUT" | awk '/^ADDR /{print $2; exit}')"
[ -n "$PROBE_IP" ] || { echo "the probe did not report its address" >&2; exit 1; }

ENGINE="$(kubectl get pod -n "$NS" -l app=andyur-temporal -o jsonpath='{.items[0].metadata.name}')"
# The access log is flushed on an interval (Envoy's default is 10s).
sleep 15
# THIS RUN'S REFUSAL, not any refusal: lines since this script started, from
# this probe Pod's address, naming its identity. Matched as fixed strings.
DENIED="$(kubectl logs "$ENGINE" -n "$NS" -c authz --since-time="$STARTED" 2>/dev/null \
          | grep -F "peer=$PROBE_ID " | grep -F "from=$PROBE_IP:" \
          | grep -cF "rbac_access_denied" || true)"
# The positive control: a poller from a control-plane Pod, whatever it is named.
CP_PODS="$(kubectl get pod -n "$NS" -l app=andyur-server -o jsonpath='{.items[*].metadata.name}')"
POLLERS=0
for cp in $CP_PODS; do
  n="$(kubectl exec "$ENGINE" -n "$NS" -c temporal -- temporal task-queue describe \
         --task-queue andyur --namespace andyur --address 127.0.0.1:7236 2>/dev/null \
       | grep -cF "@$cp" || true)"
  POLLERS=$((POLLERS + ${n:-0}))
done

ROUTE_OPEN=false; REFUSED=false; LOGGED=false; POLLING=false
echo "$OUT" | grep -q "^ROUTE open" && ROUTE_OPEN=true
echo "$OUT" | grep -q "^CALL refused" && REFUSED=true
[ "${DENIED:-0}" -gt 0 ] && LOGGED=true
[ "${POLLERS:-0}" -gt 0 ] && POLLING=true

cleanup
trap - EXIT
ABSENT=true
kubectl get pod "$NAME" -n "$NS" >/dev/null 2>&1 && ABSENT=false
kubectl get networkpolicy "$NAME" -n "$NS" >/dev/null 2>&1 && ABSENT=false
kubectl get networkpolicy "$NAME-ingress" -n "$NS" >/dev/null 2>&1 && ABSENT=false
kubectl get clusterspiffeid "$NAME" >/dev/null 2>&1 && ABSENT=false

VERDICT=PASS
for v in "$ROUTE_OPEN" "$REFUSED" "$LOGGED" "$POLLING" "$ABSENT"; do
  [ "$v" = true ] || VERDICT=FAIL
done

.venv/bin/python - "$VERDICT" "$ROUTE_OPEN" "$REFUSED" "$LOGGED" "$POLLING" "$ABSENT" "$STARTED" "$PROBE_ID" <<'PY'
import hashlib, json, platform, subprocess, sys
from datetime import datetime, timezone
verdict, route, refused, logged, polling, absent, started, probe = sys.argv[1:9]
b = lambda s: s == "true"
sources = ("infra/kubernetes/temporal.yaml", "infra/kubernetes/verify-engine-authz.sh")
server = subprocess.run(["kubectl", "config", "view", "--minify", "-o",
                         "jsonpath={.clusters[0].cluster.server}"],
                        capture_output=True, text=True).stdout
print(json.dumps({
    "verdict": verdict,
    "probe_identity": probe,
    "route_open": b(route),
    "probe_refused": b(refused),
    "refusal_logged": b(logged),
    "control_plane_polling": b(polling),
    "teardown_absent": b(absent),
    "platform": platform.platform(),
    "started_at": started,
    "finished_at": datetime.now(timezone.utc).isoformat(),
    "api_server_sha256": hashlib.sha256(server.encode()).hexdigest(),
    "source_sha256": {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in sources},
}, indent=2, sort_keys=True))
PY
[ "$VERDICT" = PASS ]

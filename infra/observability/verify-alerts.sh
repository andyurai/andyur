#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROMETHEUS_IMAGE="prom/prometheus@sha256:332c2f43e7e389d74d3893b55bb02fbbd684208e681eeb604641d5d769c0fe2a"
WORK="$(mktemp -d)"
CONTAINER="andyur-alert-gate-${RANDOM}-$$"
METRICS_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("0.0.0.0", 0))
    print(sock.getsockname()[1])
PY
)"
PROM_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
SERVER_PID=""
PRODUCER_PID=""

bounded_exec() {
  python3 -c 'import subprocess, sys
try:
    result = subprocess.run(sys.argv[1:], timeout=60)
except subprocess.TimeoutExpired:
    raise SystemExit(124)
raise SystemExit(result.returncode)' "$@"
}

container_absent() {
  local deadline=$((SECONDS + 30)) names consecutive=0
  while (( SECONDS < deadline )); do
    if names="$(bounded_exec docker ps -a \
        --filter "name=^/${CONTAINER}$" --format '{{.Names}}')"; then
      if [[ -z "$names" ]]; then
        consecutive=$((consecutive + 1))
        (( consecutive >= 4 )) && return 0
      else
        consecutive=0
        bounded_exec docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
      fi
    else
      echo "Docker daemon unavailable while verifying teardown" >&2
      return 1
    fi
    sleep 0.5
  done
  echo "Prometheus container survived teardown" >&2
  return 1
}

cleanup() {
  set +e
  if [[ -n "$PRODUCER_PID" ]]; then kill "$PRODUCER_PID" 2>/dev/null; wait "$PRODUCER_PID" 2>/dev/null; fi
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; fi
  bounded_exec docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  container_absent >/dev/null || echo "alert-gate teardown could not be proven" >&2
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

python3 - "$ROOT/infra/observability/prometheus-alerts.yaml" "$WORK/rules.yaml" <<'PY'
import pathlib, sys, yaml
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
data = yaml.safe_load(source.read_text())
expected = {
    "AndyurHttpServerErrorRate",
    "AndyurDependencyFailures",
    "AndyurRunFailures",
}
rules = [rule for group in data["groups"] for rule in group["rules"]]
actual = {rule["alert"] for rule in rules}
if actual != expected:
    raise SystemExit(f"unexpected alert set: {sorted(actual)}")
for rule in rules:
    expression = str(rule["expr"])
    expression = expression.replace("[5m]", "[5s]")
    expression = expression.replace("[10m]", "[6s]")
    expression = expression.replace("[15m]", "[7s]")
    rule["expr"] = expression
    rule["for"] = "2s"
target.write_text(yaml.safe_dump(data, sort_keys=False))
PY

cat >"$WORK/prometheus.yaml" <<EOF
global:
  scrape_interval: 1s
  evaluation_interval: 1s
rule_files:
  - /etc/prometheus/rules.yaml
scrape_configs:
  - job_name: synthetic-andyur
    fallback_scrape_protocol: PrometheusText0.0.4
    static_configs:
      - targets: [host.docker.internal:${METRICS_PORT}]
EOF

write_metrics() {
  local http_total="$1" dependency_total="$2" run_total="$3"
  local next="$WORK/metrics.next"
  cat >"$next" <<EOF
# TYPE andyur_andyur_http_server_requests_total counter
andyur_andyur_http_server_requests_total{service_name="alert-gate",http_response_status_code_class="5xx"} ${http_total}
# TYPE andyur_andyur_dependency_failures_total counter
andyur_andyur_dependency_failures_total{service_name="alert-gate",andyur_dependency="synthetic"} ${dependency_total}
# TYPE andyur_andyur_run_outcomes_total counter
andyur_andyur_run_outcomes_total{andyur_outcome="failure",service_name="alert-gate"} ${run_total}
EOF
  mv "$next" "$WORK/metrics"
}

write_metrics 0 0 0
python3 -m http.server "$METRICS_PORT" --bind 0.0.0.0 --directory "$WORK" \
  >"$WORK/http.log" 2>&1 &
SERVER_PID=$!

bounded_exec docker run -d --name "$CONTAINER" --add-host host.docker.internal:host-gateway \
  -p "127.0.0.1:${PROM_PORT}:9090" \
  -v "$WORK/prometheus.yaml:/etc/prometheus/prometheus.yml:ro" \
  -v "$WORK/rules.yaml:/etc/prometheus/rules.yaml:ro" \
  "$PROMETHEUS_IMAGE" \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --storage.tsdb.retention.time=30m >/dev/null

api="http://127.0.0.1:${PROM_PORT}"
wait_ready() {
  local deadline=$((SECONDS + 30))
  until curl --connect-timeout 2 --max-time 3 -fsS "$api/-/ready" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      bounded_exec docker logs "$CONTAINER" >&2 || true
      echo "Prometheus did not become ready" >&2
      exit 1
    fi
    sleep 0.5
  done
}

wait_scraped() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if curl --connect-timeout 2 --max-time 3 -fsS \
      "$api/api/v1/query?query=up%7Bjob%3D%22synthetic-andyur%22%7D" 2>/dev/null | \
      python3 -c 'import json, sys
data = json.load(sys.stdin)["data"]["result"]
raise SystemExit(0 if data and data[0]["value"][1] == "1" else 1)'; then
      sleep 2
      return 0
    fi
    sleep 0.5
  done
  echo "synthetic target was not successfully scraped" >&2
  exit 1
}

assert_state() {
  local wanted="$1" deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if curl --connect-timeout 2 --max-time 3 -fsS "$api/api/v1/alerts" 2>/dev/null | python3 -c '
import json, sys
wanted = sys.argv[1]
expected = {"AndyurHttpServerErrorRate", "AndyurDependencyFailures", "AndyurRunFailures"}
payload = json.load(sys.stdin)
alerts = payload["data"]["alerts"]
states = {item["labels"]["alertname"]: item["state"] for item in alerts}
if wanted == "inactive":
    ok = expected.isdisjoint(states)
else:
    ok = expected == set(states) and all(states[name] == wanted for name in expected)
raise SystemExit(0 if ok else 1)
' "$wanted"; then
      printf '%s\n' "$wanted"
      return 0
    fi
    sleep 0.5
  done
  curl --connect-timeout 2 --max-time 3 -fsS "$api/api/v1/alerts" >&2 || true
  echo "alerts did not reach ${wanted}" >&2
  exit 1
}

wait_ready
wait_scraped
assert_state inactive

(
  http=0 dependency=0 run=0
  while :; do
    http=$((http + 10)); dependency=$((dependency + 10)); run=$((run + 10))
    write_metrics "$http" "$dependency" "$run"
    sleep 1
  done
) &
PRODUCER_PID=$!

assert_state pending
assert_state firing
kill "$PRODUCER_PID"
wait "$PRODUCER_PID" 2>/dev/null || true
PRODUCER_PID=""
assert_state inactive

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
bounded_exec docker rm -f "$CONTAINER" >/dev/null
container_absent

trap - EXIT INT TERM
rm -rf "$WORK"
printf '%s\n' "PASS: all three shipped alerts inactive -> pending -> firing -> recovered; teardown absent"

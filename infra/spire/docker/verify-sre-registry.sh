#!/usr/bin/env bash
# Real SRE registry-consumption proof on the container-attested SPIRE stack.
# Owns only andyur-sre-* containers; it never tears down the shared SPIRE stack.
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NET="andyur-spire-net"
SOCK="andyur-spire-sockets"
TD="andyur.local"
WORK="$(mktemp -d)"
STATE_DIR="${TMPDIR:-/tmp}/andyur-sre-registry-${UID:-user}"
ARTIFACT_ROOT="${ANDYUR_SRE_ARTIFACT_DIR:-$HERE/data/sre-demo}"
ARTIFACT_KEEP="${ANDYUR_SRE_ARTIFACT_KEEP:-10}"
TAG="$(basename "$WORK" | tr -cd '[:alnum:]' | tail -c 10)"
SERVER="andyur-sre-server-$TAG"
LITELLM="andyur-sre-litellm-$TAG"
SERVER_ROLE="sre-server-$TAG"
OPERATOR_ROLE="sre-operator-$TAG"
WORKER_ROLE="sre-worker-$TAG"
RUN_ID=""
AGENT="sre-oncall"
REGISTRY_ID="agt_oncall_ollama"
[ "${ANDYUR_LLM:-ollama}" = api ] && REGISTRY_ID="agt_oncall"
BASE="http://127.0.0.1:18679"
LITELLM_MASTER_KEY="sk-andyur-sre-$(openssl rand -hex 24)"
RUN_SECRET="$(openssl rand -hex 32)"
OWNER_TOKEN="$(openssl rand -hex 16)"
# The external Authorization Server + IdP (reference AS). This gate no longer
# dev-mints its own tokens: dana logs in AT the AS (real Auth Code + PKCE), the
# server validates her login as the OIDC IdP, and the per-run sidecar exchanges
# her token (subject) + the run's SVID (actor) at the AS (RFC 8693). The AS is
# reachable from the containers as host.docker.internal.
AS_PORT="${ANDYUR_SRE_AS_PORT:-8684}"
AS_HOST="http://127.0.0.1:$AS_PORT"
AS_FROM_CONTAINER="http://host.docker.internal:$AS_PORT"
AS_PID=""
LOGIN_PID=""
OPENBAO_UP=0
OPA_UP=0
# opa_stack_up() resets HERE (via opa_stack_paths) and launches the AuthZEN shim
# as a child of THIS shell, so opa-stack.sh must be sourced here, not run in a
# subshell -- and HERE restored around every opa_stack_* call.
GATE_HERE="$HERE"
# ADR-010 scope map: the run asks in Andyur's LOGICAL vocabulary (the registry's
# obs:read, tickets:comment/close); asclient translates each to the AS's own
# vocabulary at exchange time so the reference AS issues telemetry:read /
# tickets:write / tickets:delete, which the resource PEPs enforce.
SCOPE_MAP='{"schema":"andyur-reference-scope-map/v1","actions":{"obs:read":{"request":"telemetry:read","claim":"telemetry:read"},"tickets:read":{"request":"tickets:read","claim":"tickets:read"},"tickets:comment":{"request":"tickets:write","claim":"tickets:write"},"tickets:close":{"request":"tickets:delete","claim":"tickets:delete"}}}'
# The resource PEPs speak the AS vocabulary too: the AS-issued token carries
# telemetry:read / tickets:write / tickets:delete, so each tool translates the
# logical action it checks into the AS scope before enforcing it.
TOOL_SCOPE_MAP='{"obs:read":"telemetry:read","tickets:read":"tickets:read","tickets:comment":"tickets:write","tickets:close":"tickets:delete"}'
PASS=0
FAIL=0
# 19 base + the three sidecar traversal checks (egress active, tools through the
# sidecar, agentgateway never serving one). The per-run agentgateway is gone
# (ADR-003), so the sidecar path is unconditional.
# +3 over the pre-external-AS gate: the AS + IdP came up, dana logged in for
# real, and the resource PEP proved the tool token was external-AS issued.
# +1 for phase 3: the external OPA engine came up and the run's authorization
# traversed it (2 checks) -- one is unconditional (up), one is post-run.
EXPECTED_PASS=28
# api mode adds the model run (+2) and phase 2's vault checks: sealed OpenBao up,
# the LLM credential read from it under model-broker, and the least-privilege
# denial (+3).
[ "${ANDYUR_LLM:-ollama}" = api ] && EXPECTED_PASS=33
TRACE_ID=""
ARTIFACT_DIR=""
ARTIFACT_READY=0
ARTIFACT_FINALIZED=0

prepare_artifact_root() {
  case "$ARTIFACT_KEEP" in *[!0-9]*|'')
    echo "ANDYUR_SRE_ARTIFACT_KEEP must be a positive integer" >&2; return 1;;
  esac
  [ "$ARTIFACT_KEEP" -gt 0 ] || {
    echo "ANDYUR_SRE_ARTIFACT_KEEP must be greater than zero" >&2; return 1;
  }
  if [ -e "$ARTIFACT_ROOT" ]; then
    [ -d "$ARTIFACT_ROOT" ] && [ ! -L "$ARTIFACT_ROOT" ] \
      && [ -O "$ARTIFACT_ROOT" ] \
      && [ -f "$ARTIFACT_ROOT/.andyur-sre-artifacts" ] || {
        echo "refusing unowned or unmarked artifact root $ARTIFACT_ROOT" >&2
        return 1
      }
    chmod 700 "$ARTIFACT_ROOT"
  else
    mkdir -m 700 -p "$ARTIFACT_ROOT"
    : >"$ARTIFACT_ROOT/.andyur-sre-artifacts"
  fi
  ARTIFACT_READY=1
}

prune_artifacts() {
  ARTIFACT_ROOT="$ARTIFACT_ROOT" ARTIFACT_KEEP="$ARTIFACT_KEEP" python3 - <<'PY'
import os, pathlib, re, shutil
root = pathlib.Path(os.environ["ARTIFACT_ROOT"])
keep = int(os.environ["ARTIFACT_KEEP"])
owned = re.compile(r"(?:[0-9a-f]{12}|failed-[A-Za-z0-9]+)$")
dirs = [p for p in root.iterdir()
        if p.is_dir() and not p.is_symlink() and owned.fullmatch(p.name)]
for path in sorted(dirs, key=lambda p: p.stat().st_mtime, reverse=True)[keep:]:
    shutil.rmtree(path)
for path in root.rglob("*"):
    if not path.is_symlink():
        path.chmod(0o700 if path.is_dir() else 0o600)
PY
}

scan_artifacts() {
  ARTIFACT_DIR="$ARTIFACT_DIR" RUN_TOKEN_VALUE="${token:-}" \
    LITELLM_KEY_VALUE="${LITELLM_MASTER_KEY:-}" RUN_SVID_VALUE="${run_svid:-}" \
    RUN_SECRET_VALUE="$RUN_SECRET" python3 - <<'PY'
import os, pathlib, re
root = pathlib.Path(os.environ["ARTIFACT_DIR"])
required = {"runner.log", "server.log", "obs.log", "tix.log",
            "jaeger-trace.json", "run-record.json"}
if os.environ.get("ANDYUR_LLM", "ollama") == "api":
    required.add("litellm.log")
present = {p.name for p in root.iterdir() if p.is_file()}
if missing := required - present:
    raise SystemExit(f"artifact scan is vacuous; missing {sorted(missing)}")
for path in root.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    data = path.read_bytes()
    for name in ("RUN_TOKEN_VALUE", "LITELLM_KEY_VALUE", "RUN_SVID_VALUE",
                 "RUN_SECRET_VALUE"):
        secret = os.environ.get(name, "").encode()
        if secret and secret in data:
            raise SystemExit(f"credential {name} retained in {path.name}")
    if re.search(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", data):
        raise SystemExit(f"JWT-shaped material retained in {path.name}")
PY
}

process_start() { ps -p "$1" -o lstart= 2>/dev/null || true; }
record_process() {
  local kind="$1" pid="$2" started=""
  for _ in $(seq 1 20); do
    started="$(process_start "$pid")"
    [ -n "$started" ] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.05
  done
  if [ -z "$started" ]; then
    echo "could not publish $kind PID $pid ownership fingerprint" >&2
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi
  printf '%s\n' "$pid" >"$STATE_DIR/$kind.pid"
  printf '%s\n' "$started" >"$STATE_DIR/$kind.started"
}
recover_process() {
  local kind="$1" needle="$2" pid expected actual command
  [ -f "$STATE_DIR/$kind.pid" ] || return 0
  pid="$(cat "$STATE_DIR/$kind.pid")"
  expected="$(cat "$STATE_DIR/$kind.started" 2>/dev/null || true)"
  case "$pid" in *[!0-9]*|'') return 1 ;; esac
  actual="$(process_start "$pid")"
  [ -n "$actual" ] || return 0
  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [ -n "$expected" ] && [ "$actual" = "$expected" ] && [[ "$command" == *"$needle"* ]] || {
    echo "refusing stale $kind PID $pid: ownership fingerprint does not match" >&2
    return 1
  }
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
  kill -KILL "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
  echo "stale $kind PID $pid did not stop" >&2
  return 1
}
stop_recorded_process() {
  local kind="$1" needle="$2" pid="$3" expected actual command state
  expected="$(cat "$STATE_DIR/$kind.started" 2>/dev/null || true)"
  actual="$(process_start "$pid")"
  if [ -z "$actual" ]; then
    kill -0 "$pid" 2>/dev/null && {
      echo "refusing $kind PID $pid: live process has no readable fingerprint" >&2
      return 1
    }
    wait "$pid" 2>/dev/null || true
    return 0
  fi
  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [ -n "$expected" ] && [ "$actual" = "$expected" ] \
    && [[ "$command" == *"$needle"* ]] || {
      echo "refusing stale $kind PID $pid: ownership fingerprint does not match" >&2
      return 1
    }
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
    [ -z "$state" ] || [[ "$state" == Z* ]] && break
    sleep 0.1
  done
  state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
  if [ -n "$state" ] && [[ "$state" != Z* ]]; then
    kill -KILL "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
      [ -z "$state" ] || [[ "$state" == Z* ]] && break
      sleep 0.1
    done
  fi
  wait "$pid" 2>/dev/null || true
  kill -0 "$pid" 2>/dev/null && {
    echo "$kind PID $pid did not stop" >&2; return 1;
  }
  return 0
}
recover_stale_run() {
  local old_server label stale_lock
  if [ -e "$STATE_DIR" ]; then
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] && [ -O "$STATE_DIR" ] || {
      echo "refusing unowned harness state $STATE_DIR" >&2; return 1;
    }
    chmod 700 "$STATE_DIR"
  else
    mkdir -m 700 "$STATE_DIR" || { echo "could not acquire $STATE_DIR" >&2; return 1; }
  fi
  # mkdir is the mutex. A contender never removes `active`: only a process that
  # found a dead fingerprint atomically renames the stale lock out of the way.
  if ! mkdir "$STATE_DIR/active" 2>/dev/null; then
    owner="$(cat "$STATE_DIR/owner.pid" 2>/dev/null || true)"
    expected="$(cat "$STATE_DIR/owner.started" 2>/dev/null || true)"
    actual="$(process_start "$owner")"
    if [ -z "$owner" ] || [ -z "$expected" ]; then
      echo "harness lease ownership is still being published; refusing to steal it" >&2
      return 1
    fi
    [ -z "$actual" ] || [ "$actual" != "$expected" ] || {
      echo "another SRE registry verifier is active as PID $owner" >&2; return 1;
    }
    stale_lock="$STATE_DIR/active.stale.$TAG"
    mv "$STATE_DIR/active" "$stale_lock" 2>/dev/null || {
      echo "another verifier is recovering the stale harness state" >&2; return 1;
    }
    if ! mkdir "$STATE_DIR/active" 2>/dev/null; then
      rm -rf "$stale_lock"
      echo "another verifier acquired the harness state" >&2; return 1
    fi
    rm -rf "$stale_lock"
  fi
  # Publish before any Docker/process recovery. A contender treats the fresh
  # directory as busy during this small publication window, never as stale.
  [ -z "${ANDYUR_SRE_LOCK_PUBLISH_DELAY:-}" ] || sleep "$ANDYUR_SRE_LOCK_PUBLISH_DELAY"
  rm -f "$STATE_DIR/owner.pid" "$STATE_DIR/owner.started" "$STATE_DIR/owner.token"
  printf '%s\n' "$$" >"$STATE_DIR/owner.pid"
  process_start "$$" >"$STATE_DIR/owner.started"
  printf '%s\n' "$OWNER_TOKEN" >"$STATE_DIR/owner.token"
  if [ -f "$STATE_DIR/server" ]; then
    old_server="$(cat "$STATE_DIR/server")"
    label="$(docker inspect -f '{{index .Config.Labels "andyur.harness"}}' "$old_server" 2>/dev/null || true)"
    [ -z "$label" ] || [ "$label" = "sre-registry-e2e" ] || {
      echo "refusing unowned stale container $old_server" >&2; return 1;
    }
    [ -z "$label" ] || docker rm -f "$old_server" >/dev/null
  fi
  if [ -f "$STATE_DIR/litellm" ]; then
    old_litellm="$(cat "$STATE_DIR/litellm")"
    label="$(docker inspect -f '{{index .Config.Labels "andyur.harness"}}' "$old_litellm" 2>/dev/null || true)"
    [ -z "$label" ] || [ "$label" = "sre-registry-e2e" ] || {
      echo "refusing unowned stale container $old_litellm" >&2; return 1;
    }
    [ -z "$label" ] || docker rm -f "$old_litellm" >/dev/null
  fi
  recover_process obs 'demos/sre-triage/observability.py'
  recover_process tix 'demos/sre-triage/tickets.py'
  rm -f "$STATE_DIR/server" "$STATE_DIR/obs.pid" "$STATE_DIR/obs.started" \
    "$STATE_DIR/tix.pid" "$STATE_DIR/tix.started" \
    "$STATE_DIR/litellm"
  printf '%s\n' "$SERVER" >"$STATE_DIR/server"
  printf '%s\n' "$LITELLM" >"$STATE_DIR/litellm"
}

say() { printf '\n== %s ==\n' "$*"; }
# Narration (ANDYUR_SRE_NARRATE=1, the sre-demo default; sre-verify leaves it
# off). A presentation layer for an operator or design-partner audience: after
# each phase banner it says, in plain language, what that hop proves and which
# external component proves it. It prints text only. It adds no check, changes
# no check, and never touches PASS/FAIL or EXPECTED_PASS.
NARRATE="${ANDYUR_SRE_NARRATE:-0}"
tell() { [ "$NARRATE" = 1 ] || return 0; printf '   | %s\n' "$@"; }
ok() { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
entry() {
  local sid="$1" out; shift
  out="$(docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
    -parentID "spiffe://$TD/agent/node" -spiffeID "$sid" -jwtSVIDTTL 1200 \
    -entryExpiry "$(( $(date +%s) + 1800 ))" \
    "$@" 2>&1)" || {
      printf '%s' "$out" | grep -q 'AlreadyExists' || { echo "$out" >&2; return 1; }
    }
}
preserve_artifacts() {
  ARTIFACT_DIR="${ARTIFACT_DIR:-$ARTIFACT_ROOT/${RUN_ID:-failed-$TAG}}"
  mkdir -p "$ARTIFACT_DIR"
  cp "$WORK"/*.log "$ARTIFACT_DIR/" 2>/dev/null || true
  docker logs "$SERVER" >"$ARTIFACT_DIR/server.log" 2>&1 || true
  docker logs "$LITELLM" >"$ARTIFACT_DIR/litellm.log" 2>&1 || true
  if [ -n "$RUN_ID" ]; then
    mkdir -p "$ARTIFACT_DIR/run"
    docker cp "$SERVER:/app/data/workspace/agents/$AGENT/runs/$RUN_ID/." \
      "$ARTIFACT_DIR/run/" >/dev/null 2>&1 || true
  fi
  printf 'run_id=%s\ntrace_id=%s\nserver=%s\n' \
    "$RUN_ID" "$TRACE_ID" "$SERVER" >"$ARTIFACT_DIR/metadata.env"
  prune_artifacts
}
cleanup() {
  local rc=$?
  if [ "$ARTIFACT_READY" != 0 ] && [ "$ARTIFACT_FINALIZED" = 0 ]; then
    preserve_artifacts || rc=1
    scan_artifacts || rc=1
    ARTIFACT_FINALIZED=1
  fi
  if [ "$rc" -ne 0 ]; then
    echo "--- server diagnostics ---" >&2
    docker logs "$SERVER" 2>&1 | tail -80 >&2 || true
  fi
  if [ -n "${OBS_PID:-}" ]; then
    stop_recorded_process obs 'demos/sre-triage/observability.py' "$OBS_PID" || rc=1
  fi
  if [ -n "${TIX_PID:-}" ]; then
    stop_recorded_process tix 'demos/sre-triage/tickets.py' "$TIX_PID" || rc=1
  fi
  for p in ${AS_PID:-} ${LOGIN_PID:-}; do kill "$p" 2>/dev/null || true; done
  [ "${OPENBAO_UP:-0}" = 1 ] && bash "${GATE_HERE:-$HERE}/infra/openbao/openbao-gate.sh" down >/dev/null 2>&1 || true
  # opa_stack_down resets HERE, so restore it after for any later use.
  [ "${OPA_UP:-0}" = 1 ] && { opa_stack_down >/dev/null 2>&1 || true; HERE="${GATE_HERE:-$HERE}"; }
  docker rm -f "$LITELLM" >/dev/null 2>&1 || true
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  [ -z "$RUN_ID" ] || docker rm -f "andyur-run-$RUN_ID" >/dev/null 2>&1 || true
  selectors="docker:label:andyur.role:$SERVER_ROLE docker:label:andyur.role:$OPERATOR_ROLE docker:label:andyur.role:$WORKER_ROLE"
  [ -z "$RUN_ID" ] || selectors="docker:label:andyur.run_id:$RUN_ID $selectors"
  for selector in $selectors; do
    ids="$(docker exec andyur-spire-server /opt/spire/bin/spire-server entry show \
      -selector "$selector" -output json 2>/dev/null \
      | python3 -c 'import json,sys; print("\n".join(
          e["id"] for e in json.load(sys.stdin).get("entries", [])))' 2>/dev/null)" \
      || { echo "could not enumerate SPIRE entries for $selector" >&2; rc=1; ids=""; }
    for id in $ids; do
      docker exec andyur-spire-server /opt/spire/bin/spire-server \
        entry delete -entryID "$id" >/dev/null 2>&1 \
        || { echo "could not delete SPIRE entry $id" >&2; rc=1; }
    done
  done
  rm -rf "$WORK"
  if [ "$(cat "$STATE_DIR/owner.token" 2>/dev/null || true)" = "$OWNER_TOKEN" ]; then
    rm -f "$STATE_DIR"/* 2>/dev/null || true
    rmdir "$STATE_DIR/active" 2>/dev/null || true
  fi
  return "$rc"
}
trap cleanup EXIT

# Failure seam proving EXIT never writes through an artifact path that has not
# passed ownership, marker, and symlink validation. Inert in normal use.
[ -z "${ANDYUR_SRE_FAIL_BEFORE_ARTIFACTS:-}" ] \
  || { echo "injected failure before artifact validation" >&2; exit 1; }

operator_api() {
  local method="$1" path="$2" data="${3:-}"
  docker run --rm --network "$NET" --label "andyur.role=$OPERATOR_ROLE" \
    -v "$SOCK:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_SERVER_URL="http://$SERVER:8642" \
    ${data:+-e ANDYUR_API_DATA="$data"} \
    --entrypoint python andyur-runner -c '
import os,sys,httpx
from andyur import identity
method,path=sys.argv[1:3]
kw={"headers":identity.auth_header(),"timeout":20}
if "ANDYUR_API_DATA" in os.environ: kw["content"]=os.environ["ANDYUR_API_DATA"]
r=httpx.request(method, os.environ["ANDYUR_SERVER_URL"]+path,
                headers={**kw.pop("headers"),"content-type":"application/json"}, **kw)
print(r.text)
raise SystemExit(0 if r.is_success else 1)
' "$method" "$path"
}

user_api() {
  # Like operator_api, but ALSO presents dana's real IdP token as
  # X-Andyur-User-Token. Under USER_AUTH the operator SVID is the caller seam
  # and this header is WHO the agent is owned by / the run acts for -- so the
  # created agent is dana's and her token becomes the run's RFC 8693 subject.
  local method="$1" path="$2" data="${3:-}"
  docker run --rm --network "$NET" --label "andyur.role=$OPERATOR_ROLE" \
    -v "$SOCK:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_SERVER_URL="http://$SERVER:8642" \
    -e ANDYUR_USER_TOKEN="$DANA_TOKEN" \
    ${data:+-e ANDYUR_API_DATA="$data"} \
    --entrypoint python andyur-runner -c '
import os,sys,httpx
from andyur import identity
method,path=sys.argv[1:3]
headers={**identity.auth_header(),"content-type":"application/json",
         "X-Andyur-User-Token":os.environ["ANDYUR_USER_TOKEN"]}
kw={"headers":headers,"timeout":20}
if "ANDYUR_API_DATA" in os.environ: kw["content"]=os.environ["ANDYUR_API_DATA"]
r=httpx.request(method, os.environ["ANDYUR_SERVER_URL"]+path, **kw)
print(r.text)
raise SystemExit(0 if r.is_success else 1)
' "$method" "$path"
}

# Filesystem-only seam for the retention contract. It never touches Docker,
# SPIRE, a model, or a network endpoint and is inert in normal use.
if [ -n "${ANDYUR_SRE_ARTIFACT_TEST_ONLY:-}" ]; then
  trap - EXIT
  prepare_artifact_root
  prune_artifacts
  rm -rf "$WORK"
  exit 0
fi

# Filesystem-only seam proving the exact retained-bundle scanner rejects
# credential material. This executes the production scanner, not a copy.
if [ -n "${ANDYUR_SRE_SCAN_TEST_DIR:-}" ]; then
  trap - EXIT
  ARTIFACT_DIR="$ANDYUR_SRE_SCAN_TEST_DIR"
  scan_artifacts
  rm -rf "$WORK"
  exit 0
fi

# Process-only seam for the exact normal-cleanup primitive. Tests provide the
# recorded PID/start fingerprint and verify both owned-stop and mismatch-refusal.
if [ "${ANDYUR_SRE_PROCESS_CLEANUP_TEST_SPAWN:-}" = 1 ]; then
  trap - EXIT
  mkdir -p "$STATE_DIR"
  sleep 60 & test_pid=$!
  record_process test "$test_pid"
  stop_recorded_process test sleep "$test_pid"
  kill -0 "$test_pid" 2>/dev/null \
    && { echo "owned cleanup test child survived" >&2; exit 1; }
  rm -rf "$WORK" "$STATE_DIR"
  exit 0
fi
if [ -n "${ANDYUR_SRE_PROCESS_CLEANUP_TEST_PID:-}" ]; then
  trap - EXIT
  stop_recorded_process test "${ANDYUR_SRE_PROCESS_CLEANUP_TEST_NEEDLE:?}" \
    "$ANDYUR_SRE_PROCESS_CLEANUP_TEST_PID"
  rm -rf "$WORK"
  exit 0
fi

# Narrow fault seam for the concurrency regression: exercise the real stable
# lease without building images or touching SPIRE. It is inert in normal use.
if [ -n "${ANDYUR_SRE_LOCK_HOLD_SECONDS:-}" ]; then
  lock_only_cleanup() {
    rc=$?
    if [ "$(cat "$STATE_DIR/owner.token" 2>/dev/null || true)" = "$OWNER_TOKEN" ]; then
      rm -f "$STATE_DIR"/* 2>/dev/null || true
      rmdir "$STATE_DIR/active" 2>/dev/null || true
    fi
    rm -rf "$WORK"
    return "$rc"
  }
  trap lock_only_cleanup EXIT
  recover_stale_run
  sleep "$ANDYUR_SRE_LOCK_HOLD_SECONDS"
  exit 0
fi

docker inspect andyur-spire-server >/dev/null 2>&1 \
  && docker inspect andyur-spire-agent >/dev/null 2>&1 \
  || { echo "start the container SPIRE stack first: ./run.sh spire-docker up"; exit 1; }
docker network inspect "$NET" >/dev/null
recover_stale_run
prepare_artifact_root

say "ensure the shared trace backend is ready"
if ! curl -sf http://127.0.0.1:16686/api/services >/dev/null 2>&1; then
  docker compose -f "$HERE/infra/docker-compose.yml" up -d jaeger >/dev/null
fi
for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:16686/api/services >/dev/null 2>&1 && break
  sleep 1
done
curl -sf http://127.0.0.1:16686/api/services >/dev/null \
  || { echo "Jaeger did not become ready on http://127.0.0.1:16686"; exit 1; }
ok "Jaeger ready"

say "build the shipped server and runner artifacts"
docker build -q -f "$HERE/Dockerfile.server" -t andyur-server "$HERE" >/dev/null
bash "$HERE/run.sh" sandbox-image --quiet >/dev/null
ok "images built"

# ---- the external Authorization Server + IdP (reference AS), host-side --------
# This gate no longer dev-mints. refas is a real OIDC IdP + RFC 8693 AS. dana
# logs in AT it; the Andyur server validates her login as the IdP; the per-run
# sidecar exchanges her token (subject) + the run's SVID (actor) THERE. It binds
# all interfaces so the host (login, the host-side resource servers) reaches it
# at 127.0.0.1 and the containers (server, runner) reach it at
# host.docker.internal. The issuer is the 127.0.0.1 URL -- a STRING the token
# carries -- while each container validator is handed an explicit
# host.docker.internal JWKS URL, so no validator ever has to resolve a name it
# cannot reach (oidc.py/asclient.py fetch keys from the configured JWKS, and
# compare iss as a string).
say "start the external AS + IdP (reference AS, real login + RFC 8693)"
tell "WHAT THIS PROVES: the platform does not mint its own authority." \
     "An external OpenID Connect provider + OAuth authorization server (the" \
     "reference AS) comes up. dana, the on-call engineer, signs in there with" \
     "a real Authorization Code + PKCE login. Her login token becomes the" \
     "subject of everything the agent does later. At no point does Andyur" \
     "invent a user, and the server validates her token as a relying party." \
     "In production this slot is the enterprise AS (Keycloak, Okta, Entra," \
     "Ping, Curity) through the same adapter interface; the reference AS is" \
     "used here because it supports full RFC 8693 delegation and runs offline."
[ -d "$HERE/infra/reference-as/patches/go-oidc" ] \
  || bash "$HERE/infra/reference-as/patches/apply.sh" >/dev/null
( cd "$HERE/infra/reference-as" && go build -o "$WORK/refas" . ) \
  || { echo "refas build failed (go required)"; exit 1; }
mkdir -p "$WORK/asdata"
# dana is entitled, at the AS, to the AS-VOCABULARY actions (telemetry:read,
# tickets:*), and to the two logical resources the registry pins tools to. The
# run asks in Andyur's logical vocabulary (obs:read, tickets:comment); the
# ADR-010 scope map on the run container translates each to the AS vocabulary at
# exchange time.
# Least privilege, mirroring the REGISTRY ceiling (obs:read, tickets:read,
# tickets:comment -> telemetry:read, tickets:read, tickets:write). dana is NOT
# entitled to tickets:delete and the AS ceiling does not grant it: the run's
# subject token + SVID live in the (threat-model: compromised) run container, so
# the AS -- not the honest runner -- must be the thing that refuses an action the
# registry never granted. A direct exchange asking tickets:delete is refused
# BELOW; keeping it out of dana's entitlement is what makes that refusal real.
cat > "$WORK/asdata/users.json" <<EOF
{"dana": {"entitlements": ["telemetry:read","tickets:read","tickets:write"],
          "resources": ["resource:telemetry","resource:tickets","telemetry","tickets","checkout-service","checkout"]}}
EOF
# Keyed on the AGENT name the AS reads from the actor SVID path
# (spiffe://.../agent/<AGENT>/run/<id>), which is $AGENT = sre-oncall.
cat > "$WORK/asdata/ceilings.json" <<EOF
{"$AGENT": {"actions": ["telemetry:read","tickets:read","tickets:write"],
            "audiences": ["resource:telemetry","resource:tickets"]}}
EOF
ANDYUR_REFAS_ADDR=":$AS_PORT" ANDYUR_REFAS_ISSUER="$AS_HOST" \
ANDYUR_REFAS_DATA="$WORK/asdata" ANDYUR_REFAS_ANDYUR_URL="$BASE" \
ANDYUR_REFAS_RESOURCES="resource:telemetry,resource:tickets" \
ANDYUR_REFAS_USERS="dana:dana-password" \
  "$WORK/refas" >"$WORK/as.log" 2>&1 &
AS_PID=$!
for _ in $(seq 1 60); do
  curl -sf "$AS_HOST/.well-known/openid-configuration" >/dev/null 2>&1 && break; sleep 0.5
done
curl -sf "$AS_HOST/.well-known/openid-configuration" >/dev/null \
  && ok "external AS + IdP on :$AS_PORT" \
  || { bad "AS never came up"; cat "$WORK/as.log"; exit 1; }

# dana signs in AT the AS -- real Authorization Code + PKCE, headless. Her token
# becomes the run's RFC 8693 subject; the server (USER_AUTH) validated it.
export ANDYUR_HOME="$WORK/home"; mkdir -p "$ANDYUR_HOME"
AS_LOGIN="$AS_HOST" AS_AUD="$BASE" VENV="$HERE/.venv" HERE="$HERE" "$HERE/.venv/bin/python" - <<'PY' >"$WORK/login.log" 2>&1
import re, subprocess, os, urllib.request, urllib.parse, http.cookiejar, sys
issuer = os.environ["AS_LOGIN"]
p = subprocess.Popen([os.environ["VENV"] + "/bin/python", "-u", "-m", "andyur.cli",
                      "auth", "login", "--issuer", issuer, "--no-browser",
                      "--audience", os.environ["AS_AUD"],
                      "--scope", "openid telemetry:read tickets:write"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                     cwd=os.environ["HERE"], env={**os.environ, "PYTHONUNBUFFERED": "1"})
url = None
for line in p.stdout:
    m = re.search(r'(http\S*/authorize\?\S+)', line)
    if m and not url:
        url = m.group(1)
        cj = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        page = op.open(url, timeout=20).read().decode()
        action = re.search(r'<form action="([^"]+)"', page).group(1)
        op.open(urllib.request.Request(action, data=urllib.parse.urlencode(
            {"username": "dana", "password": "dana-password"}).encode()), timeout=20).read()
    print(line, end="")
sys.exit(p.wait(timeout=90))
PY
DANA_TOKEN="$("$HERE/.venv/bin/python" -c "import json,os;print(json.load(open(os.path.join(os.environ['ANDYUR_HOME'],'credentials.json')))['access_token'])" 2>/dev/null || true)"
[ -n "$DANA_TOKEN" ] && ok "dana signed in at the AS (real login)" \
  || { bad "dana login failed"; cat "$WORK/login.log"; exit 1; }

entry "spiffe://$TD/control-plane" -selector "docker:label:andyur.role:$SERVER_ROLE"
entry "spiffe://$TD/operator" -selector "docker:label:andyur.role:$OPERATOR_ROLE"
entry "spiffe://$TD/worker" -selector "docker:label:andyur.role:$WORKER_ROLE"

for role_and_expected in "$SERVER_ROLE:spiffe://$TD/control-plane" \
                         "$OPERATOR_ROLE:spiffe://$TD/operator" \
                         "$WORKER_ROLE:spiffe://$TD/worker"; do
  role="${role_and_expected%%:*}"; expected_role="${role_and_expected#*:}"
  got=""
  for _ in $(seq 1 15); do
    got="$(docker run --rm --network "$NET" --label "andyur.role=$role" \
      -v "$SOCK:/run/spire/sockets:ro" \
      -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
      --entrypoint python andyur-runner -c '
import jwt
from andyur import identity
print(jwt.decode(identity.fetch_token(), options={"verify_signature":False})["sub"])
' 2>/dev/null || true)"
    [ "$got" = "$expected_role" ] && break
    sleep 1
  done
  [ "$got" = "$expected_role" ] \
    || { echo "$role identity did not propagate (got ${got:-none})"; exit 1; }
done

# PHASE 3 (external policy engine): the server's authorization decisions go to a
# real OPA over the OpenID AuthZEN standard, not the builtin PDP. Stand up the
# hardened stack (signed-bundle OPA + AuthZEN shim) BEFORE the server, so it can
# be pointed at it. The shim binds 0.0.0.0 so the server CONTAINER reaches it via
# host.docker.internal. NB: opa_stack_up resets HERE and runs the shim as our
# child, so we source + restore HERE around it.
say "start the external policy engine (OPA + AuthZEN shim, signed bundle)"
tell "WHAT THIS PROVES: authorization decisions leave the process." \
     "The server is pointed at a real Open Policy Agent, loaded with a SIGNED" \
     "policy bundle, behind an OpenID AuthZEN shim. Every decision the run" \
     "needs (load its context, check a scope) travels to OPA and back. A" \
     "policy change is a bundle change, not a redeploy. At the end, OPA's" \
     "own decision log is checked to prove the server really consulted it."
export ANDYUR_SRE_OPA_PORT="${ANDYUR_SRE_OPA_PORT:-8191}"
export OPA_PORT="$ANDYUR_SRE_OPA_PORT" BUNDLE_PORT=8393 SHIM_PORT="${ANDYUR_SRE_SHIM_PORT:-8292}" SHIM_HOST=0.0.0.0
# shellcheck disable=SC1091
. "$GATE_HERE/infra/opa/opa-stack.sh"
opa_stack_up "$GATE_HERE/infra/opa" >/dev/null 2>&1 \
  && { HERE="$GATE_HERE"; OPA_UP=1; ok "external OPA policy engine up (signed bundle, AuthZEN shim)"; } \
  || { HERE="$GATE_HERE"; bad "external OPA policy engine did not come up"; exit 1; }

say "start the real server image with its bundled registry"
tell "WHAT THIS PROVES: the shipped artifact, not a test double." \
     "The exact server image an operator would deploy starts with the" \
     "approved agent registry baked in. It runs with user auth ON, so it" \
     "will refuse any caller who merely asserts a username. Its identity" \
     "comes from SPIRE: the container is attested by its Docker labels and" \
     "issued a SPIFFE ID, with no shared secret on disk."
docker run -d --name "$SERVER" --network "$NET" --label "andyur.role=$SERVER_ROLE" \
  --label andyur.harness=sre-registry-e2e \
  --add-host host.docker.internal:host-gateway \
  -v "$SOCK:/run/spire/sockets:ro" \
  -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e ANDYUR_PROFILE=dev -e ANDYUR_AGENT_AUTH=on -e ANDYUR_USER_AUTH=on \
  -e ANDYUR_OIDC_ISSUER="$AS_HOST" -e ANDYUR_OIDC_JWKS="$AS_FROM_CONTAINER/jwks" \
  -e ANDYUR_OIDC_AUDIENCE="$BASE" \
  -e ANDYUR_AS_PROVIDER=reference \
  -e ANDYUR_AS_TOKEN_ENDPOINT="$AS_FROM_CONTAINER/token" \
  -e ANDYUR_AS_ISSUER="$AS_HOST" -e ANDYUR_AS_JWKS="$AS_FROM_CONTAINER/jwks" \
  -e ANDYUR_PDP=authzen \
  -e ANDYUR_PDP_URL="http://host.docker.internal:$SHIM_PORT" \
  -e ANDYUR_REQUIRE_RUN_SVID=on -e ANDYUR_RUN_TOKEN_SECRET="$RUN_SECRET" \
  -e ANDYUR_OTEL_ENDPOINT=http://host.docker.internal:4318 \
  -p 127.0.0.1:18679:8642 andyur-server >/dev/null
docker inspect -f '{{.State.Running}}' "$SERVER" | grep -q true \
  || { docker logs "$SERVER"; exit 1; }
for _ in $(seq 1 40); do curl -sf "$BASE/health" >/dev/null && break; sleep 1; done
curl -sf "$BASE/health" >/dev/null || { docker logs "$SERVER"; exit 1; }
ok "server healthy"

if [ "${ANDYUR_LLM:-ollama}" = api ]; then
  [ -n "${ANTHROPIC_API_KEY:-}" ] \
    || { echo "ANTHROPIC_API_KEY is required for ANDYUR_LLM=api" >&2; exit 1; }

  # PHASE 2 (vault): the model credential is not injected as a raw env var; it
  # comes FROM the sealed OpenBao vault under the least-privilege model-broker
  # policy. The operator seeds the vault and the run reads the key back with a
  # model-broker-scoped token -- the real operator/daemon->broker path, headless.
  # NOT `server -dev` (the stack forbids it): a real init/unseal/configure.
  say "seed + read the LLM credential from the sealed vault (OpenBao)"
tell "WHAT THIS PROVES: the model API key never lives in config or env." \
     "A real OpenBao vault is initialised, unsealed and configured (not the" \
     "dev server). The operator seeds the key once. The run reads it back" \
     "with a token scoped to the model-broker policy and nothing else; a" \
     "read of an unrelated path with that token is denied. The key is then" \
     "forwarded to the model proxy by reference, never on a command line."
  export ANDYUR_OPENBAO_PORT="${ANDYUR_SRE_OPENBAO_PORT:-8211}"
  OBGATE="$HERE/infra/openbao/openbao-gate.sh"
  OPENBAO_UP=1
  bash "$OBGATE" up \
    && ok "sealed OpenBao up (init/unseal/configure, not server -dev)" \
    || { bad "sealed OpenBao did not come up"; exit 1; }
  printf '%s' "$ANTHROPIC_API_KEY" | bash "$OBGATE" store \
    || { bad "could not seed the model credential into the vault"; exit 1; }
  VAULT_KEY="$(bash "$OBGATE" read)"
  [ "$VAULT_KEY" = "$ANTHROPIC_API_KEY" ] \
    && ok "LLM credential read from the sealed vault via the model-broker policy" \
    || { bad "vault read did not return the model credential"; exit 1; }
  bash "$OBGATE" deny \
    && ok "model-broker policy is least-privilege (denied an unrelated path)" \
    || bad "the model-broker policy read a path it must not"

  LITELLM_IMAGE="$("$HERE/.venv/bin/python" - "$HERE/infra/docker-compose.yml" <<'PY'
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))["services"]["litellm"]["image"])
PY
)"
  # The vault-sourced model credential is FORWARDED (-e ANTHROPIC_API_KEY, no
  # value) from this shell's env, never `-e KEY=value` which would put it on the
  # docker argv for any host `ps` to read. Same for the LiteLLM master key.
  ANTHROPIC_API_KEY="$VAULT_KEY" LITELLM_MASTER_KEY="$LITELLM_MASTER_KEY" \
  docker run -d --name "$LITELLM" --network "$NET" \
    --label andyur.harness=sre-registry-e2e \
    --add-host host.docker.internal:host-gateway \
    -e ANTHROPIC_API_KEY \
    -e "ANTHROPIC_API_BASE=${ANTHROPIC_API_BASE:-https://api.anthropic.com}" \
    -e LITELLM_MASTER_KEY \
    -e OTEL_EXPORTER=otlp_http \
    -e OTEL_EXPORTER_OTLP_ENDPOINT=http://host.docker.internal:4318 \
    -e OTEL_SERVICE_NAME=andyur-litellm \
    -v "$HERE/infra/litellm/config.yaml:/app/config.yaml:ro" \
    --entrypoint /bin/sh "$LITELLM_IMAGE" -ec \
    'exec litellm --config /app/config.yaml --host 0.0.0.0 --port 4000 --telemetry False' \
    >/dev/null
  for _ in $(seq 1 30); do
    docker exec "$LITELLM" python -c \
      "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=2)" \
      >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$LITELLM" python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=2)" \
    >/dev/null 2>&1 \
    || { docker logs "$LITELLM"; echo "shared LiteLLM did not become ready"; exit 1; }
  ok "shared LiteLLM ready"
fi

say "start the two real resource servers"
tell "WHAT THIS PROVES: the tools enforce, not just the platform." \
     "Two MCP resource servers come up (telemetry, tickets), each with its" \
     "own policy enforcement point. They discover the external AS's issuer" \
     "and keys themselves and accept ONLY tokens that AS issued, bound to" \
     "their own audience. A token Andyur minted locally is turned away." \
     "If the platform were compromised, the tools would still say no."
for url in http://127.0.0.1:8797/mcp http://127.0.0.1:8798/mcp; do
  curl -s --max-time 1 -o /dev/null "$url" 2>/dev/null \
    && { echo "refusing occupied resource endpoint $url"; exit 1; }
done
# The resource PEPs validate the AS-issued tool token: ANDYUR_AS_ISSUER makes
# them DISCOVER refas's issuer + JWKS from its openid-configuration (host-side,
# so 127.0.0.1 is reachable) and enforce iss + the logical audience.
ANDYUR_SERVER_URL="$BASE" ANDYUR_OBS_PORT=8797 ANDYUR_TOOL_HOST=0.0.0.0 \
  ANDYUR_AS_ISSUER="$AS_HOST" ANDYUR_TOOL_SCOPE_MAP="$TOOL_SCOPE_MAP" \
  "$HERE/.venv/bin/python" "$HERE/demos/sre-triage/observability.py" \
  >"$WORK/obs.log" 2>&1 &
OBS_PID=$!
record_process obs "$OBS_PID"
ANDYUR_SERVER_URL="$BASE" ANDYUR_TICKETS_PORT=8798 ANDYUR_TOOL_HOST=0.0.0.0 \
  ANDYUR_AS_ISSUER="$AS_HOST" ANDYUR_TOOL_SCOPE_MAP="$TOOL_SCOPE_MAP" \
  "$HERE/.venv/bin/python" "$HERE/demos/sre-triage/tickets.py" \
  >"$WORK/tix.log" 2>&1 &
TIX_PID=$!
record_process tix "$TIX_PID"
for _ in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:8797/mcp \
    && curl -s -o /dev/null http://127.0.0.1:8798/mcp && break
  sleep 1
done
kill -0 "$OBS_PID" && kill -0 "$TIX_PID" \
  || { cat "$WORK/obs.log" "$WORK/tix.log"; exit 1; }
curl -s -o /dev/null http://127.0.0.1:8797/mcp \
  && curl -s -o /dev/null http://127.0.0.1:8798/mcp \
  || { echo "resource readiness failed"; exit 1; }
ok "resources reachable"

say "resolve the approved definition and create only an immutable binding"
tell "WHAT THIS PROVES: the operator approves, the user only binds." \
     "The on-call agent definition (model, tools, scope ceiling) comes from" \
     "the approved registry and cannot be edited at creation. dana, as the" \
     "authenticated owner, creates a binding to it. Her real login is what" \
     "the run will act on behalf of; the server refuses an asserted user."
resolved="$(operator_api GET "/v1/registry/agents/$REGISTRY_ID/resolve")"
echo "$resolved" | EXPECTED_ID="$REGISTRY_ID" python3 -c 'import json,os,sys
r=json.load(sys.stdin)
assert r["agent_id"]==os.environ["EXPECTED_ID"]
assert isinstance(r["model"], str) and r["model"]
assert {x["resource_id"] for x in r["tools"]}=={
 "resource:telemetry","resource:tickets"}'
resolved_model="$(echo "$resolved" | python3 -c 'import json,sys; print(json.load(sys.stdin)["model"])')"
# Owned by dana (the authenticated IdP user), so her real login is the run's
# RFC 8693 subject -- no acting_user assertion (USER_AUTH refuses it).
user_api POST /agents \
  "{\"name\":\"sre-oncall\",\"description\":\"SRE registry E2E\",\"registry_agent_id\":\"$REGISTRY_ID\"}" \
  >/dev/null
ceiling="$(user_api GET /agents/sre-oncall/ceiling)"
echo "$ceiling" | grep -q 'resource:telemetry' && ok "registry ceiling materialized" \
  || bad "registry ceiling missing: $ceiling"

trigger='{"reason":"PAGE: INC-4471 checkout-service 5xx spike. Triage and comment.","subject_context":{"service":"checkout-service"},"scope":["files:read","files:write","obs:read","tickets:read","tickets:comment","tickets:close"]}'
run_json="$(user_api POST /agents/sre-oncall/trigger "$trigger")"
actual_run="$(echo "$run_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')"
[ "$actual_run" = "$RUN_ID" ] && { echo "unexpected fixed-id collision"; exit 1; } || true
RUN_ID="$actual_run"
ARTIFACT_DIR="$ARTIFACT_ROOT/$RUN_ID"
mkdir -p "$ARTIFACT_DIR"
printf '%s\n' "$resolved" >"$ARTIFACT_DIR/registry-resolution.json"
printf '%s\n' "$ceiling" >"$ARTIFACT_DIR/materialized-ceiling.json"
assignment="$(docker run --rm --network "$NET" \
  --label "andyur.role=$WORKER_ROLE" \
  -v "$SOCK:/run/spire/sockets:ro" \
  -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e SERVER="http://$SERVER:8642" -e RUN_ID="$RUN_ID" -e TAG="$TAG" \
  --entrypoint python andyur-runner -c '
import json, os, httpx
from andyur import identity
r = httpx.post(os.environ["SERVER"] + "/worker/heartbeat",
    headers=identity.auth_header(), timeout=15,
    json={"worker_id": "sre-harness-" + os.environ["TAG"], "slots": 1,
          # This worker runs the agent in the dev profile (its run container
          # sets ANDYUR_PROFILE=dev, matching the dev server), so it reports dev
          # honestly rather than claiming a prod posture it does not have.
          "slots_free": 1, "running": [], "profile": "dev"})
r.raise_for_status()
matches = [a for a in r.json()["assignments"] if a["id"] == os.environ["RUN_ID"]]
if len(matches) != 1:
    raise SystemExit("control plane did not assign the triggered run exactly once")
print(json.dumps(matches[0]))
')"
token="$(printf '%s' "$assignment" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_token"])')"
entry "spiffe://$TD/agent/$AGENT/run/$RUN_ID" \
  -selector "docker:label:andyur.run_id:$RUN_ID" \
  -selector "docker:label:andyur.agent:$AGENT"
expected="spiffe://$TD/agent/$AGENT/run/$RUN_ID"
attested=""
run_svid=""
for _ in $(seq 1 15); do
  run_svid="$(docker run --rm --network "$NET" \
    --label "andyur.run_id=$RUN_ID" --label "andyur.agent=$AGENT" \
    -v "$SOCK:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    --entrypoint python andyur-runner -c '
from andyur import identity
print(identity.fetch_token())
' 2>/dev/null || true)"
  attested="$(RUN_SVID="$run_svid" python3 -c '
import jwt,os
try: print(jwt.decode(os.environ["RUN_SVID"], options={"verify_signature":False})["sub"])
except Exception: pass
')"
  [ "$attested" = "$expected" ] && break
  sleep 1
done
[ "$attested" = "$expected" ] \
  || { echo "per-run SVID did not propagate (got ${attested:-none})"; exit 1; }

token_only_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "X-Andyur-Run-Token: $token" -H 'content-type: application/json' \
  --data '{"audience":"resource:telemetry"}' "$BASE/oauth/token")"
[ "$token_only_code" = 401 ] \
  && ok "token-only replay refused in strict mode" \
  || bad "token-only replay returned HTTP $token_only_code"

say "freeze the refusals while the run is live"
tell "WHAT THIS PROVES: the ceiling is enforced where it matters." \
     "While the run is alive, a probe performs the same RFC 8693 exchange" \
     "the agent's sidecar does: dana as subject, the run's attested SVID as" \
     "actor. It then tries to step outside the ceiling. Closing a ticket:" \
     "refused. Reaching another service: refused. Reusing a token across" \
     "audiences: refused. Asking the AS directly for tickets:delete, a" \
     "scope the registry never granted: refused BY THE AS, not by Andyur." \
     "The one allowed action, on its own service, succeeds. That asymmetry" \
     "is the proof that the authorization server is the enforcement point."
# The probe mints exactly as the sidecar does: an RFC 8693 exchange at refas.
# Its ACTOR SVID must carry the AS audience (AS_ISSUER), not Andyur's -- handing
# an Andyur-audience SVID to an external relying party is the cross-RP reuse the
# sidecar refuses -- so fetch a run SVID scoped to the AS.
probe_actor="$(docker run --rm --network "$NET" --user 0 \
  --label "andyur.run_id=$RUN_ID" --label "andyur.agent=$AGENT" \
  -v "$SOCK:/run/spire/sockets:ro" \
  --entrypoint /opt/spire/bin/spire-agent ghcr.io/spiffe/spire-agent:1.11.2 \
  api fetch jwt -audience "$AS_HOST" -socketPath /run/spire/sockets/api.sock 2>&1 \
  | grep -oE '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1)"
[ -n "$probe_actor" ] || { bad "probe actor SVID (AS audience) not fetched"; exit 1; }
probe="$(PYTHONPATH="$HERE" ANDYUR_PROBE_RUN_TOKEN="$token" ANDYUR_PROBE_SVID="$probe_actor" \
  ANDYUR_PROBE_SUBJECT_TOKEN="$DANA_TOKEN" ANDYUR_PROBE_EXPECTED_ACTOR="$expected" \
  ANDYUR_SERVER_URL="$BASE" \
  ANDYUR_OBS_PORT=8797 ANDYUR_TICKETS_PORT=8798 \
  ANDYUR_PROFILE=dev ANDYUR_AS_PROVIDER=reference ANDYUR_EXCHANGE_TTL=3600 \
  ANDYUR_AS_TOKEN_ENDPOINT="$AS_HOST/token" ANDYUR_AS_ISSUER="$AS_HOST" \
  ANDYUR_AS_JWKS="$AS_HOST/jwks" ANDYUR_AS_CLIENT_ID="client_one" \
  ANDYUR_AS_CLIENT_SECRET="gateway-secret" ANDYUR_AS_RESOURCE_SCOPE="$SCOPE_MAP" \
  "$HERE/.venv/bin/python" "$HERE/infra/sre_probe.py")"
printf '%s\n' "$probe" >"$ARTIFACT_DIR/authority-probes.log"
for expected_probe in "CLOSE REFUSED" "OTHER-SERVICE REFUSED" \
                      "OWN-SERVICE ALLOWED" "CROSS-AUDIENCE REFUSED"; do
  case "$probe" in
    *"$expected_probe"*) ok "$expected_probe" ;;
    *) bad "missing probe result: $expected_probe" ;;
  esac
done
# The red-team result must NAME THE AS'S OWN HTTP STATUS. Matching the bare
# prefix let a purely LOCAL failure satisfy this check with the AS never
# contacted -- so the natural cleanup "the registry never grants close, drop
# it from the scope map" would have turned this permanently green while
# proving nothing. Requiring three status digits binds the pass to an answer
# that only the authorization server can have produced.
case "$probe" in
  *"DELETE-DIRECT REFUSED-BY-AS: "[0-9][0-9][0-9]*)
    ok "DELETE-DIRECT REFUSED-BY-AS (the AS answered, with its status)" ;;
  *)
    bad "missing probe result: DELETE-DIRECT REFUSED-BY-AS with an AS status" ;;
esac

say "run the real labeled runner image"
tell "WHAT THIS PROVES: the end-to-end incident triage, under all of it." \
     "The real runner image starts as a labelled, attested container. The" \
     "agent reads telemetry, reasons with the model through the proxy, and" \
     "comments on the ticket, every hop carrying a narrow, audience-bound," \
     "externally issued token. Afterwards the transcript is scanned: it" \
     "must contain no JWT material, the retained evidence bundle must hold" \
     "no credential, and a single distributed trace must tie it together."
docker run --rm --network "$NET" --entrypoint python andyur-runner -c '
import socket,sys,urllib.request
socket.getaddrinfo(sys.argv[1], 8642)
with urllib.request.urlopen("http://%s:8642/health" % sys.argv[1], timeout=5) as r:
    assert r.status == 200
' "$SERVER" || { bad "runner network cannot resolve/reach the server"; exit 1; }
set +e
runner_model_args=()
if [ "${ANDYUR_LLM:-ollama}" = api ]; then
  runner_model_args=(
    -e "ANDYUR_LITELLM_URL=http://$LITELLM:4000"
    -e "LITELLM_MASTER_KEY=$LITELLM_MASTER_KEY"
  )
fi
# ANDYUR_PROFILE=dev, below, is load-bearing: config.PROFILE defaults to prod,
# and this container set none, so the runner used to come up PROD while the
# SERVER runs dev and the demo tools are served over http. gateway.scheme_refusal
# then (correctly) refuses to carry the run's delegated token over a plaintext
# hop in prod, and the whole run failed at tool egress -- a rot that hid because
# this gate was not in CI. This harness IS a single-machine dev run with http
# descriptors, so dev is the HONEST profile, matching the server; the prod
# https-mTLS-to-tool leg is proven by its own gate. Do not remove this or "fix"
# it by weakening the hardening.
# The per-run sidecar exchanges at the EXTERNAL AS (refas), not Andyur's own
# mint: ANDYUR_AS_TOKEN_ENDPOINT being set makes runner.py choose
# asclient.exchange, presenting dana's login (subject) + the run's SVID (actor).
# AS_ISSUER is the string the issued token carries; AS_JWKS is the
# container-reachable key URL (decoupled, so the container never has to resolve
# the 127.0.0.1 issuer). ANDYUR_PROFILE=dev because the reference AS is a test
# fixture (plaintext users, example key) that as_problems() correctly refuses in
# prod; the prod AS is Keycloak, proven by verify-idp-composed.
docker run --rm --name "andyur-run-$RUN_ID" --network "$NET" \
  --label "andyur.run_id=$RUN_ID" --label "andyur.agent=$AGENT" \
  --add-host host.docker.internal:host-gateway \
  -v "$SOCK:/run/spire/sockets:ro" \
  -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e ANDYUR_SERVER_URL="http://$SERVER:8642" -e ANDYUR_RUN_TOKEN="$token" \
  -e IS_SANDBOX=1 \
  -e ANDYUR_PROFILE=dev \
  -e ANDYUR_AS_PROVIDER=reference -e ANDYUR_EXCHANGE_TTL=3600 \
  -e ANDYUR_AS_TOKEN_ENDPOINT="$AS_FROM_CONTAINER/token" \
  -e ANDYUR_AS_ISSUER="$AS_HOST" \
  -e ANDYUR_AS_JWKS="$AS_FROM_CONTAINER/jwks" \
  -e ANDYUR_AS_CLIENT_ID="client_one" \
  -e ANDYUR_AS_CLIENT_SECRET="gateway-secret" \
  -e ANDYUR_AS_RESOURCE_SCOPE="$SCOPE_MAP" \
  -e ANDYUR_OTEL_ENDPOINT=http://host.docker.internal:4318 \
  -e ANDYUR_LLM="${ANDYUR_LLM:-ollama}" \
  -e ANDYUR_OLLAMA_URL="${ANDYUR_OLLAMA_URL:-http://host.docker.internal:11434}" \
  ${runner_model_args[@]+"${runner_model_args[@]}"} \
  andyur-runner --agent "$AGENT" --run-id "$RUN_ID" \
  2>&1 | tee "$WORK/runner.log"
runner_rc=${PIPESTATUS[0]}
set -e

if [ "${ANDYUR_LLM:-ollama}" = api ]; then
  docker logs "$LITELLM" >"$ARTIFACT_DIR/litellm.log" 2>&1 || true
  grep -Eq 'POST /v1/messages|/v1/messages.*200' "$ARTIFACT_DIR/litellm.log" \
    && ok "shared LiteLLM served the manifest model request" \
    || bad "shared LiteLLM did not record a native Messages request"
fi

obs_log="$(cat "$WORK/obs.log")"
tix_log="$(cat "$WORK/tix.log")"
if [ "$runner_rc" -eq 0 ]; then ok "runner completed"; else bad "runner exited $runner_rc"; fi
# PHASE 3: the run's authorization decisions went to the EXTERNAL OPA engine over
# AuthZEN, not the builtin PDP. OPA console-logs every decision (opa-config.yaml
# decision_logs.console), so a decision in its log during the run proves the
# server (ANDYUR_PDP=authzen) actually consulted it. A broken/unreached PDP would
# have failed the run before this; this makes the traversal explicit.
# OPA flushes its console decision log asynchronously, so poll briefly rather
# than read once: a single read can race the flush right after the run finishes.
#
# Read the log into a VARIABLE and match it with `case`. Do NOT write this as
# `docker logs ... | grep -q ...`: grep -q exits at the FIRST match, that closes
# the pipe while docker is still writing, docker dies of SIGPIPE (141), and
# under this script's `set -o pipefail` the PIPELINE reports failure even though
# the pattern was found. The false negative appears only once the log is big
# enough that docker has not already finished writing -- so this assertion
# passed while OPA's log was small and started reporting "no decision" as the
# gate matured, which reads exactly like a flake and is not one. The run had
# traversed OPA every time (pdp.py fails CLOSED, so the granted scopes in the
# run record could not exist without a permit from the external engine).
opa_decided=0
for _ in $(seq 1 15); do
  opa_logs="$(docker logs "$OPA_CONTAINER" 2>&1 || true)"
  case "$opa_logs" in *'"decision_id"'*) opa_decided=1; break ;; esac
  sleep 0.5
done
[ "$opa_decided" = 1 ] \
  && ok "the run's authorization decisions traversed the external OPA engine (AuthZEN)" \
  || bad "the external OPA engine logged no decision -- the run did not use it"
# ADR-003 gate: tools must traverse the per-run sidecar, the sole tool egress.
# The per-tool lines are the runner's own promises, so their absence means the
# path was not taken; the third check guards against a resurrected agentgateway.
grep -q "\[runner\] tool egress: sidecar" "$WORK/runner.log" \
  && ok "sidecar egress active" || bad "sidecar egress line absent"
grep -q "\[runner\] tool sidecar: .* -> .* (aud " "$WORK/runner.log" \
  && ok "tools served through the per-run sidecar" \
  || bad "no tool was served through the sidecar"
grep -q "\[runner\] tool gateway: .* -> .* on port" "$WORK/runner.log" \
  && bad "agentgateway served a tool" \
  || ok "agentgateway never served a tool"
echo "$obs_log" | grep -q "aud='resource:telemetry'" \
  && ok "telemetry enforced the logical audience" || bad "telemetry audience absent"
echo "$obs_log" | grep -q "sub='dana'" \
  && ok "resource received the paged human subject" || bad "subject dana absent"
# The tool tokens are EXTERNAL-AS issued, not dev-minted. This binds to the
# VALIDATED issuer logged on the PEP ACCEPTANCE line (validated_iss=), printed
# only after AndyurTokenVerifier enforced iss+JWKS on a real token -- NOT the
# issuer echoed at startup. A dev-minted iss=andyur token would have been
# rejected before this line ever printed.
echo "$obs_log" | grep -q "ALLOWED .*validated_iss='$AS_HOST'" \
  && ok "an ACCEPTED tool token was issued by the EXTERNAL AS (validated iss=refas), not dev-minted" \
  || bad "no tool call was accepted with a validated external-AS issuer"
echo "$tix_log" | grep -q "aud='resource:tickets'" \
  && ok "tickets enforced the logical audience" || bad "tickets audience absent"
echo "$tix_log" | grep -q "COMMENT on INC-4471" \
  && ok "agent filed the triage" || bad "agent did not file triage"
echo "$tix_log" | grep -q "aud='resource:telemetry'" \
  && bad "tickets accepted telemetry's audience" \
  || ok "tickets never accepted telemetry's audience"
transcript="$(docker exec "$SERVER" sh -c \
  "test -s /app/data/workspace/agents/$AGENT/runs/$RUN_ID/transcript.jsonl && cat /app/data/workspace/agents/$AGENT/runs/$RUN_ID/transcript.jsonl" \
  2>/dev/null || true)"
if [ -z "$transcript" ]; then
  bad "agent transcript is missing (credential scan would be vacuous)"
elif echo "$transcript" | grep -qE 'eyJ[A-Za-z0-9_-]{20,}'; then
  bad "JWT material appears in the agent transcript"
else
  ok "nonempty agent transcript contains no JWT material"
fi

run_record="$(operator_api GET "/runs/$RUN_ID")"
printf '%s\n' "$run_record" >"$ARTIFACT_DIR/run-record.json"
traceparent="$(printf '%s\n' "$run_record" | python3 -c '
import json,sys
print(json.load(sys.stdin).get("trace_ctx") or "")')"
TRACE_ID="$(printf '%s' "$traceparent" | cut -d- -f2)"
if [ -n "$TRACE_ID" ] && ANDYUR_TRACE_REQUIRE_LITELLM="$([ "${ANDYUR_LLM:-ollama}" = api ] && echo 1 || echo 0)" \
  python3 "$HERE/infra/validate_sre_trace.py" --wait \
     "http://127.0.0.1:16686/api/traces/$TRACE_ID" \
     "$ARTIFACT_DIR/jaeger-trace.json" "$TRACE_ID" "$resolved_model"; then
  ok "distributed trace exported to Jaeger"
else
  bad "complete distributed trace $TRACE_ID was not exported to Jaeger"
fi
cat >"$ARTIFACT_DIR/README.txt" <<EOF
Andyur SRE demo run: $RUN_ID
Trace ID: $TRACE_ID
Jaeger: http://localhost:16686/trace/$TRACE_ID

registry-resolution.json  approved registry definition
materialized-ceiling.json server-side authority ceiling
authority-probes.log      deterministic allowed/refused controls
litellm.log               API-mode shared LiteLLM request evidence
run-record.json           terminal Andyur run record
runner.log                 runner + gateway execution log
obs.log / tix.log          resource enforcement and attribution logs
run/                       prompt, transcript, and summary artifacts
jaeger-trace.json          raw retained distributed trace
EOF

# Preserve and scan exactly once while every producer still exists. Marking the
# bundle finalized prevents EXIT from adding unscanned late bytes afterward.
preserve_artifacts
if scan_artifacts; then
  ok "retained observability bundle contains no credential material"
else
  bad "retained observability bundle contains credential material"
fi
ARTIFACT_FINALIZED=1

if [ "$NARRATE" = 1 ]; then
  say "what you just saw"
  tell "1. Identity   the user logged in at an external IdP; every container" \
       "              got a SPIFFE identity from SPIRE, no shared secrets." \
       "2. Authority  the agent's tool tokens were issued by the external AS" \
       "              via RFC 8693 (user = subject, run = actor), narrowed" \
       "              to the registry ceiling, bound to one audience each." \
       "3. Refusals   widening was refused by the tools AND by the AS; a" \
       "              locally minted token was turned away by the tools." \
       "4. Secrets    the model key came from a sealed vault under least" \
       "              privilege and never appeared in env, argv, or logs." \
       "5. Policy     each authorization decision traversed external OPA" \
       "              with a signed bundle; OPA's log proves it was asked." \
       "6. Evidence   transcript, trace and artifacts were kept and scanned;" \
       "              the numbers below are the assertions that back this." \
       "" \
       "Swap-in points for production: the AS (any supported enterprise" \
       "provider + as-certify), the vault, the policy bundle, the registry."
fi

say "result: $PASS passed, $FAIL failed"
echo "  run:       $RUN_ID"
echo "  artifacts: $ARTIFACT_DIR"
echo "  size:      $(du -sh "$ARTIFACT_DIR" | awk '{print $1}') (keeping newest $ARTIFACT_KEEP runs)"
echo "  trace:     http://localhost:16686/trace/$TRACE_ID"
[ "$PASS" -eq "$EXPECTED_PASS" ] && [ "$FAIL" -eq 0 ]

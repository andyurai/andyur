#!/usr/bin/env bash
# Slice 5 live verification: production mTLS + multi-replica.
#
# The control plane as it would run in production: TWO mTLS server replicas behind
# an L4 (TCP passthrough) load balancer, against shared Postgres, all SPIFFE
# workloads on the containerized SPIRE domain. A runner reaches the control plane
# over mutually-authenticated TLS -- it presents its per-run X509-SVID, the replica
# presents its control-plane X509-SVID, each verifies the other against the trust
# bundle -- through the LB, served by either replica. The Slice 4 JWT-SVID + token
# binding still run on top as the app-level authz.
#
# Runs on this machine's Docker. Needs the andyur-server + andyur-runner images.
# Usage: ./verify-mtls.sh   (add `down` to tear down)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_AGENT="${SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.11.2}"
INFRA="$(cd "$HERE/../.." && pwd)"     # <repo root>/infra
NET="andyur-spire-net"
SOCK_VOL="andyur-spire-sockets"
TD="andyur.local"
RUN_ID="rt-1"; AGENT="scout"
SECRET="mtls-shared-run-token-secret"
PGURL="postgresql://andyur:andyur@andyur-pg:5432/andyur"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

entry() {  # $1=spiffeID, rest=selector args
  local sid="$1"; shift
  docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
    -parentID "spiffe://$TD/agent/node" -spiffeID "$sid" -x509SVIDTTL 3600 \
    -jwtSVIDTTL 300 "$@" >/dev/null
}

wait_startup() {  # $1 = container name
  # Capture-then-match. NEVER `docker logs X | grep -q PAT`: grep -q exits at the
  # FIRST match, which SIGPIPEs docker while it is still writing, and under this
  # script's pipefail the PIPELINE reports failure even though the pattern WAS
  # found -- a healthy server read as down. Root-caused in 644b63f.
  local logs
  for _ in $(seq 1 40); do
    logs="$(docker logs "$1" 2>&1 || true)"
    case "$logs" in *"Application startup complete"*) return 0 ;; esac
    sleep 1
  done
  return 1
}

teardown() {
  docker rm -f andyur-lb andyur-server1 andyur-server2 andyur-pg >/dev/null 2>&1 || true
  bash "$HERE/verify-slice3.sh" down >/dev/null 2>&1 || true
}

if [ "${1:-up}" = "down" ]; then say "tearing down"; teardown; echo "done"; exit 0; fi

trap 'echo; echo "(leaving stack up for inspection; run: $0 down)"' EXIT
teardown

say "1. SPIRE stack"
bash "$HERE/verify-slice3.sh" up >/dev/null 2>&1 && ok "SPIRE up" \
  || { bad "SPIRE failed"; exit 1; }

say "2. shared Postgres (so any replica serves any run)"
docker run -d --name andyur-pg --network "$NET" \
  -e POSTGRES_USER=andyur -e POSTGRES_PASSWORD=andyur -e POSTGRES_DB=andyur \
  postgres:17 >/dev/null
for _ in $(seq 1 30); do
  docker exec andyur-pg pg_isready -U andyur >/dev/null 2>&1 && break; sleep 1
done
docker exec andyur-pg pg_isready -U andyur >/dev/null 2>&1 && ok "postgres ready" \
  || { bad "postgres not ready"; exit 1; }

say "3. two mTLS server replicas (attested control-plane, shared DB + secret)"
entry "spiffe://$TD/control-plane" -selector "docker:label:andyur.role:server"
sleep 6   # propagate the control-plane entry before the replicas export their SVID
run_replica() {  # $1 = container name, $2 = network alias the LB config expects
  docker run -d --name "$1" --network "$NET" --network-alias "$2" \
    --label andyur.role=server \
    -v "$SOCK_VOL:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_MTLS=on -e ANDYUR_AGENT_AUTH=on \
    -e ANDYUR_RUN_TOKEN_SECRET="$SECRET" -e ANDYUR_DB_URL="$PGURL" \
    andyur-server >/dev/null
}
run_replica andyur-server1 server1
wait_startup andyur-server1 || { bad "server1 never started"; docker logs andyur-server1 2>&1 | tail -15; exit 1; }
run_replica andyur-server2 server2   # starts after server1 has initialized the schema
wait_startup andyur-server2 || { bad "server2 never started"; docker logs andyur-server2 2>&1 | tail -15; exit 1; }
ok "server1 + server2 up (mTLS, shared Postgres)"

say "4. L4 passthrough load balancer (client cert survives to the replica)"
docker run -d --name andyur-lb --network "$NET" \
  -v "$INFRA/nginx-stream.conf:/etc/nginx/nginx.conf:ro" \
  nginx:1.27 >/dev/null
sleep 2
docker ps --format '{{.Names}}' | grep -q andyur-lb && ok "LB up in front of both replicas" \
  || { bad "LB failed"; docker logs andyur-lb 2>&1 | tail; exit 1; }

say "5. per-run entry + scaffold an active run and its token (in Postgres)"
entry "spiffe://$TD/agent/$AGENT/run/$RUN_ID" \
  -selector "docker:label:andyur.run_id:$RUN_ID" \
  -selector "docker:label:andyur.agent:$AGENT"
sleep 6
tok="$(docker exec -i andyur-server1 python - <<PY
from andyur import db
from andyur.server import runtoken
import datetime
db.init_db()
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
with db.connect() as conn:
    conn.execute("INSERT INTO agents (name, created_at) VALUES ('$AGENT', ?)", (now,))
    conn.execute("INSERT INTO runs (id, agent, state, created_at) "
                 "VALUES ('$RUN_ID', '$AGENT', 'pending', ?)", (now,))
print("TOK", runtoken.mint("$AGENT", "$RUN_ID", "wf-1"))
PY
)"
T1="$(echo "$tok" | awk '/^TOK /{print $2}')"
[ -n "$T1" ] && ok "run $RUN_ID active in Postgres; token minted" \
  || { bad "scaffold failed"; echo "$tok"; exit 1; }

# a runner calling the control plane over mTLS THROUGH the LB
mtls_call() {  # $1=path  $2=extra docker -e/-label args  $3=python-verify-expr
  docker run --rm --network "$NET" \
    --label andyur.run_id=$RUN_ID --label andyur.agent=$AGENT \
    -v "$SOCK_VOL:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_MTLS=on $2 \
    --entrypoint python andyur-runner -c "
import httpx
from andyur import identity
cert, verify = identity.client_tls('runner')   # presents our X509-SVID, trusts the bundle
h = {**identity.auth_header(), **identity.run_token_header()}
try:
    r = httpx.get('https://andyur-lb:8642$1', headers=h, verify=verify, timeout=20)
    print(r.status_code, r.text)
except Exception as e:
    print('ERR', type(e).__name__)
" 2>&1 | tail -1
}

say "6. runner mTLS round-trip THROUGH the LB (served by a replica)"
out="$(mtls_call /identity/verify-run "-e ANDYUR_RUN_TOKEN=$T1")"
if echo "$out" | grep -q '"run_id":"rt-1"'; then ok "mTLS round-trip authorized -> $out"
else bad "mTLS round-trip failed: $out"; fi

say "7. a client with NO certificate is rejected at the TLS handshake"
out="$(docker run --rm --network "$NET" --entrypoint python andyur-runner -c "
import httpx
try:
    httpx.get('https://andyur-lb:8642/health', verify=False, timeout=10); print('UNEXPECTED ok')
except Exception as e:
    print('rejected', type(e).__name__)
" 2>&1 | tail -1)"
echo "$out" | grep -q "rejected" && ok "certless client rejected (mutual auth enforced): $out" \
  || bad "certless client was NOT rejected: $out"

say "8. either replica serves any request (LB distributes; both validate)"
for _ in 1 2 3 4; do mtls_call /identity/verify-run "-e ANDYUR_RUN_TOKEN=$T1" >/dev/null; done
h1="$(docker logs andyur-server1 2>&1 | grep -c 'GET /identity/verify-run')"
h2="$(docker logs andyur-server2 2>&1 | grep -c 'GET /identity/verify-run')"
echo "     server1 served $h1, server2 served $h2"
if [ "$h1" -gt 0 ] && [ "$h2" -gt 0 ]; then ok "both replicas validated mTLS runners (shared state)"
else bad "traffic did not reach both replicas (server1=$h1 server2=$h2)"; fi

trap - EXIT
say "mTLS + multi-replica verified (stack up; tear down with: $0 down)"

#!/usr/bin/env bash
# Slice 4 live verification: the server-side round-trip.
#
# Slice 3 proved the ATTESTATION mechanism (a labeled container gets its per-run
# SVID). This proves the full loop: a runner in its per-run container PRESENTS its
# container-attested SVID, and the Andyur SERVER -- itself a SPIFFE workload on the
# SAME containerized SPIRE domain -- VALIDATES it and reads back which agent/run is
# calling. No self-declared name is trusted.
#
# Layers on top of the Slice 3 stack (reuses verify-slice3.sh for SPIRE). Needs the
# andyur-server + andyur-runner images built (./run.sh sandbox-image builds runner;
# docker build -f Dockerfile.server -t andyur-server . builds server).
# Usage: ./verify-roundtrip.sh   (add `down` to tear everything down)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_AGENT="${SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.11.2}"
NET="andyur-spire-net"
SOCK_VOL="andyur-spire-sockets"
TD="andyur.local"
RUN_ID="rt-1"
AGENT="scout"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

entry() {  # create a registration entry: $1=spiffeID, shift; rest = -selector args
  local sid="$1"; shift
  docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
    -parentID "spiffe://$TD/agent/node" -spiffeID "$sid" -jwtSVIDTTL 300 "$@" >/dev/null
}

teardown() {
  docker rm -f andyur-server >/dev/null 2>&1 || true
  bash "$HERE/verify-slice3.sh" down >/dev/null 2>&1 || true
}

if [ "${1:-up}" = "down" ]; then say "tearing down"; teardown; echo "done"; exit 0; fi

trap 'echo; echo "(leaving stack up for inspection; run: $0 down)"' EXIT
teardown

say "1. SPIRE stack (reuse Slice 3 bringup)"
bash "$HERE/verify-slice3.sh" up >/dev/null 2>&1 && ok "SPIRE server + agent up" \
  || { bad "SPIRE stack failed to come up"; exit 1; }

say "2. Andyur server as a SPIFFE workload (identity on, attested by its label)"
entry "spiffe://$TD/control-plane" -selector "docker:label:andyur.role:server"
docker run -d --name andyur-server --network "$NET" \
  --label andyur.role=server \
  -v "$SOCK_VOL:/run/spire/sockets:ro" \
  -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
  -e ANDYUR_PROFILE=dev \
  -e ANDYUR_AGENT_AUTH=on \
  -e ANDYUR_RUN_TOKEN_SECRET=verify-roundtrip-secret \
  -p 127.0.0.1:18642:8642 \
  andyur-server >/dev/null
for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:18642/health >/dev/null 2>&1 && break; sleep 1
done
curl -sf http://127.0.0.1:18642/health >/dev/null 2>&1 \
  && ok "server up + identity on (validates against the containerized SPIRE)" \
  || { bad "server never came healthy"; docker logs andyur-server 2>&1 | tail -20; exit 1; }

say "3. register the run's per-run identity (keyed on its container labels)"
entry "spiffe://$TD/agent/$AGENT/run/$RUN_ID" \
  -selector "docker:label:andyur.run_id:$RUN_ID" \
  -selector "docker:label:andyur.agent:$AGENT"
# WAIT UNTIL THE ENTRY ACTUALLY RESOLVES, bounded, rather than sleeping a fixed
# 5s and announcing it. The old line printed "entry: ..." having checked
# nothing: on a loaded host the entry had not propagated and the steps below
# failed for a reason that looked like a real refusal, and on a fast host it
# wasted five seconds. This gate already waits for the server this way ten lines
# up; entry propagation was the outlier.
#
# The probe is a container carrying the run's own labels asking for its SVID,
# which is the same thing step 4 does -- so what is waited for is exactly what
# is about to be asserted, not a proxy for it.
wait_entry() {  # $1 = SPIFFE ID; remaining args are docker label arguments
  local sid="$1"; shift
  local deadline=$((SECONDS + 60))
  while [ $SECONDS -lt $deadline ]; do
    if docker run --rm --network "$NET" "$@" \
         -v "$SOCK_VOL:/run/spire/sockets:ro" \
         -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
         -e ANDYUR_SVID_TIMEOUT=5 \
         --entrypoint python andyur-runner -c \
         'from andyur import identity; identity.fetch_token()' >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  bad "$sid never propagated to the agent within 60s"
  return 1
}
wait_entry "spiffe://$TD/agent/$AGENT/run/$RUN_ID" \
  --label "andyur.run_id=$RUN_ID" --label "andyur.agent=$AGENT" || exit 1
ok "entry: spiffe://$TD/agent/$AGENT/run/$RUN_ID (resolved, not assumed)"

# a runner-image container that fetches its per-run SVID and calls the server with it
call_whoami() {  # $1 = extra docker args (labels/env); prints "status body"
  # shellcheck disable=SC2086
  docker run --rm --network "$NET" $1 \
    -v "$SOCK_VOL:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_SERVER_URL=http://andyur-server:8642 \
    --entrypoint python andyur-runner -c '
import httpx
import os
from andyur import identity
try:
    headers = identity.auth_header()
    r = httpx.get("http://andyur-server:8642/identity/whoami",
                  headers=headers, timeout=15)
    print(r.status_code, r.text)
except Exception as e:
    print("ERR", e)
' 2>&1 | tail -1
}

say "4. runner in its labeled container PRESENTS its SVID; server VALIDATES it"
out="$(call_whoami "--label andyur.run_id=$RUN_ID --label andyur.agent=$AGENT")"
if echo "$out" | grep -q '"agent":"'"$AGENT"'"' && echo "$out" | grep -q '"run_id":"'"$RUN_ID"'"'; then
  ok "server validated the container-attested SVID -> $out"
else
  bad "round-trip did not return the attested agent/run"; echo "     $out"; exit 1
fi

say "5. a caller presenting NO SVID is rejected by the server (401)"
# Make the request without calling identity.auth_header(): an unlabeled client
# cannot fetch an SVID, and waiting for that fetch tests SPIRE rather than the
# server-side tokenless denial asserted here.
out="$(docker run --rm --network "$NET" --entrypoint python andyur-runner -c '
import httpx
try:
    r = httpx.get("http://andyur-server:8642/identity/whoami", timeout=15)
    print(r.status_code, r.text)
except Exception as e:
    print("ERR", e)
' 2>&1 | tail -1)"
if echo "$out" | grep -q "^401"; then ok "tokenless caller rejected by the server (401)"
else bad "tokenless caller was NOT rejected: $out"; exit 1; fi

# --- Enforcement: bind the R1 run token to the container-attested SVID ---------
# Scaffold two active runs + their tokens directly in the server DB (a daemon
# would normally mint these). The SVID entry from step 3 attests only scout/rt-1,
# so the other/rt-2 token presented from rt-1's container must be rejected. A
# distinct agent is intentional: the database permits only one live run per
# agent, so using scout twice would silently fail the second INSERT and turn the
# mismatch check into a vacuous liveness refusal.
say "6. scaffold active runs + tokens (as a daemon would)"
toks="$(docker exec -i andyur-server python - <<'PY'
from andyur import db
from andyur.server import runtoken
import datetime
db.init_db()
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
with db.connect() as conn:
    conn.execute("INSERT OR IGNORE INTO agents (name, registry_agent_id, created_at) "
                 "VALUES ('scout', 'agt_teller', ?)", (now,))
    conn.execute("UPDATE agents SET registry_agent_id='agt_teller' WHERE name='scout'")
    conn.execute("INSERT OR IGNORE INTO agents (name, created_at) VALUES ('other', ?)", (now,))
    conn.execute("INSERT OR IGNORE INTO runs (id, agent, state, created_at) "
                 "VALUES ('rt-1', 'scout', 'pending', ?)", (now,))
    conn.execute("INSERT OR IGNORE INTO runs (id, agent, state, created_at) "
                 "VALUES ('rt-2', 'other', 'pending', ?)", (now,))
print("T1", runtoken.mint("scout", "rt-1", "wf-1"))
print("T2", runtoken.mint("other", "rt-2", "wf-1"))
PY
)"
T1="$(echo "$toks" | awk '/^T1 /{print $2}')"
T2="$(echo "$toks" | awk '/^T2 /{print $2}')"
[ -n "$T1" ] && [ -n "$T2" ] && ok "runs rt-1, rt-2 active; tokens minted" \
  || { bad "could not scaffold runs/tokens"; echo "$toks"; exit 1; }

# a runner in rt-1's container (SVID = agent/scout/run/rt-1) calling verify-run
call_verify_run() {  # $1 = run token to present
  docker run --rm --network "$NET" \
    --label andyur.run_id=$RUN_ID --label andyur.agent=$AGENT \
    -v "$SOCK_VOL:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_RUN_TOKEN="$1" \
    --entrypoint python andyur-runner -c '
import httpx
from andyur import identity
h = {**identity.auth_header(), **identity.run_token_header()}
try:
    r = httpx.get("http://andyur-server:8642/identity/verify-run", headers=h, timeout=15)
    print(r.status_code, r.text)
except Exception as e:
    print("ERR", e)
' 2>&1 | tail -1
}

say "7. rt-1 container presents rt-1's token WITH its matching SVID (accepted)"
out="$(call_verify_run "$T1")"
if echo "$out" | grep -q '"run_id":"rt-1"'; then ok "server authorized the run -> $out"
else bad "matching token+SVID was NOT accepted: $out"; exit 1; fi

say "8. rt-1 container presents rt-2's STOLEN token (SVID says rt-1) -> rejected"
out="$(call_verify_run "$T2")"
# assert BOTH 403 AND the binding message, so this can't be a role-path 403 (a
# valid token IS present -> require_run's token path ran, and only the SVID
# binding rejects it): proves the enforcement, not some other refusal
if echo "$out" | grep -q "^403" && echo "$out" | grep -qi "mismatch"; then
  ok "stolen-token replay rejected by the SVID binding -> $out"
else bad "stolen token was NOT rejected by the binding: $out"; exit 1; fi

call_registry_tools() {  # $1=run token; $2=attach this caller's SVID? (on/off)
  # `off` means THIS GATE does not attach an SVID header and does not label the
  # container for attestation -- it models a token-only replay. It is not a
  # platform mode: ANDYUR_IDENTITY was removed on 7 August 2026 and identity is
  # not optional (andyur/identity.py opens with why). The knob was named after
  # that retired flag and passed it to containers where nothing read it, which
  # made a gate look like it was exercising a configuration the platform still
  # has (ROADMAP.md 27).
  local token="$1" attach_svid="$2" labels=""
  [ "$attach_svid" = "on" ] \
    && labels="--label andyur.run_id=$RUN_ID --label andyur.agent=$AGENT"
  # shellcheck disable=SC2086
  docker run --rm --network "$NET" $labels \
    -v "$SOCK_VOL:/run/spire/sockets:ro" \
    -e SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock \
    -e ANDYUR_GATE_ATTACH_SVID="$attach_svid" -e ANDYUR_RUN_TOKEN="$token" \
    --entrypoint python andyur-runner -c '
import httpx
import os
from andyur import identity
h = dict(identity.run_token_header())
if os.environ.get("ANDYUR_GATE_ATTACH_SVID") == "on": h.update(identity.auth_header())
r = httpx.get("http://andyur-server:8642/runs/rt-1/registry-tools",
              headers=h, timeout=15)
print(r.status_code, r.text)
' 2>&1 | tail -1
}

say "9. real per-run runner fetches only its bound sidecar descriptor"
out="$(call_registry_tools "$T1" on)"
if echo "$out" | grep -q '^200' \
   && echo "$out" | grep -q '"registry_agent_id":"agt_teller"' \
   && echo "$out" | grep -q '"resource_id":"tool:bank"' \
   && ! echo "$out" | grep -q '"ceiling"'; then
  ok "attested run resolved the minimal bound tool descriptor -> $out"
else bad "attested run could not resolve its bound tools: $out"; exit 1; fi

say "10. the sensitive descriptor refuses a run token without its per-run SVID"
# The caller withholds its SVID; the platform has no mode in which it may.
out="$(call_registry_tools "$T1" off)"
if echo "$out" | grep -q '^401' && echo "$out" | grep -qi 'requires a JWT-SVID'; then
  ok "token-only replay refused: a run token is not an attested run -> $out"
else bad "token-only caller reached the descriptor: $out"; exit 1; fi

trap - EXIT
say "round-trip + enforcement verified (stack up; tear down with: $0 down)"

#!/usr/bin/env bash
# Containerized SPIRE stack for Andyur Slice 3 (per-run identity by CONTAINER
# attestation) + its live verification.
#
#   up      bring up spire-server + spire-agent (docker WorkloadAttestor), leave
#           running so the daemon can register per-run entries against it
#   verify  bring up, then PROVE the property: a container labeled andyur.run_id
#           gets the run's SVID; unlabeled / mislabeled ones are denied (default)
#   down    tear the stack down
#
# Runs entirely on this machine's Docker (no host SPIRE agent), so it works on
# macOS Docker Desktop. Container names match the daemon's registrar defaults
# (andyur-spire-server), so `ANDYUR_SPIRE_REGISTRAR=on` works against this stack.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_SERVER="${SPIRE_SERVER_IMAGE:-ghcr.io/spiffe/spire-server:1.11.2}"
IMG_AGENT="${SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.11.2}"
NET="andyur-spire-net"
SOCK_VOL="andyur-spire-sockets"
TD="andyur.local"
RUN_ID="run-verify"
AGENT="scout"
SVID="spiffe://$TD/agent/$AGENT/run/$RUN_ID"   # per-run identity (agent + run)

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
# bad() USED TO ONLY PRINT. No counter, no exit -- and the three attestation
# assertions below are if/else blocks whose every branch returns 0, with the
# script's last command a printf. So this gate reported success whenever SPIRE
# merely STARTED, and could not fail on any of the things it exists to check.
# Two of those three are refusal-only, and the fourth is meant to be their
# positive control; none of them could redden anything.
FAILED=0
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=$((FAILED+1)); }

cleanup() {
  docker rm -f andyur-spire-server andyur-spire-agent >/dev/null 2>&1 || true
  docker volume rm "$SOCK_VOL" andyur-spire-server-data >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

bringup() {
  cleanup
  say "0. network + shared socket volume"
  # Another Andyur verifier may deliberately share this network. `cleanup`
  # cannot remove an in-use network, and treating that harmless residue as a
  # fatal create collision made `up` non-idempotent. Reuse the named network;
  # the SPIRE containers and socket/data volumes remain this harness's state.
  docker network inspect "$NET" >/dev/null 2>&1 \
    || docker network create "$NET" >/dev/null
  docker volume create "$SOCK_VOL" >/dev/null
  docker volume create andyur-spire-server-data >/dev/null
  ok "created $NET, $SOCK_VOL"

  say "1. SPIRE server (issues SVIDs, holds the run entries)"
  docker run -d --name andyur-spire-server --network "$NET" --user 0 \
    -v "$HERE/server.conf:/opt/spire/conf/server/server.conf:ro" \
    -v andyur-spire-server-data:/opt/spire/data \
    --entrypoint /opt/spire/bin/spire-server \
    "$IMG_SERVER" run -config /opt/spire/conf/server/server.conf >/dev/null
  for _ in $(seq 1 30); do
    docker exec andyur-spire-server /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec andyur-spire-server /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1 \
    && ok "server healthy" || { bad "server never came healthy"; docker logs andyur-spire-server | tail; exit 1; }

  say "2. SPIRE agent (docker WorkloadAttestor, --pid=host + docker.sock)"
  local token
  token="$(docker exec andyur-spire-server /opt/spire/bin/spire-server token generate \
    -spiffeID "spiffe://$TD/agent/node" -output json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')"
  docker run -d --name andyur-spire-agent --network "$NET" --user 0 \
    --pid=host \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$HERE/agent.conf:/opt/spire/conf/agent/agent.conf:ro" \
    -v "$SOCK_VOL:/run/spire/sockets" \
    --entrypoint /opt/spire/bin/spire-agent \
    "$IMG_AGENT" run -config /opt/spire/conf/agent/agent.conf -joinToken "$token" >/dev/null
  for _ in $(seq 1 30); do
    docker exec andyur-spire-agent /opt/spire/bin/spire-agent healthcheck \
      -socketPath /run/spire/sockets/api.sock >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec andyur-spire-agent /opt/spire/bin/spire-agent healthcheck \
    -socketPath /run/spire/sockets/api.sock >/dev/null 2>&1 \
    && ok "agent attested + Workload API up" \
    || { bad "agent never came up"; docker logs andyur-spire-agent | tail -20; exit 1; }
}

# a throwaway container that tries to fetch the run SVID from the agent. The `+`
# expansion keeps it correct under `set -u` with an empty array on macOS bash 3.2.
fetch_as() {  # $1 = run_id label value (empty for none); always carries agent=scout
  local label_args=()
  [ -n "$1" ] && label_args=(--label "andyur.run_id=$1" --label "andyur.agent=$AGENT")
  docker run --rm --network "$NET" --user 0 ${label_args[@]+"${label_args[@]}"} \
    -v "$SOCK_VOL:/run/spire/sockets:ro" \
    --entrypoint /opt/spire/bin/spire-agent \
    "$IMG_AGENT" api fetch jwt -audience andyur-server \
    -socketPath /run/spire/sockets/api.sock 2>&1
}

mode="${1:-verify}"
case "$mode" in
  down) say "tearing down"; cleanup; echo "done"; exit 0 ;;
  up)
    bringup
    say "stack up (andyur-spire-server / andyur-spire-agent)"
    # No ANDYUR_IDENTITY: it was removed on 7 August 2026 and identity is not
    # optional. Telling an operator to set it is telling them to configure
    # something that does not exist.
    echo "  point Andyur at it: ANDYUR_DEPLOYMENT=docker ANDYUR_SANDBOX=on ANDYUR_SPIRE_REGISTRAR=on ./run.sh daemon"
    echo "  tear down: $0 down"
    exit 0 ;;
  verify) : ;;
  *) echo "usage: $0 {up|verify|down}"; exit 2 ;;
esac

trap 'echo; echo "(leaving stack up for inspection; run: $0 down)"' EXIT
bringup

say "3. register the run's identity, keyed on its container labels"
docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
  -parentID "spiffe://$TD/agent/node" \
  -spiffeID "$SVID" \
  -selector "docker:label:andyur.run_id:$RUN_ID" \
  -selector "docker:label:andyur.agent:$AGENT" \
  -jwtSVIDTTL 300 >/dev/null
ok "entry: $SVID  <=  docker:label:andyur.run_id:$RUN_ID + andyur.agent:$AGENT"

say "4. a container LABELED andyur.run_id=$RUN_ID (what the daemon launches)"
out=""
for _ in $(seq 1 12); do   # poll: the agent syncs new entries on an interval (~5s)
  out="$(fetch_as "$RUN_ID" || true)"
  echo "$out" | grep -q "$SVID" && break
  sleep 2
done
if echo "$out" | grep -q "$SVID"; then ok "received its run SVID: $SVID"
else bad "labeled container did NOT get the SVID"; echo "$out" | head; fi

say "5. a container with the WRONG label (a different run trying to impersonate)"
out="$(fetch_as "some-other-run" || true)"
if echo "$out" | grep -q "$SVID"; then bad "mislabeled container WRONGLY got $SVID"; echo "$out" | head
else ok "denied (no SVID issued for the wrong label)"; fi

say "6. a container with NO label at all"
out="$(fetch_as "" || true)"
if echo "$out" | grep -q "$SVID"; then bad "unlabeled container WRONGLY got $SVID"; echo "$out" | head
else ok "denied (no identity without the label)"; fi

say "why the agent cannot forge this"
cat <<'EOF'
  - the label is set by the daemon at `docker run` time and is immutable for a
    running container (docker has no API to relabel a live container);
  - run containers do NOT mount docker.sock, and the agent runs as uid 1001, so
    it cannot inspect or relabel any container;
  - therefore arbitrary code in the run container cannot obtain another run's
    identity, nor change its own. Identity is bound to the container, not to a
    uid/path the agent shares. This is the R1 property SPIRE now enforces.
EOF
trap - EXIT
if [ "$FAILED" -ne 0 ]; then
  say "verification FAILED: $FAILED check(s) did not hold"
  exit 1
fi
say "verification complete (stack left up; tear down with: $0 down)"

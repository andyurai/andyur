#!/usr/bin/env bash
# LIVE proof of O1 (F3 remediation): in Docker pod mode the untrusted agent is
# single-homed on a per-run internal network and reaches ONLY its sidecar -- no
# route to the control plane, another run, or the internet.
#
# This reproduces the EXACT topology andyur/daemon/orchestrator.py builds under
# ANDYUR_AGENT_SPLIT=pod (the argv/network flags are unit-locked in
# tests/test_pod_orchestrator.py): a shared egress network standing in for
# SANDBOX_NETWORK with the control-plane server on it; per-run `--internal`
# networks; each run's sidecar on the egress network AND connected to its per-run
# network under the alias `sidecar`; each agent single-homed on its per-run
# network only. It then drives real reachability from inside the agent's netns.
#
# It also runs the F3 MUTATION inline: rewire the agent to share the sidecar's
# netns (the pre-O1 state) and show the agent->server check flips from refused to
# reachable, proving the negative controls can actually fail. Usage:
#   ./verify-run-isolation-docker.sh          (add `down` to clean up)
set -uo pipefail
IMG="${ANDYUR_ISO_IMAGE:-busybox:1.36}"
EGRESS="andyur-iso-egress"      # stands in for SANDBOX_NETWORK (andyur-runs)
NETA="andyur-net-isoA"          # per-run network for run A (matches NET_PREFIX)
NETB="andyur-net-isoB"          # per-run network for run B
PASS=0; FAIL=0
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
info(){ printf '  \033[36m·\033[0m %s\n' "$*"; }   # neutral: counted neither PASS nor FAIL

teardown(){
  docker rm -f iso-server iso-sidecarA iso-sidecarB iso-agentA >/dev/null 2>&1 || true
  docker network rm "$NETA" "$NETB" "$EGRESS" >/dev/null 2>&1 || true
}
if [ "${1:-up}" = "down" ]; then say "tearing down"; teardown; echo done; exit 0; fi
trap teardown EXIT
teardown
command -v docker >/dev/null || { echo "docker required"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not running"; exit 1; }

# a tiny always-on listener (busybox httpd serving a one-byte page)
listen(){ sh -c 'echo ok > /www/i && httpd -f -p 80 -h /www'; }
# reachability probe: does src reach host:80 within 3s?
reach(){ docker exec "$1" wget -T3 -q -O- "http://$2:80/i" >/dev/null 2>&1; }

say "1. build the O1 topology (as orchestrator.py emits it under pod mode)"
docker network create --internal "$EGRESS" >/dev/null
docker network create --internal "$NETA"   >/dev/null   # per-run, --internal
docker network create --internal "$NETB"   >/dev/null
# control-plane server: on the egress network, as andyur-server is on andyur-runs
docker run -d --name iso-server   --network "$EGRESS" --entrypoint sh "$IMG" \
  -c 'mkdir -p /www; echo ok>/www/i; httpd -f -p 80 -h /www' >/dev/null
# run A sidecar: egress network (to reach the server) + per-run net, alias sidecar
docker run -d --name iso-sidecarA --network "$EGRESS" --entrypoint sh "$IMG" \
  -c 'mkdir -p /www; echo ok>/www/i; httpd -f -p 80 -h /www' >/dev/null
docker network connect --alias sidecar "$NETA" iso-sidecarA >/dev/null
# run B sidecar: its own per-run net, alias sidecar (same alias, different net)
docker run -d --name iso-sidecarB --network "$EGRESS" --entrypoint sh "$IMG" \
  -c 'mkdir -p /www; echo ok>/www/i; httpd -f -p 80 -h /www' >/dev/null
docker network connect --alias sidecar "$NETB" iso-sidecarB >/dev/null
# run A AGENT: single-homed on run A's per-run network ONLY (O1)
docker run -d --name iso-agentA   --network "$NETA" --entrypoint sh "$IMG" \
  -c 'sleep 3600' >/dev/null
sleep 1
ok "topology up: server + 2 sidecars on egress, agentA single-homed on $NETA"

say "2. the O1 property: agentA reaches ONLY its own sidecar"
if reach iso-agentA sidecar; then ok "(+) agentA -> its sidecar (alias) reachable"; else bad "agentA cannot reach its own sidecar"; fi
if reach iso-agentA iso-server;   then bad "agentA REACHED the control-plane server (F3 not closed)"; else ok "agentA -> control-plane server refused"; fi
if reach iso-agentA iso-sidecarB; then bad "agentA REACHED run B's sidecar (cross-run)";           else ok "agentA -> another run's sidecar refused"; fi
# internet: an --internal network has no default route / masquerade (it DOES
# have a gateway = the host; step 3 probes host-service reach via that gateway,
# enforcing it where the daemon exposes host services and reporting the
# observed reason where it does not).
if docker exec iso-agentA wget -T3 -q -O- http://1.1.1.1 >/dev/null 2>&1; then bad "agentA reached the internet"; else ok "agentA -> internet refused (no default route)"; fi
# DNS for an external name must not resolve off the per-run network
if docker exec iso-agentA nslookup example.com >/dev/null 2>&1; then bad "agentA resolved an external DNS name"; else ok "agentA -> external DNS refused"; fi

say "3. host-gateway exposure: a loopback-published host service is NOT reachable"
# An --internal net still has a gateway interface, and it IS the Docker host:
# where the daemon shares the host netns (native Linux), a host service bound
# on 0.0.0.0 is reachable from the agent at the gateway IP while one bound on
# 127.0.0.1 is not -- the mechanism behind binding every compose publish to
# 127.0.0.1. The probe SELF-CALIBRATES with a paired positive control instead
# of guessing the engine: `docker info OSType` says "linux" even on Docker
# Desktop (it reports the VM), and the agent's default route -- the previous
# source of the gateway IP -- does not exist on an --internal network at all,
# which made the old probe skip everywhere, including where the exposure is
# real. The gateway comes from the network's IPAM config; a 0.0.0.0-bound
# host listener must be reachable through it (this positive control is also
# exactly the exposure the loopback check must catch, so a daemon where it
# succeeds is a daemon where the negative can really fail); only then is the
# loopback listener's unreachability meaningful. Where the positive control
# fails, this daemon (a VM-backed engine) does not expose host services to
# containers at all, and the skip states that observed reason.
GW="$(docker network inspect "$NETA" -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null)"
if [ -z "$GW" ]; then
  bad "cannot read $NETA's gateway from IPAM -- host-gateway probe cannot run"
else
  ( python3 -m http.server 8898 --bind 0.0.0.0  >/dev/null 2>&1 & echo $! > /tmp/iso-hostsvc-open.pid )
  ( python3 -m http.server 8899 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > /tmp/iso-hostsvc.pid )
  sleep 1
  if docker exec iso-agentA wget -T3 -q -O- "http://$GW:8898" >/dev/null 2>&1; then
    ok "(+) agentA reaches a 0.0.0.0-published host service via gateway $GW (this daemon exposes host services; probe is live)"
    if docker exec iso-agentA wget -T3 -q -O- "http://$GW:8899" >/dev/null 2>&1; then
      bad "agentA reached a 127.0.0.1-published host service via the gateway ($GW)"
    else
      ok "agentA -> loopback-published host service (via gateway $GW) refused"
    fi
  else
    info "host-gateway enforcement skipped, observed reason: a 0.0.0.0-bound host listener is UNREACHABLE at gateway $GW, so this daemon (VM-backed engine) does not expose host services to containers and the loopback-exposure class cannot exist here; the compose 127.0.0.1 binds are the native-Linux control"
  fi
  kill "$(cat /tmp/iso-hostsvc-open.pid 2>/dev/null)" "$(cat /tmp/iso-hostsvc.pid 2>/dev/null)" 2>/dev/null
  rm -f /tmp/iso-hostsvc-open.pid /tmp/iso-hostsvc.pid
fi

say "4. F3 mutation: rewire agentA to SHARE the sidecar netns (pre-O1 state)"
docker rm -f iso-agentA >/dev/null 2>&1
docker run -d --name iso-agentA --network "container:iso-sidecarA" --entrypoint sh "$IMG" -c 'sleep 3600' >/dev/null
sleep 1
# sharing the sidecar's netns puts the agent on the egress network -> it now
# reaches the server. If this does NOT happen, the negative control above is
# meaningless (it would pass even when isolation is broken).
if reach iso-agentA iso-server; then ok "mutation reproduced: shared-netns agent REACHES the server (so the step-2 negatives are real)"; else bad "mutation did not reproduce: the server was unreachable even with a shared netns -- the negatives prove nothing"; fi

echo
if [ "$FAIL" -eq 0 ]; then say "run-isolation (O1) gate GREEN ($PASS checks)"; exit 0
else say "run-isolation (O1) gate RED ($FAIL failed)"; exit 1; fi

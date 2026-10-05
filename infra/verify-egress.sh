#!/usr/bin/env bash
# PROVE the egress boundary, rather than configuring it and hoping.
#
# An agent runs code it was talked into running. Assume it can be tricked; the
# question that decides whether that matters is where the data can go. Every
# other control in Andyur narrows what an agent may READ. This one removes the
# route, which is the other half: a secret you cannot send is a secret you did
# not leak.
#
# So this script does not check a setting. It runs a container in exactly the
# shape an Andyur run gets, and tries to reach the internet from inside it.
set -euo pipefail
NET="${ANDYUR_SANDBOX_NETWORK:-andyur-runs}"
IMAGE="curlimages/curl:8.11.1"
PASS=0; FAIL=0
ok()  { printf '    \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '    \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }

cleanup() {
  docker rm -f andyur-egress-peer >/dev/null 2>&1 || true
  docker network rm "$NET-test" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> creating an internal network (no route off the host, by construction)"
docker network rm "$NET-test" >/dev/null 2>&1 || true
docker network create --internal "$NET-test" >/dev/null
internal=$(docker network inspect -f '{{.Internal}}' "$NET-test")
[ "$internal" = "true" ] && ok "docker reports the network as internal" \
                         || bad "the network is not internal"

echo
echo "==> E1. an agent tries to exfiltrate to the internet"
echo '    (this is the whole threat: anything it can read, it can send)'
if docker run --rm --network "$NET-test" "$IMAGE" \
     -s --max-time 8 https://example.com >/dev/null 2>&1; then
  bad "a run container reached the public internet"
else
  ok "no route to the internet from a run container"
fi

echo
echo "==> E2. DNS resolution of an external host"
echo '    (a name lookup alone can carry data out, one subdomain at a time)'
if docker run --rm --network "$NET-test" --entrypoint sh "$IMAGE" \
     -c 'getent hosts attacker.example.com' >/dev/null 2>&1; then
  bad "external DNS resolves from a run container"
else
  ok "external names do not resolve"
fi

echo
echo "==> E3. the host itself, via the gateway escape hatch"
echo '    (a route to the host is a route to everything the host can reach)'
if docker run --rm --network "$NET-test" \
     --add-host host.docker.internal:host-gateway "$IMAGE" \
     -s --max-time 5 http://host.docker.internal:8642/health >/dev/null 2>&1; then
  bad "a run container reached a service on the host"
else
  ok "the host is unreachable even when the gateway alias is present"
fi

echo
echo "==> E4. the services a run is SUPPOSED to reach still work"
echo '    (a boundary that breaks the platform gets turned off, so this matters)'
docker run -d --rm --name andyur-egress-peer --network "$NET-test" \
  --entrypoint sh "$IMAGE" -c \
  'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080; done' \
  >/dev/null
sleep 2
if docker run --rm --network "$NET-test" "$IMAGE" \
     -s --max-time 8 http://andyur-egress-peer:8080/ | grep -q ok; then
  ok "a peer on the same network (control plane, broker, tool servers) is reachable"
else
  bad "in-network services are unreachable: the boundary is too tight to run on"
fi

echo
echo "==> E5. the daemon REFUSES a network that only looks locked down"
echo '    (naming a network proves nothing; an ordinary bridge passes a config review)'
docker network rm "$NET-open" >/dev/null 2>&1 || true
docker network create "$NET-open" >/dev/null
set +e
out=$(cd "$(dirname "$0")/.." && ANDYUR_PROFILE=prod ANDYUR_DEPLOYMENT=docker ANDYUR_SANDBOX=on \
  ANDYUR_AGENT_AUTH=on ANDYUR_LLM=ollama \
  ANDYUR_SANDBOX_NETWORK="$NET-open" \
  .venv/bin/python -c \
  'from andyur.daemon.daemon import assert_egress_locked; assert_egress_locked()' 2>&1)
rc=$?
set -e
docker network rm "$NET-open" >/dev/null 2>&1 || true
if [ $rc -ne 0 ] && echo "$out" | grep -q "NOT internal"; then
  ok "the daemon refuses to start against a routable network"
else
  bad "the daemon accepted a routable network (rc=$rc)"
fi

echo
printf '%s\n' "----------------------------------------"
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "ALL CHECKS PASSED"

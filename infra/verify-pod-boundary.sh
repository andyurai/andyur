#!/usr/bin/env bash
# PROVE the two-container pod boundary, at runtime, in real containers.
#
# The container split makes a claim that is entirely a SUBTRACTION: the agent
# container holds no credential, no identity, no view of the sidecar. Nothing
# fails when a subtraction is wrong -- the run works perfectly while the property
# it was built for has quietly stopped holding. So the claim has to be executed,
# not read.
#
# WHAT THIS IS THE SUCCESSOR TO. `verify-uid-boundary.sh` proves the SINGLE
# container shape, where the agent is a different uid inside the runner's
# container and the boundary is Linux uid permissions on /proc. Here the agent is
# a different CONTAINER: a separate PID namespace, a separate filesystem, a
# separate credential set. The interesting difference is that the sidecar's
# processes are not merely unreadable, they are NOT VISIBLE AT ALL -- so this
# checks the stronger property, and checks that the weaker one is now moot.
#
# THE HARNESS LESSON FROM THE UID ROUNDS, APPLIED HERE FROM THE START:
#   1. Build the container commands by calling the ORCHESTRATOR'S OWN functions.
#      Re-deriving a `docker run` by hand is a second source of truth, and it
#      drifted four times in the uid work before that was accepted.
#   2. Every "cannot" needs a POSITIVE CONTROL. A probe that fails for its own
#      broken reasons reports the same PASS as a boundary that holds, so the
#      sidecar is asked to SUCCEED at exactly what the agent must fail at.
#   3. Never score a skip as a pass.
#
# Linux containers only for the namespace assertions, but the pod shape itself is
# checked everywhere Docker runs.
#
#   ./run.sh pod-verify
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

IMAGE="${ANDYUR_SANDBOX_IMAGE:-andyur-runner}"
VENV="$HERE/.venv"
RUN_ID="podverify$$"
SIDECAR="andyur-run-$RUN_ID"
AGENTC="andyur-agent-$RUN_ID"
WORKDIR="$(mktemp -d)"
NET=""
# A value the agent must never be able to reach. Placed in the sidecar exactly
# where the real run token goes, so what the probe hunts for is the real thing in
# the real place.
CANARY="pod-canary-$RANDOM$RANDOM-do-not-leak"

PASS=0; FAIL=0
ok()   { printf '    \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '    \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '    \033[90mn/a\033[0m   %s\n' "$1"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f "$SIDECAR" "$AGENTC" >/dev/null 2>&1
  [ -z "$NET" ] || docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "image '$IMAGE' not found. Build it first: ./run.sh sandbox-image"; exit 1; }

# ---------------------------------------------------------------------------
step "reconstruct BOTH container commands from the orchestrator itself"
# Not written out by hand here. If the orchestrator changes what a pod looks
# like, this harness tests the new shape automatically -- or fails loudly below
# because a flag it depends on has gone.
cat > "$WORKDIR/build.py" <<'PY'
import sys
sys.path.insert(0, ".")
from andyur.daemon import orchestrator as o
which, run_id, canary = sys.argv[1], sys.argv[2], sys.argv[3]
if which == "sidecar":
    argv = o._sandbox_argv("probe", run_id, run_token=canary,
                           broker_token=canary + "-broker", channel_token="chtok",
                           pod=True)
else:
    argv = o._agent_argv("probe", run_id, channel_token="chtok")
sys.stdout.write("\0".join(argv))
PY
ANDYUR_PROFILE=dev ANDYUR_DEPLOYMENT=docker ANDYUR_SANDBOX=on ANDYUR_AGENT_SPLIT=pod \
  "$VENV/bin/python" "$WORKDIR/build.py" sidecar "$RUN_ID" "$CANARY" > "$WORKDIR/sidecar.argv" || {
    bad "could not build the sidecar command"; exit 1; }
ANDYUR_PROFILE=dev ANDYUR_DEPLOYMENT=docker ANDYUR_SANDBOX=on ANDYUR_AGENT_SPLIT=pod \
  "$VENV/bin/python" "$WORKDIR/build.py" agent "$RUN_ID" "$CANARY" > "$WORKDIR/agent.argv" || {
    bad "could not build the agent command"; exit 1; }

SIDE_ARGV=(); while IFS= read -r -d '' a; do SIDE_ARGV+=("$a"); done < "$WORKDIR/sidecar.argv"
AG_ARGV=();  while IFS= read -r -d '' a; do AG_ARGV+=("$a"); done < "$WORKDIR/agent.argv"

# A reconstruction that silently degraded to a short command would test nothing.
# Require the flags the properties below actually depend on.
for required in --cap-drop no-new-privileges --network --user; do
  case " ${AG_ARGV[*]} " in
    *" $required "*) : ;;
    *) bad "the agent command is missing $required -- the orchestrator interface"$'\n'"        changed or this reconstruction is stale; refusing to certify"; exit 1 ;;
  esac
done
ok "both commands built from andyur.daemon.orchestrator (single source of truth)"

# Form the topology through the same helpers as PodOrchestrator.launch. Merely
# replaying the two docker argv lists omits the lifecycle between them: create
# the per-run internal network, start the sidecar on its egress network, then
# attach it under the sealed alias before starting the single-homed agent.
NET="$("$VENV/bin/python" -c \
  "from andyur.daemon.orchestrator import run_network; print(run_network('$RUN_ID'))")"
"$VENV/bin/python" - "$NET" <<'PY' || {
import sys
from andyur.daemon.orchestrator import _net_create
raise SystemExit(0 if _net_create(sys.argv[1]) else 1)
PY
  bad "the orchestrator helper could not create the per-run network"; exit 1;
}
[ "$(docker network inspect -f '{{.Internal}}' "$NET" 2>/dev/null)" = "true" ] \
  && ok "the real helper created the per-run network as internal" \
  || { bad "the per-run network is absent or routable"; exit 1; }

# --- static properties, read off the REAL commands -------------------------
step "the agent command carries no credential (static)"
AG_STR="${AG_ARGV[*]}"
leaked=0
for secret in ANDYUR_RUN_TOKEN ANDYUR_BROKER_TOKEN ANDYUR_RUN_TOKEN_SECRET ANDYUR_SERVER_URL; do
  case "$AG_STR" in *"$secret"*) bad "the agent command carries $secret"; leaked=1 ;; esac
done
[ "$leaked" = "0" ] && ok "no run token, broker token, or control-plane address"
case "$AG_STR" in
  *"$CANARY"*) bad "the canary value itself appears in the agent command" ;;
  *) ok "the sidecar's credential value appears nowhere in the agent command" ;;
esac
# ...and the positive control: the sidecar DOES carry it, so the check above is
# not passing because the canary was never issued.
case "${SIDE_ARGV[*]}" in
  *"$CANARY"*) ok "positive control: the sidecar command does carry the credential" ;;
  *) bad "the sidecar has no credential either -- this test proves nothing" ;;
esac

# ---------------------------------------------------------------------------
step "form a real pod"
# The sidecar's command runs the real runner, which would exit without a control
# plane. Replace ONLY the trailing command (everything after the image) with a
# sleep, so every security-relevant flag still comes from the orchestrator.
side_flags=(); for a in "${SIDE_ARGV[@]}"; do
  [ "$a" = "$IMAGE" ] && break
  side_flags+=("$a")
done
# Prove the surgery took only the tail: the flags must be a prefix of the real
# command. Otherwise this harness is testing a container production never builds
# -- the failure mode that cost six rounds in the uid work.
if [ "${side_flags[*]}" = "${SIDE_ARGV[*]:0:${#side_flags[@]}}" ]; then
  ok "the sidecar stub keeps every flag of the real sidecar (only the command differs)"
else
  bad "the sidecar stub diverged from the real command"; exit 1
fi
"${side_flags[@]}" -d --entrypoint sh "$IMAGE" -c \
  "python -c \"
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200); s.end_headers(); s.wfile.write(b'sidecar-alive')
    def log_message(s,*a): pass
socketserver.TCPServer(('0.0.0.0', ${ANDYUR_CHANNEL_PORT:-8765}), H).serve_forever()
\"" >/dev/null 2>&1
sleep 2
if [ "$(docker inspect -f '{{.State.Running}}' "$SIDECAR" 2>/dev/null)" = "true" ]; then
  ok "the sidecar container is running"
else
  bad "the sidecar container did not start"; docker logs "$SIDECAR" 2>&1 | tail -5; exit 1
fi
"$VENV/bin/python" - "$NET" "$SIDECAR" <<'PY' || {
import sys
from andyur.daemon.orchestrator import _net_connect, SIDECAR_ALIAS
raise SystemExit(0 if _net_connect(sys.argv[1], sys.argv[2], SIDECAR_ALIAS) else 1)
PY
  bad "the orchestrator helper could not attach the sidecar to the run network"; exit 1;
}
ok "the real helper attached the sidecar under its sealed alias"

# The agent container, real command, but running a probe instead of the SDK.
ag_flags=(); for a in "${AG_ARGV[@]}"; do
  [ "$a" = "$IMAGE" ] && break
  ag_flags+=("$a")
done
if [ "${ag_flags[*]}" = "${AG_ARGV[*]:0:${#ag_flags[@]}}" ]; then
  ok "the agent probe keeps every flag of the real agent container"
else
  bad "the agent probe diverged from the real command"; exit 1
fi

probe() {   # run one shell snippet inside the REAL agent container shape
  "${ag_flags[@]}" --rm --entrypoint sh "$IMAGE" -c "$1" 2>&1
}

# THE PROBE ITSELF MUST BE KNOWN TO WORK. Every "the agent cannot X" check below
# reads probe's OUTPUT and concludes from emptiness -- so a probe container that
# never started (bad flag, missing image, dockerd hiccup) prints nothing, exits
# non-zero, and every one of those checks reports the boundary holding. That is
# the harness failing open, which is the defect this whole file exists to refuse.
# Establish once, loudly, that the probe runs and its output reaches us.
alive="$(probe 'echo PROBE-ALIVE')"
if [ "$alive" = "PROBE-ALIVE" ]; then
  ok "the probe container runs and its output is captured"
else
  bad "the probe container does not run (got: '$alive'); every 'the agent cannot'"$'\n'"        check below would pass on silence. Refusing to certify."
  exit 1
fi

# ---------------------------------------------------------------------------
step "the agent container is unprivileged from PID 1"
uid_out="$(probe 'id -u')"
[ "$uid_out" = "1001" ] \
  && ok "the agent runs as uid 1001 without ever being root (got '$uid_out')" \
  || bad "the agent's uid is '$uid_out', expected 1001"

step "the agent holds no credential AT RUNTIME"
env_out="$(probe 'env')"
held=""
for secret in ANDYUR_RUN_TOKEN ANDYUR_BROKER_TOKEN ANDYUR_RUN_TOKEN_SECRET; do
  case "$env_out" in *"$secret="*) held="$held $secret" ;; esac
done
[ -z "$held" ] && ok "no control-plane credential in the agent's environment" \
                || bad "the agent's environment holds:$held"
case "$env_out" in
  *"$CANARY"*) bad "the sidecar's credential VALUE is in the agent's environment" ;;
  *) ok "the sidecar's credential value is absent from the agent's environment" ;;
esac

step "the agent cannot see the sidecar at all (PID namespace)"
# The upgrade over the uid split. There, the runner's process existed and was
# merely unreadable; here it is not in the namespace, so there is nothing to
# address. Assert the agent's PID 1 is ITSELF, not the sidecar's process.
pid1="$(probe 'cat /proc/1/cmdline | tr "\0" " "')"
case "$pid1" in
  *serve_forever*|*http.server*) bad "the agent can see the SIDECAR's process as PID 1" ;;
  *) ok "the agent's PID 1 is its own process, not the sidecar's" ;;
esac
# and the canary is in no process environment reachable from the agent
found="$(probe "grep -l '$CANARY' /proc/*/environ 2>/dev/null | head -3")"
[ -z "$found" ] \
  && ok "the sidecar's credential is in no /proc the agent can reach" \
  || bad "the agent found the credential in: $found"
# POSITIVE CONTROL: the same grep, run INSIDE THE SIDECAR, must FIND it. Without
# this, a probe whose grep silently does nothing reports the same clean result.
side_found="$(docker exec "$SIDECAR" sh -c "grep -l '$CANARY' /proc/*/environ 2>/dev/null | head -1")"
[ -n "$side_found" ] \
  && ok "positive control: the sidecar CAN find its own credential ($side_found)" \
  || bad "the credential is unreadable even to the sidecar -- the probe is broken,"$'\n'"        so the agent's 'cannot read' above proves nothing"

step "nothing in the agent container's own /proc is a credential"
# WHY THIS IS SEPARATE from the sidecar sweep above. In pod mode the agent
# process and the agent CLI are BOTH uid 1001 in this container, so they can read
# each other's /proc/<pid>/environ -- and os.environ.pop() cannot prevent it,
# because that file is the exec-time snapshot. Verified: the CLI can read the
# agent process's environment.
#
# That is only harmless because of what is NOT there. So sweep every environment
# reachable inside this container and require that none of them holds a
# control-plane credential. This is the assertion that keeps "the agent container
# holds nothing" true as the code changes -- the day someone passes a real secret
# to the agent process by environment, this goes red.
sweep="$(probe 'for p in /proc/[0-9]*; do tr "\0" "\n" < $p/environ 2>/dev/null; done \
  | grep -E "^(ANDYUR_RUN_TOKEN|ANDYUR_RUN_TOKEN_SECRET|ANDYUR_BROKER_TOKEN|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN)=." \
  | sed "s/=.*/=<redacted>/" | sort -u')"
[ -z "$sweep" ] \
  && ok "no control-plane credential in ANY process environment in the agent container" \
  || bad "the agent container's /proc holds credentials: $(echo "$sweep" | tr '\n' ' ')"
# POSITIVE CONTROL: the same sweep must FIND a credential when one is planted,
# or it is a grep that can never fail.
planted="$("${ag_flags[@]}" --rm -e ANDYUR_RUN_TOKEN=planted-canary --entrypoint sh "$IMAGE" -c \
  'for p in /proc/[0-9]*; do tr "\0" "\n" < $p/environ 2>/dev/null; done | grep -c "^ANDYUR_RUN_TOKEN=." ' 2>/dev/null | tr -d ' ')"
[ "${planted:-0}" -gt 0 ] 2>/dev/null \
  && ok "positive control: the sweep does detect a planted credential" \
  || bad "the sweep cannot detect even a planted credential -- it proves nothing"

step "the agent has no identity and no host filesystem"
sp="$(probe 'ls /run/spire/sockets 2>&1; echo "---"; ls /run/spire 2>&1')"
case "$sp" in
  *"No such file"*) ok "no SPIRE Workload API socket: the agent cannot attest as anything" ;;
  *) bad "a SPIRE socket path is present in the agent container: $sp" ;;
esac
# `wc -l`, NOT `grep -c ... || echo 0`. grep -c exits non-zero on a zero count, so
# the fallback fired as well and the value became the two-line string "0\n0" --
# which compares equal to nothing and reported a failure with a mangled number.
# The same shape (`|| echo 0` swallowing a non-result) produced a FALSE PASS in
# verify-e2e.sh; here it produced a false FAIL. Counting with wc needs no
# arithmetic and no fallback.
mounts="$(probe 'grep -E " /(host|mnt|Users|media|host_mnt) " /proc/self/mountinfo 2>/dev/null | wc -l | tr -d " "')"
[ "${mounts:-1}" = "0" ] && ok "no host filesystem mounted into the agent" \
                         || bad "the agent has $mounts host mount(s)"

step "the pod IS a pod: the single-homed agent reaches only its sidecar alias"
# The other half of the claim. If this fails the boundary is airtight and the
# platform does not work, which is not a win.
reach="$(probe "python -c \"
import urllib.request
print(urllib.request.urlopen('http://sidecar:${ANDYUR_CHANNEL_PORT:-8765}', timeout=5).read().decode())
\"")"
case "$reach" in
  *sidecar-alive*) ok "the agent reached the sidecar's channel port over its sealed alias" ;;
  *) bad "the agent could not reach the sidecar: $reach" ;;
esac
# ...and that port is NOT exposed to the host, which makes the private network
# a boundary rather than a convenience.
if curl -s -m 3 "http://127.0.0.1:${ANDYUR_CHANNEL_PORT:-8765}" >/dev/null 2>&1; then
  bad "the channel port is reachable from the HOST -- the pod is not private"
else
  ok "the channel port is not published to the host"
fi

step "privilege cannot be regained"
esc="$(probe 'command -v su sudo setpriv newgrp 2>/dev/null | head -5')"
if [ -n "$esc" ]; then
  # present is fine; USABLE is not. no-new-privileges plus no setuid bits.
  suid="$(probe 'find / -xdev -perm -4000 -type f 2>/dev/null | head -3')"
  [ -z "$suid" ] && ok "no setuid binary exists in the agent image to escalate with" \
                 || bad "setuid binaries present in the agent container: $suid"
else
  ok "no privilege-escalation helpers on PATH"
fi
whoami_after="$(probe 'setpriv --reuid=0 id -u 2>&1 || true')"
case "$whoami_after" in
  0) bad "the agent escalated to root with setpriv" ;;
  *) ok "the agent cannot setpriv back to root" ;;
esac

# ---------------------------------------------------------------------------
step "the kill switch destroys BOTH halves"
"${ag_flags[@]}" -d --entrypoint sh "$IMAGE" -c 'sleep 300' >/dev/null 2>&1
sleep 1
before="$(docker ps -q --filter "name=^($SIDECAR|$AGENTC)$" | wc -l | tr -d ' ')"
if [ "$before" != "2" ]; then
  bad "expected both halves running before the kill (saw $before)"
else
  ANDYUR_PROFILE=dev ANDYUR_DEPLOYMENT=docker ANDYUR_SANDBOX=on ANDYUR_AGENT_SPLIT=pod \
    "$VENV/bin/python" -c "
import sys; sys.path.insert(0, '.')
from andyur.daemon import orchestrator as o
o.PodOrchestrator().kill(['$RUN_ID'])" >/dev/null 2>&1
  sleep 2
  after="$(docker ps -q --filter "name=^($SIDECAR|$AGENTC)$" | wc -l | tr -d ' ')"
  [ "$after" = "0" ] \
    && ok "one kill destroyed the sidecar AND the agent container" \
    || bad "$after container(s) survived the kill -- a halted run keeps executing"
fi

printf '\n\033[1mpassed: %d   failed: %d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || { printf '\033[31mPOD BOUNDARY: FAILED\033[0m\n'; exit 1; }
printf '\033[32mPOD BOUNDARY: VERIFIED\033[0m\n'

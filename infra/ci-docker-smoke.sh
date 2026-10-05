#!/usr/bin/env bash
# Gap 15b: prove the SHIPPED Docker deployment SATISFIES its own production
# profile, not merely that an unconfigured one refuses.
#
# The incident is the argument. CI asserted for weeks that ANDYUR_PROFILE=prod
# REFUSES an uncontained deployment, and nothing asserted that the shipped
# compose (which pins prod) still met the requirements it kept acquiring. So
# f377727 added a boot requirement the compose did not satisfy, and
# `./run.sh docker-up` -- the README-documented deployment -- crash-looped on
# InsecureProfile for two days before anything ran it. Same class, same week,
# twice more (the rotted user-idp harness; unchecked ANDYUR_BROKER_ENABLED).
# Deployment-level refusal without a positive control is how that happens.
#
# This runs the documented operator path, headless, end to end:
#   idp up -> idp wire -> docker-up -> /health answers -> anonymous refused
# It does NOT re-prove enforcement semantics; that is verify-idp-composed.sh's
# job. This proves the default path BOOTS, which is the leg CI never had.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say(){ printf '\n== %s ==\n' "$*"; }

# Teardown. On a throwaway CI runner leaving the stack up was invisible; on a
# shared local host (ci-local.sh marathon) it is not: andyur-server + worker
# left running after this gate starved the container starts of later gates
# (pod-verify "sidecar did not start", sre-verify "no decision"), failures
# that never reproduced in isolation. So the gate reaps what IT brought up,
# and only that: a tier that was already running before the gate began
# belongs to the operator (or another session) and is left alone. Persistent
# state survives either way (docker-down and idp down both retain volumes).
# SMOKE_KEEP_STACK=1 skips the teardown for local debugging of a red.
running(){ [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]; }
running andyur-server   && had_stack=1 || had_stack=0
running andyur-keycloak && had_idp=1   || had_idp=0
teardown(){
  rc=$?
  trap - EXIT
  if [ "${SMOKE_KEEP_STACK:-0}" = "1" ]; then
    echo "SMOKE_KEEP_STACK=1: leaving the stack running" >&2
    exit "$rc"
  fi
  [ "$had_stack" = 0 ] && "$HERE/run.sh" docker-down < /dev/null >/dev/null 2>&1 || true
  [ "$had_idp" = 0 ]   && "$HERE/run.sh" idp down    < /dev/null >/dev/null 2>&1 || true
  exit "$rc"
}
trap teardown EXIT

say "reference IdP up (realm imported, demo users created at setup)"
"$HERE/run.sh" idp up < /dev/null

say "idp wire: stage user-auth into the shipped env, as the docs instruct"
# Staging the env is the claim here, not reconfiguration. On a fresh runner
# there is no control plane to reconfigure; on a dirty machine a server
# crash-looping on a broken IMAGE cannot be healed by wire's recreate (it
# reuses the image) and needs docker-up's rebuild below. The boot assertions
# after docker-up are the arbiter either way, so wire failing to reach a
# healthy server is not, by itself, a smoke failure -- while a wire that
# failed to STAGE shows up downstream as the InsecureProfile red this smoke
# exists to catch.
"$HERE/run.sh" idp wire < /dev/null || true

say "docker-up: the shipped compose must boot under its pinned prod profile"
"$HERE/run.sh" docker-up < /dev/null

say "the server reaches healthy (compose returning is not the same claim)"
state=""
for _ in $(seq 1 90); do
  state="$(docker inspect -f '{{.State.Health.Status}}' andyur-server 2>/dev/null || true)"
  [ "$state" = "healthy" ] && break
  sleep 2
done
if [ "$state" != "healthy" ]; then
  echo "andyur-server is '${state:-absent}', not healthy; last log lines:" >&2
  docker logs andyur-server 2>&1 | tail -25 >&2
  exit 1
fi
echo "healthy"

say "positive control: /health answers from the host"
curl -sf --max-time 10 "http://127.0.0.1:8642/health" >/dev/null
echo "answered"

say "negative control: the API is not anonymously open while /health answers"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  "http://127.0.0.1:8642/agents")"
if [ "$code" != "401" ] && [ "$code" != "403" ]; then
  echo "GET /agents with no credential answered $code; expected 401/403" >&2
  exit 1
fi
echo "refused ($code)"

say "docker smoke GREEN: the shipped deployment satisfies its own prod profile"

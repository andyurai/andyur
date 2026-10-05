#!/usr/bin/env bash
# Run the andyur CI gates locally, on this machine, instead of on GitHub-hosted
# runners.
#
# WHY THIS EXISTS. andyur-ci.yml runs ~8 ubuntu-latest jobs per push, and on a
# PRIVATE repository every one of those minutes is billed to the account's
# Actions quota. When the quota is exhausted GitHub fails every job at
# scheduling -- no steps recorded, empty logs, a few seconds each -- regardless
# of what the commit changed. CI goes dark for a reason that has nothing to do
# with the code. This script reproduces the same gates on the developer's own
# machine at zero Actions cost, by calling the SAME verify-* scripts the
# workflow calls. There is no second copy of any check here that could drift
# from CI: this file only ORCHESTRATES, the gates themselves stay in one place.
#
# THE LINUX GATES RUN THROUGH DOCKER, NOT THE HOST. uid-verify, seccomp-verify
# and pod-verify assert INSIDE Linux run containers, so Docker Desktop's Linux
# VM gives them the correct kernel semantics (/proc ownership, seccomp, PID and
# mount namespaces) even though the host is macOS. The comment in andyur-ci.yml
# that "developer machines are macOS, where /proc does not exist" is about the
# HOST; the probe runs in the container, which is Linux either way.
#
# HONEST SKIPS. One job cannot run here: identity-stack downloads and runs a
# linux-amd64 SPIRE binary ON THE HOST, which a macOS host cannot execute. It is
# reported as SKIP with the reason, never silently passed -- and the same SPIRE
# behaviour it would prove is covered by the actor-leg gate, which uses the
# CONTAINERIZED SPIRE stack. A green summary means the gates that RAN passed and
# names every gate that did not, because a skip that reads like a pass is exactly
# the decayed-verification failure this whole workflow was built to prevent.
#
#   Usage:
#     infra/ci-local.sh            full: unit + every Docker gate (several minutes)
#     infra/ci-local.sh fast       the unit suite only, no Docker (about a minute)
#     infra/ci-local.sh -h         this help
#
# Exit status is non-zero if any gate that RAN failed. Skips do not fail the run.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # the agentic-platform root
cd "$HERE"

if [ -t 1 ]; then
  BOLD=$'\033[1m'; GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=""; GRN=""; RED=""; YEL=""; DIM=""; RST=""
fi

PASS=0; FAIL=0; SKIP=0

# EVERY andyur-ci.yml JOB MUST BE ACCOUNTED FOR HERE, and the accounting is
# CHECKED, not trusted.
#
# This file once omitted `shipping-config` entirely -- not run, and not even
# declared as a skip -- for long enough that "the local gates are green" was
# quoted as release evidence while the one job exercising the PRODUCTION profile
# had never run. The header below promises that a skip is never silently a pass;
# an omission is worse, because it is not visible at all.
#
# So the harness now derives the workflow's job list at runtime and refuses to
# start if any job is neither mapped to a local gate nor given an explicit
# reason. Forgetting becomes an error instead of a habit.
COVERAGE="\
unit|the pytest suite below
identity-stack|SKIP: fetches and runs a linux-amd64 SPIRE binary on the HOST; containerized SPIRE is covered by actor-leg
postgres|coordination-pg below
temporal|temporal below
shipping-config|shipping-config below
docker-smoke|docker-smoke below
containment|opa-hardening + opa + egress + sandbox-image + uid-verify + seccomp-verify + pod-verify below
actor-leg|actor-leg below
sre-registry-gate|sre-registry-gate below"

check_job_coverage() {
  local wf="$HERE/../.github/workflows/andyur-ci.yml" job missing=0
  [ -f "$wf" ] || { echo "cannot find andyur-ci.yml at $wf" >&2; return 1; }
  # Top-level keys under `jobs:` -- two-space indent, then a name and a colon.
  for job in $(awk '/^jobs:/{i=1;next} i&&/^  [a-z0-9][a-z0-9-]*:/{gsub(/[ :]/,"");print}' "$wf"); do
    printf '%s\n' "$COVERAGE" | grep -q "^$job|" || {
      echo "  UNACCOUNTED CI JOB: $job" >&2; missing=1; }
  done
  [ "$missing" = 0 ] || {
    echo "" >&2
    echo "andyur-ci.yml defines a job this harness neither runs nor explicitly" >&2
    echo "skips. Add it to COVERAGE with a gate or a stated reason -- an" >&2
    echo "unmentioned job is invisible, and invisible reads as covered." >&2
    return 1; }
  return 0
}
declare -a RESULTS
PY="$HERE/.venv/bin/python"

say()  { printf '\n%s==>%s %s%s%s\n' "$BOLD" "$RST" "$BOLD" "$*" "$RST"; }

run_gate() {   # run_gate "label" command...
  local label="$1"; shift
  say "$label"
  local start=$SECONDS rc
  "$@"; rc=$?
  local d=$((SECONDS - start))
  if [ "$rc" -eq 0 ]; then
    PASS=$((PASS + 1)); RESULTS+=("${GRN}PASS${RST}  ${label} (${d}s)")
    printf '%sPASS%s %s (%ss)\n' "$GRN" "$RST" "$label" "$d"
  else
    FAIL=$((FAIL + 1)); RESULTS+=("${RED}FAIL${RST}  ${label} (${d}s, exit ${rc})")
    printf '%sFAIL%s %s (%ss, exit %s)\n' "$RED" "$RST" "$label" "$d" "$rc"
  fi
}

skip_gate() {  # skip_gate "label" "reason"
  SKIP=$((SKIP + 1)); RESULTS+=("${YEL}SKIP${RST}  $1 ${DIM}-- $2${RST}")
  printf '%sSKIP%s %s %s-- %s%s\n' "$YEL" "$RST" "$1" "$DIM" "$2" "$RST"
}

# The shipped configuration, which the pytest suite structurally cannot cover:
# tests/conftest.py sets ANDYUR_PROFILE=dev for the whole suite, so all ~2288
# tests are a DEV deployment and the configuration that actually ships is
# exercised by none of them. Needs no Docker, so it runs in the fast tier too.
#
# Both checks are NEGATIVE, and each is pinned to the exact refusal rather than
# to "it failed": a prod deployment that died for an unrelated reason would
# otherwise pass this gate for the wrong reason.
shipping_config_gate() {
  "$PY" - <<'PYEOF'
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath("."))
def assert_profile(env, must_contain=None):
    """Run config.assert_profile() under `env`; require refusal, and if given,
    require the refusal to name `must_contain`."""
    done = subprocess.run(
        [sys.executable, "-c",
         "from andyur import config; config.assert_profile()"],
        capture_output=True, text=True, env={**os.environ, **env})
    if done.returncode == 0:
        return f"accepted a configuration it must refuse ({env.get('_case')})"
    blob = done.stdout + done.stderr
    if must_contain and must_contain not in blob:
        return (f"refused, but not for the stated reason: expected "
                f"{must_contain!r} in the refusal, got: {blob.strip()[:200]}")
    return None

problems = []
# 1. An unconfigured production deployment must refuse to serve.
p = assert_profile({"ANDYUR_PROFILE": "prod", "_case": "unconfigured prod"})
if p: problems.append(p)

# 2. A provider NAME must not stand in for live AS certification. The complete
#    structural control set is supplied and only the signed tenant-specific
#    conformance result is withheld, so a pass here would mean the name alone
#    bought the capability.
certified = {
    "ANDYUR_PROFILE": "prod", "ANDYUR_DEPLOYMENT": "docker",
    "ANDYUR_SANDBOX": "on", "ANDYUR_AGENT_AUTH": "on",
    "ANDYUR_USER_AUTH": "on", "ANDYUR_REQUIRE_RUN_SVID": "on",
    "ANDYUR_AS_TOKEN_ENDPOINT": "https://as.invalid/oauth/token",
    "ANDYUR_AS_ISSUER": "https://as.invalid",
    "ANDYUR_AS_CLIENT_ID": "andyur-ci", "ANDYUR_AS_CLIENT_SECRET": "ci-secret",
    "ANDYUR_AS_JWKS": "https://as.invalid/.well-known/jwks.json",
    "ANDYUR_AS_PROVIDER": "keycloak", "ANDYUR_AS_CAPABILITY": "core",
    "ANDYUR_SECCOMP": "require", "ANDYUR_SANDBOX_NETWORK": "andyur-runs",
    "ANDYUR_DELEGATIONS": "*", "ANDYUR_RUN_TOKEN_SECRET": "ci-secret",
    "ANDYUR_LLM": "ollama",
    # Explicit, not inherited: the broker requirement follows the KEY, so a host
    # that happens to have one would fail for the wrong reason and a host that
    # does not would pass without exercising the requirement at all.
    "ANDYUR_BROKER_URL": "http://127.0.0.1:8643",
    "ANTHROPIC_API_KEY": "sk-ant-ci-placeholder",
    "_case": "uncertified AS provider",
}
p = assert_profile(certified, must_contain="ANDYUR_AS_CERTIFICATION_FILE is required")
if p: problems.append(p)

for problem in problems:
    print(f"    {problem}")
sys.exit(1 if problems else 0)
PYEOF
}

# The containerized SPIRE stack is shared by the actor-leg and sre gates. Bring
# it up at most once, and tear it down on exit so a local run leaves nothing
# holding ports behind it.
SPIRE_UP=0
ensure_spire() {
  [ "$SPIRE_UP" = 1 ] && return 0
  if ./run.sh spire-docker up; then SPIRE_UP=1; return 0; fi
  return 1
}
cleanup() {
  [ "$SPIRE_UP" = 1 ] && ./run.sh spire-docker down >/dev/null 2>&1 || true
  docker rm -f "$TEMPORAL_CTR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

have_docker() { docker info >/dev/null 2>&1; }

# The durable provider against a REAL Temporal, as andyur-ci.yml's temporal job
# runs it: the same pinned admin-tools image and the same four integration
# modules, with the REQUIRE variables so a missing service FAILS rather than
# skips. Its own container on its own port, because a developer machine often
# already has a `temporal server start-dev` on 7233, and a gate that quietly
# ran against that one would be certifying whatever state it happens to hold.
TEMPORAL_IMAGE="docker.io/temporalio/admin-tools@sha256:f048113e98748c6b902e1962e3225082f42a4760467aaeda139e67c4aa692231"
TEMPORAL_CTR="andyur-ci-local-temporal"
TEMPORAL_PORT="${ANDYUR_CI_TEMPORAL_PORT:-17233}"
temporal_gate() {
  docker rm -f "$TEMPORAL_CTR" >/dev/null 2>&1 || true
  docker run -d --name "$TEMPORAL_CTR" -p "127.0.0.1:$TEMPORAL_PORT:7233" \
    --entrypoint temporal "$TEMPORAL_IMAGE" \
    server start-dev --ip 0.0.0.0 --headless >/dev/null || return 1
  local i up=0
  for i in $(seq 1 60); do
    docker exec "$TEMPORAL_CTR" temporal operator cluster health --address localhost:7233 \
      >/dev/null 2>&1 && { up=1; break; }
    sleep 2
  done
  [ "$up" = 1 ] || { docker logs "$TEMPORAL_CTR" | tail -20; return 1; }
  ANDYUR_TEMPORAL_ADDRESS="localhost:$TEMPORAL_PORT" ANDYUR_REQUIRE_TEMPORAL=1 \
  ANDYUR_REQUIRE_DOCKER=1 "$PY" -m pytest -q -m integration \
    tests/test_temporal_campaign.py \
    tests/orchestration_contract/test_provider_conformance.py \
    tests/test_engine_authorizer.py \
    tests/test_bplus_engine_dispatch.py
}

case "${1:-full}" in -h|--help|help) sed -n '1,32p' "${BASH_SOURCE[0]}"; exit 0;; esac
TIER="${1:-full}"
[ "$TIER" = fast ] || [ "$TIER" = full ] || { echo "usage: $0 [full|fast]" >&2; exit 2; }

# --- preflight ---------------------------------------------------------------
[ -x "$PY" ] || { echo "no venv at $PY -- run ./run.sh setup first" >&2; exit 1; }
check_job_coverage || exit 1
printf '%sandyur local CI%s  tier=%s  arch=%s  %s\n' "$BOLD" "$RST" "$TIER" "$(uname -m)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- unit (native) -----------------------------------------------------------
# The fast suite, the attack suites included. Runs natively; no Docker needed.
run_gate "unit: the full pytest suite" "$PY" -m pytest -q
run_gate "shipping-config: the PRODUCTION profile refuses what it must (no Docker)" \
         shipping_config_gate

if [ "$TIER" = fast ]; then
  :
elif ! have_docker; then
  skip_gate "docker-smoke / opa / egress / uid / seccomp / pod / coordination-pg / actor-leg" \
            "Docker is not running -- start Docker Desktop, then re-run"
else
  # --- Docker-backed gates (Linux semantics via Docker Desktop's VM) ---------
  run_gate "docker-smoke: the shipped deployment satisfies its production profile" \
           bash infra/ci-docker-smoke.sh
  run_gate "opa-hardening: the policy engine cannot be turned against the platform" \
           bash infra/opa/verify-opa-hardening.sh
  run_gate "opa: the external PDP still agrees with the builtin one" \
           bash infra/opa/verify-opa.sh
  run_gate "egress: an agent has nowhere to send what it reads" \
           bash infra/verify-egress.sh
  run_gate "sandbox-image: build the runner image the boundary tests run in" \
           ./run.sh sandbox-image
  run_gate "uid-verify: the agent uid cannot read the runner's secrets" \
           ./run.sh uid-verify
  run_gate "seccomp-verify: the seccomp filter is LOADED, not merely configured" \
           ./run.sh seccomp-verify
  run_gate "pod-verify: the agent container cannot reach the sidecar's credentials" \
           ./run.sh pod-verify
  run_gate "coordination-pg: the coordination paths on real Postgres, concurrent replicas" \
           bash infra/verify-coordination-pg.sh
  run_gate "temporal: the durable provider, the engine authorizer and B+ dispatch on a real Temporal" \
           temporal_gate

  if ensure_spire; then
    run_gate "actor-leg: the RFC 8693 actor leg on the wire (containerized SPIRE)" \
             ./run.sh actor-leg-verify
  else
    skip_gate "actor-leg" "the containerized SPIRE stack failed to come up"
  fi

  if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    if ensure_spire; then
      run_gate "sre-registry-gate: the registry-driven SRE run through the external AS" \
               ./run.sh sre-verify
    else
      skip_gate "sre-registry-gate" "the containerized SPIRE stack failed to come up"
    fi
  else
    skip_gate "sre-registry-gate" "nightly gate; set ANTHROPIC_API_KEY to run it"
  fi
fi

# identity-stack is the one job that cannot run on a macOS host: it fetches and
# runs a linux-amd64 SPIRE binary directly on the host, not in a container. The
# same SPIRE identity behaviour is exercised through the containerized stack by
# the actor-leg gate above.
if [ "$TIER" = full ]; then
  if [ "$(uname -s)" = Darwin ]; then
    skip_gate "identity-stack" "runs a linux-amd64 SPIRE binary on the HOST; not executable on macOS (containerized SPIRE is covered by actor-leg)"
  else
    skip_gate "identity-stack" "not yet wired into local CI; run it in andyur-ci.yml or add it here"
  fi
fi

# --- summary -----------------------------------------------------------------
printf '\n%s---- local CI summary ----%s\n' "$BOLD" "$RST"
for line in "${RESULTS[@]}"; do printf '  %s\n' "$line"; done
printf '\n%s%d passed, %d failed, %d skipped%s\n' "$BOLD" "$PASS" "$FAIL" "$SKIP" "$RST"
[ "$FAIL" -eq 0 ]

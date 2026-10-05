#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"

ROLES="$HERE/infra/roles/bin"
SITE="$VENV/lib/python3.12/site-packages"

# Resolve the interpreter for an Andyur role. If per-role binaries have been
# built (./run.sh spire-setup), use the role's distinct executable so the
# SPIRE unix attestor can identify it by path; otherwise fall back to the
# plain venv python (identity disabled).
role_py() {
  if [ -x "$ROLES/andyur-$1" ]; then
    echo "env PYTHONPATH=$SITE $ROLES/andyur-$1"
  else
    echo "$VENV/bin/python"
  fi
}

SPIRE_BIN="$HERE/infra/spire/bin"
NODE_ID="spiffe://andyur.local/node"

# SPIRE IS PINNED, AND IT IS NOT DOWNLOADABLE ON EVERY PLATFORM.
# Upstream publishes release binaries for linux-amd64, linux-arm64 and windows
# only -- there is NO darwin build. That is why this project's own macOS
# binaries report `1.15.1-dev-unk` (a source build) and why `docker-up`, which
# runs SPIRE in a container, is the supported single-host install.
# 1.11.2 is not an arbitrary pin: it is what .github/workflows/andyur-ci.yml
# downloads and checksum-verifies, and what infra/spire/docker/*.sh run as
# ghcr.io/spiffe/spire-{server,agent}:1.11.2. The local macOS build happened to
# be a 1.15.1 source build, which made three places disagree about the version
# under test. CI is the authority, because CI is the one that actually runs.
SPIRE_VERSION="${ANDYUR_SPIRE_VERSION:-1.11.2}"
# sha256 of the official tarballs, recorded HERE rather than taken from the
# release's own *_sha256sum.txt. A digest fetched from the same host as the
# archive proves the download was not truncated; it does not prove the archive
# is the one this pin was reviewed against.
SPIRE_SHA256_linux_amd64="ac53853d478175f15cec8a3757d71638d0821126c0d69583ed4141399e01c49f"
SPIRE_SHA256_linux_arm64="256a8c027eb028c40d27b8d9620763923537102178b3abf698ea12882856cca4"

spire_platform() {
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)               echo linux-amd64 ;;
    Linux-aarch64|Linux-arm64)  echo linux-arm64 ;;
    Darwin-*)                   echo darwin ;;
    *)                          echo unsupported ;;
  esac
}

# Download the pinned release and verify it against the digest above.
fetch_spire() {
  local plat tarball url want got tmp
  plat="$(spire_platform)"
  eval "want=\${SPIRE_SHA256_${plat//-/_}:-}"
  if [ -z "$want" ]; then
    echo "no pinned SPIRE release for $plat" >&2; return 1
  fi
  tarball="spire-$SPIRE_VERSION-$plat-musl.tar.gz"
  url="https://github.com/spiffe/spire/releases/download/v$SPIRE_VERSION/$tarball"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/andyur-spire-XXXXXX")"
  echo "fetching SPIRE $SPIRE_VERSION for $plat..."
  curl -sSfL --max-time 180 -o "$tmp/$tarball" "$url" || {
    echo "could not download $url" >&2; rm -rf "$tmp"; return 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "$tmp/$tarball" | awk '{print $1}')"
  fi
  if [ "$got" != "$want" ]; then
    echo "REFUSING: $tarball sha256 $got does not match the pinned $want" >&2
    rm -rf "$tmp"; return 1
  fi
  mkdir -p "$SPIRE_BIN"
  tar -xzf "$tmp/$tarball" -C "$tmp"
  cp "$tmp"/spire-*/bin/spire-server "$tmp"/spire-*/bin/spire-agent "$SPIRE_BIN/"
  chmod +x "$SPIRE_BIN/spire-server" "$SPIRE_BIN/spire-agent"
  rm -rf "$tmp"
  echo "SPIRE $SPIRE_VERSION installed to $SPIRE_BIN"
}

# Build the pinned tag from source. The only option on macOS, where upstream
# ships nothing; needs a Go toolchain.
build_spire() {
  command -v go >/dev/null 2>&1 || { echo "go is not installed" >&2; return 1; }
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/andyur-spire-src-XXXXXX")"
  echo "building SPIRE v$SPIRE_VERSION from source (needs Go; a few minutes)..."
  git clone --depth 1 --branch "v$SPIRE_VERSION" \
      https://github.com/spiffe/spire "$tmp/spire" >/dev/null 2>&1 || {
    echo "could not clone spiffe/spire at v$SPIRE_VERSION" >&2
    rm -rf "$tmp"; return 1; }
  mkdir -p "$SPIRE_BIN"
  ( cd "$tmp/spire" \
    && go build -o "$SPIRE_BIN/spire-server" ./cmd/spire-server \
    && go build -o "$SPIRE_BIN/spire-agent"  ./cmd/spire-agent ) || {
    echo "go build failed" >&2; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  echo "SPIRE v$SPIRE_VERSION built into $SPIRE_BIN"
}

# infra/spire/bin is gitignored build output, so on a FRESH CLONE it is always
# empty and nothing in the tree used to create it. `up` walked straight past
# that: it waited 20 seconds for a server that could never start, then died
# inside a python one-liner with `JSONDecodeError: Expecting value` -- a
# stranger's first command failing with a stack trace about JSON. Now the
# missing binary is named, and acquiring it is attempted rather than assumed.
ensure_spire_binaries() {
  [ -x "$SPIRE_BIN/spire-server" ] && [ -x "$SPIRE_BIN/spire-agent" ] && return 0
  local plat; plat="$(spire_platform)"
  echo "SPIRE binaries are not in $SPIRE_BIN (gitignored build output)."
  case "$plat" in
    linux-*) if fetch_spire; then return 0; fi ;;
    darwin)
      echo "Upstream SPIRE publishes no macOS binaries, so there is nothing to"
      echo "download. Two ways forward:"
      echo "  ./run.sh docker-up     the SUPPORTED install; runs SPIRE in a"
      echo "                         container, needs no Go toolchain"
      echo "  ./run.sh spire-build   build v$SPIRE_VERSION from source (needs Go)"
      if command -v go >/dev/null 2>&1; then
        echo "Go is present, so building now."
        if build_spire; then return 0; fi
      fi ;;
  esac
  echo "" >&2
  echo "Cannot continue without a SPIRE server and agent: workload identity is" >&2
  echo "not optional (see andyur/identity.py). Use ./run.sh docker-up instead." >&2
  return 1
}

# Parent each role identity to the stable node alias, keyed on the role binary's
# path (+ this uid). Self-healing: prior entries are removed first so re-running
# fixes drift instead of piling up duplicates. Requires the SPIRE server up.
# The single source of truth for role registration; both `spire-setup` and
# `ensure_spire` call it.
#
# WHY PATH AND NOT unix:sha256, WHICH WAS TRIED AND REVERTED. A path selector is
# an absolute path into whichever checkout ran `run.sh up`, which is half of why
# a gate is reproducible only there (ROADMAP.md 31), so keying on
# the binary's content looks like the obvious fix.
#
# IT IS NOT AVAILABLE, because the role binaries are IDENTICAL BY DESIGN.
# infra/spire/setup-roles.sh copies ONE standalone interpreter to five names --
# its own header says the roles are told apart BY PATH -- so all five share a
# sha256. Under content selection every role entry matches every role binary,
# and the runner can be issued the CONTROL PLANE's SVID.
#
# It passed locally and CI caught it. On macOS `codesign -f -s -` re-signs each
# copy and the signatures differ, so the five hashes differ and roles appear to
# separate; on Linux codesign is a no-op and two copies are byte-identical
# (verified both ways). A development machine masked a total collapse of role
# separation.
#
# Making content selection real means making the binaries genuinely distinct,
# which is a change to the attestation model and not to this line.
register_role_identities() {
  local SS="$SPIRE_BIN/spire-server" UID_SEL="unix:uid:$(id -u)" pair id bin eid
  echo "parenting role identities to: $NODE_ID"
  for pair in "control-plane:andyur-server" "worker:andyur-worker" \
              "runner:andyur-runner" "operator:andyur-operator" \
              "broker:andyur-broker"; do
    id="${pair%%:*}"; bin="${pair##*:}"
    "$SS" entry show -spiffeID "spiffe://andyur.local/$id" -output json |
      "$VENV/bin/python" -c "import json,sys;[print(e['id']) for e in json.load(sys.stdin).get('entries',[])]" |
      while read -r eid; do "$SS" entry delete -entryID "$eid" >/dev/null 2>&1 || true; done
    if [ ! -x "$ROLES/$bin" ]; then
      echo "  WARNING: $ROLES/$bin is missing; $id will not be registered" >&2
      continue
    fi
    # THE JWT-SVID TTL, WHICH THIS OMITTED. Role entries took SPIRE's default
    # (300s), and the runner refuses to use an actor SVID whose lifetime cannot
    # cover the remaining run plus the refresh margin -- correctly, because a
    # token that expires mid-run makes tools vanish with nothing to read. So on
    # THIS stack every managed-tool call was withheld:
    #
    #   [runner] tool egress: no actor SVID (JWT-SVID lifetime 298s is shorter
    #   than the remaining run plus refresh margin (960s)); the exchange will
    #   fail closed
    #
    # which is every authority/delegation demo, silently, for anyone who tried
    # one on the dev stack. Sized by the same 2x rule andyur/spire_registrar.py
    # applies to per-run entries, and for the same reason: the SPIRE agent
    # serves a cached SVID down to half its TTL, so TTL/2 must still cover the
    # run plus the margin.
    ROLE_JWT_TTL="${ANDYUR_SPIRE_ENTRY_TTL:-$(( 2 * ${ANDYUR_RUN_TTL_SECONDS:-900} + 300 ))}"
    "$SS" entry create \
      -parentID "$NODE_ID" \
      -spiffeID "spiffe://andyur.local/$id" \
      -jwtSVIDTTL "$ROLE_JWT_TTL" \
      -selector "unix:path:$ROLES/$bin" \
      -selector "$UID_SEL" >/dev/null 2>&1 || true
  done
}

# Identity is MANDATORY (the control plane always requires a JWT-SVID bearer), so
# a usable stack needs the SPIRE plane and role identities. Bring up whatever is
# missing, idempotently: role binaries, the SPIRE server (+registration), and
# the SPIRE agent. Safe to call when everything is already running.
# True when an operator SVID is ACTUALLY fetchable, which is a different
# question from whether the agent answers a healthcheck. After a CA rotation
# with the agent down, the cached bundle in data/spire/agent/agent-data.json no
# longer chains: the agent starts, answers healthchecks, serves the socket, and
# issues nothing. Everything downstream then fails with "unknown authority" or
# a bare timeout, and `ensure_spire` -- which only ever asked the healthcheck --
# saw a healthy agent and left it alone (ROADMAP.md 27).
#
# The role binaries are standalone interpreters without the project's deps, so
# the venv's site-packages ride in on PYTHONPATH exactly as `role_py` does it.
spire_issues_svids() {
  [ -S "$HERE/data/spire/agent/api.sock" ] || return 1
  local site op
  site=$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null)
  op="$ROLES/andyur-operator"
  [ -x "$op" ] || op="$VENV/bin/python"
  ( cd "$HERE" && ANDYUR_SVID_TIMEOUT=5 PYTHONPATH="$site:$HERE" "$op" -c \
      'from andyur import identity; identity.fetch_token()' ) >/dev/null 2>&1
}

ensure_spire() {
  local RUN_DIR="$HERE/data/run" LOG_DIR="$HERE/data/logs"
  mkdir -p "$RUN_DIR" "$LOG_DIR" "$HERE/data/spire/server" "$HERE/data/spire/agent"
  # 0. the binaries themselves. Fails CLOSED: every step below invokes them, and
  #    a missing binary used to surface 20 seconds later as a JSON parse error.
  ensure_spire_binaries || return 1
  # 1. per-role executables (built once; needs `uv`, see setup-roles.sh)
  if [ ! -x "$ROLES/andyur-operator" ]; then
    echo "building role identities (first run)..."
    bash "$HERE/infra/spire/setup-roles.sh"
  fi
  # 2. SPIRE server -- start if not already healthy, then (re)register roles
  if ! "$SPIRE_BIN/spire-server" healthcheck >/dev/null 2>&1; then
    echo "starting SPIRE server..."
    "$SPIRE_BIN/spire-server" run -config "$HERE/infra/spire/server.conf" \
      >"$LOG_DIR/spire-server.log" 2>&1 &
    echo $! > "$RUN_DIR/spire-server.pid"
    printf "waiting for spire-server"
    for _ in $(seq 1 40); do
      "$SPIRE_BIN/spire-server" healthcheck >/dev/null 2>&1 && break
      printf "."; sleep 0.5
    done; echo
    register_role_identities
  fi
  # 3. SPIRE agent -- start if it is not actually serving. The check is a
  # healthcheck, not socket-file existence: a dead agent leaves its socket file
  # behind, and gating on `-S` made `up` skip the agent forever after -- every
  # SVID fetch then times out with no hint that the agent was simply not running.
  # A SERVING agent that issues nothing is the stale-bundle case: clear the
  # agent's cache so the restart below re-joins and re-bootstraps. Only the
  # AGENT's cache -- the server's CA and the registration entries are fine and
  # deleting them would turn a two-second recovery into a full re-registration.
  if "$SPIRE_BIN/spire-agent" healthcheck \
       -socketPath "$HERE/data/spire/agent/api.sock" >/dev/null 2>&1 \
     && ! spire_issues_svids; then
    echo "SPIRE agent is serving but issues no SVID: clearing its stale cache"
    if [ -f "$RUN_DIR/spire-agent.pid" ]; then
      kill "$(cat "$RUN_DIR/spire-agent.pid")" 2>/dev/null || true
    fi
    pkill -f "spire-agent run" 2>/dev/null || true
    sleep 1
    rm -f "$HERE/data/spire/agent/agent-data.json" \
          "$HERE/data/spire/agent/api.sock" 2>/dev/null || true
  fi
  if ! "$SPIRE_BIN/spire-agent" healthcheck \
        -socketPath "$HERE/data/spire/agent/api.sock" >/dev/null 2>&1; then
    rm -f "$HERE/data/spire/agent/api.sock"
    echo "starting SPIRE agent..."
    local TOKEN
    TOKEN=$("$SPIRE_BIN/spire-server" token generate -spiffeID "$NODE_ID" -output json |
      "$VENV/bin/python" -c 'import json,sys; print(json.load(sys.stdin)["value"])')
    "$SPIRE_BIN/spire-agent" run \
      -config "$HERE/infra/spire/agent.conf" -joinToken "$TOKEN" \
      >"$LOG_DIR/spire-agent.log" 2>&1 &
    echo $! > "$RUN_DIR/spire-agent.pid"
    printf "waiting for spire-agent"
    for _ in $(seq 1 40); do
      [ -S "$HERE/data/spire/agent/api.sock" ] && break
      printf "."; sleep 0.5
    done; echo
    # A socket is not an SVID. Wait for the thing every caller actually needs,
    # and say so plainly if it never arrives rather than letting the first
    # component to start be the one that discovers it.
    printf "waiting for the first SVID"
    for _ in $(seq 1 30); do
      spire_issues_svids && break
      printf "."; sleep 1
    done; echo
    spire_issues_svids \
      || echo "WARNING: SPIRE is up but no SVID is fetchable; see $LOG_DIR/spire-agent.log" >&2
  fi
}

cmd="${1:-help}"
shift || true

# The pieces `up` starts, plus `up` itself, default to the dev profile.
#
# They used to inherit the prod default and die on InsecureProfile, so nine
# commands the README documents failed on a clean machine -- the second command
# a newcomer runs. An operator running production sets ANDYUR_PROFILE=prod
# explicitly, which is exactly the deliberate choice the design asks for; what
# is NOT reasonable is a getting-started path that cannot start.
case "$cmd" in
  server|daemon|broker|up|e2e)
    export ANDYUR_PROFILE="${ANDYUR_PROFILE:-dev}"
    ;;
esac

case "$cmd" in
  setup)
    [ -d "$VENV" ] || python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --upgrade pip
    "$VENV/bin/pip" install -q -r "$HERE/requirements.txt"
    echo "setup complete"
    ;;
  docker-up)
    exec bash "$HERE/infra/docker-stack.sh" up "$@"
    ;;
  docker-down)
    exec bash "$HERE/infra/docker-stack.sh" down "$@"
    ;;
  docker-status)
    exec bash "$HERE/infra/docker-stack.sh" status "$@"
    ;;
  docker-logs)
    exec bash "$HERE/infra/docker-stack.sh" logs "$@"
    ;;
  docker-cli)
    exec bash "$HERE/infra/docker-stack.sh" cli "$@"
    ;;
  idp)
    # Reference identity provider (Keycloak + its own PostgreSQL) as a runnable,
    # swappable component: control-plane reachable only, never on the run
    # network. up|down|wire|unwire|status|logs|verify|verify-composed|reset;
    # secrets are generated, never default. `wire`/`unwire` point the
    # dockerized control plane at it (and back); `reset` wipes IdP state
    # (required to pick up realm JSON edits); `verify-composed` proves the
    # whole composition live.
    exec bash "$HERE/infra/docker-stack.sh" idp "$@"
    ;;
  kubernetes-verify)
    exec bash "$HERE/infra/kubernetes/verify-macos.sh" "$@"
    ;;
  server)
    cd "$HERE"
    SSL_FLAGS=""
    case "${ANDYUR_MTLS:-off}" in
      1|on|true|ON|True)
        # export the control-plane X509-SVID as PEMs, then require client certs
        $(role_py server) -c "from andyur import identity; identity.export_tls_pems('server')"
        TLS="$HERE/data/tls/server"
        SSL_FLAGS="--ssl-certfile $TLS/cert.pem --ssl-keyfile $TLS/key.pem \
          --ssl-ca-certs $TLS/bundle.pem --ssl-cert-reqs 2"
        echo "mTLS on: control plane requires client X509-SVIDs"
        ;;
    esac
    exec $(role_py server) -m uvicorn andyur.server.app:app \
      --host "${ANDYUR_HOST:-127.0.0.1}" \
      --port "${ANDYUR_PORT:-8642}" $SSL_FLAGS "$@"
    ;;
  daemon)
    cd "$HERE"
    exec $(role_py worker) -m andyur.daemon
    ;;
  broker)
    # model broker (R2): holds ANTHROPIC_API_KEY and proxies model calls, so the
    # key never enters an agent's environment. Point agents at it vian ANDYUR_BROKER_URL.
    cd "$HERE"
    # Launched as its ROLE binary, not the plain venv python: the SPIRE unix
    # attestor identifies a workload by executable path, so a broker started any
    # other way has no identity and cannot reach an mTLS control plane.
    exec $(role_py broker) -m andyur.broker
    ;;
  test)
    cd "$HERE"
    [ -x "$VENV/bin/python" ] || { echo "run ./run.sh setup first"; exit 1; }
    "$VENV/bin/pip" install -q -r "$HERE/requirements-dev.txt"
    # NOT `pytest tests/`. CI's unit job runs bare `pytest -q` from this
    # directory, and a path-scoped local command collected a strict SUBSET --
    # demos/adsupport/test_app.py, 8 tests, ran only in CI and never under the
    # command this repository tells a developer to run. Both reported a large
    # green number, so the divergence was invisible from either side until two
    # sessions quoted "the suite" at each other and disagreed by exactly 8.
    #
    # RC gate line one is "unit suite green and developer/CI suite definitions
    # agree". Documenting a divergence does not satisfy a line that says they
    # AGREE, so they are the same invocation now and agree by construction.
    # Keep this in step with .github/workflows/andyur-ci.yml's unit job.
    #
    # THREE pytest scopes exist in this repository and only two of them ever
    # claimed to be "the suite". The third, `./run.sh redteam`, is a DIFFERENT
    # command for a different purpose and is correctly narrower -- it is named
    # here so nobody converges it by mistake, and so any number quoted from it
    # says which invocation produced it.
    exec "$VENV/bin/python" -m pytest "$@"
    ;;
  up)
    # Bring up the whole local stack in the background: Neo4j + control plane +
    # one worker, with the memory graph on. Dev mode: no sandbox or mTLS, but
    # workload IDENTITY is not optional -- the control plane always requires a
    # JWT-SVID, so `up` brings up the local SPIRE plane too. Stop it all with
    # ./run.sh down.
    [ -x "$VENV/bin/python" ] || { echo "run ./run.sh setup first"; exit 1; }
    # This target IS the dev stack (no sandbox or egress lockdown), so it
    # declares the dev profile rather than tripping the production check.
    export ANDYUR_PROFILE="${ANDYUR_PROFILE:-dev}"
    [ "$ANDYUR_PROFILE" = "dev" ] && echo "profile: DEV (agents run unsandboxed on this host)"
    # The daemon refuses to run agents unsandboxed under an identity plane
    # (a peer role's binary could be exec'd to steal its SVID) unless the risk
    # is explicitly accepted. The dev profile HAS already accepted unsandboxed
    # execution above, so make it self-consistent -- but ONLY in dev; production
    # (any non-dev profile) must still require ANDYUR_SANDBOX=on.
    if [ "$ANDYUR_PROFILE" = "dev" ]; then
      export ANDYUR_ALLOW_UNISOLATED_AGENT="${ANDYUR_ALLOW_UNISOLATED_AGENT:-on}"
    fi
    export ANDYUR_GRAPH="${ANDYUR_GRAPH:-neo4j}"
    export ANDYUR_OTEL="${ANDYUR_OTEL:-on}"   # tracing on by default; Jaeger below
    PORT="${ANDYUR_PORT:-8642}"
    RUN_DIR="$HERE/data/run"; LOG_DIR="$HERE/data/logs"
    mkdir -p "$RUN_DIR" "$LOG_DIR"
    if [ -f "$RUN_DIR/server.pid" ] && kill -0 "$(cat "$RUN_DIR/server.pid")" 2>/dev/null; then
      echo "andyur already up (./run.sh down to stop). server pid $(cat "$RUN_DIR/server.pid")"
      exit 0
    fi
    # Identity plane first: without it every server call is a 401 and the CLI/TUI
    # cannot authenticate. Idempotent -- reuses an already-running SPIRE.
    ensure_spire
    if [ "$ANDYUR_GRAPH" = "neo4j" ]; then
      docker compose -f "$HERE/infra/docker-compose.yml" up -d neo4j >/dev/null
      printf "waiting for neo4j"
      for _ in $(seq 1 40); do
        [ "$(docker inspect -f '{{.State.Health.Status}}' andyur-neo4j 2>/dev/null)" = "healthy" ] && break
        printf "."; sleep 1
      done; echo
    fi
    case "$ANDYUR_OTEL" in
      1|on|true|ON|True)
        docker compose -f "$HERE/infra/docker-compose.yml" up -d jaeger >/dev/null
        ;;
    esac
    case "${ANDYUR_BROKER:-off}" in
      1|on|true|ON|True)
        # start the model broker and route agents through it (key held by the
        # broker, scrubbed from every agent subprocess)
        export ANDYUR_BROKER_URL="http://127.0.0.1:${ANDYUR_BROKER_PORT:-8643}"
        # `$0` is whatever the caller typed: `bash run.sh up` makes it
        # "run.sh", which has no slash, so this became a PATH lookup that
        # failed INTO THE LOG FILE -- `up` printed its whole success banner
        # while nothing was running. $HERE is resolved from BASH_SOURCE.
        "$HERE/run.sh" broker >"$LOG_DIR/broker.log" 2>&1 & echo $! > "$RUN_DIR/broker.pid"
        echo "broker on: $ANDYUR_BROKER_URL (provider key held by broker)"
        ;;
    esac
    "$HERE/run.sh" server >"$LOG_DIR/server.log" 2>&1 & echo $! > "$RUN_DIR/server.pid"
    printf "waiting for server"
    server_up=0
    for _ in $(seq 1 40); do
      if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then server_up=1; break; fi
      printf "."; sleep 0.5
    done; echo
    # THE BANNER IS NOT THE PROOF. This loop could fall through without the
    # server ever answering, and `up` went on to print "andyur is up:" with
    # every line of its status -- the server URL, the daemon, the graph, the
    # LLM -- about a stack that was not there. It happened: `bash run.sh up`
    # (no slash in $0) made the re-invocation a failed PATH lookup, the error
    # went into the log file rather than the terminal, and the banner claimed
    # a running platform.
    if [ "$server_up" != 1 ]; then
      echo
      echo "THE SERVER DID NOT COME UP on http://127.0.0.1:$PORT after 20s." >&2
      echo "Nothing else was started. Its output is in data/logs/server.log:" >&2
      sed 's/^/  /' "$LOG_DIR/server.log" 2>/dev/null | tail -15 >&2
      exit 1
    fi
    "$HERE/run.sh" daemon >"$LOG_DIR/daemon.log" 2>&1 & echo $! > "$RUN_DIR/daemon.pid"
    # And the daemon, whose failure was equally silent: it is backgrounded and
    # its log is a file, so a daemon that died on startup left `up` reporting
    # "daemon running" forever.
    sleep 1
    if ! kill -0 "$(cat "$RUN_DIR/daemon.pid")" 2>/dev/null; then
      echo "THE WORKER DAEMON EXITED IMMEDIATELY. The server is up; nothing will" >&2
      echo "launch a run. Its output is in data/logs/daemon.log:" >&2
      sed 's/^/  /' "$LOG_DIR/daemon.log" 2>/dev/null | tail -15 >&2
      exit 1
    fi
    echo
    echo "andyur is up:"
    echo "  server   http://127.0.0.1:$PORT   (log: data/logs/server.log)"
    echo "  daemon   running                  (log: data/logs/daemon.log)"
    echo "  identity SPIRE (server + agent; operator/worker/runner SVIDs)"
    echo "  graph    $ANDYUR_GRAPH            (browser http://localhost:7474)"
    echo "  tracing  $ANDYUR_OTEL            (Jaeger UI http://localhost:16686)"
    echo "  LLM      ${ANDYUR_LLM:-api} (${ANDYUR_AGENT_MODEL:-$([ "${ANDYUR_LLM:-api}" = ollama ] && echo qwen3:8b || echo claude-opus-4-8)})"
    if [ "${ANDYUR_LLM:-api}" = "ollama" ]; then
      curl -sf "${ANDYUR_OLLAMA_URL:-http://localhost:11434}/api/tags" >/dev/null 2>&1 \
        || echo "           WARNING: ollama is not answering; start it with \`ollama serve\`"
    fi
    echo "  authority ${ANDYUR_AGENT_AUTH:-off} (agent-auth; demos that mint tool"
    echo "           credentials need it ON -- see README 'Tool credentials')"
    echo
    echo "watch it:   ./andyur-cli watch"
    echo "console:    ./andyur-cli console   (web UI: catalog, create, lifecycle)"
    echo "seed demo:  python demos/seed_andyur.py"
    echo "stop all:   ./run.sh down"
    ;;
  down)
    RUN_DIR="$HERE/data/run"
    # Order: control plane first, then the SPIRE plane it depended on.
    for role in daemon server broker spire-agent spire-server; do
      if [ -f "$RUN_DIR/$role.pid" ]; then
        kill "$(cat "$RUN_DIR/$role.pid")" 2>/dev/null && echo "stopped $role" \
          || echo "$role was not running"
        rm -f "$RUN_DIR/$role.pid"
      fi
    done
    echo "(Neo4j left running; stop it with: docker stop andyur-neo4j)"
    ;;
  spire-server)
    cd "$HERE"
    mkdir -p data/spire/server
    exec "$HERE/infra/spire/bin/spire-server" run -config "$HERE/infra/spire/server.conf"
    ;;
  spire-agent)
    cd "$HERE"
    mkdir -p data/spire/agent
    TOKEN=$("$HERE/infra/spire/bin/spire-server" token generate \
      -spiffeID spiffe://andyur.local/node -output json |
      "$VENV/bin/python" -c 'import json,sys; print(json.load(sys.stdin)["value"])')
    exec "$HERE/infra/spire/bin/spire-agent" run \
      -config "$HERE/infra/spire/agent.conf" -joinToken "$TOKEN"
    ;;
  jaeger)
    # local trace backend: Jaeger UI at http://localhost:16686, OTLP on 4317/4318
    if [ "$#" -eq 0 ]; then set -- up -d; fi
    exec docker compose -f "$HERE/infra/docker-compose.yml" "$@"
    ;;
  graph)
    # memory graph store: Neo4j (browser http://localhost:7474, Bolt on 7687).
    # Run the server with ANDYUR_GRAPH=neo4j to use it.
    exec docker compose -f "$HERE/infra/docker-compose.yml" up -d neo4j
    ;;
  sandbox-image)
    # build the runner image used when ANDYUR_SANDBOX=on
    #
    # The egress credential broker is built IN by default. Without it every tool
    # declaring `andyur.audience` is withheld, and a withheld tool looks exactly
    # like one the agent was never granted -- so an image built the obvious way
    # used to silently disable the feature. Set ANDYUR_AGENTGATEWAY_VERSION=""
    # to build without it. Checksums are per-arch and pinned; the build refuses
    # a binary that does not match.
    AGW_VERSION="${ANDYUR_AGENTGATEWAY_VERSION-1.4.1}"
    AGW_SHA_AMD64="${ANDYUR_AGENTGATEWAY_SHA256_AMD64-20f7b298e0c36eef33e7d612b0d0b91d87d43124f59b01f6e9b730477f66d982}"
    AGW_SHA_ARM64="${ANDYUR_AGENTGATEWAY_SHA256_ARM64-983a0919e30d287ec34ba51a69aa678fb81c5b893a59ae267b29d9fd30365d0e}"
    exec docker build -f "$HERE/Dockerfile.runner" \
      --build-arg "ANDYUR_AGENTGATEWAY_VERSION=$AGW_VERSION" \
      --build-arg "ANDYUR_AGENTGATEWAY_SHA256_AMD64=$AGW_SHA_AMD64" \
      --build-arg "ANDYUR_AGENTGATEWAY_SHA256_ARM64=$AGW_SHA_ARM64" \
      -t "${ANDYUR_SANDBOX_IMAGE:-andyur-runner}" "$HERE" "$@"
    ;;
  e2e)
    # END TO END: a real agent, a real model, every capability. Pass `fast` to
    # skip the model-driven phases. Costs nothing (local Ollama by default).
    exec bash "$HERE/infra/verify-e2e.sh" "${1:-full}"
    ;;
  reset)
    # Stop everything and delete accumulated state (db, logs, minds). Identity
    # material is kept unless --all. The counterpart to `up`.
    exec bash "$HERE/infra/reset.sh" "$@"
    ;;
  demo)
    # Run a demo with its prerequisites (venv, SPIRE, a dev control plane on a
    # free port, Neo4j, an Ollama model) checked and any missing ones started.
    # `demo list` shows what exists; `demo down` stops only what it started.
    exec bash "$HERE/infra/demo.sh" "$@"
    ;;
  authority-demo)
    # Hands-on tour of the token mint: watch each authority term refuse
    # something, driving the requests yourself. See docs/authority-runbook.md.
    exec bash "$HERE/infra/authority-demo.sh" "$@"
    ;;
  sre-demo)
    # AN ON-CALL AGENT TRIAGES AN INCIDENT under authority it cannot widen.
    # Uses the real server/runner images and per-run container SVID. It owns and
    # removes only its throwaway Andyur/tool processes; the shared SPIRE stack
    # must already be up (`./run.sh spire-docker up`). Narrated by default:
    # each hop explains what it proves (ANDYUR_SRE_NARRATE=0 to silence).
    ANDYUR_SRE_NARRATE="${ANDYUR_SRE_NARRATE:-1}" \
      exec bash "$HERE/infra/spire/docker/verify-sre-registry.sh" "$@"
    ;;
  msg-demo)
    # THE AUTONOMOUS RELAY: one page, zero orchestration. The REAL daemon
    # launches every turn; two agents resolve the incident by delegating tasks
    # to each other, every turn a separate attested run under the server's
    # 10-run workflow cap. This script only narrates. Needs spire-docker up.
    exec bash "$HERE/infra/spire/docker/demo-msg-relay.sh" "$@"
    ;;
  msg-verify)
    # The same relay as a GATE: the harness plays the worker so it can freeze
    # both agents' refusals with live credentials, and asserts the chain shape
    # (alternating turns, one workflow, inherited pin, distinct per-run SVIDs,
    # credential-free artifacts). Needs `./run.sh spire-docker up`.
    exec bash "$HERE/infra/spire/docker/verify-msg-relay.sh" "$@"
    ;;
  actor-leg-verify)
    # THE WIRE PROOF for the RFC 8693 actor leg: a real per-run JWT-SVID (docker
    # attested) exchanged at the reference AS as the ACTOR, so the issued token
    # asserts delegation (act.sub = the run) rather than the user acting
    # directly. Unit tests prove the config shape; only this proves the real
    # agentgateway binary and the real AS agree. Needs ./run.sh spire-docker up.
    exec bash "$HERE/infra/verify-actor-leg.sh" "$@"
    ;;
  svc-cred-verify)
    # THE WIRE PROOF for brokered SERVICE credentials (phase 2c): a run's real
    # docker-attested SPIRE JWT-SVID logs in to the SEALED OpenBao (SPIFFE ->
    # JWT-auth federation), reads a service credential via the real
    # credential_service, an upstream ACCEPTS it, and the credential is ABSENT
    # from the agent env, the container argv, the transcript, and the logs. The
    # vault for SERVICE credentials, as the SRE gate's phase 2 is for the LLM one.
    # Needs ./run.sh spire-docker up.
    exec bash "$HERE/infra/verify-service-credential.sh" "$@"
    ;;

  redteam)
    # The FROZEN attacks. Red-team agents are non-deterministic -- a run finds
    # what it happens to find -- so every attack one of them actually ran is
    # kept here as an ordinary test. The agents discover; this is the part that
    # is reproducible. One file per round, only ever added to.
    # See tests/redteam/README.md. Live-stack attacks are `spire-redteam` and
    # `infra/reference-as/verify.sh`, which need a running process.
    exec "$HERE/.venv/bin/python" -m pytest "$HERE/tests/redteam" -q
    ;;

  sre-verify)
    # The same demo as a GATE against the container-attested SPIRE stack. It
    # builds real server/runner images and owns its Andyur/tool containers, but
    # deliberately reuses SPIRE: start it first with `./run.sh spire-docker up`.
    exec bash "$HERE/infra/spire/docker/verify-sre-registry.sh" "$@"
    ;;
  resource-verify)
    # PROVE the other half of the handshake: a resource server that REFUSES.
    # Andyur mints narrow, audience-bound, pinned tokens; this drives real ones
    # at a real MCP server running the PEP from demos/authority-tool/ and asserts
    # what it turns away. Until it existed every constraint was self-asserted.
    exec bash "$HERE/infra/verify-resource-pep.sh" "$@"
    ;;
  seccomp-verify)
    # PROVE the seccomp filter is loaded, not merely configured: docker honours
    # only the LAST --security-opt seccomp=, so argv presence is not evidence.
    # Every denial is paired with the same probe under seccomp=unconfined, which
    # must SUCCEED -- a probe that fails both ways certifies nothing.
    exec bash "$HERE/infra/verify-seccomp.sh"
    ;;
  uid-verify)
    # PROVE the uid split, the assumption every credential claim rests on: can
    # the agent uid actually read the runner's /proc, memory, fds and tokens?
    # Runs the SAME probe as root and as the agent; root must succeed on the
    # vectors the agent must fail, or the harness refuses to certify anything.
    exec bash "$HERE/infra/verify-uid-boundary.sh"
    ;;
  pod-verify)
    # PROVE the two-container pod boundary at runtime: the agent container runs
    # unprivileged from PID 1, holds no credential, cannot see the sidecar's
    # processes at all, has no identity and no host mounts -- while still
    # reaching the sidecar on loopback, and dying with it under one kill.
    # Every "cannot" has a positive control, so a broken probe cannot certify.
    exec bash "$HERE/infra/verify-pod-boundary.sh"
    ;;
  coord-verify)
    # PROVE the coordination paths on REAL Postgres with REAL concurrent
    # processes. The unit suite is SQLite-only by design, and coordination is
    # where that has hidden the most (a reserved word, three lock-order
    # inversions, a deadlock the operator's halt lost 68% of the time).
    exec bash "$HERE/infra/verify-coordination-pg.sh"
    ;;
  egress-verify)
    # PROVE the egress boundary: run a container in the shape an Andyur run gets
    # and try to reach the internet, external DNS, and the host from inside it.
    exec bash "$HERE/infra/verify-egress.sh"
    ;;
  egress-network)
    # create the internal run network the production profile requires
    NET="${ANDYUR_SANDBOX_NETWORK:-andyur-runs}"
    docker network inspect "$NET" >/dev/null 2>&1 && { echo "$NET exists"; exit 0; }
    docker network create --internal "$NET" >/dev/null
    echo "created internal network '$NET' (no route off this host)"
    echo "attach the control plane and broker to it so runs can reach those and nothing else"
    ;;
  opa-verify)
    # PROVE the external PDP agrees with the builtin one on every case, against
    # the hardened engine (signed bundle, token auth, deny-by-default API).
    exec bash "$HERE/infra/opa/verify-opa.sh"
    ;;
  opa-attack)
    # ATTACK the policy engine: try to rewrite policy over HTTP with and without
    # the enforcement point's token, inject data, read the policy back, publish a
    # tampered bundle, and kill the engine mid-flight. Every one must fail.
    exec bash "$HERE/infra/opa/verify-opa-hardening.sh"
    ;;
  opa-demo)
    # authorization changes with no redeploy, delivered as a signed bundle
    exec bash "$HERE/infra/opa/demo-no-redeploy.sh"
    ;;
  spire-docker)
    # containerized SPIRE stack for per-run identity by container attestation
    # (Slice 3). `up` leaves it running for the daemon; `down` tears it down.
    exec bash "$HERE/infra/spire/docker/verify-slice3.sh" "${1:-up}"
    ;;
  spire-verify)
    # bring up the containerized SPIRE stack and PROVE label attestation
    # (labeled container gets the run SVID; unlabeled/mislabeled denied)
    exec bash "$HERE/infra/spire/docker/verify-slice3.sh" verify
    ;;
  spire-roundtrip)
    # PROVE the full server-side round-trip: a runner container presents its
    # container-attested per-run SVID and the Andyur server validates it.
    # (add `down` to tear down.) Needs the andyur-server + andyur-runner images.
    exec bash "$HERE/infra/spire/docker/verify-roundtrip.sh" "${1:-up}"
    ;;
  spire-mtls)
    # PROVE production mTLS + multi-replica: 2 mTLS server replicas behind an L4
    # load balancer + shared Postgres, and a runner completing the round-trip over
    # mutually-authenticated TLS through the LB. (add `down` to tear down.)
    exec bash "$HERE/infra/spire/docker/verify-mtls.sh" "${1:-up}"
    ;;
  spire-redteam)
    # LIVE adversarial run: fire concrete OWASP MAS attacks at the running secure
    # stack with real SVIDs + tokens; each check passes when the attack is blocked.
    exec bash "$HERE/infra/spire/docker/verify-redteam.sh" "${1:-up}"
    ;;
  spire-full-trace)
    # A REAL agent run on the containerized SPIRE domain, so one Jaeger trace shows
    # the agent's work AND the per-run identity decision. Needs host Jaeger + Ollama.
    # (add `down` to tear down.)
    exec bash "$HERE/infra/spire/docker/verify-full-trace.sh" "${1:-up}"
    ;;
  user-idp)
    # LIVE user-identity proof against a REAL OIDC provider (Keycloak): a genuine
    # user login seals the agent's owner, the run acts for that user, a forged token
    # is refused, and a second user cannot see the first's agent. (add `down`.)
    exec bash "$HERE/infra/keycloak/verify-user-idp.sh" "${1:-up}"
    ;;
  run-isolation)
    # LIVE proof of O1 (F3 remediation): in Docker pod mode the untrusted agent
    # is single-homed on a per-run internal network and reaches ONLY its sidecar
    # -- not the control plane, another run, or the internet. Reproduces the
    # orchestrator's exact pod-mode wiring and includes the F3 mutation. (add
    # `down` to clean up.)
    exec bash "$HERE/infra/verify-run-isolation-docker.sh" "${1:-up}"
    ;;
  console)
    # LIVE console gates: the BFF fences and the collector read-back over
    # HTTP (verify-console.sh), then the REAL page in headless Chrome over the
    # DevTools protocol (verify-console-browser.py). Assumes ./run.sh up.
    bash "$HERE/infra/verify-console.sh" && exec "$VENV/bin/python" "$HERE/infra/verify-console-browser.py"
    ;;
  console-modes)
    # LIVE console admin-vs-user proof against a REAL Keycloak: the admin realm
    # role gates workers/halt and all-owners visibility, cross-tenant
    # pause/resume/ceiling is refused without effect, admin cannot impersonate
    # (trigger), and the real PKCE login drives the real BFF in each mode. (add
    # `down` to remove a lingering Keycloak container.)
    exec bash "$HERE/infra/verify-console-modes.sh" "${1:-up}"
    ;;
  u4-keycloak)
    # LIVE U4 downstream delegation against Keycloak's NATIVE RFC 8693 token
    # exchange (the "compose OSS in production" model): the AS keeps the user,
    # rebinds the audience, carries the granted scope, and cannot widen. (add `down`.)
    exec bash "$HERE/infra/keycloak/verify-u4-keycloak.sh" "${1:-up}"
    ;;
  oauth-bakeoff)
    # Reproducible, hash-pinned TLS/concurrency comparison. This is transport
    # evidence only; Keycloak and the reference AS remain separate semantic
    # floor/ceiling gates so their claims cannot be conflated.
    exec bash "$HERE/infra/oauth-client-bakeoff/verify.sh" "$@"
    ;;
  as-certify)
    # Live enterprise-AS gate. Credentials and subject/actor tokens are read
    # only from *_FILE paths by the verifier, never accepted on argv.
    cd "$HERE"
    exec "$VENV/bin/python" -m andyur.server.asconformance
    ;;
  as-provision)
    # Render/plan/apply provider-owned development resources. Authentication
    # stays in each official Terraform provider's environment, never argv.
    cd "$HERE"
    exec "$VENV/bin/python" -m andyur.asprovision "$@"
    ;;
  openbao)
    exec bash "$HERE/infra/openbao/openbao-stack.sh" "$@"
    ;;
  spire-fetch)
    # Download + verify the pinned SPIRE release (linux only; see spire_platform)
    ensure_spire_binaries
    ;;
  spire-build)
    # Build the pinned SPIRE tag from source. The macOS path, since upstream
    # ships no darwin binaries.
    build_spire
    ;;
  spire-setup)
    # build per-role executables + register one SPIFFE ID per role, keyed on
    # each executable's path (see infra/spire/setup-roles.sh for the why)
    cd "$HERE"
    bash "$HERE/infra/spire/setup-roles.sh"
    # Parent workload entries to the STABLE node alias, not a per-restart agent
    # id. The agent joins via `token generate -spiffeID .../node`, so every agent
    # instance holds this alias; parenting here means the role entries keep
    # working across agent restarts (which each mint a fresh join-token identity).
    register_role_identities
    "$SPIRE_BIN/spire-server" entry show | grep -E "SPIFFE ID|Parent ID" | head
    ;;
  *)
    echo "usage: ./run.sh {setup|test|up|down|docker-up|docker-down|docker-cli|kubernetes-verify|server|daemon|jaeger|graph|sandbox-image|spire-fetch|spire-build|spire-server|spire-agent|spire-setup}"
    echo "  setup          create the venv and install dependencies"
    echo "  test           install dev deps and run the test suite"
    echo "  up             start the whole local stack (Neo4j + server + daemon, graph on)"
    echo "  down           stop the server + daemon started by 'up'"
    echo "  demo           run a demo with prereqs auto-checked+started (list|<name>|down)"
    echo "  docker-up      build + start the full single-host Docker deployment"
    echo "  docker-down    stop that deployment (persistent state is retained)"
    echo "  docker-status  show its control-plane and worker status"
    echo "  docker-logs    follow its logs (optionally name a service)"
    echo "  docker-cli     run an authenticated operator CLI command in Docker"
    echo "  idp            reference OIDC IdP (Keycloak), control-plane-only (up|down|wire|unwire|status|logs|verify|verify-composed|reset)"
    echo "  kubernetes-verify run the registry/model, halt, persistence and isolation gate on Rancher Desktop"
    echo "  server         start the control plane server"
    echo "  daemon         start a worker daemon (launches agent runs)"
    echo "  jaeger         start the local trace backend (Docker)"
    echo "  graph          start the Neo4j memory graph store (Docker)"
    echo "  sandbox-image  build the runner image for ANDYUR_SANDBOX=on"
    echo "  spire-fetch    download + verify the pinned SPIRE release (Linux)"
    echo "  spire-build    build the pinned SPIRE tag from source (needs Go; the"
    echo "                 macOS path, since upstream ships no darwin binaries)"
    echo "  spire-server   start the local SPIRE server"
    echo "  spire-agent    join-token bootstrap and start the SPIRE agent"
    echo "  spire-setup    build role executables + register SPIFFE identities"
    echo "  spire-docker   containerized SPIRE stack for per-run container attestation (up|down)"
    echo "  spire-verify   prove per-run container attestation live (Slice 3)"
    echo "  spire-roundtrip prove the server validates a runner's per-run SVID (Slice 4)"
    echo "  e2e            run a real agent end to end and assert every capability"
    echo "  egress-network create the internal run network the prod profile requires"
    echo "  egress-verify  prove an agent cannot reach the internet, DNS, or the host"
    echo "  coord-verify   coordination on real Postgres, with concurrent replicas"
    echo "  uid-verify     prove the agent uid cannot read the runner's secrets"
    echo "  seccomp-verify prove the run containers' seccomp filter is loaded"
    echo "  opa-verify     external PDP agrees with the builtin one (hardened engine)"
    echo "  opa-attack     attack the policy engine; every attempt must fail"
    echo "  opa-demo       authorization changes with no redeploy, via signed bundle"
    echo
    echo " demos -- these need the platform up first (see each script's header)"
    echo "  sre-demo       an on-call agent triages an incident under a ceiling (narrated)"
    echo "  msg-demo       autonomous multi-turn relay: two agents resolve an incident"
    echo "  msg-verify     the same relay as a gate (frozen refusals, SVID checks)"
    echo "  sre-verify     the same, as a self-contained gate that asserts it"
    echo "  actor-leg-verify  the RFC 8693 actor leg (per-run SVID) on the wire"
    echo "  svc-cred-verify   a brokered service credential from the vault via SPIFFE-JWT"
    echo "  redteam        every attack a red team ran, frozen as tests"
    echo "  authority-demo a guided tour of the mint: what it issues and refuses"
    echo "  resource-verify a real resource server REFUSING real minted tokens"
    echo "  user-idp       the user's OIDC login sealed onto a run (Keycloak)"
    echo "  console        console gates: BFF fences + collector read-back, then the real page in headless Chrome"
  echo "  console-modes  console admin vs user modes, live vs Keycloak (roles, PKCE)"
    echo "  run-isolation  O1: agent single-homed on a per-run net, reaches only its sidecar"
    echo "  u4-keycloak    downstream delegation against a real Keycloak"
    echo "  oauth-bakeoff  Authlib vs requests-oauth2client TLS/concurrency gate"
    echo "  as-certify     certify a configured live Entra/Okta/Auth0/Ping tenant"
    echo "  as-provision   safely render/plan/apply development AS resources"
    echo "  openbao        operate the isolated development secrets vault"
    echo
    echo " lower-level checks"
    echo "  reset          delete local state and start clean"
    echo "  broker         start the model broker (keeps provider keys off runners)"
    echo "  pod-verify     the Kubernetes runner pod carries its own SVID"
    echo "  spire-mtls     mutual TLS between server and runner, both SVID-backed"
    echo "  spire-full-trace one run, every SPIFFE identity it touched"
    echo "  spire-redteam  attack the identity plane; every attempt must fail"
    ;;
esac

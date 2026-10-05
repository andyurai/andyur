#!/usr/bin/env bash
# Idempotent prerequisite checks for the demos. Each `ensure_*` reports what it
# found and starts only what is missing, so re-running a demo is cheap and a
# half-set-up box heals rather than erroring.
#
# Design rules that come from real breakage:
#   - The demos are DEV-shaped, but a prod docker stack may hold :8642. So the
#     dev control plane here binds a FREE port and exports ANDYUR_SERVER_URL;
#     it never fights the prod stack for 8642.
#   - Native SPIRE keeps a CA + SVID cache under data/spire. A server started
#     against a stale cache fails node attestation with "certificate signed by
#     unknown authority". ensure_spire detects an unfetchable socket and clears
#     the stale state before restarting, rather than leaving the user to guess.
#   - Nothing large downloads silently. The Ollama model is created from a
#     present base, or gated behind --pull.
#
# Sourced by infra/demo.sh; not meant to run standalone. Every function returns
# 0 on success and non-zero on a genuine, unrecoverable miss.

# HERE is the agentic-platform root; set by the sourcing script.
: "${HERE:?demo-preflight.sh must be sourced with HERE set to the project root}"
VENV="$HERE/.venv"
DEMO_STATE="$HERE/data/demo"        # pidfiles for services THIS tooling started
mkdir -p "$DEMO_STATE" "$HERE/data/logs" 2>/dev/null || true

# --- output -----------------------------------------------------------------
_dp_c() { printf '%b' "$1"; }
dp_step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
dp_ok()   { printf '  \033[32m\xe2\x9c\x93\033[0m %s\n' "$*"; }
dp_info() { printf '  \033[36m\xc2\xb7\033[0m %s\n' "$*"; }
dp_warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
dp_fail() { printf '  \033[31m\xe2\x9c\x97\033[0m %s\n' "$*" >&2; }

# role_py picks the per-role interpreter the way run.sh does; fall back to venv.
_dp_py() {
  if command -v role_py >/dev/null 2>&1; then role_py "${1:-server}"; else echo "$VENV/bin/python"; fi
}

_dp_port_free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
_dp_first_free_port() {   # $1 = start port; scans upward
  local p="$1"; while ! _dp_port_free "$p"; do p=$((p+1)); done; echo "$p"
}

# --- venv -------------------------------------------------------------------
ensure_setup() {
  dp_step "venv + dependencies"
  if [ -x "$VENV/bin/python" ]; then
    dp_ok "venv present ($VENV)"
  else
    dp_info "no venv; running ./run.sh setup (first time is slow)"
    ( cd "$HERE" && ./run.sh setup ) || { dp_fail "./run.sh setup failed"; return 1; }
    dp_ok "venv created"
  fi
}

# --- SPIRE identity plane ---------------------------------------------------
_dp_spire_fetches() {   # true when an operator SVID is actually fetchable
  [ -S "$HERE/data/spire/agent/api.sock" ] || return 1
  # The role binaries are standalone interpreters WITHOUT the project's deps;
  # the venv's site-packages ride in on PYTHONPATH, exactly as run.sh's role_py
  # and verify-e2e.sh do it. Invoking the binary without $SITE fails with
  # "No module named 'spiffe'" and makes a healthy SPIRE look dead.
  local site; site="$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null)"
  local op="$HERE/infra/roles/bin/andyur-operator"
  [ -x "$op" ] || op="$VENV/bin/python"
  ( cd "$HERE" && ANDYUR_SVID_TIMEOUT=5 PYTHONPATH="$site:$HERE" "$op" -c \
      'from andyur import identity; identity.fetch_token()' ) >/dev/null 2>&1
}

ensure_spire() {
  dp_step "SPIRE identity plane"
  if _dp_spire_fetches; then dp_ok "SPIRE up; operator SVID fetchable"; return 0; fi
  if [ -S "$HERE/data/spire/agent/api.sock" ]; then
    dp_warn "socket present but no SVID fetchable -- treating cache as stale"
  fi
  dp_info "starting SPIRE (server, agent, role registration)"
  pkill -f 'spire-agent' 2>/dev/null; pkill -f 'spire-server' 2>/dev/null; sleep 1
  # Clear the stale CA + SVID cache; a fresh server mints a new CA the cached
  # agent SVID will not verify against. Registration is rebuilt by spire-setup.
  rm -rf "$HERE"/data/spire/agent/* "$HERE"/data/spire/server/* 2>/dev/null || true
  ( cd "$HERE" && ./run.sh spire-server >"$HERE/data/logs/demo-spire-server.log" 2>&1 & echo $! >"$DEMO_STATE/spire-server.pid" )
  sleep 6
  ( cd "$HERE" && ./run.sh spire-agent  >"$HERE/data/logs/demo-spire-agent.log"  2>&1 & echo $! >"$DEMO_STATE/spire-agent.pid" )
  sleep 4
  ( cd "$HERE" && ./run.sh spire-setup  >"$HERE/data/logs/demo-spire-setup.log"  2>&1 ) || true
  local i; for i in $(seq 1 30); do _dp_spire_fetches && break; sleep 1; done
  if _dp_spire_fetches; then dp_ok "SPIRE up; operator SVID fetchable"; return 0; fi
  dp_fail "SPIRE did not become ready; see data/logs/demo-spire-*.log"; return 1
}

# --- Neo4j graph ------------------------------------------------------------
ensure_graph() {
  dp_step "Neo4j memory graph"
  if curl -s --max-time 3 http://127.0.0.1:7474 >/dev/null 2>&1 \
     || [ "$(docker inspect -f '{{.State.Running}}' andyur-neo4j 2>/dev/null)" = "true" ]; then
    dp_ok "Neo4j reachable"
  else
    if ! docker info >/dev/null 2>&1; then
      dp_fail "Neo4j needs Docker, which is not running"; return 1
    fi
    dp_info "starting Neo4j via Docker (./run.sh graph)"
    ( cd "$HERE" && ./run.sh graph >/dev/null 2>&1 ) || { dp_fail "could not start Neo4j"; return 1; }
    local i; for i in $(seq 1 40); do
      [ "$(docker inspect -f '{{.State.Health.Status}}' andyur-neo4j 2>/dev/null)" = "healthy" ] && break; sleep 1
    done
    dp_ok "Neo4j up"
  fi
  export ANDYUR_GRAPH=neo4j
}

# --- dev control plane on a free port ---------------------------------------
# Exports ANDYUR_SERVER_URL / ANDYUR_PORT for every later step and the demo.
ensure_server() {   # $1 (optional) = "worker" to also start a daemon
  dp_step "dev control plane"
  if [ -n "${ANDYUR_SERVER_URL:-}" ] && curl -s --max-time 3 "$ANDYUR_SERVER_URL/health" >/dev/null 2>&1; then
    dp_ok "control plane already serving at $ANDYUR_SERVER_URL"
  else
    local port; port=$(_dp_first_free_port 8656)
    export ANDYUR_PORT="$port"
    export ANDYUR_SERVER_URL="http://127.0.0.1:$port"
    export ANDYUR_PROFILE="${ANDYUR_PROFILE:-dev}"
    # Dev demos run the agent on the host (no container sandbox), which the
    # platform refuses by default. This is the documented dev escape; safe here
    # because the whole demo stack is a throwaway dev instance.
    export ANDYUR_ALLOW_UNISOLATED_AGENT="${ANDYUR_ALLOW_UNISOLATED_AGENT:-on}"
    if [ "$port" != 8642 ]; then dp_info "prod :8642 is busy or reserved; using free port $port"; fi
    # Record the PORT, not just the pid: `run.sh server` forks a child uvicorn,
    # so the recorded pid is the wrapper and killing it orphans the listener
    # (the same fork gotcha verify-console-modes.sh documents). demo_down kills
    # by this port to reap the real listener.
    echo "$port" >"$DEMO_STATE/server.port"
    ( cd "$HERE" && ./run.sh server >"$HERE/data/logs/demo-server.log" 2>&1 & echo $! >"$DEMO_STATE/server.pid" )
    local i; for i in $(seq 1 40); do curl -s --max-time 2 "$ANDYUR_SERVER_URL/health" >/dev/null 2>&1 && break; sleep 0.5; done
    curl -s --max-time 3 "$ANDYUR_SERVER_URL/health" >/dev/null 2>&1 \
      || { dp_fail "control plane did not come up; see data/logs/demo-server.log"; return 1; }
    dp_ok "control plane serving at $ANDYUR_SERVER_URL"
  fi
  if [ "${1:-}" = worker ]; then
    if [ -f "$DEMO_STATE/daemon.pid" ] && kill -0 "$(cat "$DEMO_STATE/daemon.pid" 2>/dev/null)" 2>/dev/null; then
      dp_ok "worker already running"
    else
      ( cd "$HERE" && ./run.sh daemon >"$HERE/data/logs/demo-daemon.log" 2>&1 & echo $! >"$DEMO_STATE/daemon.pid" )
      sleep 2; dp_ok "worker started"
    fi
  fi
}

# --- Ollama model (gated) ---------------------------------------------------
# $1 = required|optional, $2 = "--pull" to permit the big download.
ensure_model() {
  local mode="${1:-optional}" pull="${2:-}"
  local model="${ANDYUR_AGENT_MODEL:-qwen3-andyur}" base="qwen3:8b"
  dp_step "Ollama model ($model)"
  if ! curl -s --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    if command -v ollama >/dev/null 2>&1; then
      dp_info "starting ollama serve"
      ( ollama serve >"$HERE/data/logs/demo-ollama.log" 2>&1 & echo $! >"$DEMO_STATE/ollama.pid" )
      local i; for i in $(seq 1 20); do curl -s --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break; sleep 1; done
    fi
  fi
  if ! curl -s --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    _dp_model_miss "$mode" "Ollama is not running on :11434 (install from https://ollama.com, then 'ollama serve')"; return $?
  fi
  if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$model"; then
    dp_ok "model $model present"; export ANDYUR_LLM=ollama ANDYUR_AGENT_MODEL="$model"; return 0
  fi
  # Model missing: create from a present base, else gate on --pull.
  if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$base"; then
    dp_info "base $base present; creating $model"
  elif [ "$pull" = "--pull" ]; then
    dp_info "pulling $base (~5GB) then creating $model"
    ollama pull "$base" || { dp_fail "ollama pull $base failed"; return 1; }
  else
    _dp_model_miss "$mode" "model $model absent and base $base not pulled; re-run with --pull (~5GB): ollama pull $base && ollama create $model"; return $?
  fi
  printf 'FROM %s\nPARAMETER num_ctx 32768\n' "$base" > "$DEMO_STATE/Modelfile"
  ollama create "$model" -f "$DEMO_STATE/Modelfile" >/dev/null 2>&1 \
    || { dp_fail "ollama create $model failed"; return 1; }
  dp_ok "model $model ready"; export ANDYUR_LLM=ollama ANDYUR_AGENT_MODEL="$model"
}

_dp_model_miss() {   # $1 = required|optional, $2 = message
  if [ "$1" = required ]; then dp_fail "$2"; return 1; fi
  dp_warn "$2"
  dp_warn "continuing: the demo will set up, but running an agent needs a model"
  return 0
}

# --- teardown of only what this tooling started -----------------------------
demo_down() {
  dp_step "stopping demo-started services (prod docker stack untouched)"
  local name pid
  # Kill the server by PORT first: run.sh server forks a child uvicorn, so the
  # recorded pid is only the wrapper. The port file is written by ensure_server.
  if [ -f "$DEMO_STATE/server.port" ]; then
    local sp; sp="$(cat "$DEMO_STATE/server.port" 2>/dev/null)"
    if [ -n "$sp" ] && lsof -ti ":$sp" >/dev/null 2>&1; then
      lsof -ti ":$sp" 2>/dev/null | xargs kill 2>/dev/null
      # Wait for the socket to actually release before claiming it stopped --
      # SIGTERM returns before uvicorn closes its listener, so an immediate
      # re-check (or a follow-on demo run) would still see the old port.
      local i; for i in $(seq 1 20); do lsof -ti ":$sp" >/dev/null 2>&1 || break; sleep 0.5; done
      if lsof -ti ":$sp" >/dev/null 2>&1; then
        lsof -ti ":$sp" 2>/dev/null | xargs kill -9 2>/dev/null   # last resort
      fi
      dp_ok "stopped dev control plane (:$sp)"
    fi
    rm -f "$DEMO_STATE/server.port"
  fi
  for name in daemon server ollama spire-agent spire-server; do
    pid="$DEMO_STATE/$name.pid"
    if [ -f "$pid" ] && kill -0 "$(cat "$pid" 2>/dev/null)" 2>/dev/null; then
      kill "$(cat "$pid")" 2>/dev/null && dp_ok "stopped $name"
    fi
    rm -f "$pid"
  done
  dp_ok "done (Neo4j left running; stop with: docker stop andyur-neo4j)"
}

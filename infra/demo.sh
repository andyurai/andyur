#!/usr/bin/env bash
# `./run.sh demo <name>` -- run a demo with its prerequisites checked and any
# missing ones started. `demo list` shows what exists; `demo down` stops only
# the services this tooling started (the prod docker stack is never touched).
#
# Each demo below declares what it needs; the ensure_* functions
# (infra/demo-preflight.sh) are idempotent, so re-running is cheap and a
# partially-set-up box heals instead of erroring.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=infra/demo-preflight.sh
source "$HERE/infra/demo-preflight.sh"
cd "$HERE"
PY="$VENV/bin/python"

cmd="${1:-list}"; [ $# -gt 0 ] && shift

# Optional flags any demo may accept.
PULL=""; MODE=""
for a in "$@"; do
  case "$a" in
    --pull) PULL="--pull" ;;
    full|fast) MODE="$a" ;;
  esac
done

# Print the agent's final user-visible answer from a completed run's transcript.
_demo_show_answer() {   # $1 = agent, $2 = run_id
  local t="$HERE/data/workspace/agents/$1/runs/$2/transcript.jsonl"
  if [ -z "$2" ] || [ ! -f "$t" ]; then
    dp_warn "no transcript found (run may still be starting, or used a container runner)"; return 0
  fi
  "$VENV/bin/python" - "$t" <<'PY'
import json, sys
answer = ""
for line in open(sys.argv[1]):
    try: m = json.loads(line)
    except Exception: continue
    if m.get("type") != "AssistantMessage": continue
    for c in m.get("data", {}).get("content", []):
        # content items are keyed by field: {"text": ...}, {"thinking": ...},
        # {"tool_use": ...} -- the visible answer is a bare "text" (no "thinking").
        if isinstance(c, dict) and c.get("text", "").strip() and "thinking" not in c:
            answer = c["text"].strip()
print(answer or "(the run completed but produced no visible text -- "
      "a small local model often reasons about the tool without calling it; "
      "set ANTHROPIC_API_KEY for a capable model)")
PY
}

banner() { printf '\n\033[1m== demo: %s ==\033[0m\n' "$1"; }
nexthint() { printf '\n\033[1mnext:\033[0m\n'; while [ $# -gt 0 ]; do printf '  %s\n' "$1"; shift; done; }

# The auto-wired demos, printed by `list`. Intricate ones (byoa-*, adsupport,
# sre-triage, agent-registry, authority-tool) are listed as pointers because
# they need external keys/deps or run only under a live run's sidecar.
list_demos() {
  cat <<'TXT'
Usage: ./run.sh demo <name> [fast|full] [--pull]     ./run.sh demo down

Auto-wired (prereqs checked and started for you):
  authority        token-mint escalation refusals, live         needs: SPIRE (own server)
  seed             populate 4 agents + memory graph, then watch  needs: server + Neo4j (no LLM)
  incident-recall  narrated memory recall across three runs      needs: server + Neo4j + a model
  tool-agent       an agent with one local (stdio) MCP tool      needs: server (+model to RUN it)
  tool-agent-http  the same tool as a remote HTTP service        needs: server (+model to RUN it)
  select-tools     ten tools, the agent picks by intent          needs: server (+model to RUN it)
  e2e              whole platform end-to-end (own stack)          needs: SPIRE (+model for full)

Pointers (set up by hand; see each README):
  byoa-hello / byoa-langgraph / byoa-openai   framework-independent agents (run under a live run)
  adsupport                                    tau2-inspired advertiser/support harness
  sre-triage / agent-registry / authority-tool see demos/<name>/

Flags: fast|full pick e2e depth; --pull permits the ~5GB Ollama model download.
'demo down' stops only what this tooling started; Neo4j and the prod stack stay up.
TXT
}

# Model policy shared by the agent-running demos. Prefer a capable API model
# when a key is available (small local models are unreliable at tool-calling --
# they reason about the tool but often never emit the call), else the local
# Ollama model. The key is read from the gitignored ../.env config.load_dotenv
# already uses, so a demo picks it up the same way the platform does.
ensure_a_model() {   # $1 = required|optional
  if [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -f "$HERE/../.env" ]; then
    local k; k="$(grep -m1 '^ANTHROPIC_API_KEY=' "$HERE/../.env" 2>/dev/null | cut -d= -f2-)"
    [ -n "$k" ] && export ANTHROPIC_API_KEY="$k"
  fi
  if [ -n "${ANTHROPIC_API_KEY:-}" ] && [ "${ANDYUR_LLM:-}" != ollama ]; then
    export ANDYUR_LLM=api
    export ANDYUR_AGENT_MODEL="${ANDYUR_AGENT_MODEL:-claude-haiku-4-5-20251001}"
    dp_step "model backend"
    dp_ok "using ANDYUR_LLM=api ($ANDYUR_AGENT_MODEL) -- reliable tool-calling"
    return 0
  fi
  ensure_model "$1" "$PULL"
  dp_warn "local model: small models reason about tools but may not reliably CALL them; set ANTHROPIC_API_KEY for a capable model"
}

case "$cmd" in
  ""|list|-h|--help|help) list_demos ;;

  down) demo_down ;;

  authority)
    banner "authority (token-mint escalation refusals)"
    ensure_setup && ensure_spire || exit 1
    ./run.sh authority-demo up || exit 1
    nexthint "walk docs/authority-runbook.md (tokens.env path printed above)" \
             "stop it: ./run.sh authority-demo down"
    ;;

  seed)
    banner "seed (populate + watch, no LLM)"
    ensure_setup && ensure_graph && ensure_server || exit 1
    "$PY" demos/seed_andyur.py || exit 1
    nexthint "watch it live: ANDYUR_SERVER_URL=$ANDYUR_SERVER_URL ./andyur-cli watch" \
             "stop demo services: ./run.sh demo down"
    ;;

  incident-recall|incident)
    banner "incident-recall (memory recall across three runs)"
    ensure_setup && ensure_graph && ensure_server worker && ensure_a_model required || exit 1
    "$PY" demos/incident_recall_demo.py || exit 1
    nexthint "stop demo services: ./run.sh demo down"
    ;;

  tool-agent|tool-agent-http|select-tools)
    banner "$cmd"
    case "$cmd" in
      tool-agent)      AGENT_NAME=toolbot ;;
      tool-agent-http) AGENT_NAME=cibot-http ;;
      select-tools)    AGENT_NAME=opsbot ;;
    esac
    SAMPLE_ASK="What is the CI status of checkout-service?"
    # Model FIRST, so the worker daemon inherits the backend env (a worker
    # started before the model config would default to the wrong backend).
    ensure_setup && ensure_a_model required && ensure_server worker || exit 1
    # Create the agent from the folder's files (idempotent: a prior run's agent
    # is fine; the demo just re-triggers it).
    ./demos/"$cmd"/run.sh >/dev/null 2>&1 || true
    dp_ok "agent '$AGENT_NAME' ready"
    dp_step "trigger: \"$SAMPLE_ASK\""
    ./andyur-cli agents trigger "$AGENT_NAME" --reason "$SAMPLE_ASK" >/dev/null 2>&1 || true
    RID=""
    for _ in $(seq 1 48); do
      RID="$(./andyur-cli agents runs "$AGENT_NAME" 2>/dev/null | awk 'NR==2{print $1}')"
      ST="$(./andyur-cli agents runs "$AGENT_NAME" 2>/dev/null | awk 'NR==2{print $3}')"
      case "$ST" in done|failed|cancelled) break ;; esac
      sleep 5
    done
    dp_step "the agent's answer (run $RID: $ST)"
    _demo_show_answer "$AGENT_NAME" "$RID"
    nexthint "watch live next time: ANDYUR_SERVER_URL=$ANDYUR_SERVER_URL ./andyur-cli watch" \
             "stop demo services: ./run.sh demo down"
    ;;

  e2e)
    banner "e2e (${MODE:-fast})"
    ensure_setup && ensure_spire || exit 1
    if [ "$MODE" = full ]; then ensure_a_model required || exit 1; fi
    ./run.sh e2e "${MODE:-fast}"
    ;;

  *)
    dp_fail "unknown demo '$cmd'"; echo; list_demos; exit 2 ;;
esac

#!/usr/bin/env bash
# Real-wire conformance check for the shared LLM gateway. This deliberately
# launches the shipped Claude client protocol against the pinned LiteLLM image;
# it does not import LiteLLM or emulate its request translation in Andyur.
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")/../.." && pwd)"
VERIFY_TAG="${ANDYUR_LITELLM_VERIFY_TAG:-$$}"
export COMPOSE_PROJECT_NAME="andyur-litellm-verify-$VERIFY_TAG"
ANDYUR_LITELLM_PORT="${ANDYUR_LITELLM_VERIFY_PORT:-0}"
export ANDYUR_LITELLM_PORT
COMPOSE=(docker compose -f "$HERE/infra/docker-compose.yml" --profile llm)
MODEL="claude-haiku-4-5"

: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY to run the real provider check}"
command -v claude >/dev/null || {
  echo "claude CLI is required (the runner image pins the supported version)" >&2
  exit 1
}

if [[ -z "${LITELLM_MASTER_KEY:-}" ]]; then
  LITELLM_MASTER_KEY="sk-andyur-$(openssl rand -hex 24)"
  export LITELLM_MASTER_KEY
fi

cleanup() {
  "${COMPOSE[@]}" down --remove-orphans --volumes >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Native-wire verification does not need a collector. Do not conflict with or
# create an operator's global Jaeger container and persistent trace volume.
"${COMPOSE[@]}" up -d --no-deps litellm
container_id="$("${COMPOSE[@]}" ps -q litellm)"
[[ -n "$container_id" ]] || { echo "LiteLLM container was not created" >&2; exit 1; }
published="$(docker port "$container_id" 4000/tcp)"
ANDYUR_LITELLM_PORT="${published##*:}"
[[ "$ANDYUR_LITELLM_PORT" =~ ^[0-9]+$ ]] || {
  echo "could not discover LiteLLM host port: $published" >&2; exit 1;
}
for _ in {1..40}; do
  state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
  [[ "$state" == healthy ]] && break
  sleep 1
done
[[ "${state:-}" == healthy ]] || {
  "${COMPOSE[@]}" logs --no-color --tail=100 litellm >&2
  echo "LiteLLM did not become healthy" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"; cleanup' EXIT
HOME="$work" \
ANTHROPIC_BASE_URL="http://127.0.0.1:$ANDYUR_LITELLM_PORT" \
ANTHROPIC_AUTH_TOKEN="$LITELLM_MASTER_KEY" \
ANTHROPIC_API_KEY= \
  claude -p "Reply with exactly ANDYUR_LITELLM_OK" \
    --model "$MODEL" --output-format json >"$work/result.json"

python3 - "$work/result.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
if data.get("result", "").strip() != "ANDYUR_LITELLM_OK":
    raise SystemExit(f"unexpected model response: {data.get('result')!r}")
print("PASS native Anthropic Messages/SSE reached the provider through shared LiteLLM")
PY

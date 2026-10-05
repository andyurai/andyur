#!/usr/bin/env bash
# Non-interactive OpenBao bring-up for the SRE gate: the SEALED production vault
# (NOT `server -dev`, which the stack forbids), stood up so a run's model
# credential comes FROM the vault under the least-privilege `model-broker` policy
# rather than being injected as a raw env var. This is the operator/daemon seam:
# an operator seeds the vault, and the daemon reads the key under model-broker to
# hand to the model proxy -- exactly what this reproduces, headless.
#
#   up      : TLS + compose up + init(1/1) + unseal + configure(kv/transit/policies)
#   store   : write the LLM key at the model-broker path (root, on stdin)
#   read    : mint a model-broker-scoped token and read the key back with it
#   deny    : prove the model-broker policy CANNOT read an unrelated path
#   down    : tear the vault down and remove its volume
#
# The root token never touches a command line or a log: it lives only in this
# process and on stdin to configure.sh, matching the shipped stack's contract.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDYUR_OPENBAO_PORT="${ANDYUR_OPENBAO_PORT:-8200}"
export ANDYUR_OPENBAO_TLS_DIR="$HERE/../../data/openbao/tls"
STATE="${ANDYUR_OPENBAO_GATE_STATE:-${TMPDIR:-/tmp}/andyur-openbao-gate}"
compose() { docker compose -f "$HERE/compose.yaml" "$@"; }
MB_PATH="secret/production/model-providers/anthropic"

up() {
  # Clean slate: this harness owns its vault for the run, so a leftover
  # initialized volume from a prior run would 400 the init. Fresh every time.
  compose down -v >/dev/null 2>&1 || true
  docker volume rm andyur-openbao-data >/dev/null 2>&1 || true
  mkdir -p "$STATE"; chmod 700 "$STATE"
  bash "$HERE/openbao-stack.sh" up >/dev/null 2>&1 \
    || { echo "openbao up failed" >&2; compose logs --no-log-prefix openbao 2>&1 | tail >&2; return 1; }
  local init unseal root
  init="$(compose exec -T openbao bao operator init -format=json \
            -key-shares=1 -key-threshold=1 2>&1)" \
    || { echo "openbao init failed: $init" >&2; return 1; }
  unseal="$(printf '%s' "$init" | python3 -c 'import json,sys; print(json.load(sys.stdin)["unseal_keys_b64"][0])')"
  root="$(printf '%s' "$init" | python3 -c 'import json,sys; print(json.load(sys.stdin)["root_token"])')"
  [ -n "$unseal" ] && [ -n "$root" ] || { echo "openbao init produced no keys" >&2; return 1; }
  compose exec -T openbao bao operator unseal "$unseal" >/dev/null \
    || { echo "openbao unseal failed" >&2; return 1; }
  printf '%s\n' "$root" | compose exec -T openbao /openbao/bootstrap/configure.sh >/dev/null \
    || { echo "openbao configure failed" >&2; return 1; }
  # Root token stays in a 0600 file readable only by this harness, for store/read.
  ( umask 077; printf '%s' "$root" >"$STATE/root" )
  return 0
}

# Secrets reach the container's environment by FORWARDING (`-e VAR`, no value),
# never as `-e VAR=value` -- a value after `=` lands on the `docker` process
# argv where any `ps` on the host reads it. The token/key lives only in this
# shell's env for the length of one exec.
store() {   # LLM key on stdin
  local root; root="$(cat "$STATE/root")"
  local key; IFS= read -r key
  [ -n "$key" ] || { echo "store: empty key on stdin" >&2; return 1; }
  BAO_TOKEN="$root" KEYVAL="$key" compose exec -T -e BAO_TOKEN -e KEYVAL openbao \
    sh -c 'bao kv put '"$MB_PATH"' api_key="$KEYVAL" >/dev/null'
}

_mb_token() {   # mint a model-broker-scoped token, print it (root forwarded, not on argv)
  local root ttl="${1:-15m}"; root="$(cat "$STATE/root")"
  BAO_TOKEN="$root" compose exec -T -e BAO_TOKEN openbao \
    sh -c 'bao token create -policy=model-broker -ttl='"$ttl"' -format=json' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["auth"]["client_token"])'
}

read_key() {   # read the key with a model-broker token, print it
  local mb; mb="$(_mb_token 15m)"
  [ -n "$mb" ] || { echo "read: model-broker token mint failed" >&2; return 1; }
  BAO_TOKEN="$mb" compose exec -T -e BAO_TOKEN openbao \
    sh -c 'bao kv get -format=json '"$MB_PATH" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"]["api_key"])'
}

deny() {   # a model-broker token must NOT read an unrelated path (least privilege)
  local mb; mb="$(_mb_token 5m)"
  [ -n "$mb" ] || { echo "deny: model-broker token mint failed" >&2; return 1; }
  local out; out="$(BAO_TOKEN="$mb" compose exec -T -e BAO_TOKEN openbao \
    sh -c 'bao kv get secret/production/other 2>&1' || true)"
  printf '%s' "$out" | grep -qiE "permission denied|403"
}

down() {
  compose down -v >/dev/null 2>&1 || true
  docker volume rm andyur-openbao-data >/dev/null 2>&1 || true
  rm -rf "$STATE" 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  store) store ;;
  read) read_key ;;
  deny) deny ;;
  down) down ;;
  *) echo "usage: $0 {up|store|read|deny|down}" >&2; exit 2 ;;
esac

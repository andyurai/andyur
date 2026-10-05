#!/usr/bin/env bash
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$HERE/compose.yaml"
TLS_DIR="$HERE/../../data/openbao/tls"
export ANDYUR_OPENBAO_TLS_DIR="$TLS_DIR"

die() { echo "openbao: $*" >&2; exit 1; }
compose() { docker compose -f "$COMPOSE" "$@"; }

make_tls() {
  mkdir -p "$TLS_DIR"
  chmod 700 "$TLS_DIR"
  if [ -e "$TLS_DIR/ca.key" ] || [ -e "$TLS_DIR/server.key" ]; then
    [ -s "$TLS_DIR/ca.crt" ] && [ -s "$TLS_DIR/server.crt" ] \
      && [ -s "$TLS_DIR/server.key" ] || die "partial TLS state; inspect $TLS_DIR"
    return
  fi
  local ext="$TLS_DIR/server.ext"
  openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes \
    -subj "/CN=Andyur development OpenBao CA" \
    -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" >/dev/null 2>&1
  openssl req -newkey rsa:3072 -sha256 -nodes -subj "/CN=openbao" \
    -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" >/dev/null 2>&1
  printf '%s\n' 'subjectAltName=DNS:openbao,DNS:localhost,IP:127.0.0.1' \
    'extendedKeyUsage=serverAuth' >"$ext"
  openssl x509 -req -sha256 -days 30 -in "$TLS_DIR/server.csr" \
    -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -extfile "$ext" -out "$TLS_DIR/server.crt" >/dev/null 2>&1
  rm -f "$TLS_DIR/server.csr" "$TLS_DIR/server.ext" "$TLS_DIR/ca.srl"
  chmod 600 "$TLS_DIR"/*
}

wait_for_api() {
  for _ in $(seq 1 40); do
    compose exec -T openbao bao status >/dev/null 2>&1 && return 0
    status=$?
    [ "$status" -eq 2 ] && return 0 # sealed is reachable and expected
    sleep 0.5
  done
  die "API did not become reachable over verified TLS"
}

initialize() {
  recovery="${ANDYUR_OPENBAO_RECOVERY_DIR:-}"
  [ -n "$recovery" ] || die "set ANDYUR_OPENBAO_RECOVERY_DIR to a private, empty directory"
  case "$recovery" in /*) ;; *) die "recovery directory must be an absolute path" ;; esac
  mkdir -p "$recovery"
  [ "$(find "$recovery" -mindepth 1 -maxdepth 1 -print -quit)" = "" ] \
    || die "recovery directory must be empty"
  chmod 700 "$recovery"
  bundle="$recovery/openbao-init.json"
  compose exec -T openbao bao operator init -format=json \
    -key-shares=3 -key-threshold=2 >"$bundle"
  chmod 600 "$bundle"
  echo "initialized; recovery bundle written mode 0600 to $bundle"
  echo "distribute its unseal shares to separate custodians before production use"
}

unseal() {
  echo "enter two different custodian shares when prompted; input is hidden"
  compose exec openbao bao operator unseal
  compose exec openbao bao operator unseal
}

configure() {
  [ -t 0 ] || die "configure requires an interactive terminal"
  printf 'root token (hidden; used only on bootstrap stdin): ' >&2
  IFS= read -r -s token
  printf '\n' >&2
  [ -n "$token" ] || die "empty root token"
  printf '%s\n' "$token" | compose exec -T openbao /openbao/bootstrap/configure.sh
  unset token
}

case "${1:-help}" in
  up) make_tls; compose up -d; wait_for_api; compose ps ;;
  init) wait_for_api; initialize ;;
  unseal) wait_for_api; unseal ;;
  configure) wait_for_api; configure ;;
  status) compose exec -T openbao bao status ;;
  logs) compose logs --no-log-prefix openbao ;;
  down) compose down ;;
  destroy-dev)
    [ "${2:-}" = "--confirm-destroy-development-vault" ] \
      || die "refusing; pass --confirm-destroy-development-vault"
    compose down -v
    echo "development OpenBao volume removed; recovery material was not removed"
    ;;
  *) echo "usage: $0 {up|init|unseal|configure|status|logs|down|destroy-dev --confirm-destroy-development-vault}" ;;
esac

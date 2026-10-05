#!/usr/bin/env bash
# Stand up the HARDENED policy stack. Sourced by the verify/demo scripts so
# every one of them exercises the same production shape, rather than each
# script inventing its own weaker version.
#
#   bundle server  (static HTTP)  --pull-->  OPA  <--ask--  AuthZEN shim  <--  Andyur
#
# What "hardened" means here, and why each piece exists:
#
#   token auth + system.authz   OPA's own API is deny-by-default; the only
#                               capability granted to anyone is "ask a question"
#   signed bundles              policy arrives by pull and must verify against a
#                               public key, so owning the bundle SERVER is not
#                               enough to change authorization
#   explicit bundle roots       a bundle may own `andyur` and nothing else, so
#                               activating one can never remove the policy that
#                               protects OPA itself
#   no write API in use         policy still changes with no redeploy, but
#                               through the bundle, not an inbound mutation path
#   least privilege container   non-root, all capabilities dropped, no new privs
#   per-invocation identity     name and ports belong to ONE run, so gates in
#                               different sessions cannot delete each other
#
# Usage:  source opa-stack.sh; opa_stack_up; ... ; opa_stack_down
#
# After opa_stack_up returns, $OPA_CONTAINER, $OPA_PORT, $SHIM_PORT and
# $BUNDLE_PORT hold this invocation's values; export any of them beforehand to
# pin it. opa_stack_orphans lists containers left by runs that died before
# their trap; opa_stack_reap <stack-id> removes one of them.

OPA_IMAGE="${OPA_IMAGE:-openpolicyagent/opa:1.18.2}"

# THE STACK'S IDENTITY IS PER-INVOCATION, NOT FIXED, AND THAT IS LOAD-BEARING.
# Four scripts source this helper -- verify-opa.sh, verify-opa-hardening.sh,
# verify-sre-registry.sh and demo-no-redeploy.sh -- and on a developer machine
# several of them run at once, in different sessions, against one Docker daemon.
# This file used to hard-assign OPA_CONTAINER="andyur-opa" and then
# `docker rm -f` that name on the way up, so whichever gate started LAST
# silently destroyed the engine of every gate already running. The victim did
# not fail as "someone deleted my container"; it failed as a missing decision or
# an unreachable PDP, which reads like a policy defect and is not one.
#
# So the name carries a per-invocation id, and the three host ports are asked
# for from the kernel rather than assumed. A caller that needs a specific value
# still wins by exporting it -- these are all `${VAR:-default}`.
OPA_STACK_ID="${OPA_STACK_ID:-$$-$(openssl rand -hex 3)}"
OPA_CONTAINER="${OPA_CONTAINER:-andyur-opa-$OPA_STACK_ID}"

# Empty, not a literal: opa_stack_up asks the kernel for a free port at the
# moment it needs one. Resolving these at SOURCE time would widen the window
# between choosing a port and binding it, and would burn three probes on the
# callers that override them anyway.
OPA_PORT="${OPA_PORT:-}"
SHIM_PORT="${SHIM_PORT:-}"
BUNDLE_PORT="${BUNDLE_PORT:-}"

# Where generated material lives: signing keys, the built bundle, the bundle
# server's document root. Never committed; regenerated on every run so a stale
# key can never silently authorise a stale bundle.
OPA_WORK=""

opa_stack_paths() {
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ROOT="$(cd "$HERE/../.." && pwd)"
  VENV="$ROOT/.venv"
}

# The three free TCP ports this stack needs, chosen by the kernel rather than
# guessed -- and chosen TOGETHER.
#
# All three sockets are held open until the last one is bound, so the kernel
# cannot hand the same port out twice. Probing them one at a time would work
# only because the OS happens to cycle its ephemeral range (measured here: 0
# collisions in 200 triples) and nothing guarantees that. This file has already
# been bitten twice by an assumption that held on macOS and broke on Linux --
# the in-container build uid, and the loopback bundle bind -- so distinctness is
# made a kernel guarantee instead of a property of the host we happened to test.
#
# $1 is the address the shim will really bind, because a port free on loopback
# is not necessarily free on 0.0.0.0. There remains an unavoidable window
# between these sockets closing and the real services binding; a lost race there
# surfaces as this stack failing to come up, which is loud and affects only us.
_opa_free_ports() {   # $1 = shim bind address; prints "OPA SHIM BUNDLE"
  python3 -c 'import socket, sys
held = []
# The OPA port is probed on 0.0.0.0, not loopback: `docker run -p "$OPA_PORT:8181"`
# publishes on ALL interfaces, so a port free only on 127.0.0.1 is one docker
# then fails to bind.
for addr in ("0.0.0.0", sys.argv[1], "0.0.0.0"):
    s = socket.socket()
    s.bind((addr, 0))
    held.append(s)
print(" ".join(str(s.getsockname()[1]) for s in held))
for s in held:
    s.close()' "$1"
}

# --- the bundle ------------------------------------------------------------

# Build a SIGNED bundle from a policy directory.
#   $1 = directory of .rego files to include
# The manifest is written by us rather than defaulted, because the default is
# dangerous: a bundle with no declared roots owns the ENTIRE document tree, and
# activating it removes anything not in it -- including the system.authz policy
# that stops the engine being rewritten. Declaring `andyur` means an activation
# can only ever replace Andyur's own policy, never the engine's defences.
opa_build_bundle() {
  local src="$1"
  local stage="$OPA_WORK/stage"
  rm -rf "$stage" && mkdir -p "$stage"
  cp "$src"/*.rego "$stage"/
  cat > "$stage/.manifest" <<'JSON'
{
  "roots": ["andyur"],
  "metadata": {"name": "andyur-authz"}
}
JSON

  # The signature covers every file's digest plus a scope claim, so a bundle
  # signed for some other purpose with the same key will not verify here.
  cat > "$OPA_WORK/claims.json" <<'JSON'
{"scope": "andyur_policy"}
JSON

  # As the INVOKING uid, not the image's default (1000). `mktemp -d` makes
  # $OPA_WORK mode 0700 owned by us, and the opa image runs as uid 1000, which
  # on Linux cannot even traverse into it to read the signing key or write the
  # bundle. macOS Docker Desktop hid this: its file-sharing layer ignores the
  # in-container uid, so the build passed locally and failed on every Linux CI
  # runner -- the "verified against a stand-in" gap, with macOS as the stand-in.
  # Not >/dev/null: a swallowed error here cost a diagnosis. opa build writes to
  # -o, so success is quiet anyway; only a failure prints.
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$stage:/stage:ro" \
    -v "$OPA_WORK:/work" \
    "$OPA_IMAGE" build -b /stage \
      --signing-key /work/bundle-signing-private.pem \
      --signing-alg RS256 \
      --claims-file /work/claims.json \
      -o /work/serve/andyur-bundle.tar.gz
}

opa_make_keys() {
  # A fresh signing keypair per run. OPA gets the PUBLIC half only, so the
  # engine can verify a bundle but can never mint one: an attacker who owns the
  # OPA container still cannot author policy.
  openssl genrsa -out "$OPA_WORK/bundle-signing-private.pem" 2048 2>/dev/null
  openssl rsa -in "$OPA_WORK/bundle-signing-private.pem" \
    -pubout -out "$OPA_WORK/bundle-signing-public.pem" 2>/dev/null
  # OPA's config takes the PEM inline. Newlines become \n escapes so the value
  # survives environment substitution into a quoted YAML scalar.
  OPA_BUNDLE_PUBKEY="$(awk '{printf "%s\\n", $0}' "$OPA_WORK/bundle-signing-public.pem")"
  export OPA_BUNDLE_PUBKEY
}

# --- bringing it up --------------------------------------------------------

opa_stack_up() {
  local policy_src="${1:-$HERE}"
  opa_stack_paths

  # PRECONDITION FIRST, before this function creates anything at all.
  #
  # Refuse a name we did not create; never force-delete it. The line that used
  # to stand further down was `docker rm -f "$OPA_CONTAINER"`, and with a fixed
  # name that made starting a gate an attack on every gate already running.
  # Reaching this branch means either a genuine collision on an explicitly
  # exported OPA_CONTAINER, or an orphan from a run killed before its trap fired
  # (opa_stack_orphans lists those). Both want a human, not a silent delete.
  #
  # It is checked HERE, at the top, rather than beside the `docker run`: doing it
  # late meant every refusal had already made a signing key on disk and started a
  # bundle server listening on all interfaces, and then returned without
  # unwinding either.
  if docker container inspect "$OPA_CONTAINER" >/dev/null 2>&1; then
    echo "    refusing to start: a container named $OPA_CONTAINER already exists"
    echo "    it is not ours to delete -- another gate may be using it right now."
    echo "    List reapable orphans of this stack with: opa_stack_orphans"
    return 1
  fi

  # Resolve the ports now, as late as possible (see _opa_free_ports). Any that
  # the caller pinned by exporting it still wins; only the blanks are filled.
  if [ -z "$OPA_PORT" ] || [ -z "$SHIM_PORT" ] || [ -z "$BUNDLE_PORT" ]; then
    local free_opa free_shim free_bundle
    read -r free_opa free_shim free_bundle \
      <<<"$(_opa_free_ports "${SHIM_HOST:-127.0.0.1}")"
    OPA_PORT="${OPA_PORT:-$free_opa}"
    SHIM_PORT="${SHIM_PORT:-$free_shim}"
    BUNDLE_PORT="${BUNDLE_PORT:-$free_bundle}"
  fi

  OPA_WORK="$(mktemp -d)"
  mkdir -p "$OPA_WORK/serve"

  # A high-entropy token that grants ONE capability: POST the decision query.
  # It cannot write policy or data, so leaking it does not let an attacker
  # change any answer -- see system-authz.rego.
  OPA_QUERY_TOKEN="$(openssl rand -hex 32)"
  export OPA_QUERY_TOKEN

  echo "==> generating a bundle signing keypair (public half to OPA only)"
  opa_make_keys

  echo "==> building the signed policy bundle (roots: andyur)"
  # Only the base policy goes in the first bundle. The demo adds a second one
  # later to prove policy changes with no redeploy.
  local base="$OPA_WORK/base"; mkdir -p "$base"; cp "$policy_src/policy.rego" "$base/"
  opa_build_bundle "$base"

  echo "==> serving the bundle over HTTP (pull, so OPA needs no inbound write path)"
  # Bound to all interfaces, not 127.0.0.1: the OPA CONTAINER pulls this over the
  # docker bridge, reaching the host as host.docker.internal -> host-gateway
  # (172.17.0.1 on Linux), and a server bound to loopback refuses that. macOS
  # Docker Desktop makes 127.0.0.1 reachable from containers, so loopback passed
  # locally and every Linux runner got "connection refused" on bundle load --
  # the same macOS-as-stand-in gap as the build uid. The content is a SIGNED
  # public policy bundle that OPA verifies, and the server dies with the run, so
  # binding all interfaces exposes nothing secret.
  (cd "$OPA_WORK/serve" && exec python3 -m http.server "$BUNDLE_PORT" \
      --bind 0.0.0.0 >/dev/null 2>&1) &
  BUNDLE_PID=$!

  echo "==> starting OPA: token auth, deny-by-default API, non-root, no capabilities"
  if ! docker run -d --name "$OPA_CONTAINER" -p "$OPA_PORT:8181" \
    --label andyur.opa-stack="$OPA_STACK_ID" \
    --add-host host.docker.internal:host-gateway \
    --user 1000:1000 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --read-only \
    --tmpfs /tmp \
    -v "$HERE/opa-config.yaml:/config/opa-config.yaml:ro" \
    -v "$HERE/system-authz.rego:/policies/system-authz.rego:ro" \
    -v "$HERE/system-log-mask.rego:/policies/system-log-mask.rego:ro" \
    -e "OPA_BUNDLE_URL=http://host.docker.internal:$BUNDLE_PORT" \
    -e "OPA_BUNDLE_PUBKEY=$OPA_BUNDLE_PUBKEY" \
    -e "OPA_QUERY_TOKEN=$OPA_QUERY_TOKEN" \
    "$OPA_IMAGE" run --server --addr=0.0.0.0:8181 \
      --authentication=token \
      --authorization=basic \
      --config-file=/config/opa-config.yaml \
      /policies >/dev/null; then
    # `docker run -d` can fail AFTER creating the container -- a host port taken
    # between our probe and the bind exits 125 with the container sitting in
    # Created. Unwinding here is what stops that becoming a permanent orphan
    # that a pinned OPA_CONTAINER could never start past again.
    echo "    OPA container failed to start"
    opa_stack_down
    return 1
  fi

  # Readiness means "the signed bundle activated", not merely "the process is
  # listening". Without the bundle check a test could pass against an engine
  # with no Andyur policy at all, where every decision is an undefined-deny.
  local ok=""
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$OPA_PORT/health?bundles=true" >/dev/null; then ok=1; break; fi
    sleep 0.5
  done
  if [ -z "$ok" ]; then
    echo "    OPA did not become ready. Logs:"; docker logs "$OPA_CONTAINER" 2>&1 | tail -20
    # Unwind before returning. A readiness timeout used to leave a RUNNING
    # container holding its port, and a caller whose teardown is gated on its
    # own "did the stack come up" flag (verify-sre-registry.sh:334) would then
    # never remove it -- wedging every later run on that port.
    opa_stack_down
    return 1
  fi
  echo "    OPA up, signed bundle verified and activated"

  echo "==> starting the AuthZEN shim"
  # Binds loopback by default; a harness whose PDP client is IN A CONTAINER sets
  # SHIM_HOST=0.0.0.0 so it can reach the shim via host.docker.internal (Linux
  # containers cannot reach the host's 127.0.0.1; macOS Docker Desktop can).
  OPA_URL="http://127.0.0.1:$OPA_PORT" OPA_TOKEN="$OPA_QUERY_TOKEN" \
    "$VENV/bin/python" -m uvicorn authzen_shim:app \
    --app-dir "$HERE" --host "${SHIM_HOST:-127.0.0.1}" \
    --port "$SHIM_PORT" --log-level warning &
  SHIM_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$SHIM_PORT/.well-known/authzen-configuration" >/dev/null && break
    sleep 0.5
  done
  echo "    shim up"
}

opa_stack_down() {
  [ -n "${SHIM_PID:-}" ] && kill "$SHIM_PID" 2>/dev/null || true
  [ -n "${BUNDLE_PID:-}" ] && kill "$BUNDLE_PID" 2>/dev/null || true
  SHIM_PID=""
  BUNDLE_PID=""
  # Only what THIS invocation created -- and ownership is proven by the LABEL on
  # the actual container, not by a shell flag set after a successful start.
  #
  # The flag was wrong in both directions. `docker run -d` can fail after
  # CREATING the container (a taken host port exits 125 with it sitting in
  # Created), so a flag set only on success left that container orphaned
  # forever. The label cannot disagree with reality: only this invocation ever
  # writes this OPA_STACK_ID, so a peer's container never matches and a
  # created-but-not-started one does.
  opa_stack_reap "$OPA_STACK_ID"
  [ -n "${OPA_WORK:-}" ] && rm -rf "$OPA_WORK"
  OPA_WORK=""
  return 0
}

# --- orphans ---------------------------------------------------------------
#
# Honest consequence of per-invocation names: the old fixed name garbage-
# collected itself, because the next run force-deleted whatever held it. That
# self-cleaning was the very bug, so removing it means a gate killed hard enough
# to skip its EXIT trap (SIGKILL, a closed laptop) now leaves its container
# behind, and on a small Docker VM those add up.
#
# Reaping is therefore explicit and targeted, never automatic and never "all":
# an automatic sweep is indistinguishable from the destructive behaviour just
# removed, and on this host a peer session's live engine would be the casualty.
opa_stack_orphans() {
  docker ps -a --filter "label=andyur.opa-stack" \
    --format '{{.Label "andyur.opa-stack"}}  {{.Names}}  {{.Status}}'
}

opa_stack_reap() {
  local id="${1:-}"
  if [ -z "$id" ]; then
    echo "usage: opa_stack_reap <stack-id>   (see opa_stack_orphans)" >&2
    return 2
  fi
  docker ps -aq --filter "label=andyur.opa-stack=$id" | while read -r cid; do
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true
  done
}

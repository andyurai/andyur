#!/usr/bin/env bash
# THE GOVERNED REGISTRY, END TO END ON REAL TOOLS: a local OCI registry, a real
# cosign keypair, real oras pushes. Proves the composed G05 path -- publish
# signed snapshot, resolve by pinned digest -- and that every refusal actually
# refuses: wrong key, moved tag, deny-listed digest.
#
# Needs: docker, cosign, oras, and the project venv. ~30 seconds.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$HERE/.venv/bin/python"
PORT=5001
REG="localhost:$PORT/andyur/agents"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
ok()  { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
cleanup() {
  docker rm -f andyur-verify-registry >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v cosign >/dev/null || { echo "cosign not on PATH"; exit 1; }
command -v oras   >/dev/null || { echo "oras not on PATH"; exit 1; }
[ -x "$PY" ] || { echo "run ./run.sh setup first"; exit 1; }

echo "== 1. local OCI registry =="
docker rm -f andyur-verify-registry >/dev/null 2>&1
docker run -d --name andyur-verify-registry -p "$PORT:5000" registry:2 >/dev/null \
  || { echo "could not start registry:2"; exit 1; }
until curl -sf "http://localhost:$PORT/v2/" >/dev/null; do sleep 0.5; done

push_digest() {  # dir tag -> digest on stdout
  ( cd "$1" && oras push --plain-http --format json "$REG:$2" ./*.json 2>/dev/null ) \
    | "$PY" -c "import json,sys; print(json.load(sys.stdin)['reference'].split('@')[1])"
}
echo "== 2. compile, publish, and sign one atomic BYOA snapshot =="
( cd "$WORK" && COSIGN_PASSWORD="" cosign generate-key-pair >/dev/null 2>&1 )
mkdir "$WORK/publisher-input"
"$PY" - "$WORK/publisher-input/agent.json" <<'PY'
import json, sys
json.dump({
    "apiVersion": "andyur.ai/v1", "kind": "Agent",
    "metadata": {"id": "agt_published", "name": "published", "version": "1.0.0"},
    "runtime": {"type": "builtin-claude"},
    "instructions": "Live atomic publisher proof.",
}, open(sys.argv[1], "w"))
PY
PINNED=$(cd "$HERE" && COSIGN_PASSWORD="" "$PY" - \
  "$WORK/publisher-input/agent.json" "$HERE/demos/agent-registry/bystander.json" \
  "$WORK/snapshot" "$REG:approved" "$WORK/cosign.key" <<'PY'
import sys
from andyur.agentspec.publisher import package_agents, publish_snapshot
manifest, policy, output, ref, key = sys.argv[1:]
package_agents([manifest], policy, output, approved_models=(),
               policy_revision="live-review-1")
print(publish_snapshot(output, ref, key, allow_http_registry=True,
                       disable_transparency_log=True))
PY
)
DIGEST=${PINNED##*@}
[ "$PINNED" = "$REG@$DIGEST" ] || { echo "publisher returned non-pinned ref"; exit 1; }
echo "  snapshot: $DIGEST"

resolve() {  # ref key extra_env -> prints resolved digest or error to stderr
  env ANDYUR_REGISTRY=governed \
      ANDYUR_REGISTRY_REF="$1" \
      ANDYUR_REGISTRY_COSIGN_KEY="$2" \
      ANDYUR_REGISTRY_COSIGN_IGNORE_TLOG=on \
      ANDYUR_REGISTRY_ALLOW_HTTP=on \
      ${3:+ANDYUR_REGISTRY_DENY_DIGESTS="$3"} \
      "$PY" - <<'EOF'
from andyur.registry.service import configured_registry
reg = configured_registry()
agents = reg.list_agents()
assert agents, "governed registry served no agents"
digests = {a.registry_digest for a in agents}
assert len(digests) == 1, f"inconsistent digests: {digests}"
print(digests.pop())
EOF
}

echo "== 3. positive control: verified snapshot serves, digest stamped =="
GOT=$( cd "$HERE" && resolve "$REG@$DIGEST" "$WORK/cosign.pub" "" 2>"$WORK/pos.err" )
if [ "$GOT" = "$DIGEST" ]; then ok "resolved $(echo "$GOT" | cut -c1-19)... under valid signature"
else bad "positive control: $(tail -1 "$WORK/pos.err")"; fi

echo "== 4. a tag reference is refused =="
if ( cd "$HERE" && resolve "$REG:approved" "$WORK/cosign.pub" "" ) >/dev/null 2>"$WORK/tag.err"
then bad "tag reference was accepted"
else grep -q "digest" "$WORK/tag.err" && ok "tag refused: digest pin required" \
     || bad "tag refused for the wrong reason: $(tail -1 "$WORK/tag.err")"; fi

echo "== 5. the wrong key is refused =="
( cd "$WORK" && mkdir wrong && cd wrong && COSIGN_PASSWORD="" cosign generate-key-pair >/dev/null 2>&1 )
if ( cd "$HERE" && resolve "$REG@$DIGEST" "$WORK/wrong/cosign.pub" "" ) >/dev/null 2>"$WORK/key.err"
then bad "signature from a different key was accepted"
else ok "wrong key refused"; fi

echo "== 6. a deny-listed digest is refused despite a valid signature =="
if ( cd "$HERE" && resolve "$REG@$DIGEST" "$WORK/cosign.pub" "$DIGEST" ) >/dev/null 2>"$WORK/deny.err"
then bad "deny-listed digest was served"
else grep -q "deny-listed" "$WORK/deny.err" && ok "deny-list refused the snapshot" \
     || bad "deny refused for the wrong reason: $(tail -1 "$WORK/deny.err")"; fi

echo "== 7. an unsigned but otherwise VALID snapshot is refused =="
# The rogue must be VALID manifests, merely unsigned, so the ONLY thing that
# can refuse it is the missing signature. An invalid manifest would be rejected
# by ManifestAgentRegistry even with signature-checking disabled, making this a
# test that cannot fail for its stated purpose (red-team finding, 2026-08-13).
mkdir "$WORK/rogue"
cp "$HERE"/demos/agent-registry/*.json "$WORK/rogue/"
ROGUE=$(push_digest "$WORK/rogue" rogue)   # pushed, never signed
if ( cd "$HERE" && resolve "$REG@$ROGUE" "$WORK/cosign.pub" "" ) >/dev/null 2>"$WORK/rogue.err"
then bad "unsigned snapshot was served"
else grep -qi "verify\|signature\|no matching signatures\|cosign" "$WORK/rogue.err" \
     && ok "unsigned valid snapshot refused at the signature gate" \
     || bad "unsigned snapshot refused for the wrong reason: $(tail -1 "$WORK/rogue.err")"; fi

echo
echo "registry governance gate: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

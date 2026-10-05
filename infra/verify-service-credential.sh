#!/usr/bin/env bash
# Phase 2c, THE WIRE PROOF: a run fetches a real SERVICE credential from the
# sealed OpenBao vault using its own docker-attested SPIRE JWT-SVID (SPIFFE ->
# OpenBao JWT-auth federation), presents it to an upstream that ACCEPTS it, and
# the credential is ABSENT from the agent's environment, the container argv, the
# run transcript, and the logs. This is the brokered-credential half of "the
# vault for service and LLM credentials" -- the LLM half is the SRE gate's phase
# 2; this proves the service half through the real andyur.credential_service.
#
# PREREQUISITES: the containerized SPIRE stack (./run.sh spire-docker up), docker,
# and the project venv. It stands up its OWN sealed OpenBao and tears it down.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# port_held/port_listener, the same source verify-resource-pep.sh:16 uses. This
# file borrowed that gate's occupancy idiom without its `source` line, so every
# `port_held` call was `command not found`: the new squatter refusal below could
# never fire, and the upstream readiness check reddened a gate whose upstream was
# in fact up and accepting the brokered credential -- a false RED replacing a
# false green. Found by running the gate end to end; `bash -n` cannot see it,
# because an undefined function is a runtime error in shell, not a syntax one.
. "$HERE/infra/ports.sh"
OB="$HERE/infra/openbao"
NET="andyur-spire-net"; SOCK="andyur-spire-sockets"; TD="andyur.local"
export ANDYUR_OPENBAO_PORT="${ANDYUR_SVC_OPENBAO_PORT:-8212}"
export ANDYUR_OPENBAO_TLS_DIR="$HERE/data/openbao/tls"
compose() { docker compose -f "$OB/compose.yaml" "$@"; }
WORK="$(mktemp -d)"
RUN_ID="svc-cred-$$"
SPIFFE_ID="spiffe://$TD/agent/oncall/run/$RUN_ID"
AUD="openbao"
CRED_REF="pagerduty"
# The brokered service credential: a header the upstream requires. This is the
# value that must NEVER appear in the agent's environment, argv, transcript, or
# logs -- only in the vault and on the sidecar->upstream hop.
SVC_VALUE="Bearer svc-$(openssl rand -hex 20)"
UP_PORT="${ANDYUR_SVC_UPSTREAM_PORT:-8713}"
# FIXED PORTS WITH NO OCCUPANCY REFUSAL. verify-resource-pep.sh:46 already
# refuses to certify against a squatter, for the reason recorded there: a stale
# server from an earlier run made six of seven checks pass against code that was
# NOT the code under test. Two concurrent runs of this gate, or one leftover
# process, and the upstream check describes something else entirely.
for _p in "$ANDYUR_OPENBAO_PORT" "$UP_PORT"; do
  if port_held "$_p"; then
    echo "port $_p is already held by another process:"
    lsof -i "tcp:$_p" 2>/dev/null | sed 's/^/  /'
    echo "refusing to certify against a process this gate did not start."
    exit 1
  fi
done

PASS=0; FAIL=0
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
UP_PID=""
cleanup(){
  [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null || true
  docker rm -f "andyur-svc-run-$RUN_ID" >/dev/null 2>&1 || true
  bash "$OB/openbao-gate.sh" down >/dev/null 2>&1 || true
  docker exec andyur-spire-server /opt/spire/bin/spire-server entry delete \
    -entryID "$(docker exec andyur-spire-server /opt/spire/bin/spire-server entry show \
      -selector "docker:label:andyur.run_id:$RUN_ID" -output json 2>/dev/null \
      | python3 -c 'import json,sys;e=json.load(sys.stdin).get("entries",[]);print(e[0]["id"] if e else "")' 2>/dev/null)" \
    >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker inspect andyur-spire-server >/dev/null 2>&1 \
  || { echo "start the container SPIRE stack first: ./run.sh spire-docker up"; exit 1; }
# Build the runner image from the CURRENT tree: the credential_service the run
# uses lives in it, so a stale image would test stale code.
bash "$HERE/run.sh" sandbox-image --quiet >/dev/null 2>&1 \
  || { echo "could not build the andyur-runner image"; exit 1; }

say "1. the sealed OpenBao vault (real init/unseal/configure, not server -dev)"
bash "$OB/openbao-gate.sh" up \
  && ok "sealed OpenBao up" || { bad "OpenBao did not come up"; exit 1; }
ROOT="$(cat "${TMPDIR:-/tmp}/andyur-openbao-gate/root")"
bao(){ BAO_TOKEN="$ROOT" compose exec -T -e BAO_TOKEN openbao sh -c "$*"; }
# Reachable from run containers under the alias its TLS cert names.
docker network connect --alias openbao "$NET" andyur-openbao 2>/dev/null || true

say "2. federate SPIRE -> OpenBao: JWT auth trusts SPIRE's jwt-svid keys"
docker exec andyur-spire-server /opt/spire/bin/spire-server bundle show -format spiffe \
  >"$WORK/bundle.json" 2>/dev/null
PEMS="$("$HERE/.venv/bin/python" - "$WORK/bundle.json" <<'PY'
import json, base64, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
d = json.load(open(sys.argv[1]))
b = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
out=[]
for k in d.get("keys", []):
    if k.get("use") != "jwt-svid": continue
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b(k["x"]),"big"),
        int.from_bytes(b(k["y"]),"big"), ec.SECP256R1()).public_key()
    out.append(pub.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode())
print("\x1e".join(out))
PY
)"
[ -n "$PEMS" ] || { bad "no SPIRE jwt-svid keys"; exit 1; }
JWT_CONFIG="$("$HERE/.venv/bin/python" - "$PEMS" <<'PY'
import json,sys; print(json.dumps({"jwt_validation_pubkeys": sys.argv[1].split("\x1e"), "default_role":"andyur-service"}))
PY
)"
bao 'bao auth enable jwt 2>/dev/null; true' >/dev/null
printf '%s' "$JWT_CONFIG" | BAO_TOKEN="$ROOT" compose exec -T -e BAO_TOKEN openbao \
  sh -c 'bao write auth/jwt/config - >/dev/null' \
  && ok "OpenBao JWT auth trusts SPIRE's signing keys" || { bad "jwt config"; exit 1; }

say "3. least-privilege: a role bound to THIS run's SPIFFE id + audience"
bao 'echo "path \"secret/data/production/saas/+\" { capabilities = [\"read\"] }" | bao policy write andyur-saas-read -' >/dev/null
bao "bao write auth/jwt/role/andyur-service role_type=jwt user_claim=sub bound_subject='$SPIFFE_ID' bound_audiences='$AUD' token_policies=andyur-saas-read token_ttl=5m" >/dev/null \
  && ok "role bound to $SPIFFE_ID (aud=$AUD), saas-read only" || { bad "role"; exit 1; }

say "4. the operator seeds the SERVICE credential in the vault"
# The secret is a HEADER MAP, not one name/value pair: a vendor may need two
# headers (Datadog needs DD-API-KEY and DD-APPLICATION-KEY together). Which
# names are permitted is decided by the binding, not by this shape.
# `bao kv put k=v` stores a STRING. The secret's `headers` is a nested OBJECT,
# so the whole document goes in on stdin via `-`; writing it as k=v stores the
# literal text {"authorization":"..."} and the resolver correctly refuses it.
bao "printf '%s' '{\"headers\":{\"authorization\":\"$SVC_VALUE\"}}' | bao kv put secret/production/saas/$CRED_REF - >/dev/null" \
  && ok "service credential stored at secret/production/saas/$CRED_REF" || { bad "store"; exit 1; }

say "5. the upstream that REQUIRES the brokered header"
UP_VALUE="$SVC_VALUE" UP_PORT="$UP_PORT" "$HERE/.venv/bin/python" - <<'PY' >"$WORK/upstream.log" 2>&1 &
import os, http.server
WANT = os.environ["UP_VALUE"]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        got = self.headers.get("authorization", "")
        ok = got == WANT
        self.send_response(200 if ok else 401); self.end_headers()
        self.wfile.write(b"UPSTREAM-ACCEPTED" if ok else b"UPSTREAM-REFUSED")
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", int(os.environ["UP_PORT"])), H).serve_forever()
PY
UP_PID=$!
# This was an unconditional `ok` after `sleep 1`: it incremented PASS whether or
# not anything was listening, inflating the count the exit pin below checks.
for _ in $(seq 1 40); do port_held "$UP_PORT" && break; sleep 0.25; done
if port_held "$UP_PORT"; then
  ok "upstream up on :$UP_PORT (accepts only the exact brokered header)"
else
  bad "upstream never came up on :$UP_PORT"
fi

say "6. the RUN's docker-attested JWT-SVID (per-run, aud=$AUD)"
docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
  -parentID "spiffe://$TD/agent/node" -spiffeID "$SPIFFE_ID" \
  -selector "docker:label:andyur.run_id:$RUN_ID" -jwtSVIDTTL 300 >/dev/null 2>&1 || true
JWT=""
for _ in $(seq 1 15); do
  JWT="$(docker run --rm --network "$NET" --user 0 --label "andyur.run_id=$RUN_ID" \
    -v "$SOCK:/run/spire/sockets:ro" \
    --entrypoint /opt/spire/bin/spire-agent ghcr.io/spiffe/spire-agent:1.11.2 \
    api fetch jwt -audience "$AUD" -socketPath /run/spire/sockets/api.sock 2>&1 \
    | grep -oE '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1)"
  [ -n "$JWT" ] && break; sleep 2
done
[ -n "$JWT" ] && ok "per-run JWT-SVID fetched (sub=$SPIFFE_ID)" || { bad "no JWT-SVID"; exit 1; }

say "7. the run fetches the credential via credential_service + presents it upstream"
# The agent CONTAINER never receives the secret in its environment or argv: the
# JWT-SVID goes in, the brokered header is fetched over TLS INSIDE the container
# by andyur.credential_service, and presented to the upstream. The container is
# labelled + captured so the absence checks can inspect exactly what it held.
UP_FROM_CONTAINER="http://host.docker.internal:$UP_PORT"
# NO --rm. The absence checks in step 8 `docker inspect` this container BY NAME,
# and --rm deleted it the instant it exited: inspect then failed, `|| echo '[]'`
# swallowed the failure, and grep found nothing in `[]`. A container launched
# with the credential LITERALLY in its environment reported "absent" -- proven by
# running exactly that shape. cleanup() already does `docker rm -f` on this name,
# so the container is still removed; it just survives long enough to be examined.
run_out="$(docker run --name "andyur-svc-run-$RUN_ID" --network "$NET" \
  --label "andyur.run_id=$RUN_ID" --add-host host.docker.internal:host-gateway \
  -v "$ANDYUR_OPENBAO_TLS_DIR/ca.crt:/tmp/ca.crt:ro" \
  -e OB_JWT="$JWT" -e OB_ADDR="https://openbao:8200" -e UP="$UP_FROM_CONTAINER" \
  -e CRED_REF="$CRED_REF" \
  --entrypoint python andyur-runner -c '
import os, shutil, httpx
from andyur.credential_service import OpenBaoClient
ca="/home/runner/ca.crt"; shutil.copy("/tmp/ca.crt", ca); os.chmod(ca, 0o600)
jf="/home/runner/jwt.txt"; open(jf,"w").write(os.environ["OB_JWT"]); os.chmod(jf, 0o600)
# The `with` context manager exercises close() -> revoke-self (204) on exit,
# proving that path works against a REAL OpenBao (the empty-204 fix).
with OpenBaoClient(os.environ["OB_ADDR"], ca, "andyur-service") as c:
    c.login(jf)
    headers = c.read_service_headers(os.environ["CRED_REF"])
r = httpx.get(os.environ["UP"], headers=headers, timeout=5)
print(r.text.strip())
' 2>&1)"
if printf '%s' "$run_out" | grep -q "UPSTREAM-ACCEPTED"; then
  ok "upstream ACCEPTED the brokered credential the run fetched from the vault"
else
  bad "upstream did not accept"; printf '      --- run output ---\n%s\n' "$run_out" | tail -8
fi

say "8. the credential is ABSENT where the threat model forbids it"
# FAIL CLOSED. These two checks previously read `|| echo '[]'`, so a failed
# inspect became an empty haystack and reported "absent". Absence of evidence
# was being reported as evidence of absence, which is the whole defect.
if ! docker inspect "andyur-svc-run-$RUN_ID" >/dev/null 2>&1; then
  bad "cannot inspect andyur-svc-run-$RUN_ID; the ENV and ARGV checks are unproven"
else
  # (a) agent environment: the run container's env, as docker recorded it.
  env_dump="$(docker inspect "andyur-svc-run-$RUN_ID" --format '{{json .Config.Env}}')"
  printf '%s' "$env_dump" | grep -qF "$SVC_VALUE" \
    && bad "the service credential appears in the agent container ENV" \
    || ok "absent from the agent container environment"
  # (b) container argv: the docker run command line.
  argv_dump="$(docker inspect "andyur-svc-run-$RUN_ID" --format '{{json .Args}} {{json .Path}}')"
  printf '%s' "$argv_dump" | grep -qF "$SVC_VALUE" \
    && bad "the service credential appears in the container ARGV" \
    || ok "absent from the container argv"
fi

# POSITIVE CONTROL, the same idiom verify-pod-boundary.sh:268 already uses: the
# sweep must FIND a credential when one is deliberately planted, or it is a grep
# that can never fail. Without this the two checks above are green whether the
# credential is confined or merely invisible to a broken probe.
CANARY="svc-cred-planted-canary-$RUN_ID"
docker run -d --name "andyur-svc-canary-$RUN_ID" -e SVC_CRED="$CANARY" \
  --entrypoint sleep andyur-runner 20 >/dev/null 2>&1 || true
canary_env="$(docker inspect "andyur-svc-canary-$RUN_ID" --format '{{json .Config.Env}}' 2>/dev/null || echo '')"
printf '%s' "$canary_env" | grep -qF "$CANARY" \
  && ok "positive control: the ENV sweep does detect a planted credential" \
  || bad "the ENV sweep cannot detect even a planted credential -- it proves nothing"
docker rm -f "andyur-svc-canary-$RUN_ID" >/dev/null 2>&1 || true
# (c) transcript + (d) logs: everything the run wrote out, plus the upstream log.
LEAK=0
for f in "$WORK/upstream.log"; do
  [ -f "$f" ] && grep -qF "$SVC_VALUE" "$f" && LEAK=1
done
printf '%s' "$run_out" | grep -qF "$SVC_VALUE" && LEAK=1
[ "$LEAK" = 0 ] \
  && ok "absent from the run transcript/stdout and the logs" \
  || bad "the service credential leaked into a transcript or log"

# The count pin catches a check that stops running. It did NOT save the two
# broken checks above, because those INCREMENTED PASS -- the pin was satisfied
# BY the defect. It is still worth having, and it moves 10 -> 11 for the planted
# canary positive control added in step 8.
say "result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && [ "$PASS" -eq 11 ]

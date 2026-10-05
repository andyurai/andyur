#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
REF="$ROOT/infra/reference-as"
PYTHON=${PYTHON:-"$ROOT/.venv/bin/python"}
OUTPUT=${ANDYUR_ACTOR_PROOF_OUTPUT:-"$ROOT/infra/result-actor-proof-2026-08-14-macos-arm64.json"}
WORK=$(mktemp -d)
PORT=${ANDYUR_ACTOR_PROOF_PORT:-18443}
ISSUER="https://localhost:$PORT"
AUDIENCE="$ISSUER/token"
RESOURCE="https://resource.example/mcp"
RUN_ID="actor-proof-$$"
GOOD_ID="spiffe://andyur.local/agent/oncall/run/$RUN_ID"
WRONG_ID="spiffe://andyur.local/agent/oncall/run/$RUN_ID-wrong"
AS_PID=""
ENTRY_IDS="$WORK/entry-ids"
: >"$ENTRY_IDS"

run_bounded() {
  seconds=$1
  shift
  "$PYTHON" - "$seconds" "$@" <<'PY'
import os, signal, subprocess, sys, time
p = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    raise SystemExit(p.wait(timeout=float(sys.argv[1])))
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGTERM)
    try:
        p.wait(timeout=1)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=1)
    raise
PY
}

delete_entries() {
  while IFS= read -r entry_id; do
    [ -z "$entry_id" ] || run_bounded 10 docker exec andyur-spire-server \
      /opt/spire/bin/spire-server entry delete -entryID "$entry_id" >/dev/null
  done <"$ENTRY_IDS"
  : >"$ENTRY_IDS"
}

stop_as() {
  if [ -n "$AS_PID" ]; then
    kill "$AS_PID" 2>/dev/null || true
    deadline=$((SECONDS + 2))
    while kill -0 "$AS_PID" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
      sleep 0.05
    done
    if kill -0 "$AS_PID" 2>/dev/null; then
      kill -KILL "$AS_PID" 2>/dev/null || true
    fi
    wait "$AS_PID" 2>/dev/null || true
    AS_PID=""
  fi
}

delete_run_entries() {
  run_bounded 10 docker exec andyur-spire-server \
    /opt/spire/bin/spire-server entry show -output json >"$WORK/entries-cleanup.json"
  RUN_ID="$RUN_ID" "$PYTHON" - "$WORK/entries-cleanup.json" <<'PY' >"$WORK/fallback-entry-ids"
import json, os, sys
for entry in json.load(open(sys.argv[1])).get('entries', []):
    if os.environ['RUN_ID'] in json.dumps(entry, sort_keys=True):
        print(entry['id'])
PY
  while IFS= read -r entry_id; do
    [ -z "$entry_id" ] || run_bounded 10 docker exec andyur-spire-server \
      /opt/spire/bin/spire-server entry delete -entryID "$entry_id" >/dev/null
  done <"$WORK/fallback-entry-ids"
}

cleanup() {
  stop_as
  delete_entries 2>/dev/null || true
  delete_run_entries 2>/dev/null || true
  find "$WORK" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

command -v go >/dev/null
command -v docker >/dev/null
run_bounded 10 docker inspect andyur-spire-server >/dev/null
run_bounded 10 docker inspect andyur-spire-agent >/dev/null
if [ "$(run_bounded 10 docker inspect -f '{{.State.Running}}' andyur-spire-server)" != true ] || \
   [ "$(run_bounded 10 docker inspect -f '{{.State.Running}}' andyur-spire-agent)" != true ]; then
  echo "the containerized SPIRE stack must be running" >&2
  exit 1
fi
run_bounded 10 docker inspect -f '{{.Image}}' andyur-spire-server >"$WORK/spire-server-image-id"
run_bounded 10 docker inspect -f '{{.Image}}' andyur-spire-agent >"$WORK/spire-agent-image-id"
run_bounded 10 docker image inspect -f '{{.Id}}' ghcr.io/spiffe/spire-agent:1.11.2 \
  >"$WORK/spire-fetch-image-id"
if "$PYTHON" - "$PORT" <<'PY'
import socket, sys
with socket.socket() as s:
    raise SystemExit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
then
  echo "actor-proof port is already held: $PORT" >&2
  exit 1
fi

run_bounded 10 docker exec andyur-spire-server /opt/spire/bin/spire-server bundle show \
  -format spiffe >"$WORK/bundle.json"
run_bounded 10 openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost' -keyout "$WORK/tls.key" \
  -out "$WORK/tls.crt" >/dev/null 2>&1
mkdir -p "$WORK/data"
printf '%s\n' '{"dana":{"entitlements":["telemetry:read"],"resources":["mcp"]}}' \
  >"$WORK/data/users.json"
printf '%s\n' '{"oncall":{"actions":["telemetry:read"],"audiences":["https://resource.example/mcp"]}}' \
  >"$WORK/data/ceilings.json"

create_entry() {
  spiffe_id=$1
  label=$2
  ttl=$3
  created=$(run_bounded 10 docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
    -parentID spiffe://andyur.local/agent/node -spiffeID "$spiffe_id" \
    -selector "docker:label:andyur.actor_proof:$label" -jwtSVIDTTL "$ttl" -output json)
  CREATED="$created" "$PYTHON" - <<'PY' >>"$ENTRY_IDS"
import json, os
value=json.loads(os.environ['CREATED'])
entry=value['results'][0]['entry']
entry_id=entry.get('id')
assert isinstance(entry_id, str) and entry_id
print(entry_id)
PY
}

fetch_svid() {
  label=$1
  audience=$2
  target=$3
  for _ in $(seq 1 15); do
    raw=$(run_bounded 15 docker run --rm --network andyur-spire-net --user 0 \
      --label "andyur.actor_proof=$label" \
      -v andyur-spire-sockets:/run/spire/sockets:ro \
      --entrypoint /opt/spire/bin/spire-agent ghcr.io/spiffe/spire-agent:1.11.2 \
      api fetch jwt -audience "$audience" \
      -socketPath /run/spire/sockets/api.sock 2>&1 || true)
    token=$(RAW="$raw" "$PYTHON" - <<'PY'
import os, re
m = re.search(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', os.environ['RAW'])
print(m.group(0) if m else '')
PY
)
    if [ -n "$token" ]; then
      printf '%s' "$token" >"$target"
      return
    fi
    sleep 2
  done
  echo "failed to fetch JWT-SVID for $label" >&2
  exit 1
}

create_entry "$GOOD_ID" "$RUN_ID-good" 120
create_entry "$WRONG_ID" "$RUN_ID-wrong" 120
create_entry "spiffe://andyur.local/agent/oncall/run/$RUN_ID-long" "$RUN_ID-long" 600
fetch_svid "$RUN_ID-good" "$AUDIENCE" "$WORK/good.jwt"
fetch_svid "$RUN_ID-good" wrong-audience "$WORK/wrong-audience.jwt"
fetch_svid "$RUN_ID-wrong" "$AUDIENCE" "$WORK/wrong-actor.jwt"
fetch_svid "$RUN_ID-long" "$AUDIENCE" "$WORK/long.jwt"

"$PYTHON" - "$WORK/good.jwt" "$WORK/forged.jwt" <<'PY'
import base64, json, sys
source, target = sys.argv[1:]
parts = open(source).read().split('.')
claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
claims['sub'] = claims['sub']
payload = base64.urlsafe_b64encode(json.dumps(claims, separators=(',', ':')).encode()).rstrip(b'=').decode()
open(target, 'w').write(parts[0] + '.' + payload + '.' + parts[2][::-1])
PY

SUBJECT=$($PYTHON - <<'PY'
import base64, json
h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps({'sub':'dana'}).encode()).rstrip(b'=').decode()
print(h + '.' + p + '.')
PY
)

prepare_source() {
  profile=$1
  rm -rf "$WORK/src"
  cp -R "$REF" "$WORK/src"
  case "$profile" in
    secure) ;;
    no_signature)
      "$PYTHON" - "$WORK/src/main.go" <<'PY'
from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text()
old='jwtsvid.ParseAndValidate(token, v.bundle, []string{v.audience})'
new='jwtsvid.ParseInsecure(token, []string{v.audience})'
assert s.count(old) == 1
p.write_text(s.replace(old,new))
PY
      ;;
    wrong_audience)
      "$PYTHON" - "$WORK/src/main.go" <<'PY'
from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text()
old='[]string{v.audience}'
new='[]string{"wrong-audience"}'
assert s.count(old) == 1
p.write_text(s.replace(old,new))
PY
      ;;
    no_expected_id)
      "$PYTHON" - "$WORK/src/main.go" <<'PY'
from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text()
old='if svid.ID != v.expectedID {'
new='if false {'
assert s.count(old) == 1
p.write_text(s.replace(old,new))
PY
      ;;
    no_lifetime_ceiling)
      "$PYTHON" - "$WORK/src/main.go" <<'PY'
from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text()
old='if lifetime <= 0 || lifetime > v.maxLifetime {'
new='if lifetime <= 0 {'
assert s.count(old) == 1
p.write_text(s.replace(old,new))
PY
      ;;
    no_actor_token_type)
      "$PYTHON" - "$WORK/src/main.go" <<'PY'
from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text()
old='if req.ActorTokenType != goidc.TokenTypeIdentifierJWT {'
new='if false {'
assert s.count(old) == 1
p.write_text(s.replace(old,new))
PY
      ;;
    no_delegated_actor)
      "$PYTHON" - "$WORK/src/main.go" <<'PY'
from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text()
old='return goidc.TokenExchangeResult{Subject: sub, Actor: actor}, nil'
new='return goidc.TokenExchangeResult{Subject: sub}, nil'
assert s.count(old) == 1
p.write_text(s.replace(old,new))
PY
      ;;
    *) echo "unknown mutation profile: $profile" >&2; exit 1 ;;
  esac
  cp "$WORK/src/main.go" "$WORK/source-$profile.go"
  (cd "$WORK/src" && run_bounded 60 go build -trimpath -o "$WORK/refas-$profile" .)
}

start_as() {
  profile=$1
  expected_id=${2:-$GOOD_ID}
  stop_as
  ANDYUR_REFAS_ADDR=":$PORT" ANDYUR_REFAS_ISSUER="$ISSUER" \
  ANDYUR_REFAS_DATA="$WORK/data" ANDYUR_REFAS_ANDYUR_URL=https://andyur.invalid \
  ANDYUR_REFAS_RESOURCES="$RESOURCE" \
  ANDYUR_REFAS_TLS_CERT="$WORK/tls.crt" ANDYUR_REFAS_TLS_KEY="$WORK/tls.key" \
  ANDYUR_REFAS_ACTOR_SPIFFE_BUNDLE="$WORK/bundle.json" \
  ANDYUR_REFAS_ACTOR_AUDIENCE="$AUDIENCE" \
  ANDYUR_REFAS_ACTOR_EXPECTED_ID="$expected_id" \
  ANDYUR_REFAS_ACTOR_MAX_LIFETIME_SECONDS=180 \
    "$WORK/refas-$profile" >"$WORK/as-$profile.log" 2>&1 &
  AS_PID=$!
  for _ in $(seq 1 50); do
    if curl --silent --fail --connect-timeout 1 --max-time 2 --cacert "$WORK/tls.crt" \
      "$ISSUER/.well-known/openid-configuration" >/dev/null; then
      return
    fi
    if ! kill -0 "$AS_PID" 2>/dev/null; then
      cat "$WORK/as-$profile.log" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "reference AS did not become ready" >&2
  exit 1
}

exchange() {
  actor_file=$1
  result_file=$2
  actor_type=${3:-urn:ietf:params:oauth:token-type:jwt}
  curl --silent --show-error --connect-timeout 2 --max-time 8 --cacert "$WORK/tls.crt" \
    --output "$result_file.body" --write-out '%{http_code}' \
    -X POST "$AUDIENCE" -d client_id=client_one -d client_secret=gateway-secret \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d subject_token="$SUBJECT" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
    --data-urlencode "actor_token@$actor_file" -d actor_token_type="$actor_type" \
    -d resource="$RESOURCE" -d audience="$RESOURCE" -d scope=telemetry:read \
    >"$result_file.status"
}

assert_status() {
  result_file=$1
  expected=$2
  actual=$(cat "$result_file.status")
  if [ "$actual" != "$expected" ]; then
    echo "status $actual, want $expected: $(cat "$result_file.body")" >&2
    if [ -f "$WORK/as-secure.log" ]; then
      tail -20 "$WORK/as-secure.log" >&2
    fi
    exit 1
  fi
}

assert_delegated_output() {
  EXPECTED_ACTOR="$GOOD_ID" "$PYTHON" - "$1" <<'PY'
import base64, json, os, sys
response=json.load(open(sys.argv[1]))
token=response.get('access_token','')
parts=token.split('.')
assert len(parts) == 3
claims=json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
assert claims.get('sub') == 'dana', claims
assert (claims.get('act') or {}).get('sub') == os.environ['EXPECTED_ACTOR'], claims
PY
}

prepare_source secure
start_as secure
exchange "$WORK/good.jwt" "$WORK/secure-good"
assert_status "$WORK/secure-good" 200
exchange "$WORK/forged.jwt" "$WORK/secure-forged"
assert_status "$WORK/secure-forged" 400
exchange "$WORK/wrong-audience.jwt" "$WORK/secure-audience"
assert_status "$WORK/secure-audience" 400
exchange "$WORK/wrong-actor.jwt" "$WORK/secure-actor"
assert_status "$WORK/secure-actor" 400
start_as secure "spiffe://andyur.local/agent/oncall/run/$RUN_ID-long"
exchange "$WORK/long.jwt" "$WORK/secure-lifetime"
assert_status "$WORK/secure-lifetime" 400
start_as secure
exchange "$WORK/good.jwt" "$WORK/secure-token-type" \
  urn:ietf:params:oauth:token-type:access_token
assert_status "$WORK/secure-token-type" 400

for profile in no_signature wrong_audience no_expected_id no_lifetime_ceiling no_actor_token_type no_delegated_actor; do
  prepare_source "$profile"
  if [ "$profile" = no_lifetime_ceiling ]; then
    start_as "$profile" "spiffe://andyur.local/agent/oncall/run/$RUN_ID-long"
  else
    start_as "$profile"
  fi
  case "$profile" in
    no_signature) token="$WORK/forged.jwt" ;;
    wrong_audience) token="$WORK/wrong-audience.jwt" ;;
    no_expected_id) token="$WORK/wrong-actor.jwt" ;;
    no_lifetime_ceiling) token="$WORK/long.jwt" ;;
    no_actor_token_type) token="$WORK/good.jwt" ;;
    no_delegated_actor) token="$WORK/good.jwt" ;;
  esac
  if [ "$profile" = no_actor_token_type ]; then
    exchange "$token" "$WORK/red-$profile" urn:ietf:params:oauth:token-type:access_token
  else
    exchange "$token" "$WORK/red-$profile"
  fi
  assert_status "$WORK/red-$profile" 200
  if [ "$profile" = no_delegated_actor ]; then
    if assert_delegated_output "$WORK/red-$profile.body" 2>/dev/null; then
      echo "delegated-output mutation did not turn the claim assertion red" >&2
      exit 1
    fi
    printf 'red\n' >"$WORK/delegated-output-mutation.result"
  fi
done

start_as secure
exchange "$WORK/good.jwt" "$WORK/restored-good"
assert_status "$WORK/restored-good" 200
exchange "$WORK/forged.jwt" "$WORK/restored-forged"
assert_status "$WORK/restored-forged" 400
exchange "$WORK/wrong-audience.jwt" "$WORK/restored-audience"
assert_status "$WORK/restored-audience" 400
exchange "$WORK/wrong-actor.jwt" "$WORK/restored-actor"
assert_status "$WORK/restored-actor" 400
start_as secure "spiffe://andyur.local/agent/oncall/run/$RUN_ID-long"
exchange "$WORK/long.jwt" "$WORK/restored-lifetime"
assert_status "$WORK/restored-lifetime" 400
start_as secure
exchange "$WORK/good.jwt" "$WORK/restored-token-type" \
  urn:ietf:params:oauth:token-type:access_token
assert_status "$WORK/restored-token-type" 400
stop_as

assert_delegated_output "$WORK/restored-good.body"
printf 'green\n' >"$WORK/delegated-output-restored.result"
delete_entries
delete_run_entries
if "$PYTHON" - "$PORT" <<'PY'
import socket, sys
with socket.socket() as s:
    raise SystemExit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
then
  echo "reference AS listener survived teardown" >&2
  exit 1
fi
run_bounded 10 docker exec andyur-spire-server /opt/spire/bin/spire-server entry show \
  -output json >"$WORK/entries-after.json"
RUN_ID="$RUN_ID" "$PYTHON" - "$WORK/entries-after.json" <<'PY'
import json, os, sys
entries=json.load(open(sys.argv[1])).get('entries', [])
needle=os.environ['RUN_ID']
assert not any(needle in json.dumps(entry, sort_keys=True) for entry in entries)
PY

RUN_ID="$RUN_ID" GOOD_ID="$GOOD_ID" ISSUER="$ISSUER" AUDIENCE="$AUDIENCE" \
RESOURCE="$RESOURCE" "$PYTHON" - "$WORK/spire-server-image-id" \
  "$WORK/spire-agent-image-id" "$WORK/spire-fetch-image-id" \
  "$WORK/effective-config.json" <<'PY'
import json, os, sys
server_image, agent_image, fetch_image, output = sys.argv[1:]
config = {
    'schema': 'andyur.actor-proof.effective-config.v1',
    'run_id': os.environ['RUN_ID'],
    'expected_actor_id': os.environ['GOOD_ID'],
    'issuer': os.environ['ISSUER'],
    'actor_audience': os.environ['AUDIENCE'],
    'resource': os.environ['RESOURCE'],
    'actor_max_original_lifetime_seconds': 180,
    'reference_as_component': 'github.com/luikyv/go-oidc@v0.25.0',
    'jwt_svid_component': 'github.com/spiffe/go-spiffe/v2@v2.8.1',
    'spire_server_image_id': open(server_image).read().strip(),
    'spire_agent_image_id': open(agent_image).read().strip(),
    'spire_fetch_image': 'ghcr.io/spiffe/spire-agent:1.11.2',
    'spire_fetch_image_id': open(fetch_image).read().strip(),
    'transport': 'locally-trusted-https',
}
open(output, 'w').write(json.dumps(config, indent=2, sort_keys=True) + '\n')
PY

"$PYTHON" - "$REF/main.go" "$REF/main_test.go" "$REF/go.mod" "$REF/go.sum" "$0" \
  "$WORK/bundle.json" "$WORK" "$OUTPUT" <<'PY'
import hashlib, json, os, platform, sys
main, main_test, gomod, gosum, verifier, bundle, work, output = map(__import__('pathlib').Path, sys.argv[1:])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
status = lambda name: int((work / (name + '.status')).read_text())
schema = {
  'name': 'andyur.actor-proof.evidence',
  'version': 1,
  'required_top_level': ['status', 'scope', 'component', 'observed', 'effective_config', 'evidence_inputs', 'remaining'],
}
mutation_profiles = ['no_signature', 'wrong_audience', 'no_expected_id', 'no_lifetime_ceiling', 'no_actor_token_type', 'no_delegated_actor']
observed = {
  'docker_attested_positive': status('secure-good'),
  'forged_signature_denied': status('secure-forged'),
  'wrong_audience_denied': status('secure-audience'),
  'wrong_sealed_actor_denied': status('secure-actor'),
  'overlong_lifetime_denied': status('secure-lifetime'),
  'wrong_actor_token_type_denied': status('secure-token-type'),
  'signature_mutation_red': status('red-no_signature'),
  'audience_mutation_red': status('red-wrong_audience'),
  'sealed_actor_mutation_red': status('red-no_expected_id'),
  'lifetime_mutation_red': status('red-no_lifetime_ceiling'),
  'actor_token_type_mutation_red': status('red-no_actor_token_type'),
  'delegated_output_http_control': status('red-no_delegated_actor'),
  'delegated_output_mutation_assertion': (work / 'delegated-output-mutation.result').read_text().strip(),
  'restored_positive': status('restored-good'),
  'restored_negative_statuses': [status(name) for name in (
    'restored-forged', 'restored-audience', 'restored-actor',
    'restored-lifetime', 'restored-token-type')],
  'delegated_output_restored_assertion': (work / 'delegated-output-restored.result').read_text().strip(),
  'bounded_process_listener_and_registration_teardown': True,
}
assert {name: observed[name] for name in (
  'docker_attested_positive', 'forged_signature_denied',
  'wrong_audience_denied', 'wrong_sealed_actor_denied',
  'overlong_lifetime_denied', 'wrong_actor_token_type_denied')
} == {
  'docker_attested_positive': 200, 'forged_signature_denied': 400,
  'wrong_audience_denied': 400, 'wrong_sealed_actor_denied': 400,
  'overlong_lifetime_denied': 400, 'wrong_actor_token_type_denied': 400,
}
assert {name: observed[name] for name in (
  'signature_mutation_red', 'audience_mutation_red',
  'sealed_actor_mutation_red', 'lifetime_mutation_red',
  'actor_token_type_mutation_red')
} == {
  'signature_mutation_red': 200, 'audience_mutation_red': 200,
  'sealed_actor_mutation_red': 200, 'lifetime_mutation_red': 200,
  'actor_token_type_mutation_red': 200,
}
assert observed['delegated_output_http_control'] == 200
assert observed['delegated_output_mutation_assertion'] == 'red'
assert observed['restored_positive'] == 200
assert observed['restored_negative_statuses'] == [400] * 5
assert observed['delegated_output_restored_assertion'] == 'green'
config = json.loads((work / 'effective-config.json').read_text())
result = {
  'status': 'pass',
  'scope': 'disposable-spire-jwt-svid-actor-proof',
  'component': 'github.com/spiffe/go-spiffe/v2@v2.8.1',
  'actor_token_type': 'urn:ietf:params:oauth:token-type:jwt',
  'transport': config['transport'],
  'evidence_schema': schema,
  'evidence_schema_sha256': hashlib.sha256(json.dumps(schema, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
  'effective_config': config,
  'effective_config_sha256': sha(work / 'effective-config.json'),
  'observed': observed,
  'evidence_inputs': {
    'reference_as_main_sha256': sha(main),
    'reference_as_test_sha256': sha(main_test),
    'go_mod_sha256': sha(gomod),
    'go_sum_sha256': sha(gosum),
    'verifier_sha256': sha(verifier),
    'spire_bundle_sha256': sha(bundle),
    'secure_binary_sha256': sha(work / 'refas-secure'),
    'mutation_binary_sha256': {p: sha(work / ('refas-' + p)) for p in mutation_profiles},
    'mutation_source_sha256': {p: sha(work / ('source-' + p + '.go')) for p in mutation_profiles},
  },
  'platform': platform.platform(),
  'remaining': [
    'named_enterprise_tenant_actor_token_acceptance',
    'production_sealed_run_binding_delivery',
    'agent_socket_and_filesystem_exclusion_in_pod',
    'bundle_rotation_and_mid_request_behavior',
    'revocation_window_and_actor_token_replay_semantics',
  ],
}
target = output.resolve(); target.parent.mkdir(parents=True, exist_ok=True)
tmp = target.with_name(target.name + f'.{os.getpid()}.tmp')
tmp.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
os.replace(tmp, target)
print(json.dumps(result, sort_keys=True))
PY

shasum -a 256 "$OUTPUT"
echo "PASS: disposable SPIRE JWT-SVID actor proof; production broker and Pod remain STOP"

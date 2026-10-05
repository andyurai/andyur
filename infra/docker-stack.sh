#!/usr/bin/env bash
# Supported single-host Docker deployment for Andyur.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$HERE/infra/docker-compose.yml"
SPIRE="$HERE/infra/spire/docker/verify-slice3.sh"
ENV_FILE="$HERE/data/docker.env"
RUN_NETWORK="andyur-runs"
TD="${ANDYUR_TRUST_DOMAIN:-andyur.local}"

# One consolidated EXIT trap: bash keeps only the LAST trap per signal, so the
# lock release and the admin-token cleanup must live in one handler or whichever
# is armed second silently disarms the first.
ADMIN_HDR=""
_on_exit() {
  [ -n "${_ENV_LOCK_HELD:-}" ] && rmdir "$ENV_FILE.lock" 2>/dev/null
  [ -n "$ADMIN_HDR" ] && rm -f "$ADMIN_HDR" 2>/dev/null
  true
}
trap _on_exit EXIT
# INT/TERM do not fire the EXIT trap on their own; route them through exit so
# the lock and the token header file are cleaned on Ctrl-C too
trap 'exit 130' INT
trap 'exit 143' TERM

compose() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" --profile andyur "$@"
}

compose_idp() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" --profile idp "$@"
}

idp_port() {
  # The default is stated once, by write_env materializing ANDYUR_IDP_PORT into
  # the env file; a shell-exported override wins, matching compose interpolation
  # precedence (OS env over --env-file).
  port="$(grep '^ANDYUR_IDP_PORT=' "$ENV_FILE" | tail -1 | cut -d= -f2)"
  echo "${ANDYUR_IDP_PORT:-$port}"
}

# --- IdP admin over REST on the loopback publish. NOT kcadm/docker exec: any
# secret passed as a CLI flag lands on host argv, readable via ps for the life
# of the call -- and on native Linux, host ps sees container processes too, so
# running kcadm inside the container does not help. Here the admin password and
# every provisioned secret travel via stdin or a request body; the short-lived
# bearer token's only rest is a 0600 header file removed by the shared trap.
idp_admin_login() {
  admin_user="$(grep '^ANDYUR_IDP_ADMIN_USER=' "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
  admin_pw="$(grep '^ANDYUR_IDP_ADMIN_PASSWORD=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
  ADM_BASE="http://127.0.0.1:$(idp_port)"
  tok="$(printf '%s' "$admin_pw" | curl -sf \
    -d grant_type=password -d client_id=admin-cli \
    -d "username=${admin_user:-admin}" --data-urlencode "password@-" \
    "$ADM_BASE/realms/master/protocol/openid-connect/token" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null)"
  [ -n "$tok" ] || return 1
  umask 077
  ADMIN_HDR="$HERE/data/.idp-admin-hdr.$$"
  printf 'Authorization: Bearer %s\n' "$tok" > "$ADMIN_HDR"
}

admrest() {
  # METHOD PATH [stdin: JSON body for non-GET/DELETE]. Prints the response
  # body; the HTTP status lands in ADM_CODE. Re-authenticates once on 401
  # (the master admin token lives ~60s and an interactive password prompt can
  # outlast it). CONSTRAINT: ADM_CODE is only meaningful when admrest runs in
  # the CURRENT shell -- a $(admrest ...) capture runs in a subshell and the
  # variable dies there, so capture-callers must validate the BODY they
  # captured (structural JSON parse, fail closed) and never read ADM_CODE.
  m="$1"; p="$2"
  body="$([ "$m" = GET ] || [ "$m" = DELETE ] || cat)"
  for _ in 1 2; do
    if [ "$m" = GET ] || [ "$m" = DELETE ]; then
      out="$(curl -s -w '\n%{http_code}' -X "$m" -H @"$ADMIN_HDR" \
        "$ADM_BASE/admin/realms/andyur$p")"
    else
      out="$(printf '%s' "$body" | curl -s -w '\n%{http_code}' -X "$m" \
        -H @"$ADMIN_HDR" -H 'Content-Type: application/json' \
        --data-binary @- "$ADM_BASE/admin/realms/andyur$p")"
    fi
    ADM_CODE="${out##*$'\n'}"
    [ "$ADM_CODE" != 401 ] && break
    idp_admin_login || break
  done
  printf '%s' "${out%$'\n'*}"
}

env_lock() {
  lock="$ENV_FILE.lock"
  acquired=""
  for _ in $(seq 1 100); do
    if mkdir "$lock" 2>/dev/null; then acquired=1; break; fi
    sleep 0.1
  done
  [ -n "$acquired" ] || {
    echo "another invocation holds $lock; if none is running, remove it" >&2
    exit 1
  }
  # Release-once via the shared _on_exit trap: it removes the lock ONLY while
  # THIS invocation still owns it (a long-running command's exit must not
  # rmdir a lock a concurrent invocation has since acquired) and covers a
  # set -e abort inside the critical section. Cleared by env_unlock.
  _ENV_LOCK_HELD=1
}

env_unlock() {
  _ENV_LOCK_HELD=""
  rmdir "$ENV_FILE.lock" 2>/dev/null || true
}

env_file_put() {
  # Replace-or-append KEY=VALUE atomically by rename, mode 0600 -- under the
  # SAME lock as write_env: an unlocked rename here would clobber a concurrent
  # invocation's append (rename-vs-append lost update), the exact multi-writer
  # race the lock exists to close.
  env_lock
  umask 077
  tmp="$ENV_FILE.tmp.$$"
  grep -v "^$1=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
  env_unlock
}

rotate_demo_agent_secret() {
  # The committed demo realm carries a PUBLIC secret for the CONFIDENTIAL
  # andyur-agent client, with token exchange enabled. That is deliberate for
  # the throwaway harnesses, which import the realm into disposable containers
  # -- and a category error for this persistent reference deployment, where a
  # confidential client's whole security model is that its secret is secret.
  # The realm file stays static (the harnesses depend on it); THIS deployment
  # rotates the secret live on first up, idempotently (only while the
  # committed default is still in place), and stores the generated value for
  # anyone driving the token-exchange walkthrough against the reference.
  cid="$(admrest GET "/clients?clientId=andyur-agent" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["id"] if r else "")')"
  [ -n "$cid" ] || { echo "andyur-agent client missing from the realm" >&2; exit 1; }
  current="$(admrest GET "/clients/$cid/client-secret" \
    | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    # a valid-JSON error body without "value" (client vanished between the
    # two GETs) must be ERR too, or rotation would silently skip
    print(d["value"] if "value" in d else "ERR")
except Exception:
    print("ERR")')"
  [ "$current" != "ERR" ] || { echo "cannot read the andyur-agent client secret; refusing to leave the committed value unverified" >&2; exit 1; }
  if [ "$current" = "agent-secret" ]; then
    new="$(openssl rand -hex 16)"
    # Persist BEFORE the authoritative realm write: a crash between the two
    # then leaves the realm on the committed value, and the next up simply
    # rotates again -- whereas realm-first would strand a secret that lived
    # only in this process, with the idempotency guard skipping forever.
    env_file_put ANDYUR_IDP_AGENT_CLIENT_SECRET "$new"
    admrest PUT "/clients/$cid" >/dev/null <<JSON
{"secret": "$new"}
JSON
    [ "$ADM_CODE" = 204 ] || { echo "agent-secret rotation failed ($ADM_CODE)" >&2; exit 1; }
    echo "rotated the committed andyur-agent demo secret; the generated value is ANDYUR_IDP_AGENT_CLIENT_SECRET in $ENV_FILE"
  fi
}

ropc_code() { # user pw issuer -> HTTP status of a demo-realm password login
  # password via STDIN (curl name@- form): a --data-urlencode value would sit
  # on host argv for the life of the call
  printf '%s' "$2" | curl -s -o /dev/null -w '%{http_code}' \
    -d grant_type=password -d client_id=andyur-cli -d "username=$1" \
    --data-urlencode "password@-" "$3/protocol/openid-connect/token"
}

fixture_probe() { # user issuer -> fixture|gone, nonzero on indeterminate
  # The "committed creds are dead" property must FAIL CLOSED: a transient
  # non-200 (endpoint warming, port blip) must never be read as "fixture
  # already gone" -- that would silently leave the committed public password
  # alive. 200 = fixture lives; an explicit refusal = committed credential
  # dead; anything else is retried, then aborts the setup.
  code=""
  for _ in 1 2 3 4 5; do
    code="$(ropc_code "$1" "$1-password" "$2")"
    case "$code" in
      200) echo fixture; return 0 ;;
      400|401) echo gone; return 0 ;;
      *) sleep 1 ;;
    esac
  done
  echo "cannot determine whether the committed '$1' fixture is live (last status $code)" >&2
  return 1
}

set_user_password() { # uid pw -- body via stdin, JSON-escaped, never on argv
  pj="$(printf '%s' "$2" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
  admrest PUT "/users/$1/reset-password" >/dev/null <<JSON
{"type": "password", "value": $pj, "temporary": false}
JSON
  [ "$ADM_CODE" = 204 ] || { echo "setting a demo user password failed ($ADM_CODE)" >&2; exit 1; }
}

ensure_carol_admin_role() { # uid -- idempotent; sets ROLE_ATTACHED=1 if it acted
  ROLE_ATTACHED=""
  roles="$(admrest GET "/users/$1/role-mappings/realm" \
    | python3 -c 'import json,sys; print(" ".join(r["name"] for r in json.load(sys.stdin)))' 2>/dev/null)"
  case " $roles " in *" andyur-admin "*) return 0 ;; esac
  role_json="$(admrest GET "/roles/andyur-admin" | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
    print(json.dumps({"id": r["id"], "name": r["name"]}))
except Exception:
    pass' 2>/dev/null)"
  [ -n "$role_json" ] || { echo "andyur-admin role missing from the realm" >&2; exit 1; }
  admrest POST "/users/$1/role-mappings/realm" >/dev/null <<JSON
[$role_json]
JSON
  [ "$ADM_CODE" = 204 ] || { echo "attaching andyur-admin to carol failed ($ADM_CODE)" >&2; exit 1; }
  ROLE_ATTACHED=1
}

demo_user_id() { # username -> id or empty
  admrest GET "/users?username=$1&exact=true" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["id"] if r else "")' 2>/dev/null
}

create_demo_users() {
  # Demo users are CREATED at setup, on the fly. The committed realm ships
  # alice/bob/carol only as bootstrap fixtures for the throwaway harnesses
  # (which import it into disposable containers); on this persistent
  # reference deployment each fixture -- detected fail-closed by its
  # committed password still authenticating -- is deleted and replaced with a
  # freshly created user: new random Keycloak id, password asked at the
  # terminal (empty = generate) or generated non-interactively. The
  # andyur-demo GROUP marker is applied ATOMICALLY in the create request (an
  # attribute marker is silently dropped: KC 24+ rejects unmanaged
  # attributes; and firstName/lastName are REQUIRED by the default user
  # profile or every login fails "Account is not fully set up"). Marked users
  # self-heal on re-up -- stored password re-applied, carol's admin role
  # re-attached -- while an unmarked user is operator-owned and never
  # touched. Env records persist before every authoritative realm write.
  # NOTE: concurrent `idp up` is unsupported -- the mkdir lock serializes
  # docker.env, not Keycloak state.
  issuer="$1"
  changed=""
  admrest POST "/groups" >/dev/null <<'JSON'
{"name": "andyur-demo"}
JSON
  case "$ADM_CODE" in 201|409) ;; *) echo "ensuring the andyur-demo marker group failed ($ADM_CODE)" >&2; exit 1 ;; esac
  for user in alice bob carol; do
    key="ANDYUR_IDP_PASSWORD_$(printf '%s' "$user" | tr '[:lower:]' '[:upper:]')"
    stored="$(grep "^$key=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
    uid="$(demo_user_id "$user")"
    if [ -n "$uid" ]; then
      state="$(fixture_probe "$user" "$issuer")" || exit 1
      if [ "$state" = fixture ]; then
        admrest DELETE "/users/$uid" >/dev/null   # the bootstrap fixture goes
        [ "$ADM_CODE" = 204 ] || { echo "deleting the '$user' fixture failed ($ADM_CODE)" >&2; exit 1; }
        uid=""
      fi
    fi
    if [ -n "$uid" ]; then
      marked="$(admrest GET "/users/$uid/groups" | python3 -c '
import json, sys
try:
    print("yes" if any(g.get("name") == "andyur-demo" for g in json.load(sys.stdin)) else "no")
except Exception:
    print("err")')"
      [ "$marked" != "err" ] || { echo "cannot read '$user' group marker; refusing to guess ownership" >&2; exit 1; }
      if [ "$marked" != "yes" ]; then
        if [ -n "$stored" ] && [ "$(ropc_code "$user" "$stored" "$issuer")" != 200 ]; then
          echo "WARNING: demo user '$user' exists unmarked and neither the" >&2
          echo "committed nor the stored ANDYUR_IDP password authenticates;" >&2
          echo "if it is not your own user, './run.sh idp reset' rebuilds it" >&2
        fi
        continue   # operator-owned: hands off
      fi
      # ours: heal covers the WHOLE provisioned state, not just the password
      if [ "$user" = carol ]; then
        ensure_carol_admin_role "$uid"
        [ -z "$ROLE_ATTACHED" ] || changed="$changed carol(role-healed)"
      fi
      if [ -n "$stored" ] && [ "$(ropc_code "$user" "$stored" "$issuer")" = 200 ]; then
        continue
      fi
      if [ -n "$stored" ]; then
        set_user_password "$uid" "$stored"
        changed="$changed $user(healed)"
        continue
      fi
      admrest DELETE "/users/$uid" >/dev/null   # marked but no record: redo
      [ "$ADM_CODE" = 204 ] || { echo "recreating half-made '$user' failed ($ADM_CODE)" >&2; exit 1; }
    fi
    pw="$stored"
    if [ -z "$pw" ] && [ -t 0 ]; then
      printf "Password for demo user %s (empty = generate): " "$user"
      IFS= read -rs pw
      echo
    fi
    [ -n "$pw" ] || pw="$(openssl rand -hex 12)"
    env_file_put "$key" "$pw"
    cap="$(printf '%s' "$user" | cut -c1 | tr '[:lower:]' '[:upper:]')$(printf '%s' "$user" | cut -c2-)"
    admrest POST "/users" >/dev/null <<JSON
{"username": "$user", "enabled": true, "email": "$user@andyur.test",
 "emailVerified": true, "firstName": "$cap", "lastName": "Demo",
 "groups": ["/andyur-demo"]}
JSON
    case "$ADM_CODE" in
      201) ;;
      409) echo "demo user '$user' already exists though the lookup missed it" >&2
           echo "(transient blip?); re-run './run.sh idp up' to heal" >&2; exit 1 ;;
      *) echo "creating demo user '$user' failed ($ADM_CODE)" >&2; exit 1 ;;
    esac
    uid="$(demo_user_id "$user")"
    [ -n "$uid" ] || { echo "created demo user '$user' not found" >&2; exit 1; }
    # assert the atomic marker actually applied (a groups list a future KC
    # ignores would silently disable every self-heal)
    marked="$(admrest GET "/users/$uid/groups" | python3 -c '
import json, sys
try:
    print("yes" if any(g.get("name") == "andyur-demo" for g in json.load(sys.stdin)) else "no")
except Exception:
    print("err")')"
    [ "$marked" = "yes" ] || { echo "andyur-demo marker did not apply to '$user' (got: $marked)" >&2; exit 1; }
    set_user_password "$uid" "$pw"
    if [ "$user" = carol ]; then
      ensure_carol_admin_role "$uid"
    fi
    # the created user must actually be able to log in NOW: a silently
    # incomplete account (the exact user-profile class dodged above) must
    # fail the setup, not the first real login later
    login_ok=""
    for _ in 1 2 3; do
      [ "$(ropc_code "$user" "$pw" "$issuer")" = 200 ] && { login_ok=1; break; }
      sleep 1
    done
    [ -n "$login_ok" ] || { echo "created demo user '$user' cannot log in" >&2; exit 1; }
    changed="$changed $user"
  done
  [ -z "$changed" ] || echo "demo users created at setup:$changed (passwords stored as ANDYUR_IDP_PASSWORD_* in $ENV_FILE)"
}

refresh_control_plane() {
  # Recreate the control plane only when it is running, so wiring can also be
  # done before the first docker-up; compose recreates on env-file change.
  # NOTE the recreate reuses the existing image: when the server is crash-
  # looping because the IMAGE is broken (not the env), only docker-up's
  # rebuild can help, and this refresh will honestly fail -- callers that
  # have a rebuild coming (ci-docker-smoke.sh) tolerate that; operators get
  # the failure, which is the truth.
  if [ "$(docker inspect -f '{{.State.Running}}' andyur-server 2>/dev/null)" = "true" ]; then
    compose up -d andyur-server andyur-worker
    for _ in $(seq 1 60); do
      [ "$(docker inspect -f '{{.State.Health.Status}}' andyur-server 2>/dev/null)" = "healthy" ] && break
      sleep 1
    done
    [ "$(docker inspect -f '{{.State.Health.Status}}' andyur-server 2>/dev/null)" = "healthy" ] \
      || { echo "andyur-server did not become healthy after reconfiguration" >&2; exit 1; }
    echo "control plane reconfigured"
  else
    echo "(control plane not running; it will pick the wiring up on docker-up)"
  fi
}

idp_wire() {
  # One-command wiring of the dockerized control plane to the reference IdP:
  # materializes the exact lines idp_up used to ask the operator to paste,
  # computed from the same single sources (idp_port; the fixed in-network
  # JWKS path), then recreates the server so it picks them up. None of these
  # values is a secret, so argv/env custody is not a concern here.
  require_docker
  write_env
  port="$(idp_port)"
  issuer="http://127.0.0.1:$port/realms/andyur"
  env_file_put ANDYUR_USER_AUTH on
  env_file_put ANDYUR_OIDC_ISSUER "$issuer"
  env_file_put ANDYUR_OIDC_JWKS "http://keycloak:8080/realms/andyur/protocol/openid-connect/certs"
  env_file_put ANDYUR_OIDC_AUDIENCE andyur
  env_file_put ANDYUR_ADMIN_ROLE andyur-admin
  echo "user-auth wired to $issuer in $ENV_FILE"
  refresh_control_plane
}

idp_unwire() {
  require_docker
  write_env
  env_lock
  umask 077
  tmp="$ENV_FILE.tmp.$$"
  grep -Ev '^ANDYUR_USER_AUTH=|^ANDYUR_OIDC_ISSUER=|^ANDYUR_OIDC_JWKS=|^ANDYUR_OIDC_AUDIENCE=|^ANDYUR_ADMIN_ROLE=' \
    "$ENV_FILE" > "$tmp" || true
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
  env_unlock
  echo "user-auth unwired (absent keys fall back to off/empty defaults)"
  echo "NOTE: the compose pins ANDYUR_PROFILE=prod, which requires user-auth;"
  echo "an unwired control plane will refuse to boot until 'idp wire' runs again."
  refresh_control_plane
}

idp_up() {
  require_docker
  write_env
  compose_idp up -d keycloak keycloak-db
  port="$(idp_port)"
  issuer="http://127.0.0.1:$port/realms/andyur"
  # The server's issuer is a separately-set fact; if the port moved after it
  # was wired, every login 401s with "Invalid issuer" and nothing names the
  # cause -- so name it here, at the moment the drift is created.
  wired="$(grep '^ANDYUR_OIDC_ISSUER=' "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
  if [ -n "$wired" ] && [ "$wired" != "$issuer" ]; then
    {
      echo "WARNING: $ENV_FILE wires ANDYUR_OIDC_ISSUER=$wired"
      echo "         but this IdP now issues as $issuer -- logins will fail with"
      echo "         'Invalid issuer' until the two agree."
    } >&2
  fi
  echo "waiting for OIDC discovery at $issuer (imports the realm on first boot)"
  for _ in $(seq 1 120); do
    curl -sf "$issuer/.well-known/openid-configuration" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -sf "$issuer/.well-known/openid-configuration" >/dev/null || {
    echo "the IdP did not become ready; last log lines:" >&2
    docker logs andyur-keycloak 2>&1 | tail -15 >&2
    # Capture-then-match: `docker logs | grep -qi` false-negatives under
    # pipefail (grep exits at the first match, docker dies of SIGPIPE), which
    # here would silently SKIP this hint. nocasematch preserves grep -i.
    kc_logs="$(docker logs andyur-keycloak 2>&1 || true)"
    shopt -s nocasematch
    case "$kc_logs" in
      *"password authentication failed"*) kc_pwfail=1 ;;
      *) kc_pwfail=0 ;;
    esac
    shopt -u nocasematch
    if [ "$kc_pwfail" = 1 ]; then
      echo "HINT: ANDYUR_IDP_DB_PASSWORD in $ENV_FILE does not match the" >&2
      echo "andyur-idp-db volume (rotated without a reset?). './run.sh idp reset'" >&2
      echo "wipes the volume so the next up re-initializes with the current value." >&2
    fi
    exit 1
  }
  idp_admin_login || {
    echo "cannot authenticate to the IdP admin API for demo setup; refusing" >&2
    echo "to leave the committed bootstrap credentials in place" >&2
    exit 1
  }
  rotate_demo_agent_secret
  create_demo_users "$issuer"
  # Committed credentials are dead after setup (agent secret rotated, fixture
  # users replaced), but the realm itself stays demo-grade: say so at the
  # exact moment someone wires real user-auth against it.
  if grep -q '^ANDYUR_USER_AUTH=on' "$ENV_FILE" 2>/dev/null \
     && grep -qxF "ANDYUR_OIDC_ISSUER=$issuer" "$ENV_FILE"; then
    {
      echo "NOTE: user-auth is wired against the bundled demo realm (demo users"
      echo "created at setup; ROPC stays enabled on the andyur-cli test client)."
      echo "Replace it with your own realm/IdP for real use."
    } >&2
  fi
  echo
  echo "Reference IdP ready. Issuer: $issuer"
  echo "Admin console: http://127.0.0.1:$port  (user 'admin'; password = ANDYUR_IDP_ADMIN_PASSWORD in $ENV_FILE)"
  echo "Demo realm 'andyur': users alice/bob/carol created at setup (carol is"
  echo "andyur-admin); their passwords are ANDYUR_IDP_PASSWORD_* in $ENV_FILE"
  echo
  echo "To point the Dockerized control plane at it: ./run.sh idp wire"
  echo "(writes the ANDYUR_OIDC_* lines into $ENV_FILE and reconfigures a"
  echo "running server; 'idp unwire' reverts. A NATIVE server instead uses"
  echo "the issuer URL itself as the JWKS base -- see .env.example)"
}

idp_down() {
  require_docker
  write_env
  # Scoped teardown: only the idp services and the idp-only network, so a
  # running andyur/jaeger tier is untouched. State stays in andyur-idp-db.
  compose_idp rm -sf keycloak keycloak-db
  docker network rm andyur-idp >/dev/null 2>&1 || true
}

require_docker() {
  command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
  docker info >/dev/null 2>&1 || { echo "Docker daemon is not reachable" >&2; exit 1; }
  docker compose version >/dev/null || { echo "Docker Compose v2 is required" >&2; exit 1; }
}

write_env() {
  mkdir -p "$HERE/data"
  # Serialize the whole check-then-write against concurrent invocations (e.g.
  # `docker-up` and `idp up` started together): two unserialized creators can
  # each truncate-write a DIFFERENT run-token secret, and the loser's IdP
  # passwords vanish while the Postgres volume keeps the old one -- a silent
  # crash-loop. mkdir is the portable atomic lock (macOS has no flock(1)),
  # and env_lock's release-once trap removes it ONLY while this invocation
  # still owns it, so a long-running command's exit cannot rmdir a lock a
  # concurrent invocation has since acquired.
  env_lock
  if [ ! -f "$ENV_FILE" ]; then
    umask 077
    secret="$(openssl rand -hex 32)"
    printf 'ANDYUR_RUN_TOKEN_SECRET=%s\n' "$secret" > "$ENV_FILE"
    printf 'ANDYUR_DELEGATIONS=*\n' >> "$ENV_FILE"
  fi
  # Reference-IdP settings (idp profile). Appended so an env file from an
  # earlier install gains them too; compose refuses to boot the IdP without
  # the secrets, so there is no default-credential state to reach. The port is
  # materialized here so the wrapper and compose read ONE stated value.
  grep -q '^ANDYUR_IDP_PORT=' "$ENV_FILE" || \
    printf 'ANDYUR_IDP_PORT=8480\n' >> "$ENV_FILE"
  grep -q '^ANDYUR_IDP_ADMIN_PASSWORD=' "$ENV_FILE" || \
    printf 'ANDYUR_IDP_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 16)" >> "$ENV_FILE"
  grep -q '^ANDYUR_IDP_DB_PASSWORD=' "$ENV_FILE" || \
    printf 'ANDYUR_IDP_DB_PASSWORD=%s\n' "$(openssl rand -hex 16)" >> "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  env_unlock
}

create_run_network() {
  if docker network inspect "$RUN_NETWORK" >/dev/null 2>&1; then
    internal="$(docker network inspect -f '{{.Internal}}' "$RUN_NETWORK")"
    [ "$internal" = "true" ] || {
      echo "refusing existing non-internal network '$RUN_NETWORK'" >&2
      echo "remove or rename it, then run docker-up again" >&2
      exit 1
    }
  else
    docker network create --internal "$RUN_NETWORK" >/dev/null
  fi
}

entry() {
  sid="$1" selector="$2"
  # Delete old role entries so repeated setup repairs selector/parent drift.
  docker exec andyur-spire-server /opt/spire/bin/spire-server entry show \
    -spiffeID "$sid" -output json | python3 -c \
    'import json,sys; [print(x["id"]) for x in json.load(sys.stdin).get("entries", [])]' | \
    while IFS= read -r id; do
      [ -z "$id" ] || docker exec andyur-spire-server \
        /opt/spire/bin/spire-server entry delete -entryID "$id" >/dev/null
    done
  docker exec andyur-spire-server /opt/spire/bin/spire-server entry create \
    -parentID "spiffe://$TD/agent/node" -spiffeID "$sid" \
    -selector "$selector" -jwtSVIDTTL 3600 >/dev/null
}

register_roles() {
  entry "spiffe://$TD/control-plane" "docker:label:andyur.role:server"
  entry "spiffe://$TD/worker" "docker:label:andyur.role:worker"
  entry "spiffe://$TD/operator" "docker:label:andyur.role:operator"
}

up() {
  require_docker
  write_env
  create_run_network
  bash "$SPIRE" up
  register_roles
  "$HERE/run.sh" sandbox-image
  compose up -d --build andyur-server andyur-worker
  compose ps
  echo
  echo "Andyur Docker deployment is ready at http://127.0.0.1:${ANDYUR_PORT:-8642}"
  echo "State: $HERE/data/docker.env (secret, mode 0600) + Docker volume andyur-data"
}

down() {
  require_docker
  write_env
  compose down
  bash "$SPIRE" down
  docker network rm "$RUN_NETWORK" >/dev/null 2>&1 || true
  # O1: reap any per-run isolation networks a crash left behind, so they do not
  # accumulate against Docker's address pool. Label-filtered, so this only ever
  # touches Andyur's run networks.
  orphan_nets="$(docker network ls --filter label=andyur.role=run-network -q 2>/dev/null)"
  [ -n "$orphan_nets" ] && docker network rm $orphan_nets >/dev/null 2>&1 || true
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  status) require_docker; write_env; compose ps ;;
  logs) require_docker; write_env; compose logs -f "${@:2}" ;;
  cli)
    require_docker
    write_env
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE" \
      --profile operator run --rm --no-deps andyur-cli "${@:2}"
    ;;
  idp)
    case "${2:-up}" in
      up) idp_up ;;
      down) idp_down ;;
      wire) idp_wire ;;
      unwire) idp_unwire ;;
      verify-composed) exec bash "$HERE/infra/verify-idp-composed.sh" ;;
      # Scoped to the IdP pair: profile-less services (jaeger, postgres, ...)
      # are implicitly part of EVERY profile, so an unscoped ps/logs would show
      # the whole fleet and drown the IdP's own signal.
      status) require_docker; write_env; compose_idp ps keycloak keycloak-db ;;
      logs) require_docker; write_env; compose_idp logs -f keycloak keycloak-db "${@:3}" ;;
      verify) exec bash "$HERE/infra/keycloak/verify-idp-reference.sh" ;;
      reset)
        # The realm JSON is imported ONLY into a fresh volume (Keycloak's
        # import strategy is ignore-existing), and the db password is baked in
        # at first init -- so realm edits and secret rotation both require
        # wiping the IdP state. This is the explicit path for that. Destroys
        # all IdP state: realm changes made via the admin console included --
        # hence the confirmation (-y for scripted use).
        require_docker; write_env
        if [ "${3:-}" != "-y" ]; then
          if [ -t 0 ]; then
            printf "This wipes ALL IdP state (imported realm, users, admin-console changes) AND discards the stored demo passwords/agent secret so the next up rotates them. Type 'yes' to continue: "
            read -r answer
            [ "$answer" = "yes" ] || { echo "aborted"; exit 1; }
          else
            echo "refusing to wipe IdP state non-interactively without -y" >&2
            exit 1
          fi
        fi
        idp_down
        docker volume rm andyur-idp-db >/dev/null 2>&1 || true
        # An operator resetting to ROTATE a leaked demo credential must get
        # rotation: strip the stored records so the next up asks/generates
        # fresh instead of silently reusing the old values.
        env_lock
        umask 077
        tmp="$ENV_FILE.tmp.$$"
        grep -Ev '^ANDYUR_IDP_PASSWORD_|^ANDYUR_IDP_AGENT_CLIENT_SECRET=' "$ENV_FILE" > "$tmp" || true
        chmod 600 "$tmp"
        mv "$tmp" "$ENV_FILE"
        env_unlock
        echo "IdP state wiped and stored demo credentials discarded; the next"
        echo "'./run.sh idp up' re-imports the realm and rotates everything"
        ;;
      *) echo "usage: $0 idp {up|down|wire|unwire|status|logs|verify|verify-composed|reset}" >&2; exit 2 ;;
    esac
    ;;
  *) echo "usage: $0 {up|down|status|logs [service]|cli <args...>|idp {up|down|wire|unwire|status|logs|verify|verify-composed|reset}}" >&2; exit 2 ;;
esac

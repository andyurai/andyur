#!/usr/bin/env bash
# What an in-cluster gate needs to talk to the control plane as an operator.
#
# EXTRACTED BECAUSE THERE ARE NOW TWO GATES THAT NEED IT, and two copies of a
# token-refresh rule is one copy and one that drifts. Every hard-won detail
# below was paid for by a failing RC run; none of it should have to be learned
# twice.
#
# Sourced, not executed. The caller must have set SYSTEM_NS and defined fail().

# WHERE THE USER TOKEN COMES FROM. It lived in the workload gate, which is
# where the extraction found it -- and every helper below reads it, so a
# second gate sourcing this file got `IDP_REALM: unbound variable` from
# inside a function whose job is to explain why there is no token.
IDP_REALM="${ANDYUR_GATE_IDP_REALM:-http://andyur-keycloak.andyur-system.svc:8080/realms/andyur}"

# THE TOKEN EXPIRES BEFORE THE RUN DOES. The realm's access tokens live 300
# seconds and this gate waits up to 900 for a workload, so a token fetched once
# at the start is dead well before the run's summary is read. That was invisible
# while the reads swallowed their failures -- the gate carried on with a `body`
# fetched minutes earlier -- and it surfaced the moment those reads were made
# strict: "the control plane returned NOTHING when 'summary' was read".
#
# So it is refreshed on use, from the same source, whenever it is close to
# expiry. An operator-supplied token (ANDYUR_GATE_USER_TOKEN) is never
# refreshed: it is theirs, and silently replacing it with the demo realm's
# admin would be the gate authenticating as somebody the operator did not name.
USER_TOKEN="${ANDYUR_GATE_USER_TOKEN:-}"
USER_TOKEN_FIXED=0
[ -n "$USER_TOKEN" ] && USER_TOKEN_FIXED=1
USER_TOKEN_AT=-1000
USER_TOKEN_MAX_AGE="${ANDYUR_GATE_TOKEN_MAX_AGE:-200}"   # < the realm's 300 s

fetch_user_token() {
  [ "$USER_TOKEN_FIXED" = 1 ] && return 0
  USER_TOKEN="$(kubectl exec -n "$SYSTEM_NS" deployment/andyur-operator -- python -c '
import json, sys, urllib.request, urllib.parse
base = sys.argv[1]
try:
    cfg = json.load(urllib.request.urlopen(base + "/.well-known/openid-configuration", timeout=10))
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "andyur-cli",
                                   "username": "carol", "password": "carol-password",
                                   "scope": "openid"}).encode()
    print(json.load(urllib.request.urlopen(cfg["token_endpoint"], data=data, timeout=10))["access_token"])
except Exception:
    # No reachable IdP is not an error HERE: a deployment with user-auth off
    # needs no token, and one with it on fails loudly at the first call.
    print("")
' "$IDP_REALM" 2>/dev/null || true)"
  USER_TOKEN_AT=$SECONDS
  if [ -z "$USER_TOKEN" ]; then
    # WHICH OF THE TWO IT IS. An empty token can mean the IdP refused, or it can
    # mean the Kubernetes API is gone -- `kubectl exec` cannot reach a pod on a
    # cluster that is not answering, and this gate's machine stalls its k3s under
    # load. Blaming the token for a missing cluster is the same misdirection as
    # the JSONDecodeError this file used to raise: true about the symptom,
    # useless about the cause.
    if ! kubectl get --raw /readyz >/dev/null 2>&1; then
      echo "NOTE: the Kubernetes API is unreachable, so no user token could be fetched; every check after this one is about the cluster being gone" >&2
    else
      echo "NOTE: no user token from $IDP_REALM; owner-gated calls will be refused if this deployment has user-auth on" >&2
    fi
  fi
}

# The token reaches the pod on STDIN and is exported inside it, never passed on
# argv: a credential in argv is readable by every process in that container, and
# this repository refuses that shape everywhere else.
operator() {
  if [ $((SECONDS - USER_TOKEN_AT)) -ge "$USER_TOKEN_MAX_AGE" ]; then fetch_user_token; fi
  printf '%s' "$USER_TOKEN" | kubectl exec -i -n "$SYSTEM_NS" deployment/andyur-operator -- \
    sh -c 'IFS= read -r ANDYUR_USER_TOKEN || true; export ANDYUR_USER_TOKEN; exec python -m andyur.cli "$@"' sh "$@"
}
# READ ONE FIELD, OR SAY WHY NOT. This was `json.load(sys.stdin)`, so any
# answer that was not JSON became a bare JSONDecodeError traceback with no
# mention of what was being read -- "Expecting value: line 1 column 1", about a
# run the gate never made. It happened twice in RC runs, both times because an
# owner-gated call came back empty (the operator Deployment mid-rollout, so
# `kubectl exec` hit a terminating pod and the user token was empty).
#
# I fixed the agents listing the first time and left this helper alone, which
# is fixing the instance and not the class. Every call site goes through here.
json_field() {  # field name; the document on stdin
  python3 -c '
import json, sys
field = sys.argv[1]
raw = sys.stdin.read()
if not raw.strip():
    sys.stderr.write(f"the control plane returned NOTHING when {field!r} was read; "
                     "an owner-gated call with no user token answers 401 with an "
                     "empty body\n")
    sys.exit(3)
try:
    document = json.loads(raw)
except json.JSONDecodeError as exc:
    sys.stderr.write(f"the control plane answer is not JSON when {field!r} was "
                     f"read ({exc}); it said: {raw[:200]!r}\n")
    sys.exit(3)
value = document.get(field)
print("" if value is None else value)
' "$1"
}

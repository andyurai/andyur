#!/usr/bin/env bash
# Bring up Andyur from this bundle, after asking what only you can answer.
#
#   ./deploy.sh --ask          interview, and write andyur.values.yaml
#   ./deploy.sh                render, preflight, apply, using that file
#   ./deploy.sh --preflight    check the cluster and change nothing
#
# WHY AN INTERVIEW AND NOT DEFAULTS. Everything this asks is something a wrong
# guess turns into a pod that fails for a reason pointing somewhere else: an
# image your nodes cannot pull, an identity provider at an address that is not
# yours, a SPIRE release name that makes the API server silently ignore every
# identity this deployment declares. There is no safe default for any of them,
# so this refuses instead of choosing.
#
# WHY A PREFLIGHT. Every check below is answerable BEFORE anything is applied,
# and every one of them is otherwise discovered as a CrashLoopBackOff whose
# message names the wrong thing. That is the failure this whole bundle has been
# working against.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALUES="${ANDYUR_VALUES:-$HERE/andyur.values.yaml}"
RENDERED="${ANDYUR_RENDERED:-$HERE/rendered}"

ok(){   printf '  \033[32mok\033[0m    %s\n' "$*"; }
bad(){  printf '  \033[31mNO\033[0m    %s\n' "$*"; FAILED=$((FAILED+1)); }
note(){ printf '        %s\n' "$*"; }
say(){  printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
die(){  printf '\n\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
FAILED=0

# --- the interview ----------------------------------------------------------
ask() {  # variable  prompt  default(optional)
  local var="$1" prompt="$2" default="${3-}" reply
  if [ -n "$default" ]; then
    printf '%s\n  [%s]: ' "$prompt" "$default" >&2
  else
    printf '%s\n  (no default -- a wrong value here fails somewhere else)\n  : ' "$prompt" >&2
  fi
  IFS= read -r reply
  reply="${reply:-$default}"
  [ -n "$reply" ] || die "$var is required; nothing was written"
  printf -v "$var" '%s' "$reply"
}

# WHAT THE RELEASE ALREADY KNOWS. Question 3 used to have no default because
# nothing in the bundle recorded which catalog it was built against. The release
# manifest records it now, so the answer is offered rather than demanded -- and a
# deployer who just presses return gets the catalog this bundle was rendered
# for, which is the right answer in every case except deliberately using another.
recorded_catalog() {
  python3 - "$HERE/release-manifest.json" <<'CATALOG' 2>/dev/null
import json, sys
try:
    manifest = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(0)
for artifact in manifest.get("artifacts", []):
    if artifact.get("kind") == "agent-catalog":
        print(artifact["name"])
        break
CATALOG
}

interview() {
  cat >&2 <<'INTRO'

This asks nine questions. Seven have defaults that are conventions; two do not,
because no default for them is safe. PREREQUISITES.md explains each in full.

INTRO
  ask REGISTRY "1. Which registry can your NODES pull from? The images in this
   bundle are pinned by digest and name where they were pushed; if that is not
   reachable from your cluster, push the same digests somewhere that is."
  ask REGISTRY_CIDR "2. That registry's address as a CIDR. The control plane's
   NetworkPolicy egress rule is an ipBlock -- NetworkPolicy cannot select by
   DNS name -- so this is the one place an address, not a name, is required."
  ask CATALOG "3. The governed agent catalog: a pinned OCI reference to the
   signed snapshot of agents this deployment may run. Without one the server
   has no agents and no run can start. The default is the catalog THIS bundle
   was built against, from release-manifest.json." "$(recorded_catalog)"
  ask MODEL_CIDR "3a. The address your MODEL answers on, as a CIDR -- another
   NetworkPolicy ipBlock, and not necessarily the registry's, though on a
   single-machine deployment they are the same host." "$REGISTRY_CIDR"
  ask IDP_MODE "4. Identity provider: 'bundled' deploys the Keycloak in
   idp.yaml with its demo realm, 'external' points at yours." "bundled"
  if [ "$IDP_MODE" = "external" ]; then
    ask IDP_ISSUER "4a. Your issuer URL, exactly as it appears in tokens' iss"
    ask IDP_AUDIENCE "4b. The audience this deployment's tokens must name"
    ask IDP_JWKS "4c. The JWKS URL (named, not discovered: a discovery
   document behind an ingress advertises the ingress, not the address your
   control plane can reach)"
    ask IDP_ADMIN_ROLE "4d. The realm role that means admin here"
  else
    IDP_ISSUER=""; IDP_AUDIENCE=""; IDP_JWKS=""; IDP_ADMIN_ROLE=""
  fi
  ask TRUST_DOMAIN "5. SPIFFE trust domain. It appears in every identity this
   deployment declares and must equal the one SPIRE was installed with." "andyur.local"
  ask SPIRE_NAMESPACE "6. The namespace SPIRE is installed in" "spire-system"
  ask SPIRE_RELEASE "7. Its Helm RELEASE NAME. The ClusterSPIFFEIDs use a
   className of <namespace>-<release>; get this wrong and the controller
   ignores every identity silently -- no SVIDs, no error." "andyur-spire"
  ask SYSTEM_NS "8. Namespace for the control plane" "andyur-system"
  ask RUNS_NS "9. Namespace runs are launched into" "andyur-runs"

  cat > "$VALUES" <<VALUESEOF
# Written by deploy.sh --ask. This file IS the deployment: keep it, and the
# same answers produce the same cluster. Nothing here is a credential.
schema: andyur.deploy-values/v1
registry:
  images: "$REGISTRY"
  cidr: "$REGISTRY_CIDR"
model:
  cidr: "$MODEL_CIDR"
agent_catalog: "$CATALOG"
idp:
  mode: "$IDP_MODE"
  issuer: "$IDP_ISSUER"
  audience: "$IDP_AUDIENCE"
  jwks: "$IDP_JWKS"
  admin_role: "$IDP_ADMIN_ROLE"
spire:
  namespace: "$SPIRE_NAMESPACE"
  release: "$SPIRE_RELEASE"
  trust_domain: "$TRUST_DOMAIN"
namespaces:
  system: "$SYSTEM_NS"
  runs: "$RUNS_NS"
VALUESEOF
  echo >&2
  echo "wrote $VALUES -- review it, then run ./deploy.sh" >&2
}

# --- reading the answers back ------------------------------------------------
# THE INSTALLER NEEDS PyYAML, AND USED TO HIDE THAT.
#
# `value` below reads the values file with the SYSTEM python3 -- a partner runs
# this script out of the bundle, with no virtualenv -- and PyYAML is not a
# runtime dependency of Andyur (requirements-dev.txt only; ADR-008 C2 keeps
# runtime manifest loading on JSON). It therefore has to be checked for, not
# assumed.
#
# It was assumed, and `value` sent stderr to /dev/null, so a missing PyYAML made
# EVERY lookup return empty and the installer died with
# "andyur.values.yaml has no value for registry" -- a message about the values
# file, when the values file was fine and the interpreter was missing a module.
# It passed on the author's Mac, whose system python3 happens to carry PyYAML,
# and failed all 15 installer tests on every Linux CI runner.
require_yaml() {
  python3 -c 'import yaml' 2>/dev/null && return 0
  die "this installer needs PyYAML for $(basename "$VALUES"), and the python3 on
your PATH ($(command -v python3 || echo 'not found')) does not have it.

  python3 -m pip install pyyaml

Nothing else about your deployment is wrong: the values file was never read."
}

value() {  # dotted.path
  # stderr is NOT discarded. A missing key already prints an empty line below,
  # so anything on stderr is a real fault (an unreadable or malformed values
  # file) and hiding it is how the message above came to misdirect.
  python3 -c '
import sys, yaml
document = yaml.safe_load(open(sys.argv[1])) or {}
for key in sys.argv[2].split("."):
    document = (document or {}).get(key)
print("" if document is None else document)
' "$VALUES" "$1"
}

load_values() {
  [ -f "$VALUES" ] || die "no $VALUES -- run ./deploy.sh --ask first"
  require_yaml
  REGISTRY="$(value registry.images)"; REGISTRY_CIDR="$(value registry.cidr)"
  # An older values file has no model.cidr. Defaulting it to the registry's is
  # exactly what the shipped manifest already assumed, so this reads back the
  # same deployment rather than silently changing one.
  MODEL_CIDR="$(value model.cidr)"; MODEL_CIDR="${MODEL_CIDR:-$REGISTRY_CIDR}"
  CATALOG="$(value agent_catalog)"
  IDP_MODE="$(value idp.mode)"; IDP_ISSUER="$(value idp.issuer)"
  IDP_AUDIENCE="$(value idp.audience)"; IDP_JWKS="$(value idp.jwks)"
  IDP_ADMIN_ROLE="$(value idp.admin_role)"
  SPIRE_NAMESPACE="$(value spire.namespace)"; SPIRE_RELEASE="$(value spire.release)"
  TRUST_DOMAIN="$(value spire.trust_domain)"
  SYSTEM_NS="$(value namespaces.system)"; RUNS_NS="$(value namespaces.runs)"
  # REFUSED, not defaulted. An empty answer here is the caller believing they
  # configured something they did not.
  for required in REGISTRY REGISTRY_CIDR MODEL_CIDR CATALOG IDP_MODE SPIRE_NAMESPACE \
                  SPIRE_RELEASE TRUST_DOMAIN SYSTEM_NS RUNS_NS; do
    # `${required,,}` is bash 4. macOS ships bash 3.2, so the REFUSAL ITSELF
    # was a "bad substitution" on the shell a Mac partner runs this with --
    # the one message that has to work when nothing else does.
    [ -n "${!required}" ] \
      || die "$VALUES has no value for $(printf '%s' "$required" | tr 'A-Z' 'a-z')"
  done
  # THE NAMESPACES ARE NOT YET RENDERABLE, so answering them differently is
  # refused rather than half-honoured. `andyur-runs` and `andyur-system` are
  # written into the manifests themselves -- the worker's env, the
  # ClusterSPIFFEID namespaceSelectors, the NetworkPolicy peers, the Roles --
  # and the render substitutes images, addresses and the catalog, not names. A
  # deployer who answered `platform-runs` got a control plane whose every
  # selector pointed at a namespace nothing was in, and nothing said so.
  #
  # Questions 8 and 9 stay in the interview because they are real questions and
  # the answer will be honoured; until then this refuses in one sentence rather
  # than deploying something that cannot work.
  if [ "$SYSTEM_NS" != "andyur-system" ] || [ "$RUNS_NS" != "andyur-runs" ]; then
    die "this release renders images, addresses and the agent catalog, but not
NAMESPACES: 'andyur-system' and 'andyur-runs' are written into the manifests
themselves. You answered '$SYSTEM_NS' and '$RUNS_NS'. Re-run ./deploy.sh --ask
and take the defaults for questions 8 and 9, or edit the manifests by hand and
accept that they are then no longer the signed ones."
  fi
  if [ "$IDP_MODE" = "external" ]; then
    for required in IDP_ISSUER IDP_AUDIENCE IDP_JWKS IDP_ADMIN_ROLE; do
      [ -n "${!required}" ] || die "idp.mode is external but $(printf '%s' "$required" | tr 'A-Z' 'a-z') is empty"
    done
  fi
}

# --- rendering ---------------------------------------------------------------
render() {
  # THE KUBERNETES API'S OWN ADDRESSES, DISCOVERED. This is not a preference and
  # asking for it produced the worst kind of wrong answer: a worker with an
  # egress rule pointing at the wrong host, failing with a message about the
  # NetworkPolicy stamp -- which names something the deployer never touched.
  # Every address behind the kubernetes.default Endpoints object, as CIDRs.
  API_CIDRS="$(kubectl get endpoints kubernetes -n default \
    -o jsonpath='{range .subsets[*].addresses[*]}{.ip}/32 {end}' 2>/dev/null)"
  API_CIDRS="${API_CIDRS% }"
  [ -n "$API_CIDRS" ] || die "could not read the kubernetes.default endpoints; \
the worker's egress rule to the API server cannot be rendered from a guess"
  # Only after everything the render NEEDS is in hand. Copying first left a
  # `rendered/` directory holding the manifests exactly as shipped -- carrying
  # the BUILD machine's addresses -- for anyone who then reached for
  # `kubectl apply -f rendered/`. A half-rendered output is worse than none.
  mkdir -p "$RENDERED"
  local manifests=(control-plane.yaml observability.yaml run-isolation.yaml temporal.yaml)
  [ "$IDP_MODE" = "bundled" ] && manifests+=(idp.yaml)
  for name in "${manifests[@]}"; do
    [ -f "$HERE/$name" ] || die "$name is missing from this bundle"
    cp "$HERE/$name" "$RENDERED/$name"
  done
  # THE SPIFFE className, IN EVERY MANIFEST THAT DECLARES AN IDENTITY.
  #
  # Questions 6 and 7 asked for the SPIRE namespace and release, the preflight
  # checked that SPIRE was really installed under them -- and nothing rendered
  # them. The manifests hard-code `spire-system-andyur-spire`, so a deployer who
  # answered anything else got a green preflight and a set of ClusterSPIFFEIDs
  # the controller ignores, with no error anywhere. This file's own question 7
  # describes that failure ("get this wrong and the controller ignores every
  # identity silently -- no SVIDs, no error") and then let it happen.
  for name in control-plane.yaml run-isolation.yaml temporal.yaml; do
    python3 - "$RENDERED/$name" "${SPIRE_NAMESPACE}-${SPIRE_RELEASE}" <<'CLASSNAME'
import re, sys
path, class_name = sys.argv[1:3]
text = open(path).read()
before = len(re.findall(r"^\s*className:", text, re.M))
text = re.sub(r"(^\s*className:).*$", r"\1 " + class_name, text, flags=re.M)
open(path, "w").write(text)
# Asserted positively: every identity this manifest declares must now name the
# class the controller is actually watching. A ClusterSPIFFEID with no
# className at all is INVISIBLE to a controller running watchClassless: false,
# so "no className lines" is a failure, not a no-op.
identities = len(re.findall(r"kind: ClusterSPIFFEID", text))
if identities and before != identities:
    sys.exit(f"{path}: {identities} ClusterSPIFFEID(s) but {before} className "
             "line(s) -- one declares an identity nothing will ever create, and "
             "it fails silently")
CLASSNAME
    [ $? -eq 0 ] || die "rendering the SPIFFE className refused"
  done
  # THE TRUST DOMAIN, IN EVERY MANIFEST THAT NAMES AN IDENTITY. It was rendered
  # into control-plane.yaml alone, so under any other trust domain the engine's
  # authorizer listed IDs the cluster never issues and fetched certificates
  # under names SPIRE does not serve: the durable provider stayed offline with
  # no error. control-plane.yaml is rendered below with its other answers.
  for name in run-isolation.yaml temporal.yaml; do
    python3 - "$RENDERED/$name" "$TRUST_DOMAIN" <<'TRUSTDOMAIN'
import sys
path, trust = sys.argv[1:3]
text = open(path).read().replace("andyur.local", trust)
if trust != "andyur.local" and "andyur.local" in text:
    sys.exit(f"{path}: the default trust domain survived the render")
open(path, "w").write(text)
TRUSTDOMAIN
    [ $? -eq 0 ] || die "rendering the SPIFFE trust domain into $name refused"
  done
  python3 - "$RENDERED/control-plane.yaml" "$REGISTRY" "$REGISTRY_CIDR" "$CATALOG" \
    "$IDP_ISSUER" "$IDP_AUDIENCE" "$IDP_JWKS" "$IDP_ADMIN_ROLE" "$TRUST_DOMAIN" \
    "$API_CIDRS" "$MODEL_CIDR" <<'PY'
import re, sys
path, registry, cidr, catalog, issuer, audience, jwks, admin_role, trust = sys.argv[1:10]
api_cidrs, model_cidr = sys.argv[10:12]
text = open(path).read()

# The images keep their digests and change only their registry: a digest IS the
# identity, so re-homing an image must never re-tag it.
#
# The WHOLE reference is replaced, not the segment before the name. Matching
# only `([a-z0-9.:-]+)/andyur-x` cannot see a registry with a path in it --
# `ghcr.io/acme/andyur-server` would have kept `ghcr.io/` and grown a second
# registry in front of it. Ours are single-segment today, which is exactly why
# that would have gone unnoticed.
text = re.sub(r"\S*\b(andyur-(?:server|worker|runner))@sha256:([a-f0-9]+)",
              rf"{registry}/\1@sha256:\2", text)
# The agent catalog is a whole reference, digest included.
text = re.sub(r'ANDYUR_REGISTRY_REF, value: "[^"]*"',
              f'ANDYUR_REGISTRY_REF, value: "{catalog}"', text)
# THE PLACES AN ADDRESS IS REQUIRED, because NetworkPolicy cannot select by
# name -- and there are THREE of them, meaning three different things.
#
# This used to be one substitution over every ipBlock in the file, on the
# comment "Every ipBlock in the file is the registry rule". It was not. Two of
# them are the Kubernetes API server (the worker's and the reconciler's egress)
# and one is the model host, so rendering pointed the worker's API egress at
# the REGISTRY -- and the symptom was a worker that could not launch, blaming
# the NetworkPolicy verification stamp. Every ipBlock in control-plane.yaml now
# carries an `andyur:render=<purpose>` marker on the line above it, and each
# purpose is rendered from its own answer.
def render_marked(text, purpose, replacement):
    """Rewrite the FIRST cidr after each `andyur:render=<purpose>` marker.

    Deliberately not a structural YAML edit: the rendered file is the one a
    deployer reads when something is wrong, and round-tripping it through a
    YAML loader would drop every comment in it -- including the markers that
    make this renderable at all. Deliberately not a clever pattern over the
    surrounding flow-style either: markers and cidrs are both unambiguous, and
    "the next cidr after this marker" is a rule that survives someone
    reformatting the peer list around it.
    """
    marker = "# andyur:render=" + purpose
    out, seen, position = [], 0, 0
    while True:
        found = text.find(marker, position)
        if found < 0:
            out.append(text[position:])
            break
        cidr_at = text.find("cidr: ", found)
        if cidr_at < 0:
            sys.exit(f"the {purpose} marker is not followed by any cidr")
        end = cidr_at + len("cidr: ")
        while end < len(text) and text[end] in "0123456789./":
            end += 1
        out.append(text[position:cidr_at])
        out.append("cidr: " + replacement)
        position = end
        seen += 1
    return "".join(out), seen

# The API server may sit behind several addresses; the rule takes the first,
# and the rest are appended as sibling peers so a multi-master cluster is not
# rendered down to one of its API servers.
first_api = api_cidrs.split()[0]
text, api_rules = render_marked(text, "kubernetes-api", first_api)
text, model_rules = render_marked(text, "model-host", model_cidr)
text, registry_rules = render_marked(text, "registry", cidr)
missing = [name for name, n in (("kubernetes-api", api_rules), ("model-host", model_rules),
                                ("registry", registry_rules)) if n == 0]
if missing:
    sys.exit("no ipBlock carries the render marker(s): " + ", ".join(missing) +
             " -- control-plane.yaml and this renderer have drifted apart, and a "
             "silently unrendered egress rule points at the BUILD machine")
if issuer:
    text = re.sub(r'ANDYUR_OIDC_ISSUER, value: "[^"]*"',
                  f'ANDYUR_OIDC_ISSUER, value: "{issuer}"', text)
    text = re.sub(r"ANDYUR_OIDC_AUDIENCE, value: \S+",
                  f"ANDYUR_OIDC_AUDIENCE, value: {audience}", text)
    text = re.sub(r'ANDYUR_OIDC_JWKS, value: "[^"]*"',
                  f'ANDYUR_OIDC_JWKS, value: "{jwks}"', text)
    text = re.sub(r"ANDYUR_ADMIN_ROLE, value: \S+",
                  f"ANDYUR_ADMIN_ROLE, value: {admin_role}", text)
text = text.replace("andyur.local", trust)
open(path, "w").write(text)

# REFUSE A HALF-RENDERED MANIFEST -- by asserting what must be TRUE, not by
# blocklisting what was there before.
#
# The first version refused any manifest mentioning `localhost:5000` or
# `host.lima.internal`, and then refused a correct render because those were
# the deployer's OWN answers. A ban list of the build machine's past addresses
# is a regression test, not a rule: it cannot tell "an address nobody chose"
# from "the address you just chose".
#
# The property is: every Andyur image names the registry that was ANSWERED, the
# catalog is the reference that was ANSWERED, and no placeholder survives.
# ASSERTED POSITIVELY, and it can fail. The first version looked for images at
# the WRONG registry after a substitution that rewrote every registry -- so
# there was nothing left to find and the check could not fail, which is the one
# property a check must never have. What must be true is that every Andyur
# image now names the registry that was answered.
images = re.findall(r"\S*\b(?:andyur-server|andyur-worker|andyur-runner)@sha256:[a-f0-9]+", text)
if not images:
    sys.exit("the manifest names no Andyur images: this is not a control plane")
wrong = [i for i in images if not i.startswith(registry + "/")]
if wrong:
    sys.exit("these images do not name the registry you gave (%s): %s"
             % (registry, ", ".join(sorted(set(wrong))[:3])))
placeholders = sorted(set(re.findall(r"registry\.example/\S+", text)))
if placeholders:
    sys.exit("the manifest still carries placeholders: " + ", ".join(placeholders[:3]))
if catalog not in text:
    sys.exit("the agent catalog you gave is not in the rendered manifest")
# ASSERTED POSITIVELY, like the images: no ipBlock may still name an address
# nobody in this deployment chose. `first_api` is discovered and the other two
# are answers, so the set of legitimate addresses is exactly these three.
chosen = {first_api, model_cidr, cidr}
for block in re.findall(r"ipBlock: \{cidr: ([0-9./]+)\}", text):
    if block not in chosen:
        sys.exit(f"an egress rule still names {block}, which is not the API "
                 f"server, the model host or the registry you gave: it is the "
                 "address the bundle was BUILT on")
PY
  [ $? -eq 0 ] || die "rendering refused"
  ok "rendered $(ls "$RENDERED" | tr '\n' ' ')into $RENDERED"
}

# --- preflight ---------------------------------------------------------------
preflight() {
  say "preflight (nothing is applied)"
  kubectl version -o json >/dev/null 2>&1 \
    && ok "the cluster answers" || { bad "kubectl cannot reach a cluster"; return; }

  kubectl get crd clusterspiffeids.spire.spiffe.io >/dev/null 2>&1 \
    && ok "the SPIFFE CRDs are installed" \
    || { bad "clusterspiffeids.spire.spiffe.io is not installed"
         note "install SPIRE first -- PREREQUISITES.md names the charts and versions"; }

  # THE QUIETEST FAILURE IN THIS SYSTEM, checked before it can happen: the
  # ClusterSPIFFEIDs declare className "<namespace>-<release>", and a mismatch
  # means the controller ignores every one of them with no error at all.
  if kubectl get statefulset -n "$SPIRE_NAMESPACE" \
       -l "app.kubernetes.io/instance=$SPIRE_RELEASE" 2>/dev/null | grep -q .; then
    ok "SPIRE is installed as '$SPIRE_RELEASE' in '$SPIRE_NAMESPACE' (className will match)"
  else
    bad "no SPIRE release named '$SPIRE_RELEASE' in namespace '$SPIRE_NAMESPACE'"
    note "the manifest's className is ${SPIRE_NAMESPACE}-${SPIRE_RELEASE}; a mismatch"
    note "is silent -- the controller ignores every identity and nothing says so"
    kubectl get statefulset -A -l app.kubernetes.io/name=server \
      -o custom-columns=NS:.metadata.namespace,RELEASE:.metadata.labels.app\\.kubernetes\\.io/instance \
      2>/dev/null | sed 's/^/        found: /' | head -4
  fi

  for secret in andyur-secrets andyur-idp-secrets andyur-temporal-secrets; do
    [ "$secret" = "andyur-idp-secrets" ] && [ "$IDP_MODE" != "bundled" ] && continue
    kubectl get secret "$secret" -n "$SYSTEM_NS" >/dev/null 2>&1 \
      && ok "Secret $secret exists in $SYSTEM_NS" \
      || { bad "Secret $secret is missing from $SYSTEM_NS"
           note "PREREQUISITES.md section 2 has the create command; no credential ships here"; }
  done

  # THE ANSWER, OR THE FACT THAT THERE WASN'T ONE. `kubectl ... 2>/dev/null |
  # grep -q .` cannot tell "this cluster has no StorageClass" from "that call
  # failed", and on a cluster whose API stalls under load the second is common:
  # this preflight reported "no StorageClass: the PersistentVolumeClaims will
  # never bind" about a cluster with a default local-path provisioner, and
  # refused a deploy for a reason that was not true. A false RED is the same
  # defect as a false green, pointed the other way.
  if storage="$(kubectl get storageclass -o name 2>&1)"; then
    if [ -n "$storage" ]; then
      ok "the cluster has a StorageClass (the server and the IdP database claim volumes)"
    else
      bad "no StorageClass: the PersistentVolumeClaims will never bind"
    fi
  else
    bad "could not ask the cluster for its StorageClasses, so this is unknown"
    note "$(printf '%s' "$storage" | head -1)"
  fi

  # A REAL PULL, not an assumption. The images are digests on a registry that
  # may be reachable from your laptop and not from your nodes -- which is the
  # single most common way this deployment fails, and the only way to know is
  # to make a node try.
  local image probe="andyur-preflight-pull"
  image="$(grep -oE "${REGISTRY//./\\.}/andyur-server@sha256:[a-f0-9]+" \
            "$RENDERED/control-plane.yaml" | head -1)"
  if [ -n "$image" ]; then
    kubectl delete pod "$probe" -n "$SYSTEM_NS" --ignore-not-found >/dev/null 2>&1
    # THE PROBE MUST SATISFY THE SAME ADMISSION POLICY AS THE REAL WORKLOADS.
    # `kubectl run` builds a Pod with no securityContext, and this namespace
    # enforces PodSecurity "restricted" -- so the probe was REJECTED at
    # admission, no pod ever existed, and the preflight reported "a node could
    # NOT pull" about an image the cluster was already running. A check that
    # cannot run in the namespace it is checking answers a question about
    # itself.
    local created
    created="$(kubectl apply -n "$SYSTEM_NS" -f - 2>&1 <<PODEOF
apiVersion: v1
kind: Pod
metadata: {name: $probe}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 1000, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: pull
      image: $image
      command: ["/bin/true"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
PODEOF
)"
    if [ $? -ne 0 ]; then
      bad "the pull probe could not be created: $created"
    else
      # Bounded, and the bound is settable: the tests drive this against a
      # fake kubectl where nothing will ever become Ready, and paying 90
      # seconds per case to learn that made the suite slower than the cluster.
      local deadline=$((SECONDS + ${ANDYUR_PULL_PROBE_SECONDS:-90})) phase="" reason=""
      while [ $SECONDS -lt $deadline ]; do
        phase="$(kubectl get pod "$probe" -n "$SYSTEM_NS" -o jsonpath='{.status.phase}' 2>/dev/null)"
        reason="$(kubectl get pod "$probe" -n "$SYSTEM_NS" \
          -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)"
        case "$reason" in *ImagePull*|*ErrImage*|*InvalidImageName*) break ;; esac
        case "$phase" in Succeeded|Running|Failed) break ;; esac
        sleep 3
      done
      case "$phase:$reason" in
        Succeeded:*|Running:*) ok "a node pulled $image" ;;
        Failed:*)              ok "a node pulled $image (the container exited, which is the point)" ;;
        *)                     bad "a node could NOT pull $image (${reason:-still $phase after 90s})"
                               note "the digest is right; the registry is not reachable from your nodes" ;;
      esac
    fi
    kubectl delete pod "$probe" -n "$SYSTEM_NS" --ignore-not-found >/dev/null 2>&1
  fi
}

# --- apply -------------------------------------------------------------------
apply() {
  say "applying, in the order the manifests depend on each other"
  [ "$IDP_MODE" = "bundled" ] && { kubectl apply -f "$RENDERED/idp.yaml" >/dev/null \
    && ok "idp.yaml" || die "applying idp.yaml failed"; }
  kubectl apply -f "$RENDERED/observability.yaml" >/dev/null \
    && ok "observability.yaml" || die "applying observability.yaml failed"
  # THE CATALOG'S VERIFICATION KEY, as a Secret. Public key, so the bundle
  # carries it; created here because the server mounts `andyur-registry-cosign`
  # and refuses to fetch the catalog without it -- and a deployer with no source
  # tree had no copy of it and no instruction naming it. Not a credential, so
  # unlike the two Secrets in PREREQUISITES.md this one is not the deployer's to
  # invent. Applied, not created, so re-running deploy.sh is idempotent.
  if [ -f "$HERE/agent-catalog-cosign.pub" ]; then
    kubectl -n "$SYSTEM_NS" create secret generic andyur-registry-cosign \
      --from-file=cosign.pub="$HERE/agent-catalog-cosign.pub" \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null \
      && ok "andyur-registry-cosign (the catalog verification key, from the bundle)" \
      || die "could not create the catalog verification Secret"
  else
    note "no agent-catalog-cosign.pub in this bundle: the server will refuse to"
    note "fetch the agent catalog unless you create andyur-registry-cosign yourself"
  fi
  # BEFORE the control plane: control-plane.yaml puts a Role and a RoleBinding
  # in the run namespace, and a Role cannot be applied into a namespace that
  # does not exist yet.
  kubectl apply -f "$RENDERED/run-isolation.yaml" >/dev/null \
    && ok "run-isolation.yaml (the run namespace)" || die "applying run-isolation.yaml failed"
  # THE WORKFLOW ENGINE, BEFORE THE CONTROL PLANE THAT BINDS IT. control-plane
  # mounts a ConfigMap this file defines and selects the Temporal provider, so
  # applying it second left the server Pod waiting on a volume that did not
  # exist yet. The registration Job is deleted first because a Job's template
  # is immutable: re-running this script with a changed Job otherwise fails
  # and silently skips reconciling the namespace's retention.
  kubectl -n "$SYSTEM_NS" delete job andyur-temporal-namespace \
    --ignore-not-found >/dev/null 2>&1 || true
  # THE DATABASE'S VOLUME TEMPLATE IS IMMUTABLE, and a changed one made this
  # apply fail -- and with it everything after, the control plane included.
  # Deleting the StatefulSet with --cascade=orphan leaves its Pod and its claim
  # running; the apply re-creates the StatefulSet, which adopts both. The
  # existing claim keeps its old size: RUNBOOK.md, "Resizing the database
  # volume", is how it grows.
  live_size="$(kubectl -n "$SYSTEM_NS" get statefulset andyur-temporal-db \
    -o jsonpath='{.spec.volumeClaimTemplates[0].spec.resources.requests.storage}' 2>/dev/null || true)"
  want_size="$(python3 - "$RENDERED/temporal.yaml" <<'SIZE'
import sys, yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d and d.get("kind") == "StatefulSet" and d["metadata"]["name"] == "andyur-temporal-db":
        print(d["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"])
SIZE
)"
  if [ -n "$live_size" ] && [ "$live_size" != "$want_size" ]; then
    kubectl -n "$SYSTEM_NS" delete statefulset andyur-temporal-db --cascade=orphan \
      >/dev/null || die "could not re-create the engine database StatefulSet"
    note "engine database volume template: $live_size -> $want_size; the existing"
    note "claim keeps $live_size until resized (infra/temporal/RUNBOOK.md)"
  fi
  authz_before="$(kubectl -n "$SYSTEM_NS" get configmap andyur-temporal-authz \
    -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || true)"
  kubectl apply -f "$RENDERED/temporal.yaml" >/dev/null \
    && ok "temporal.yaml (the workflow engine)" || die "applying temporal.yaml failed"
  # THE AUTHORIZER READS ITS CONFIG AT START. A changed allowlist or listener
  # in the ConfigMap changes nothing running, so an upgrade that tightened who
  # may call the engine would leave the old list serving. Restarted only when
  # the ConfigMap actually changed, and only if there was one before.
  authz_after="$(kubectl -n "$SYSTEM_NS" get configmap andyur-temporal-authz \
    -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || true)"
  if [ -n "$authz_before" ] && [ "$authz_before" != "$authz_after" ]; then
    kubectl -n "$SYSTEM_NS" rollout restart deployment/andyur-temporal >/dev/null \
      && ok "the engine restarted onto its changed authorizer config" \
      || die "the authorizer config changed and the engine could not be restarted onto it"
  fi
  kubectl apply -f "$RENDERED/control-plane.yaml" >/dev/null \
    && ok "control-plane.yaml" || die "applying control-plane.yaml failed"

  # THE MODEL SERVICE'S ClusterIP, WHICH ONLY EXISTS ONCE IT IS APPLIED.
  #
  # control-plane.yaml carries `ANDYUR_OLLAMA_URL` as a numeric address, with
  # the comment "Render the numeric ClusterIP of the andyur-ollama Service
  # here" -- and nothing rendered it. The build machine's value shipped: a
  # deployer got the address of a Service on somebody else's cluster.
  #
  # It survived every deploy onto a cluster that already had that Service,
  # because Kubernetes keeps a ClusterIP for the life of the Service. Delete
  # the namespace -- which is what a first-time deployer has, and what tearing
  # down between RC passes produces -- and the new Service gets a new address
  # while the worker keeps handing the old one to every run. The failure is
  # `upstream_unreachable` on every model call, in the run's trace, naming an
  # IP that belongs to nothing.
  #
  # It has to happen AFTER the apply, because the Service is in the file being
  # applied. The address is read back from the API server and set on the
  # worker, and the deploy refuses if it cannot be read: a guess here is the
  # build machine's address all over again.
  ollama_ip="$(kubectl -n "$SYSTEM_NS" get service andyur-ollama \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
  case "$ollama_ip" in
    ""|None) die "the andyur-ollama Service has no ClusterIP, so the model
address every run is handed cannot be rendered. Runs would fail with
upstream_unreachable naming an address that belongs to nothing." ;;
  esac
  kubectl -n "$SYSTEM_NS" set env statefulset/andyur-worker \
    "ANDYUR_OLLAMA_URL=http://$ollama_ip:11434" >/dev/null \
    && ok "model address rendered to this cluster's Service ($ollama_ip)" \
    || die "could not set the model address on the worker"

  say "waiting for the control plane"
  kubectl rollout status "statefulset/andyur-server" -n "$SYSTEM_NS" --timeout=300s \
    && ok "the control plane is up" || bad "the control plane did not become ready"

  cat <<'AFTER'

  ONE THING TAKES A MINUTE, and it is not something you did wrong.

  The worker will not launch runs until the run namespace carries a
  NetworkPolicy verification stamp under 600 seconds old, and applying
  run-isolation.yaml deliberately resets that stamp to unverified: a manifest
  that has just been re-applied has not been proved.

  andyur-netpol-reconciler (in control-plane.yaml) proves it and stamps, within
  a cycle. Until then andyur-worker restarts, on purpose. Watch it happen:

    kubectl -n andyur-system logs deploy/andyur-netpol-reconciler -f
    kubectl get namespace andyur-runs -o yaml | grep andyur.network-policy

  If the stamp never appears, the reconciler's log names which check failed --
  and that is a containment problem in your cluster, not a deployment step you
  missed. VERIFY.md section 4 explains what it proves and what it does not.
AFTER
}

case "${1:-}" in
  --ask)        interview ;;
  --preflight)  load_values; render; preflight
                [ "$FAILED" -eq 0 ] || die "$FAILED precondition(s) unmet; nothing was applied" ;;
  "")           load_values; render; preflight
                [ "$FAILED" -eq 0 ] || die "$FAILED precondition(s) unmet; nothing was applied"
                apply ;;
  *)            die "usage: deploy.sh [--ask|--preflight]" ;;
esac

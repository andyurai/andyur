#!/usr/bin/env bash
# RC gate line 5, performed rather than described: a party holding ONLY the
# bundle, on a machine with no checkout, verifies it and deploys it WITH THE
# BUNDLE'S OWN INSTALLER.
#
# The bundle is what a design partner receives -- images plus signed manifests
# and `deploy.sh`, no source. This gate is the only place that answers the
# question that matters after "is it complete?", which is "does it come up in
# somebody else's hands?" -- and it found four defects the completeness scan
# could not see: a manifest whose profile could not boot, a readiness probe
# that could never pass, an OOMKilled sidecar and a registry the server
# refused to verify.
#
#   ./infra/rc/verify-partner-deploy.sh <bundle-dir>
#
# It COPIES the bundle to a scratch directory outside any checkout and works
# only from there, so "the deployer has no source" is a property of the
# environment rather than a promise about what the script happens to touch.
#
# WHAT CHANGED, AND WHY (the 2026-08-30 readiness review's finding). This gate
# used to verify two of the five signed files, apply ONE of the three manifests
# by hand with `kubectl apply`, and never run `deploy.sh` at all. So the bundle
# grew an installer, an IdP and an observability stack that NOTHING exercised:
# the gate was green on a path no partner takes. Three properties follow from
# that, and each is now a section below:
#
#   every signed file is verified   -- a signature nobody checks is decoration,
#                                      and the set is derived FROM THE BUNDLE
#                                      rather than listed here, so a file added
#                                      to the bundle cannot escape by being
#                                      absent from this script
#   the installer is what deploys   -- including its interview, its render and
#                                      its preflight, because those are what a
#                                      partner's deployment actually depends on
#   everything shipped is applied   -- idp.yaml and observability.yaml included;
#                                      shipping a manifest no gate applies is
#                                      shipping an untested manifest
#
# THE ANSWERS THIS GATE GIVES THE INTERVIEW are this machine's, from the
# environment, and they are the only workload-specific thing here. A partner
# gives their own; the questions, the render and the preflight are the same.
set -uo pipefail
BUNDLE="${1:?usage: verify-partner-deploy.sh <bundle-dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok(){  printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# The interview's answers for THIS cluster. Named here rather than buried in a
# heredoc so the one machine-specific part of this gate is visible.
ANS_REGISTRY="${ANDYUR_PARTNER_REGISTRY:-localhost:5000}"
ANS_REGISTRY_CIDR="${ANDYUR_PARTNER_REGISTRY_CIDR:-192.168.5.2/32}"
ANS_CATALOG="${ANDYUR_PARTNER_CATALOG:-${ANDYUR_RC_REGISTRY_REF:-}}"
# The model host. Its own question, because it is its own NetworkPolicy rule;
# on this single-machine reference deployment it happens to be the registry.
ANS_MODEL_CIDR="${ANDYUR_PARTNER_MODEL_CIDR:-$ANS_REGISTRY_CIDR}"
ANS_TRUST_DOMAIN="${ANDYUR_PARTNER_TRUST_DOMAIN:-andyur.local}"
ANS_SPIRE_NS="${ANDYUR_PARTNER_SPIRE_NAMESPACE:-spire-system}"
ANS_SPIRE_RELEASE="${ANDYUR_PARTNER_SPIRE_RELEASE:-andyur-spire}"
ANS_SYSTEM_NS="${ANDYUR_KUBERNETES_SYSTEM_NAMESPACE:-andyur-system}"
ANS_RUNS_NS="${ANDYUR_KUBERNETES_NAMESPACE:-andyur-runs}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/andyur-partner-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cp -R "$BUNDLE"/. "$WORK/" || { echo "cannot read bundle $BUNDLE"; exit 1; }

say "1. the deployer has the bundle and nothing else"
cd "$WORK" || exit 1
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  bad "this directory is inside a git checkout; the property under test is absent"
else
  ok "no checkout is reachable from $WORK"
fi
# The completeness scan is the BUILD side's, run from HERE because the deployer
# does not have it -- that is the point of it being a .py, and why every check
# below this line uses only what the bundle carries.
if python3 "$HERE/infra/rc/verify_bundle.py" "$WORK" >/dev/null; then
  ok "the bundle is complete and carries no source (build-side scan)"
else
  bad "verify_bundle refused the bundle"
fi

say "2. every signed file verifies, and the set comes from the bundle"
# --insecure-ignore-tlog is expected: these signatures are deliberately not in
# a public transparency log, because publishing one would publish a record of
# every digest shipped. VERIFY.md says the same to the deployer.
#
# DERIVED, NOT LISTED. The previous version named two files, so idp.yaml,
# observability.yaml and deploy.sh shipped signed and unchecked for as long as
# they existed. Every `*.cosign-bundle.json` in the bundle must verify against
# the file it signs, AND every file a partner is asked to trust must have one --
# so neither an unverified signature nor an unsigned manifest can pass.
signed_found=0; sig_fail=0
for sig in "$WORK"/*.cosign-bundle.json; do
  [ -e "$sig" ] || continue
  f="$(basename "${sig%.cosign-bundle.json}")"
  signed_found=$((signed_found+1))
  if cosign verify-blob --key cosign.pub --bundle "$f.cosign-bundle.json" \
       --insecure-ignore-tlog=true "$f" >/dev/null 2>&1; then
    ok "$f verifies"
  else
    bad "$f does NOT verify"; sig_fail=1
  fi
done
[ "$signed_found" -gt 0 ] || { bad "the bundle carries no signatures at all"; sig_fail=1; }
# The other direction: nothing a partner must trust may arrive unsigned.
for must in control-plane.yaml idp.yaml observability.yaml run-isolation.yaml deploy.sh release-manifest.json; do
  if [ ! -f "$WORK/$must" ]; then
    bad "$must is not in the bundle"; sig_fail=1
  elif [ ! -f "$WORK/$must.cosign-bundle.json" ]; then
    bad "$must ships WITHOUT a signature"; sig_fail=1
  fi
done
# Scoped to THIS section's own failures. Reading the gate-wide $FAIL here would
# have made section 1's verdict decide section 2's, which is how a check comes
# to report something it did not measure.
[ "$sig_fail" = 0 ] && ok "$signed_found signed file(s), and every file a partner must trust is one of them"

say "3. every image is a digest nobody has to trust a tag for"
# ALL THREE MANIFESTS, not just the control plane. idp.yaml runs Keycloak and
# Postgres in this cluster; an unpinned tag there is exactly as repointable as
# an unpinned tag in the control plane, and nothing checked it.
# PARSED, NOT GREPPED, and this gate had to learn it a second time.
#
# `verify_bundle.images_in` reads the YAML and returns what a manifest actually
# RUNS -- a container's `image`, and the env values naming images the platform
# launches later. The first version of this section wrote its own
# `re.findall(r"image: (\S+)")` instead, and refused a perfectly good bundle
# because a COMMENT in control-plane.yaml contains the words
# "image: `brokerstate_server". verify_bundle.py carries a fix for exactly that
# and a paragraph explaining it; writing a second, worse copy here undid it.
#
# So the parser is imported rather than re-implemented. It is the BUILD side's
# module, used here the same way the completeness scan above is -- what a
# deployer can check with what they hold is sections 2, 4 and 5.
pinned=1
for manifest in control-plane.yaml idp.yaml observability.yaml run-isolation.yaml; do
  python3 - "$HERE/infra/rc" "$WORK/$manifest" <<'PY' || { bad "$manifest: an image is unpinned or still a placeholder"; pinned=0; }
import sys
sys.path.insert(0, sys.argv[1])
from verify_bundle import images_in

text = open(sys.argv[2]).read()
loose = [f"{where}: {image}" for where, image in images_in(text)
         if "@sha256:" not in image or "registry.example" in image]
if loose:
    sys.stderr.write("unpinned: %s\n" % ", ".join(sorted(loose)[:4]))
sys.exit(1 if loose else 0)
PY
done
[ "$pinned" = 1 ] && ok "every image in every shipped manifest is digest-pinned, none is a placeholder"

say "4. the installer's interview, answered"
[ -n "$ANS_CATALOG" ] || { bad "no agent catalog to answer question 3 with (set ANDYUR_PARTNER_CATALOG or ANDYUR_RC_REGISTRY_REF)"; }
# The answers go in on STDIN, in the order the interview asks. `bundled` for the
# IdP skips questions 4a-4d, which is why there are ten lines and not fourteen.
#
# AND THEN THE FILE IS READ BACK, because feeding an ordered list of answers to
# an interview is exactly the shape that mis-answers silently when a question is
# INSERTED: a tenth question (the model host) went in ahead of the IdP, so
# `bundled` answered it, every answer after that shifted by one, and the last
# question fell off the end and took its default. Nothing failed. The comment
# here used to claim the render would catch it; the render checks addresses and
# images, and every shifted answer was still a plausible address or name.
#
# So the check is what it should always have been: the values file must contain
# the answers that were given.
answers=("$ANS_REGISTRY" "$ANS_REGISTRY_CIDR" "$ANS_CATALOG" "$ANS_MODEL_CIDR" "bundled" \
         "$ANS_TRUST_DOMAIN" "$ANS_SPIRE_NS" "$ANS_SPIRE_RELEASE" "$ANS_SYSTEM_NS" "$ANS_RUNS_NS")
printf '%s\n' "${answers[@]}" | bash "$WORK/deploy.sh" --ask > "$WORK/ask.log" 2>&1
if [ ! -f "$WORK/andyur.values.yaml" ]; then
  bad "deploy.sh --ask produced no values file"; tail -8 "$WORK/ask.log" | sed 's/^/      /'
else
  values="$(cat "$WORK/andyur.values.yaml")"
  misplaced=0
  for answer in "${answers[@]}"; do
    printf '%s' "$values" | grep -qF -- "$answer" || {
      bad "the answer '$answer' is not in andyur.values.yaml: the interview and this gate disagree about the ORDER of the questions"
      misplaced=1
    }
  done
  [ "$misplaced" = 0 ] && ok "deploy.sh --ask wrote andyur.values.yaml, and every answer landed where it was meant to"
fi

say "5. the installer's own preflight, which changes nothing"
if bash "$WORK/deploy.sh" --preflight > "$WORK/preflight.log" 2>&1; then
  ok "preflight passed: the cluster meets what the bundle requires"
else
  bad "preflight refused this cluster"; tail -12 "$WORK/preflight.log" | sed 's/^/      /'
fi

say "6. deploy it, with the bundle's installer and not by hand"
if bash "$WORK/deploy.sh" > "$WORK/deploy.log" 2>&1; then
  ok "deploy.sh applied the bundle"
else
  bad "deploy.sh failed"; tail -20 "$WORK/deploy.log" | sed 's/^/      /'
fi
# EVERYTHING THE BUNDLE SHIPS REACHED THE CLUSTER. `deploy.sh` reports its own
# applies; this checks the API server instead, because a script's account of
# what it did is the thing under test.
NS="$ANS_SYSTEM_NS"
for object in statefulset/andyur-server statefulset/andyur-worker deployment/andyur-operator \
              deployment/andyur-netpol-reconciler \
              deployment/andyur-keycloak statefulset/andyur-keycloak-db \
              deployment/otel-collector deployment/andyur-jaeger; do
  if kubectl get "$object" -n "$NS" >/dev/null 2>&1; then
    ok "$object exists (${object%%/*} from the bundle's manifests)"
  else
    bad "$object is absent: a manifest the bundle ships did not reach the cluster"
  fi
done

say "7. it comes up, and it is the bundle's own images that are running"
TIMEOUT="${ANDYUR_PARTNER_DEPLOY_TIMEOUT:-300}"
# WAIT FOR THE ROLLOUT, NOT JUST FOR READINESS. Read the pods straight after
# `kubectl apply` and you are reading the PREVIOUS generation: a manifest whose
# images cannot be pulled at all reports a Ready control plane and matching
# digests, because nothing has restarted yet. Found by mutating a bundle to
# carry a placeholder image and watching this gate pass it.
for workload in statefulset/andyur-server statefulset/andyur-worker deployment/andyur-operator; do
  if kubectl rollout status "$workload" -n "$NS" --timeout="${TIMEOUT}s" >/dev/null 2>&1; then
    ok "$workload rolled out to the applied generation"
  else
    bad "$workload never reached the applied generation"
  fi
done
states="$(kubectl get pod andyur-server-0 -n "$NS" -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null)"
case "$states" in
  *false*|"") bad "the control plane is not Ready ($states)" ;;
  *) ok "the control plane is Ready" ;;
esac

wanted="$(python3 -c '
import json, sys
m = json.load(open(sys.argv[1] + "/release-manifest.json"))
print(" ".join(sorted(a["extra"]["pullable_as"] for a in m["artifacts"]
                      if a["kind"] == "container-image" and "pullable_as" in a.get("extra", {}))))
' "$WORK")"
running="$(kubectl get pod andyur-server-0 andyur-worker-0 -n "$NS" \
  -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null | sort -u)"
missing=0
for image in $wanted; do
  case "$image" in *andyur-runner@*) continue ;; esac   # the runner is launched per run, not by a Pod here
  # The installer RE-HOMES images to the registry the deployer named, keeping
  # the digest. The digest is the identity, so that is what must match -- the
  # previous check compared whole references and would have failed any partner
  # who pushed the same images to their own registry, which is the supported
  # case this gate exists to prove.
  digest="${image##*@}"
  printf '%s\n' "$running" | grep -qF "$digest" || { bad "the cluster is not running $digest ($image)"; missing=1; }
done
[ "$missing" = 0 ] && ok "the running control plane is exactly the bundle's digests"

say "result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1

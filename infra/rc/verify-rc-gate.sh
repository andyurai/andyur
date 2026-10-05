#!/usr/bin/env bash
# THE RC GATE: thirteen lines, one tree, one artifact, one question -- can the
# supported MVP safely ship?
#
# Every line here already had a gate. What did not exist was a run of all of
# them AGAINST ONE FROZEN TREE: today's greens were spread across four commits,
# and "the suite passed on Tuesday and the cluster gate on Wednesday" is not
# the same claim as "this tree is releasable". A release candidate is a
# statement about ONE commit, so this refuses a dirty tree and records the SHA
# it certified beside every result.
#
#   ./infra/rc/verify-rc-gate.sh
#
# Inputs it will not guess, because guessing them is how a gate certifies
# something other than what ships:
#
#   ANDYUR_RC_REGISTRY      registry to push release images to (localhost:5000)
#   ANDYUR_RC_REGISTRY_REF  the governed agent-catalog snapshot, pinned by digest
#   ANDYUR_RC_REGISTRY_HTTP on   when that registry is plain HTTP
#   ANDYUR_RC_REGISTRY_TLOG off  when its snapshot is signed with a local key
#   ANDYUR_RC_SKIP          comma-separated line ids to skip (a skip is NO-GO)
#   ANDYUR_RC_REGISTRY_COSIGN_PUB  the agent catalog's public verification key,
#                           which ships in the bundle so a deployer can verify
#                           the catalog the manifest names
#   ANDYUR_RC_RELEASE_DOCKER_HOST
#                           the daemon to BUILD AND PUSH the release with, when
#                           it is not the default one. Two daemons is not a
#                           quirk of this machine: the conformance and identity
#                           lines reach their harness through
#                           host.docker.internal, and the release must push to
#                           a registry the cluster's nodes can pull from. One
#                           DOCKER_HOST for the whole run would silently give
#                           one of them the wrong daemon.
#
# PREREQUISITES, all checked by the lines that need them rather than here:
# a reachable Kubernetes context, the host control plane for the console line
# (./run.sh up), Ollama with the workloads' model, and Jaeger.
#
# A skipped line is NOT a passed line. The artifact records it as skipped and
# the verdict is NO-GO, because the only reason to build this was that the
# they were being asserted from memory.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$HERE" || exit 1
SKIP=",${ANDYUR_RC_SKIP:-},"
ONLY="${ANDYUR_RC_ONLY:-}"
REGISTRY="${ANDYUR_RC_REGISTRY:-}"
REGISTRY_REF="${ANDYUR_RC_REGISTRY_REF:-}"
OUT="${ANDYUR_RC_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/andyur-rc-XXXXXX")}"
PY="${ANDYUR_PY:-$HERE/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

say(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
green(){ printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
red(){   printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
grey(){  printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }

RESULTS="$OUT/lines.jsonl"
: > "$RESULTS"
# When THIS invocation began, so the verdict can tell a line it ran itself from
# one merged in from an earlier run of the same commit.
RC_STARTED_AT="$(date +%s)"

# WHAT EACH LINE NEEDS TO BE ABLE TO ANSWER AT ALL. When a line fails, the
# environment it depends on is probed, and a line whose environment has GONE is
# recorded `unavailable` rather than `fail`.
#
# That distinction is the whole point: this machine's k3s stalls under sustained
# load (production-gaps row 22), and it stalled during the gate's own run -- so
# five lines "failed" with `Unable to connect to the server: EOF`. Recording an
# infrastructure stall as a product failure is a FALSE RED, the exact mirror of
# the false greens this repository has spent a week closing, and it would send
# the next person to debug a rollback that never ran.
#
# `unavailable` is still NOT a pass and still NO-GO. It names the cause.
env_up() {
  case "$1" in
    cluster) kubectl get --raw /readyz >/dev/null 2>&1 ;;
    docker)  docker info >/dev/null 2>&1 ;;
    host)    curl -sf "${ANDYUR_SERVER_URL:-http://127.0.0.1:8642}/health" >/dev/null 2>&1 ;;
    *)       return 0 ;;
  esac
}

# HOW MANY LINES THERE ARE IS COUNTED, NOT TYPED. The verdict used to require
# `len(passed) == 12`, with 12 written in three places -- so adding a thirteenth
# line would have produced a GO on twelve of thirteen, silently, in the one
# artifact whose entire purpose is to not be believed on trust.
DECLARED=0
line() {  # id  environment  title  command...
  local id="$1" env="$2" title="$3"; shift 3
  DECLARED=$((DECLARED + 1))
  if [ -n "$ONLY" ]; then
    case ",$ONLY," in *",$id,"*) ;; *) return 0 ;; esac
  fi
  case "$SKIP" in *",$id,"*)
    grey "$id  $title"
    printf '{"id":"%s","title":"%s","outcome":"skipped"}\n' "$id" "$title" >> "$RESULTS"
    return 0 ;;
  esac
  say "$id  $title"
  local started=$SECONDS log="$OUT/$id.log"
  "$@" > "$log" 2>&1
  local rc=$? seconds=$((SECONDS - started)) outcome
  if [ "$rc" -eq 0 ]; then
    outcome=pass; green "$id in ${seconds}s"
  elif ! env_up "$env"; then
    outcome=unavailable
    printf '  \033[33mUNAVAILABLE\033[0m  %s: its %s is not reachable, so this line could not answer\n' "$id" "$env"
  else
    outcome=fail; red "$id exited $rc after ${seconds}s (see $log)"; tail -12 "$log" | sed 's/^/      /'
  fi
  # The COMMAND is recorded, not just the outcome: a line whose command changed
  # is a different line, and an artifact that says only "identity: pass" cannot
  # be checked by anyone later.
  # The log is recorded by NAME, not by path. $OUT is an operator-local
  # directory (a mktemp dir, or whatever ANDYUR_RC_OUT pointed at), the logs
  # themselves are never published, and the absolute path put the operator's
  # home directory and session id into a shipped release artifact. The file
  # name is the part that binds a line to its log; the rest was PII.
  "$PY" - "$id" "$title" "$rc" "$seconds" "$(basename "$log")" "$outcome" "$env" "$OUT" "$HERE" "$HOME" "$@" >> "$RESULTS" <<'PY'
import json, sys, time
id, title, rc, seconds, log, outcome, environment, out, here, home, *command = sys.argv[1:]
# $OUT is a mktemp dir and $HERE is wherever this checkout happens to live, so
# two runs of the SAME line recorded two different commands and neither could be
# compared to the other -- while also writing the operator's home directory into
# a shipped artifact. Substituting both back makes the record machine-independent
# AND comparable, which is the whole reason the command is recorded. $OUT first:
# it can sit under $HERE, and the narrower substitution has to win.
# Order is load-bearing: $OUT and $HERE can both sit under $HOME, so the
# narrower substitutions have to run first or $HOME swallows them.
command = [c.replace(out, "$ANDYUR_RC_OUT").replace(here + "/", "")
            .replace(home + "/", "~/")
           for c in command]
print(json.dumps({"id": id, "title": title, "outcome": outcome,
                  "environment": environment, "exit": int(rc),
                  "seconds": int(seconds), "log": log, "command": command,
                  "at_epoch": time.time()}, sort_keys=True))
PY
  return 0
}

say "the tree this certifies"
SHA="$(git -C "$HERE" rev-parse HEAD)"
ARTIFACT_DIR="$HERE/data/rc"
ARTIFACT="$ARTIFACT_DIR/result-rc-gate-$(date +%Y-%m-%d)-$(uname -s | tr A-Z a-z)-$(uname -m).json"
# A DIRTY TREE IS REFUSED, WITH ONE EXCEPTION THAT THE GATE ITSELF CREATES.
#
# A green run leaves the tree dirty by design: the live lines write evidence
# into it, and that evidence is the record of THIS commit's behaviour. So a
# resumed pass (ANDYUR_RC_ONLY) would refuse on the previous pass's own output,
# and the resume feature would be unusable -- which is what happened: pass A
# went green on six lines and pass B refused to start.
#
# The exception is exactly as wide as the problem: when resuming, a changed
# path is tolerated only if the artifact for THIS SAME COMMIT recorded it as
# evidence the gate produced. A source edit, a stray file, or a resume across
# commits still refuses, because what "one frozen tree" forbids is certifying
# two different trees as one.
dirty="$("$PY" "$HERE/infra/rc/uncertified_changes.py" "$HERE" "$ARTIFACT" "$SHA" "${ANDYUR_RC_ONLY:-}")"
if [ -n "$dirty" ]; then
  red "the working tree has uncommitted changes; an RC gate certifies a COMMIT"
  printf '%s\n' "$dirty" | head -10 | sed 's/^/  /'
  exit 2
fi
green "frozen at $SHA"

[ -n "$REGISTRY" ] || { red "set ANDYUR_RC_REGISTRY"; exit 2; }
[ -n "$REGISTRY_REF" ] || { red "set ANDYUR_RC_REGISTRY_REF"; exit 2; }

# ---- prerequisites the LINES need, brought up here so a missing one is a
# ---- named refusal at the start rather than a line failing in one second ---
say "prerequisites"
if ! docker inspect andyur-spire-server >/dev/null 2>&1; then
  bash infra/spire/docker/verify-slice3.sh up >/dev/null 2>&1 \
    && green "containerised SPIRE up (the credential and identity lines need it)" \
    || { red "could not start the containerised SPIRE stack"; exit 2; }
else
  green "containerised SPIRE already up"
fi
# The console line drives a HOST control plane. It is not started here on
# purpose: `run.sh up` backgrounds its processes in the caller's process group,
# so a stack started from inside this script dies with it -- which is exactly
# how the first full run of this gate reported the console line as "control
# plane not up" after the suite had been running for half an hour beside it.
if curl -sf "${ANDYUR_SERVER_URL:-http://127.0.0.1:8642}/health" >/dev/null 2>&1; then
  green "host control plane up (the console line needs it)"
else
  red "host control plane is not up: start it in its OWN session first --"
  red "  setsid ./run.sh up   (a plain ./run.sh up dies with the shell that ran it)"
  exit 2
fi

# ---- the lines ---------------------------------------------------------------
#
# ORDER IS LOAD-BEARING, and the first full run is what taught it:
#
#   the release refuses a dirty tree, and the LIVE GATES WRITE EVIDENCE INTO
#   THE TREE. Run them first and the release can never pass -- it reported six
#   untracked artifacts, five of which its own gate lines had just produced.
#
# So everything that certifies the COMMITTED tree runs first (suite, currency,
# release, and the deploy of what the release produced), and the live gates
# run afterwards against the images that deploy just installed. That ordering
# is stronger than the one it replaced: the in-cluster lines now exercise the
# exact images the release built, rather than whatever the cluster had.
# 1. The suite, in CI's own invocation. `run.sh test` execs the same one, and a
#    test in the suite pins that they agree -- a gate line that says the
#    definitions AGREE is not satisfied by a document describing how they differ.
line suite none "unit suite, CI's invocation" "$PY" -m pytest -q --timeout=300 -p no:randomly

# 2. Every artifact the tree ships still describes THIS tree.
line currency none "evidence currency" env PYTHONPATH=. "$PY" infra/rc/evidence_currency.py

# 3. The release itself: images included, pushed, signed.
RELEASE_OUT="$OUT/release"
release_flags=(--out "$RELEASE_OUT" --push-to "$REGISTRY" --registry-ref "$REGISTRY_REF")
# The catalog's PUBLIC verification key, into the bundle. Without it the bundle
# names a catalog the deployer cannot verify -- which is the gap the delivery
# path had: PREREQUISITES.md said the catalog "comes from us with the bundle",
# and neither it nor its key did.
[ -n "${ANDYUR_RC_REGISTRY_COSIGN_PUB:-}" ] \
  && release_flags+=(--registry-cosign-pub "$ANDYUR_RC_REGISTRY_COSIGN_PUB")
[ "${ANDYUR_RC_REGISTRY_HTTP:-off}" = "on" ] && release_flags+=(--registry-allow-http)
[ "${ANDYUR_RC_REGISTRY_TLOG:-on}" = "off" ] && release_flags+=(--registry-ignore-tlog)
line release docker "full image-inclusive release build, signed" \
  env DOCKER_HOST="${ANDYUR_RC_RELEASE_DOCKER_HOST:-${DOCKER_HOST:-}}" \
  "$PY" infra/rc/build_release.py "${release_flags[@]}"

# 4. A party holding only what the release produced can deploy it -- after
#    which the cluster is running exactly what the release built.
#
#    THIS USED TO RUN AFTER CONTAINMENT, and the inversion was a product fact
#    rather than a preference: the daemon refuses to start unless the run
#    namespace carries a NetworkPolicy verification stamp younger than 600 s
#    (kubernetes_api.assert_isolation_ready), nothing in a deployed cluster
#    renewed it, and only `verify-network-policy.sh` from a source checkout
#    could stamp. So a freshly applied worker crash-looped until the gate ahead
#    of it stamped, and `andyur-worker never reached the applied generation`
#    was true and was about the stamp rather than about the bundle.
#
#    The bundle now deploys `andyur-netpol-reconciler`, which re-proves
#    containment inside the run namespace and stamps on its own -- so the
#    inversion is gone, and with it the reason this gate could not start from a
#    torn-down cluster. Containment now runs AFTER the deploy, which is also
#    the only order in which it can run at all on a clean cluster: before the
#    deploy there is no run namespace to probe and no image to probe with.
line deploy cluster "a machine with no checkout deploys the bundle" \
  bash infra/rc/verify-partner-deploy.sh "$RELEASE_OUT/bundle"

# 5. Containment, proved the hard way: an active CNI probe with the allow-all
#    mutation that turns it red and back. The reconciler deliberately does not
#    run that mutation unattended; this line is where it is run, by a person, on
#    a release candidate.
line containment cluster "network containment, live CNI probe" \
  bash infra/rc/record-network-policy.sh

# 6. Credential confinement, on the same shared Docker/SPIRE stack as the
#    identity line below, so the two run one after another and never beside
#    each other.
line credentials docker "credential confinement, live, with a planted canary" \
  bash infra/verify-service-credential.sh

# 7. Identity and authority: one trace carrying the per-run identity decision.
line identity docker "identity and authority narrowing, end to end" \
  bash infra/spire/docker/verify-full-trace.sh

# 8. Stock-workload conformance.
line conformance docker "exec/v1 conformance for the stock workload" \
  bash infra/rc/record-conformance.sh demos/opensre alert.json

# 9-10. The runtime itself, with BOTH stock workloads: one proves exec/v1, two
#      prove it is not the workload.
line kubernetes cluster "governed Kubernetes runtime (Goose, in-cluster)" \
  bash infra/kubernetes/verify-exec-goose.sh
line opensre cluster "OpenSRE in-cluster, ADR-011 acceptance #1" \
  bash infra/kubernetes/verify-exec-opensre.sh

# 11. The MVP's differentiated claim.
line action cluster "consequential action: deny, allow, approve, against a real cluster" \
  bash infra/kubernetes/verify-consequential-action.sh

# 12. WHO ASKED. The action line above proves the DECISION against a real
#     cluster and is silent on who initiated it -- it drives the decision module
#     in-process with a hand-minted grant. This one proves a stock workload
#     initiated the request through the generic MCP tool path, and that the gate
#     could not have: POST /runs/{id}/actions refuses an operator outright.
line requested cluster "the AGENT initiated the action, through the generic tool path" \
  bash infra/kubernetes/verify-agent-requested-action.sh

# 13. The operator's surface, live.
line console host "console golden path through the real BFF" \
  bash infra/verify-console.sh

# ---- the verdict ----------------------------------------------------------
# The verdict lands in the gitignored data directory -- the path is set at the
# top, beside the frozen-tree check that needs it -- because a verdict left in
# the TREE is release-blocking evidence the moment any gate it binds changes,
# and the release line is inside this gate.
mkdir -p "$ARTIFACT_DIR"
git -C "$HERE" status --porcelain > "$OUT/tree-after.txt"
export RC_DECLARED="$DECLARED" RC_ONLY="$ONLY" RC_STARTED_AT
"$PY" - "$SHA" "$RESULTS" "$ARTIFACT" "$OUT" <<'PY'
import hashlib, json, os, platform, subprocess, sys, time
sha, results, artifact, out = sys.argv[1:5]
lines = [json.loads(l) for l in open(results) if l.strip()]
# MERGE WITH AN EARLIER RUN OF THE SAME COMMIT, and only the same commit.
#
# Twelve lines cannot always be run in one pass here: the local cluster stalls
# under sustained load, and a line that could not answer must be re-run rather
# than argued about. Re-running a subset (ANDYUR_RC_ONLY) against the SAME
# frozen tree is legitimate -- what "one frozen tree" forbids is greens from
# DIFFERENT trees, so the merge refuses the moment the commit differs, and
# every line carries the time it was actually run.
if os.path.exists(artifact):
    previous = json.load(open(artifact))
    if previous.get("frozen_commit") == sha:
        fresh = {l["id"] for l in lines}
        lines += [l for l in previous.get("lines", []) if l["id"] not in fresh]
    else:
        print(f"(earlier artifact is for {previous.get('frozen_commit', '?')[:12]}, "
              f"not this tree; starting fresh)")
passed = [l for l in lines if l["outcome"] == "pass"]
failed = [l for l in lines if l["outcome"] == "fail"]
skipped = [l for l in lines if l["outcome"] == "skipped"]
unavailable = [l for l in lines if l["outcome"] == "unavailable"]
# EVERY DECLARED LINE, all passed, all on this commit. Anything else is NO-GO --
# a skipped line and a line whose environment vanished are both "we do not
# know", and the only reason this gate exists is that "we do not know" was being
# carried as "fine". The count comes from the gate's own declarations
# (RC_DECLARED), so adding a line raises the bar instead of leaving a GO that
# means one line fewer than it says.
declared = int(os.environ.get("RC_DECLARED") or 0) or len(lines)
# WAS THIS ONE PASS, OR SEVERAL MERGED? A resumed run (ANDYUR_RC_ONLY) re-runs a
# subset against the same frozen tree and merges with what an earlier run of the
# SAME COMMIT recorded. That is legitimate and it is not the same claim: "these
# thirteen passed together, from a clean start" is a stronger statement than
# "these thirteen have each passed at some point on this commit". The artifact
# said neither -- both produced an identical GO -- so a reader could not tell
# which one they were holding. Now it says.
resumed = bool(os.environ.get("RC_ONLY"))
# Lines whose recorded run predates THIS invocation came from the merge.
STARTED_AT = float(os.environ.get("RC_STARTED_AT") or 0)
merged_in = sorted(l["id"] for l in lines if l.get("at_epoch", 0) < STARTED_AT)
verdict = ("GO" if len(passed) == declared and not failed and not skipped
           and not unavailable else "NO-GO")
doc = {
    "gate": "rc",
    "schema": "andyur.rc-gate/v1",
    "frozen_commit": sha,
    "frozen_subject": subprocess.run(
        ["git", "log", "-1", "--format=%s", sha], capture_output=True,
        text=True).stdout.strip(),
    "host": platform.platform(),
    "finished_at_epoch": time.time(),
    "lines": sorted(lines, key=lambda l: l["id"]),
    "passed": len(passed), "failed": len(failed), "skipped": len(skipped),
    "unavailable": len(unavailable),
    # A skipped line is not a passed line, and the number is counted rather
    # than typed. Both are in the verdict rather than in a reader's head.
    "verdict": verdict,
    "declared_lines": declared,
    # THE TWO FACTS A READER OF THIS FILE MOST NEEDS AND COULD NOT GET.
    "resumed": resumed,
    "lines_merged_from_an_earlier_run": merged_in,
    "single_pass": not resumed and not merged_in,
    "ok": verdict == "GO",
    # Basename only, for the same reason the per-line log is: see run_line.
    "logs": os.path.basename(out),
    # WHAT THE RUN ITSELF PRODUCED. The live lines write evidence into the
    # tree, so a green run leaves it dirty by design -- and that evidence is
    # the record of THIS commit's behaviour, which the operator commits next.
    # Naming the files here is the difference between "commit the new evidence"
    # and an operator guessing which of six untracked paths belong to the gate.
    # THE PROGRAMS THIS VERDICT IS ABOUT. Every other gate binds its evidence
    # to the source it exercised; this one exercises EVERY GATE IT RAN, so it binds
    # to them -- and an RC verdict then goes STALE the moment any gate it ran
    # changes, which is exactly right. Without it the verdict was UNBOUND: a
    # release decision nobody could check.
    "source_sha256": {
        path: hashlib.sha256(open(path, "rb").read()).hexdigest()
        for path in sorted({
            arg for line in lines for arg in line.get("command", [])
            if "/" in arg and not arg.startswith("/") and os.path.isfile(arg)
        } | {"infra/rc/verify-rc-gate.sh"})
    },
    # STRIPPED. These carried a trailing newline, so the resume check --
    # which compares them against `git status` output that has none -- could
    # never match one, and a resumed pass would refuse on exactly the evidence
    # the previous pass produced. It fails closed, so it cost a feature rather
    # than the truth, but a list that cannot match anything is not a record.
    "evidence_produced": sorted(
        line.split(maxsplit=1)[1].strip() for line in open(out + "/tree-after.txt")
        if line.strip() and ("result-" in line or "/evidence/" in line)),
}
open(artifact, "w").write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
print(f"\n{'=' * 68}")
print(f"RC GATE {verdict}: {len(passed)} passed, {len(failed)} failed, "
      f"{len(unavailable)} unavailable, {len(skipped)} skipped, of {declared}")
if resumed or merged_in:
    print(f"  RESUMED: {len(merged_in)} line(s) came from an earlier run of this "
          f"same commit ({', '.join(merged_in) or 'none recorded'}).")
    print("  This is NOT one pass from a clean start; the artifact says so too.")
else:
    print("  one pass, from a clean start")
for l in lines:
    mark = {"pass": "  ok  ", "fail": " FAIL ", "skipped": " skip ",
            "unavailable": " n/a  "}[l["outcome"]]
    print(f"  [{mark}] {l['id']:<12} {l['title']}")
print(f"frozen at {sha[:12]}")
print(f"wrote {artifact}")
if verdict == "GO":
    print("PUBLISH IT BESIDE THE TAG -- the verdict lives in a gitignored")
    print("directory so a green run does not itself block the next release:")
    print(f"  {sys.executable} infra/rc/publish-verdict.py {artifact} <tag>")
sys.exit(0 if verdict == "GO" else 1)
PY

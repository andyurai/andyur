#!/usr/bin/env bash
# THE UID SPLIT, EXECUTED. Does the agent actually fail to read the runner's
# secrets, on Linux, in the real run container, DROPPED THE WAY PRODUCTION DROPS?
#
# WHY THIS IS THE MOST IMPORTANT HARNESS IN THE REPOSITORY. Every credential
# claim Andyur makes reduces to one kernel behaviour: /proc/<pid>/environ, mem
# and fd are readable only by the process owner, so an agent at uid 1001 cannot
# reach a runner at uid 0. The broker holds the provider key because the runner
# can be trusted with it; the model proxy holds the broker credential for the
# same reason; the run-token seal assumes the same thing. All of it rests on a
# permission check that had never been run on Linux -- every earlier test ran on
# macOS, where /proc does not exist and the mechanism is not the same one.
#
# THREE DESIGN RULES, learned by red teams getting this harness to certify a
# broken boundary:
#
#  1. The agent probe runs THROUGH THE PRODUCTION WRAPPER
#     (/usr/local/bin/andyur-agent-claude), not a hand-written setpriv. An
#     earlier version dropped uid itself, "byte for byte what the wrapper does"
#     -- a second source of truth for the one line that matters, exactly what
#     this harness reads _sandbox_argv (daemon/orchestrator.py) to avoid for the
#     container flags. It then
#     certified PASSED on an image whose wrapper did not drop uid at all. Now a
#     sabotaged or missing wrapper makes the agent probe run as root, read every
#     secret, and FAIL every assertion.
#
#  2. Every must-be-BLOCKED vector is paired with a root run that must READ. A
#     probe that only ever runs as the agent proves nothing when everything
#     fails, because "cannot read" and "my script is broken" are the same
#     output. Root is required to succeed on environ, mem, fd, ptrace, cwd and
#     escalate; if it cannot, the probe is broken and the harness refuses to
#     certify anything.
#
#  3. THE FILESYSTEM IS A VECTOR TOO. Rules 1 and 2 were learned about PROCESSES,
#     and so was every original probe: they read /proc, memory, an fd table or an
#     argv, and not one of them opens a file on disk. That let a whole class
#     hide. The runner writes its X509-SVID private key to a FILE -- uvicorn's
#     --ssl-keyfile and httpx's load_cert_chain take paths, not key objects -- and
#     it landed 0644 in a 0755 directory, readable by the agent and invisible to
#     every assertion in this file. The filesystem sweep below closes the class,
#     under the same discipline: it runs as the agent uid through the production
#     wrapper, it must prove it actually walked the tree, and it must detect a
#     planted key and a planted credential file or its clean verdict is refused.
#
# THE TRUST BOUNDARY, and it is not a limitation to paper over. This harness
# certifies that an image of TRUSTED PROVENANCE -- one built from this repo's
# Dockerfile.runner, as CI does before it runs this -- correctly implements the
# uid split. It catches misconfiguration, regression, and tampering with the
# WRAPPER (eight red-team rounds, all closed). It does NOT and CANNOT detect a
# maliciously BUILT image that swaps a base binary the wrapper or this harness
# relies on: /bin/sh, setpriv, cmp, python, libc. A red team proved the general
# case -- a trojan setpriv that does the honest drop for the harness's own
# invocations (which always override the exec target with a script) and stays
# root only when the target is the real claude ELF. No content inspection run
# from INSIDE a hostile image is sound, because every tool the inspection uses is
# a tool the attacker also controls, and the malicious component can always
# detect the test. Pinning the wrapper text harder cannot fix this; it is a
# different control. The defense against a trojaned image is PROVENANCE: build
# the runner image in trusted CI from the pinned Dockerfile, sign it, and deploy
# by digest so the running image is verifiably the one that was reviewed. That is
# tracked as its own gap (image provenance / signing) in ROADMAP.md.
# Read every PASS here as "the uid split holds in THIS image"; read "this image
# is the one we built and shipped" off the image's signature, not off this file.
#
#   ./run.sh uid-verify
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

VENV="$HERE/.venv"
IMAGE="${ANDYUR_SANDBOX_IMAGE:-andyur-runner}"
CONTAINER="andyur-uid-boundary"
# Distinctive, and NOT a real credential: the point is to trace a string. Two
# suffixes so the sweep's own positive control can plant a DISTINCT value and
# prove it found that one, not an inherited copy of the shared canary.
CANARY="CANARY-uid-boundary-7f3a91"
PLANT="CANARY-planted-only-2b5e"

WORKDIR="$(mktemp -d)"     # never a predictable /tmp path a stale file can hide in
trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1; rm -rf "$WORKDIR"; true' EXIT

PASS=0; FAIL=0
ok()   { printf '    \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '    \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

command -v docker >/dev/null 2>&1 || { echo "docker required"; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || { echo "image '$IMAGE' not found; run ./run.sh sandbox-image"; exit 1; }

# ---------------------------------------------------------------------------
step "the image under test is built from the code under test"
# An image is a stand-in for the source unless something checks. The first run
# of this harness tested a three-hour-old image and the stand-in died on the
# very function the day's fix had added. Same hash algorithm both sides,
# computed by the image's own python so there is no md5-vs-md5sum question.
HASHER='
import hashlib, os, sys
root = sys.argv[1]; h = hashlib.sha256()
for dp, dns, fns in sorted(os.walk(root)):
    dns[:] = sorted(d for d in dns if d != "__pycache__")
    for name in sorted(fns):
        if name.endswith(".py"):
            p = os.path.join(dp, name)
            h.update(os.path.relpath(p, root).encode()); h.update(open(p, "rb").read())
print(h.hexdigest()[:16])
'
LOCAL_HASH=$("$VENV/bin/python" -c "$HASHER" "$HERE/andyur")
IMAGE_HASH=$(docker run --rm --entrypoint python "$IMAGE" -c "$HASHER" /app/andyur 2>/dev/null | tr -d '\r')
if [ -n "$IMAGE_HASH" ] && [ "$LOCAL_HASH" = "$IMAGE_HASH" ]; then
  ok "image source matches the working tree ($LOCAL_HASH)"
else
  bad "image is STALE (image $IMAGE_HASH vs source $LOCAL_HASH): run ./run.sh sandbox-image"
  echo "        refusing to certify the boundary in a build that is not the code under test"
  exit 1
fi

# ---------------------------------------------------------------------------
step "the image is CONFIGURED for the uid split"
# The split fails OPEN: driver._uid_split_on() is False when the wrapper env var
# is unset, and then the SDK spawns the agent as the runner's own uid, silently.
# A red team removed the wrapper and this harness still passed, because it did
# its own setpriv. Assert the image's own view before trusting the drop.
SPLIT=$(docker run --rm --entrypoint python "$IMAGE" -c \
  "import sys; sys.path.insert(0,'/app'); from andyur.runner import driver; \
print(driver._uid_split_on(), driver.AGENT_CLI)" 2>/dev/null | tr -d '\r')
case "$SPLIT" in
  "True /usr/local/bin/andyur-agent-claude")
    ok "driver reports the uid split ON, wrapper at the expected path" ;;
  *)
    bad "driver does not report a configured uid split: '$SPLIT'"
    echo "        the agent would run as the runner uid; refusing to certify"
    exit 1 ;;
esac

# THE WRAPPER MUST BE AN UNCONDITIONAL DROP, pinned byte-exact. This closes the
# whole argv/env-conditional class at its root: six red-team rounds each found a
# wrapper that drops for the harness's inputs and stays root for production's
# (keyed on ANDYUR_CLAUDE_BIN, a `--` flag, --input-format, --max-turns,
# --mcp-config, and finally a branch smuggled past comment-parsing). The dynamic
# test below chases each behaviourally; this refuses the SHAPE that makes it
# possible. The wrapper is generated by our Dockerfile and is NOT covered by the
# source-hash gate (which hashes only /app/andyur), so an image FROM
# andyur-runner can swap it freely -- exactly what every bypass did. The wrapper
# may be only full-line comments, an optional `set -e`-family line, and ONE
# byte-exact `exec setpriv --reuid=1001 ... "${ANDYUR_CLAUDE_BIN:-<target>}" "$@"`.

# The wrapper's default target, resolved independently so a wrapper that baked a
# DIFFERENT one fails the byte-exact check below. Also used by the dynamic test.
CLAUDE_PATH=$(docker run --rm --entrypoint sh "$IMAGE" -c 'command -v claude' 2>/dev/null | tr -d '\r')
[ -n "$CLAUDE_PATH" ] || { bad "cannot resolve the wrapper's default target in the image"; exit 1; }
# Script in a FILE, wrapper content on stdin. `python - <<HEREDOC` consumes stdin
# for the script, so sys.stdin.read() would get nothing (it did: "EXECS 0" on the
# legit wrapper). A file leaves stdin free for the pipe.
cat > "$WORKDIR/check_wrapper.py" <<'PY'
import re, sys
# BYTE-EXACT on the executable lines, NOT a heuristic parse of shell syntax.
# Six rounds taught that any regex modelling of comments/quoting has a seam: the
# last bypass hid a branch in `set -e#; ... && exec claude` because the inline
# `#` is not a shell comment when glued to a word. So do not try to strip inline
# comments at all. Strip only FULL-LINE comments -- a line whose first
# non-whitespace character is `#`, which IS unambiguously a shell comment -- and
# require every remaining (executable) line to EQUAL a canonical line exactly.
# A smuggled `set -e#; branch` is not a full-line comment, so it is an
# executable line, and it does not equal "set -e"; refused. Anything appended,
# any extra statement, any altered flag or target changes a byte and is refused.
path = sys.argv[1]                                  # resolved default target
canonical_exec = ('exec setpriv --reuid=1001 --regid=1001 --clear-groups '
                  '"${ANDYUR_CLAUDE_BIN:-%s}" "$@"' % path)
lines = sys.stdin.read().splitlines()

# THE SHEBANG IS EXECUTABLE METADATA, NOT A COMMENT, and pinning the body while
# folding the shebang into the comment skip is how a red team certified a green
# boundary on an image that runs the agent as root. `#!/usr/local/bin/evil`
# starts with `#`, so it was skipped like any comment; the pin then validated a
# perfect `set -e` + canonical-exec BODY -- which the kernel never runs, because
# it hands the whole file to /usr/local/bin/evil (root, every spawn). The body it
# checks is a decoration. Pin the interpreter explicitly, as the FIRST line, to
# exactly the shebang our Dockerfile emits.
if not lines or lines[0].rstrip() != "#!/bin/sh":
    print("SHEBANG " + repr(lines[0] if lines else "")); sys.exit()

exe = []
for raw in lines[1:]:
    s = raw.strip()
    if not s or s.startswith("#"):                  # blank or full-line comment
        continue
    exe.append(s)
# An optional `set -e`-family line may precede the one exec.
if exe and re.fullmatch(r"set -[eux]+", exe[0]):
    exe = exe[1:]
if exe == [canonical_exec]:
    print("OK")
else:
    print("MISMATCH executable lines were: " + " | ".join(exe))
PY
WRAP=$(docker run --rm --entrypoint cat "$IMAGE" /usr/local/bin/andyur-agent-claude 2>/dev/null)
# CLAUDE_PATH is resolved independently (command -v claude), so a wrapper that
# baked a DIFFERENT default target fails the byte-exact match -- closing the
# "baked path differs from command -v claude" question too.
wrap_verdict=$(printf '%s' "$WRAP" | "$VENV/bin/python" "$WORKDIR/check_wrapper.py" "$CLAUDE_PATH")
[ "$wrap_verdict" = "OK" ] \
  && ok "the wrapper is a single unconditional setpriv drop (no branch can keep root)" \
  || { bad "the wrapper is not a plain unconditional drop: $wrap_verdict"; \
       echo "        a conditional wrapper can run the real agent as root; refusing to certify"; exit 1; }

# ...and the wrapper actually drops ON THE PATH PRODUCTION USES. This is the
# subtle one, and an earlier version got it wrong: it invoked the wrapper with
# ANDYUR_CLAUDE_BIN=/usr/bin/id, but the real SDK spawns the wrapper with that
# variable UNSET (driver._subprocess_env sets HOME and nothing else). A wrapper
# whose drop is CONDITIONAL on ANDYUR_CLAUDE_BIN -- drop when set, stay root on
# the default path -- then passed the test and ran the real agent as root. A red
# team built exactly that and got a full 32/32 PASSED on it.
#
# So drive the DEFAULT path: shadow the baked target (`$CLAUDE_BIN`, resolved
# here) with a uid-printer and invoke the wrapper with ANDYUR_CLAUDE_BIN unset,
# which is byte-for-byte the production spawn. The conditional wrapper yields 0
# here and is refused.
#
# WITH THE LITERAL ARGV THE SDK BUILDS, not a sampled set. A drop can key on the
# arguments just as easily as on the env, and enumerating argv shapes is a
# losing game: the real command always carries a distinguishing token a finite
# list omits. One red-team wrapper stayed root only when `$1` was a `--` flag
# (caught by adding one flag shape); the next stayed root only when
# `--input-format` appeared, which the SDK ALWAYS appends and no sampled shape
# contained. The fix is to stop sampling. We reconstruct the exact argv from the
# driver's own ClaudeAgentOptions via the SDK's own _build_command, so the test
# argv IS the production argv -- every token the real spawn carries, the test
# carries, and it tracks whatever the driver and SDK do. A wrapper that keys on
# a token OUTSIDE the real argv is irrelevant, because production never sends it.
# CLAUDE_PATH was resolved above (the wrapper pin needs it too).
printf '#!/bin/sh\nid -u\n' > "$WORKDIR/fake-target"; chmod 0755 "$WORKDIR/fake-target"

# Reconstruct the real command the SDK would spawn, in the image, from the
# driver's own options. BOTH run types, because they differ (a conversation run
# omits --max-turns) and BOTH are production inputs -- a wrapper could stay root
# on the difference. Testing every argv production actually sends is the closure;
# argv it never sends is irrelevant. NUL-separated within a mode so a flag value
# with spaces/newlines (the system prompt) survives intact.
cat > "$WORKDIR/build_argv.py" <<'PY'
import sys
sys.path.insert(0, "/app")
from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport
from andyur.runner import driver
# CALL THE DRIVER'S OWN _build_options, do not re-derive the options by hand.
# Hand-building ClaudeAgentOptions is how the reconstruction kept drifting: it
# missed --input-format (round 4), then the conversation prompt, then
# --mcp-config, each a token the real spawn carries and the copy did not. The
# driver builds mcp_servers (the in-process andyur MCP server), the per-run-type
# system prompt, the model, and the tool policy; deriving any of those a second
# time is a second source of truth guaranteed to fall behind. This calls the
# EXACT function run_agent / _run_conversation call, so the reconstructed argv
# is whatever the driver would actually spawn, by construction.
if sys.argv[1] == "conversation":
    opts = driver._build_options(
        "probe", "/tmp", driver.CONVERSATION_SYSTEM_PROMPT, None, "probe", None,
        max_turns=None, proxy_url="http://127.0.0.1:9999")
else:
    opts = driver._build_options(
        "probe", "/tmp", driver.SYSTEM_PROMPT, None, "probe", None,
        proxy_url="http://127.0.0.1:9999")
if sys.argv[1] == "env":
    # The env overrides the SDK merges over os.environ (options.env =
    # driver._subprocess_env). The wrapper is spawned with these SET, so a
    # wrapper that branches on one of them -- CLAUDE_CODE_DISABLE_AUTO_MEMORY is
    # set unconditionally for every real agent, and the harness never reproduced
    # it -- would stay root in production while dropping for the bare-env test.
    sys.stdout.write("\0".join(f"{k}={v}" for k, v in (opts.env or {}).items()))
    sys.exit()
cmd = SubprocessCLITransport(prompt="hi", options=opts)._build_command()
sys.stdout.write("\0".join(cmd[1:]))   # flags only; the wrapper is argv[0]
PY

# The env overrides the real spawn applies, so the wrapper under test sees the
# same environment production gives it (CLAUDE_CODE_DISABLE_AUTO_MEMORY, the
# proxy base URL, the blanked credentials). Belt-and-suspenders with the
# structural check: even a branch that slipped the allow-list is caught here
# behaviourally.
docker run --rm -v "$WORKDIR/build_argv.py:/build_argv.py:ro" \
  -e ANDYUR_AGENT_MODEL -e ANDYUR_LLM -e ANDYUR_MAX_TURNS \
  --entrypoint python "$IMAGE" /build_argv.py env > "$WORKDIR/realenv" 2>/dev/null
ENVARGS=(); while IFS= read -r -d '' kv; do ENVARGS+=(-e "$kv"); done < "$WORKDIR/realenv"

drop_uid() {   # invoke the wrapper on the default path (unset var) with $@ argv
  docker run --rm --cap-drop ALL --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges -v "$WORKDIR/fake-target:$CLAUDE_PATH:ro" \
    "${ENVARGS[@]}" \
    --entrypoint /usr/local/bin/andyur-agent-claude "$IMAGE" "$@" 2>/dev/null | tr -d '\r'
}
# no-args as a floor, then the literal argv for each run type.
drop_ok=1; detail="no-args=$(drop_uid)"
[ "${detail#no-args=}" = "1001" ] || drop_ok=0
for mode in headless conversation; do
  # Forward the env vars that shape the argv VALUES (the model, the backend), so
  # when the harness runs with a deployment's config the reconstruction uses that
  # config's model rather than the image default -- otherwise a wrapper keying on
  # `--model <specific value>` would pass here (tested with the default model)
  # and stay root for a deployment on a different model. `-e VAR` with no value
  # forwards from the harness's own environment.
  docker run --rm -v "$WORKDIR/build_argv.py:/build_argv.py:ro" \
    -e ANDYUR_AGENT_MODEL -e ANDYUR_LLM -e ANDYUR_MAX_TURNS \
    --entrypoint python "$IMAGE" /build_argv.py "$mode" > "$WORKDIR/argv-$mode" 2>/dev/null
  FLAGS=(); while IFS= read -r -d '' f; do FLAGS+=("$f"); done < "$WORKDIR/argv-$mode"
  # A failed reconstruction must not silently degrade the test to a short argv.
  # Require the tokens the driver+SDK are known to always emit -- including
  # --mcp-config, the one a hand-built options set dropped and a wrapper keyed
  # on. If _build_options changes and stops emitting one of these, this fails
  # loudly rather than testing a stale shape.
  for required in --input-format --mcp-config --system-prompt; do
    case " ${FLAGS[*]} " in
      *" $required "*) : ;;
      *) bad "reconstructed $mode argv is missing $required: the driver interface"$'\n'"        changed or the reconstruction is stale; refusing to certify"; exit 1 ;;
    esac
  done
  u=$(drop_uid "${FLAGS[@]}")
  detail="$detail ${mode}(${#FLAGS[@]}args)=$u"
  [ "$u" = "1001" ] || drop_ok=0
done
[ "$drop_ok" = "1" ] \
  && ok "the wrapper drops to uid 1001 on the default path for the SDK's literal argv [$detail]" \
  || { bad "the wrapper did NOT drop on its default path [$detail]:"; \
       echo "        a drop conditional on argv or env would run the real agent as root; refusing to certify"; exit 1; }

# ---------------------------------------------------------------------------
step "the container, with production's OWN flags and every runner secret seeded"
# Flags come from the orchestrator's _sandbox_argv (the daemon's placement code,
# moved there when the pod shape was added) so a weakened posture weakens the
# test rather than passing under flags production does not use. Then EVERY
# credential a runner can hold is seeded with the canary as its value, so the
# sweep catches a leak of any of them, not only the two that used to carry it.
"$VENV/bin/python" - > "$WORKDIR/argv" <<PY
import os
os.environ["ANDYUR_SANDBOX"] = "on"
os.environ.setdefault("ANDYUR_SANDBOX_IMAGE", "$IMAGE")
from andyur.daemon import orchestrator
from andyur.runner import driver
argv = orchestrator._sandbox_argv("uid-probe", "uidtest",
                                  run_token="$CANARY-RUNTOKEN",
                                  broker_token="$CANARY-BROKERTOKEN")
image_at = argv.index("$IMAGE")
flags = argv[:image_at]
flags[flags.index("--name") + 1] = "$CONTAINER"
flags.insert(flags.index("run") + 1, "-d")
# This is a discrimination harness, not a launch configuration. Give its root
# positive-control process *more* tracing authority than production so mem and
# ptrace must demonstrably work before a different-uid denial counts. The same
# container then invokes the real no-new-privileges uid-drop wrapper; the agent
# mem/ptrace negatives below are the guard that this extra root authority did
# not cross that boundary. The daemon-generated --cap-drop ALL remains intact.
flags += ["--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined"]
# Seed the rest of the forbidden set with the canary, so a leak of the HMAC
# signing secret or the provider key is caught by the same sweep.
for var in driver._AGENT_ENV_FORBIDDEN:
    if var not in ("ANDYUR_RUN_TOKEN", "ANDYUR_BROKER_TOKEN"):
        flags += ["-e", f"{var}=$CANARY-{var}"]
# A SENTINEL, because this stdout is shared. The daemon's log() writes to
# stdout ON PURPOSE -- it is the andyur.log.v1 JSON plane, stamped with trace
# and span ids per observability-exit-criteria.md 6 -- so importing the
# orchestrator and calling _sandbox_argv can legitimately print. It does:
# "[daemon] run telemetry off: ... is host-local ..." fires whenever the OTel
# endpoint is not reachable from the run network, which is every CI runner and
# no developer machine with Jaeger up. That line landed as ARGV[0] and the gate
# then tried to EXECUTE it, failing with "No such file or directory" under a
# message that said only "could not start the probe container".
# Reading after a sentinel makes this harness immune to that, now and to
# whatever the daemon logs next, without arguing with the log plane's design.
print("--ANDYUR-ARGV--")
print("\n".join(flags + ["--entrypoint", "sleep", "$IMAGE", "infinity"]))
# The list of vars the AGENT env must not carry, for the probe to strip so it
# faithfully mimics driver._subprocess_env rather than defining the leak away.
open("$WORKDIR/forbidden", "w").write("\n".join(driver._AGENT_ENV_FORBIDDEN) + "\n")
PY
ARGV=(); argv_started=0
while IFS= read -r line; do
  if [ "$argv_started" -eq 0 ]; then
    [ "$line" = "--ANDYUR-ARGV--" ] && argv_started=1
    continue                      # anything before the sentinel is daemon logging
  fi
  ARGV+=("$line")
done < "$WORKDIR/argv"
[ "$argv_started" -eq 1 ] \
  || { echo "the argv sentinel never appeared; $WORKDIR/argv holds:"; \
       sed 's/^/    /' "$WORKDIR/argv"; exit 1; }
[ "${#ARGV[@]}" -gt 5 ] || { echo "could not build the container argv"; exit 1; }

posture="${ARGV[*]}"
for required in "--cap-drop ALL" "--security-opt no-new-privileges"; do
  case "$posture" in *"$required"*) ;; *) bad "the daemon no longer passes '$required'"; ;; esac
done
case "$posture" in
  *"$CANARY-RUNTOKEN"*) ok "the run token is delivered through the container environment" ;;
  *) bad "no run token in the container environment: the probe would test nothing" ;;
esac

docker rm -f "$CONTAINER" >/dev/null 2>&1
# KEEP docker's own error. This line used to be `>/dev/null 2>&1 || { echo
# "could not start the probe container"; exit 1; }`, which threw away the only
# description of what went wrong and left a red containment job in CI saying
# nothing a reader could act on. The gate's own register is that a refusal has
# to name its reason; a gate that cannot say why it could not run is worse than
# one that fails, because nobody can tell an infrastructure problem from a
# containment regression.
if ! start_err="$("${ARGV[@]}" 2>&1 >/dev/null)"; then
  echo "could not start the probe container. docker said:"
  printf '%s\n' "${start_err:-(docker printed nothing)}" | sed 's/^/    /'
  echo "the command was:"
  printf '    %q' "${ARGV[0]}"; printf ' %q' "${ARGV[@]:1}"; echo
  exit 1
fi
docker cp infra/uid-boundary-probe.sh "$CONTAINER:/tmp/probe.sh" >/dev/null
# ALSO overwrite the wrapper's baked default target with the probe, so the agent
# run below exercises the EXACT production spawn: the wrapper invoked with
# ANDYUR_CLAUDE_BIN unset, dropping uid, then exec'ing its default target (which
# is now the probe). This is what closes the conditional-drop bypass at the
# probe level too, not only in the standalone assertion above.
docker cp infra/uid-boundary-probe.sh "$CONTAINER:$CLAUDE_PATH" >/dev/null
# No chmod: docker cp preserves the host uid, and root here has no CAP_FOWNER,
# so it cannot chmod a file it does not own. Run it through `sh`, no exec bit
# needed.
#
# The forbidden credentials are stripped with `env -u` INSIDE the container, not
# `docker exec -u` -- that flag sets the USER (and "docker exec -u ANDYUR_...":
# "no users found"). STRIP is an in-container `env` prefix, so the probe runs
# with the same scrubbed environment driver._subprocess_env gives the real
# agent; leaving them in would make the probe find its own inherited copy and
# report a leak that exists only because of how it was invoked.
# `|| [ -n "$v" ]` so the FINAL line is not dropped. Python's "\n".join writes no
# trailing newline, so `read` hits EOF on the last entry and returns nonzero --
# and a plain `while read` skips the loop body for it. That silently left the
# LAST forbidden variable (ANDYUR_RUN_TOKEN_SECRET, the HMAC signing key, the
# worst one to leak) unstripped, and the probe's own sweep caught it: it saw the
# secret in the probe's own environment. The harness found a bug in the harness,
# which is the whole reason the sweep exists.
STRIP=(env)
while IFS= read -r v || [ -n "$v" ]; do
  [ -n "$v" ] && STRIP+=(-u "$v")
done < "$WORKDIR/forbidden"

# probe <root|agent>. The agent path goes THROUGH THE PRODUCTION WRAPPER, so a
# broken drop runs the probe as root and fails the assertions.
# HOME=/home/agent for the agent path, because driver._agent_env() sets exactly
# that for the real agent subprocess. Inheriting the container's HOME
# (/home/runner, owned by uid 1000) would make the agent unable to write ANY
# home, so appwrite's paired control (agent CAN write its own home) would fail
# for a reason that is an artifact of the harness, not the platform.
AGENT_HOME=$(docker exec "$CONTAINER" python -c \
  "import sys;sys.path.insert(0,'/app');from andyur.runner import driver;print(driver.AGENT_HOME)" \
  2>/dev/null | tr -d '\r')
probe() {
  if [ "$1" = "agent" ]; then
    # ANDYUR_CLAUDE_BIN deliberately UNSET, exactly as the real SDK spawn leaves
    # it, so the wrapper takes its default-target path -- which is the probe,
    # cp'd over $CLAUDE_PATH above. A wrapper that only drops when the var is set
    # runs this as root and fails every vector below.
    #
    # ENVARGS reproduce the SDK's env overrides (CLAUDE_CODE_DISABLE_AUTO_MEMORY
    # and the rest of driver._subprocess_env), so a wrapper that branches on a
    # production-only env variable runs THIS probe as root and fails the vectors,
    # rather than dropping because the harness forgot to set the signal. STRIP
    # still unsets the forbidden credentials afterward, so the probe holds none.
    docker exec -e "HOME=$AGENT_HOME" "${ENVARGS[@]}" "$CONTAINER" \
      "${STRIP[@]}" /usr/local/bin/andyur-agent-claude "$RPID" "$CANARY" 2>&1
  else
    docker exec "${ENVARGS[@]}" "$CONTAINER" \
      "${STRIP[@]}" /bin/sh /tmp/probe.sh "$RPID" "$CANARY" 2>&1
  fi
}

# ---------------------------------------------------------------------------
step "a runner-shaped process, holding what a runner holds"
# Root, the run token in its environ at exec time, sealed into memory the way
# identity.seal_run_token does it, and the loopback model proxy serving. Not the
# real runner (it needs a control plane), but the same posture: same uid, same
# secrets, same listening socket. stdout kept, so a failure explains itself.
docker exec -d "$CONTAINER" /bin/sh -c '
cd /app && exec python - > /tmp/standin.log 2>&1 <<PY
import os, time
from andyur import identity
from andyur.runner.modelproxy import ModelProxy
identity.seal_run_token()
p = ModelProxy("http://127.0.0.1:9", credential=os.environ.get("ANDYUR_BROKER_TOKEN", ""))
open("/tmp/proxy_url", "w").write(p.start())
open("/tmp/runner_pid", "w").write(str(os.getpid()))
time.sleep(3600)
PY'
for _ in $(seq 1 40); do
  docker exec "$CONTAINER" test -f /tmp/runner_pid 2>/dev/null && break
  sleep 0.5
done
RPID=$(docker exec "$CONTAINER" cat /tmp/runner_pid 2>/dev/null | tr -d '\r')
if [ -n "$RPID" ]; then
  ok "runner-shaped process is up as uid 0 (pid $RPID)"
else
  bad "the stand-in runner never started:"
  docker exec "$CONTAINER" cat /tmp/standin.log 2>&1 | sed 's/^/          /' | tail -6
  exit 1
fi
uid=$(docker exec "$CONTAINER" awk '/^Uid:/{print $2}' "/proc/$RPID/status" 2>/dev/null | tr -d '\r')
[ "$uid" = "0" ] && ok "it runs as uid 0, as the real runner does" \
                 || { bad "stand-in runs as uid '$uid', not 0"; exit 1; }
# The seal must have actually put the token in the stand-in's memory, or the mem
# positive control below is searching for something that is not there.
docker exec "$CONTAINER" grep -qc "$CANARY" "/proc/$RPID/environ" 2>/dev/null \
  && ok "the runner's environ holds the seeded canary (mem control is meaningful)" \
  || bad "the seeded canary is not in the stand-in environ: the probe target is wrong"

# A probe run must reach its DONE sentinel. A probe that dies partway emits some
# verdicts and no sentinel, and those partial verdicts must not be read as a
# clean run. Guard both captures on it.
require_complete() {   # $1 = file, $2 = label
  grep -q '^DONE ' "$1" || { bad "the $2 probe did not complete (no DONE sentinel):"; \
    sed 's/^/          /' "$1" | tail -4; return 1; }
}

# ---------------------------------------------------------------------------
step "POSITIVE CONTROL: the same probe as root MUST read what the agent must not"
probe root > "$WORKDIR/root.txt" 2>&1
require_complete "$WORKDIR/root.txt" root || exit 1
sed 's/^/        /' "$WORKDIR/root.txt"
rverdict() { awk -v k="$1" '$1==k{print $2}' "$WORKDIR/root.txt"; }
# Every vector the agent must be BLOCKED on by the UID SPLIT (not by DAC or a
# docker mask) must be readable by root. mem must find the CANARY, not any byte.
for vector in environ mem fd cwd ptrace escalate; do
  v=$(rverdict "$vector")
  [ "$v" = "READ" ] && ok "root can $vector (the probe works)" \
    || bad "root could NOT $vector ($v) -- the probe is broken, so an agent"$'\n'"          failing the same vector would prove nothing"
done
# NB: the write-mechanism control is NOT here. Root's HOME is /home/runner
# (owned by the uid-1000 runner account, mode 700), and container root has no
# CAP_DAC_OVERRIDE, so root cannot write it either. The control that appwrite
# BLOCKED is a real deny lives in the AGENT run: the agent CAN write its own
# HOME (owned by 1001) and CANNOT write /app.

# ---------------------------------------------------------------------------
step "THE BOUNDARY: the same probe as the agent, dropped through the real wrapper"
probe agent > "$WORKDIR/agent.txt" 2>&1
require_complete "$WORKDIR/agent.txt" agent || exit 1
sed 's/^/        /' "$WORKDIR/agent.txt"
averdict() { awk -v k="$1" '$1==k{print $2}' "$WORKDIR/agent.txt"; }
adetail()  { awk -v k="$1" '{if($1==k){$1="";$2="";print}}' "$WORKDIR/agent.txt"; }

# Vectors the uid split must BLOCK.
for vector in environ mem fd cwd ptrace appwrite escalate; do
  v=$(averdict "$vector")
  [ "$v" = "BLOCKED" ] && ok "agent cannot reach the runner's $vector" \
                       || bad "agent $vector = ${v:-<missing>}:$(adetail "$vector")"
done
# Readable-by-design vectors: the assertion is that they carry no secret.
for vector in cmdline sweep selfenv; do
  v=$(averdict "$vector")
  [ "$v" = "ABSENT" ] && ok "no credential in the agent-readable $vector" \
                      || bad "agent $vector = ${v:-<missing>}:$(adetail "$vector")"
done
# The agent MUST be able to write its own home (else appwrite BLOCKED is vacuous
# -- a process that can write nothing trivially cannot write /app).
[ "$(averdict ownwrite)" = "READ" ] && ok "agent can write its own HOME (appwrite deny is real)" \
  || bad "agent could not write its own HOME: appwrite BLOCKED proves nothing"

# ---------------------------------------------------------------------------
step "the sweep can fail: plant a secret where the agent CAN read it"
# The sweep is the check that catches the whole same-uid class. Its own control
# must plant a token the agent can genuinely reach and require detection of THAT
# value. The env is stripped (as the real agent's is), the planted var set
# explicitly, and the probe run for the PLANT string specifically -- so an
# inherited copy of the shared canary cannot satisfy it.
# env -u strips the inherited forbidden vars, then sets the plant explicitly, so
# the found hit can ONLY be the plant, not an inherited copy of the shared
# canary. The plant process runs as uid 1001, so the agent probe can read it.
docker exec -d "$CONTAINER" \
  "${STRIP[@]}" "ANDYUR_RUN_TOKEN=$PLANT" \
  setpriv --reuid=1001 --regid=1001 --clear-groups /bin/sleep 300
sleep 1
# Through the production path (ANDYUR_CLAUDE_BIN unset, default target = probe),
# so the plant control exercises the same drop the boundary probe does.
docker exec -e "HOME=$AGENT_HOME" "$CONTAINER" \
  "${STRIP[@]}" /usr/local/bin/andyur-agent-claude "$RPID" "$PLANT" > "$WORKDIR/plant.txt" 2>&1
require_complete "$WORKDIR/plant.txt" plant || exit 1
pv=$(awk '$1=="sweep"{print $2}' "$WORKDIR/plant.txt")
[ "$pv" = "READ" ] && ok "the sweep detects a planted token in a same-uid process (it can fail)" \
                   || bad "the sweep reported '$pv' with a token planted in plain sight:"$'\n'"          it cannot fail, so its clean verdict above means nothing"
docker exec "$CONTAINER" sh -c 'kill -9 $(pgrep -f "sleep 300") 2>/dev/null; true' >/dev/null 2>&1

# ---------------------------------------------------------------------------
step "FILESYSTEM: credential material on disk that the agent uid can open"
# THE CLASS THIS HARNESS COULD NOT SEE. Every vector above reads a PROCESS:
# /proc/<pid>/environ, /proc/<pid>/mem, the fd table, the argv, the process
# sweep. Not one of them looks at a FILE. So a secret the platform WRITES TO
# DISK -- and the runner writes one, its X509-SVID private key, because uvicorn's
# --ssl-keyfile and httpx's load_cert_chain both take paths and there is no
# in-memory handoff -- was outside everything this file certified. It landed at
# mode 0644 in a 0755 directory, which under the uid split means the agent can
# open the credential that authenticates the workload to the control plane and
# then simply BE the workload. The uid split does nothing about that: file
# permissions, not /proc ownership, are the control, and nothing was checking
# them.
#
# HONEST SCOPE, because overstating this is worse than not having it: at the
# time of writing the 0644 key was NOT reachable in a real run (ANDYUR_MTLS is
# never forwarded into a run container by orchestrator._sandbox_argv, and
# container root there cannot even create /app/data with CAP_DAC_OVERRIDE
# dropped). The sweep is here for the class, not for one bug: it is the check
# that will notice the day a config change, a new credential file, or a cache
# written by some library puts key material where uid 1001 can read it.
cat > "$WORKDIR/fs-sweep.py" <<'PY'
#!/usr/bin/env python3
# Walk the filesystem AS WHATEVER UID INVOKED US and report every file this uid
# can actually open that holds credential material. Two detectors:
#
#  1. A PEM private key that PARSES. Grepping for the BEGIN marker is not enough
#     and the difference is not cosmetic: andyur/redact.py contains that literal
#     as a redaction pattern, and so does this script's own compiled regex, so a
#     marker-only sweep reports three hits on a clean image and then gets muted
#     by an allow-list -- which is exactly the hole a real leak would sit in.
#     Requiring cryptography to LOAD the block means a hit is usable key
#     material or it is not a hit.
#  2. An exact credential VALUE passed in by the caller (the canary it seeded
#     into every runner secret, or the distinct plant string), so a token
#     written to a log, a cache or a dotfile is caught even though it is not PEM.
#
# ELF files are skipped. libgnutls.so ships a parseable PEM key inside its own
# .rodata, so it is a permanent false positive on the base image, and Andyur
# never writes a credential into an executable -- the things it writes are text.
# Skipping by MAGIC rather than by path keeps that narrow: a key dropped next to
# a library is still found, only the library itself is not re-reported.
import os, re, sys, time
from cryptography.hazmat.primitives.serialization import load_pem_private_key

extra = sys.argv[1].encode() if len(sys.argv) > 1 and sys.argv[1] else None
SKIP = {"/proc", "/sys", "/dev"}          # kernel interfaces, not stored files
MARK = b"PRIVATE" + b" KEY-----"          # split so this file is not its own hit
BLOCK = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
                   rb"-----END [A-Z ]*PRIVATE KEY-----", re.S)
MAX = 4 << 20
keyhits, credhits, files, byts = [], [], 0, 0
t0 = time.time()
for dp, dns, fns in os.walk("/", onerror=lambda e: None):
    # Do not descend a symlinked directory: it would double-count and can loop.
    dns[:] = [d for d in dns if os.path.join(dp, d) not in SKIP
              and not os.path.islink(os.path.join(dp, d))]
    for n in fns:
        p = os.path.join(dp, n)
        try:
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            sz = os.path.getsize(p)
            if sz == 0 or sz > MAX:
                continue
            with open(p, "rb") as fh:
                data = fh.read(MAX)
        except OSError:
            continue        # unreadable by this uid IS the boundary working
        if data[:4] == b"\x7fELF":
            continue
        files += 1
        byts += len(data)
        if extra and extra in data:
            credhits.append(p)
        if MARK in data:
            for m in BLOCK.finditer(data):
                try:
                    load_pem_private_key(m.group(0), password=None)
                except Exception:
                    continue
                keyhits.append(p)
                break
print("uid %d" % os.getuid())
print("scanned %d files %d bytes in %.1fs" % (files, byts, time.time() - t0))
for p in keyhits:
    print("keyhit " + p)
for p in credhits:
    print("credhit " + p)
print("fssweep %s %d key file(s), %d credential file(s)"
      % ("READ" if (keyhits or credhits) else "ABSENT", len(keyhits), len(credhits)))
print("DONE %d" % (len(keyhits) + len(credhits)))
PY
chmod 0755 "$WORKDIR/fs-sweep.py"
# Over the wrapper's DEFAULT TARGET, same as the boundary probe, so the sweep
# runs through the production drop rather than a hand-rolled setpriv. Safe to
# clobber here: every step that used the boundary probe has already run.
docker cp "$WORKDIR/fs-sweep.py" "$CONTAINER:$CLAUDE_PATH" >/dev/null

fssweep() {   # $1 = needle, $2 = label -> writes $WORKDIR/fs-$2.txt
  docker exec -e "HOME=$AGENT_HOME" "${ENVARGS[@]}" "$CONTAINER" \
    "${STRIP[@]}" /usr/local/bin/andyur-agent-claude "$1" > "$WORKDIR/fs-$2.txt" 2>&1
  require_complete "$WORKDIR/fs-$2.txt" "filesystem-$2"
}
fsverdict() { awk '$1=="fssweep"{print $2}' "$WORKDIR/fs-$1.txt"; }
fsdetail()  { grep -E '^(keyhit|credhit) ' "$WORKDIR/fs-$1.txt" | head -5 | tr '\n' ' '; }

fssweep "$CANARY" base || exit 1
# THE SWEEP MUST HAVE ACTUALLY WALKED SOMETHING. "found nothing" and "the walk
# died on line one" are the same output, which is the exact failure mode this
# harness exists to refuse. The real image scans ~14k files; 500 is a floor that
# a broken walk cannot clear and a slimmer image still can.
scanned=$(awk '$1=="scanned"{print $2}' "$WORKDIR/fs-base.txt")
[ "${scanned:-0}" -gt 500 ] \
  && ok "the filesystem sweep read $scanned files as the agent (it is really walking)" \
  || { bad "the sweep only reached ${scanned:-0} files: it is not searching anything,"$'\n'"        so an ABSENT verdict from it would mean nothing"; exit 1; }
# ...as uid 1001. If the wrapper failed to drop, this ran as root and its clean
# verdict would be a claim about the wrong principal entirely.
sweep_uid=$(awk '$1=="uid"{print $2}' "$WORKDIR/fs-base.txt")
[ "$sweep_uid" = "1001" ] && ok "the filesystem sweep ran as the agent uid (1001)" \
  || { bad "the sweep ran as uid '$sweep_uid', not the agent: it proves nothing"; exit 1; }
[ "$(fsverdict base)" = "ABSENT" ] \
  && ok "no private key and no seeded credential is readable by the agent on disk" \
  || bad "agent-readable credential material on disk: $(fsdetail base)"

# --- THE REGRESSION THIS EXISTS FOR: export the real SVID PEMs and re-sweep ----
# Run the SHIPPED identity.export_tls_pems (only the SPIRE Workload API is
# stubbed -- there is no SPIRE agent in this container) into a directory the
# agent can traverse, then sweep. With the export writing 0600/0700 the key is
# invisible to uid 1001; with the 0644 it shipped with, the sweep finds it. The
# positive control immediately below re-runs on THE SAME FILE with only the mode
# changed, so "clean" cannot be the sweep failing to look there.
#
# What this measures is READABILITY, not the mechanism, and that is deliberate.
# The export applies two independent controls -- 0600 on the key and 0700 on the
# directory -- and either one alone denies the agent, so removing just the
# directory chmod correctly leaves this step green (verified: it does). The unit
# tests in tests/test_key_hygiene.py pin each control separately; this pins the
# property they exist to produce, which is the one an attacker experiences.
cat > "$WORKDIR/export-pems.py" <<'PY'
import datetime, os, sys
sys.path.insert(0, "/app")
import spiffe
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "uid-boundary")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1)).sign(key, hashes.SHA256()))

class _Src:
    def __init__(self, *a, **k): pass
    def get_x509_context(self):
        return type("C", (), {"default_svid": type("S", (), {
            "cert_chain": [cert], "private_key": key})()})()
    def get_bundle_for_trust_domain(self, td):
        return type("B", (), {"x509_authorities": [cert]})()
    def close(self): pass

spiffe.X509Source = _Src            # export_tls_pems imports this inside the call
from andyur import identity
print(identity.export_tls_pems("runner")["key"])
PY
docker cp "$WORKDIR/export-pems.py" "$CONTAINER:/tmp/export-pems.py" >/dev/null
# /tmp, not /app: container root here has CAP_DAC_OVERRIDE dropped and /app is
# owned by uid 1000, so it cannot write there at all. /tmp is 1777, which is the
# HARDER case for the fix -- every uid can traverse the parent, so the mode on
# the exported directory and key is the only thing left protecting them.
EXPORTED=$(docker exec -e ANDYUR_DATA_DIR=/tmp/andyur-keyexport "$CONTAINER" \
  python /tmp/export-pems.py 2>"$WORKDIR/export-err.txt" | tr -d '\r' | tail -1)
case "$EXPORTED" in
  /tmp/andyur-keyexport/*/key.pem)
    ok "exported a real X509-SVID key through the shipped code path ($EXPORTED)" ;;
  *)
    bad "could not export the SVID PEMs, so the key-hygiene check cannot run:"
    sed 's/^/          /' "$WORKDIR/export-err.txt" | tail -4
    EXPORTED="" ;;
esac
if [ -n "$EXPORTED" ]; then
  fssweep "$CANARY" export || exit 1
  [ "$(fsverdict export)" = "ABSENT" ] \
    && ok "the exported SVID private key is NOT readable by the agent" \
    || bad "the agent can read the runner's X509-SVID private key: $(fsdetail export)"$'\n'"          it can present that cert and act AS the workload"

  # POSITIVE CONTROL, on the very same file: widen the modes to what the export
  # used to produce and require the sweep to find it. Same path, same bytes, same
  # sweep -- only the permission bits differ, so a pass above cannot be the sweep
  # overlooking this location.
  docker exec "$CONTAINER" chmod 0755 "$(dirname "$EXPORTED")" >/dev/null 2>&1
  docker exec "$CONTAINER" chmod 0644 "$EXPORTED" >/dev/null 2>&1
  fssweep "$CANARY" widened || exit 1
  if [ "$(fsverdict widened)" = "READ" ] && grep -q "^keyhit $EXPORTED\$" "$WORKDIR/fs-widened.txt"; then
    ok "with 0644/0755 the agent DOES read that same key (the check can fail)"
  else
    bad "the sweep missed a world-readable private key at $EXPORTED:"$'\n'"          it cannot fail, so the clean verdict above means nothing"
  fi
  docker exec "$CONTAINER" rm -rf /tmp/andyur-keyexport >/dev/null 2>&1
fi

# --- and the non-PEM half: a credential VALUE in a plain file -----------------
# The key detector would never see this one. Distinct plant string, so an
# inherited copy of the shared canary cannot satisfy it.
docker exec "$CONTAINER" sh -c \
  "mkdir -p /tmp/leakcheck && printf 'token=%s\n' '$PLANT' > /tmp/leakcheck/creds && chmod 0644 /tmp/leakcheck/creds" \
  >/dev/null 2>&1
fssweep "$PLANT" plantfile || exit 1
if [ "$(fsverdict plantfile)" = "READ" ] \
   && grep -q "^credhit /tmp/leakcheck/creds\$" "$WORKDIR/fs-plantfile.txt"; then
  ok "the sweep detects a planted credential file the agent can read (it can fail)"
else
  bad "the sweep missed a world-readable credential file: $(fsdetail plantfile)"
fi
docker exec "$CONTAINER" rm -rf /tmp/leakcheck >/dev/null 2>&1

# ---------------------------------------------------------------------------
step "the image is hardened: no setuid, no file capabilities, scanned AS ROOT"
# As root, so nothing is hidden by a directory the agent cannot enter, and
# across ALL mounts (no -xdev) plus the tmpfses docker adds (/dev, /dev/shm),
# where an agent could drop a setuid binary the -xdev scan would miss.
suid=$(docker exec "$CONTAINER" find / /dev /dev/shm -perm -4000 -type f 2>/dev/null | sort -u)
[ -z "$suid" ] && ok "no setuid binaries anywhere in the image" \
               || bad "setuid binaries present: $(echo "$suid" | tr '\n' ' ')"
# Positive control: the scan must actually DETECT a setuid binary, or "none
# found" could mean the scan is broken. Plant one as root, confirm it is found,
# remove it. (File capabilities cannot be planted in-container: root here lacks
# CAP_SETFCAP, so the xattr walk has no positive control -- noted, not hidden.)
docker exec "$CONTAINER" sh -c 'cp /bin/true /tmp/suidprobe && chmod 4755 /tmp/suidprobe' 2>/dev/null
seen=$(docker exec "$CONTAINER" find /tmp -perm -4000 -type f 2>/dev/null)
[ -n "$seen" ] && ok "the setuid scan detects a planted setuid binary (it can fail)" \
              || bad "the setuid scan did NOT find a planted setuid binary: it cannot fail"
docker exec "$CONTAINER" rm -f /tmp/suidprobe 2>/dev/null
sgid=$(docker exec "$CONTAINER" find / /dev /dev/shm -perm -2000 -type f 2>/dev/null | sort -u)
[ -z "$sgid" ] && ok "no setgid binaries anywhere in the image" \
               || bad "setgid binaries present: $(echo "$sgid" | tr '\n' ' ')"
# File capabilities bypass the uid check entirely (a binary with cap_setuid=ep
# would let the agent become root). Walk the security.capability xattr.
caps=$(docker exec -i "$CONTAINER" python3 - <<'PY' 2>/dev/null
import os
found = []
for dp, dns, fns in os.walk("/"):
    for name in fns:
        p = os.path.join(dp, name)
        try:
            if "security.capability" in os.listxattr(p, follow_symlinks=False):
                found.append(p)
        except OSError:
            pass
print("\n".join(found))
PY
)
[ -z "$caps" ] && ok "no file carries a capability xattr" \
              || bad "file capabilities present: $(echo "$caps" | tr '\n' ' ')"

# ---------------------------------------------------------------------------
step "the spawn path does not leak an inherited fd to the agent child"
# The real agent is a CHILD of the runner and inherits every non-CLOEXEC fd,
# which bypasses /proc/<pid>/fd permissions entirely. The runner spawns via the
# SDK (anyio.open_process, close_fds=True) and its proxy socket is CLOEXEC by
# default (PEP 446), so nothing should pass through. Verify the MECHANISM: open
# a secret fd, spawn a uid-1001 child the way the runner does, and confirm it
# cannot read the fd it did not receive.
#
# THE CHILD READS THE INHERITED FD DIRECTLY (`cat <&$fd`), never
# /proc/self/fd/$fd. The /proc path re-opens the underlying file and re-checks
# its permissions, so a root-owned 0600 file is denied to uid 1001 whether or
# not the fd was inherited -- which made the negative control report BLOCKED
# even with close_fds off, hiding the fact that the fd HAD passed through. The
# open file description, dup'd from the parent, carries no permission recheck:
# that is precisely why an inherited fd is a leak and /proc/self/fd is not the
# test.
fdcheck() {   # $1 = close_fds bool, $2 = inheritable bool -> LEAKED | BLOCKED
  docker exec -i "$CONTAINER" python3 - "$CANARY" "$1" "$2" <<'PY' 2>/dev/null
import os, subprocess, sys
canary, close_fds, inherit = sys.argv[1], sys.argv[2] == "True", sys.argv[3] == "True"
path = f"/tmp/fdsecret_{close_fds}_{inherit}"
open(path, "w").write(canary + "\n"); os.chmod(path, 0o600)
fd = os.open(path, os.O_RDONLY)
os.set_inheritable(fd, inherit)
r = subprocess.run(
    ["setpriv", "--reuid=1001", "--regid=1001", "--clear-groups",
     "/bin/sh", "-c", f"cat <&{fd} 2>/dev/null || echo BLOCKED"],
    close_fds=close_fds, capture_output=True, text=True)
os.remove(path)
print("LEAKED" if canary in r.stdout else "BLOCKED")
PY
}
# The runner's way: close_fds=True. Nothing inherited, even a deliberately
# inheritable fd, because close_fds wins.
leak=$(fdcheck True True)
[ "$leak" = "BLOCKED" ] && ok "a uid-1001 child does not inherit the runner's open fds (close_fds)" \
                        || bad "an inherited fd reached the agent child ($leak)"
# The negative control: what the runner must NEVER do -- close_fds off AND the
# fd inheritable -- DOES leak, proving the check above can fail.
antileak=$(fdcheck False True)
[ "$antileak" = "LEAKED" ] && ok "the fd check is not vacuous (an inheritable fd DOES leak the open file)" \
                           || bad "could not demonstrate an fd leak: the negative control is broken ($antileak)"

# ---------------------------------------------------------------------------
step "kcore is masked by the runtime (a posture check, not a uid check)"
# /proc/kcore would expose all of physical memory. Docker masks it by
# bind-mounting /dev/null, so it yields no bytes for EVERY uid -- which is why
# it is asserted here, against root, as a container-posture property, rather
# than sitting among the uid-split vectors where a BLOCKED-for-everyone result
# would look like the split working.
kb=$(docker exec "$CONTAINER" sh -c 'head -c 64 /proc/kcore 2>/dev/null | wc -c' | tr -d ' ')
[ "${kb:-0}" = "0" ] && ok "/proc/kcore yields no bytes even to root (masked)" \
                     || bad "/proc/kcore returned $kb bytes to root: physical memory is exposed"

echo
printf '%s\n' "----------------------------------------"
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || { echo "probes in $WORKDIR (root.txt, agent.txt, plant.txt)"; cp "$WORKDIR"/*.txt /tmp/ 2>/dev/null; exit 1; }
echo "UID BOUNDARY: PASSED"

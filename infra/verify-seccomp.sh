#!/usr/bin/env bash
# Prove the seccomp filter is actually in force in a real run container.
#
# WHY THIS EXISTS SEPARATELY FROM THE UNIT TESTS. Unit tests can prove the
# rendered JSON denies a syscall and that the flag reaches argv. Neither is
# evidence the kernel loaded a filter: docker silently honours only the LAST
# `--security-opt seccomp=`, a host may apply nothing by default, and a denial
# and an absent facility look identical from inside. So every check here is
# PAIRED -- the same probe under the profile and under `seccomp=unconfined` --
# and the unconfined leg must SUCCEED. A probe that fails both ways proves
# nothing, and that is the failure mode this script refuses to have.
#
# EPERM is also not self-identifying: a capability denial and a seccomp denial
# are the same errno. The pairing is what separates them, because capabilities
# are identical in both legs.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${ANDYUR_SANDBOX_IMAGE:-andyur-runner}"
FAIL=0
CHECKS=0
# A skipped check must not look like a passed one: CI compares this total.
EXPECTED_CHECKS=8

ok()   { CHECKS=$((CHECKS+1)); printf '  ok    %s\n' "$1"; }
bad()  { CHECKS=$((CHECKS+1)); FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }

# Render the profiles exactly as the daemon would, from the daemon's own code,
# so this cannot drift from what launches.
read -r AGENT_PROFILE RUNNER_PROFILE <<<"$(
  "$HERE/.venv/bin/python" -c '
from andyur.daemon import seccomp
print(seccomp.profile_path(seccomp.AGENT)[0], seccomp.profile_path(seccomp.RUNNER)[0])'
)" || { echo "could not render profiles"; exit 1; }

# probe <name> <profile-args...> -- runs a python snippet on stdin, echoes result
probe() {
  local prof="$1"; shift
  docker run --rm --cap-drop ALL --security-opt no-new-privileges \
    --security-opt "seccomp=$prof" --user 1001 --entrypoint python \
    "$IMAGE" -c "$1" 2>&1
}
probe_unconfined() {
  docker run --rm --cap-drop ALL --security-opt no-new-privileges \
    --security-opt seccomp=unconfined --user 1001 --entrypoint python \
    "$IMAGE" -c "$1" 2>&1
}
probe_setgid() {
  local prof="$1"; shift
  # Verification-only authority makes the positive leg meaningful: the runner
  # profile must permit a real gid transition while the agent profile denies
  # the same syscall at seccomp before capability checks can muddy the result.
  docker run --rm --cap-drop ALL --cap-add SETGID \
    --security-opt no-new-privileges --security-opt "seccomp=$prof" \
    --entrypoint python "$IMAGE" -c "$1" 2>&1
}

# --- the filter is loaded at all -------------------------------------------
# Seccomp: 2 means a filter is installed; 0 means none. This is the check that
# catches "the flag was in argv and did nothing".
n="$(probe "$AGENT_PROFILE" 'print(open("/proc/self/status").read().split("Seccomp:")[1].split()[0])')"
[ "$n" = "2" ] && ok "agent container has a seccomp filter loaded (Seccomp: 2)" \
                || bad "agent container reports Seccomp: $n (expected 2)"
n="$(probe "$RUNNER_PROFILE" 'print(open("/proc/self/status").read().split("Seccomp:")[1].split()[0])')"
[ "$n" = "2" ] && ok "sidecar container has a seccomp filter loaded" \
                || bad "sidecar container reports Seccomp: $n (expected 2)"
n="$(probe_unconfined 'print(open("/proc/self/status").read().split("Seccomp:")[1].split()[0])')"
[ "$n" = "0" ] && ok "control: unconfined container has NO filter (Seccomp: 0)" \
                || bad "unconfined container reports Seccomp: $n (expected 0)"

# --- ptrace: denied under the profile, permitted without it ----------------
# Attaching to a sibling of the same uid is the pod-mode threat: the driver and
# the agent share uid 1001, so DAC does not separate them.
PTRACE_SNIPPET='
import ctypes, errno, os, sys, time
pid = os.fork()
if pid == 0:
    time.sleep(5); os._exit(0)
libc = ctypes.CDLL("libc.so.6", use_errno=True)
ctypes.set_errno(0)
libc.ptrace(16, pid, 0, 0)   # PTRACE_ATTACH
e = ctypes.get_errno()
print("EPERM" if e == errno.EPERM else ("OK" if e == 0 else errno.errorcode.get(e, e)))
os.kill(pid, 9)
'
r="$(probe "$AGENT_PROFILE" "$PTRACE_SNIPPET")"
[ "$r" = "EPERM" ] && ok "ptrace of a same-uid sibling is denied (agent profile)" \
                   || bad "ptrace under agent profile returned '$r' (expected EPERM)"
r="$(probe_unconfined "$PTRACE_SNIPPET")"
[ "$r" = "OK" ] && ok "control: ptrace SUCCEEDS unconfined, so the denial is ours" \
                || bad "unconfined ptrace returned '$r' (expected OK); the check above proves nothing"

# --- the uid family: the agent/sidecar role difference ----------------------
# Use libc's architecture-portable symbol, not a hard-coded syscall number.
# Both legs receive CAP_SETGID: the runner profile must make the transition,
# while the tighter agent profile must reject the identical syscall.
UID_SNIPPET='
import ctypes, errno
libc = ctypes.CDLL("libc.so.6", use_errno=True)
ctypes.set_errno(0)
libc.setgid(1001)
e = ctypes.get_errno()
print(errno.errorcode.get(e, e) if e else "OK")
'
a="$(probe_setgid "$AGENT_PROFILE" "$UID_SNIPPET")"
s="$(probe_setgid "$RUNNER_PROFILE" "$UID_SNIPPET")"
[ "$a" = "EPERM" ] && ok "setgid denied under the agent profile" \
                   || bad "setgid under agent profile returned '$a' (expected EPERM)"
# The sidecar must permit the transition: this is the positive control proving
# the agent denial came from the role-specific filter, not the host or caps.
[ "$s" = "OK" ] && ok "sidecar keeps the uid family (setpriv needs it)" \
                || bad "sidecar setgid returned '$s' (expected OK)"

# --- positive control: real work still runs --------------------------------
# A profile that denied everything would pass every denial check above.
r="$(probe "$AGENT_PROFILE" '
import os, subprocess, tempfile
d = tempfile.mkdtemp()
open(os.path.join(d, "f"), "w").write("x")
assert open(os.path.join(d, "f")).read() == "x"
subprocess.run(["/bin/true"], check=True)
print("OK")')"
[ "$r" = "OK" ] && ok "positive control: file I/O and subprocess still work" \
                || bad "the agent profile breaks ordinary work: $r"

echo
if [ "$CHECKS" -ne "$EXPECTED_CHECKS" ]; then
  echo "FAIL: ran $CHECKS checks, expected $EXPECTED_CHECKS (a skipped check is a failure)"
  exit 1
fi
[ "$FAIL" -eq 0 ] && echo "seccomp boundary: $CHECKS/$CHECKS checks passed" \
                  || { echo "seccomp boundary: $FAIL of $CHECKS checks FAILED"; exit 1; }

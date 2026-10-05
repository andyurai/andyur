#!/bin/sh
# THE ATTACK, run INSIDE the run container as whichever uid the caller chose.
#
# It is deliberately the SAME script for the attacker (uid 1001) and for the
# positive control (uid 0). That is the whole design: a probe that only ever
# runs as the agent proves nothing when every vector fails, because "cannot
# read" and "my script is broken" produce identical output, and this repository
# has shipped that exact mistake more than once. Running it as root must SUCCEED
# on the vectors it must FAIL on as the agent. Only the difference between those
# two runs is evidence, so the caller pairs every must-be-BLOCKED vector with a
# root run that must READ.
#
# Emits one line per vector: "<name> <READ|BLOCKED|ABSENT> <detail>", then a
# final "DONE <n>" sentinel. The caller checks the sentinel: a probe that dies
# partway (a broken tool, a syntax error) stops before DONE, and a truncated run
# must be a hard failure rather than a set of missing verdicts read as passes.
#
# Usage: uid-boundary-probe.sh <runner-pid> <canary>
set -u
PID="$1"
CANARY="$2"
N=0

say() { printf '%s %s %s\n' "$1" "$2" "$3"; N=$((N + 1)); }

# --- the runner's environment: where the run token lives at exec time ---------
# /proc/<pid>/environ is the file the uid split exists to protect. It holds what
# the process was STARTED with, so sealing the token in memory does not remove
# it from here -- only a different uid does.
#
# READABILITY IS TESTED SEPARATELY FROM THE COUNT, and the count is piped, never
# captured. `envdump=$(cat environ)` DROPS the NUL separators (command
# substitution strips NUL), collapsing the whole environ to one line so grep -c
# could return at most 1 -- a regression that made a 5-secret environ report "1
# canary hit". `tr '\0' '\n' < file` reads the file directly with NULs intact.
# `|| true` on the grep because grep -c exits 1 on zero matches.
if head -c1 "/proc/$PID/environ" >/dev/null 2>&1 || [ -r "/proc/$PID/environ" ]; then
  hits=$(tr '\0' '\n' < "/proc/$PID/environ" 2>/dev/null | grep -c "$CANARY" || true)
  if [ "${hits:-0}" -gt 0 ]; then say environ READ "$hits canary hit(s)"
  else say environ ABSENT "readable, no canary"; fi
else
  say environ BLOCKED "cannot read /proc/$PID/environ"
fi

# --- the runner's memory ------------------------------------------------------
# Where the token lives AFTER the seal. THE ASSERTION IS FINDING THE CANARY, not
# reading any bytes: an earlier version read 16 bytes of the first mapped region
# and called it READ, but that region is the public python ELF header, so the
# positive control proved only that /proc/<pid>/mem is a file. Search the
# readable regions for the secret itself, which is what an attacker is actually
# after and what the seal is supposed to keep in a place the agent cannot reach.
#
# /proc/<pid>/mem is indexed by VIRTUAL ADDRESS, not file offset, so it is
# seeked per-region from /maps rather than read from zero (address 0 is never
# mapped and returns EIO for everyone, root included).
mem=$(python3 - "$PID" "$CANARY" <<'PY' 2>/dev/null
import sys
pid, canary = sys.argv[1], sys.argv[2].encode()
try:
    with open(f"/proc/{pid}/maps") as m:
        regions = [l for l in m if l.split()[1].startswith("r")]
except PermissionError:
    print("BLOCKED maps unreadable"); raise SystemExit
except Exception as e:
    print(f"ABSENT cannot enumerate maps ({type(e).__name__})"); raise SystemExit
try:
    fh = open(f"/proc/{pid}/mem", "rb", 0)
except PermissionError:
    print("BLOCKED mem open denied"); raise SystemExit
except Exception as e:
    print(f"BLOCKED mem open failed ({type(e).__name__})"); raise SystemExit
read_any = False
with fh:
    for line in regions:
        lo, hi = (int(x, 16) for x in line.split()[0].split("-"))
        try:
            fh.seek(lo)
            data = fh.read(min(hi - lo, 16 * 1024 * 1024))
        except (PermissionError, OSError):
            continue
        if not data:
            continue
        read_any = True
        if canary in data:
            print("READ canary found in runner memory"); raise SystemExit
# Distinguish "read memory but the secret was not in the sampled regions" from
# "could not read memory at all": only the latter is the boundary holding.
print("READBUTCLEAN read memory, canary not in sampled regions" if read_any
      else "BLOCKED opened mem but no region was readable")
PY
)
[ -n "$mem" ] && say mem ${mem%% *} "${mem#* }" || say mem ABSENT "no python3 to probe memory"

# --- the runner's open files --------------------------------------------------
if ls "/proc/$PID/fd" >/dev/null 2>&1; then
  say fd READ "$(ls /proc/$PID/fd 2>/dev/null | wc -l | tr -d ' ') descriptors"
else
  say fd BLOCKED "cannot list /proc/$PID/fd"
fi

# --- the runner's cwd symlink -------------------------------------------------
if target=$(readlink "/proc/$PID/cwd" 2>/dev/null) && [ -n "$target" ]; then
  say cwd READ "$target"
else
  say cwd BLOCKED "cannot resolve /proc/$PID/cwd"
fi

# --- the command line, WORLD READABLE by design -------------------------------
# Not a boundary and never will be: /proc/<pid>/cmdline is 0444. The assertion
# is "contains no secret", because anything passed as an argv is public to every
# uid in the container. This is the vector that makes a future "pass the token
# as a flag" refactor loudly fail instead of silently leaking.
if cl=$(tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null); then
  case "$cl" in
    *"$CANARY"*) say cmdline READ "canary in argv: $cl" ;;
    *)           say cmdline ABSENT "readable (0444 by design), no canary" ;;
  esac
else
  say cmdline BLOCKED "cannot read cmdline"
fi

# --- EVERY process this uid can read ------------------------------------------
# The one that matters most, and the one a per-pid test misses. The uid split
# protects the runner's environ; it does nothing about a process running as the
# AGENT'S OWN uid that was handed a secret. That is exactly what the SDK's
# version check did: open_process([cli_path, "-v"]) with no env argument, where
# cli_path is the setpriv wrapper -- so the token landed in a uid-1001 process,
# which uid 1001 may read in full. Sweep everything readable for the canary,
# which the caller has planted as the VALUE of every credential a runner holds,
# so a leak of any of them (not only the two that used to carry it) is caught.
hits=0
for p in /proc/[0-9]*; do
  e=$(cat "$p/environ" 2>/dev/null | tr '\0' '\n' | grep -c "$CANARY" 2>/dev/null || true)
  hits=$((hits + ${e:-0}))
done
if [ "$hits" -gt 0 ]; then
  say sweep READ "$hits canary hit(s) across readable /proc/*/environ"
else
  say sweep ABSENT "no canary in any readable process environment"
fi

# --- ptrace ------------------------------------------------------------------
# Attaching to the runner reads its memory regardless of file permissions.
# Blocked by uid (a different uid needs CAP_SYS_PTRACE, which --cap-drop ALL
# removes) rather than by anything Andyur does: this confirms the platform's
# assumption about the kernel, and does not depend on Yama being present.
if command -v python3 >/dev/null 2>&1 && python3 -c '' 2>/dev/null; then
  pt=$(python3 - "$PID" <<'PY' 2>/dev/null
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
rc = libc.ptrace(16, int(sys.argv[1]), None, None)   # PTRACE_ATTACH
print("attached" if rc == 0 else "denied")
PY
)
  case "$pt" in
    attached) say ptrace READ "PTRACE_ATTACH succeeded" ;;
    denied)   say ptrace BLOCKED "PTRACE_ATTACH denied" ;;
    *)        say ptrace ABSENT "ptrace attempt produced no answer" ;;
  esac
else
  say ptrace ABSENT "no working python3 to attempt ptrace"
fi

# --- the runner's code ---------------------------------------------------------
# Writing /app would let the agent alter what the NEXT run executes as root.
# Paired in the caller with a write the agent SHOULD be able to do (its own
# home), so a probe that cannot write anything at all cannot pass this vacuously.
if echo x 2>/dev/null > /app/.uid_probe_write; then
  rm -f /app/.uid_probe_write
  say appwrite READ "wrote to /app"
else
  say appwrite BLOCKED "cannot write /app"
fi
if echo x 2>/dev/null > "$HOME/.uid_probe_write"; then
  rm -f "$HOME/.uid_probe_write"
  say ownwrite READ "wrote to my own HOME ($HOME)"
else
  say ownwrite BLOCKED "cannot write my own HOME ($HOME)"
fi

# --- privilege escalation ------------------------------------------------------
if setpriv --reuid=0 /bin/true 2>/dev/null; then
  say escalate READ "setpriv --reuid=0 succeeded"
else
  say escalate BLOCKED "cannot setpriv back to root"
fi

# --- the agent's OWN environment ------------------------------------------------
# Always readable by definition. The assertion is that there is nothing in it.
s=$(tr '\0' '\n' < /proc/self/environ 2>/dev/null | grep -c "$CANARY" || true)
[ "${s:-0}" -gt 0 ] && say selfenv READ "$s canary hit(s) in my own environment" \
                    || say selfenv ABSENT "my own environment holds no canary"

# NB: there is deliberately no "does the model proxy reflect the credential"
# vector here. With the stand-in's upstream a dead port, the request always
# errors before a body, so the check could only ever report ABSENT -- a check
# that cannot fail, which is the thing this harness exists to eliminate. The
# real concern (the proxy relays any path to the broker with the broker
# credential attached) is a broker-surface property, gated by the broker's own
# inference-path allowlist, and tracked as a defense-in-depth gap in
# ROADMAP.md rather than asserted vacuously here.

say DONE "$N" ""

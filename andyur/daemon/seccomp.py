"""Per-role seccomp profiles for run containers.

WHAT THIS BUYS, STATED NARROWLY. `--cap-drop ALL` bounds what a syscall can
ACHIEVE; a seccomp filter bounds whether it is REACHABLE at all. Those are
different surfaces: `mount` fails without CAP_SYS_ADMIN, but the kernel's mount
path is still entered, so a bug in it is still reachable. This removes that
reachability for syscalls the workload never needs.

It is NOT a large win on its own, and the honest accounting matters more than
the feature: with the stock Docker profile and `--cap-drop ALL`, the
capability-gated syscalls (mount, unshare, bpf, keyctl, setns, kcmp,
perf_event_open) are ALREADY denied, because the runtime drops any allow rule
whose required capability the container does not hold. The genuine additions
here are the ones that need no capability and work between processes of the
SAME uid -- ptrace and the process_vm_* pair -- which is exactly the pod-mode
shape, where the SDK driver and the agent share uid 1001.

WHY WE START FROM THE RUNTIME'S OWN PROFILE INSTEAD OF WRITING ONE. Passing
`--security-opt seccomp=<file>` REPLACES the default; there is no way to add to
it. A hand-written allowlist would therefore silently drop the default's
argument-level rules (notably the `clone` namespace-flag mask and the ENOSYS
answer for `clone3`, which glibc needs to fall back correctly) and would be
narrower in names while weaker in arguments. So `seccomp_base.json` is moby's
profile, vendored, and the deltas below only ever SUBTRACT from it.

Subtraction, not an added deny rule, is deliberate: removing a name from every
allow group lets it fall through to the profile's own defaultAction, so there
is no rule-precedence question to get wrong.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

_BASE_PATH = Path(__file__).resolve().parent / "seccomp_base.json"

# Both roles: no process in a run container has any business inspecting or
# attaching to another process. In pod mode this is the whole point -- the SDK
# driver and the agent run as the same uid, so DAC does not separate them and
# only seccomp does. `kcmp` is here because it compares processes; the rest are
# the attach/read/write family.
_DENY_BOTH = ("ptrace", "process_vm_readv", "process_vm_writev", "kcmp")

# Agent container only. The sidecar keeps these because it drops the CLI it
# spawns to an unprivileged uid with setpriv, and that IS a uid change. The
# agent container is already unprivileged at PID 1 and never changes uid again,
# so the whole family is dead weight there -- and it is the family every
# privilege-escalation chain ends with.
_DENY_AGENT_ONLY = (
    "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid", "setfsuid", "setfsgid", "setgroups",
)

AGENT = "agent"
RUNNER = "runner"
_DENY = {AGENT: _DENY_BOTH + _DENY_AGENT_ONLY, RUNNER: _DENY_BOTH}

# Rendered profiles are cached per process: the content is a pure function of
# the base file and the role, so rendering twice would only risk the two copies
# disagreeing.
_cache: dict[str, tuple[str, str]] = {}


class SeccompUnavailable(RuntimeError):
    """The profile could not be produced, so no container may be launched.

    Fail closed and say why. A run container that silently starts without the
    filter is the failure this whole module exists to prevent, and it would be
    invisible: every call still succeeds.
    """


def _load_base() -> dict:
    try:
        base = json.loads(_BASE_PATH.read_text())
    except FileNotFoundError as e:
        raise SeccompUnavailable(
            f"seccomp base profile missing at {_BASE_PATH}. It ships inside the "
            f"andyur package; a build that omits package data will hit this."
        ) from e
    except json.JSONDecodeError as e:
        raise SeccompUnavailable(f"seccomp base profile is not valid JSON: {e}") from e
    if base.get("defaultAction") != "SCMP_ACT_ERRNO":
        # An allow-by-default base would make every subtraction below a no-op
        # while still looking like a profile. Refuse rather than ship theatre.
        raise SeccompUnavailable(
            f"seccomp base profile has defaultAction={base.get('defaultAction')!r}; "
            f"expected SCMP_ACT_ERRNO (deny by default)."
        )
    return base


def render(role: str) -> dict:
    """The profile for a role: the base with that role's denials subtracted."""
    if role not in _DENY:
        raise SeccompUnavailable(f"unknown seccomp role {role!r}")
    base = _load_base()
    deny = set(_DENY[role])
    groups = []
    for group in base.get("syscalls", []):
        names = [n for n in group.get("names", []) if n not in deny]
        if not names:
            continue  # the whole group was denied names; drop it entirely
        group = dict(group, names=names)
        groups.append(group)
    base["syscalls"] = groups
    return base


def profile_path(role: str) -> tuple[str, str]:
    """Return (path, sha256) of the rendered profile for `role`.

    The docker CLI reads this file and inlines it into the API call, so it must
    exist wherever the daemon runs -- which is why the base ships inside the
    package rather than in infra/, where a container image that copies only
    `andyur/` would leave it behind.
    """
    if role in _cache:
        return _cache[role]
    body = json.dumps(render(role), separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(body.encode()).hexdigest()
    directory = Path(tempfile.gettempdir()) / "andyur-seccomp"
    directory.mkdir(mode=0o755, exist_ok=True)
    path = directory / f"{role}-{digest[:16]}.json"
    if not path.exists():
        # Write-then-rename so a concurrent daemon never reads a partial file.
        tmp = path.with_suffix(".tmp")
        tmp.write_text(body)
        os.chmod(tmp, 0o644)
        tmp.replace(path)
    _cache[role] = (str(path), digest)
    return _cache[role]


def docker_args(role: str) -> list[str]:
    """`docker run` arguments applying this role's profile, or [] when off.

    Note for anyone adding another `--security-opt seccomp=` anywhere: docker
    takes the LAST one silently, so a second flag disables this one with no
    error. Asserting on argv is therefore not evidence the filter is in force;
    read Seccomp_filters from /proc inside the container instead.
    """
    from .. import config
    if config.SECCOMP_MODE == "off":
        return []
    path, _ = profile_path(role)
    return ["--security-opt", f"seccomp={path}"]


def describe(role: str) -> dict:
    """What was actually applied, for the run record and for docs-truth."""
    from .. import config
    if config.SECCOMP_MODE == "off":
        return {"mode": "off", "role": role, "profile_sha256": None}
    _, digest = profile_path(role)
    return {"mode": config.SECCOMP_MODE, "role": role, "profile_sha256": digest}

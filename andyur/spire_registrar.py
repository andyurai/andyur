"""Per-run SPIRE registration (Slice 3).

When a run executes in its own container, its identity should be bound to that
container, not to a uid/path the agent shares. This module creates one SPIRE
registration entry per run whose SVID is `spiffe://<td>/agent/<name>/run/<run_id>`
(per-run, not just per-agent), keyed on the run container's Docker labels, so the
containerized SPIRE agent's `docker` WorkloadAttestor issues the run its SVID --
and an agent inside the container (uid 1001, no docker.sock) cannot relabel its
container to forge another run's identity. Proven in
`infra/spire/docker/verify-slice3.sh`.

SECURITY BOUNDARY (important): the entry is keyed on Docker LABELS, which are not
secrets -- `run_id` appears in logs, the container name, and spans. This binding is
sound ONLY because the untrusted agent cannot create a container carrying those
labels (it has no docker.sock and cannot launch containers). If an agent is ever
granted Docker/DinD, or the host exposes dockerd over TCP, a labeled impostor
container could claim a run's SVID -- revisit this (add an image-id selector or a
per-run secret selector) before doing so. Two label selectors (run_id AND agent)
are required here as a small hardening; they are not a substitute for that.

The daemon calls `register_run` before launching a run container and
`unregister_run` when it reaps it. Both are best-effort: a registrar failure
logs and returns rather than breaking a run (identity is opt-in hardening, not a
prerequisite for the platform to function).

The SPIRE server is reached through a configurable command prefix (default
`docker exec andyur-spire-server /opt/spire/bin/spire-server`, matching the
containerized stack in `infra/spire/docker/`), so this works whether the server
runs in a container or as a local binary.
"""

import json
import os
import shlex
import subprocess
import time

from . import identity

# labels the daemon stamps on each run container (see daemon._sandbox_argv). The
# entry requires BOTH, so a container must carry the run's id AND its agent name.
RUN_LABEL = "andyur.run_id"
AGENT_LABEL = "andyur.agent"
# a leaked entry (daemon crash between register and reap) self-expires after this
# many seconds, so the datastore cannot grow without bound (F3). Runs are bounded.
ENTRY_MAX_AGE = int(os.environ.get("ANDYUR_SPIRE_ENTRY_MAX_AGE", str(6 * 3600)))
# the SPIRE node identity that per-run workload entries parent to; the
# containerized agent join-tokens as this id (see infra/spire/docker)
NODE_ID = os.environ.get(
    "ANDYUR_SPIRE_NODE_ID", f"spiffe://{identity.TRUST_DOMAIN}/agent/node"
)
# The gateway's exchange config snapshots this proof for the bounded run. Keep
# it alive beyond the run rather than discovering halfway through execution that
# a token refresh can no longer authenticate. Deployments may shorten it only
# when they shorten the run bound too.
_RUN_TTL = int(os.environ.get("ANDYUR_RUN_TTL_SECONDS", "900"))
# Twice the run bound, not run+margin: the SPIRE agent serves a CACHED JWT-SVID
# until it falls below half its TTL, so the freshest token a late fetch can see
# may carry only TTL/2. TTL/2 must still cover the remaining run plus refresh
# margin, or a long-thinking agent's first tool call is refused fail-closed on
# a token that outlives the run (observed: 801s remaining vs 960s required).
ENTRY_JWT_TTL = os.environ.get(
    "ANDYUR_SPIRE_ENTRY_TTL", str(2 * _RUN_TTL + 300))
_ENTRY_TTL_PINNED = "ANDYUR_SPIRE_ENTRY_TTL" in os.environ
# A JWT-SVID cannot outlive the SPIRE CA that signs it. Ask for more and SPIRE
# issues a SHORTER token than requested -- which the runner's freshness check
# then refuses, so `_fetch_actor_token` returns None and every managed tool call
# is withheld while THE RUN KEEPS GOING. The delegation disappears and nothing
# says so.
#
# So the ask is clamped to what can actually be granted, and a grant this cannot
# cover is reported LOUDLY at registration rather than discovered as a silent
# loss of authority mid-run. Default matches SPIRE's own default CA TTL.
MAX_ENTRY_JWT_TTL = int(os.environ.get("ANDYUR_SPIRE_MAX_ENTRY_TTL", str(24 * 3600)))


def _entry_ttl_for(run_ttl_seconds: int | None) -> str:
    """The JWT-SVID TTL for THIS run's entry.

    The module default is sized from the daemon's own ANDYUR_RUN_TTL_SECONDS,
    which is the PLATFORM value -- a per-agent grant reaches only the run
    container's environment. So a run granted 7200s got an entry sized for 900s
    and its first tool call was refused fail-closed on an SVID that could not
    cover the remaining run, which is exactly the incident the comment above
    records.

    Same 2x rule and the same reason: the SPIRE agent serves a cached JWT-SVID
    down to half its TTL, so TTL/2 must still cover what remains of the run plus
    the refresh margin. An operator who pinned the variable keeps their value.
    """
    if _ENTRY_TTL_PINNED or not run_ttl_seconds:
        return ENTRY_JWT_TTL
    wanted = 2 * int(run_ttl_seconds) + 300
    if wanted > MAX_ENTRY_JWT_TTL:
        # Report the exact numbers. A run that loses its actor leg mid-flight
        # looks like a tool outage, and the operator has no way back from the
        # symptom to this ceiling without them.
        _log(f"WARNING: a {run_ttl_seconds}s grant needs a {wanted}s JWT-SVID "
             f"but the ceiling is {MAX_ENTRY_JWT_TTL}s "
             f"(ANDYUR_SPIRE_MAX_ENTRY_TTL). The run's actor identity will "
             f"expire before its deadline and its delegated tool calls will be "
             f"withheld from that point. Shorten the grant or raise the SPIRE "
             f"CA TTL.")
        return str(MAX_ENTRY_JWT_TTL)
    return str(wanted)


def _entry_max_age_for(run_ttl_seconds: int | None) -> int:
    """When the entry self-deletes. Must outlive the run it exists for: a grant
    near the lifetime ceiling would otherwise lose its identity a fraction of
    the way in, and the run would fail closed with nothing explaining why."""
    if not run_ttl_seconds:
        return ENTRY_MAX_AGE
    return max(ENTRY_MAX_AGE, int(run_ttl_seconds) + 3600)


def enabled() -> bool:
    """On only when the sandbox is up AND the registrar is opted in.

    Identity is no longer a term here: it is unconditional. What remains
    genuinely optional is whether ANDYUR registers the per-run entries or the
    adopter's own SPIRE tooling does."""
    sandbox = os.environ.get("ANDYUR_SANDBOX", "off").lower() in ("1", "on", "true")
    reg = os.environ.get("ANDYUR_SPIRE_REGISTRAR", "off").lower() in ("1", "on", "true")
    return sandbox and reg


def _server_cmd() -> list[str]:
    """The command prefix that invokes `spire-server`. Configurable so the daemon
    can reach a containerized server (docker exec) or a local binary."""
    override = os.environ.get("ANDYUR_SPIRE_SERVER_CMD")
    if override:
        return shlex.split(override)
    container = os.environ.get("ANDYUR_SPIRE_SERVER_CONTAINER", "andyur-spire-server")
    return ["docker", "exec", container, "/opt/spire/bin/spire-server"]


def run_spiffe_id(run_id: str, agent: str) -> str:
    """The per-run SVID: the agent identity with the run appended, so two
    concurrent runs of the same agent get distinct identities."""
    return f"{identity.agent_spiffe_id(agent)}/run/{run_id}"


def register_argv(run_id: str, agent: str, expiry: int | None = None,
                  run_ttl_seconds: int | None = None) -> list[str]:
    """The `entry create` argv binding this run's per-run SVID to its container.
    Requires BOTH the run_id and agent labels (see module docstring). `expiry` is
    an absolute unix time after which the (possibly leaked) entry self-deletes."""
    argv = _server_cmd() + [
        "entry", "create",
        "-parentID", NODE_ID,
        "-spiffeID", run_spiffe_id(run_id, agent),
        "-selector", f"docker:label:{RUN_LABEL}:{run_id}",
        "-selector", f"docker:label:{AGENT_LABEL}:{agent}",
        "-jwtSVIDTTL", _entry_ttl_for(run_ttl_seconds),
    ]
    if expiry is not None:
        argv += ["-entryExpiry", str(expiry)]
    return argv


def _show_argv(run_id: str) -> list[str]:
    return _server_cmd() + [
        "entry", "show",
        "-selector", f"docker:label:{RUN_LABEL}:{run_id}",
        "-output", "json",
    ]


def _log(msg: str) -> None:
    print(f"[spire-registrar] {msg}", flush=True)


def _run(argv: list[str], *, capture: bool = False) -> str | None:
    try:
        res = subprocess.run(
            argv, capture_output=True, text=True, timeout=15, check=False,
        )
        if res.returncode != 0:
            _log(f"command failed ({res.returncode}): {res.stderr.strip()[:200]}")
            return None
        return res.stdout if capture else ""
    except (OSError, subprocess.SubprocessError) as exc:
        _log(f"command error: {exc}")
        return None


def register_run(run_id: str, agent: str,
                 run_ttl_seconds: int | None = None) -> None:
    """Create the per-run entry so the container gets its per-run SVID.
    Best-effort. `run_ttl_seconds` is this run's GRANTED wall clock; without it
    the entry is sized from the platform default and a longer grant fails closed
    on its first tool call."""
    if not enabled():
        return
    expiry = int(time.time()) + _entry_max_age_for(run_ttl_seconds)
    if _run(register_argv(run_id, agent, expiry, run_ttl_seconds)) is not None:
        _log(f"registered {run_spiffe_id(run_id, agent)} "
             f"(docker:label:{RUN_LABEL}:{run_id} + {AGENT_LABEL}:{agent})")


def _entry_ids(run_id: str) -> list[str]:
    out = _run(_show_argv(run_id), capture=True)
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    # SPIRE `entry show -output json` => {"entries": [{"id": ...}, ...]}
    return [e["id"] for e in data.get("entries", []) if e.get("id")]


def unregister_run(run_id: str) -> None:
    """Delete the run's entry (found by its label selector). Best-effort, so a
    missed delete just leaves a harmless stale entry that no live container matches."""
    if not enabled():
        return
    ids = _entry_ids(run_id)
    for entry_id in ids:
        _run(_server_cmd() + ["entry", "delete", "-entryID", entry_id])
    if ids:
        _log(f"unregistered run {run_id} ({len(ids)} entry/entries)")

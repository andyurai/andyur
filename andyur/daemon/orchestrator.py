"""WHERE a run executes, and in what shape.

The daemon decides WHICH runs execute and when. This module decides where they
land: a host process, one locked-down container, or a two-container pod. That
separation is the point. The daemon's loop -- reap, heartbeat, kill, launch -- is
orchestrator-agnostic, so moving Andyur to Kubernetes is a new implementation of
the four methods below rather than a rewrite of the coordination code.

The interface is deliberately tiny, because it is the whole surface a scheduler
actually needs:

    launch(spec, logfile)   start one run, return the handle whose exit means
                            "this run is over"
    kill(run_ids)           destroy runs, idempotently
    list_running()          what is executing here, read from the RUNTIME rather
                            than from this process's memory (so a restarted
                            daemon can still see -- and stop -- what it inherited)
    sweep()                 reconcile leftovers the above cannot name

`sweep` exists because a pod has a part the run id does not directly name: if the
sidecar is gone, its agent container is invisible to `list_running` and would
never be condemned. It is also the seam a Kubernetes implementation needs anyway,
since that one is a reconcile controller by nature.

THE THREE SHAPES (andyur/config.py, ANDYUR_AGENT_SPLIT):

  HostOrchestrator       a plain subprocess. Dev only: the agent shares the
                         host, so the isolation story is "there isn't one".
  ContainerOrchestrator  one container per run. The runner supervises as root
                         inside it and drops the untrusted agent CLI to uid 1001;
                         the UID SPLIT is the boundary between them.
  PodOrchestrator        two containers per run. The sidecar holds every
                         credential; the agent container holds nothing and (O1)
                         is single-homed on its OWN per-run --internal network,
                         reaching only its sidecar by the `sidecar` alias -- NOT
                         the sidecar's netns, so it inherits none of the sidecar's
                         egress to the control plane (that shared-netns version
                         was the F3 gap this closes).
                         The container boundary replaces the uid split FOR THE
                         HEADLESS AGENT, which runs unprivileged from PID 1 in
                         its own container. The sidecar still keeps SETUID,
                         because two paths still spawn the CLI inside it --
                         conversational runs and graph capture -- and saying
                         otherwise broke both, silently. See _sandbox_argv.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .. import config, identity, otel, spire_registrar
from . import seccomp
from ..config import BROKER_URL, LITELLM_URL, PROJECT_ROOT, SERVER_URL

# Docker volume holding the containerized SPIRE agent's Workload API socket.
# Mounted into the SIDECAR ONLY -- never the agent container. That is what keeps
# the agent unable to attest as anything: it holds no identity and cannot ask for
# one.
SPIRE_SOCKET_VOLUME = os.environ.get("ANDYUR_SPIRE_SOCKET_VOLUME", "andyur-spire-sockets")

SANDBOX_IMAGE = os.environ.get("ANDYUR_SANDBOX_IMAGE", "andyur-runner")
# The agent container's image. Defaults to the same image, run with a different
# entrypoint and a different uid. Split them (an image with no control-plane code
# for the agent, one with no Claude CLI for the sidecar) when the build pipeline
# is ready; the seam is here.
AGENT_IMAGE = os.environ.get("ANDYUR_AGENT_IMAGE", SANDBOX_IMAGE)
SANDBOX_MEMORY = os.environ.get("ANDYUR_SANDBOX_MEMORY", "2g")
SANDBOX_CPUS = os.environ.get("ANDYUR_SANDBOX_CPUS", "2")
SANDBOX_PIDS = os.environ.get("ANDYUR_SANDBOX_PIDS", "512")
SANDBOX_NETWORK = os.environ.get("ANDYUR_SANDBOX_NETWORK", "")
# The unprivileged uid the agent container runs as. Baked into Dockerfile.runner
# as `agent`; here it is applied by --user, so the agent process is unprivileged
# from PID 1 rather than dropping to it mid-flight.
AGENT_UID = os.environ.get("ANDYUR_AGENT_UID", "1001")

# Container naming. Deliberately DIFFERENT prefixes rather than a suffix on the
# run name: `docker ps --filter name=^andyur-run-` must match sidecars and only
# sidecars, or the agent container of run X gets adopted as a phantom run whose
# id is "X-agent" -- reported as executing, subtracted from free slots, and
# condemned forever because no such run exists.
RUN_PREFIX = "andyur-run-"
AGENT_PREFIX = "andyur-agent-"


def _read_as_evidence(path: str, label: str) -> str:
    """Read an already-validated evidence file without an unbounded allocation."""
    with open(path, "rb") as handle:
        raw = handle.read((64 << 10) + 1)
    if len(raw) > 64 << 10:
        raise config.InsecureProfile(f"{label} exceeds the 64 KiB safety limit")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise config.InsecureProfile(f"{label} is not UTF-8") from exc


def run_container(run_id: str) -> str:
    return f"{RUN_PREFIX}{run_id}"


def agent_container(run_id: str) -> str:
    return f"{AGENT_PREFIX}{run_id}"


# O1 run-scoped isolation (F3 remediation, docs/network-topology.md). Each pod
# run gets its OWN internal Docker network holding just that run's sidecar and
# agent. The agent is single-homed on this network, so it reaches ONLY its
# sidecar -- no route to the control plane, other runs, or the internet. The
# sidecar stays on SANDBOX_NETWORK for its egress to the server/AS/LLM and is
# also connected here under a stable alias the agent addresses it by.
NET_PREFIX = "andyur-net-"
SIDECAR_ALIAS = "sidecar"
RUN_NETWORK_LABEL = "andyur.role=run-network"


def run_network(run_id: str) -> str:
    return f"{NET_PREFIX}{run_id}"


def _net_create(name: str) -> bool:
    """Create the per-run network as `--internal`: no default route and no
    masquerade, so no off-subnet or internet egress. (The network still has a
    gateway, which is the Docker host, and the host is L3-reachable at that
    gateway IP -- host SERVICES are kept off it by binding every compose publish
    to 127.0.0.1, see infra/docker-compose.yml.) Returns True on success.
    Labeled so `sweep` can find orphans. Returns
    False (never raises) if docker is absent or times out, so the caller can fail
    the launch cleanly rather than with an unhandled error."""
    try:
        res = subprocess.run(
            ["docker", "network", "create", "--internal",
             "--label", RUN_NETWORK_LABEL, name],
            capture_output=True, text=True, check=False, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    if res.returncode != 0:
        # Surface docker's own reason -- most usefully the pool-exhaustion
        # message ("could not find an available, non-overlapping IPv4 address
        # pool"), which the caller's generic RuntimeError would otherwise hide.
        log(f"docker network create {name} failed: {res.stderr.strip()}")
    return res.returncode == 0


def _net_connect(name: str, container: str, alias: str) -> bool:
    """Attach a running container to the per-run network under a stable alias."""
    try:
        res = subprocess.run(
            ["docker", "network", "connect", "--alias", alias, name, container],
            capture_output=True, text=True, check=False, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    if res.returncode != 0:
        log(f"docker network connect {name} {container} failed: {res.stderr.strip()}")
    return res.returncode == 0


def _list_run_networks() -> list[str] | None:
    """Names of every per-run isolation network (label-filtered), or None if the
    runtime could not be asked. Same None-means-do-not-destroy safety as
    `_list_names`: a failed query must not read every live network as an orphan."""
    try:
        res = subprocess.run(
            ["docker", "network", "ls", "--filter", f"label={RUN_NETWORK_LABEL}",
             "--format", "{{.Name}}"],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log(f"could not list run networks ({type(exc).__name__})")
        return None
    if res.returncode != 0:
        return None
    return [n.strip() for n in res.stdout.splitlines() if n.strip()]


def _net_rm(name: str) -> None:
    """Remove the per-run network. Idempotent and best-effort: a network that
    does not exist, or still has an endpoint mid-teardown, is not an error worth
    failing a cleanup over -- the next launch recreates it and `sweep` reaps it."""
    try:
        subprocess.run(
            ["docker", "network", "rm", name],
            capture_output=True, text=True, check=False, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


# What a run id may look like when it comes back from Docker rather than from the
# control plane. Anything else is not ours to report or to kill.
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def log(msg: str) -> None:
    print(f"[daemon] {msg}", flush=True)


@dataclass(frozen=True)
class RunSpec:
    """Everything an orchestrator needs to start one run. The credentials are
    passed explicitly rather than read from the environment so that WHICH
    credential reaches WHICH container is visible at the call site -- in pod mode
    that distinction is the security boundary."""
    run_id: str
    agent: str
    run_token: str | None = None
    broker_token: str | None = None
    channel_token: str | None = None
    server_run_ttl: int | None = None
    # Conversational runs execute IN-PROCESS in the sidecar in every mode (their
    # turn loop is not split yet), so a pod must not start an agent container for
    # one: it would poll a channel that is never created, wait out the whole
    # connect timeout, and exit -- a wasted container and a failure-shaped log
    # line for a run that is working perfectly.
    run_type: str = "headless"
    # Stable worker generation selected before assignment. Kubernetes ownership
    # and deletion are scoped to this value so a worker cannot adopt or delete
    # another replica's incarnation of the same logical run.
    generation: str | None = None
    # Immutable registry identity selected by the control plane. Kubernetes
    # refuses unbound agents because this identity is part of the workload and
    # audit labels; substituting the display name would make that claim false.
    registry_agent_id: str | None = None
    broker_enabled: bool = False
    # The run's SEALED input (runinput canonical text) or None. Only the
    # exec/v1 launcher reads it: every other runtime fetches the run record
    # itself and finds the same value there.
    run_input: str | None = None
    # The model the registry resolution GRANTED, or None. Same reader: the
    # exec/v1 launcher resolves services.model.name from it; runtime-v1 reads
    # it from the run's context document.
    model: str | None = None


_HOST_LOCAL = ("127.0.0.1", "localhost", "0.0.0.0", "[::1]")


def _host_local(url: str) -> bool:
    """Does this URL name the caller's own machine?

    Checked on the url ALREADY passed through `_container_url`, so a dev-profile
    rewrite to the host gateway has happened and is correctly not host-local.
    What remains host-local at that point is a URL nothing rewrote -- which in
    production means the run's own loopback.
    """
    from urllib.parse import urlsplit
    return (urlsplit(url).hostname or "") in {h.strip("[]") for h in _HOST_LOCAL}


def _container_url(url: str) -> str:
    """Rewrite a host-local URL so a run container can reach the host service
    (server, Ollama, collector) through the Docker host gateway. 0.0.0.0 is a
    bind-any address a server may advertise itself as; from a container it is not
    routable, so it means the host just like localhost.

    Not done in the production profile. There, runs live on an internal network
    with no route to the host at all, and the services they may reach are
    containers ON that network, addressed by name. Rewriting to the host gateway
    would quietly produce URLs that cannot resolve, and the resulting failure
    would look like a bug rather than the boundary doing its job."""
    if config.PROD:
        return url
    for host_local in ("127.0.0.1", "localhost", "0.0.0.0"):
        url = url.replace(host_local, "host.docker.internal")
    return url


# Execution context forwarded into a run container: which backend, which model,
# what bounds. Not credentials -- those are passed explicitly per container.
_FORWARD = ["ANDYUR_LLM", "ANDYUR_AGENT_MODEL", "ANDYUR_RUN_TTL_SECONDS",
            "ANDYUR_MAX_TURNS", "ANDYUR_OTEL", "ANDYUR_OTEL_TOOL_PAYLOADS",
            "ANDYUR_CONVERSATION_IDLE_SECONDS", "ANDYUR_CONVERSATION_MAX_SECONDS",
            "ANDYUR_CONVERSATION_TURN_TTL_SECONDS", "ANDYUR_CONVERSATION_MAX_TURNS",
            "ANDYUR_CONVERSATION_MAX_TURN_BYTES", "ANDYUR_CONVERSATION_MAX_EVENT_BYTES"]

# What the AGENT container gets. Strictly the execution context it needs to drive
# the SDK -- no server URL, no credential, no SPIRE socket. The short list IS the
# security claim: read it and you can see there is nothing here worth stealing.
_AGENT_FORWARD = ["ANDYUR_LLM", "ANDYUR_AGENT_MODEL", "ANDYUR_MAX_TURNS",
                  "ANDYUR_PROFILE", "ANDYUR_OTEL"]


def _limits() -> list[str]:
    return ["--memory", SANDBOX_MEMORY, "--cpus", SANDBOX_CPUS,
            "--pids-limit", SANDBOX_PIDS]


def _sandbox_argv(agent: str, run_id: str, run_token: str | None = None,
                  broker_token: str | None = None, server_run_ttl: int | None = None,
                  channel_token: str | None = None, pod: bool = False) -> list[str]:
    """The `docker run` command for a run's PRIMARY container: all capabilities
    dropped, no privilege escalation, CPU/memory/PID limits, and NO host
    filesystem mounted at all. The mind lives in object storage behind the
    server, which the runner reaches over HTTP, so a sandboxed run needs zero
    host access.

    Single-container mode: the runner supervises as root INSIDE this container
    and needs SETUID/SETGID to drop the untrusted agent to uid 1001, isolating
    the agent from the runner's /proc and run token (see Dockerfile.runner).

    Pod mode: the agent is not here at all -- it is a separate container. Nothing
    in this container drops privilege, so SETUID/SETGID are NOT restored. The
    capability that existed solely to build the uid boundary is removed once the
    container boundary provides it instead.
    """
    argv = [
        "docker", "run", "--rm",
        "--name", run_container(run_id),
        # per-run labels: identify the container itself (not a uid the agent
        # shares), which is what a container-attested per-run SPIFFE entry keys on
        "--label", f"andyur.run_id={run_id}",
        "--label", f"andyur.agent={agent}",
        "--label", "andyur.role=sidecar" if pod else "andyur.role=run",
        "--cap-drop", "ALL",
    ]
    if SANDBOX_NETWORK:
        argv += ["--network", SANDBOX_NETWORK]
    if not config.PROD:
        # Dev convenience: reach a control plane, Ollama or collector running on
        # the host. Deliberately absent in production -- a route to the host is a
        # route to everything the host can reach, which is the whole internet.
        argv += ["--add-host", "host.docker.internal:host-gateway"]
    # Restore ONLY the two capabilities needed to drop an agent to its own
    # unprivileged uid. no-new-privileges stays on: it blocks GAINING privilege
    # via execve, it does not block dropping to a lower uid.
    #
    # THIS IS STILL NEEDED IN POD MODE, and the reason is worth stating because
    # the first version of the pod dropped it and broke two things silently. The
    # pod moves the HEADLESS agent into its own container, but two paths still
    # spawn the Claude CLI inside the SIDECAR: conversational runs (a persistent
    # turn loop, in-process in every mode) and graph capture (extract_graph is
    # itself a model call). Both go through the setpriv wrapper, and without
    # CAP_SETUID setpriv fails closed -- so pod mode made every conversational
    # run fail, and made graph capture return nothing at all, quietly, because
    # extract_graph swallows its own errors.
    #
    # So the honest statement is narrower than "the pod retires the uid split":
    # it retires it for the headless agent, which is the part that runs untrusted
    # code, while the sidecar keeps the means to isolate the CLI it still spawns
    # for itself. Removing this needs those two paths split as well (Phase 3).
    argv += ["--cap-add", "SETUID", "--cap-add", "SETGID"]
    # The RUNNER role's filter: keeps the setuid family, because this container
    # is where setpriv drops the CLI it spawns for conversational runs and graph
    # capture. The agent container gets the tighter one.
    argv += ["--security-opt", "no-new-privileges"] + seccomp.docker_args(
        seccomp.RUNNER) + _limits() + [
        "-e", f"ANDYUR_SERVER_URL={_container_url(SERVER_URL)}",
        # the container IS the sandbox; tell Claude Code so it does not try to
        # build its own bash sandbox (which fails closed to a read-only FS when
        # we drop the capabilities its sandbox needs, blocking the agent's writes)
        "-e", "IS_SANDBOX=1",
    ]
    # the per-run token (R1): names which agent/run this container is, so the
    # server scopes its calls. Delivered here through the trusted spawn channel.
    if run_token:
        argv += ["-e", f"ANDYUR_RUN_TOKEN={run_token}"]
    # The broker credential, deliberately distinct from the run token above: the
    # model client sends this one, so it is minted for the broker alone.
    if broker_token:
        argv += ["-e", f"ANDYUR_BROKER_TOKEN={broker_token}"]
    # WHICH SHAPE THE RUNNER INSIDE SHOULD TAKE. Set explicitly and always, not
    # forwarded: ANDYUR_AGENT_SPLIT was previously injected only in the pod
    # branch, so `ANDYUR_SANDBOX=on ANDYUR_AGENT_SPLIT=process` started a
    # container whose runner saw no split variable at all and quietly ran the
    # SINGLE-PROCESS shape. The documented "two processes, one container" simply
    # did not exist under sandboxing, and nothing said so.
    argv += ["-e", f"ANDYUR_AGENT_SPLIT={'pod' if pod else config.AGENT_SPLIT_MODE}"]
    if pod:
        # This container is the SIDECAR of a two-container pod: it must wait for
        # the agent container to connect rather than spawning an agent itself.
        argv += [
            "-e", f"ANDYUR_CHANNEL_PORT={config.CHANNEL_PORT}",
            "-e", f"ANDYUR_AGENT_CONNECT_TIMEOUT={config.AGENT_CONNECT_TIMEOUT}",
            # O1: the agent is on its own per-run network, not this sidecar's
            # netns, so it reaches the sidecar by this alias, not loopback. The
            # runner binds all interfaces and advertises this name (the same
            # pattern the Kubernetes path uses with the proxy Pod IP), so the
            # tool/model/channel URLs it hands the agent resolve on the per-run
            # network. The alias exists only on the per-run network, so it is
            # private to this run.
            "-e", f"ANDYUR_ADVERTISE_HOST={SIDECAR_ALIAS}",
        ]
        if channel_token:
            argv += ["-e", f"ANDYUR_CHANNEL_TOKEN={channel_token}"]
    forward = list(_FORWARD)
    if LITELLM_URL:
        # Trusted PRIMARY/sidecar only. The URL is routing; the key is authority.
        # Neither belongs in _AGENT_FORWARD, and the key is passed explicitly so
        # nobody can accidentally widen that allowlist later.
        argv += ["-e", f"ANDYUR_LITELLM_URL={_container_url(LITELLM_URL)}"]
        if os.environ.get("LITELLM_MASTER_KEY"):
            argv += ["-e", f"LITELLM_MASTER_KEY={os.environ['LITELLM_MASTER_KEY']}"]
    if BROKER_URL:
        # brokered: the container reaches the broker (which holds the key); the
        # provider key is NOT passed in, so a compromised agent has none to steal
        argv += ["-e", f"ANDYUR_BROKER_URL={_container_url(BROKER_URL)}"]
    elif not config.PROD:
        # Unbrokered dev fallback. Never in production: the profile check already
        # requires a broker whenever a key exists, and this is the second lock on
        # the same door -- the one that holds if that check is ever loosened.
        forward.append("ANTHROPIC_API_KEY")
    for var in forward:
        if var in os.environ:
            argv += ["-e", f"{var}={os.environ[var]}"]
    # ...and let the server's TTL win over any local one, so the run inside the
    # container and the record on the server agree on when it is over.
    if server_run_ttl:
        argv += ["-e", f"ANDYUR_RUN_TTL_SECONDS={server_run_ttl}"]
    if config.AS_TOKEN_ENDPOINT:
        # The adopter's authorization server, into the SIDECAR only: the runner
        # builds the gateway's exchange config from these, and without them a
        # sandboxed run cannot reach the AS at all -- the exchange the host
        # verified simply never existed inside the container.
        #
        # The TOKEN ENDPOINT is a network address, so it gets the container
        # rewrite like every other host-local service here. The ISSUER does
        # not: it is an identifier compared byte-for-byte against the token's
        # `iss` claim, and rewriting it makes every validation fail while the
        # network path works perfectly.
        argv += ["-e",
                 f"ANDYUR_AS_TOKEN_ENDPOINT={_container_url(config.AS_TOKEN_ENDPOINT)}"]
        argv += ["-e", f"ANDYUR_AS_PROVIDER={config.AS_PROVIDER}",
                 "-e", f"ANDYUR_AS_CAPABILITY={config.AS_CAPABILITY}",
                 "-e", f"ANDYUR_AS_PRODUCT_VERSION={config.AS_PRODUCT_VERSION}"]
        if config.AS_CERTIFICATION_FILE and \
                config.AS_CERTIFICATION_PUBLIC_KEY_FILE:
            certification_target = "/run/secrets/andyur-as/certification.json"
            public_key_target = "/run/secrets/andyur-as/certifier.pub"
            argv += [
                "-v", f"{os.path.abspath(config.AS_CERTIFICATION_FILE)}:"
                      f"{certification_target}:ro",
                "-v", f"{os.path.abspath(config.AS_CERTIFICATION_PUBLIC_KEY_FILE)}:"
                      f"{public_key_target}:ro",
                "-e", f"ANDYUR_AS_CERTIFICATION_FILE={certification_target}",
                "-e", "ANDYUR_AS_CERTIFICATION_PUBLIC_KEY_FILE="
                      f"{public_key_target}",
            ]
        if config.AS_RESOURCE_SCOPE:
            argv += ["-e", f"ANDYUR_AS_RESOURCE_SCOPE={config.AS_RESOURCE_SCOPE}"]
        if config.AS_ISSUER:
            argv += ["-e", f"ANDYUR_AS_ISSUER={config.AS_ISSUER}"]
        if config.AS_JWKS_URL:
            argv += ["-e", f"ANDYUR_AS_JWKS={_container_url(config.AS_JWKS_URL)}"]
        if config.AS_CLIENT_ID:
            argv += ["-e", f"ANDYUR_AS_CLIENT_ID={config.AS_CLIENT_ID}"]
        if config.AS_CLIENT_SECRET:
            # A credential, passed explicitly like the run token above -- never
            # via _FORWARD, whose comment is the contract that it carries none,
            # and never to the agent container (_AGENT_FORWARD), whose short
            # list is the security claim.
            argv += ["-e", f"ANDYUR_AS_CLIENT_SECRET={config.AS_CLIENT_SECRET}"]
    argv += ["-e", f"ANDYUR_OLLAMA_URL={_container_url(os.environ.get('ANDYUR_OLLAMA_URL', 'http://localhost:11434'))}"]
    if otel.OTEL_ON:
        endpoint = os.environ.get("ANDYUR_OTEL_ENDPOINT", "http://localhost:4318")
        reachable = _container_url(endpoint)
        # DO NOT HAND A RUN A COLLECTOR IT CANNOT REACH. In production
        # `_container_url` deliberately does not rewrite -- the run is on an
        # internal network with no route to the host -- so a host-local endpoint
        # (the default is `localhost:4318`) resolves to the run's OWN loopback,
        # where nothing listens. The exporter then retries forever, and every
        # run's log fills with connection-refused warnings and export-failed
        # errors that have nothing to do with the run.
        #
        # Telemetry off is the honest configuration for that case, and it is
        # said once here rather than implied by a wall of retries. Point
        # ANDYUR_OTEL_ENDPOINT at a collector ON the run network to get traces
        # back.
        if _host_local(reachable):
            argv += ["-e", "ANDYUR_OTEL=off"]
            log(f"run telemetry off: {reachable} is host-local and this run has "
                "no route to the host; set ANDYUR_OTEL_ENDPOINT to a collector "
                "on the run network to export traces")
        else:
            argv += ["-e", f"ANDYUR_OTEL_ENDPOINT={reachable}"]
    if spire_registrar.enabled():
        # Mount the containerized SPIRE agent's Workload API socket so a workload
        # here can fetch this run's SVID -- issued because the container carries
        # the andyur.run_id + andyur.agent labels the per-run entry is keyed on.
        # Read-only, and SIDECAR ONLY: the agent container never gets this, so it
        # cannot attest as anything.
        argv += [
            "-v", f"{SPIRE_SOCKET_VOLUME}:/run/spire/sockets:ro",
            "-e", "SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/api.sock",
        ]
    argv += [SANDBOX_IMAGE, "--agent", agent, "--run-id", run_id]
    return argv


def _agent_argv(agent: str, run_id: str, channel_token: str | None = None) -> list[str]:
    """The `docker run` command for the AGENT container of a pod.

    Everything here is a subtraction. It joins ONLY this run's own internal
    network (O1), where the single other member is its sidecar, runs as an
    unprivileged uid from PID 1, drops every capability, and carries no
    credential, no server URL, and no SPIRE socket. What it can do is talk to the
    sidecar (by the `sidecar` alias on that network); what it cannot do is reach
    the control plane, other runs, the internet, or act as the platform.

    Note what is ABSENT and why:
      netns share    the agent does NOT join the sidecar's netns anymore. Sharing
                     a netns gave the agent the sidecar's routes -- including its
                     egress to the control plane on SANDBOX_NETWORK -- so the
                     agent-sink held only at the app layer (F3). A separate netns
                     on a per-run internal network is what makes it a real sink.
      --add-host     the per-run network is `--internal` (no default route,
                     no masquerade), so there is no internet or off-subnet
                     route to map. (The gateway IP is the host and stays
                     L3-reachable; host services are bound to 127.0.0.1 so none
                     is reachable there.)
      --cap-add      nothing in THIS container drops privilege (the agent is
                     already unprivileged at PID 1), so nothing needs it here.
                     The sidecar still has it, for the CLI it spawns itself.
      -v             no mounts at all, SPIRE socket included
    """
    argv = [
        "docker", "run", "--rm",
        "--name", agent_container(run_id),
        "--label", f"andyur.run_id={run_id}",
        "--label", f"andyur.agent={agent}",
        "--label", "andyur.role=agent",
        # O1: the agent's OWN netns on this run's internal network only. The
        # sidecar is reachable here as `sidecar`; nothing else is on this
        # network, and it is --internal (no default route/masquerade -> no
        # internet or off-subnet egress), so the untrusted agent reaches only
        # its sidecar.
        "--network", run_network(run_id),
        # unprivileged from PID 1, rather than root dropping to it later
        "--user", f"{AGENT_UID}:{AGENT_UID}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        # The AGENT role's filter, which is tighter than the sidecar's in the
        # one way that matters here: this container is unprivileged from PID 1
        # and never changes uid, so the whole setuid family is denied on top of
        # the ptrace family both roles lose.
    ] + seccomp.docker_args(seccomp.AGENT) + _limits() + [
        "-e", "IS_SANDBOX=1",
        "-e", "HOME=/home/agent",
        # The uid split is RETIRED in this shape: the setpriv wrapper exists to
        # drop a root runner's child to the agent uid, and there is no root
        # runner here. Blanking it makes the SDK spawn the real CLI directly,
        # already unprivileged. An empty value (not an unset one) so the image's
        # own ENV cannot supply it.
        "-e", "ANDYUR_AGENT_CLI=",
    ]
    if channel_token:
        argv += ["-e", f"ANDYUR_CHANNEL_TOKEN={channel_token}"]
    # Bound the agent's own wait for the sidecar by the same number the sidecar
    # waits for it, so the two halves cannot disagree about when to give up.
    argv += ["-e", f"ANDYUR_AGENT_CONNECT_TIMEOUT={config.AGENT_CONNECT_TIMEOUT}"]
    for var in _AGENT_FORWARD:
        if var in os.environ:
            argv += ["-e", f"{var}={os.environ[var]}"]
    # The model endpoint for a DIRECT backend (ANDYUR_LLM=ollama), where the SDK
    # is pointed straight at it rather than at the sidecar's proxy. Not a
    # credential, just an address. Always passed, because keying it on the broker
    # being configured got it wrong in the shape that mixes them -- a broker set
    # for api mode while the run is on ollama -- leaving the agent to default to
    # its own loopback, where nothing is listening.
    #
    # In the brokered production path this address is unreachable anyway (the run
    # network has no route to it) and unused: there the agent talks to the
    # sidecar's loopback model proxy and never learns an upstream address at all.
    argv += ["-e", f"ANDYUR_OLLAMA_URL={_container_url(os.environ.get('ANDYUR_OLLAMA_URL', 'http://localhost:11434'))}"]
    argv += [
        "--entrypoint", "python", AGENT_IMAGE,
        "-m", "andyur.agent",
        # O1: address the sidecar by its per-run-network alias, not loopback --
        # the agent no longer shares the sidecar's netns.
        "--channel-url", f"http://{SIDECAR_ALIAS}:{config.CHANNEL_PORT}",
    ]
    return argv


# ---------------------------------------------------------------------------


class Orchestrator(ABC):
    name = "orchestrator"

    @abstractmethod
    def launch(self, spec: RunSpec, logfile) -> subprocess.Popen:
        """Start one run. The returned handle's exit means the run is over."""

    @abstractmethod
    def kill(self, run_ids: list[str]) -> None:
        """Destroy these runs. Idempotent, and never verified: the server keeps
        condemning whatever is still reported as executing, so a kill that missed
        simply comes back on the next beat."""

    def list_running(self) -> list[str]:
        """Run ids executing here according to the RUNTIME, not this process."""
        return []

    def sweep(self) -> None:
        """Reconcile leftovers list_running cannot name. Default: nothing."""

    def cleanup(self, run_id: str) -> None:
        """Release whatever the run leaves behind once its handle has exited."""

    def release_after_outcome(self, run_id: str, generation: str) -> None:
        """Release what a FAILED launch kept for the outcome to land first.
        Only a runtime with a run fence keeps anything; elsewhere, nothing."""

    def engine_runs(self) -> list[tuple[str, str]]:
        """Runs the ENGINE launched that this reconciler did not, as exact
        (run, generation) pairs. Only a runtime with a run fence can find them
        safely; everywhere else there are none."""
        return []

    def read_exec_completion(self, run_id: str):
        """Daemon-owned completion for a stock exec/v1 run, or None.

        runtime-v1 runs -- and every local shape -- report their own
        completion: the runner streams a `done` the server turns into a
        finished run. A stock exec/v1 workload reports nothing, so the platform
        reads its exit at the one boundary it owns, the process's exit. Only the
        Kubernetes orchestrator, which holds that boundary, overrides this;
        every other shape returns None and the daemon leaves the finish to the
        run's own reporter.

        Returns ``(exit_code, stdout, stderr, output_max_bytes)`` for a tracked
        exec/v1 run, else None. Must be called BEFORE cleanup deletes the Pod,
        or the exit code and logs are no longer readable.
        """
        return None

    def describe(self, run_id: str) -> str:
        """WHERE this run was placed, for the launch log.

        Load-bearing, not decoration: host and container launches were once
        indistinguishable in the log, so nothing could confirm a run had actually
        been contained -- which is how a runner image that could not even start
        under ANDYUR_SANDBOX=on went unnoticed. The e2e harness asserts against
        this line, so it has to name the shape precisely."""
        return "somewhere unspecified"


# The prefix of an execution generation the ENGINE's claim records (Architecture
# B+, ADR-014 D11; coordinator.claim_for_execution). A reconciler that did not
# launch a run finds it by this, then verifies it like any adopted generation.
ENGINE_GENERATION_PREFIX = "exec-"


class HostOrchestrator(Orchestrator):
    """A plain subprocess on this host. Dev only: the agent runs with the
    daemon's own filesystem and network, so the containment story is that there
    isn't one. The process GROUP is the only handle -- killing the supervisor
    alone would leave the CLI and every shell it spawned running as orphans."""

    name = "host"

    def launch(self, spec: RunSpec, logfile) -> subprocess.Popen:
        env = identity.runner_launch_env(spec.run_token, spec.broker_token)
        if spec.server_run_ttl:
            env["ANDYUR_RUN_TTL_SECONDS"] = str(spec.server_run_ttl)
        return subprocess.Popen(
            [identity.role_python("runner"), "-m", "andyur.runner",
             "--agent", spec.agent, "--run-id", spec.run_id],
            cwd=PROJECT_ROOT, stdout=logfile, stderr=subprocess.STDOUT, env=env,
            # Its own process group, so a kill takes the whole tree and never the
            # daemon. Detaching also matches the documented behaviour: runners
            # survive the daemon and report for themselves.
            start_new_session=True,
        )

    def kill(self, run_ids: list[str]) -> None:
        pass   # the daemon signals the process group it holds; see Daemon.kill

    def describe(self, run_id: str) -> str:
        return "on the host"


class ContainerOrchestrator(Orchestrator):
    """One locked-down container per run. The runner supervises as root inside
    it and drops the untrusted agent CLI to uid 1001; the uid split is the
    boundary between them."""

    name = "container"
    pod = False

    def launch(self, spec: RunSpec, logfile) -> subprocess.Popen:
        # Register this run's SVID BEFORE the container starts, so the entry has
        # time to propagate to the SPIRE agent before the workload inside fetches
        # its identity. Keyed on the container labels the argv stamps. No-op
        # unless the registrar is enabled. Rolled back if the launch itself fails
        # (the run never enters the daemon's table, so reap would not).
        spire_registrar.register_run(spec.run_id, spec.agent,
                                     spec.server_run_ttl)
        try:
            return subprocess.Popen(
                _sandbox_argv(spec.agent, spec.run_id, spec.run_token,
                              spec.broker_token, spec.server_run_ttl,
                              spec.channel_token, pod=self.pod),
                stdout=logfile, stderr=subprocess.STDOUT,
                # Its OWN process group, exactly as on the host branch. Without
                # this the docker client inherits the DAEMON's group, and a kill
                # that signals the group would take the daemon and every other
                # run on this worker with it.
                start_new_session=True,
            )
        except Exception:
            spire_registrar.unregister_run(spec.run_id)
            raise

    def _names_to_kill(self, run_ids: list[str]) -> list[str]:
        return [run_container(r) for r in run_ids]

    def kill(self, run_ids: list[str]) -> None:
        # ONE invocation for the whole batch. Per-run subprocesses meant the beat
        # took the sum of them, so twenty condemned runs at the docker timeout
        # blew the 45s worker-stale window and the server declared the worker dead
        # while its containers were still executing. Failures are not inspected:
        # an unkillable container simply comes back on the next beat.
        subprocess.run(
            ["docker", "kill", "--signal=KILL"] + self._names_to_kill(run_ids),
            capture_output=True, text=True, check=False, timeout=30,
        )

    def _list_names(self, prefix: str) -> list[str] | None:
        """Names of RUNNING containers with this prefix, or None if the runtime
        could not be asked.

        The None is the whole point, and it is a safety property rather than
        tidiness. "I asked and there are none" and "I could not ask" are
        different facts, and a caller that DESTROYS things must never confuse
        them: sweep() kills agent containers whose sidecar is absent, so if a
        failed query reported an empty list it would read every healthy pod on
        the worker as an orphan and kill them all. A transient `docker ps`
        timeout is entirely plausible under load -- the kill batching exists
        because docker calls near their timeout already blew a worker window.
        """
        try:
            res = subprocess.run(
                ["docker", "ps", "--filter", f"name=^{prefix}", "--format", "{{.Names}}"],
                capture_output=True, text=True, check=False, timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log(f"could not list containers ({type(exc).__name__})")
            return None
        if res.returncode != 0:
            # The daemon answered, but with an error. Same rule: not an answer.
            log(f"could not list containers (docker exited {res.returncode})")
            return None
        found = set()
        for line in res.stdout.splitlines():
            name = line.strip()
            if not name.startswith(prefix):
                continue
            run_id = name[len(prefix):]
            # Validate the shape. A container name is attacker-influenceable on a
            # shared host, and these ids become SQL bind parameters, kill targets
            # and a regex; one carrying a newline injected extra run ids into the
            # worker's report, which the server then finalized as real runs.
            if _RUN_ID_RE.match(run_id):
                found.add(run_id)
        return sorted(found)

    def list_running(self) -> list[str]:
        """RUNNING run containers on this host, from Docker rather than memory.

        Without this the kill switch cannot see its own second population: it
        condemns runs the worker REPORTS, and after a restart the worker holds
        nothing, so every container in flight at that moment becomes permanently
        invisible -- still executing, still holding a run token, never again
        eligible to be stopped.

        Matched and read back by the NAME we assign, so what is adopted and what
        can be killed are the same key. Two mistakes are designed out: -a would
        list EXITED and CREATED containers, which are not executing but would be
        adopted, reported in flight, subtracted from free slots and condemned
        forever (docker kill cannot kill a stopped container); and adopting by
        LABEL while killing by NAME meant a container whose label said run-x but
        whose name did not was reported killed while it kept running.

        An unanswerable query degrades to "nothing adopted", which is safe HERE
        (it only under-reports capacity for a beat). sweep() must NOT make the
        same reduction -- see _list_names.
        """
        return self._list_names(RUN_PREFIX) or []

    def cleanup(self, run_id: str) -> None:
        # Drop the run's SPIRE entry now the container is gone, so a future
        # container cannot reuse a stale label->identity binding.
        spire_registrar.unregister_run(run_id)

    def describe(self, run_id: str) -> str:
        return f"in container {run_container(run_id)}"


class PodOrchestrator(ContainerOrchestrator):
    """Two containers per run: a sidecar holding every credential, and an agent
    container holding none, single-homed on the run's own --internal network (O1)
    and reaching only its sidecar by the `sidecar` alias.

    The sidecar's container is the run's LIFECYCLE handle -- it is the process
    that finalizes the run -- so `launch` returns it and the agent container is
    tracked alongside. The agent is started second, because its per-run network
    must exist and the sidecar must be connected to it first; if the sidecar
    never comes up, the pod (and its network) is torn down and the launch fails
    rather than leaving half of it running.
    """

    name = "pod"
    pod = True
    # How long to wait for the sidecar container to be running before the agent
    # can join its namespace. Generous: this is image start-up, not model work.
    # Kept well under the control plane's worker-stale window, because launches are
    # serialised inside one heartbeat. Combined with the exited-handle check in
    # _wait_until_running, the realistic worst case is milliseconds per doomed
    # launch rather than the full timeout.
    READY_TIMEOUT = float(os.environ.get("ANDYUR_POD_READY_TIMEOUT", "15"))

    def __init__(self) -> None:
        self._agent_procs: dict[str, subprocess.Popen] = {}

    def _wait_until_running(self, name: str, deadline: float, proc=None) -> bool:
        """Wait for the sidecar container to be running.

        WATCH THE PROCESS, NOT JUST THE CLOCK. The common failures here -- a
        missing image, a bad flag, a dockerd error -- make `docker run` exit
        within milliseconds, and polling only for "running" then burned the whole
        timeout per launch. Launches are serialised inside one heartbeat, so a
        worker handed several doomed assignments spent minutes inside a single
        beat and the control plane declared it dead while it was merely waiting.
        A handle that has already exited is a decision, so take it immediately.
        """
        import time
        while time.monotonic() < deadline:
            if proc is not None and proc.poll() is not None:
                return False
            try:
                res = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Running}}", name],
                    capture_output=True, text=True, check=False, timeout=10,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
            if res.stdout.strip() == "true":
                return True
            time.sleep(0.1)
        return False

    def launch(self, spec: RunSpec, logfile) -> subprocess.Popen:
        import time
        net = run_network(spec.run_id)
        # A conversation run has NO agent container (the turn loop runs in the
        # sidecar), so it needs no per-run network -- creating one would waste an
        # address-pool slot for nothing. Only headless runs get the network.
        needs_net = spec.run_type != "conversation"
        if needs_net:
            # O1: the per-run internal network the agent will be single-homed on.
            # Created BEFORE the agent so it exists to join; `--internal` (no
            # default route/masquerade, so the agent gets no internet or
            # off-subnet egress). Removed first, defensively, in case a prior run
            # of the same id left one behind. The sidecar stays on SANDBOX_NETWORK
            # for its own egress and is connected here after it is up.
            _net_rm(net)
            if not _net_create(net):
                raise RuntimeError(
                    f"could not create the per-run isolation network {net} for run "
                    f"{spec.run_id}; refusing to launch without run-scoped isolation")
        try:
            sidecar = super().launch(spec, logfile)
        except Exception:
            _net_rm(net)
            raise
        deadline = time.monotonic() + self.READY_TIMEOUT
        if not self._wait_until_running(run_container(spec.run_id), deadline, sidecar):
            # The sidecar never came up. Tear down whatever half started, and let
            # the caller record a failed launch: a pod with no agent would
            # otherwise sit until the run TTL producing nothing.
            self.kill([spec.run_id])
            self.cleanup(spec.run_id)
            raise RuntimeError(
                f"the sidecar container for run {spec.run_id} did not start "
                f"within {self.READY_TIMEOUT}s; the pod was not formed"
            )
        if spec.run_type == "conversation":
            # The sidecar runs this one itself. No second half, no per-run network.
            log(f"run {spec.run_id} is a conversation: no agent container "
                "(the turn loop runs in the sidecar)")
            return sidecar
        # Connect the running sidecar to the per-run network under the stable
        # alias the agent addresses it by. Done now (not at `docker run`) because
        # the sidecar's primary network is SANDBOX_NETWORK, which it needs from
        # the first instant to reach the control plane; the per-run network only
        # has to exist before the AGENT starts, which is below.
        if not _net_connect(net, run_container(spec.run_id), SIDECAR_ALIAS):
            self.kill([spec.run_id])
            self.cleanup(spec.run_id)
            raise RuntimeError(
                f"could not connect the sidecar for run {spec.run_id} to its "
                f"per-run network {net}; the pod was not formed")
        # The agent's own log file, kept separate: interleaving two containers'
        # output into one file makes both unreadable exactly when a run is being
        # debugged. Named `<run>-agent.log`, NOT `<run>.log.agent`, so it still
        # matches the `*.log` glob every harness and operator uses -- a log that
        # sorts outside the pattern is a log nobody reads, and the agent's half is
        # where the interesting output lives.
        agent_log = subprocess.DEVNULL
        name = getattr(logfile, "name", "")
        if name.endswith(".log"):
            agent_log = open(f"{name[:-len('.log')]}-agent.log", "a")
        try:
            self._agent_procs[spec.run_id] = subprocess.Popen(
                _agent_argv(spec.agent, spec.run_id, spec.channel_token),
                stdout=agent_log, stderr=subprocess.STDOUT, start_new_session=True,
            )
        except Exception:
            self.kill([spec.run_id])
            self.cleanup(spec.run_id)
            raise
        return sidecar

    def _names_to_kill(self, run_ids: list[str]) -> list[str]:
        """Both halves of every pod, in one docker invocation. `docker kill`
        processes each name independently, so a name that is already gone costs
        an ignored error and never spares the others."""
        names = []
        for r in run_ids:
            names.append(run_container(r))
            names.append(agent_container(r))
        return names

    def cleanup(self, run_id: str) -> None:
        # The sidecar exited, so the run is over -- but the agent container has
        # its own lifetime and would otherwise keep running against a namespace
        # whose owner is gone. Destroy it explicitly rather than trusting it to
        # notice.
        proc = self._agent_procs.pop(run_id, None)
        subprocess.run(
            ["docker", "kill", "--signal=KILL", agent_container(run_id)],
            capture_output=True, text=True, check=False, timeout=15,
        )
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError):
                pass
        super().cleanup(run_id)
        # O1: remove the per-run network once both containers are gone. A network
        # with live endpoints refuses removal, so this follows the kills above;
        # if it still lingers (a container mid-teardown), the next launch of the
        # same id recreates it (see launch's defensive `_net_rm`), and `sweep`
        # reaps orphans.
        _net_rm(run_network(run_id))

    def describe(self, run_id: str) -> str:
        return (f"in pod {run_container(run_id)} + {agent_container(run_id)} "
                f"(container {run_container(run_id)})")

    def sweep(self) -> None:
        """Destroy pod remnants whose sidecar is gone: orphan AGENT containers
        and orphan per-run NETWORKS.

        A pod's agent half and its per-run network are both invisible to
        list_running (neither is a run), so nothing else condemns them. In the
        normal case cleanup() takes both when the sidecar exits; this covers the
        case cleanup cannot -- a daemon that died and restarted holds no memory
        of the pod, adopts the sidecar, and would otherwise leave the agent
        container running forever AND leak the per-run /24 network, which
        accumulates against Docker's finite address pool until no pod can launch.
        """
        agents = self._list_names(AGENT_PREFIX)
        nets = _list_run_networks()
        if not agents and not nets:
            return                      # none, or could not ask: nothing to do
        live = self._list_names(RUN_PREFIX)
        if live is None:
            # COULD NOT ASK which sidecars are alive. Every agent container and
            # every per-run network would look like an orphan, so sweeping now
            # would destroy the agent half of every healthy pod and tear the
            # network out from under it -- from one transient docker timeout. An
            # orphan costs a container/network until the next beat; this mistake
            # costs every run in flight. Do nothing and try again.
            log("sweep skipped: could not determine which sidecars are alive")
            return
        live = set(live)
        orphans = [agent_container(r) for r in (agents or []) if r not in live]
        if orphans:
            log(f"sweeping {len(orphans)} orphaned agent container(s): "
                + ", ".join(orphans[:5]) + ("..." if len(orphans) > 5 else ""))
            subprocess.run(["docker", "kill", "--signal=KILL"] + orphans,
                           capture_output=True, text=True, check=False, timeout=30)
        # Reap orphan per-run networks: a run-network whose sidecar is no longer
        # live. Done after the agent kill above so an endpoint isn't holding it;
        # a network still in use refuses removal harmlessly and is retried next
        # sweep. This is what the create/cleanup comments promise.
        orphan_nets = [n for n in (nets or [])
                       if n.startswith(NET_PREFIX) and n[len(NET_PREFIX):] not in live]
        if orphan_nets:
            log(f"sweeping {len(orphan_nets)} orphaned run network(s): "
                + ", ".join(orphan_nets[:5]) + ("..." if len(orphan_nets) > 5 else ""))
            for n in orphan_nets:
                _net_rm(n)


@dataclass(frozen=True)
class _ExecRun:
    """What the daemon needs to close out a stock exec/v1 run: the Pod and
    container whose exit is the run's completion, and the two output bounds
    (the manifest's emission cap and, applied on top, the platform retention
    ceiling). Recorded at launch because the run group is deleted before the
    daemon would otherwise know the run was exec/v1."""

    pod: str
    container: str
    output_max_bytes: int
    capture_stdout: str
    capture_stderr: str


# Read a little past the retention window so capture_output's final byte-cut
# (after redaction, which can shift length) has material to land exactly on the
# bound. Small: the read is bounded at the API, not here.
_READ_MARGIN_BYTES = 8192


class KubernetesOrchestrator(Orchestrator):
    """Production two-Pod run groups controlled through the Kubernetes API.

    This adapter translates the daemon's deliberately small orchestration seam
    into the Kubernetes lifecycle controller. It retains exact generations for
    both locally launched and adopted runs; broad deletion by logical run id is
    forbidden because it could destroy another worker's replacement.
    """

    name = "kubernetes"

    def __init__(self, controller=None, owner_generation: str | None = None, *,
                 run_scoped_generations: bool = False) -> None:
        # RUN-SCOPED GENERATIONS are the engine's execution worker's mode
        # (Architecture B+, ADR-014 D11): each run carries its OWN generation,
        # recorded by the control plane, so this process owns no single one and
        # adopts a run only through that run's fence. Opt-in and explicit: the
        # worker daemon still refuses to start without its stable generation.
        self.run_scoped_generations = run_scoped_generations
        if controller is None:
            from .kubernetes_api import OfficialKubernetesApi
            from .kubernetes_controller import KubernetesRunController

            namespace = os.environ.get("ANDYUR_KUBERNETES_NAMESPACE", "").strip()
            if not namespace:
                raise config.InsecureProfile(
                    "ANDYUR_DEPLOYMENT=kubernetes requires "
                    "ANDYUR_KUBERNETES_NAMESPACE; refusing to select another "
                    "runtime"
                )
            if not owner_generation and not run_scoped_generations:
                raise config.InsecureProfile(
                    "ANDYUR_DEPLOYMENT=kubernetes requires a stable "
                    "ANDYUR_WORKER_ID so a restarted worker adopts only its own "
                    "run generations"
                )
            controller = KubernetesRunController(
                OfficialKubernetesApi(), namespace,
                None if run_scoped_generations else owner_generation)
        self.controller = controller
        if run_scoped_generations:
            controller.retain_fence_on_failed_launch = True
        self.namespace = controller.namespace
        self.proxy_image = os.environ.get("ANDYUR_KUBERNETES_PROXY_IMAGE", "")
        self.agent_image = os.environ.get("ANDYUR_KUBERNETES_AGENT_IMAGE", "")
        self.broker_envoy_image = os.environ.get(
            "ANDYUR_KUBERNETES_BROKER_ENVOY_IMAGE", "")
        self.broker_state_host = os.environ.get(
            "ANDYUR_KUBERNETES_BROKER_STATE_HOST", "")
        try:
            self.broker_state_port = int(os.environ.get(
                "ANDYUR_KUBERNETES_BROKER_STATE_PORT", "0"))
        except ValueError as exc:
            raise config.InsecureProfile(
                "ANDYUR_KUBERNETES_BROKER_STATE_PORT must be an integer") from exc
        self.litellm_key = os.environ.get("LITELLM_MASTER_KEY", "")
        self._generations: dict[str, str] = {}
        # run_id -> _ExecRun, only for stock exec/v1 runs whose completion the
        # daemon owns. Populated by GovernedKubernetesOrchestrator.launch_governed.
        self._exec_runs: dict[str, _ExecRun] = {}

    @staticmethod
    def _proxy_egress():
        """The explicit cluster peers trusted run proxies may reach."""
        import json
        from .kubernetes_manifests import ClusterPeer

        raw = os.environ.get("ANDYUR_KUBERNETES_PROXY_EGRESS", "[]")
        try:
            values = json.loads(raw)
            if not isinstance(values, list):
                raise TypeError("expected a JSON list")
            return tuple(ClusterPeer(
                namespace=item["namespace"], labels=item["labels"],
                port=int(item["port"]), protocol=item.get("protocol", "TCP"),
            ) for item in values)
        except (ValueError, TypeError, KeyError) as exc:
            raise config.InsecureProfile(
                "ANDYUR_KUBERNETES_PROXY_EGRESS must be a JSON list of "
                "{namespace, labels, port, optional protocol} peers"
            ) from exc

    @staticmethod
    def _agent_model_egress():
        import json
        from .kubernetes_manifests import ClusterPeer

        raw = os.environ.get("ANDYUR_KUBERNETES_AGENT_MODEL_EGRESS", "").strip()
        if not raw:
            return None
        try:
            item = json.loads(raw)
            return ClusterPeer(
                namespace=item["namespace"], labels=item["labels"],
                port=int(item["port"]), protocol=item.get("protocol", "TCP"),
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise config.InsecureProfile(
                "ANDYUR_KUBERNETES_AGENT_MODEL_EGRESS must be one JSON "
                "{namespace, labels, port, optional protocol} peer"
            ) from exc

    @staticmethod
    def _broker_state_peer():
        """The one NetworkPolicy destination added only to brokered runs."""
        import json
        from .kubernetes_manifests import ClusterPeer

        raw = os.environ.get("ANDYUR_KUBERNETES_BROKER_STATE_PEER", "").strip()
        if not raw:
            return None
        try:
            item = json.loads(raw)
            if not isinstance(item, dict):
                raise TypeError("expected a JSON object")
            return ClusterPeer(
                namespace=item["namespace"], labels=item["labels"],
                port=int(item["port"]), protocol=item.get("protocol", "TCP"),
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise config.InsecureProfile(
                "ANDYUR_KUBERNETES_BROKER_STATE_PEER must be one JSON "
                "{namespace, labels, port, optional protocol} peer"
            ) from exc

    def launch(self, spec: RunSpec, logfile):
        from .kubernetes_controller import RunCredentials
        from .kubernetes_manifests import RunGroupSpec

        required = {
            "assignment generation": spec.generation,
            "registry agent id": spec.registry_agent_id,
            "run token": spec.run_token,
            "channel token": spec.channel_token,
            "LiteLLM service key": self.litellm_key,
            "proxy image digest": self.proxy_image,
            "agent image digest": self.agent_image,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise config.InsecureProfile(
                "Kubernetes run launch requires " + ", ".join(missing)
                + "; refusing to fall back or launch a partially credentialed run"
            )
        proxy_egress = self._proxy_egress()
        broker_peer = self._broker_state_peer()
        if spec.broker_enabled:
            if broker_peer is None:
                raise config.InsecureProfile(
                    "broker-enabled Kubernetes run requires "
                    "ANDYUR_KUBERNETES_BROKER_STATE_PEER")
            proxy_egress = (*proxy_egress, broker_peer)
        run_group = RunGroupSpec(
            namespace=self.namespace,
            run_id=spec.run_id,
            generation=spec.generation,
            agent_id=spec.agent,
            registry_agent_id=spec.registry_agent_id,
            proxy_image=self.proxy_image,
            agent_image=self.agent_image,
            server_url=SERVER_URL,
            litellm_url=LITELLM_URL,
            llm_mode=os.environ.get("ANDYUR_LLM", "api"),
            ollama_url=os.environ.get("ANDYUR_OLLAMA_URL", ""),
            trust_domain=os.environ.get("ANDYUR_TRUST_DOMAIN", "andyur.local"),
            otel_mode=os.environ.get("ANDYUR_OTEL", "on"),
            otel_endpoint=os.environ.get("ANDYUR_OTEL_ENDPOINT", ""),
            as_token_endpoint=config.AS_TOKEN_ENDPOINT,
            as_issuer=config.AS_ISSUER,
            as_jwks_url=config.AS_JWKS_URL,
            as_client_id=config.AS_CLIENT_ID,
            as_provider=config.AS_PROVIDER,
            as_capability=config.AS_CAPABILITY,
            as_resource_scope=config.AS_RESOURCE_SCOPE,
            as_product_version=config.AS_PRODUCT_VERSION,
            as_certified=bool(config.AS_CERTIFICATION_FILE and
                              config.AS_CERTIFICATION_PUBLIC_KEY_FILE),
            broker_enabled=spec.broker_enabled,
            broker_envoy_image=(self.broker_envoy_image
                                if spec.broker_enabled else ""),
            broker_state_host=(self.broker_state_host
                               if spec.broker_enabled else ""),
            broker_state_port=(self.broker_state_port
                               if spec.broker_enabled else 0),
            broker_state_peer=(broker_peer if spec.broker_enabled else None),
            proxy_egress=proxy_egress,
            agent_model_egress=self._agent_model_egress(),
        )
        certification = ""
        certification_public_key = ""
        if run_group.as_certified:
            certification = _read_as_evidence(
                config.AS_CERTIFICATION_FILE, "AS certification")
            certification_public_key = _read_as_evidence(
                config.AS_CERTIFICATION_PUBLIC_KEY_FILE,
                "AS certification public key")
        handle = self.controller.launch(
            run_group,
            RunCredentials(spec.channel_token, spec.run_token, self.litellm_key,
                           config.AS_CLIENT_SECRET, certification,
                           certification_public_key, spec.broker_token or ""),
        )
        self._generations[spec.run_id] = spec.generation
        return handle

    def release_after_outcome(self, run_id: str, generation: str) -> None:
        self.controller.release_fence(run_id, generation)

    def adopt(self, run_id: str, generation: str):
        """Adopt one exact run generation through its fence (see the
        controller). Only in run-scoped mode: a daemon adopts its own
        generation through `list_running`, and nothing else."""
        if not self.run_scoped_generations:
            raise config.InsecureProfile(
                "adopting another process's run generation requires the "
                "run-scoped mode of the engine's execution worker")
        handle = self.controller.adopt(run_id, generation)
        self._generations[run_id] = generation
        return handle

    def kill(self, run_ids: list[str]) -> None:
        try:
            running = dict(self.controller.list_running_generations())
        except Exception as exc:                              # noqa: BLE001
            # Our OWN adoption set is ambiguous. Runs we launched are still
            # resolved from `_generations`; an engine run is resolved through
            # its own view below. Neither waits on the other's failure.
            log(f"kubernetes kill could not list this daemon's runs: "
                f"{type(exc).__name__}: {exc}")
            running = {}
        unresolved = []
        for run_id in run_ids:
            generation = self._generations.get(run_id) or running.get(run_id)
            if generation is not None:
                self.controller.delete_generation(run_id, generation)
            else:
                unresolved.append(run_id)
        if unresolved:
            # Not ours: an engine-launched run the server condemned. Destroyed
            # by its exact, fence-verified generation, never by run id alone.
            engine = dict(self.engine_runs())
            for run_id in unresolved:
                if run_id in engine:
                    self._engine_view().delete_generation(run_id, engine[run_id])

    def _engine_view(self):
        """All generations in the namespace, fence-verified -- the controller's
        own adoption view, without the owner filter. Read and kill only."""
        if getattr(self, "_engine_controller", None) is None:
            from .kubernetes_controller import KubernetesRunController
            self._engine_controller = KubernetesRunController(
                self.controller.api, self.namespace, None)
        return self._engine_controller

    def engine_runs(self) -> list[tuple[str, str]]:
        """The RECONCILER'S reach over engine-launched runs (Gate C): a halted
        run must die even when the execution worker that launched it is dead,
        so the worker daemon -- which watches the runtime, not the engine --
        reports them for condemnation and destroys the exact generation the
        server condemns. The execution worker itself never reconciles."""
        if self.run_scoped_generations:
            return []
        # POD BY POD (see `list_engine_generations`): one ambiguous Pod
        # anywhere in the namespace must not hide every engine run from the
        # kill switch.
        return self._engine_view().list_engine_generations(ENGINE_GENERATION_PREFIX)

    def list_running(self) -> list[str]:
        adopted = self.controller.list_running_generations()
        for run_id, generation in adopted:
            self._generations.setdefault(run_id, generation)
        return sorted(run_id for run_id, _ in adopted)

    def sweep(self) -> None:
        """Destroy agent Pods that outlived the proxy they were single-homed on.

        THE GAP THIS CLOSES. A run here is two Pods, and `list_running` selects
        the PROXY -- so an agent Pod whose proxy is gone is invisible to
        adoption. Nothing reports the run as executing, so `runs_to_kill` never
        condemns it, and the group deletion that would remove it correctly is
        never reached. Nothing else bounds it: the agent Pod has
        `restartPolicy: Never`, no `activeDeadlineSeconds` and no ownerReference
        to the proxy, so Kubernetes will not collect it either.

        The base class has said all along that this is "the seam a Kubernetes
        implementation needs anyway, since that one is a reconcile controller by
        nature"; the Docker pod shape, same two-part structure, has implemented
        it since it existed. This one inherited the no-op.

        IT CANNOT RACE A LAUNCH. `KubernetesRunController.launch` creates the
        agent only after the proxy is ready -- "the agent is never created
        unless its only allowed destination is ready" -- so an agent with no
        live proxy means the proxy died, never that the run is half-built.

        Best effort by contract, like every sweep: a failure must not cost the
        heartbeat, so one generation that will not delete does not stop the
        next from being tried.

        NOT GUARANTEED ON EVERY BEAT, and the first version of this docstring
        said it was. The heartbeat calls `adopted_runs()` first, unguarded, and
        that path raises on an ambiguous proxy phase, a rewritten identity, a
        missing singleton fence or an exceeded cardinality bound -- so in
        exactly those degraded states the beat aborts before reaching here.
        Reconciliation is therefore best effort in two senses, and an operator
        seeing orphans persist should look at adoption first.
        """
        try:
            orphans = [(self.controller, r, g)
                       for r, g in self.controller.list_orphaned_agent_generations()]
        except Exception as exc:
            log(f"kubernetes sweep could not list orphaned agents: "
                f"{type(exc).__name__}: {exc}")
            orphans = []
        if not self.run_scoped_generations:
            # The engine's runs too (Gate C): an agent that outlived its proxy
            # is swept whether or not its launcher is alive. LISTED SEPARATELY:
            # a failure reaching the engine view must not cost this daemon's
            # own sweep, nor the reverse.
            try:
                engine = self._engine_view()
                orphans += [(engine, r, g) for r, g in
                            engine.list_orphaned_agent_generations()
                            if g.startswith(ENGINE_GENERATION_PREFIX)]
            except Exception as exc:
                log(f"kubernetes sweep could not list the engine's orphaned "
                    f"agents: {type(exc).__name__}: {exc}")
        for controller, run_id, generation in orphans:
            # NAMED BEFORE IT IS DESTROYED. An agent Pod outliving its proxy is
            # untrusted code that the platform had lost track of; an operator
            # reading this line is the only record that it existed at all,
            # because there is no live run row to attribute it to.
            log(f"kubernetes sweep: agent for run {run_id} outlived its proxy; "
                f"destroying generation {generation}")
            try:
                controller.delete_generation(run_id, generation)
            except Exception as exc:
                log(f"kubernetes sweep could not destroy run {run_id}: "
                    f"{type(exc).__name__}: {exc}")

    def read_exec_completion(self, run_id: str):
        info = self._exec_runs.get(run_id)
        if info is None:
            return None                       # runtime-v1 / builtin: self-reports
        api = self.controller.api
        exit_code = api.read_container_exit(
            self.namespace, info.pod, info.container)
        # On Kubernetes the container log is ONE combined stream: stdout and
        # stderr are not separable at the API. It is captured under the stdout
        # bound. A manifest that DISCARDS stdout discards the captured log, and
        # stderr='capture' alone is NOT silently promoted to capturing the whole
        # combined stream -- an operator who asked to drop stdout does not get it
        # back relabelled as stderr.
        stdout = None
        if info.capture_stdout == "capture":
            # Bound the READ at the API to the effective retention window (+ a
            # margin so the final cut has material), so redaction and storage
            # never touch more than ~the bound. A hostile print of a megabyte
            # cannot make this unbounded.
            bound = min(info.output_max_bytes, config.OUTPUT_RETENTION_MAX_BYTES)
            try:
                # tail_lines=None: send ONLY limitBytes, so this is the HEAD of
                # the log up to the bound. Omitting it (the client default is 80)
                # would read only the last 80 LINES and then bytes from the start
                # of those -- a window the code claimed but did not request.
                stdout = api.pod_logs(self.namespace, info.pod,
                                      tail_lines=None,
                                      limit_bytes=bound + _READ_MARGIN_BYTES)
            except Exception as exc:
                # Unreadable logs are not fatal to the RUN, but they must not be
                # SILENT: a missing pods/log RBAC grant (403) once stored "" for
                # every summary with nothing to show why. Name the failure.
                log(f"run {run_id}: reading exec/v1 output failed "
                    f"({type(exc).__name__}: {exc}); summary will be empty")
                stdout = ""
        return exit_code, stdout, None, info.output_max_bytes

    def cleanup(self, run_id: str) -> None:
        self._exec_runs.pop(run_id, None)
        generation = self._generations.pop(run_id, None)
        if generation is not None:
            self.controller.delete_generation(run_id, generation)

    def describe(self, run_id: str) -> str:
        return f"in Kubernetes run group {run_id}"


def select(owner_generation: str | None = None) -> Orchestrator:
    """The orchestrator this worker's configuration asks for.

    One place answers "where do runs execute here", so the daemon never branches
    on the sandbox flag and a new runtime is a new class rather than another
    if-statement threaded through launch, kill, and reap.
    """
    if config.DEPLOYMENT == "kubernetes":
        return KubernetesOrchestrator(owner_generation=owner_generation)
    if config.DEPLOYMENT == "native":
        return HostOrchestrator()
    if config.AGENT_SPLIT_POD and not config.SANDBOX:
        # REFUSE rather than silently degrade. A pod is two containers; with
        # sandboxing off there are none, so this used to fall through to the host
        # shape and take the worst of both: the runner still saw
        # ANDYUR_AGENT_SPLIT=pod, so it bound the channel on the HOST's loopback
        # at a fixed, well-known port with no token (the daemon mints one only
        # for a pod launch) -- serving the run's whole prompt to any local
        # process -- and then waited out the full connect timeout for an agent
        # container nobody would ever start. Every run: a hang, then a failure,
        # with a prompt-disclosing port open the whole time.
        raise config.InsecureProfile(
            "ANDYUR_AGENT_SPLIT=pod needs ANDYUR_SANDBOX=on: a pod IS two "
            "containers. Without the sandbox there is nothing to put the agent "
            "in, and the sidecar would serve the run's prompt on a host port "
            "while waiting for a container that never starts. Use "
            "ANDYUR_AGENT_SPLIT=process for the two-process shape on a host."
        )
    # The Docker deployment always uses containers. ANDYUR_SANDBOX remains a
    # hardening/transition check; it no longer selects the execution runtime.
    if config.AGENT_SPLIT_POD:
        return PodOrchestrator()
    return ContainerOrchestrator()

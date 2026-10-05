"""DISPOSABLE live gate for the BYOA runtime contract (ADR-008 C1).

Runs the containerized reference agent -- a real OCI container, digest-pinned
base, zero Andyur imports, zero dependencies -- against the REAL platform
components on this machine (AgentChannel, ModelProxy, real MCP transport),
and records dated evidence. The container is launched with the same
subtraction the daemon applies to agent containers: cap-drop ALL,
no-new-privileges, read-only rootfs, unprivileged uid, no mounts, an
environment holding exactly the two contract variables.

Checks (each with its positive control; a refusal from a harness that cannot
also succeed proves nothing):

  G1  containerized round trip: context -> model (via the credential-
      injecting proxy) -> granted MCP tool -> events -> result -> done
  G2  launch configuration: env is exactly the contract pair, no mounts,
      read-only rootfs, every capability dropped, unprivileged user
  G3  protocol-version refusal: the workload fetches a v99 context, then
      exits non-zero (the spec fixes the refusal, not a numeric code) and
      stays silent on the wire
  G4  stream budgets at the enforcement point: an over-budget STREAM is
      refused (413 + failed run) while an in-budget stream is accepted. The
      whole-stream budget is tested rather than the per-line cap because the
      per-line cap is chunk-boundary-dependent (a complete oversized line in
      one receive bypasses it -- found by this gate's first run and handed to
      the channel's owning session); the stream budget enforces reliably.
  G5  the image cannot import andyur (and CAN import the stdlib)
  G6  a killed agent fails the run closed: the platform synthesizes a
      failure `done`, never a silent success

Secret absence is proven BY VALUE: a canary gateway key must reach the stub
gateway (the proxy injected it) and must never appear in the context, the
container's environment, or anything the agent emitted.

NETWORK NOTE: to let the container reach the harness across the Docker
boundary, the channel, model proxy, and MCP service bind 0.0.0.0 for the
gate's duration -- so on a host with a routable interface these ports are
briefly reachable from the LAN. The risk is negligible (the channel is
guarded by an unguessable per-run token; the deliberately-unauthenticated
model proxy fronts only the canary stub gateway, which holds no real
credential), but it is why this is a disposable gate and not a production
launcher.

Scope, honestly: per-tool authority filtering (tools/list vs tools/call) is
enforced by the data-plane gateway and evidenced by its own Slice 2b gate;
image signature/digest ADMISSION is the C2 governed-registry extension. This
gate proves the runtime CONTRACT, not those neighbors.

Run:  ./verify-byoa.sh   (from infra/byoa-spike)

Environment. These three are read; `andyur agents conformance` sets all of
them when the gate runs as the governed publication gate. Unset, the gate
builds and tests the local reference agent instead, which is the developer
path. Nothing else in the environment changes what the gate proves: the
channel budgets G4 exercises are assigned above, not inherited.

  ANDYUR_CONFORMANCE_IMAGE     pull and test THIS digest-pinned image instead
                               of building the local reference agent
  ANDYUR_CONFORMANCE_COMMAND   JSON array: the manifest command to run in that
                               image, replacing its entrypoint exactly as the
                               production Pod does. REQUIRED whenever
                               ANDYUR_CONFORMANCE_IMAGE is set, because
                               evidence for a command production will not run
                               proves nothing about the governed workload.
  ANDYUR_CONFORMANCE_EVIDENCE  write the evidence artifact here, refusing to
                               overwrite an existing one (governed evidence is
                               immutable). Unset, a dated file is written
                               beside this gate and may be replaced.

Publication binds evidence back to this gate: `gate_sha256`/`harness_sha256`
in the artifact are recomputed from the installed sources before a snapshot may
be signed, so evidence from an edited or older gate can never publish.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

# Shrink the channel budgets BEFORE the module that reads them is imported, so
# the budget check moves megabytes, not the production 64 MiB. ASSIGNED, not
# setdefault: a certification gate fixes its own conditions. Inherited budgets
# would let an ambient environment variable decide what G4 actually proved,
# and publication accepts the resulting evidence either way.
os.environ["ANDYUR_CHANNEL_MAX_LINE_BYTES"] = str(256 * 1024)
os.environ["ANDYUR_CHANNEL_MAX_STREAM_BYTES"] = str(1024 * 1024)

HERE = Path(__file__).resolve().parent
PLATFORM_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PLATFORM_ROOT))

import httpx  # noqa: E402

import runtime_v1  # noqa: E402
from andyur.runner.agentchannel import AgentChannel  # noqa: E402
from andyur.runner import agentchannel  # noqa: E402
from andyur.runner.modelproxy import ModelProxy  # noqa: E402

AGENT_DIR = PLATFORM_ROOT / "demos" / "byoa-hello-agent"
EXTERNAL_IMAGE = os.environ.get("ANDYUR_CONFORMANCE_IMAGE")
IMAGE_TAG = EXTERNAL_IMAGE or "byoa-hello-agent:gate"
ADVERTISE = "host.docker.internal"
CONTAINER = "byoa-gate-agent"


def _selected_command() -> tuple[str, ...] | None:
    """The manifest command this gate must exercise, JSON via the CLI.

    Production overrides the image entrypoint with the governed manifest
    command, so conformance of the bare image proves nothing about the workload
    that will actually launch. An external (governed) image therefore REQUIRES
    the command; the local dev build alone may run its own entrypoint.
    """
    raw = os.environ.get("ANDYUR_CONFORMANCE_COMMAND")
    if raw is None:
        if EXTERNAL_IMAGE:
            raise RuntimeError(
                "ANDYUR_CONFORMANCE_IMAGE requires ANDYUR_CONFORMANCE_COMMAND: "
                "conformance must run the manifest command, not the image default")
        return None
    try:
        command = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ANDYUR_CONFORMANCE_COMMAND is not JSON: {exc}") from exc
    if (not isinstance(command, list) or not command or
            not all(isinstance(part, str) and part for part in command)):
        raise RuntimeError(
            "ANDYUR_CONFORMANCE_COMMAND must be a JSON list of non-empty strings")
    return tuple(command)


# Resolved in main(), never at import: framework_gate.py imports this module to
# reuse the harness, and a governed-image env var must not kill that import.
COMMAND: tuple[str, ...] | None = None

CHECKS: list[dict] = []


def record(name: str, ok: bool, detail: str) -> None:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)


def sh(*argv: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True,
                          timeout=timeout)


def advertised(url: str) -> str:
    return url.replace("0.0.0.0", ADVERTISE)


def local(url: str) -> str:
    return url.replace("0.0.0.0", "127.0.0.1")


AGENT_RUN_FLAGS = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--read-only",
    "--user", "65534:65534",
    "--pids-limit", "64",
    "--memory", "256m",
    # The scratch space the contract promises (protocol spec section 8): a
    # read-only rootfs plus two writable, empty, ephemeral directories. The
    # production Pod grants these as emptyDir volumes; tmpfs is the closest
    # Docker equivalent, and without them this gate would be STRICTER than the
    # cluster and could redden an agent that runs fine in production.
    # `:exec` because a Kubernetes emptyDir is exec-capable and Docker's tmpfs
    # is noexec by default. Without it the gate is stricter than the Pod in a
    # way that is invisible until an agent tries to run something it unpacked
    # into its own scratch space: measured, `cp /bin/echo /tmp/e && /tmp/e` is
    # "Permission denied" without the option and succeeds with it.
    "--tmpfs", "/tmp:exec",
    "--tmpfs", "/home/agent:exec",
    # host.docker.internal auto-resolves on Docker Desktop (macOS dev box) but
    # NOT on plain Linux Docker (CI); without this the container cannot reach
    # the harness there and every round trip fails. Harmless on Mac, required
    # on Linux -- so the gate is portable, not Docker-Desktop-only.
    "--add-host", "host.docker.internal:host-gateway",
]


class Harness:
    """The full real-component stack bound on 0.0.0.0 (token-guarded) so a
    container can reach it through the Docker boundary."""

    def __init__(self, *, protocol_version=runtime_v1.PROTOCOL_V1,
                 model_delay_s: float = 0.0):
        self.token = "gate-" + hashlib.sha256(os.urandom(16)).hexdigest()[:24]
        self.canary = runtime_v1.make_canary()
        self.protocol_version = protocol_version
        self.model_delay_s = model_delay_s
        self.events: list[dict] = []
        self._consume: asyncio.Task | None = None

    async def __aenter__(self):
        self.gateway = runtime_v1.StubModelGateway(host="127.0.0.1",
                                                   delay_s=self.model_delay_s)
        gateway_url = await self.gateway.start()
        self.proxy = ModelProxy(gateway_url, self.canary, host="0.0.0.0")
        proxy_url = await asyncio.to_thread(self.proxy.start)
        self.mcp = runtime_v1.StubMcpService(host="0.0.0.0")
        mcp_url = await self.mcp.start()
        self.context = runtime_v1.build_context(
            run_id="run_byoa_gate", agent_id="agt_hello",
            prompt="Gate run: call the model, then echo through the tool.",
            model_base_url=advertised(proxy_url), mcp_url=advertised(mcp_url),
            protocol_version=self.protocol_version)
        self.channel = AgentChannel(self.context, token=self.token,
                                    host="0.0.0.0")
        channel_url = await self.channel.start()
        self.shim = runtime_v1.RuntimeV1Shim(local(channel_url), host="0.0.0.0")
        self.shim_url = await self.shim.start()

        async def consume():
            async for ev in self.channel.messages():
                self.events.append(ev)

        self._consume = asyncio.create_task(consume())
        return self

    async def finish_stream(self, timeout: float = 10) -> None:
        try:
            await asyncio.wait_for(asyncio.shield(self._consume), timeout)
        except asyncio.TimeoutError:
            await self.channel.inject_done(-1, "gate: no stream completed")
            await self._consume

    async def __aexit__(self, *exc):
        if self._consume and not self._consume.done():
            await self.channel.inject_done(-1, "gate teardown")
            try:
                await asyncio.wait_for(self._consume, 5)
            except asyncio.TimeoutError:
                self._consume.cancel()
        await self.shim.stop()
        await self.channel.stop()
        await self.mcp.stop()
        await asyncio.to_thread(self.proxy.stop)
        await self.gateway.stop()


def run_agent_container(shim_url: str, token: str,
                        timeout: float = 120, image: str = IMAGE_TAG,
                        name: str = CONTAINER,
                        command: tuple[str, ...] | None = None
                        ) -> subprocess.CompletedProcess:
    """Launch one agent container, optionally under a governed command.

    The command travels with the image it belongs to rather than being read
    from module state, so other callers (framework_gate's demo images) cannot
    inherit the governed agent's entrypoint override.
    """
    # Mirror the production Pod exactly: the manifest command REPLACES the
    # image entrypoint (Kubernetes `command:`), it is not appended to it.
    entrypoint_flags = [] if command is None else ["--entrypoint", command[0]]
    container_args = [] if command is None else list(command[1:])
    return sh("docker", "run", "--rm", "--name", name,
              *AGENT_RUN_FLAGS, *entrypoint_flags,
              "-e", f"ANDYUR_RUNTIME_URL={advertised(shim_url)}",
              "-e", f"ANDYUR_RUNTIME_TOKEN={token}",
              image, *container_args, timeout=timeout)


def run_governed_agent(shim_url: str, token: str, timeout: float = 120
                       ) -> subprocess.CompletedProcess:
    """The workload under test: this gate's image under this gate's command."""
    return run_agent_container(shim_url, token, timeout, command=COMMAND)


async def g1_round_trip() -> None:
    async with Harness() as h:
        proc = await asyncio.to_thread(run_governed_agent, h.shim_url, h.token)
        await h.finish_stream()
        done = h.channel.done
        texts = [t for ev in h.events for t in ev["texts"]]
        tools = [t["name"] for ev in h.events for t in ev["tools"]]
        results = [r for ev in h.events for r in ev["results"]]
        finals = [ev["result"] for ev in h.events if ev["result"]]
        ok = (proc.returncode == 0 and done == {"kind": "done", "exit": 0,
                                                "error": None}
              and any("stub reply" in t for t in texts)
              and tools == ["echo"] and results
              and "echo:" in results[0]["content"]
              and len(finals) == 1 and finals[0]["is_error"] is False)
        record("G1 containerized round trip", ok,
               f"exit={proc.returncode} done={done} tools={tools} "
               f"finals={len(finals)} stderr={proc.stderr[-200:]!r}")
        injected = h.gateway.seen_authorization == [f"Bearer {h.canary}"]
        record("G1 canary injected upstream by the proxy", injected,
               f"gateway saw {len(h.gateway.seen_authorization)} call(s)")
        # The granted tool call, proven HARNESS-SIDE (the MCP transport
        # recorded it) rather than from the agent's self-reported events --
        # so a forged tools/results event alone cannot pass this.
        tool_calls = [name for name, _ in h.mcp.seen_calls]
        record("G1 granted MCP tool invoked (observed on the transport)",
               tool_calls == ["echo"],
               f"mcp transport saw calls: {h.mcp.seen_calls}")
        # The agent must SEND the effective model from context, not a name it
        # invented -- so the model the gateway saw is the context's model.
        # (Enforcement of the effective model is server-side, out of scope
        # here; this proves the agent read and used it.)
        ctx_model = h.context["model"]
        used_ctx_model = (bool(h.gateway.seen_models)
                          and all(m == ctx_model for m in h.gateway.seen_models))
        record("G1 agent sent the context's effective model", used_ctx_model,
               f"context model={ctx_model!r}, gateway saw {h.gateway.seen_models}")
        leaked = (h.canary in json.dumps(h.context)
                  or h.canary in json.dumps(h.events)
                  or h.canary in proc.stdout + proc.stderr)
        record("G1 canary invisible to the agent", not leaked,
               "canary absent from context, events, and agent output")


def g2_launch_configuration() -> None:
    # Created with the governed command too: an image built FOR governed launch
    # has no reason to declare an ENTRYPOINT or CMD, and `docker create` on one
    # without either fails "no command specified" -- turning this check red for
    # exactly the images the publication path exists to certify.
    entrypoint_flags = [] if COMMAND is None else ["--entrypoint", COMMAND[0]]
    container_args = [] if COMMAND is None else list(COMMAND[1:])
    create = sh("docker", "create", "--name", CONTAINER + "-inspect",
                *AGENT_RUN_FLAGS, *entrypoint_flags,
                "-e", "ANDYUR_RUNTIME_URL=http://example.invalid",
                "-e", "ANDYUR_RUNTIME_TOKEN=inspect-only",
                IMAGE_TAG, *container_args)
    try:
        if create.returncode != 0:
            record("G2 launch configuration", False, create.stderr[-200:])
            return
        inspect = sh("docker", "inspect", CONTAINER + "-inspect")
        info = json.loads(inspect.stdout)[0]
        env = info["Config"]["Env"]
        andyur_env = [e for e in env if e.startswith("ANDYUR_")]
        extra = [e for e in env if not e.startswith(
            ("ANDYUR_RUNTIME_URL=", "ANDYUR_RUNTIME_TOKEN=", "PATH=",
             "PYTHON", "GPG_KEY=", "LANG="))]
        host = info["HostConfig"]
        # Tmpfs maps mountpoint -> options; compare the paths, and assert the
        # options separately so a silent drop of `exec` cannot pass.
        tmpfs = host.get("Tmpfs") or {}
        scratch = set(tmpfs)
        scratch_exec = all("exec" in value.split(",")
                           for value in tmpfs.values())
        ok = (sorted(e.split("=")[0] for e in andyur_env) ==
              ["ANDYUR_RUNTIME_TOKEN", "ANDYUR_RUNTIME_URL"]
              and not extra
              # No host filesystem reaches the workload...
              and info["Mounts"] == []
              # ...and the only writable paths are the two ephemeral scratch
              # directories the published contract promises it.
              and scratch == {"/tmp", "/home/agent"} and scratch_exec
              and host["ReadonlyRootfs"] is True
              and host["CapDrop"] == ["ALL"]
              and info["Config"]["User"] == "65534:65534")
        record("G2 launch configuration is the subtraction", ok,
               f"env={sorted(e.split('=')[0] for e in env)} "
               f"mounts={info['Mounts']} scratch={sorted(scratch)} "
               f"scratch_exec={scratch_exec} "
               f"readonly={host['ReadonlyRootfs']} "
               f"capdrop={host['CapDrop']} user={info['Config']['User']}")
    finally:
        sh("docker", "rm", "-f", CONTAINER + "-inspect")


async def g3_protocol_refusal() -> None:
    async with Harness(protocol_version="andyur-agent-runtime/v99") as h:
        proc = await asyncio.to_thread(run_governed_agent, h.shim_url,
                                       h.token, 60)
        await h.finish_stream(timeout=2)
        # The spec fixes the REFUSAL, not a numeric code, so a specific exit
        # value would test this demo agent's private choice instead of the
        # protocol. But "exited non-zero and stayed silent" is also true of a
        # container that never ran -- so require that it fetched its context
        # first: it started, read the unsupported version, and then refused.
        ok = (h.shim.context_fetches >= 1 and proc.returncode != 0
              and h.events == [] and not h.gateway.seen_authorization)
        record("G3 unsupported protocol refused silently", ok,
               f"context_fetches={h.shim.context_fetches} exit={proc.returncode} "
               f"events={len(h.events)} "
               f"model_calls={len(h.gateway.seen_authorization)}")


async def g4_stream_budgets() -> None:
    async with Harness() as h:
        headers = {"Authorization": f"Bearer {h.token}"}
        url = local(h.shim_url) + "/v1/events"
        # positive control FIRST: an in-budget stream is accepted end to end
        good = (json.dumps({"kind": "msg", "record": {}, "texts": ["ok"],
                            "tools": [], "results": [], "result": None})
                + "\n" + json.dumps({"kind": "done", "exit": 0,
                                     "error": None}) + "\n").encode()
        async with httpx.AsyncClient(timeout=30) as client:
            r_good = await client.post(url, headers=headers, content=good)
        await h.finish_stream()
        done = h.channel.done or {}
        accepted = r_good.status_code == 200 and done.get("exit") == 0
        record("G4 in-budget stream accepted (positive control)", accepted,
               f"status={r_good.status_code} done={h.channel.done}")

    async with Harness() as h:
        headers = {"Authorization": f"Bearer {h.token}"}
        url = local(h.shim_url) + "/v1/events"
        # Exceed the WHOLE-STREAM budget, which is the bound that actually
        # protects the credential-holding half's memory. (The per-line cap is
        # chunk-boundary-dependent -- a complete oversized line inside one
        # receive bypasses it; found by this gate's first run and handed to
        # the channel's owning session with a repro. The stream budget backs
        # it either way.)
        line = (json.dumps({"kind": "msg", "record": {}, "texts": ["x" * 900],
                            "tools": [], "results": [], "result": None})
                + "\n").encode()

        async def flood():
            sent = 0
            while sent <= agentchannel._MAX_STREAM + len(line):
                yield line
                sent += len(line)

        status: object = None
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r_bad = await client.post(url, headers=headers,
                                          content=flood())
                status = r_bad.status_code
        except httpx.HTTPError as exc:
            # The refusal can also surface as an aborted upload when the
            # server cuts the connection mid-flood; the authoritative signal
            # is the failed done naming the budget, asserted below.
            status = f"aborted:{type(exc).__name__}"
        await h.finish_stream()
        done = h.channel.done
        refused = (done is not None and done["exit"] == -1
                   and "budget" in (done["error"] or "")
                   and (status == 413 or isinstance(status, str)))
        record("G4 over-budget stream refused, run failed closed", refused,
               f"status={status} done={done}")


# Debian, Ubuntu and Alpine ship `python3` with NO `python` alias; only the
# official python:* images provide both. Probing one name and treating its
# absence as "no Python here" would wave through every distro-based image.
PYTHON_CANDIDATES = ("python", "python3")
_PYTHON_NAME_RE = re.compile(r"python[0-9]*(\.[0-9]+)*")


def command_interpreters(command: tuple[str, ...] | None) -> list[str]:
    """Python interpreters named anywhere in the governed command.

    COMMAND[0] alone is not enough: a command may wrap the real interpreter in
    a shell, as in ["/bin/sh", "-c", "exec /venv/bin/python /app/agent.py"],
    where the interpreter that actually runs the agent is a word inside the
    third argument. Every whitespace-separated word is considered, and only
    those whose basename looks like a Python are probed -- probing the script
    path or a data file would produce "not executable" and fail the gate for
    no reason.

    Remaining limit, stated because it is not obvious: an interpreter reached
    under a name that does not look like Python (a renamed binary, or one
    invoked by a wrapper script inside the image) is still not probed.
    """
    found: list[str] = []
    seen: set[str] = set()
    for token in command or ():
        # BOTH tokenizers, unioned, because the party that writes this command
        # is the party this check polices, and each tokenizer is blind to
        # exactly what the other sees. str.split cannot see through quotes:
        # `exec '/venv/bin/python' agent.py` yields a word whose basename is
        # `python'`, matching nothing. shlex consumes backslashes: a real
        # interpreter at /opt/we\ird/python3 resolves to /opt/weird/python3,
        # a path that does not exist, which probes as "absent". Swapping one
        # for the other just trades a quoting bypass for an escaping one.
        plain = token.split()
        try:
            lexed = shlex.split(token)
        except ValueError:
            # Unbalanced quoting is not a parseable word list. Degrade to the
            # naive split rather than raising: a command that cannot be parsed
            # must still be probed as best it can be, never skipped.
            lexed = []
        # Ordered, first-seen dedupe rather than a set: probe order ends up in
        # the evidence artifact's recorded detail, and set iteration order
        # varies BETWEEN PROCESSES, so two identical runs of the same gate on
        # the same image would produce different artifacts.
        for word in (*plain, *lexed):
            if word in seen:
                continue
            seen.add(word)
            # `python`, `python3`, `python3.12` -- and NOT `python.json`, which
            # a prefix match happily probes as an interpreter and then reports
            # as inconclusive, failing the gate over a data file.
            if _PYTHON_NAME_RE.fullmatch(word.rsplit("/", 1)[-1]):
                found.append(word)
    return found


def interpreter_state(interpreter: str) -> tuple[str, str]:
    """Is this name a usable Python inside the image? -> (state, detail).

    Three outcomes, not two, and the third is why this is not a boolean:
      python       the stdlib imported, so it is a Python and can be asked
      absent       there is definitively no such executable in the image
      inconclusive the probe did not run: not executable, a daemon error, a
                   crash. An unanswered question must never certify an image,
                   so this fails the check rather than excusing it.
    """
    probe = sh("docker", "run", "--rm", "--entrypoint", interpreter, IMAGE_TAG,
               "-c", "import json, http.client")
    if probe.returncode == 0:
        return "python", f"{interpreter}: python"
    if probe.returncode == 127 or "executable file not found" in probe.stderr:
        return "absent", f"{interpreter}: not in image"
    if "is a directory" in probe.stderr:
        # A path whose basename is a valid Python name can be a DIRECTORY
        # (/usr/lib/python3.11). Docker reports exit 126 "is a directory",
        # which is a definitive answer that this is not an interpreter, not an
        # unanswered question -- leaving it inconclusive would fail the gate
        # for an image that did nothing wrong.
        return "absent", f"{interpreter}: a directory, not an interpreter"
    return "inconclusive", (f"{interpreter}: probe did not run "
                            f"(exit={probe.returncode}) {probe.stderr.strip()[-120:]}")


def g5_image_cannot_import_andyur() -> None:
    """No Python in the image can import `andyur`.

    The probe is a Python import because that is the only way this property is
    checkable, and the check is therefore Python-specific. The CONTRACT is
    language-neutral by design -- a Go or Rust agent satisfies it by having no
    interpreter at all -- so an image without Python must not be failed for
    lacking one, or every non-Python agent becomes unpublishable, the opposite
    of what this gate is for.

    Two things this has to get right, both found in review:
    "no Python" must MEAN no Python -- absence is concluded only from a probe
    that definitively found no such executable, never from a probe that failed
    for some other reason. And the interpreter that matters is the one the
    governed command will actually run, not whichever `python` happens to sit
    on PATH: an image can carry andyur in a venv the command names while PATH
    stays clean.
    """
    candidates = list(PYTHON_CANDIDATES)
    for interpreter in command_interpreters(COMMAND):
        if interpreter not in candidates:
            candidates.append(interpreter)
    states = [interpreter_state(name) for name in candidates]
    details = [detail for _, detail in states]
    pythons = [name for name, (state, _) in zip(candidates, states)
               if state == "python"]
    if not pythons:
        if any(state == "inconclusive" for state, _ in states):
            record("G5 image has no andyur package (inconclusive: FAILED)",
                   False, "; ".join(details) + " -- no probe answered, so the "
                   "image is not certified as andyur-free")
            return
        record("G5 image has no andyur package (no Python: not applicable)",
               True, "; ".join(details) + " -- a non-Python image cannot import it")
        return
    clean = True
    for name in pythons:
        bad = sh("docker", "run", "--rm", "--entrypoint", name, IMAGE_TAG,
                 "-c", "import andyur")
        importable = not (bad.returncode != 0
                          and "ModuleNotFoundError" in bad.stderr)
        clean = clean and not importable
        details.append(f"{name}: import andyur exit={bad.returncode} "
                       f"{'IMPORTABLE' if importable else 'clean'}")
    record("G5 image has no andyur package (stdlib positive control)", clean,
           "; ".join(details))


async def g6_killed_agent_fails_closed() -> None:
    async with Harness(model_delay_s=30.0) as h:
        run_task = asyncio.create_task(asyncio.to_thread(
            run_governed_agent, h.shim_url, h.token, 90))
        try:
            await asyncio.wait_for(h.channel.connected.wait(), timeout=60)
        except asyncio.TimeoutError:
            record("G6 killed agent fails the run closed", False,
                   "agent never opened its stream")
            await run_task
            return
        await asyncio.to_thread(sh, "docker", "kill", CONTAINER)
        await run_task
        await h.finish_stream()
        done = h.channel.done
        ok = (done is not None and done["exit"] == -1
              and "without completion" in (done["error"] or ""))
        record("G6 killed agent fails the run closed", ok, f"done={done}")


def build_image() -> str:
    if EXTERNAL_IMAGE:
        pull = sh("docker", "pull", IMAGE_TAG, timeout=600)
        if pull.returncode != 0:
            raise RuntimeError(f"docker pull failed: {pull.stderr[-500:]}")
        inspect = sh("docker", "image", "inspect", "--format", "{{.Id}}", IMAGE_TAG)
        if inspect.returncode != 0 or not inspect.stdout.strip():
            raise RuntimeError(f"docker inspect failed: {inspect.stderr[-500:]}")
        return inspect.stdout.strip()
    build = sh("docker", "build", "-q", str(AGENT_DIR), "-t", IMAGE_TAG,
               timeout=600)
    if build.returncode != 0:
        raise RuntimeError(f"docker build failed: {build.stderr[-500:]}")
    return build.stdout.strip()


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_evidence(image_id: str, started: float, ok: bool) -> Path:
    stamp = time.strftime("%Y-%m-%d", time.localtime(started))
    requested = os.environ.get("ANDYUR_CONFORMANCE_EVIDENCE")
    out = (Path(requested) if requested else
           HERE / f"result-byoa-{stamp}-{platform.system().lower()}-{platform.machine()}.json")
    evidence = {
        "gate": "byoa-runtime-v1", "adr": "adr-008", "phase": "C1",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                     time.gmtime(started)),
        "duration_s": round(time.time() - started, 1),
        "host": {"platform": platform.platform(),
                 "python": sys.version.split()[0],
                 "docker": sh("docker", "version", "--format",
                              "{{.Server.Version}}").stdout.strip()},
        "image": {"tag": IMAGE_TAG, "id": image_id},
        "inputs": {
            "selected_image": IMAGE_TAG if EXTERNAL_IMAGE else None,
            "selected_command": None if COMMAND is None else list(COMMAND),
            "agent_py_sha256": (None if EXTERNAL_IMAGE else
                                file_sha(AGENT_DIR / "agent.py")),
            "dockerfile_sha256": (None if EXTERNAL_IMAGE else
                                  file_sha(AGENT_DIR / "Dockerfile")),
            "gate_sha256": file_sha(Path(__file__)),
            "harness_sha256": file_sha(HERE / "runtime_v1.py"),
            "channel_budgets": {"max_line": agentchannel._MAX_LINE,
                                "max_stream": agentchannel._MAX_STREAM},
        },
        "checks": CHECKS,
        "ok": ok,
    }
    # The temp file is a PREDICTABLE sibling of an operator-supplied path, so
    # it is created exclusively and never through a symlink: otherwise
    # pre-planting `<evidence>.tmp` as a link both clobbers the target file and
    # leaves the attacker an open handle on the artifact publication re-reads.
    # An atomic link on `out` is worth nothing if `tmp` can be steered.
    # APPEND the suffix rather than replacing it: `--evidence run.tmp` made
    # with_suffix return the artifact's own path, so the gate wrote, linked and
    # then deleted the completed run's only evidence and called it a refusal.
    tmp = out.with_name(out.name + ".tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(evidence, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise RuntimeError(
            f"{tmp} already exists; remove it (the gate never reuses it)")
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    # link + unlink instead of rename: a CLI-requested artifact is governed
    # evidence, and link refuses an existing file atomically (no check-then-
    # write window). The default dated path stays replaceable so repeated dev
    # runs on one day keep working.
    if requested:
        try:
            os.link(tmp, out)
        except FileExistsError:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"refusing to overwrite conformance evidence {out}")
        except OSError as exc:
            # e.g. a filesystem without hard links. The run really happened;
            # keep its only copy and name where it is instead of deleting it.
            raise RuntimeError(
                f"could not place conformance evidence at {out}: {exc}; "
                f"this run's evidence is at {tmp}")
        tmp.unlink()
        fd = os.open(out.parent, os.O_RDONLY)  # persist the new directory entry
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        os.replace(tmp, out)
    return out


async def main() -> int:
    global COMMAND
    started = time.time()
    # Resolve configuration before touching docker: a misconfigured run should
    # fail without side effects, and it makes the refusal testable anywhere.
    try:
        COMMAND = _selected_command()
    except RuntimeError as exc:
        print(f"[gate] {exc}", file=sys.stderr)
        return 2
    sh("docker", "rm", "-f", CONTAINER)
    try:
        image_id = build_image()
    except RuntimeError as exc:
        print(f"[gate] {exc}", file=sys.stderr)
        return 2
    checks = [
        ("G1", g1_round_trip), ("G2", g2_launch_configuration),
        ("G3", g3_protocol_refusal), ("G4", g4_stream_budgets),
        ("G5", g5_image_cannot_import_andyur),
        ("G6", g6_killed_agent_fails_closed),
    ]
    try:
        for label, fn in checks:
            try:
                result = fn()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                # A crashing check must not swallow the whole gate's evidence:
                # record it as a FAIL and press on, so the dated artifact
                # always reflects every check that ran (and this one's error).
                record(f"{label} crashed", False,
                       f"{type(exc).__name__}: {exc}")
    finally:
        sh("docker", "rm", "-f", CONTAINER)
        sh("docker", "rm", "-f", CONTAINER + "-inspect")
    ok = all(c["ok"] for c in CHECKS)
    out = write_evidence(image_id, started, ok)
    print(f"[gate] {'GREEN' if ok else 'RED'}: "
          f"{sum(c['ok'] for c in CHECKS)}/{len(CHECKS)} checks passed; "
          f"evidence {out.name}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

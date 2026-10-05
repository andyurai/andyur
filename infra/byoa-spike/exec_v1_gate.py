#!/usr/bin/env python3
"""Live conformance gate for `exec/v1` stock workloads (ADR-011 D8).

The runtime-v1 gate (byoa_gate.py, G1-G6) proves an agent that SPEAKS the
protocol. An exec/v1 workload speaks nothing: it is an ordinary process the
platform speaks ABOUT, so every property is observed at boundaries the
platform owns. This gate launches the manifest's exact workload -- the
digest-pinned image under the manifest command, with the process and
configuration blocks resolved through the REAL parser and the REAL execconfig
resolver against a harness that stands in for the run's proxy Pod -- and
records, per D8:

  E1 starts and completes   process spawned, input delivered by the declared
                            mode, exits 0 within the lifecycle bound
  E2 model at the proxy     model requests reach the stub only THROUGH the
                            real front (allowed endpoints, granted model);
                            the front refuses listing / other model /
                            case-variant key (positive controls)
  E3 tools at the MCP       a probe under the workload's posture: no bearer
     boundary               401, the declared bearer initialize + the granted
                            tool, an undeclared tool refused; the workload's
                            own tool traffic, if any, carried the bearer
  E4 no credential in the   the run-token / channel-token canaries appear in
     workload               no env, argv, generated file, stdout or stderr;
                            the MCP bearer only where the manifest declared it
  E5 budgets enforced       captured output bounded by process.output.max_bytes
                            through the daemon's own capture; an over-budget
                            input refused at the door before any launch
  E6 killed fails closed    the same launch killed mid-run maps to a failed
                            run (exit_error), never to success
  E7 scratch writable as    create/read/delete in both scratch roots AS the
     the workload uid       workload's uid, before the workload runs (D6)
  E8 unsupported protocol   not applicable: replaced by digest-bound evidence
                            (D7) -- the image digest, the command, the
                            manifest and the generated configuration are all
                            recorded in the artifact

Evidence has the same contract as the runtime-v1 gate's, so
`andyur agents package --conformance-evidence` accepts it: `inputs` names the
selected image and command, and all three installed gate sources are hashed
into it.

Environment (set by `andyur agents conformance` for an exec/v1 manifest):
  ANDYUR_CONFORMANCE_IMAGE      digest-pinned image (required)
  ANDYUR_CONFORMANCE_COMMAND    JSON list, the manifest command (required)
  ANDYUR_CONFORMANCE_MANIFEST   path to the governed manifest (required):
                                the process + configuration blocks are taken
                                from HERE through the real parser, never
                                re-typed
  ANDYUR_CONFORMANCE_INPUT      path to a JSON file used as the run's input
                                (default: a small generic task object)
  ANDYUR_CONFORMANCE_EVIDENCE   write the artifact here, refusing to overwrite
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLATFORM_ROOT = HERE.parents[1]
sys.path.insert(0, str(PLATFORM_ROOT))

from andyur import execconfig, modelpolicy, runinput  # noqa: E402
from andyur.agentspec import load_manifest  # noqa: E402
from andyur.execlifecycle import TRUNCATION_MARKER, capture_output, exit_error  # noqa: E402
from andyur.identity import bearer_token  # noqa: E402
from andyur.runner.execfront import ExecFront  # noqa: E402

ADVERTISE = "host.docker.internal"
# The relay that gives the workload a BOUNDED route instead of no route.
#
# `--network none` cannot be the answer here: the workload must reach the model
# front and the MCP service, which this harness serves from the HOST. So the
# workload goes on an INTERNAL docker network whose only peer is this relay,
# forwarding exactly the two harness ports and nothing else. That mirrors the
# production shape, where the agent Pod's single egress rule names the proxy Pod
# on two ports (`daemon/kubernetes_manifests.py`), and it makes "the workload
# reached nothing else" a measured property (E8) rather than an assumption.
#
# Same digest the cluster's control plane pins for the same job, so the relay
# image has one source of truth in this repository.
# What the workload must NOT be able to reach. `host.docker.internal` now
# resolves to the relay by design, so probing that NAME would prove nothing; the
# probe needs the address the default bridge would have handed it.
HOST_GATEWAY_PROBE = os.environ.get("ANDYUR_GATE_HOST_PROBE", "192.168.65.254")
RELAY_IMAGE = ("alpine/socat@sha256:"
               "87d88ff79bf42ca723fb360e9585c40e2923a2f4df9b9d148b127568ef6b99e7")
# Set by `bound_network()` for the life of one gate run; read by `run_flags`, so
# every container the gate starts is under the workload's own posture.
_BOUND: dict | None = None
CONTAINER = "exec-v1-gate-workload"
WORKLOAD_UID = 1001                       # the production agent container's uid
GATE_TIMEOUT_CEILING = 900.0
CHECKS: list[dict] = []


def record(name: str, ok: bool, detail: str) -> None:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)


def sh(*argv: str, timeout: float = 120, stdin: bytes | None = None
       ) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, timeout=timeout,
                          input=stdin)


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# The harness: what the run's proxy Pod looks like from the workload's side.
# ---------------------------------------------------------------------------

class Harness:
    """What the workload sees of its proxy Pod, with the REAL front in the path.

    Three listeners: a recording model stub (answers the Ollama, OpenAI and
    Anthropic chat shapes with a canned reply and records every request it
    receives), the platform's own `runner.execfront.ExecFront` in front of it
    -- the exact code the serve-only sidecar runs, pinned to the granted model
    with `require_model` -- and a bearer-guarded MCP stub granting ONE tool.
    A first cut answered `/llm/*` itself and accepted model listing, a
    model-less chat and `/v1/messages` that the real front refuses (R MED-2);
    now a request the front refuses never reaches the stub, and the stub's
    record IS the post-policy model traffic.
    """

    def __init__(self, granted_model: str | None, run_id: str = "gate",
                 origin_trace: str | None = None):
        self.granted_model = granted_model
        self.bearer = "gate-mcp-" + secrets.token_urlsafe(24)
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        harness = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _read(self):
                n = int(self.headers.get("content-length") or 0)
                return self.rfile.read(n) if n else b""

            def _note(self, body: bytes):
                model = None
                try:
                    parsed = json.loads(body) if body else None
                    if isinstance(parsed, dict):
                        model = parsed.get("model")
                except ValueError:
                    parsed = None
                # The JSON-RPC method, so an empty refusal list can be read as
                # measured-and-none rather than never-measured (ADR-012 D10).
                rpc_method = parsed.get("method") if isinstance(parsed, dict) else None
                with harness._lock:
                    harness.requests.append({
                        "method": self.command, "path": self.path,
                        "authorization": self.headers.get("authorization"),
                        "model": model, "rpc_method": rpc_method, "bytes": len(body)})
                return parsed

            def _send(self, status, obj):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _stream_chat(self, model, reply):
                # A client that asks for `stream: true` reads SSE and nothing
                # else. Answering it with one JSON completion is not a
                # simplification: an OpenAI-shaped client parses that as an
                # empty stream with no finish_reason, retries, and exits
                # non-zero, so the gate failed E1 for a workload whose only
                # "fault" was streaming -- which the real front forwards, and
                # which is the DEFAULT for Hermes Agent. The stub is the part
                # of the path that is not the platform; it must not be the
                # part that decides which workloads can pass.
                def chunk(delta, finish=None):
                    return {"id": "gate", "object": "chat.completion.chunk", "model": model,
                            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
                events = [chunk({"role": "assistant", "content": reply}), chunk({}, "stop")]
                body = b"".join(b"data: " + json.dumps(e).encode() + b"\n\n" for e in events)
                body += b"data: [DONE]\n\n"
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._note(b"")
                self._route(None)

            def do_POST(self):
                self._route(self._note(self._read()))

            def _route(self, parsed):
                path = self.path.split("?", 1)[0]
                if path == "/mcp":
                    return self._mcp(parsed)
                # the MODEL STUB: reached only through the real front, which
                # has already applied the path policy and the model pin
                return self._model(path, parsed)

            def _model(self, path, parsed):
                m = harness.granted_model or "no-model-granted"
                reply = ("ROOT CAUSE: the payments_etl job exhausted its database "
                         "connection pool after a config reload. Restart the pool "
                         "and raise max_connections. CONFIDENCE: high.")
                if path == "/api/chat":
                    return self._send(200, {"model": m, "created_at": "2026-08-26T00:00:00Z",
                                            "message": {"role": "assistant", "content": reply},
                                            "done": True, "done_reason": "stop",
                                            "prompt_eval_count": 1, "eval_count": 1})
                if path == "/api/generate":
                    return self._send(200, {"model": m, "response": reply, "done": True})
                if path == "/v1/chat/completions" and isinstance(parsed, dict) and parsed.get("stream") is True:
                    return self._stream_chat(m, reply)
                if path == "/v1/chat/completions":
                    return self._send(200, {"id": "gate", "object": "chat.completion", "model": m,
                                            "choices": [{"index": 0, "finish_reason": "stop",
                                                         "message": {"role": "assistant", "content": reply}}],
                                            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
                if path == "/v1/messages":
                    return self._send(200, {"id": "gate", "type": "message", "role": "assistant", "model": m,
                                            "content": [{"type": "text", "text": reply}],
                                            "stop_reason": "end_turn",
                                            "usage": {"input_tokens": 1, "output_tokens": 1}})
                self._send(404, {"error": f"model path {path} not served"})

            def _mcp(self, parsed):
                if bearer_token(self.headers.get("authorization")) != harness.bearer:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", "Bearer")
                    self.send_header("content-length", "0")
                    self.end_headers()
                    return
                if not isinstance(parsed, dict):
                    return self._send(400, {"error": "json-rpc expected"})
                rid, method = parsed.get("id"), parsed.get("method")
                if method == "initialize":
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                        "protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "andyur-gate", "version": "0"}}})
                if method == "tools/list":
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                        {"name": "granted_tool", "description": "the one granted tool",
                         "inputSchema": {"type": "object"}}]}})
                if method == "tools/call":
                    name = (parsed.get("params") or {}).get("name")
                    if name != "granted_tool":
                        return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                            "isError": True, "content": [{"type": "text", "text": f"tool {name!r} not granted"}]}})
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                        "content": [{"type": "text", "text": "ok"}], "isError": False}})
                self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {}})

        self._server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.port = self._server.server_address[1]          # stub + MCP
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        # The real front, bound on all interfaces for the container, forwarding
        # to the stub on loopback exactly as the sidecar forwards to its model
        # leg; pinned to the granted model, refusing every call with no grant.
        self.front = ExecFront(f"http://127.0.0.1:{self.port}", host="0.0.0.0",
                               enforced_model=granted_model, require_model=True,
                               run_id=run_id, agent="conformance", origin_trace=origin_trace)
        self.front_port = int(self.front.start().rsplit(":", 1)[1])

    @property
    def base(self) -> str:
        """The MCP boundary's base (stub listener)."""
        return f"http://{ADVERTISE}:{self.port}"

    @property
    def front_base(self) -> str:
        """The model path's base: the REAL front."""
        return f"http://{ADVERTISE}:{self.front_port}"

    def stop(self) -> None:
        self.front.stop()
        self._server.shutdown()

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self.requests)


# ---------------------------------------------------------------------------
# Resolving the manifest the way the launcher does.
# ---------------------------------------------------------------------------

def load_selected_manifest():
    path = os.environ.get("ANDYUR_CONFORMANCE_MANIFEST", "").strip()
    if not path:
        raise RuntimeError("ANDYUR_CONFORMANCE_MANIFEST is required: the exec/v1 gate "
                           "resolves the manifest's process and configuration blocks")
    manifest = load_manifest(path, governed=True)
    runtime = manifest.runtime
    if runtime.interface_protocol != "exec/v1":
        raise RuntimeError(f"{path}: not an exec/v1 manifest")
    if runtime.process is None:
        raise RuntimeError(f"{path}: exec/v1 manifest without a process block")
    return Path(path), manifest


def selected_image_and_command() -> tuple[str, tuple[str, ...]]:
    image = os.environ.get("ANDYUR_CONFORMANCE_IMAGE", "").strip()
    if "@sha256:" not in image:
        raise RuntimeError("ANDYUR_CONFORMANCE_IMAGE must be digest-pinned")
    raw = os.environ.get("ANDYUR_CONFORMANCE_COMMAND")
    if raw is None:
        raise RuntimeError("ANDYUR_CONFORMANCE_COMMAND (JSON list) is required")
    command = json.loads(raw)
    if (not isinstance(command, list) or not command
            or not all(isinstance(p, str) and p for p in command)):
        raise RuntimeError("ANDYUR_CONFORMANCE_COMMAND must be a JSON list of non-empty strings")
    return image, tuple(command)


def gate_input():
    path = os.environ.get("ANDYUR_CONFORMANCE_INPUT", "").strip()
    if path:
        return json.loads(Path(path).read_text())
    return {"task": "conformance", "detail": "exec/v1 gate run"}


def facts_for(harness: Harness, run_id: str, model: str | None, input_mode: str,
              deadline_seconds: int) -> execconfig.RunFacts:
    return execconfig.RunFacts(
        run_id=run_id, deadline_epoch=int(time.time()) + deadline_seconds,
        model_base_url=f"{harness.front_base}/llm",
        model_openai_base_url=f"{harness.front_base}/llm/v1",
        model_name=model or "", mcp_url=f"{harness.base}/mcp",
        workspace_home=execconfig.WORKSPACE_HOME, workspace_tmp=execconfig.WORKSPACE_TMP,
        input_path=execconfig.INPUT_PATH if input_mode == "file" else "",
        # what the Secret delivers: the complete header value (PR #21)
        mcp_bearer=f"Bearer {harness.bearer}")


class Launch:
    """One resolved launch: env, files, input bytes, argv."""

    def __init__(self, image, command, process, configuration, facts, value):
        self.image, self.base_command = image, command
        self.process = process
        runinput.check_against_process(runinput.seal(value), process, where="gate input",
                                       error=RuntimeError)
        sealed = runinput.seal(value)
        self.payload = runinput.delivery_bytes(sealed) if process.input_mode != "none" else b""
        plain, secret_names = execconfig.plan_environment(configuration, facts)
        self.env = [*plain, *((name, facts.mcp_bearer) for name in secret_names)]
        self.secret_env_names = tuple(secret_names)
        self.files = execconfig.render_files(configuration, facts)
        self.command = (tuple(command) + (self.payload.decode("utf-8"),)
                        if process.input_mode == "argv" else tuple(command))
        self.stdin = self.payload if process.input_mode == "stdin" else None
        # whether any declared file template names the bearer reference
        from andyur.registry.models import TEMPLATE_REF_RE
        self.bearer_in_files = any(
            execconfig.is_secret_reference(ref)
            for f in ((configuration.files if configuration else ()) or ())
            for ref in TEMPLATE_REF_RE.findall(f.template))


def prepare_scratch(volume: str, launch: Launch) -> None:
    """A fresh named volume for ${workspace.home}, owned by the workload uid,
    holding the rendered files and (mode file) the input -- the init
    container's job, done by a helper container as that uid."""
    sh("docker", "volume", "rm", "-f", volume)
    sh("docker", "volume", "create", volume)
    own = sh("docker", "run", "--rm", "-v", f"{volume}:/scratch", "alpine:3.20",
             "chown", f"{WORKLOAD_UID}:{WORKLOAD_UID}", "/scratch", timeout=120)
    if own.returncode != 0:
        raise RuntimeError(f"scratch ownership failed: {own.stderr[-300:]!r}")
    writes = list(launch.files)
    if launch.process.input_mode == "file":
        writes.append((execconfig.INPUT_PATH, launch.payload.decode("utf-8")))
    for path, content in writes:
        home = execconfig.WORKSPACE_HOME
        if path.startswith(home + "/"):
            target = "/scratch" + path[len(home):]
        elif path.startswith(execconfig.WORKSPACE_TMP + "/"):
            target = "/scratch/.tmp-seed" + path[len(execconfig.WORKSPACE_TMP):]
        else:
            raise RuntimeError(f"generated file outside the scratch roots: {path}")
        script = (f"mkdir -p \"$(dirname '{target}')\" && cat > '{target}' && chmod 0600 '{target}'")
        put = sh("docker", "run", "--rm", "-i", "--user", f"{WORKLOAD_UID}:{WORKLOAD_UID}",
                 "-v", f"{volume}:/scratch", "alpine:3.20", "sh", "-c", script,
                 stdin=content.encode("utf-8"), timeout=120)
        if put.returncode != 0:
            raise RuntimeError(f"writing {path} failed: {put.stderr[-300:]!r}")


def run_flags(volume: str) -> list[str]:
    return [
        "--user", f"{WORKLOAD_UID}:{WORKLOAD_UID}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--read-only", "--pids-limit", "256", "--memory", "1g",
        "--tmpfs", f"/tmp:exec,uid={WORKLOAD_UID},gid={WORKLOAD_UID}",
        "-v", f"{volume}:{execconfig.WORKSPACE_HOME}",
        # The advertised name resolves to the RELAY on the bounded network, and
        # to the host only when no bounded network was established. Keeping the
        # name stable is what lets every URL the harness advertises stay
        # unchanged while the route underneath it narrows.
        *(["--network", _BOUND["network"], "--add-host", f"{ADVERTISE}:{_BOUND['relay_ip']}"]
          if _BOUND else host_alias_flags()),
    ]


_HOST_ALIAS_FLAGS: list[str] | None = None


def host_alias_flags() -> list[str]:
    """How a container on the default bridge should resolve ADVERTISE to the host.

    THE BUG THIS EXISTS FOR. The relay was always started with
    `--add-host host.docker.internal:host-gateway` and forwarded to that name. On a
    VM-backed engine (Rancher Desktop, Docker Desktop) the engine ALREADY provides
    a working route for that name, and the explicit mapping REPLACES it with the
    bridge gateway -- which on such an engine cannot reach a host listener at all.
    `infra/verify-run-isolation-docker.sh` documents exactly that: "a 0.0.0.0-bound
    host listener is UNREACHABLE at gateway, so this daemon (VM-backed engine) does
    not expose host services to containers".

    The consequence was silent. socat ACCEPTS before it dials upstream, so the
    relay answered `nc -z` normally and E8 called the network bounded and reachable
    while every model call from the workload failed with a connection error.

    The flag is still right on native Linux, where the engine provides no such
    name. So it is used only when the engine does not: one probe container per gate
    run, answered once and cached.
    """
    global _HOST_ALIAS_FLAGS
    if _HOST_ALIAS_FLAGS is None:
        probe = sh("docker", "run", "--rm", "--entrypoint", "sh", RELAY_IMAGE,
                   "-c", f"getent hosts {ADVERTISE} >/dev/null 2>&1 && echo provided",
                   timeout=120)
        provided = b"provided" in probe.stdout
        _HOST_ALIAS_FLAGS = [] if provided else ["--add-host", f"{ADVERTISE}:host-gateway"]
        print(f"[gate] {ADVERTISE} is "
              f"{'provided by the engine; not overriding it' if provided else 'not provided; mapping it to host-gateway'}",
              flush=True)
    return list(_HOST_ALIAS_FLAGS)


def bound_network(run_id: str, ports: tuple[int, ...]) -> dict:
    """Create the internal network and the one relay the workload may reach.

    Returns the state `run_flags` consumes. The relay sits on BOTH the default
    bridge (so it can reach the host's harness) and the internal network (so the
    workload can reach it); the workload sits only on the internal one, which is
    what makes every other destination unreachable rather than merely unused.
    """
    global _BOUND
    network, relay = f"exec-v1-net-{run_id}", f"exec-v1-relay-{run_id}"
    sh("docker", "network", "rm", "-f", network)
    sh("docker", "rm", "-f", relay)
    r = sh("docker", "network", "create", "--internal", network)
    if r.returncode != 0:
        raise RuntimeError(f"gate: could not create the bounded network: "
                           f"{r.stderr.decode(errors='replace')[-200:]}")
    forwards = " & ".join(
        f"socat TCP-LISTEN:{port},fork,reuseaddr TCP:{ADVERTISE}:{port}" for port in ports)
    r = sh("docker", "run", "-d", "--name", relay,
           *host_alias_flags(),
           "--entrypoint", "sh", RELAY_IMAGE, "-c", f"{forwards} & wait")
    if r.returncode != 0:
        sh("docker", "network", "rm", "-f", network)
        raise RuntimeError(f"gate: could not start the relay: "
                           f"{r.stderr.decode(errors='replace')[-200:]}")
    r = sh("docker", "network", "connect", network, relay)
    if r.returncode != 0:
        sh("docker", "rm", "-f", relay); sh("docker", "network", "rm", "-f", network)
        raise RuntimeError("gate: could not attach the relay to the bounded network")
    ip = sh("docker", "inspect", "-f",
            "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}",
            relay).stdout.decode().strip()
    if not ip:
        sh("docker", "rm", "-f", relay); sh("docker", "network", "rm", "-f", network)
        raise RuntimeError("gate: the relay reported no address on the bounded network")
    _BOUND = {"network": network, "relay": relay, "relay_ip": ip, "ports": list(ports)}
    return _BOUND


def unbind_network() -> None:
    global _BOUND
    if not _BOUND:
        return
    sh("docker", "rm", "-f", _BOUND["relay"])
    sh("docker", "network", "rm", "-f", _BOUND["network"])
    _BOUND = None


def workload_argv(name: str, launch: Launch, volume: str) -> list[str]:
    # `-i` attaches stdin ONLY when the declared mode delivers on it: the
    # production Pod opens stdin (stdinOnce) for mode 'stdin' and not otherwise.
    argv = ["docker", "run", "--name", name, *(["-i"] if launch.stdin is not None else []),
            *run_flags(volume)]
    for key, value in launch.env:
        argv += ["-e", f"{key}={value}"]
    argv += ["--entrypoint", launch.command[0], launch.image, *launch.command[1:]]
    return argv


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def e7_scratch_as_uid(volume: str) -> None:
    probe = ("set -e; for d in /home/agent /tmp; do f=$d/.gate-$$; "
             "echo x > $f && [ \"$(cat $f)\" = x ] && rm $f && echo OK $d $(id -u); done")
    r = sh("docker", "run", "--rm", *run_flags(volume), "--entrypoint", "sh",
           "alpine:3.20", "-c", probe, timeout=120)
    out = r.stdout.decode(errors="replace")
    ok = r.returncode == 0 and f"OK /home/agent {WORKLOAD_UID}" in out and f"OK /tmp {WORKLOAD_UID}" in out
    record("E7 scratch create/read/delete as the workload uid", ok,
           out.strip().replace("\n", "; ") or r.stderr.decode(errors="replace")[-200:])


MUST_DENY = ("internet-ip", "public-dns", "external-dns", "host-gateway-direct")
MUST_REACH = ("allowed-front", "allowed-mcp")
# REACHABILITY IS NOT A ROUTE, and this is the false green it cost.
#
# The allowed destinations are probed with `nc -z` against the RELAY. socat
# ACCEPTS a connection before it dials upstream, so a relay whose forward to the
# front is broken answers that probe exactly like a working one: E8 reported
# "bounded network, allowed destinations reachable, positive_control=ok" for a run
# in which the workload could not reach the front at all and died with
# "Ollama API failed: Connection error", front_forwarded=0.
#
# So one allowed destination must also ANSWER. /ready is the right target: it is
# the front's own liveness route, needs no model grant, and a 200 proves the whole
# path -- workload, internal network, relay, host, front -- rather than proving
# that socat is running.
MUST_SERVE = ("allowed-front",)


def containment_verdict(probe_output: str) -> dict:
    """Decide E8 from the probe's lines. Pure, because the property is the
    VERDICT and a property that can only be exercised by starting a container
    is a property nothing tests the edges of."""
    reached = sorted(l.split()[1] for l in probe_output.splitlines() if l.startswith("REACHED "))
    denied = sorted(l.split()[1] for l in probe_output.splitlines() if l.startswith("DENIED "))
    # The positive control first: every denial below is meaningless if the
    # allowed destinations are also unreachable, which is what a broken relay
    # or a probe that silently failed would look like.
    served = sorted(l.split()[1] for l in probe_output.splitlines() if l.startswith("SERVED "))
    unserved = sorted(l.split()[1] for l in probe_output.splitlines() if l.startswith("UNSERVED "))
    positive = set(MUST_REACH) <= set(reached) and set(MUST_SERVE) <= set(served)
    leaked = sorted(set(MUST_DENY) & set(reached))
    unprobed = sorted((set(MUST_DENY + MUST_REACH) - set(reached) - set(denied))
                      | (set(MUST_SERVE) - set(served) - set(unserved)))
    return {"measured": positive and not unprobed, "reached": reached, "denied": denied,
            "served": served, "unserved": unserved,
            "leaked": leaked, "positive_control": positive, "unprobed": unprobed,
            "ok": positive and not leaked and not unprobed}


def tool_traffic_verdict(mcp_reqs: list, unauth: list, declared_tools: tuple) -> dict:
    """Decide E3b. Fails CLOSED when the manifest declared tool grants and the
    workload made no tool request at all: the old wording was "the tool traffic,
    if any", which passed identically for a workload that authenticated
    correctly and one that never tried."""
    per_method = {}
    for request in mcp_reqs:
        name = request.get("rpc_method") or "(none)"
        per_method[name] = per_method.get(name, 0) + 1
    silent_despite_grants = bool(declared_tools) and not mcp_reqs
    return {"ok": not unauth and not silent_despite_grants,
            "requests": len(mcp_reqs), "unauthenticated": len(unauth),
            "per_method": per_method,
            "declared_tool_servers": [t.server for t in declared_tools],
            "silent_despite_grants": silent_despite_grants}


def e8_network_containment(harness: Harness, volume: str) -> dict:
    """MEASURE what the workload's network can and cannot reach.

    production-gaps 24 exists because this was never measured: the gate ran the
    container on Docker's default network with a host route, so "made no other
    network calls" was an absence nobody bounded. An absence is only evidence if
    something measured it, so this records destinations REACHED and DENIED, with
    a positive control -- a denial proves nothing when everything is refused.
    """
    relay_ip = (_BOUND or {}).get("relay_ip", "")
    front_port = harness.front_port
    probe = f"""
ok() {{ nc -z -w 3 "$1" "$2" >/dev/null 2>&1 && echo "REACHED $3" || echo "DENIED $3"; }}
served() {{ wget -q -T 5 -O- "$1" >/dev/null 2>&1 && echo "SERVED $2" || echo "UNSERVED $2"; }}
ok {relay_ip} {front_port} allowed-front
served http://{relay_ip}:{front_port}/ready allowed-front
ok {relay_ip} {harness.port} allowed-mcp
ok 1.1.1.1 443 internet-ip
ok 8.8.8.8 53 public-dns
getent hosts example.com >/dev/null 2>&1 && echo "REACHED external-dns" || echo "DENIED external-dns"
ok {HOST_GATEWAY_PROBE} {front_port} host-gateway-direct
"""
    r = sh("docker", "run", "--rm", *run_flags(volume), "--entrypoint", "sh",
           "alpine:3.20", "-c", probe, timeout=180)
    verdict = containment_verdict(r.stdout.decode(errors="replace"))
    record("E8 the workload's network is bounded: allowed destinations reachable, "
           "every other probed destination denied",
           verdict["ok"],
           f"reached={verdict['reached']} denied={verdict['denied']} "
           f"served={verdict['served']} unserved={verdict['unserved']} "
           f"leaked={verdict['leaked']} unprobed={verdict['unprobed']} "
           f"positive_control={'ok' if verdict['positive_control'] else 'FAILED'}")
    return {**verdict, "network": (_BOUND or {}).get("network")}


def e3_mcp_boundary_probe(harness: Harness, volume: str) -> None:
    """A REAL positive at the MCP boundary the workload faces, driven from a
    container under the workload's own posture: no bearer -> 401; the
    declared bearer -> initialize 200 and the granted tool called; an
    undeclared tool refused. A workload that declares no tools (OpenSRE) makes
    no such calls itself, so this is what proves the boundary (R MED-2)."""
    probe = f"""set -e
u='{harness.base}/mcp'
init='{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}'
code=$(wget -q -S -O /dev/null --post-data="$init" --header='Content-Type: application/json' "$u" 2>&1 | awk '/^ *HTTP\\/[0-9.]+ [0-9]+/{{c=$2}} END{{print c}}'); echo "NOBEARER $code"
wget -q -O /tmp/i.json --post-data="$init" --header='Content-Type: application/json' --header='Authorization: Bearer {harness.bearer}' "$u"; grep -q andyur-gate /tmp/i.json && echo "BEARER 200"
call='{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"granted_tool","arguments":{{}}}}}}'
wget -q -O /tmp/c.json --post-data="$call" --header='Content-Type: application/json' --header='Authorization: Bearer {harness.bearer}' "$u"; grep -q '"isError": false' /tmp/c.json && echo "GRANTED ok"
bad='{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"other_tool","arguments":{{}}}}}}'
wget -q -O /tmp/b.json --post-data="$bad" --header='Content-Type: application/json' --header='Authorization: Bearer {harness.bearer}' "$u"; grep -q '"isError": true' /tmp/b.json && echo "UNGRANTED refused"
"""
    r = sh("docker", "run", "--rm", *run_flags(volume), "--entrypoint", "sh",
           "alpine:3.20", "-c", probe, timeout=120)
    out = r.stdout.decode(errors="replace")
    ok = ("NOBEARER 401" in out and "BEARER 200" in out and "GRANTED ok" in out
          and "UNGRANTED refused" in out)
    record("E3 MCP boundary: no bearer 401, declared bearer initialize + granted tool, undeclared refused",
           ok, out.strip().replace("\n", "; ") or r.stderr.decode(errors="replace")[-200:])


def e5_input_door(process) -> None:
    too_big = {"task": "x" * (process.input_max_bytes + 1)}
    try:
        runinput.check_against_process(runinput.seal(too_big), process, where="gate",
                                       error=RuntimeError)
        record("E5 over-budget input refused at the door", False, "accepted")
    except Exception as exc:                                  # noqa: BLE001
        record("E5 over-budget input refused at the door", True,
               f"{type(exc).__name__}: {str(exc)[:120]}")


def run_workload(launch: Launch, volume: str, timeout: float, kill_when=None
                 ) -> tuple[int | None, str, str, float, bool]:
    """Run the launch once; with `kill_when`, SIGKILL the container the moment
    that predicate turns true (E6 uses the harness seeing the workload's first
    model request: the process is then provably mid-run, whatever its speed).
    Returns (exit_code, stdout, stderr, elapsed, killed)."""
    sh("docker", "rm", "-f", CONTAINER)
    argv = workload_argv(CONTAINER, launch, volume)
    started = time.monotonic()
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if launch.stdin is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    killed = threading.Event()
    stop_watch = threading.Event()

    def watch():
        while not stop_watch.is_set():
            if kill_when():
                sh("docker", "kill", "-s", "KILL", CONTAINER)
                killed.set()
                return
            time.sleep(0.02)

    watcher = None
    if kill_when is not None:
        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
    try:
        out, err = proc.communicate(input=launch.stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        sh("docker", "kill", CONTAINER)
        out, err = proc.communicate()
    finally:
        stop_watch.set()
        if watcher is not None:
            watcher.join(timeout=2)
    elapsed = time.monotonic() - started
    exit_code = None
    inspect = sh("docker", "inspect", "--format", "{{.State.ExitCode}}", CONTAINER)
    if inspect.returncode == 0 and inspect.stdout.strip():
        exit_code = int(inspect.stdout.strip())
    return (exit_code, out.decode("utf-8", errors="replace"),
            err.decode("utf-8", errors="replace"), elapsed, killed.is_set())


def credential_scan(launch: Launch, canaries: dict[str, str], stdout: str, stderr: str) -> None:
    """E4: the launched container's env and argv, every generated file, and
    the workload's output, scanned by VALUE for what must be absent."""
    inspect = sh("docker", "inspect", CONTAINER)
    info = json.loads(inspect.stdout)[0] if inspect.returncode == 0 else {}
    env = info.get("Config", {}).get("Env", [])
    argv = [info.get("Path", "")] + (info.get("Args") or [])
    haystacks = {
        "env": "\n".join(env), "argv": "\n".join(argv),
        "files": "\n".join(content for _, content in launch.files),
        "stdout": stdout, "stderr": stderr,
    }
    findings = []
    for name, value in canaries.items():
        for where, text in haystacks.items():
            if value not in text:
                continue
            # The MCP bearer may live EXACTLY where the manifest declared it --
            # a bearer-backed env name, or a template naming the reference --
            # and nowhere else (never argv, never the output).
            if name == "mcp_bearer" and where == "env" and launch.secret_env_names:
                continue
            if name == "mcp_bearer" and where == "files" and launch.bearer_in_files:
                continue
            findings.append(f"{name} in {where}")
    andyur_env = [e.split("=", 1)[0] for e in env if e.startswith("ANDYUR_")]
    record("E4 no credential in env, argv, generated files or output",
           not findings and not andyur_env,
           f"findings={findings} andyur_env={andyur_env} env_names={sorted(e.split('=',1)[0] for e in env)}")


def trace_record(gate_span, recorder, otel_endpoint: str | None) -> dict:
    spans = recorder.get_finished_spans()
    ctx = gate_span.get_span_context()
    refusals = sorted({s.attributes.get("andyur.refusal") for s in spans
                       if s.attributes.get("andyur.refusal") not in (None, "none")})
    return {
        "trace_id": format(ctx.trace_id, "032x") if ctx.is_valid else None,
        "exported_to": otel_endpoint or "in-memory only",
        "span_count": len(spans),
        "span_names": sorted({s.name for s in spans}),
        "front_refusals_by_name": refusals,
        "front_forwarded": sum(1 for s in spans if s.attributes.get("andyur.decision") == "forwarded"),
    }


def write_evidence(payload: dict) -> Path:
    stamp = time.strftime("%Y-%m-%d", time.localtime(payload["started_epoch"]))
    requested = os.environ.get("ANDYUR_CONFORMANCE_EVIDENCE")
    out = (Path(requested) if requested else
           HERE / f"result-exec-v1-{stamp}-{platform.system().lower()}-{platform.machine()}.json")
    tmp = out.with_name(out.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(json.dumps(payload, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    if requested:
        try:
            os.link(tmp, out)
        except FileExistsError:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"refusing to overwrite conformance evidence {out}")
        tmp.unlink()
    else:
        os.replace(tmp, out)
    return out


def gate_tracing():
    """The gate's own trace: OTLP export when ANDYUR_OTEL_ENDPOINT names a
    collector, and ALWAYS an in-memory record of every span (the real front's
    included) so the evidence can list what the run produced without one."""
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from andyur import otel
    recorder = InMemorySpanExporter()
    otel.attach_span_processor(SimpleSpanProcessor(recorder))
    tracer = otel.setup_tracing("andyur-gate")
    return tracer, recorder


def main() -> int:
    started = time.time()
    tracer, recorder = gate_tracing()
    try:
        with tracer.start_as_current_span("exec-v1-conformance") as gate_span:
            return _main(started, gate_span, recorder)
    finally:
        # the gate's own exit is bounded like the sidecar's: no collector, no wait
        from andyur import otel
        otel.shutdown_bounded(5.0)


def _main(started: float, gate_span, recorder) -> int:
    from andyur import otel
    otel_endpoint = os.environ.get("ANDYUR_OTEL_ENDPOINT") if otel.OTEL_ON else None
    try:
        image, command = selected_image_and_command()
        manifest_path, manifest = load_selected_manifest()
    except (RuntimeError, ValueError) as exc:
        print(f"[gate] {exc}", file=sys.stderr)
        return 2
    runtime = manifest.runtime
    process, configuration = runtime.process, runtime.configuration
    granted_model = manifest.model_requested      # None = no grant: every model call refused
    lifecycle_seconds = (runtime.lifecycle.max_seconds if runtime.lifecycle else 600)
    timeout = float(min(lifecycle_seconds, GATE_TIMEOUT_CEILING))
    pull = sh("docker", "pull", image, timeout=900)
    if pull.returncode != 0:
        print(f"[gate] docker pull failed: {pull.stderr[-300:]!r}", file=sys.stderr)
        return 2
    image_id = sh("docker", "image", "inspect", "--format", "{{.Id}}", image).stdout.decode().strip()

    run_id = "gate" + secrets.token_hex(6)
    gate_span.set_attribute("andyur.run_id", run_id)
    gate_span.set_attribute("andyur.model.granted", granted_model or "")
    harness = Harness(granted_model, run_id=run_id, origin_trace=otel.current_traceparent())
    canaries = {"run_token": "run-token-canary-" + secrets.token_urlsafe(12),
                "channel_token": "channel-token-canary-" + secrets.token_urlsafe(12),
                "mcp_bearer": harness.bearer}
    # The launcher process HOLDS the run's other credentials (the daemon has
    # the run token and the channel token in hand when it builds the Pod).
    # This gate holds the canaries the same way, in its own environment, so
    # E4 can fail: a launch that inherited or forwarded them would show them
    # in the container (R MED-2).
    os.environ["ANDYUR_RUN_TOKEN"] = canaries["run_token"]
    os.environ["ANDYUR_CHANNEL_TOKEN"] = canaries["channel_token"]
    facts = facts_for(harness, run_id, granted_model, process.input_mode, lifecycle_seconds)
    volume = f"exec-v1-gate-{run_id}"
    # BEFORE any container starts, because `run_flags` puts every one of them --
    # the workload and each probe -- on this network.
    bound_network(run_id, (harness.port, harness.front_port))
    containment = {"measured": False}
    try:
        launch = Launch(image, command, process, configuration, facts, gate_input())
        input_sha = hashlib.sha256(launch.payload).hexdigest()
        # E5 (door), E7 and the E3 boundary probe need no workload
        e5_input_door(process)
        prepare_scratch(volume, launch)
        e7_scratch_as_uid(volume)
        containment = e8_network_containment(harness, volume)
        e3_mcp_boundary_probe(harness, volume)

        # E1: the run (MCP traffic is counted from here: the E3 probe's own
        # requests above are the gate's, not the workload's)
        mcp_before = len([r for r in harness.snapshot() if r["path"].split("?")[0] == "/mcp"])
        exit_code, stdout, stderr, elapsed, _ = run_workload(launch, volume, timeout)
        # the daemon's OWN capture (redacted, bounded by the smaller of the
        # manifest's emission bound and the platform's retention bound)
        captured = capture_output(stdout if process.stdout == "capture" else None,
                                  stderr if process.stderr == "capture" else None,
                                  emission_max_bytes=process.output_max_bytes,
                                  retention_max_bytes=process.output_max_bytes)
        error = exit_error(exit_code)
        record("E1 stock workload started, consumed its input and exited 0",
               exit_code == 0,
               f"exit={exit_code} error={error!r} elapsed={elapsed:.1f}s stdout_bytes={len(stdout.encode())}"
               f" stderr_tail={stderr[-160:]!r}")
        # E2 / E3: where the traffic went
        seen = harness.snapshot()
        mcp_reqs = [r for r in seen if r["path"].split("?")[0] == "/mcp"][mcp_before:]
        # everything else the stub saw came THROUGH the real front, i.e. passed
        # the path policy and the model pin (the front forwards the validated
        # object, so `model` here is the granted one by construction)
        model_reqs = [r for r in seen if r["path"].split("?")[0] != "/mcp"]
        wrong_model = [r for r in model_reqs if r["model"] != granted_model]
        allowed = set(modelpolicy.FRONT_LLM_PATHS)
        off_policy = [r for r in model_reqs if r["path"].split("?")[0] not in allowed]
        # the front's policy, as a positive control from the gate itself
        import httpx
        fb = harness.front_base.replace(ADVERTISE, "127.0.0.1")
        tags = httpx.get(f"{fb}/llm/api/tags", timeout=10).status_code
        wrong = httpx.post(f"{fb}/llm/api/chat", json={"model": "other-model"}, timeout=10).status_code
        variant = httpx.post(f"{fb}/llm/api/chat", content=b'{"model": "%s", "MODEL": "other"}' % (granted_model or "x").encode(),
                             headers={"content-type": "application/json"}, timeout=10).status_code
        record("E2 model traffic observed only through the front, on the allowed endpoints, naming the granted model",
               bool(model_reqs) and not wrong_model and not off_policy,
               f"model_requests={len(model_reqs)} paths={sorted({r['path'].split('?')[0] for r in model_reqs})}"
               f" wrong_model={wrong_model} off_policy={[r['path'] for r in off_policy]}")
        record("E2b the front refuses model listing (404), another model (403) and a case-variant key (403)",
               (tags, wrong, variant) == (404, 403, 403), f"tags={tags} wrong_model={wrong} variant_key={variant}")
        unauth = [r for r in mcp_reqs if bearer_token(r["authorization"]) != harness.bearer]
        # the workload's OWN MCP traffic: only what the probe proved the
        # boundary allows; a workload declaring no tools makes none
        # E3b USED TO READ "the tool traffic, if any", which passed identically
        # for a workload that authenticated correctly and one that never tried:
        # OpenSRE recorded workload_mcp_requests=0 and went green. It now fails
        # CLOSED when the manifest declared tool grants, and reports positive
        # per-method counts either way so that zero is a measurement.
        verdict = tool_traffic_verdict(
            mcp_reqs, unauth, tuple(getattr(manifest, "tool_requests", ()) or ()))
        record("E3b the workload's tool traffic carried the declared bearer, and a "
               "workload that declared tool grants actually used them",
               verdict["ok"],
               f"workload_mcp_requests={verdict['requests']} "
               f"unauthenticated={verdict['unauthenticated']} "
               f"per_method={verdict['per_method']} "
               f"declared_tool_servers={verdict['declared_tool_servers']} "
               f"silent_despite_grants={verdict['silent_despite_grants']} "
               f"declared_bearer_env={list(launch.secret_env_names)}")
        # E4
        credential_scan(launch, canaries, stdout, stderr)
        # E5 (output bound): the daemon's capture on the real output, AND a
        # real positive -- the same launch under a 256-byte bound is truncated
        # with the marker (the bound is enforced, not merely declared)
        record("E5 captured output bounded by process.output.max_bytes (daemon capture)",
               len(captured.encode()) <= process.output_max_bytes,
               f"raw={len(stdout.encode())} bound={process.output_max_bytes} kept={len(captured.encode())}")
        _, stdout_small, stderr_small, _, _ = run_workload(launch, volume, timeout)
        small = capture_output(stdout_small, stderr_small, emission_max_bytes=256, retention_max_bytes=256)
        record("E5b a 256-byte bound truncates the same output with the marker",
               len(stdout_small.encode()) > 256 and len(small.encode()) <= 256 + len(TRUNCATION_MARKER.encode())
               and TRUNCATION_MARKER.strip() in small,
               f"raw={len(stdout_small.encode())} kept={len(small.encode())} marker={TRUNCATION_MARKER.strip() in small}")
        # E6: the same launch, SIGKILLed the moment the harness sees its first
        # model request -- provably mid-run, however fast the workload is.
        seen_before = len(harness.snapshot())
        exit_code_k, _, _, elapsed_k, killed = run_workload(
            launch, volume, timeout,
            kill_when=lambda: len(harness.snapshot()) > seen_before)
        record("E6 killed workload maps to a failed run, never success",
               killed and exit_code_k not in (0, None) and exit_error(exit_code_k) is not None,
               f"killed={killed} exit={exit_code_k} error={exit_error(exit_code_k)!r} "
               f"elapsed={elapsed_k:.1f}s")
        summary_excerpt = _truncate(captured, 600)
    finally:
        sh("docker", "rm", "-f", CONTAINER)
        sh("docker", "volume", "rm", "-f", volume)
        unbind_network()
        harness.stop()

    ok = all(c["ok"] for c in CHECKS)
    evidence = {
        "gate": "exec-v1-conformance", "adr": "adr-011", "decision": "D8",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "started_epoch": started, "duration_s": round(time.time() - started, 1),
        "host": {"platform": platform.platform(), "python": sys.version.split()[0],
                 "docker": sh("docker", "version", "--format", "{{.Server.Version}}").stdout.decode().strip()},
        "image": {"ref": image, "id": image_id},
        "inputs": {
            "selected_image": image,
            "selected_command": list(command),
            "manifest_sha256": file_sha(manifest_path),
            # Bound to THIS gate's source only: the runtime-v1 gate's files are
            # not what produced this artifact, and binding them would let an
            # edit there stale exec/v1 evidence for no reason (per-gate binding,
            # publisher.CONFORMANCE_GATES).
            "exec_gate_sha256": file_sha(Path(__file__)),
            # what the publisher binds beyond image+command (R MED-3)
            "interface": runtime.interface_protocol,
            "granted_model": granted_model,
            "input_mode": process.input_mode,
            "input_sha256": input_sha,
            "generated_configuration": {
                "env_names": [k for k, _ in launch.env],
                "secret_env_names": list(launch.secret_env_names),
                "files": [{"path": p, "sha256": hashlib.sha256(c.encode()).hexdigest()}
                          for p, c in launch.files]},
        },
        # the trace this run produced (observability-exit-criteria.md 7):
        # its id, where it was exported, and the span names recorded in-process
        # (the real front's decisions among them, by name)
        "trace": trace_record(gate_span, recorder, otel_endpoint),
        "workload_stdout_excerpt": summary_excerpt,
        # What the workload's network could reach, MEASURED. The five-state
        # vocabulary in ADR-012 D10 reads this: a containment property is
        # OBSERVED/REFUSED when `measured` is true, and NOT MEASURED otherwise.
        # Recorded whether or not the run reached the probe, so a gate that died
        # before measuring says so instead of implying an absence.
        "containment": containment,
        "checks": CHECKS,
        "ok": ok,
    }
    out = write_evidence(evidence)
    print(f"[gate] {'GREEN' if ok else 'RED'}: {sum(c['ok'] for c in CHECKS)}/{len(CHECKS)} "
          f"checks passed; evidence {out}", flush=True)
    return 0 if ok else 1


def _truncate(text: str, max_bytes: int) -> str:
    data = text.encode("utf-8")
    if len(data) <= max_bytes:
        return text
    return data[:max_bytes].decode("utf-8", errors="ignore")


if __name__ == "__main__":
    sys.exit(main())

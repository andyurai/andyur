"""exec/v1 input delivery: from the assignment to the process (ADR-011 D10).

The door (test_run_input.py) proved a run that cannot be delivered is refused
before it exists. This file proves the other half: a run that CAN be delivered
is, by the mode its manifest declared, with the bytes it was sealed with.

  argv   appended as the last argument, bounded by Linux MAX_ARG_STRLEN
  stdin  the controller attaches to the WORKLOAD after it is Running
  file   the controller attaches to the platform INIT container, which
         persists the bytes VERBATIM to execconfig.INPUT_PATH before the
         workload starts

Throughout: the bytes never appear in a Pod object, and never pass through
execconfig.substitute(). The second property is the one that matters -- the
init container holds this run's bearer whenever a declared file needs it, and
a caller-controlled payload must not be able to name it.
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import pathlib
import shutil
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

import conftest
from test_kubernetes_controller import FakeApi
from andyur import config, execconfig, runinput
from andyur.daemon.governed_kubernetes import (_exec_input_delivery,
                                               validate_runtime_envelope)
from andyur.daemon.kubernetes_controller import (KubernetesRunController,
                                                 RunCredentials)
from andyur.daemon.kubernetes_manifests import (RunGroupSpec, build_run_group,
                                                run_group_names)
from andyur.daemon.orchestrator import RunSpec
from andyur.execconfig import UnresolvedReference
from andyur.registry.models import (RUNTIME_PROTOCOL_EXEC_V1, ConfigFile,
                                    ConfigurationSpec, EnvVar, ProcessSpec,
                                    RuntimeResolution)
from andyur.registry.runtime_wire import encode_runtime
from andyur.runinput import ARGV_MAX_BYTES, InputRefused
from andyur.server import coordinator
from andyur.server.app import app

# THE CONFIG-RENDER INIT CONTAINER, BY NAME. The agent Pod also carries
# `await-containment`, which must run first and always (it holds the workload
# until its NetworkPolicy is actually in force). These tests are about
# materialising configuration, so they select the container they mean instead
# of assuming it is the only one, or the first.
def _config_init(pod_spec):
    inits = pod_spec.get("initContainers", [])
    named = [c for c in inits if c["name"] == "materialize-config"]
    assert len(named) <= 1, f"more than one materialize-config: {[c['name'] for c in inits]}"
    return named[0] if named else None


def _config_inits(pod_spec):
    return [c for c in pod_spec.get("initContainers", [])
            if c["name"] == "materialize-config"]


IMAGE = "registry.example/andyur@sha256:" + "a" * 64
DIGEST = "sha256:" + "ab" * 32
CREDENTIALS = RunCredentials("CHANNEL-SECRET-VALUE", "RUN-TOKEN-VALUE", "LLM-KEY-VALUE",
                             mcp_bearer="MCP-BEARER-VALUE")   # exec/v1 launches need one (M1)
# A payload that NAMES the bearer reference. Delivered correctly it arrives as
# these characters; delivered through the template resolver it would arrive as
# the run's credential. Every delivery assertion below uses it.
MARKER = '{"incident":"INC-4471","note":"${services.tools.mcp_headers.Authorization}"}'
PAYLOAD = MARKER.encode()
COMMAND = ("/app/tool", "investigate", "-i", "-")


def _spec(mode: str, payload: bytes = PAYLOAD, files=(), max_bytes: int = 1024,
          **changes) -> RunGroupSpec:
    return RunGroupSpec(
        namespace="andyur-runs", run_id="run-one", generation="gen-a",
        agent_id="stock", registry_agent_id="agt_stock",
        proxy_image=IMAGE, agent_image=IMAGE, agent_args=COMMAND,
        agent_runtime="container", agent_interface=RUNTIME_PROTOCOL_EXEC_V1,
        exec_configuration=ConfigurationSpec(env=(), files=tuple(files)) if files else None,
        exec_input_mode=mode, exec_input=payload, exec_input_max_bytes=max_bytes,
        **changes)


def _agent_pod(spec: RunGroupSpec) -> dict:
    return list(build_run_group(spec))[-1]      # the controller pops the agent last


def _init(pod: dict) -> dict | None:
    inits = _config_inits(pod["spec"])
    return inits[0] if inits else None


def _env(container: dict) -> dict:
    return {e["name"]: e for e in container.get("env", [])}


# --------------------------------------------------------------------------
# The Pod shape, per mode
# --------------------------------------------------------------------------

def test_stdin_mode_opens_the_workloads_stdin_for_exactly_one_attach():
    pod = _agent_pod(_spec("stdin"))
    [workload] = pod["spec"]["containers"]
    assert workload["stdin"] is True and workload["stdinOnce"] is True
    assert _init(pod) is None                     # nothing to materialise


def test_file_mode_adds_the_init_container_even_with_no_declared_files():
    spec = _spec("file", max_bytes=4096)
    pod = _agent_pod(spec)
    [workload] = pod["spec"]["containers"]
    assert "stdin" not in workload                # the workload reads a FILE
    init = _init(pod)
    assert init["name"] == "materialize-config"
    assert init["image"] == IMAGE                 # the platform's image
    assert init["command"] == ["python", "-m", "andyur.execconfig"]
    assert init["stdin"] is True and init["stdinOnce"] is True
    env = _env(init)
    assert env[execconfig.INPUT_PATH_ENV]["value"] == execconfig.INPUT_PATH
    assert env[execconfig.INPUT_MAX_ENV]["value"] == "4096"
    assert execconfig.BEARER_ENV not in env       # no file needs it
    # No templates: no ConfigMap object and no templates mount.
    assert not any(m["name"] == "exec-config" for m in init["volumeMounts"])
    assert not any(r["kind"] == "ConfigMap" for r in build_run_group(spec))


def test_file_mode_with_declared_files_is_one_init_container_doing_both_jobs():
    files = (ConfigFile(path="${workspace.home}/.cfg",
                        template="mcp: ${services.tools.mcp_url}"),)
    spec = _spec("file", files=files)
    pod = _agent_pod(spec)
    inits = _config_inits(pod["spec"])
    assert len(inits) == 1
    init = inits[0]
    assert init["stdin"] is True
    assert execconfig.INPUT_PATH_ENV in _env(init)
    assert any(m["name"] == "exec-config" for m in init["volumeMounts"])
    assert any(r["kind"] == "ConfigMap" for r in build_run_group(spec))


def test_no_delivery_mode_leaves_every_stdin_closed():
    files = (ConfigFile(path="${workspace.home}/.cfg", template="k: v"),)
    for spec in (_spec("", payload=b"", max_bytes=0),
                 _spec("", payload=b"", max_bytes=0, files=files)):
        pod = _agent_pod(spec)
        for container in [*pod["spec"].get("initContainers", []),
                          *pod["spec"]["containers"]]:
            assert "stdin" not in container and "stdinOnce" not in container
            assert execconfig.INPUT_PATH_ENV not in _env(container)


@pytest.mark.parametrize("mode", ["stdin", "file"])
def test_the_input_bytes_appear_in_no_pod_object(mode):
    """They are written by attach after the objects exist. A payload in a Pod
    spec, ConfigMap or annotation would be readable by anything with `get` on
    the namespace, and would outlive the attach."""
    rendered = json.dumps(list(build_run_group(_spec(mode))))
    assert "INC-4471" not in rendered
    assert "mcp_headers" not in rendered


@pytest.mark.parametrize("changes,match", [
    ({"exec_input_mode": "argv"}, "must be ''"),
    ({"agent_interface": ""}, "requires the exec/v1 interface"),
    ({"exec_input_max_bytes": 0}, "requires the manifest's bound"),
    ({"exec_input": b"x" * 2000}, "exceeds the manifest's bound"),
    ({"exec_input_mode": ""}, "input without a delivery mode"),
])
def test_the_builder_refuses_an_inconsistent_delivery_spec(changes, match):
    with pytest.raises(ValueError, match=match):
        build_run_group(dataclasses.replace(_spec("stdin"), **changes))


# --------------------------------------------------------------------------
# The controller: attach AFTER the target container is Running, inside the
# rollback scope, to the right container, with the exact bytes
# --------------------------------------------------------------------------

class DeliveringApi(FakeApi):
    def __init__(self):
        super().__init__()
        self.events: list[tuple] = []
        self.running = True
        self.attach_error: Exception | None = None

    def apply(self, resource):
        super().apply(resource)
        self.events.append(("apply", resource["kind"],
                            resource["metadata"]["labels"].get(
                                "app.kubernetes.io/component")))

    def wait_container_running(self, namespace, name, container, timeout):
        self.events.append(("wait", name, container, timeout))
        return self.running

    def attach_stdin(self, namespace, name, container, data):
        self.events.append(("attach", name, container, data))
        if self.attach_error:
            raise self.attach_error


def _launch(spec, api=None):
    api = api or DeliveringApi()
    controller = KubernetesRunController(api, "andyur-runs")
    controller.launch(spec, CREDENTIALS)
    return api


@pytest.mark.parametrize("mode,target", [("stdin", "agent"),
                                         ("file", "materialize-config")])
def test_delivery_targets_the_declared_container_after_the_pod_is_applied(mode, target):
    api = _launch(_spec(mode))
    agent_name = run_group_names(_spec(mode))["agent"]
    kinds = [e for e in api.events
             if e[0] != "apply" or (e[1] == "Pod" and e[2] == "agent")]
    # Exactly: the agent Pod is applied, then its target container is awaited,
    # then the attach happens. Nothing is attached before the Pod exists.
    assert kinds == [
        ("apply", "Pod", "agent"),
        ("wait", agent_name, target, KubernetesRunController.READY_TIMEOUT),
        ("attach", agent_name, target, PAYLOAD),
    ]


class _WSAttachServer:
    """A real local server that completes the k8s attach WebSocket handshake and
    then NEVER reads -- the field case (a workload that upgrades, then stalls).
    Lets the H3 fix be tested as the PROPERTY (a real bounded socket), not the
    helper: no mock of stream(), no cluster."""

    def __init__(self):
        import socket, threading
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        self._conns = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        import base64, hashlib
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        self._conns.append(conn)
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
        key = ""
        for line in req.decode("latin1").split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        conn.send(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
            b"Sec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n")
        # then never read -- the stall

    def close(self):
        try:
            self._srv.close()
        finally:
            for c in self._conns:
                try:
                    c.close()
                except OSError:
                    pass


def _api_against(port):
    from kubernetes import client
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    cfg = client.Configuration()
    cfg.host = f"http://127.0.0.1:{port}"
    cfg.verify_ssl = False
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    api._core = client.CoreV1Api(client.ApiClient(cfg))
    api.ATTACH_TIMEOUT_SECONDS = 2.0   # keep the test fast
    return api


def test_open_attach_stream_bounds_the_real_socket_the_client_opens():
    """H3 as the PROPERTY: against a real server that completes the handshake,
    the returned socket carries a timeout (the previous fix set it on the
    create_connection path the client never uses, leaving this None)."""
    server = _WSAttachServer()
    try:
        api = _api_against(server.port)
        ws = api._open_attach_stream("ns", "pod", "agent")
        try:
            assert ws.sock.gettimeout() == api.ATTACH_TIMEOUT_SECONDS
            assert ws.sock.gettimeout() is not None
        finally:
            ws.close()
    finally:
        server.close()


def test_attach_stdin_to_a_stalling_peer_raises_within_the_bound():
    """The field case that matters: a workload that upgrades then never reads an
    8 MiB write. attach_stdin must RAISE (fatal -> rollback) within the bound,
    not block the worker forever."""
    import time
    server = _WSAttachServer()
    try:
        api = _api_against(server.port)
        big = b"x" * (8 * 1024 * 1024)
        start = time.monotonic()
        with pytest.raises(RuntimeError, match="after the stream opened.*partial task"):
            api.attach_stdin("ns", "pod", "agent", big)
        elapsed = time.monotonic() - start
        assert elapsed < 6 * api.ATTACH_TIMEOUT_SECONDS, f"took {elapsed:.1f}s"
    finally:
        server.close()


def test_total_write_deadline_exceeds_the_per_send_timeout():
    """LOW1: the total-write deadline must be a DISTINCT, larger constant than
    the per-send socket timeout (equal constants would leave the trickle case
    bounded only per-send). Pins the ordering the mutation pass found unpinned."""
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    assert (OfficialKubernetesApi.ATTACH_WRITE_DEADLINE_SECONDS
            > OfficialKubernetesApi.ATTACH_TIMEOUT_SECONDS)


def test_write_bounded_stops_between_frames_when_the_total_deadline_blows(monkeypatch):
    """The trickle HIGH: a peer reading just fast enough that no single send
    stalls still stretches the whole write to payload/rate. _write_bounded
    checks a total deadline BETWEEN chunked frames (no cross-thread close, which
    could not interrupt a held frame lock) and raises when it blows -- stopping
    before sending the rest, so the launch fails rather than hang."""
    import time as _time
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    api.ATTACH_WRITE_DEADLINE_SECONDS = 5.0
    api.ATTACH_CHUNK_BYTES = 1024

    clock = {"t": 1000.0}
    monkeypatch.setattr(_time, "monotonic", lambda: clock["t"])

    sent = {"chunks": 0}
    class _WS:
        def write_stdin(self, chunk):
            sent["chunks"] += 1
            clock["t"] += 2.0   # each frame "takes" 2s -> deadline blows on the 3rd check

    with pytest.raises(TimeoutError, match="total deadline"):
        api._write_bounded(_WS(), b"x" * (10 * 1024))   # 10 chunks, would need 20s
    assert sent["chunks"] < 10, "must stop before sending every chunk"


def test_write_bounded_sends_all_frames_within_the_deadline(monkeypatch):
    """Positive control: a prompt peer gets the whole payload, chunked."""
    import time as _time
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    api.ATTACH_WRITE_DEADLINE_SECONDS = 60.0
    api.ATTACH_CHUNK_BYTES = 1024
    monkeypatch.setattr(_time, "monotonic", lambda: 1000.0)   # no time passes
    received = []
    class _WS:
        def write_stdin(self, chunk): received.append(chunk)
    api._write_bounded(_WS(), b"y" * 4096)
    assert b"".join(received) == b"y" * 4096 and len(received) == 4
    # LOW2: frames are byte-bounded, so every frame is <= ATTACH_CHUNK_BYTES
    assert all(len(c) <= api.ATTACH_CHUNK_BYTES for c in received)


def test_write_bounded_chunks_by_bytes_not_characters():
    """LOW2: slicing a str would count CHARACTERS -- a 4096-char multibyte
    payload would emit one frame far larger than the byte bound. Slicing bytes
    keeps every frame <= ATTACH_CHUNK_BYTES bytes."""
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)
    api.ATTACH_WRITE_DEADLINE_SECONDS = 1e9
    api.ATTACH_CHUNK_BYTES = 1024
    payload = ("\u2603" * 4096).encode("utf-8")   # snowman: 3 bytes each = 12288 bytes
    frames = []
    class _WS:
        def write_stdin(self, chunk): frames.append(chunk)
    api._write_bounded(_WS(), payload)
    assert b"".join(frames) == payload
    assert all(len(f) <= 1024 for f in frames)     # bytes, not 4096 chars in one frame
    assert len(frames) >= 12


class _WSAttachDrainServer(_WSAttachServer):
    """Completes the handshake, then DRAINS every stdin frame and reassembles
    the channel-0 payload. The positive control R asked for: a fix that shut
    the socket unconditionally would pass every refusal test, so we need a peer
    that READS and prove the full payload arrives byte-for-byte."""

    def __init__(self):
        self.received = bytearray()
        self._done = __import__("threading").Event()
        super().__init__()

    def _recvn(self, conn, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def _serve(self):
        import base64, hashlib
        conn, _ = self._srv.accept()
        self._conns.append(conn)
        req = b""
        while b"\r\n\r\n" not in req:
            c = conn.recv(4096)
            if not c:
                return
            req += c
        key = next(l.split(":", 1)[1].strip() for l in req.decode("latin1").split("\r\n")
                   if l.lower().startswith("sec-websocket-key:"))
        acc = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        conn.send(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + acc.encode() +
                  b"\r\nSec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n")
        try:
            while True:
                h = self._recvn(conn, 2)
                if h is None:
                    break
                opcode = h[0] & 0x0F
                masked = h[1] & 0x80
                length = h[1] & 0x7F
                if length == 126:
                    length = int.from_bytes(self._recvn(conn, 2), "big")
                elif length == 127:
                    length = int.from_bytes(self._recvn(conn, 8), "big")
                mask = self._recvn(conn, 4) if masked else b"\x00\x00\x00\x00"
                payload = self._recvn(conn, length) or b""
                data = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
                if opcode == 0x8:            # close
                    break
                if opcode in (0x1, 0x2) and data:
                    # channel byte (0 = stdin) then the stdin bytes
                    if data[0] == 0:
                        self.received += data[1:]
        finally:
            self._done.set()


def test_a_draining_peer_receives_the_whole_payload_byte_for_byte():
    """DRAIN positive control (R): a peer that reads gets the full payload and
    attach_stdin RETURNS. Without this, a fix that unconditionally shuts the
    socket would pass every refusal test above while delivering nothing."""
    payload = b"".join(bytes([i % 251]) for i in range(3)) + b"INC-4471:" + b"z" * (256 * 1024)
    server = _WSAttachDrainServer()
    try:
        api = _api_against(server.port)
        api.attach_stdin("ns", "pod", "agent", payload)   # must NOT raise
        assert server._done.wait(10), "server did not finish draining"
        assert bytes(server.received) == payload, (
            f"received {len(server.received)} bytes, expected {len(payload)}")
    finally:
        server.close()


def test_a_trickle_reader_is_bounded_by_the_total_deadline():
    """PROPERTY on a real socket: a peer that reads slowly (never fully stalls,
    so the per-send timeout never fires) still makes attach_stdin RAISE within
    the total deadline rather than run to payload/rate."""
    import socket, threading, time
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi

    class _Trickle(_WSAttachServer):
        def _serve(self):
            import base64, hashlib
            conn, _ = self._srv.accept()
            self._conns.append(conn)
            req = b""
            while b"\r\n\r\n" not in req:
                c = conn.recv(4096)
                if not c:
                    return
                req += c
            key = next(l.split(":", 1)[1].strip() for l in req.decode("latin1").split("\r\n")
                       if l.lower().startswith("sec-websocket-key:"))
            acc = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            conn.send(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + acc.encode() +
                      b"\r\nSec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n")
            # trickle: read a little, forever, so no single send fully stalls
            try:
                while True:
                    conn.recv(16 * 1024)
                    time.sleep(0.2)
            except OSError:
                pass

    server = _Trickle()
    try:
        api = _api_against(server.port)
        api.ATTACH_TIMEOUT_SECONDS = 5.0        # per-send: never fires (trickle progresses)
        api.ATTACH_WRITE_DEADLINE_SECONDS = 2.0  # total: this is what must bite
        start = time.monotonic()
        with pytest.raises(RuntimeError, match="after the stream opened.*partial task"):
            api.attach_stdin("ns", "pod", "agent", b"z" * (8 * 1024 * 1024))
        elapsed = time.monotonic() - start
        assert elapsed < 4 * api.ATTACH_WRITE_DEADLINE_SECONDS, f"took {elapsed:.1f}s"
    finally:
        server.close()


def test_a_timed_out_attach_write_is_fatal_not_retried(monkeypatch):
    """A WebSocketTimeoutException on write (peer upgraded then never read) is
    the fatal post-handshake failure: it must roll the launch back, not retry
    into a closed stdinOnce stream."""
    import websocket
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi
    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)

    class _WS:
        def write_stdin(self, text):
            raise websocket.WebSocketTimeoutException("write timed out")
        def close(self): pass

    opens = {"n": 0}
    def one_open(*a, **k):
        opens["n"] += 1
        return _WS()
    monkeypatch.setattr(api, "_open_attach_stream", one_open)
    with pytest.raises(RuntimeError, match="after the stream opened.*partial task"):
        api.attach_stdin("ns", "pod", "agent", b"data")
    assert opens["n"] == 1   # not retried


def test_the_bytes_are_delivered_verbatim_never_through_the_resolver():
    """The payload names the bearer reference. It must arrive as those
    characters: the controller has no bearer to substitute (it never holds it),
    and the init container that does hold it writes input on a path that
    does not render."""
    api = _launch(_spec("file"))
    [attach] = [e for e in api.events if e[0] == "attach"]
    assert attach[3] == PAYLOAD
    assert b"${services.tools.mcp_headers.Authorization}" in attach[3]


def test_a_target_that_never_runs_fails_the_launch_by_name_and_rolls_back():
    api = DeliveringApi()
    api.running = False
    with pytest.raises(RuntimeError, match="materialize-config.*not running.*input not delivered"):
        _launch(_spec("file"), api)
    assert not any(e[0] == "attach" for e in api.events)
    assert api.deleted, "the generation was not rolled back"
    assert api.leases == {}, "the singleton claim was not released"


def test_a_failed_attach_fails_the_launch_and_rolls_back():
    api = DeliveringApi()
    api.attach_error = RuntimeError("attach refused")
    # The controller re-raises the cause itself once rollback succeeds (the
    # "launch failed" wrapper only appears when proxy logs were captured).
    with pytest.raises(RuntimeError, match="attach refused"):
        _launch(_spec("stdin"), api)
    assert api.deleted and api.leases == {}


def test_no_delivery_mode_means_no_wait_and_no_attach():
    api = _launch(_spec("", payload=b"", max_bytes=0))
    assert not any(e[0] in ("wait", "attach") for e in api.events)


def test_the_controller_binds_run_input_path_for_file_mode():
    """Regression: _bind_exec_configuration built RunFacts WITHOUT input_path,
    so ${run.input_path} in a declared template resolved empty and the init
    container failed the launch. The Pod-builder tests could not catch it --
    they never run the controller's late-binding step. Caught live first; this
    is the unit that would have caught it, asserting the resolved facts the
    init container is handed.
    """
    files = (ConfigFile(path="${workspace.home}/.cfg",
                        template="in: ${run.input_path}"),)
    spec = _spec("file", files=files)
    api = _launch(spec)
    applied_agent = next(item for item in reversed(api.applied)
                         if item["kind"] == "Pod"
                         and item["metadata"]["labels"]["app.kubernetes.io/component"] == "agent")
    init = _config_init(applied_agent["spec"])
    facts_env = next(e for e in init["env"] if e["name"] == execconfig.FACTS_ENV)
    facts = json.loads(facts_env["value"])
    assert facts["run.input_path"] == execconfig.INPUT_PATH
    # And it resolves: rebuilt from the env, the reference becomes the path.
    import os
    os.environ[execconfig.FACTS_ENV] = facts_env["value"]
    try:
        rebuilt = execconfig.facts_from_environment()
        assert execconfig.resolve("run.input_path", rebuilt, where="probe") == \
            execconfig.INPUT_PATH
    finally:
        del os.environ[execconfig.FACTS_ENV]


def test_non_file_modes_leave_run_input_path_empty_and_failing_closed():
    """stdin/argv/none must NOT bind a run.input_path: nothing writes that file.

    The spec DECLARES A FILE so an init container is actually emitted -- without
    one the assertion had nothing to run against and could not fail (the defect
    R's test-quality lens found). A benign template (no ${run.input_path}, which
    the parser refuses under these modes anyway) forces the init container."""
    files = (ConfigFile(path="${workspace.home}/.cfg", template="k: v"),)
    for mode in ("stdin", "argv"):
        spec = (_spec(mode, files=files) if mode != "argv" else dataclasses.replace(
            _spec("stdin", files=files), exec_input_mode="", exec_input=b"",
            exec_input_max_bytes=0, agent_args=(*COMMAND, "the-arg")))
        api = _launch(spec)
        applied_agent = next(item for item in reversed(api.applied)
                             if item["kind"] == "Pod"
                             and item["metadata"]["labels"]["app.kubernetes.io/component"] == "agent")
        init = _config_init(applied_agent["spec"])    # exactly one, and it exists
        facts_env = next(e for e in init["env"] if e["name"] == execconfig.FACTS_ENV)
        assert json.loads(facts_env["value"])["run.input_path"] == ""


def test_attach_retries_the_handshake_but_a_write_failure_is_fatal(monkeypatch):
    """stdinOnce makes the write one-shot: a handshake refused at the Running
    edge is safe to retry (nothing sent), but a write that fails after the
    stream opened may have delivered a partial task, so it must be fatal and let
    the launch roll back rather than retry into a false success."""
    from andyur.daemon.kubernetes_api import OfficialKubernetesApi

    api = OfficialKubernetesApi.__new__(OfficialKubernetesApi)

    class _WS:
        def __init__(self, fail_write=False):
            self.fail_write = fail_write
            self.written = None
            self.closed = False
        def write_stdin(self, text):
            if self.fail_write:
                raise ConnectionResetError("peer reset mid-write")
            self.written = text
        def close(self):
            self.closed = True

    # (a) two handshake failures then success: retried, payload delivered whole.
    calls = {"n": 0}
    good = _WS()
    def flaky_handshake(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("attach endpoint not ready")
        return good
    monkeypatch.setattr(api, "_open_attach_stream", flaky_handshake)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    api.attach_stdin("ns", "pod", "agent", b"the-whole-task")
    assert calls["n"] == 3 and good.written == b"the-whole-task" and good.closed

    # (b) handshake succeeds, write fails: FATAL, not retried, stream closed.
    bad = _WS(fail_write=True)
    hs = {"n": 0}
    def one_handshake(*a, **k):
        hs["n"] += 1
        return bad
    monkeypatch.setattr(api, "_open_attach_stream", one_handshake)
    with pytest.raises(RuntimeError, match="after the stream opened.*partial task"):
        api.attach_stdin("ns", "pod", "agent", b"half")
    assert hs["n"] == 1, "a post-handshake write failure must NOT be retried"
    assert bad.closed, "the stream must still be closed on the fatal path"


# --------------------------------------------------------------------------
# The launcher: what each mode turns the sealed input into, fail-closed
# --------------------------------------------------------------------------

def _runtime(mode: str, max_bytes: int = 1024) -> RuntimeResolution:
    return RuntimeResolution(
        runtime_type="container", interface_version=RUNTIME_PROTOCOL_EXEC_V1,
        manifest_digest=DIGEST, image_ref="ghcr.io/x/tool", image_digest=DIGEST,
        command=COMMAND, process=ProcessSpec(input_mode=mode, input_max_bytes=max_bytes))


def _run(run_input) -> RunSpec:
    return RunSpec(run_id="run-one", agent="stock", run_input=run_input)


def test_stdin_and_file_hand_the_controller_the_delivery_bytes():
    for mode in ("stdin", "file"):
        args, delivery, payload, bound = _exec_input_delivery(_run(MARKER), _runtime(mode, 900))
        assert args == COMMAND                     # the command is untouched
        assert (delivery, payload, bound) == (mode, PAYLOAD, 900)


def test_argv_appends_the_input_as_one_last_argument():
    args, delivery, payload, bound = _exec_input_delivery(_run(MARKER), _runtime("argv"))
    assert args == (*COMMAND, MARKER)
    assert (delivery, payload, bound) == ("", b"", 0)
    # A JSON string is delivered as its TEXT, in argv as everywhere else.
    args, *_ = _exec_input_delivery(_run('"fix the flaky test"'), _runtime("argv"))
    assert args[-1] == "fix the flaky test"


def test_mode_none_delivers_nothing_and_takes_nothing():
    assert _exec_input_delivery(_run(None), _runtime("none")) == (COMMAND, "", b"", 0)
    with pytest.raises(config.InsecureProfile, match="mode 'none'"):
        _exec_input_delivery(_run(MARKER), _runtime("none"))


@pytest.mark.parametrize("mode", ["stdin", "file", "argv"])
def test_an_input_taking_process_with_no_input_is_refused_at_the_worker_too(mode):
    """The door already refused this. The worker refuses it AGAIN because an
    assignment is untrusted input here, and the alternative is a Pod whose
    stdin nobody will ever write."""
    with pytest.raises(config.InsecureProfile, match="needs an input"):
        _exec_input_delivery(_run(None), _runtime(mode))


def test_over_the_manifest_bound_is_refused_at_the_worker():
    with pytest.raises(config.InsecureProfile, match="max_bytes at 16"):
        _exec_input_delivery(_run(MARKER), _runtime("stdin", 16))


def test_argv_has_a_linux_bound_that_stdin_does_not():
    big = '"' + "x" * (ARGV_MAX_BYTES + 1) + '"'
    with pytest.raises(config.InsecureProfile, match="MAX_ARG_STRLEN"):
        _exec_input_delivery(_run(big), _runtime("argv", 8 * 1024 * 1024))
    # positive control: the same bytes are deliverable by stdin
    _, delivery, payload, _ = _exec_input_delivery(_run(big), _runtime("stdin", 8 * 1024 * 1024))
    assert delivery == "stdin" and len(payload) == ARGV_MAX_BYTES + 1
    # and the door applies the identical rule through the same function
    with pytest.raises(InputRefused, match="MAX_ARG_STRLEN"):
        runinput.check_against_process(big, ProcessSpec("argv", 8 * 1024 * 1024), where="door")


def test_an_envelope_without_a_process_block_is_refused():
    runtime = dataclasses.replace(_runtime("stdin"), process=None)
    with pytest.raises(config.InsecureProfile, match="no process block"):
        _exec_input_delivery(_run(MARKER), runtime)


def test_the_worker_now_launches_exec_v1_and_the_flip_is_gated_on_M1():
    """Recorded on purpose, replacing the pre-flip refusal test: delivery,
    output capture, D3 completion and M1 are built, and LAUNCHABLE_PROTOCOLS
    admits exec/v1. The gate that keeps it there is
    test_kubernetes_controller.py::test_exec_v1_is_not_launchable_unless_M1_holds."""
    resolved = validate_runtime_envelope(encode_runtime(_runtime("stdin")))
    assert resolved.interface_version == "exec/v1"
    assert resolved.process.input_mode == "stdin"


# --------------------------------------------------------------------------
# The init container: persist VERBATIM, bounded, inside the scratch
# --------------------------------------------------------------------------

@pytest.fixture()
def scratch():
    """A directory under the platform's writable root, because containment is
    checked against WRITABLE_ROOTS and pytest's tmp_path is not under it."""
    path = pathlib.Path("/tmp") / f"andyur-test-{uuid.uuid4().hex[:8]}"
    yield path
    shutil.rmtree(path, ignore_errors=True)


def test_persist_input_writes_the_bytes_verbatim_and_private(scratch):
    target = scratch / "andyur" / "input"
    written = execconfig.persist_input(str(target), 1024, source=io.BytesIO(PAYLOAD))
    assert written == str(target)
    assert target.read_bytes() == PAYLOAD          # the ${...} survives intact
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert oct(target.parent.stat().st_mode & 0o777) == "0o700"


def test_persist_input_refuses_a_short_stream_when_the_length_is_known(scratch):
    """FIX for the attach-retry/stdinOnce truncation window: given the exact
    attached length, a stream that arrives short is refused, not written as a
    silently truncated task."""
    import io
    target = scratch / "input"
    with pytest.raises(InputRefused, match="refusing to write a truncated task"):
        execconfig.persist_input(str(target), 1024,
                                 source=io.BytesIO(b"12345"), expect_len=8)
    assert not target.exists()
    # exact length is fine
    execconfig.persist_input(str(target), 1024,
                             source=io.BytesIO(b"12345678"), expect_len=8)
    assert target.read_bytes() == b"12345678"


def test_file_mode_init_container_carries_the_exact_expected_length(scratch):
    """The controller wires INPUT_LEN_ENV = len(exec_input) so the in-pod check
    can catch a short delivery."""
    files = (ConfigFile(path="${workspace.home}/.cfg", template="in: ${run.input_path}"),)
    spec = _spec("file", files=files)
    api = _launch(spec)
    applied = next(item for item in reversed(api.applied)
                   if item["kind"] == "Pod"
                   and item["metadata"]["labels"]["app.kubernetes.io/component"] == "agent")
    init = _config_init(applied["spec"])
    env = {e["name"]: e["value"] for e in init["env"] if "value" in e}
    assert env[execconfig.INPUT_LEN_ENV] == str(len(spec.exec_input))


def test_persist_input_refuses_a_stream_longer_than_the_bound(scratch):
    target = scratch / "input"
    with pytest.raises(InputRefused, match="max_bytes bound of 8"):
        execconfig.persist_input(str(target), 8, source=io.BytesIO(b"123456789"))
    assert not target.exists()
    # exactly at the bound is fine
    execconfig.persist_input(str(target), 8, source=io.BytesIO(b"12345678"))
    assert target.read_bytes() == b"12345678"


def test_persist_input_refuses_a_path_outside_the_writable_roots():
    with pytest.raises(UnresolvedReference, match="outside the platform's writable roots"):
        execconfig.persist_input("/etc/andyur-input", 8, source=io.BytesIO(b"x"))


def test_the_init_container_entrypoint_persists_input_without_templates(scratch, monkeypatch):
    """Mode 'file' with an env-only manifest: no templates mount, no facts
    needed, just the input. main() must not demand what it was not given."""
    target = scratch / "input"
    monkeypatch.setenv(execconfig.INPUT_PATH_ENV, str(target))
    monkeypatch.setenv(execconfig.INPUT_MAX_ENV, "1024")
    monkeypatch.delenv(execconfig.FACTS_ENV, raising=False)
    monkeypatch.setattr(execconfig, "TEMPLATES_MOUNT", str(scratch / "no-such-mount"))
    monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(PAYLOAD)})())
    assert execconfig.main() == 0
    assert target.read_bytes() == PAYLOAD


def test_input_path_is_a_public_fact_that_fails_closed_when_empty():
    facts = execconfig.RunFacts(
        run_id="r", deadline_epoch=1, model_base_url="http://m",
        model_openai_base_url="http://m/v1", model_name="m", mcp_url="http://t/mcp",
        workspace_home="/home/agent", workspace_tmp="/tmp")
    assert facts.public()["run.input_path"] == ""
    with pytest.raises(UnresolvedReference, match="empty value"):
        execconfig.resolve("run.input_path", facts, where="probe")
    with_path = dataclasses.replace(facts, input_path=execconfig.INPUT_PATH)
    assert execconfig.resolve("run.input_path", with_path, where="probe") == "/tmp/andyur/input"
    # and it round-trips through the init container's environment
    os.environ[execconfig.FACTS_ENV] = json.dumps(with_path.public())
    try:
        assert execconfig.facts_from_environment().input_path == execconfig.INPUT_PATH
    finally:
        del os.environ[execconfig.FACTS_ENV]


# --------------------------------------------------------------------------
# The assignment carries the sealed input to the worker
# --------------------------------------------------------------------------

client = TestClient(app)


def test_a_non_exec_v1_assignment_does_not_carry_input_inline(env):
    """S1: the inline assignment copy exists only for exec/v1, the sole reader.
    A native/runtime-v1 run re-fetches its input from the run record, so the
    heartbeat body must NOT carry a second (up to 8 MiB) copy for it."""
    env.agent("carried")
    run_id = client.post("/agents/carried/trigger",
                         json={"input": {"b": 1, "a": 2}}).json()["run_id"]
    beat = client.post("/worker/heartbeat",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w1", "slots": 2, "slots_free": 2,
                             "running": [], "profile": "dev"})
    assert beat.status_code == 200
    [mine] = [a for a in beat.json()["assignments"] if a["id"] == run_id]
    assert mine["input"] is None
    # ...but the run RECORD still serves it, which is where the runner reads it.
    tok = client.post(f"/runs/{run_id}/token").json()["run_token"]
    rec = client.get(f"/runs/{run_id}", headers={"X-Andyur-Run-Token": tok})
    assert rec.json()["input"] == '{"a":2,"b":1}'



def test_a_plain_wakeup_is_assigned_with_a_null_input(env):
    env.agent("plainrun")
    run_id = client.post("/agents/plainrun/trigger", json={}).json()["run_id"]
    beat = client.post("/worker/heartbeat",
                       headers=conftest.svid_header(conftest.WORKER_SVID),
                       json={"worker_id": "w2", "slots": 2, "slots_free": 2,
                             "running": [], "profile": "dev"})
    [mine] = [a for a in beat.json()["assignments"] if a["id"] == run_id]
    assert "input" in mine and mine["input"] is None


def test_run_spec_carries_the_input_to_the_launcher():
    assert RunSpec(run_id="r", agent="a").run_input is None
    assert RunSpec(run_id="r", agent="a", run_input='"t"').run_input == '"t"'

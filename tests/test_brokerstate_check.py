"""The health check that must not be able to take down what it monitors.

`brokerstate_server --check` imported the whole serving module to make one
request to a unix socket: 83 MiB and 0.54 s per invocation, run every two
seconds. The container was OOMKilled in a real cluster, and under load the
probe exceeded its own timeout so the kubelet killed a healthy process for
failing a liveness check that was slow only because of what the check cost.

These pin both halves: that it answers correctly, and that it stays cheap.
"""

import http.server
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from andyur.server import brokerstate_check


@pytest.fixture
def sockdir(tmp_path):
    """A SHORT directory. AF_UNIX paths are capped near 104 bytes on macOS and
    pytest's tmp_path is nowhere near short enough, so the socket lives under
    the shortest writable directory instead."""
    import shutil, tempfile
    d = tempfile.mkdtemp(prefix="bs", dir="/tmp")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


class _Ready(http.server.BaseHTTPRequestHandler):
    status = 200

    def do_GET(self):
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass


class _UnixServer(http.server.HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        socket.socket.bind(self.socket, self.server_address)


def _serve(path, status=200):
    handler = type("H", (_Ready,), {"status": status})
    server = _UnixServer(str(path), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_a_server_answering_200_is_healthy(sockdir):
    path = sockdir / "state.sock"
    server = _serve(path)
    try:
        assert brokerstate_check.check(str(path)) == 0
    finally:
        server.shutdown()


def test_a_server_answering_anything_else_is_not(sockdir):
    path = sockdir / "state.sock"
    server = _serve(path, status=503)
    try:
        assert brokerstate_check.check(str(path)) == 1
    finally:
        server.shutdown()


@pytest.mark.parametrize("path", ["", "relative/state.sock", "/nope/state.sock"])
def test_anything_that_is_not_a_reachable_socket_is_unhealthy(path):
    """Not answering IS the unhealthy state, and the kubelet reads one bit --
    so every failure gives the same answer rather than a taxonomy nothing
    consumes."""
    assert brokerstate_check.check(path) == 1


def test_a_server_that_never_answers_fails_INSIDE_the_timeout(sockdir):
    """The defect this file exists for: a probe that outlives its own timeout
    gets a HEALTHY process killed. A socket that accepts and says nothing must
    return, not hang."""
    path = sockdir / "silent.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    try:
        start = time.monotonic()
        assert brokerstate_check.check(str(path), timeout=0.3) == 1
        assert time.monotonic() - start < 2.0
    finally:
        listener.close()


def test_the_check_does_not_import_andyur_at_all():
    """THE PROPERTY, not the file size: this ran every two seconds and paid for
    FastAPI, the server app, httpx and OpenTelemetry each time. Asserted by
    running it in a fresh interpreter and asking what it loaded, so the cost
    cannot creep back in through a convenience import."""
    root = Path(__file__).resolve().parents[1]
    probe = (
        "import sys, runpy;\n"
        "sys.argv=['brokerstate_check'];\n"
        "import andyur.server.brokerstate_check as c;\n"
        "c.check('/nonexistent/x.sock');\n"
        "heavy=[m for m in sys.modules if m.split('.')[0] in "
        "{'fastapi','httpx','starlette','opentelemetry','uvicorn','pydantic'}];\n"
        "print(len(heavy), sorted(heavy)[:5])"
    )
    out = subprocess.run([sys.executable, "-c", probe], cwd=root,
                         capture_output=True, text=True, check=True).stdout
    assert out.startswith("0 "), f"the health check pulled in the application: {out}"


def test_the_manifest_probes_use_it():
    """A cheap check nothing runs is not a fix. Both probes on the
    broker-state container must be this module, and neither may go back to the
    module that imports the application."""
    manifest = (Path(__file__).resolve().parents[1]
                / "infra/kubernetes/control-plane.yaml").read_text()
    assert manifest.count('"andyur.server.brokerstate_check"') == 2
    assert "brokerstate_server\", \"--check\"" not in manifest


def test_a_status_line_that_arrives_in_two_pieces_is_still_healthy(sockdir):
    """THE SAME BUG A SECOND TIME, in the fix for the first one. `recv(64)`
    returns whatever is in the buffer, so a HEALTHY server whose status line
    crosses two writes -- which any server may do, and a loopback server does
    whenever it writes the status line and the headers separately -- came back
    partial, failed the `200` test, and was reported unhealthy. The liveness
    probe then kills a process for answering correctly.

    Reproduced against the single-recv version before this was written."""
    path = sockdir / "split.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        conn.recv(1024)
        conn.sendall(b"HTTP/1.1 2")
        time.sleep(0.05)
        conn.sendall(b"00 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        assert brokerstate_check.check(str(path), timeout=2.0) == 0
    finally:
        listener.close()
        thread.join(timeout=2)


def test_a_server_that_streams_without_a_newline_does_not_hang_the_probe(sockdir):
    """The bound that makes the loop safe: a peer answering with an endless
    newline-free stream must not make the probe read forever, because a probe
    that outlives its timeout is how the first version of this killed a healthy
    container."""
    path = sockdir / "endless.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    stop = threading.Event()

    def serve():
        conn, _ = listener.accept()
        conn.recv(1024)
        try:
            while not stop.is_set():
                conn.sendall(b"x" * 512)
        except OSError:
            pass
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        start = time.monotonic()
        assert brokerstate_check.check(str(path), timeout=1.0) == 1
        assert time.monotonic() - start < 3.0
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)

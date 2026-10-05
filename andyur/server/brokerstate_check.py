"""The broker-state health check, with nothing of the application in it.

WHY THIS IS ITS OWN MODULE. The check used to be `brokerstate_server --check`,
which imports the whole serving module -- FastAPI, the server app, httpx,
OpenTelemetry -- to make one request to a unix socket. Measured in the shipped
image: 83 MiB resident and 0.54 s per invocation, run every 2 seconds by the
readiness probe and every 5 by the liveness probe, inside a 256 MiB container
whose serving process was already using half of it.

The consequences were both kinds of wrong at once. The container was OOMKilled
in a real cluster, and under load the probe exceeded its own timeout, so the
kubelet killed a HEALTHY process for failing a liveness check that was only
slow because of what the check itself costs. A health check that can take down
what it monitors is not a health check.

So this speaks HTTP/1.0 to the socket with the standard library and nothing
else: ~10 MiB, a few milliseconds, no import of andyur at all. The protocol is
one request line and one status line, which is the whole of what "is it
answering?" requires -- and keeping it in Python rather than inlining a socket
one-liner into the manifest keeps that knowledge where it can be read and
tested.
"""

from __future__ import annotations

import os
import socket
import sys

TIMEOUT_SECONDS = 0.75
REQUEST = b"GET /ready HTTP/1.0\r\nHost: andyur-broker-state\r\nConnection: close\r\n\r\n"
# Enough for any status line, and a bound so a server that answers with a
# newline-free stream cannot make this read forever. "HTTP/1.1 200 OK\r\n" is 17.
MAX_STATUS_BYTES = 128


def _status_line(sock) -> bytes:
    """The response's first line, however many reads it takes to arrive.

    THIS WAS ONE `recv(64)`, AND THAT WAS THE SAME BUG AGAIN. A single recv
    returns whatever happens to be in the buffer, so a healthy server whose
    status line crosses two writes -- which any server is entitled to do, and
    which a loopback server does whenever it writes the status line and headers
    separately -- came back as a partial buffer, failed the `200` test, and was
    reported UNHEALTHY. The liveness probe then kills the process for
    answering correctly. Reproduced before it was fixed.

    Reading to EOF would make the probe's cost depend on the response body,
    which is what this module exists to avoid; reading to the first newline
    costs the status line and nothing more.
    """
    buffer = b""
    while len(buffer) < MAX_STATUS_BYTES:
        chunk = sock.recv(MAX_STATUS_BYTES - len(buffer))
        if not chunk:                      # the peer closed; take what we have
            break
        buffer += chunk
        if b"\n" in buffer:
            break
    return buffer.split(b"\n", 1)[0]


def check(path: str, timeout: float = TIMEOUT_SECONDS) -> int:
    """0 if the broker-state server answers 200 on its socket, else 1.

    Every failure is the same answer -- not answering IS the unhealthy state,
    and a probe that distinguished "refused" from "timed out" would still be
    read by the kubelet as one bit.
    """
    if not path.startswith("/"):
        return 1
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
        sock.sendall(REQUEST)
        status = _status_line(sock)
    except OSError:
        return 1
    finally:
        sock.close()
    return 0 if status.startswith(b"HTTP/1.") and b" 200 " in status else 1


def main() -> int:
    return check(os.environ.get("ANDYUR_BROKER_STATE_SOCKET", ""))


if __name__ == "__main__":
    sys.exit(main())

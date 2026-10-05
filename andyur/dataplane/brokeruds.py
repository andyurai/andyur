"""Private Unix-socket lifecycle for the per-run authorization broker.

The supervisor owns the parent directory and passes the already-built broker
application. This module owns only the local transport: it never constructs
authority, accepts a TCP fallback, or exposes a credential-producing API.
"""
from __future__ import annotations

import os
import errno
import socket
import stat
import threading
import time
import uuid
from pathlib import Path

import uvicorn

BROKER_DIRECTORY_MODE = 0o750
BROKER_SOCKET_MODE = 0o660
BROKER_START_TIMEOUT_SECONDS = 5.0


def _validate_parent(path: Path, expected_uid: int, expected_gid: int) -> None:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ValueError("broker socket path must be an absolute file path")
    parent = path.parent
    if parent.resolve(strict=True) != parent:
        raise ValueError("broker socket parent path must contain no symlinks")
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or parent.is_symlink():
        raise ValueError("broker socket parent must be a real directory")
    if (info.st_uid, info.st_gid) != (expected_uid, expected_gid):
        raise PermissionError("broker socket parent ownership does not match")
    if stat.S_IMODE(info.st_mode) not in {
            BROKER_DIRECTORY_MODE, stat.S_ISGID | BROKER_DIRECTORY_MODE}:
        raise PermissionError("broker socket parent mode must be 0750 or 2750")


def bind_private_broker_socket(
    socket_path: str | os.PathLike[str], *, expected_uid: int | None = None,
    expected_gid: int | None = None,
    adopt_stale: bool = False,
) -> tuple[socket.socket, tuple[int, int]]:
    """Bind and listen on a new private UDS, refusing stale/ambiguous paths.

    The caller must create the parent directory with the sealed sidecar uid/gid
    and mode 0750. Existing socket paths are never removed here: only the
    supervisor can prove the previous generation is dead before cleanup.
    """
    path = Path(socket_path)
    uid = os.getuid() if expected_uid is None else expected_uid
    gid = os.getgid() if expected_gid is None else expected_gid
    _validate_parent(path, uid, gid)
    if os.path.lexists(path):
        if not adopt_stale:
            raise FileExistsError("broker socket path already exists")
        _adopt_stale_socket(path, uid, gid)

    bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    created_identity: tuple[int, int] | None = None
    try:
        try:
            bound.bind(str(path))
            created = path.lstat()
            created_identity = (created.st_dev, created.st_ino)
        except OSError as exc:
            raise ValueError("broker socket path cannot be bound") from exc
        os.chown(path, uid, gid)
        os.chmod(path, BROKER_SOCKET_MODE)
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or (info.st_uid, info.st_gid) != (uid, gid) \
                or stat.S_IMODE(info.st_mode) != BROKER_SOCKET_MODE:
            raise PermissionError("broker socket security attributes do not match")
        bound.listen(socket.SOMAXCONN)
        return bound, (info.st_dev, info.st_ino)
    except BaseException:
        bound.close()
        try:
            current = path.lstat()
            if created_identity == (current.st_dev, current.st_ino) \
                    and stat.S_ISSOCK(current.st_mode):
                path.unlink()
        except (FileNotFoundError, OSError):
            pass
        raise


def _adopt_stale_socket(path: Path, expected_uid: int, expected_gid: int) -> None:
    """Remove only one exact, owned socket proven to have no live listener.

    On Linux an O_PATH descriptor pins the exact inode between the liveness
    check and quarantine rename. That closes the unlink/rebind inode-reuse race:
    a replacement pathname can never masquerade as the stale socket merely
    because the filesystem recycled its numeric inode. Platforms without O_PATH
    retain the original dev/inode check as a conservative fallback.
    """
    before = path.lstat()
    identity = (before.st_dev, before.st_ino)
    if not stat.S_ISSOCK(before.st_mode) \
            or (before.st_uid, before.st_gid) != (expected_uid, expected_gid) \
            or stat.S_IMODE(before.st_mode) != BROKER_SOCKET_MODE:
        raise PermissionError("stale broker socket attributes do not match")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        result = probe.connect_ex(str(path))
    finally:
        probe.close()
    if result == 0:
        raise FileExistsError("broker socket has a live listener")
    if result != errno.ECONNREFUSED:
        raise OSError(result, "broker socket liveness is ambiguous")

    pinned_fd: int | None = None
    if hasattr(os, "O_PATH"):
        flags = os.O_PATH | getattr(os, "O_NOFOLLOW", 0)
        pinned_fd = os.open(path, flags)
        pinned = os.fstat(pinned_fd)
        if (pinned.st_dev, pinned.st_ino) != identity:
            os.close(pinned_fd)
            raise RuntimeError("broker socket changed before stale quarantine")

    quarantine = path.with_name(f".{path.name}.stale-{uuid.uuid4().hex}")
    try:
        path.rename(quarantine)
        moved = quarantine.lstat()
        expected_identity = identity
        if pinned_fd is not None:
            pinned = os.fstat(pinned_fd)
            expected_identity = (pinned.st_dev, pinned.st_ino)
        if (moved.st_dev, moved.st_ino) != expected_identity \
                or not stat.S_ISSOCK(moved.st_mode) \
                or (moved.st_uid, moved.st_gid) != (expected_uid, expected_gid) \
                or stat.S_IMODE(moved.st_mode) != BROKER_SOCKET_MODE:
            raise RuntimeError(
                f"broker socket changed during stale adoption; quarantined at {quarantine}")
        quarantine.unlink()
    finally:
        if pinned_fd is not None:
            os.close(pinned_fd)


class BrokerUdsServer:
    """Bounded lifecycle wrapper around Uvicorn on one pre-bound private UDS."""

    def __init__(self, app, socket_path: str | os.PathLike[str], *,
                 expected_uid: int | None = None,
                 expected_gid: int | None = None,
                 limit_concurrency: int | None = None,
                 adopt_stale_socket: bool = False) -> None:
        if limit_concurrency is not None and limit_concurrency < 1:
            raise ValueError("UDS server concurrency limit must be positive")
        self._path = Path(socket_path)
        self._expected_uid = os.getuid() if expected_uid is None else expected_uid
        self._expected_gid = os.getgid() if expected_gid is None else expected_gid
        self._socket: socket.socket | None = None
        self._identity: tuple[int, int] | None = None
        self._adopt_stale_socket = adopt_stale_socket
        self._server = uvicorn.Server(uvicorn.Config(
            app, log_level="warning", lifespan="off",
            limit_concurrency=limit_concurrency))
        self._thread = threading.Thread(
            target=self._run, name="andyur-deny-broker-uds", daemon=True)

    def _run(self) -> None:
        assert self._socket is not None
        self._server.run(sockets=[self._socket])

    def start(self) -> None:
        if self._thread.is_alive() or self._socket is not None:
            raise RuntimeError("broker UDS server has already been started")
        self._socket, self._identity = bind_private_broker_socket(
            self._path, expected_uid=self._expected_uid,
            expected_gid=self._expected_gid,
            adopt_stale=self._adopt_stale_socket)
        self._thread.start()
        deadline = time.monotonic() + BROKER_START_TIMEOUT_SECONDS
        while not self._server.started and self._thread.is_alive() \
                and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self._server.started:
            self.stop()
            raise RuntimeError("broker UDS server did not start within its deadline")

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread.is_alive():
            self._thread.join(timeout=BROKER_START_TIMEOUT_SECONDS)
        if self._thread.is_alive():
            raise RuntimeError("broker UDS server did not stop within its deadline")
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        try:
            info = self._path.lstat()
            if self._identity == (info.st_dev, info.st_ino) \
                    and stat.S_ISSOCK(info.st_mode):
                self._path.unlink()
        except FileNotFoundError:
            pass

    def __enter__(self) -> "BrokerUdsServer":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

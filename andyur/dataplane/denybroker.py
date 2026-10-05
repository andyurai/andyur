"""Production process seam for the per-run deny-only authorization broker.

Envoy and SPIRE carry/enforce transport identity.  This module owns only the
Andyur-specific composition: freeze one authenticated control-plane snapshot,
compare every later snapshot to it, and serve the already-reviewed deny-only
ASGI app on a private Unix socket.  It has no exchange callable or credential
output type.
"""

from __future__ import annotations

import json
import os
import signal
import stat
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx
import grpc
from spiffe.workloadapi.errors import WorkloadApiError

from .. import identity
from .brokeruds import BrokerUdsServer
from .extauthz import SealedAuthorityEnvelope, build_deny_only_broker


STATE_SCHEMA = "andyur.deny-broker-state/v1"
MAX_STATE_BYTES = 64 * 1024
STATE_TIMEOUT_SECONDS = 0.2
STARTUP_TIMEOUT_SECONDS = 55.0
STARTUP_RETRY_SECONDS = 0.05


class TransientBrokerStartup(RuntimeError):
    """A local identity/transport dependency that may become ready shortly."""


def provision_socket_parent(
        socket_path: str, *, expected_uid: int | None = None,
        expected_gid: int | None = None) -> None:
    """Create or safely adopt the broker-owned child on a supervised volume."""
    parent = os.path.dirname(socket_path)
    uid = os.getuid() if expected_uid is None else expected_uid
    gid = os.getgid() if expected_gid is None else expected_gid
    try:
        os.mkdir(parent, 0o750)
    except FileExistsError:
        pass
    info = os.lstat(parent)
    # kubelet applies S_ISGID to fsGroup-managed directories.  It is safe and
    # required for the differently-uid'd Envoy sibling to inherit the sealed
    # broker group; no group/other write bit is accepted.
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) not in {
            0o750, 0o2750} or (info.st_uid, info.st_gid) != (uid, gid):
        raise RuntimeError("broker socket parent provisioning was not exact")


@dataclass(frozen=True)
class BrokerState:
    run_id: str
    agent: str
    live: bool
    expected_subject: str
    expected_actor: str
    registry_sha256: str
    audiences: tuple[str, ...]
    actions: tuple[str, ...] | None
    pin: dict[str, Any] | None

    @classmethod
    def parse(cls, raw: object) -> "BrokerState":
        if not isinstance(raw, dict) or set(raw) != {
            "schema", "run_id", "agent", "live", "expected_subject",
            "expected_actor", "registry_sha256", "audiences", "actions", "pin",
        } or raw["schema"] != STATE_SCHEMA:
            raise ValueError("broker state has an unknown or incomplete schema")
        audiences = raw["audiences"]
        actions = raw["actions"]
        pin = raw["pin"]
        if not isinstance(raw["live"], bool):
            raise ValueError("broker liveness must be boolean")
        if not isinstance(audiences, list) or len(audiences) != 1 \
                or any(not isinstance(item, str) or not item.strip()
                       for item in audiences):
            raise ValueError("deny-only broker requires exactly one sealed audience")
        if actions is not None and (not isinstance(actions, list)
                or any(not isinstance(item, str) for item in actions)):
            raise ValueError("broker state actions are malformed")
        if pin is not None and not isinstance(pin, dict):
            raise ValueError("broker state pin is malformed")
        state = cls(
            run_id=raw["run_id"], agent=raw["agent"], live=raw["live"],
            expected_subject=raw["expected_subject"],
            expected_actor=raw["expected_actor"],
            registry_sha256=raw["registry_sha256"],
            audiences=tuple(audiences),
            actions=(None if actions is None else tuple(sorted(actions))),
            pin=pin,
        )
        # Reuse the enforcement contract as the definitive shape validator.
        state.envelope()
        return state

    def envelope(self) -> SealedAuthorityEnvelope:
        pin_json = (None if self.pin is None else json.dumps(
            self.pin, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return SealedAuthorityEnvelope(
            agent=self.agent, run_id=self.run_id,
            expected_subject=self.expected_subject,
            expected_actor=self.expected_actor,
            audience=self.audiences[0], actions=self.actions,
            resource_pin_json=pin_json, registry_sha256=self.registry_sha256,
        )


class ControlPlaneState:
    """Fetch state only through the broker-owned local Envoy UDS."""

    def __init__(self, socket_path: str, run_id: str, broker_token: str) -> None:
        if not isinstance(socket_path, str) or not socket_path.startswith("/"):
            raise ValueError("broker state transport requires an absolute UDS path")
        if not run_id or not broker_token:
            raise ValueError("broker run identity and credential are required")
        self._socket_path = socket_path
        self._url = f"http://andyur-broker-state/runs/{run_id}/broker-state"
        self._run_id = run_id
        self._token = broker_token

    def fetch(self) -> BrokerState:
        deadline = time.monotonic() + STATE_TIMEOUT_SECONDS
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransientBrokerStartup(
                "broker state deadline expired before identity")
        try:
            identity_headers = identity.auth_header(timeout=remaining)
        except (TimeoutError, OSError, WorkloadApiError, grpc.RpcError) as exc:
            raise TransientBrokerStartup(
                "broker workload identity is not ready") from exc
        headers = {**identity_headers, identity.RUN_TOKEN_HEADER: self._token}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransientBrokerStartup(
                "broker state deadline expired after identity")
        body = bytearray()
        timeout = httpx.Timeout(remaining, connect=remaining,
                                read=remaining, write=remaining,
                                pool=remaining)
        transport = httpx.HTTPTransport(uds=self._socket_path)
        try:
            with httpx.Client(
                    timeout=timeout, trust_env=False, transport=transport) as client:
                with client.stream("GET", self._url, headers=headers) as response:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            "broker state deadline expired after headers")
                    if response.status_code in {502, 503, 504}:
                        raise TransientBrokerStartup(
                            f"broker state ingress is warming ({response.status_code})")
                    response.raise_for_status()
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            if int(declared) > MAX_STATE_BYTES:
                                raise ValueError(
                                    "broker state response exceeds 64 KiB")
                        except ValueError as exc:
                            if "exceeds" in str(exc):
                                raise
                            raise ValueError(
                                "broker state content length is malformed") from exc
                    for chunk in response.iter_bytes():
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "broker state exceeded its total deadline")
                        if len(body) + len(chunk) > MAX_STATE_BYTES:
                            raise ValueError("broker state response exceeds 64 KiB")
                        body.extend(chunk)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                httpx.WriteTimeout, httpx.PoolTimeout, httpx.ReadError,
                httpx.WriteError, httpx.RemoteProtocolError,
                TimeoutError) as exc:
            raise TransientBrokerStartup(
                "broker state transport is not ready") from exc
        try:
            raw = json.loads(body, parse_constant=lambda value: (
                (_ for _ in ()).throw(ValueError(f"non-finite JSON {value}"))))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("broker state is not valid JSON") from exc
        state = BrokerState.parse(raw)
        if state.run_id != self._run_id:
            raise ValueError("broker state run identity changed")
        return state


def build_state_bound_broker(fetch: Callable[[], BrokerState]):
    """Freeze one snapshot and compare one fresh atomic snapshot per request."""
    sealed = fetch()
    if not sealed.live:
        raise ValueError("deny-only broker cannot start for a terminal run")
    envelope = sealed.envelope()

    def atomic_state():
        state = fetch()
        return (
            state.live,
            (state.expected_subject, state.expected_actor),
            state.registry_sha256,
            {
                "audience": (envelope.audience
                             if envelope.audience in state.audiences else None),
                "actions": (None if state.actions is None
                            else list(state.actions)),
                "pin": state.pin,
            },
        )

    return build_deny_only_broker(
        envelope=envelope,
        state_fn=atomic_state,
    )


def build_state_bound_broker_after_transport_ready(
        fetch: Callable[[], BrokerState], stopping: threading.Event, *,
        timeout: float = STARTUP_TIMEOUT_SECONDS,
        retry_interval: float = STARTUP_RETRY_SECONDS):
    """Bound only the Envoy-UDS cold-start race; semantic errors fail once."""
    deadline = time.monotonic() + timeout
    while not stopping.is_set():
        try:
            return build_state_bound_broker(fetch)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError,
                httpx.WriteError, httpx.RemoteProtocolError,
                TransientBrokerStartup) as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    "broker state transport was unavailable at startup") from exc
            stopping.wait(min(retry_interval, remaining))
    return None


def main() -> None:
    if sys.argv[1:] == ["--check"]:
        socket_path = os.environ.get("ANDYUR_BROKER_SOCKET", "")
        if not socket_path.startswith("/"):
            raise SystemExit(1)
        try:
            with httpx.Client(
                transport=httpx.HTTPTransport(uds=socket_path),
                timeout=0.75, trust_env=False,
            ) as client:
                response = client.get("http://andyur-broker/ready")
            raise SystemExit(0 if response.status_code == 200 else 1)
        except httpx.HTTPError:
            raise SystemExit(1) from None
    if sys.argv[1:]:
        raise SystemExit("usage: python -m andyur.dataplane.denybroker [--check]")
    run_id = os.environ.get("ANDYUR_RUN_ID", "")
    token = os.environ.pop("ANDYUR_BROKER_TOKEN", "")
    stopping = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    state = ControlPlaneState(
        os.environ.get("ANDYUR_BROKER_STATE_SOCKET", ""), run_id, token)
    try:
        app = build_state_bound_broker_after_transport_ready(
            state.fetch, stopping)
    except (ValueError, httpx.HTTPStatusError) as exc:
        # Native sidecars restart every exit, including exit 0. A permanent
        # authority refusal therefore stays alive and unready until the
        # controller's bounded readiness rollback deletes the Pod; it does not
        # hammer SPIRE/control-plane in a restart loop.
        print(f"deny broker refused permanent startup state: {exc}",
              file=sys.stderr, flush=True)
        stopping.wait()
        return
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
    if app is None:
        return
    broker_socket = os.environ.get(
        "ANDYUR_BROKER_SOCKET", "/run/andyur-broker/authz.sock")
    if os.environ.get("ANDYUR_BROKER_PROVISION_PARENT", "off") == "on":
        try:
            provision_socket_parent(broker_socket)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from None
    server = BrokerUdsServer(
        app, broker_socket,
        adopt_stale_socket=(os.environ.get(
            "ANDYUR_BROKER_PROVISION_PARENT", "off") == "on"),
    )
    server.start()
    try:
        stopping.wait()
    finally:
        server.stop()


if __name__ == "__main__":
    main()

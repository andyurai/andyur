"""UDS-only backend for SPIRE-authenticated broker state.

The fronting control-plane Envoy terminates mTLS, removes caller-supplied XFCC,
and emits only the verified peer URI SAN.  This app is deliberately a separate
listener: the general HTTP API must never be able to confer trust on an XFCC
header supplied over the network.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
import httpx
import os
import signal
import sys
import threading
import time

from .. import identity
from . import app as server_app
from . import auth
from ..dataplane.brokeruds import BrokerUdsServer
from ..dataplane.denybroker import provision_socket_parent


app = FastAPI()
def _verified_peer(value: str | None) -> tuple[str, str]:
    if not isinstance(value, str) or not value or "," in value or '"' in value:
        raise HTTPException(401, "verified mTLS peer identity is required")
    fields: dict[str, str] = {}
    for part in value.split(";"):
        key, separator, item = part.partition("=")
        if separator != "=" or key not in {"By", "Hash", "URI"} \
                or not item or key in fields:
            raise HTTPException(401, "verified mTLS peer identity is malformed")
        fields[key] = item
    peer = fields.get("URI")
    if peer is None:
        raise HTTPException(401, "verified mTLS peer identity is malformed")
    agent, run = identity.parse_agent_run(peer)
    if not agent or not run:
        raise HTTPException(401, "verified mTLS peer identity is malformed")
    return agent, run


@app.get("/runs/{run_id}/broker-state")
def broker_state(
    run_id: str,
    ctx: auth.RunCtx = auth.require_broker_run(),
    x_forwarded_client_cert: str | None = Header(default=None),
) -> dict:
    """Bind the live TLS peer to the token, JWT-SVID and path before DB access."""
    peer_agent, peer_run = _verified_peer(x_forwarded_client_cert)
    if (peer_agent, peer_run) != (ctx.agent, ctx.run_id) or peer_run != run_id:
        raise HTTPException(403, "mTLS peer does not match the sealed run")
    return server_app.run_broker_state(run_id, ctx)


@app.get("/ready")
def ready() -> dict[str, bool]:
    return {"ok": True}


def main() -> None:
    """Run only on a supervisor-owned private UDS; there is no TCP mode."""
    path = os.environ.get("ANDYUR_BROKER_STATE_SOCKET", "")
    if not path.startswith("/"):
        raise SystemExit("ANDYUR_BROKER_STATE_SOCKET must be an absolute UDS path")
    if sys.argv[1:] == ["--check"]:
        try:
            with httpx.Client(
                transport=httpx.HTTPTransport(uds=path),
                timeout=0.75, trust_env=False,
            ) as client:
                response = client.get("http://andyur-broker-state/ready")
            raise SystemExit(0 if response.status_code == 200 else 1)
        except httpx.HTTPError:
            raise SystemExit(1) from None
    if sys.argv[1:]:
        raise SystemExit(
            "usage: python -m andyur.server.brokerstate_server [--check]")
    if os.environ.get("ANDYUR_BROKER_PROVISION_PARENT", "off") == "on":
        try:
            provision_socket_parent(
                path,
                expected_uid=int(os.environ.get(
                    "ANDYUR_BROKER_STATE_UID", os.getuid())),
                expected_gid=int(os.environ.get(
                    "ANDYUR_BROKER_STATE_GID", os.getgid())),
            )
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from None
    server = BrokerUdsServer(
        app, path,
        expected_uid=int(os.environ.get("ANDYUR_BROKER_STATE_UID", os.getuid())),
        expected_gid=int(os.environ.get("ANDYUR_BROKER_STATE_GID", os.getgid())),
        limit_concurrency=64,
        adopt_stale_socket=(os.environ.get(
            "ANDYUR_BROKER_PROVISION_PARENT", "off") == "on"),
    )
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    server.start()
    try:
        stopping.wait()
    finally:
        server.stop()


if __name__ == "__main__":
    main()

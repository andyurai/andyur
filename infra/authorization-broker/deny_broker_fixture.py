"""Static sealed-state fixture around the real deny-only broker and UDS server."""
from __future__ import annotations

import hashlib
import json
import os
import signal
import threading

from andyur.dataplane.brokeruds import BrokerUdsServer
from andyur.dataplane.extauthz import SealedAuthorityEnvelope, build_deny_only_broker

directory = "/authz"
trusted_gid = int(os.environ.get("ANDYUR_GATE_TRUSTED_GID", "1337"))
os.chown(directory, os.getuid(), trusted_gid)
os.chmod(directory, 0o750)
envelope = SealedAuthorityEnvelope(
    agent="scout", run_id="r1", expected_subject="alice",
    expected_actor="spiffe://andyur.local/agent/scout/run/r1",
    audience="resource:calendar", actions=("calendar:read",),
    resource_pin_json=None,
    registry_sha256=hashlib.sha256(b"registry-g1").hexdigest())

hang = threading.Event()


def observe(name, args):
    with open("/authz/observed", "a", encoding="utf-8") as evidence:
        evidence.write(json.dumps([name, *args], separators=(",", ":")) + "\n")


def liveness(*args):
    observe("liveness", args)
    if os.environ.get("ANDYUR_GATE_HANG") == "1":
        hang.wait()
    return True


def authority(*args):
    observe("authority", args)
    return {"audience": envelope.audience,
            "actions": list(envelope.actions), "pin": None}


inner_app = build_deny_only_broker(
    envelope=envelope, liveness_fn=liveness,
    identity_fn=lambda *args: observe("identity", args) or (
        envelope.expected_subject, envelope.expected_actor),
    registry_digest_fn=lambda *args: observe("registry", args) or
        envelope.registry_sha256,
    authority_fn=authority)


async def unconditional_denial(scope, receive, send):
    from starlette.responses import Response
    with open("/authz/bypass-observed", "a", encoding="utf-8") as evidence:
        evidence.write(scope.get("path", "") + "\n")
    await Response("fixture bypass", status_code=403)(scope, receive, send)


app = unconditional_denial if os.environ.get("ANDYUR_GATE_BYPASS") == "1" \
    else inner_app

stop = threading.Event()
for signum in (signal.SIGTERM, signal.SIGINT):
    signal.signal(signum, lambda *_: stop.set())

with BrokerUdsServer(app, "/authz/authz.sock", expected_gid=trusted_gid):
    print("deny-only broker ready", flush=True)
    stop.wait()
hang.set()

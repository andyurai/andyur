"""Delete only the namespace this gate created, enforced by API-server UID.

Compose with Kubernetes DeleteOptions rather than a read-then-delete ownership
check: a same-name replacement must be refused atomically at the consumer.
No production resources, shared credentials or cluster-wide RBAC are modified.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from pathlib import Path

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from andyur import otel

SERVICE = "andyur-action-gate"
log = logging.getLogger("andyur.action_gate")


def _failure_reason(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ValueError):
        return "invalid"
    if isinstance(exc, ApiException) and exc.status == 409:
        return "conflict"
    return "unavailable"


def _decision(reason: str) -> None:
    """Closed reasons only; SDK/log failure cannot change deletion authority."""
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        span.set_attribute("andyur.component", "action-gate")
        for field in ("RUN_ID", "AGENT_ID"):
            value = os.environ.get(f"ANDYUR_GATE_{field}")
            if value:
                span.set_attribute(f"andyur.{field.lower()}", otel.safe_attribute(value))
        span.add_event(
            "action_gate.cleanup.decided", {"andyur.cleanup_reason": reason})
        log.info("action_gate.cleanup %s", reason)
    except Exception:
        pass


# 30s was not enough on a Rancher Desktop cluster: the gate timed out, declared
# "owned namespace cleanup failed", and the EXIT trap's retry then logged
# "cleanup deleted" SEVEN SECONDS LATER -- so a successful teardown was recorded
# as a failed one and no evidence was written for a run that had passed. Namespace
# deletion waits on finalizers and pod termination, neither of which is bounded by
# anything this gate controls, so the limit is now generous and overridable rather
# than tuned to one machine.
_CLEANUP_TIMEOUT = float(os.environ.get("ANDYUR_ACTION_CLEANUP_TIMEOUT", "120"))


def delete_owned(core, namespace: str, uid: str, *, timeout: float = _CLEANUP_TIMEOUT) -> None:
    with otel.observe_dependency(SERVICE, "kubernetes", "cleanup", _failure_reason):
        try:
            reason = _delete_owned(core, namespace, uid, timeout=timeout)
        except Exception as exc:
            _decision(_failure_reason(exc))
            raise
        _decision(reason)


def _delete_owned(core, namespace: str, uid: str, *, timeout: float) -> str:
    if not re.fullmatch(r"andyur-action-[0-9a-f]{16}", namespace) or not uid:
        raise ValueError("unowned_namespace")
    try:
        core.delete_namespace(
            namespace,
            body=client.V1DeleteOptions(
                preconditions=client.V1Preconditions(uid=uid)),
            _request_timeout=5,
        )
    except ApiException as exc:
        if exc.status == 404:
            return "already_absent"
        raise
    deadline = time.monotonic() + timeout
    while True:
        try:
            current = core.read_namespace(namespace, _request_timeout=5)
        except ApiException as exc:
            if exc.status == 404:
                return "deleted"
            raise
        if current.metadata.uid != uid:
            # Our namespace has gone; do not touch a replacement.
            return "replacement_untouched"
        if time.monotonic() >= deadline:
            raise TimeoutError("owned_namespace_cleanup_timeout")
        time.sleep(0.25)


def main() -> int:
    from opentelemetry.context import attach, detach

    context, namespace, uid = sys.argv[1:]
    parent = otel.context_from(os.environ.get("ANDYUR_GATE_TRACEPARENT"))
    token = attach(parent) if parent is not None else None
    try:
        with otel.observe_dependency(SERVICE, "kubernetes", "readiness", _failure_reason):
            if context != "rancher-desktop":
                raise ValueError("unexpected_gate_context")
            config.load_kube_config(context=context)
        with client.ApiClient() as api:
            delete_owned(client.CoreV1Api(api), namespace, uid)
    except Exception:
        # observe_dependency records a closed reason, never vendor error text.
        return 1
    finally:
        if token is not None:
            detach(token)
        otel.shutdown_bounded(5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Vendor-neutral, secret-safe observability hooks for every Andyur process.

OpenTelemetry carries metrics and traces.  JSON on stdout carries logs to the
operator's chosen collector.  This module owns Andyur's stable vocabulary and
cardinality boundary; components must not construct exporter-specific clients.
"""

from __future__ import annotations

import json
import logging
import math
import numbers
import re
from datetime import UTC, datetime
from typing import Any

from . import actions, rollback

_METRICS = {
    "andyur.http.server.requests": "counter",
    "andyur.http.server.duration": "histogram",
    "andyur.http.server.in_flight": "up_down_counter",
    "andyur.run.outcomes": "counter",
    "andyur.dependency.calls": "counter",
    "andyur.dependency.duration": "histogram",
    "andyur.dependency.failures": "counter",
    "andyur.authorization.decisions": "counter",
    # An extension's authorization policy (andyur/extensions.py): what each
    # consultation came to, and how long somebody else's code took to say so.
    "andyur.extension_policy.decisions": "counter",
    "andyur.extension_policy.duration": "histogram",
    # exec/v1 (observability-exit-criteria.md 5): decisions per outcome and
    # reason at the two boundaries a stock workload crosses, the capped
    # resource, and the bounded waits the daemon's loop depends on
    "andyur.execfront.decisions": "counter",
    "andyur.execfront.request_bytes": "histogram",
    "andyur.mcp.decisions": "counter",
    "andyur.controller.wait_seconds": "histogram",
    "andyur.daemon.finish_seconds": "histogram",
    "andyur.daemon.finish_attempts": "counter",
    # Lane A (board rows 9-12): what Andyur decided about a requested
    # consequential action, and what the CLUSTER was then observed to do. Two
    # counters, not one, because "we decided to allow it" and "it happened" are
    # different facts and a platform that reports the first as the second is the
    # false-green family this repository has spent a week closing.
    "andyur.action.decisions": "counter",
    "andyur.action.results": "counter",
    "andyur.action.observation_seconds": "histogram",
}
_RECORD_SCHEMAS = {
    "andyur.run.outcomes": {"andyur.outcome", "andyur.operation"},
    "andyur.dependency.failures": {
        "andyur.dependency", "andyur.reason", "andyur.operation"},
    "andyur.dependency.calls": {
        "andyur.dependency", "andyur.operation", "andyur.outcome"},
    "andyur.dependency.duration": {
        "andyur.dependency", "andyur.operation", "andyur.outcome"},
    "andyur.authorization.decisions": {"andyur.outcome", "andyur.reason"},
    "andyur.extension_policy.decisions": {"andyur.outcome", "andyur.reason"},
    "andyur.extension_policy.duration": {"andyur.outcome"},
    "andyur.execfront.decisions": {"andyur.outcome", "andyur.refusal"},
    "andyur.execfront.request_bytes": set(),
    "andyur.mcp.decisions": {"andyur.outcome", "andyur.refusal"},
    "andyur.controller.wait_seconds": {"andyur.operation", "andyur.outcome"},
    "andyur.daemon.finish_seconds": {"andyur.operation", "andyur.outcome"},
    "andyur.daemon.finish_attempts": {"andyur.operation", "andyur.outcome"},
    "andyur.action.decisions": {"andyur.action_decision", "andyur.action_reason"},
    "andyur.action.results": {"andyur.action_result"},
    "andyur.action.observation_seconds": {"andyur.rollback_reason"},
}
_METRIC_ATTRIBUTES = {
    "service.name", "http.request.method", "http.response.status_code_class",
    "andyur.endpoint.class", "andyur.outcome", "andyur.reason",
    "andyur.dependency", "andyur.operation", "andyur.refusal",
    "andyur.action_decision", "andyur.action_reason", "andyur.action_result",
    "andyur.rollback_reason",
}
# ONE reason vocabulary for a refused exec/v1 request: the code the error body
# carries, the span attribute records, the log line names and the gate asserts
# (modelpolicy.REFUSAL_CODES is the source; mirrored here as a metric bound).
_REFUSALS = {
    "none", "path_refused", "path_not_model_call", "duplicate_model_key",
    "body_not_json", "model_missing", "model_key_variant", "model_not_granted",
    "no_model_granted", "body_too_large", "no_model_proxy", "upstream_unreachable",
    "bearer_rejected",
}
# THE CONSEQUENTIAL-ACTION VOCABULARY, taken from `andyur.actions` rather than
# copied. The contract says a decision reason "lands in observability.py's
# closed sets in the same change that emits it"; binding to the source module is
# how that stays true after the change, since a name added there without being
# admitted here would otherwise be a metric dimension nobody declared, and a
# name REMOVED there would leave a set describing a decision that no longer
# exists. The three sets a decider can emit; `decision` is already taken as a
# log field by the heartbeat's drain, so these are prefixed `action_`.
_ACTION_DECISIONS = frozenset(actions.DECISIONS)
_ACTION_REASONS = frozenset(actions.REASONS)
_ACTION_RESULTS = frozenset(actions.RESULTS)
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "OTHER"}
_STATUS_CLASSES = {"1xx", "2xx", "3xx", "4xx", "5xx", "unknown"}
_ENDPOINT_CLASSES = {"api", "health", "metrics", "unknown"}
_OUTCOMES = {"success", "failure", "denied", "cancelled", "timeout", "unknown"}
_REASONS = {
    "invalid", "unavailable", "timeout", "refused", "conflict", "exhausted",
    "cleanup", "readiness", "unknown",
}
_DEPENDENCIES = {
    "database", "object-store", "identity", "authorization-server", "pdp",
    "vault", "model", "tool", "kubernetes", "telemetry",
    # The control plane's HTTP API, as seen by something in front of it (the
    # console BFF). Without a name here, the one hop the operator's UI makes
    # had no dependency metric at all: "the console is slow" could not be
    # separated from "the control plane is slow".
    "control-plane",
}
_OPERATIONS = {
    "trigger", "claim", "heartbeat", "launch", "readiness", "exchange",
    "authorize", "fetch", "call", "finish", "cleanup",
    "attach", "rollback", "delete", "serve",
}
_EVENT_FIELDS = {
    "run.completed": {"outcome", "duration_ms"},
    "dependency.failed": {"dependency", "reason", "operation"},
    "authorization.decision": {"outcome", "reason"},
    "extension_policy.decision": {"outcome", "reason"},
    # One consequential action, in two events: what was decided about it, and
    # what the cluster was observed to do. Neither carries the target, the run
    # or the approver -- those are unbounded, and they are on the row an
    # operator reads over the API.
    "action.decided": {"action_decision", "action_reason"},
    "action.performed": {"action_result"},
    "action.observed": {"rollback_reason", "duration_ms"},
    # The console BFF's own refusals. Declared here rather than logged with an
    # ad-hoc `extra=`, so the field schema is checked in the same place as
    # every other event and a typo is a ValueError, not a silently missing
    # field in the operator's log. `reason` is the platform bucket, so an
    # operator can group console refusals with every other refusal;
    # `console_reason` is the exact word the console answered the browser with,
    # which is what makes a report actionable.
    "console.refuse": {"reason", "console_reason", "status", "method", "route"},
    "telemetry.export.failed": {"signal", "reason"},
    # The heartbeat's drain, which is the platform's self-healing path: work
    # handed to a busy agent is re-driven from here, so a drain that stops is
    # work that silently never runs. `decision` is the ATTRIBUTION reached (see
    # _DRAIN_DECISIONS) and `reason` the refusal bucket, so "why did this
    # workflow stop draining?" and "why is this run drawn as a root?" are both
    # answerable from the log without reading the code. The agent name and run
    # id are deliberately absent: they are unbounded, and they are on the span.
    "heartbeat.drain": {"outcome", "reason", "decision"},
}
# How a drained run was attributed to a workflow. Bounded and held here with
# every other log vocabulary, so a decision invented at a call site is a
# ValueError rather than a new log dimension nobody declared.
_DRAIN_DECISIONS = {
    "joined",           # the work agreed on one workflow AND one live parent
    "joined_rootless",  # one workflow, no parent all the work agrees on
    "fresh_workflow",   # the work spans workflows, so it belongs to none
    "none",             # refused before any attribution was reached
}
# The console BFF's refusal vocabulary, held HERE with every other bounded set
# rather than only in the console's own enum: the module that owns what may
# appear in a log is the module that lists it, and a console reason invented at
# a call site is then a ValueError rather than a new log dimension nobody
# declared. tests/test_console_bff.py pins these against the Reason enum, so
# adding one there without adding it here fails.
_CONSOLE_REASONS = {
    "cross_origin", "missing_host", "bad_host", "bad_session",
    "method_not_allowed", "bad_path", "not_a_console_route", "body_too_large",
    "client_disconnected", "launch_spent", "launch_unknown", "session_expired",
    "idp_error", "identity_unavailable", "upstream_unreachable",
    "upstream_protocol_error", "upstream_timeout", "upstream_too_large",
    "body_timeout",
}
_LOW_CARDINALITY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SENSITIVE = re.compile(
    r"(?:authorization|cookie|credential|password|secret|token|api[_-]?key|body|prompt|transcript)",
    re.IGNORECASE,
)
_LOG_FIELD = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def metric_attributes(**attributes: str) -> dict[str, str]:
    """Validate bounded metric dimensions; identifiers are deliberately absent."""
    clean: dict[str, str] = {}
    for key, value in attributes.items():
        key = key.replace("__", ".")
        if key not in _METRIC_ATTRIBUTES:
            raise ValueError(f"metric attribute {key!r} is not in the bounded vocabulary")
        value = str(value)
        if key == "http.request.method" and value not in _METHODS:
            raise ValueError("unbounded HTTP method metric attribute")
        if key == "http.response.status_code_class" and value not in _STATUS_CLASSES:
            raise ValueError("invalid HTTP status class metric attribute")
        if key == "andyur.endpoint.class" and value not in _ENDPOINT_CLASSES:
            raise ValueError("invalid endpoint class metric attribute")
        if key == "andyur.outcome" and value not in _OUTCOMES:
            raise ValueError("invalid outcome metric attribute")
        bounded = {"andyur.reason": _REASONS, "andyur.dependency": _DEPENDENCIES,
                   "andyur.operation": _OPERATIONS, "andyur.refusal": _REFUSALS,
                   "andyur.action_decision": _ACTION_DECISIONS,
                   "andyur.action_reason": _ACTION_REASONS,
                   "andyur.action_result": _ACTION_RESULTS,
                   "andyur.rollback_reason": rollback.REASONS}
        if key in bounded and value not in bounded[key]:
            raise ValueError(f"metric attribute {key!r} is not low-cardinality")
        if key == "service.name" and not _LOW_CARDINALITY.fullmatch(value):
            raise ValueError("invalid service name metric attribute")
        clean[key] = value
    return clean


def instrument_kind(name: str) -> str:
    try:
        return _METRICS[name]
    except KeyError as exc:
        raise ValueError(f"metric {name!r} is not in the stable vocabulary") from exc


def validate_record(name: str, value: int | float,
                    attributes: dict[str, str]) -> None:
    """Require an actionable dimension set and a valid instrument value."""
    kind = instrument_kind(name)
    if isinstance(value, bool) or not isinstance(value, numbers.Real) \
            or not math.isfinite(value):
        raise ValueError("metric value must be a finite real number")
    if kind in {"counter", "histogram"} and value < 0:
        raise ValueError(f"{kind} values must be non-negative")
    required = _RECORD_SCHEMAS.get(name)
    if required is not None and set(attributes) != set(required):
        raise ValueError(f"metric {name!r} requires attributes {sorted(required)}")


def _trace_fields() -> dict[str, str]:
    try:
        from opentelemetry import trace
        context = trace.get_current_span().get_span_context()
        if not context.is_valid:
            return {}
        return {
            "trace_id": format(context.trace_id, "032x"),
            "span_id": format(context.span_id, "016x"),
        }
    except Exception:
        return {}


class JsonFormatter(logging.Formatter):
    """Stable stdout envelope; arbitrary LogRecord internals are not serialized."""

    def __init__(self, service_name: str) -> None:
        super().__init__()
        if not _LOW_CARDINALITY.fullmatch(service_name):
            raise ValueError("invalid telemetry service name")
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        # Redaction is a property of the BOUNDARY: every message that leaves
        # through this formatter is scrubbed here, whichever logger wrote it
        # (the MCP SDK's warning carrying a caller-chosen tool name included).
        from .redact import redact
        try:
            message = record.getMessage()
        except Exception:                                  # a bad format string
            message = str(record.msg)
        envelope: dict[str, Any] = {
            "schema": "andyur.log.v1",
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "severity": record.levelname,
            "service": self.service_name,
            "logger": record.name,
            "event": getattr(record, "event_name", "log.message"),
            "message": getattr(record, "event_name", None) or redact(message[:4096]),
            **_trace_fields(),
        }
        fields = getattr(record, "event_fields", None)
        if fields:
            envelope["fields"] = fields
        if record.exc_info:
            envelope["exception_type"] = record.exc_info[0].__name__
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True,
                          allow_nan=False)


def configure_logging(service_name: str, *, level: int = logging.INFO,
                      stream=None, root: bool = False) -> logging.Logger:
    """Install one JSON stdout handler unless the operator already configured one.

    ``root=True`` puts the handler on the ROOT logger: a run-path process (the
    sidecar, the daemon) then emits every library's log line through the
    same redacting envelope, and nothing reaches Python's lastResort stderr
    handler unredacted (R MED-2 on PR #25: the MCP SDK's warning echoed a
    caller-chosen tool name verbatim).
    """
    logger = logging.getLogger("andyur")
    target = logging.getLogger() if root else logger
    if not logger.handlers and not logging.getLogger().handlers:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonFormatter(service_name))
        target.addHandler(handler)
        if root:
            target.setLevel(level)
    logger.setLevel(level)
    return logger


def event(logger: logging.Logger, event_name: str, *, level: int = logging.INFO,
          **fields: Any) -> None:
    """Emit one declared low-cardinality event with an exact field schema."""
    if event_name not in _EVENT_FIELDS:
        raise ValueError("unknown event name")
    if set(fields) != _EVENT_FIELDS[event_name]:
        raise ValueError(f"event {event_name!r} requires fields "
                         f"{sorted(_EVENT_FIELDS[event_name])}")
    safe: dict[str, Any] = {}
    for key, value in fields.items():
        if not _LOG_FIELD.fullmatch(key) or _SENSITIVE.search(key):
            raise ValueError(f"unsafe structured log field {key!r}")
        if not isinstance(value, (str, int, float, bool, type(None))):
            raise TypeError(f"structured log field {key!r} must be scalar")
        if isinstance(value, str) and len(value) > 256:
            raise ValueError(f"structured log field {key!r} exceeds 256 characters")
        if key == "outcome" and value not in _OUTCOMES:
            raise ValueError("invalid event outcome")
        if key == "reason" and value not in _REASONS:
            raise ValueError("invalid event reason")
        if key == "decision" and value not in _DRAIN_DECISIONS:
            raise ValueError("invalid drain decision")
        if key == "console_reason" and value not in _CONSOLE_REASONS:
            raise ValueError("invalid console reason")
        if key == "action_decision" and value not in _ACTION_DECISIONS:
            raise ValueError("invalid consequential-action decision")
        if key == "action_reason" and value not in _ACTION_REASONS:
            raise ValueError("invalid consequential-action decision reason")
        if key == "action_result" and value not in _ACTION_RESULTS:
            raise ValueError("invalid consequential-action result")
        if key == "rollback_reason" and value not in rollback.REASONS:
            raise ValueError("invalid rollback observation reason")
        if key == "dependency" and value not in _DEPENDENCIES:
            raise ValueError("invalid event dependency")
        if key == "operation" and value not in _OPERATIONS:
            raise ValueError("invalid event operation")
        if key == "signal" and value not in {"traces", "metrics", "logs"}:
            raise ValueError("invalid telemetry signal")
        if key == "duration_ms" and (
                isinstance(value, bool) or not isinstance(value, numbers.Real)
                or not math.isfinite(value) or value < 0):
            raise ValueError("invalid event duration")
        safe[key] = value
    logger.log(level, event_name, extra={
        "event_name": event_name, "event_fields": safe,
    })

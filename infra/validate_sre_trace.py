#!/usr/bin/env python3
"""Validate that a Jaeger response contains the real cross-process SRE trace."""

import json
from pathlib import Path
import sys
import time
from urllib.request import urlopen


def validate(path: Path, trace_id: str, expected_model: str | None = None,
             require_litellm: bool = False) -> None:
    envelope = json.loads(path.read_text())
    traces = envelope.get("data") or []
    trace = next((item for item in traces if item.get("traceID") == trace_id), None)
    if trace is None:
        raise ValueError(f"Jaeger response contains no trace {trace_id}")
    processes = trace.get("processes", {})
    services = {p.get("serviceName") for p in processes.values()}
    # This container-attestation verifier intentionally launches its assigned
    # runner directly; the normal `run.sh up` path additionally has a daemon.
    required_services = {
        "andyur-server", "andyur-runner", "andyur-sidecar",
        "sre-observability", "sre-tickets",
    }
    if not required_services <= services:
        raise ValueError(f"trace services {services} omit {required_services - services}")
    if require_litellm and "andyur-litellm" not in services:
        raise ValueError("API trace contains no andyur-litellm service")
    operations = {span.get("operationName") for span in trace.get("spans", [])}
    required = {
        "run sre-oncall", "runner sre-oncall", "runner.prepare", "runner.prompt",
        "runner.execute", "llm.request", "llm.response", "runner.process",
        "runner.finalize",
    }
    if not required <= operations:
        raise ValueError(f"trace omits phases {required - operations}")
    if not any(str(op).startswith("tool:obs/") for op in operations):
        raise ValueError("trace contains no observability tool span")
    if "tool:tickets/comment" not in operations:
        raise ValueError("trace contains no ticket-comment span")
    owned = {}
    for span in trace.get("spans", []):
        service = processes.get(span.get("processID"), {}).get("serviceName")
        owned.setdefault(service, set()).add(span.get("operationName"))
    server_required = {"run sre-oncall", "server.start_run", "server.finish_run"}
    runner_required = required - {"run sre-oncall"}
    if not server_required <= owned.get("andyur-server", set()):
        raise ValueError("server process does not own its required run spans")
    if not runner_required <= owned.get("andyur-runner", set()):
        raise ValueError("runner process does not own its required phase spans")
    if require_litellm and "litellm_request" not in owned.get(
            "andyur-litellm", set()):
        raise ValueError("andyur-litellm does not own a litellm_request span")
    sidecar_ops = owned.get("andyur-sidecar", set())
    if not {"tool.request obs", "tool.request tickets"} <= sidecar_ops:
        raise ValueError("andyur-sidecar does not own both outbound tool spans")
    if "mcp.request POST" not in owned.get("sre-observability", set()):
        raise ValueError("sre-observability does not own an inbound MCP span")
    if "mcp.request POST" not in owned.get("sre-tickets", set()):
        raise ValueError("sre-tickets does not own an inbound MCP span")
    by_id = {span.get("spanID"): span for span in trace.get("spans", [])
             if span.get("spanID")}

    def parent_service(span):
        parent_id = next((ref.get("spanID") for ref in span.get("references", [])
                          if ref.get("refType") == "CHILD_OF"), None)
        parent = by_id.get(parent_id)
        return (processes.get(parent.get("processID"), {}).get("serviceName")
                if parent else None)

    linked_resources = {
        processes.get(span.get("processID"), {}).get("serviceName")
        for span in trace.get("spans", [])
        if span.get("operationName") == "mcp.request POST"
        and parent_service(span) == "andyur-sidecar"
    }
    required_links = {"sre-observability", "sre-tickets"}
    if not required_links <= linked_resources:
        raise ValueError(
            "enterprise MCP spans are not children of the sidecar calls: "
            f"missing {required_links - linked_resources}")
    if expected_model is not None:
        execute = [span for span in trace.get("spans", [])
                   if span.get("operationName") == "runner.execute"
                   and processes.get(span.get("processID"), {}).get("serviceName")
                   == "andyur-runner"]
        models = {tag.get("value") for span in execute for tag in span.get("tags", [])
                  if tag.get("key") == "andyur.model"}
        if models != {expected_model}:
            raise ValueError(
                f"runner model telemetry {models} does not match manifest {expected_model}")


def wait_for_trace(url: str, path: Path, trace_id: str, *, attempts: int = 20,
                   pause: float = 1.0, fetch=None,
                   expected_model: str | None = None,
                   require_litellm: bool = False) -> None:
    """Poll until Jaeger contains the complete expected distributed trace."""
    fetch = fetch or (lambda target: urlopen(target, timeout=5).read())
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            path.write_bytes(fetch(url))
            validate(path, trace_id, expected_model, require_litellm)
            return
        except Exception as exc:  # readiness, ingest, and indexing are eventual
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(pause)
    raise RuntimeError(f"trace {trace_id} incomplete after {attempts} attempts") from last_error


if __name__ == "__main__":
    import os
    require_litellm = os.environ.get("ANDYUR_TRACE_REQUIRE_LITELLM") == "1"
    if len(sys.argv) in (5, 6) and sys.argv[1] == "--wait":
        wait_for_trace(sys.argv[2], Path(sys.argv[3]), sys.argv[4],
                       expected_model=sys.argv[5] if len(sys.argv) == 6 else None,
                       require_litellm=require_litellm)
    else:
        validate(Path(sys.argv[1]), sys.argv[2],
                 sys.argv[3] if len(sys.argv) == 4 else None,
                 require_litellm=require_litellm)

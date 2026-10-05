"""Read one trace back from Jaeger v2 by trace id -- the gates' shared helper.

Every gate that claims "the run produced a trace" proves it the same way: it
takes the run's `trace_ctx` (the W3C traceparent the server stored on the run
record), extracts the trace id, and fetches that trace over Jaeger's v3 query
API -- `GET /api/v3/traces/{traceId}`, the documented OTLP-shaped API -- never
the UI and never the legacy `/api/traces` (documented as undocumented and
subject to change). A trace that is not there after the wait is a FAILURE the
gate reports by name (`trace_not_found`), not a skipped check.

Usable as a module (`fetch_trace`, `summarize`) and as a script that prints
one JSON summary line; the script form is what a shell gate pipes into
`kubectl exec -i ... python -` so the module never has to live in an image:

    python3 trace_readback.py http://andyur-jaeger:16686 <trace_id> [--wait 30] [--expect a,b,c]

Delivery is batched three times over (the process's BatchSpanProcessor, the
Collector's batch, Jaeger's batch), so the FIRST spans of a trace arrive
before the LAST -- a read taken at first sight is incomplete (PR #24: a run
read back as 5 spans that was 8 minutes later). `--expect` names the spans
the caller requires; the wait continues until all are present or the bound
expires, and the summary says which were missing (`expected_missing`).

Exit 0 with the summary on stdout (with `expected_present` when --expect was
given -- the CALLER decides whether missing spans fail it); exit 2 with
`{"error": "trace_not_found"}` when the trace never appeared; any other
failure raises.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

V3_TRACE_PATH = "/api/v3/traces/{trace_id}"


def trace_id_from_traceparent(traceparent: str) -> str:
    """`00-<trace-id>-<span-id>-<flags>` -> `<trace-id>`; anything else is refused."""
    parts = (traceparent or "").strip().split("-")
    if len(parts) != 4 or len(parts[1]) != 32 or set(parts[1]) - set("0123456789abcdef"):
        raise ValueError(f"not a W3C traceparent: {traceparent!r}")
    return parts[1]


def fetch_trace(base_url: str, trace_id: str, *, timeout: float = 10.0) -> dict | None:
    """The trace as OTLP JSON (`{"resourceSpans": [...]}`), or None when 404.

    The v3 HTTP API wraps the TracesData message in a `result` envelope; that
    wrapper is removed here so callers see the OTLP shape only.
    """
    url = base_url.rstrip("/") + V3_TRACE_PATH.format(trace_id=trace_id)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RuntimeError(f"jaeger query {url} -> HTTP {exc.code}") from exc
    if isinstance(body, dict) and "result" in body:
        body = body["result"]
    if not isinstance(body, dict) or "resourceSpans" not in body:
        raise RuntimeError(f"jaeger query {url} returned no TracesData: {str(body)[:200]}")
    if not body["resourceSpans"]:
        return None
    return body


def _value(node: dict):
    for key in ("stringValue", "intValue", "boolValue", "doubleValue"):
        if key in node:
            value = node[key]
            return int(value) if key == "intValue" else value
    if "arrayValue" in node:
        return [_value(v) for v in node["arrayValue"].get("values", [])]
    return None


def _attributes(items: list) -> dict:
    return {a["key"]: _value(a.get("value", {})) for a in items or []}


def spans(trace: dict) -> list[dict]:
    """Flat span records: name, service, span/parent ids, attributes, status."""
    out = []
    for resource in trace.get("resourceSpans", []):
        service = _attributes(resource.get("resource", {}).get("attributes")).get("service.name")
        for scope in resource.get("scopeSpans", []):
            for span in scope.get("spans", []):
                out.append({
                    "name": span.get("name"), "service": service,
                    "span_id": span.get("spanId"), "parent_span_id": span.get("parentSpanId") or None,
                    "kind": span.get("kind"), "attributes": _attributes(span.get("attributes")),
                    "status": (span.get("status") or {}).get("code"),
                })
    return out


def summarize(trace_id: str, trace: dict) -> dict:
    records = spans(trace)
    return {
        "trace_id": trace_id,
        "span_count": len(records),
        "span_names": sorted({r["name"] for r in records if r["name"]}),
        "services": sorted({r["service"] for r in records if r["service"]}),
        "root_spans": sorted(r["name"] for r in records if not r["parent_span_id"]),
        # spans whose parent is NOT in this read: a late or lost ancestor shows
        # here by name (R MED-3 on PR #24) instead of hiding as a child
        "dangling_parent_spans": sorted(
            r["name"] for r in records
            if r["parent_span_id"] and r["parent_span_id"] not in {x["span_id"] for x in records}),
        "spans": [{"name": r["name"], "service": r["service"],
                   "attributes": {k: v for k, v in r["attributes"].items()
                                  if k.startswith(("andyur.", "gen_ai.", "http.", "andyur_"))}}
                  for r in records],
    }


def missing_names(trace: dict | None, expected: list[str]) -> list[str]:
    present = {r["name"] for r in spans(trace)} if trace else set()
    return [name for name in expected if name not in present]


def wait_for_trace(base_url: str, trace_id: str, *, wait: float, poll: float = 2.0,
                   expected: list[str] | None = None) -> dict | None:
    """Poll until the trace holds every EXPECTED span name (or, with no
    expectation, until it exists) or `wait` runs out; returns the last read."""
    deadline = time.monotonic() + wait
    while True:
        trace = fetch_trace(base_url, trace_id)
        complete = trace is not None and not missing_names(trace, expected or [])
        if complete or time.monotonic() >= deadline:
            return trace
        time.sleep(poll)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    base_url, trace_id = argv[0], argv[1]
    wait = float(argv[argv.index("--wait") + 1]) if "--wait" in argv else 30.0
    expected = ([n for n in argv[argv.index("--expect") + 1].split(",") if n]
                if "--expect" in argv else [])
    if len(trace_id) != 32:                     # a full traceparent was handed over
        trace_id = trace_id_from_traceparent(trace_id)
    started = time.monotonic()
    trace = wait_for_trace(base_url, trace_id, wait=wait, expected=expected)
    if trace is None:
        print(json.dumps({"error": "trace_not_found", "trace_id": trace_id, "waited_seconds": wait}))
        return 2
    summary = summarize(trace_id, trace)
    summary["waited_seconds"] = round(time.monotonic() - started, 1)
    if expected:
        summary["expected"] = expected
        summary["expected_missing"] = missing_names(trace, expected)
        summary["expected_present"] = not summary["expected_missing"]
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

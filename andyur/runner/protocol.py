"""The A<->B wire protocol for the container split.

The sidecar (A) holds the run token and does prepare/redact/record/finalize; the
agent process (B) holds NOTHING and only drives the SDK + CLI. B forwards every
SDK message to A as newline-delimited JSON, and A redacts and records ON RECEIPT
-- it never trusts B, because the process that runs the untrusted agent CLI is
one prompt-injection away from being the untrusted agent.

Each line B sends is one event:

    {"kind": "msg",  "record": {...}, "texts": [...], "tools": [...],
                     "results": [...], "result": {...}|null}
    {"kind": "done", "exit": <int>, "error": <str>|null}

`record` is the full message dict A appends to the transcript (after redaction).
`texts`/`tools`/`results`/`result` are B's classification of that message, a
CONVENIENCE for A's reply-streaming, tool-span tracing, and summary extraction --
never a security decision. A applies redaction to everything regardless, so a
lying B corrupts only its own transcript; it cannot leak a secret past the
redactor or forge a control-plane call (it has no token).

The `done` sentinel is the clean end of the stream: B sends it last, carrying the
agent process's exit status. If the stream ends WITHOUT a done event, A treats
the run as a B that died mid-flight -- a failure, not a success.
"""

from __future__ import annotations

import dataclasses
import json

KIND_MSG = "msg"
KIND_DONE = "done"


def _message_record(message) -> dict:
    """The transcript record for one SDK message. Identical shape to
    runner._message_record so split and in-process transcripts match."""
    try:
        data = dataclasses.asdict(message)
    except (TypeError, ValueError):
        data = {"repr": repr(message)}
    return {"type": type(message).__name__, "data": data}


def normalize(message) -> dict:
    """Turn one SDK message (a live object, in B) into a wire event (a dict).

    Imports SDK types lazily so A -- which only ever parses the dicts -- need not
    depend on them. B classifies text/tool/result blocks here; A reads the
    classification but re-derives nothing security-relevant from it."""
    from claude_agent_sdk import (
        AssistantMessage,
        ResultMessage,
        TextBlock,
        ToolResultBlock,
        ToolUseBlock,
        UserMessage,
    )

    ev: dict = {"kind": KIND_MSG, "record": _message_record(message),
                "texts": [], "tools": [], "results": [], "result": None}

    if isinstance(message, AssistantMessage):
        for block in message.content:
            if isinstance(block, TextBlock) and block.text:
                ev["texts"].append(block.text)
            elif isinstance(block, ToolUseBlock):
                ev["tools"].append(
                    {"id": block.id, "name": block.name, "input": block.input})
    elif isinstance(message, UserMessage):
        blocks = message.content
        if isinstance(blocks, list):
            for block in blocks:
                if isinstance(block, ToolResultBlock):
                    ev["results"].append({
                        "tool_use_id": block.tool_use_id,
                        "content": block.content,
                        "is_error": bool(getattr(block, "is_error", False)),
                    })
    elif isinstance(message, ResultMessage):
        # The SDK's OWN field names, verbatim. This dict is handed straight to
        # describe_failure_fields, which reads `result` -- so naming that field
        # `summary` here silently dropped the highest-precedence cause of a failed
        # run: every failure whose text lives in ResultMessage.result (a provider
        # parse error, a refusal, a tool crash) was reported by the split path as
        # "the SDK reported an error with no cause attached", a sentence that was
        # not true. Mirroring the SDK's names is what keeps the two paths from
        # drifting; a rename here is a rename of the contract.
        ev["result"] = {
            "result": message.result,
            "num_turns": message.num_turns,
            "total_cost_usd": message.total_cost_usd,
            "session_id": message.session_id,
            "is_error": message.is_error,
            "usage": message.usage,
            "subtype": getattr(message, "subtype", None),
            "api_error_status": getattr(message, "api_error_status", None),
            "errors": getattr(message, "errors", None),
            "permission_denials": getattr(message, "permission_denials", None),
            "stop_reason": getattr(message, "stop_reason", None),
        }
    return ev


def done_event(exit_code: int, error: str | None) -> dict:
    return {"kind": KIND_DONE, "exit": exit_code, "error": error}


# How much of an agent-supplied string the sidecar will keep in the fields it
# uses for logging and spans. The transcript record is bounded separately by the
# channel's stream budget; these are the values that reach an operator's console.
_MAX_TEXT = 1_000_000


def _str(x, limit: int = _MAX_TEXT) -> str:
    s = x if isinstance(x, str) else json.dumps(x, default=str)
    return s if len(s) <= limit else s[:limit] + " ...(truncated)"


def sanitize(event: dict) -> dict:
    """Normalise ONE event from the untrusted side into a known shape.

    THE SIDECAR MUST NOT TRUST B'S TYPES. "A never trusts B" was true of B's
    CONTENT -- everything is redacted on receipt and B holds no credential -- but
    it was not structurally true of B's SHAPES: the consumer did `for text in
    ev["texts"]` and `tool.get("name")`, so an event with `texts` as a string was
    iterated one CHARACTER at a time into the operator's log, and `tools` as a
    string or a list of scalars raised AttributeError inside the trusted half.
    That failed closed, which is the right direction, but it crashed the trusted
    process on untrusted input and reported a Python error where a diagnosis
    belongs.

    So every event is forced into shape HERE, at the one place events enter, and
    the consumer downstream may assume what it reads. Anything unusable is
    dropped rather than rejected: a malformed field is the agent's problem, and
    the run's own result is what decides success.
    """
    if not isinstance(event, dict):
        return {"kind": KIND_MSG, "record": {}, "texts": [], "tools": [],
                "results": [], "result": None}

    if event.get("kind") == KIND_DONE:
        exit_raw = event.get("exit")
        try:
            exit_code = int(exit_raw)
        except (TypeError, ValueError):
            exit_code = -1
        err = event.get("error")
        return {"kind": KIND_DONE, "exit": exit_code,
                "error": None if err is None else _str(err, 4096)}

    record = event.get("record")
    if not isinstance(record, dict):
        # keep it, but as something json.dumps can render for the transcript
        record = {"unstructured": _str(record)}

    texts = event.get("texts")
    texts = [_str(t) for t in texts] if isinstance(texts, list) else []

    tools = []
    raw_tools = event.get("tools")
    if isinstance(raw_tools, list):
        for t in raw_tools:
            if not isinstance(t, dict):
                continue
            tools.append({"id": _str(t.get("id"), 256),
                          "name": _str(t.get("name"), 256),
                          "input": t.get("input")})

    results = []
    raw_results = event.get("results")
    if isinstance(raw_results, list):
        for r in raw_results:
            if not isinstance(r, dict):
                continue
            # `content` is DESTRUCTURED by the consumer, which joins
            # item["text"] across a list -- so passing it through raw left the
            # exact defect class this function exists to close, one nesting level
            # down: a {"text": 123} item raised TypeError inside the trusted
            # half's consume loop and aborted the whole run. Normalise it to
            # either a string or a list of {"text": str}.
            content = r.get("content")
            if isinstance(content, list):
                content = [{"text": _str(x.get("text"))}
                           for x in content if isinstance(x, dict)]
            elif not isinstance(content, str):
                content = _str(content)
            results.append({"tool_use_id": _str(r.get("tool_use_id"), 256),
                            "content": content,
                            "is_error": bool(r.get("is_error"))})

    result = event.get("result")
    if not isinstance(result, dict):
        result = None

    return {"kind": KIND_MSG, "record": record, "texts": texts,
            "tools": tools, "results": results, "result": result}


def encode(event: dict) -> bytes:
    """One event as a single NDJSON line (default=str so odd values never
    crash the stream)."""
    return (json.dumps(event, default=str) + "\n").encode()

"""MCP wire decisions, shared by every path that enforces per-tool authority.

These four functions were the dataplane's. They are here because the SIDECAR
tool leg needs the same answers, and the alternative was a second
implementation of the same decision.

The rule they exist to keep is in `permitted_tools`'s own docstring: one
function backs both the `tools/call` denial and the `tools/list` rewrite, so
the menu an agent sees and the calls it may make cannot drift apart. Two copies
would break exactly that, and the drift would be silent -- an agent shown a
tool it cannot call, or worse, allowed one it was never shown.

Deliberately dependency-free: `json` and nothing else. Both the ext_authz
decision service and the per-run sidecar import it, and neither should pull in
the other's package to authorize a tool call.
"""

from __future__ import annotations

from typing import Any



# The closed method vocabulary for an ENUMERATED binding.
#
# A per-tool grant says "this server is used for THESE tools". Every other
# JSON-RPC method reaches the same upstream over the same delegated or brokered
# credential, so leaving the vocabulary open is a side door around the reviewed
# grant: `resources/read` and `prompts/get` read server state and run
# server-side templates that no tool grant ever mentioned.
#
# Bindings that do not enumerate keep the audience-level posture and are not
# constrained by this set.
MCP_TOOL_SESSION_METHODS = frozenset({
    "initialize", "ping", "tools/list", "tools/call",
    "notifications/initialized", "notifications/cancelled",
    "notifications/progress",
    # Standard client->server notifications a conforming client may send
    # mid-session; excluding them would 403 a client that advertised the
    # capability. None invokes a tool.
    "notifications/roots/list_changed",
})

def permitted_tools(decision: dict[str, Any],
                    mcp_tools: dict[str, str] | None) -> list[str] | None:
    """The MCP tools THIS decision permits, from registry grants alone.

    `None` when the binding does not enumerate its tools (the decision stays
    audience-level -- there is nothing declared to filter against). Otherwise
    the grant names whose required action the decision carries; `actions is
    None` means no action model restricts this run, so every ENUMERATED grant
    stands (never a tool outside the enumeration). This one function backs both
    the tools/call denial and the tools/list rewrite, so the menu an agent sees
    and the calls it may make cannot drift apart.
    """
    if mcp_tools is None:
        return None
    actions = decision.get("actions")
    if actions is None:
        return list(mcp_tools)
    # Compare on the BASE action, dropping any "@resource" qualifier -- the same
    # normalization the manifest ceiling cross-check uses. A qualifier narrows
    # WHICH resource an action may touch (enforced at the resource PEP's pin
    # check), not WHETHER the action exists; comparing whole strings here would
    # make a legitimately granted "files:write@account=447" fail to satisfy a
    # "files:write" tool grant, a dead-grant the two checks would then disagree
    # about. `requires` never carries a qualifier (manifest validation forbids
    # "@"), so only the granted side needs stripping.
    granted = {a.partition("@")[0] for a in actions if isinstance(a, str)}
    return [name for name, requires in mcp_tools.items() if requires in granted]


def filter_tools_payload(body: bytes, permitted: set[str]) -> bytes:
    """Rewrite a tools/list RESPONSE so only permitted tools remain.

    Handles both MCP streamable-HTTP response shapes: a plain JSON-RPC object,
    and an SSE stream. Per the SSE standard an event's payload may span several
    consecutive `data:` lines (joined by newlines) and is dispatched at the
    blank line; `\r\n`/`\r` terminators are tolerated. A message that is not a
    tools/list result (an error, a notification) passes through unchanged -- it
    names no tools. Anything that cannot be parsed raises ValueError, and the
    caller substitutes a fail-closed error: an unreadable body riding a
    tools/list exchange must not reach the agent unverified.
    """
    import json

    def _filter_msg(msg: Any) -> Any:
        # A JSON-RPC BATCH is a top-level array; recurse so a tools/list result
        # smuggled inside one is still filtered (never returned unchanged, which
        # would re-expose the ghost tool the rewrite exists to strip).
        if isinstance(msg, list):
            return [_filter_msg(m) for m in msg]
        if isinstance(msg, dict):
            result = msg.get("result")
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                # A list entry without a readable name cannot be checked
                # against the grants; dropping it narrows, never widens.
                result["tools"] = [
                    t for t in result["tools"]
                    if isinstance(t, dict) and t.get("name") in permitted]
        return msg

    try:
        return json.dumps(_filter_msg(json.loads(body))).encode()
    except (ValueError, UnicodeDecodeError):
        pass  # not a plain JSON body; try the SSE shape below
    try:
        text = body.decode()
    except UnicodeDecodeError as exc:
        raise ValueError("tools/list response is neither JSON nor SSE") from exc

    out: list[str] = []
    data_buf: list[str] = []
    saw_data = False

    def _flush() -> None:
        # One SSE event's data lines are joined by newline (SSE spec), then the
        # accumulated payload is one JSON-RPC message. Re-emitted as a single
        # data line -- semantically identical for JSON.
        if not data_buf:
            return
        payload = "\n".join(data_buf)
        data_buf.clear()
        if not payload.strip():
            return
        out.append("data: " + json.dumps(_filter_msg(json.loads(payload))))

    for raw in text.split("\n"):
        line = raw.rstrip("\r")            # tolerate CRLF / lone CR terminators
        if line.startswith("data:"):
            saw_data = True
            # SSE strips exactly one leading space after the colon.
            frag = line[len("data:"):]
            data_buf.append(frag[1:] if frag.startswith(" ") else frag)
        elif line == "":
            _flush()                       # blank line dispatches the event
            out.append("")
        else:
            out.append(line)               # event:/id:/comment field of the event
    _flush()                               # trailing event with no final blank
    if not saw_data:
        raise ValueError("tools/list response carries no JSON or SSE data")
    return "\n".join(out).encode()


def mcp_body_kind(body: bytes) -> str:
    """Classify an ext_authz request body for an enumerated binding:

      "empty"   no body -- a body-less transport leg (GET SSE, DELETE session).
      "object"  a single JSON-RPC message (request/notification/response).
      "array"   a JSON-RPC BATCH. It can carry a forbidden tools/call that
                parse_mcp cannot surface (it reads a single object), so an
                enumerated binding must fail closed rather than authorize it
                per-tool. MCP 2025-06-18 removed batching, so refusing arrays
                is protocol-correct, not merely defensive.
      "invalid" a non-empty body that is not a single JSON object or array
                (a scalar, or unparseable) -- nothing to authorize; deny.

    This exists because `method is None` alone is ambiguous: it is the correct
    state for a body-less leg AND the state a batch or a garbage POST produces,
    and treating the latter two as the former is a fail-open (a batched
    tools/call would skip every per-tool check and still be minted a token).
    """
    if not body or not body.strip():
        return "empty"
    import json
    try:
        msg = json.loads(body)
    except Exception:                                          # noqa: BLE001
        return "invalid"
    if isinstance(msg, dict):
        return "object"
    if isinstance(msg, list):
        return "array"
    return "invalid"


def parse_mcp(body: bytes) -> tuple[str | None, str | None]:
    """Extract (method, tool) from an MCP JSON-RPC request body. `tool` is the
    `params.name` of a `tools/call`, else None. A body that is not JSON returns
    (None, None) -- the decision then has no method to authorize and denies. On
    the composed production plane this parsing is the Envoy AI Gateway MCP
    filter's job (it publishes method/tool as dynamic metadata); here the
    decision service parses the buffered body (Envoy `with_request_body`), the
    same pattern used before a native MCP filter is deployed."""
    import json
    try:
        msg = json.loads(body or b"{}")
    except Exception:                                          # noqa: BLE001
        return None, None
    if not isinstance(msg, dict):
        return None, None
    method = msg.get("method")
    tool = None
    if method == "tools/call":
        params = msg.get("params")
        if isinstance(params, dict):
            tool = params.get("name")
    return (method if isinstance(method, str) else None,
            tool if isinstance(tool, str) else None)

"""A conforming Andyur agent with zero Andyur imports and zero dependencies.

This is the reference implementation of `andyur-agent-runtime/v1`
(docs/agent-runtime-protocol-v1.md) in Python's standard library alone. It
exists to prove, by running, that the protocol needs nothing from Andyur: no
SDK, no package, no credential -- an HTTP client and a JSON encoder are the
whole toolchain, in any language.

What it does, which is the whole v1 lifecycle:

  1. reads ANDYUR_RUNTIME_URL / ANDYUR_RUNTIME_TOKEN (the only environment
     the contract promises);
  2. fetches GET /v1/context, retrying connection failures while the sidecar
     comes up, and refuses a protocol version it does not implement WITHOUT
     opening an event stream (a conforming refusal is silent on the wire);
  3. calls the model through services.model_base_url with no credential;
  4. calls one granted MCP tool through services.mcp_url (a real
     streamable-HTTP MCP handshake: initialize, initialized, tools/list,
     tools/call -- hand-rolled JSON-RPC, ~40 lines, no MCP SDK);
  5. streams events to POST /v1/events as chunked NDJSON while it works,
     ending with the `done` sentinel.

It streams incrementally (a generator body with chunked encoding) because
that is the idiomatic shape; buffering the whole event list and posting once
is equally conforming. Errors inside the run become the done sentinel's
`error` -- the platform always learns why a run ended.
"""

import http.client
import json
import os
import socket
import sys
import time
import urllib.parse

PROTOCOL = "andyur-agent-runtime/v1"
CONNECT_TIMEOUT_S = 120.0
RETRY_INTERVAL_S = 0.25
HTTP_TIMEOUT_S = 60.0
# Cap on a single response body this agent will hold. The sidecar's loopback
# services are trusted less than the platform's control plane -- a malformed or
# hostile model/MCP reply should fail this run, not OOM the workload. 32 MiB is
# far above any real context/model/tool reply and far below memory pressure.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

# Exit codes are part of this agent's observable conformance behavior: the
# harness asserts an unsupported protocol exits 3 with no event stream.
EXIT_OK = 0
EXIT_FATAL = 1
EXIT_UNSUPPORTED_PROTOCOL = 3


def _conn(base_url: str) -> http.client.HTTPConnection:
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme != "http":
        raise RuntimeError(f"unsupported scheme in {base_url!r}")
    return http.client.HTTPConnection(parts.hostname, parts.port,
                                      timeout=HTTP_TIMEOUT_S)


def _request(base_url: str, method: str, path: str, headers: dict,
             body=None, encode_chunked: bool = False):
    """One HTTP exchange; returns (status, headers dict, body bytes)."""
    conn = _conn(base_url)
    try:
        prefix = urllib.parse.urlsplit(base_url).path.rstrip("/")
        conn.request(method, prefix + path, body=body, headers=headers,
                     encode_chunked=encode_chunked)
        resp = conn.getresponse()
        # Bounded read: one byte over the cap is enough to know the reply is
        # too big, without pulling the whole thing into memory first.
        data = resp.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise RuntimeError(
                f"response from {path} exceeded {MAX_RESPONSE_BYTES} bytes")
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def fetch_context(runtime_url: str, headers: dict) -> dict:
    """GET /v1/context, retrying only CONNECTION failures. An HTTP answer is
    a decision (401 is a wrong token, not a cold start) and is fatal."""
    deadline = time.monotonic() + CONNECT_TIMEOUT_S
    while True:
        try:
            status, _, body = _request(runtime_url, "GET", "/v1/context", headers)
        except (ConnectionError, socket.timeout, OSError) as exc:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"could not reach the runtime endpoint within "
                    f"{CONNECT_TIMEOUT_S:.0f}s: {type(exc).__name__}") from exc
            time.sleep(RETRY_INTERVAL_S)
            continue
        if status != 200:
            raise RuntimeError(f"/v1/context answered {status}")
        return json.loads(body)


def call_model(model_base_url: str, model: str, prompt: str) -> str:
    """One Anthropic-compatible /v1/messages call, with NO credential: the
    platform's proxy injects its own on the outbound leg and strips anything
    sent here anyway. `model` is the effective model from the run context --
    the platform enforces it regardless, but a conforming agent sends the one
    it was told rather than inventing a name."""
    payload = json.dumps({
        "model": model,
        "max_tokens": 128,
        "messages": [{"role": "user", "content": prompt}],
    })
    status, _, body = _request(
        model_base_url, "POST", "/v1/messages",
        {"Content-Type": "application/json"}, body=payload)
    if status != 200:
        raise RuntimeError(f"model call answered {status}: {body[:200]!r}")
    data = json.loads(body)
    blocks = data.get("content") or []
    return " ".join(b.get("text", "") for b in blocks
                    if isinstance(b, dict)) or json.dumps(data)[:200]


class McpClient:
    """A minimal streamable-HTTP MCP client: JSON-RPC over POST, one session.

    `mcp_url` is the full endpoint URL; `extra_headers` is the context's
    services.mcp_headers, sent on every request as the spec requires."""

    def __init__(self, mcp_url: str, extra_headers: dict):
        parts = urllib.parse.urlsplit(mcp_url)
        self._base = f"{parts.scheme}://{parts.netloc}"
        self._path = parts.path or "/"
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **extra_headers,
        }
        self._session_id = None
        self._next_id = 1

    def _post(self, payload: dict) -> dict | None:
        headers = dict(self._headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        status, resp_headers, body = _request(
            self._base, "POST", self._path, headers, body=json.dumps(payload))
        if status not in (200, 202):
            raise RuntimeError(f"MCP endpoint answered {status}: {body[:200]!r}")
        sid = {k.lower(): v for k, v in resp_headers.items()}.get("mcp-session-id")
        if sid:
            self._session_id = sid
        if not body:
            return None
        reply = json.loads(body)
        if "error" in reply:
            raise RuntimeError(f"MCP error: {reply['error']}")
        return reply.get("result")

    def _call(self, method: str, params: dict) -> dict:
        payload = {"jsonrpc": "2.0", "id": self._next_id,
                   "method": method, "params": params}
        self._next_id += 1
        return self._post(payload)

    def handshake(self) -> None:
        self._call("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "byoa-hello-agent", "version": "1.0.0"},
        })
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized",
                    "params": {}})

    def list_tools(self) -> list:
        return (self._call("tools/list", {}) or {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> str:
        result = self._call("tools/call",
                            {"name": name, "arguments": arguments}) or {}
        if result.get("isError"):
            raise RuntimeError(f"tool {name!r} returned an error: {result}")
        content = result.get("content") or []
        return " ".join(c.get("text", "") for c in content
                        if isinstance(c, dict))


def _event(**fields) -> bytes:
    base = {"kind": "msg", "record": {}, "texts": [], "tools": [],
            "results": [], "result": None}
    base.update(fields)
    return (json.dumps(base) + "\n").encode()


def _done(exit_code: int, error: str | None) -> bytes:
    return (json.dumps({"kind": "done", "exit": exit_code,
                        "error": error}) + "\n").encode()


def run(context: dict):
    """Yield the run's NDJSON event lines. Failures become the done
    sentinel's error, never a silently truncated stream."""
    error = None
    exit_code = EXIT_OK
    try:
        services = context["services"]
        prompt = (context.get("input") or {}).get("prompt", "hello")
        model = context.get("model") or "default"

        model_reply = call_model(services["model_base_url"], model, prompt)
        yield _event(record={"framework": "byoa-hello-agent",
                             "step": "model", "reply": model_reply},
                     texts=[model_reply])

        mcp = McpClient(services["mcp_url"],
                        services.get("mcp_headers") or {})
        mcp.handshake()
        tools = mcp.list_tools()
        if not tools:
            raise RuntimeError("tools/list returned no callable tool")
        tool_name = tools[0]["name"]
        yield _event(record={"framework": "byoa-hello-agent", "step": "tool"},
                     tools=[{"id": "call-1", "name": tool_name,
                             "input": {"text": model_reply[:200]}}])
        tool_reply = mcp.call_tool(tool_name, {"text": model_reply[:200]})
        yield _event(record={"framework": "byoa-hello-agent",
                             "step": "tool_result"},
                     results=[{"tool_use_id": "call-1", "content": tool_reply,
                               "is_error": False}])

        summary = (f"model answered {len(model_reply)} chars; "
                   f"tool {tool_name!r} answered {len(tool_reply)} chars")
        yield _event(record={"framework": "byoa-hello-agent", "step": "result"},
                     texts=[summary],
                     result={"result": summary, "is_error": False,
                             "num_turns": 1})
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        exit_code = EXIT_FATAL
    yield _done(exit_code, error)


def main() -> int:
    runtime_url = os.environ.get("ANDYUR_RUNTIME_URL")
    if not runtime_url:
        print("[hello-agent] ANDYUR_RUNTIME_URL is not set", file=sys.stderr)
        return EXIT_FATAL
    token = os.environ.get("ANDYUR_RUNTIME_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    context = fetch_context(runtime_url, headers)
    if context.get("protocol_version") != PROTOCOL:
        # A conforming refusal: no event stream at all. Streaming a complaint
        # would mean half-speaking a protocol this agent just said it does
        # not speak.
        print(f"[hello-agent] unsupported protocol "
              f"{context.get('protocol_version')!r}", file=sys.stderr)
        return EXIT_UNSUPPORTED_PROTOCOL

    status, _, body = _request(
        runtime_url, "POST", "/v1/events", headers,
        body=run(context), encode_chunked=True)
    if status != 200:
        print(f"[hello-agent] /v1/events answered {status}: {body[:200]!r}",
              file=sys.stderr)
        return EXIT_FATAL
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

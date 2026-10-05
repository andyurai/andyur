"""The agent process (B) of the container split.

B is the thin, credential-less half. It holds NO run token, NO broker credential
-- only a URL to the sidecar (A) and, optionally, a per-run channel token. It:

  1. fetches runtime-v1 context from A (GET /v1/context): prompt, model,
     and the loopback URLs of A's MCP tool service and model proxy;
  2. drives the SDK with the SAME driver._build_options the in-process path uses
     -- but with the andyur tools pointed at A's HTTP MCP service, so B builds no
     tool object and needs no run token;
  3. spawns the agent CLI under the uid-split wrapper (dropped to uid 1001), the
     same isolation the non-split runner applies;
  4. forwards every SDK message to A (POST /v1/events) as NDJSON, ending with a
     `done` sentinel carrying the exit status.

A redacts and records everything B forwards, on receipt, and independently
enforces the halt kill-switch and the run TTL -- so B being one prompt-injection
from the untrusted CLI grants no new authority. That is the whole point of the
split: the process that runs untrusted code holds nothing worth stealing.

Launched as:  python -m andyur.agent --channel-url URL [--channel-token TOK]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile
import time

import httpx

from claude_agent_sdk import ClaudeSDKClient

from ..runner import driver
from ..runner import agentenv
from ..runner import protocol

def _scrub_env(environ=None) -> None:
    environ = os.environ if environ is None else environ
    safe = agentenv.allowed(environ)
    environ.clear()
    environ.update(safe)
    # The channel token authorizes talking to the sidecar's A<->B channel, which
    # only B may do -- never the agent CLI. Take it out of the environment before
    # any child is spawned so the CLI cannot inherit it. main() has already read
    # its value from here into a local, so popping it costs nothing.
    environ.pop("ANDYUR_CHANNEL_TOKEN", None)


# How long to keep trying to reach the sidecar before giving up. In pod mode the
# two containers start CONCURRENTLY, so the agent routinely wins the race and
# must wait for the sidecar's channel to bind rather than treating a refused
# connection as fatal. Bounded, so a sidecar that never comes up is a fast,
# named failure and not a container that sits forever.
CONNECT_TIMEOUT = float(os.environ.get("ANDYUR_AGENT_CONNECT_TIMEOUT", "120"))
_RETRY_INTERVAL = 0.25


async def _fetch_inputs(http: httpx.AsyncClient, base: str) -> dict:
    """Fetch the run's inputs, retrying while the sidecar is still coming up.

    Only CONNECTION failures are retried. An HTTP answer means the sidecar is
    there and has made a decision -- a 401 is a wrong token, not a cold start,
    and retrying it would turn a clear failure into a two-minute hang."""
    deadline = time.monotonic() + CONNECT_TIMEOUT
    last: Exception | None = None
    while True:
        try:
            r = await http.get(f"{base}/v1/context")
            r.raise_for_status()
            return r.json()
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadError) as exc:
            last = exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"could not reach the sidecar at {base} within "
                    f"{CONNECT_TIMEOUT:.0f}s: {type(exc).__name__}"
                ) from last
            await asyncio.sleep(_RETRY_INTERVAL)


def _options_for(inputs: dict, scratch_dir: str):
    """Build ClaudeAgentOptions from A's inputs. Same driver, same tool policy
    and isolation as the non-split path; only the andyur MCP transport (HTTP, in
    A) and the process boundary differ."""
    services = inputs["services"]
    return driver._build_options(
        inputs["agent_id"], scratch_dir, driver.SYSTEM_PROMPT,
        inputs.get("trace", {}).get("traceparent"), inputs["run_id"],
        services.get("extra_mcp_servers") or {},
        max_turns=driver.DEFAULT_MAX_TURNS,
        proxy_url=services["model_base_url"],
        andyur_mcp_url=services["mcp_url"],
        andyur_mcp_headers=services.get("mcp_headers") or {},
        # The manifest model A resolved (req 1: model parity for the split path);
        # None -> the driver default, exactly the pre-registry behaviour.
        model=inputs.get("model"),
    )


async def _run(channel_url: str, channel_token: str | None, environ=None) -> int:
    """Run B after scrubbing the environment that belongs to this process.

    Production deliberately uses ``os.environ``: B is a dedicated process and
    its SDK child must not inherit control-plane credentials.  The injectable
    mapping lets in-process callers (notably tests) preserve their parent
    process environment while exercising the same scrubbing behavior.
    """
    _scrub_env(environ)
    headers = {"Authorization": f"Bearer {channel_token}"} if channel_token else {}
    # No read timeout: the forward POST stays open for the whole run while B
    # uploads events. Connect/write bounds still apply.
    async with httpx.AsyncClient(headers=headers,
                                 timeout=httpx.Timeout(30.0, read=None, write=None)) as http:
        inputs = await _fetch_inputs(http, channel_url)
        scratch = tempfile.mkdtemp(prefix=f"andyur-agent-{inputs['run_id']}-")
        options = _options_for(inputs, scratch)
        driver._open_scratch(scratch)   # make the cwd writable by the agent uid
        prompt = inputs["input"]["prompt"]

        async def body():
            """The forward stream: drive the SDK and yield one NDJSON event per
            message, then a done sentinel. Any SDK failure becomes the sentinel's
            error rather than a lost stream, so A always learns why a run ended."""
            error: str | None = None
            exit_code = 0
            try:
                async with ClaudeSDKClient(options=options) as client:
                    await client.query(prompt)
                    async for message in client.receive_response():
                        yield protocol.encode(protocol.normalize(message))
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                exit_code = 1
            yield protocol.encode(protocol.done_event(exit_code, error))

        resp = await http.post(f"{channel_url}/v1/events", content=body())
        resp.raise_for_status()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="andyur-agent")
    parser.add_argument("--channel-url", required=True)
    parser.add_argument("--channel-token", default=os.environ.get("ANDYUR_CHANNEL_TOKEN"))
    args = parser.parse_args()
    try:
        sys.exit(asyncio.run(_run(args.channel_url, args.channel_token)))
    except Exception as exc:
        # B could not even reach A or forward its stream. Exit non-zero so the
        # sidecar's watchdog sees a dead B and fails the run closed; A never got
        # a done sentinel, so it will not mistake this for success.
        print(f"[agent] fatal: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

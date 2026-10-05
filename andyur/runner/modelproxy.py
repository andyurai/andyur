"""A loopback forwarder that holds the agent's model credential for it.

THE PROBLEM THIS REMOVES. The agent's model client sends a credential on every
call, so that credential had to live in the agent's environment -- and the agent
is the component we assume is compromised. It could read it, and exfiltrate it,
and keep spending the platform's inference budget after its run was destroyed.

The whole liveness subsystem in the broker existed to bound that window: a check
per model call, a cache, a grace window, an mTLS client, and an endpoint on the
control plane to answer it. Four consecutive reviews found bugs in that
machinery, and none of them was about liveness. It was the wrong answer to the
right question -- but note that it is the wrong answer STILL RUNNING, see below.

THE RIGHT ANSWER is not to bound the leak but to have nothing to leak. The
runner and the agent share a container (production requires the sandbox), with
the runner as root and the agent dropped to its own uid. So the runner can hold
the credential and serve a proxy on loopback that the agent may USE but cannot
READ:

    agent  --http://127.0.0.1:PORT-->  this proxy  --credential-->  broker

What that buys, beyond deleting code:

  the agent holds nothing        there is no credential in its environment to
                                 find, so exfiltration has no target
  liveness becomes structural    killing the container kills this process, so
                                 the ability to spend dies with the run, with
                                 nothing to check and nothing to get wrong
  the blast radius shrinks       a stolen credential used to be good until its
                                 TTL expired, from anywhere that could reach the
                                 broker port

WHAT IS ACTUALLY DEPLOYED, because this docstring used to overstate it. It said
"No check, no cache, no grace window, no endpoint" while every one of them was
still live and enforced in production: broker._assert_run_is_live, its cache,
_LIVENESS_GRACE, and GET /runs/{run_id}/live. S4 built this proxy but never did
the deletion, so the claim described an intended end state as a finished one --
in a repository whose whole theme is making claims true.

The subsystem stays, deliberately, and the reason is worth stating: structural
liveness holds only where the runner and the agent really do share a container
that dies together, which is production (ANDYUR_SANDBOX=on). Off-sandbox the
runner is a host process and this proxy is a thread in it, so the structural
argument is weaker than it sounds. Two independent bounds on a credential that
buys inference on the platform's key is the right number; one of them being
belt-and-braces is not a reason to cut it. What changed is that it is no longer
the ONLY thing standing between a stolen credential and unbounded spend.

AND THIS PROXY IS UNAUTHENTICATED, WHICH IS ONLY SAFE BEHIND THE NETWORK
BOUNDARY. It attaches the broker credential to whatever arrives, because its
access control IS that boundary. The bind depends on the shape:
  - loopback shapes (single-container / process split): 127.0.0.1 is the run's
    own container; nothing else can reach the port.
  - O1 pod mode: bound 0.0.0.0 and advertised as the `sidecar` alias. The
    UNTRUSTED agent, single-homed on the per-run --internal network, is the only
    thing that reaches it there -- but 0.0.0.0 ALSO exposes it on the sidecar's
    SANDBOX_NETWORK interface, i.e. to the framework and SIBLING SIDECARS (NOT
    the agent). That is a trusted-plane residual (a compromised sibling sidecar
    could relay inference on this run's broker token), bounded by the per-run
    token scope and SVID TTL and documented in docs/network-topology.md; it is
    not an agent escape.
  - off-sandbox: that same bind is the HOST's loopback, so any local process can
    spend the platform's key -- the honest reason the production profile refuses
    to start without ANDYUR_SANDBOX=on rather than treating it as a hardening
    option. Adding a credential here would only move the
problem: whatever the agent must present, the agent must be able to read.

Deliberately tiny: it adds a header and streams bytes. It never buffers a
response (model output is streamed, and buffering it would break the CLI's
incremental rendering), and it never logs a body -- those carry the agent's
prompt and the model's reply, the most sensitive material on the platform.
"""

from __future__ import annotations

import threading

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse
from .. import config

# Hop-by-hop headers, plus the client's own authorization: it has none worth
# forwarding, and we replace it. The hop-by-hop set is the same one the broker
# drops and for the same reason -- these describe the agent-to-proxy connection
# and mean nothing on the proxy-to-broker one. Kept identical deliberately: this
# is the first of two hops, and a header this one forwards is one the broker
# then has to decide about again.
_DROP_REQ = {"host", "content-length", "authorization", "x-api-key",
             "accept-encoding", "connection", "keep-alive", "te", "trailer",
             "transfer-encoding", "upgrade", "proxy-authorization",
             "proxy-connection", "expect"}

# Dropped because this proxy hands the client a DECODED body (see below), so the
# upstream's content-encoding and content-length no longer describe what we send.
# date/server: uvicorn generates its own, and forwarding the upstream's gave the
# agent's client two of each -- RFC 9110 makes Date a singleton.
_DROP_RESP = {"content-length", "content-encoding", "transfer-encoding",
              "connection", "keep-alive", "date", "server"}


def build_app(upstream: str, credential: str) -> FastAPI:
    app = FastAPI(title="andyur-model-proxy")
    client = httpx.AsyncClient(base_url=upstream, timeout=600.0)

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def forward(path: str, request: Request) -> Response:
        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in _DROP_REQ
        }
        # The credential the agent never sees. It lives in this process's memory,
        # under a uid the agent cannot read from /proc.
        headers["Authorization"] = f"Bearer {credential}"
        upstream_req = client.build_request(
            request.method, "/" + path.lstrip("/"),
            headers=headers, content=await request.body(),
            params=request.query_params,
        )
        resp = await client.send(upstream_req, stream=True)

        async def body():
            # aiter_bytes, NOT aiter_raw: httpx decodes the upstream's
            # content-encoding for us.
            #
            # This was aiter_raw, which yields the bytes exactly as they arrived
            # -- still gzipped -- while the header saying so was stripped two
            # lines below. The client then tried to parse compressed bytes as
            # JSON and failed with "API Error: Failed to parse JSON". It went
            # unnoticed because the local model used in testing never
            # compressed; api.anthropic.com always does. The pairing is the
            # invariant: decode the body here, or forward the encoding header,
            # never one without the other.
            try:
                async for chunk in resp.aiter_bytes():
                    yield chunk
            finally:
                await resp.aclose()

        return StreamingResponse(
            body(), status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()
                     if k.lower() not in _DROP_RESP},
        )

    return app


class ModelProxy:
    """The forwarder, running in a thread for the life of one run.

    A thread rather than a process: it must die with the runner, and a child
    process would need its own supervision to guarantee that -- which is the
    kind of machinery this change exists to remove.
    """

    def __init__(self, upstream: str, credential: str, host: str = "127.0.0.1",
                 advertise_host: str | None = None):
        self._server = uvicorn.Server(uvicorn.Config(
            build_app(upstream, credential),
            host=host, port=0, log_level="warning", loop="asyncio", timeout_graceful_shutdown=config.THREAD_SERVER_GRACEFUL_SHUTDOWN_SECONDS,
        ))
        self._thread: threading.Thread | None = None
        self._host = host
        # The host the agent uses to reach us, which differs from the BIND host
        # when we bind all interfaces but the agent is in a separate netns/Pod
        # and must address us by a routable name (Kubernetes proxy Pod IP, or the
        # O1 per-run `sidecar` alias). Mirrors ToolService.advertise_host. Falls
        # back to the bind host, so loopback shapes are unchanged.
        self._advertise = advertise_host or host

    def start(self) -> str:
        """Start serving and return the base URL to give the agent."""
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        # uvicorn assigns the port; wait for the socket rather than guessing,
        # so the agent is never handed a URL nothing is listening on.
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("the model proxy failed to start")
            threading.Event().wait(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://{self._advertise}:{port}"

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)

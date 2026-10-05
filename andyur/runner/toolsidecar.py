"""Serve the per-run tool sidecar for one run: the `andyur/proxy` app on loopback.

Mirrors `ToolService`/`ModelProxy` (a daemon thread hosting uvicorn, a `start()`
that blocks until the socket is up and returns the base URL, a `stop()` that ends
with the run). Where `ToolService` serves Andyur's OWN platform tools, this
serves the run's REGISTRY tools through the credential-holding proxy:

    agent --(loopback /tools/<name>, NO credential)--> this sidecar
        RFC 8693 exchange + mTLS(run X509-SVID) + delegated bearer --> the tool
    agent --(loopback /llm)--> this sidecar --x-api-key(master)--> shared LiteLLM

This replaces the per-run agentgateway on the tool path (ADR-003). The run's
identity material is built by the runner from its own context and passed in as a
`sidecar.RunIdentity`, so this module needs neither SPIRE nor an AS to be
unit-tested; the proxy behaviour it hosts is covered by the proxy tests.
"""

from __future__ import annotations

import threading
import time
import os

import uvicorn

from ..proxy import app as proxy_app
from ..proxy import sidecar as sc
from ..credential_service import OpenBaoClient
from .. import config

# How long start() waits for uvicorn to report ready before failing the run's
# tool path closed instead of hanging the runner's event loop.
START_TIMEOUT = 15.0


class _BrokeredSource:
    """One run-sidecar lease. Lazy login keeps non-brokered runs vault-free."""

    def __init__(self):
        required = {name: os.environ.get(name, "") for name in (
            "ANDYUR_OPENBAO_ADDR", "ANDYUR_OPENBAO_CA_FILE",
            "ANDYUR_OPENBAO_RUNTIME_ROLE", "ANDYUR_OPENBAO_JWT_FILE")}
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError("brokered tools require: " + ", ".join(missing))
        self._jwt_file = required["ANDYUR_OPENBAO_JWT_FILE"]
        self._client = OpenBaoClient(required["ANDYUR_OPENBAO_ADDR"],
                                     required["ANDYUR_OPENBAO_CA_FILE"],
                                     required["ANDYUR_OPENBAO_RUNTIME_ROLE"])
        self._lock = threading.Lock()
        self._logged_in = False
        self._cache: dict[str, tuple[dict[str, str], float]] = {}

    def get(self, credential_ref: str) -> dict[str, str]:
        with self._lock:
            cached = self._cache.get(credential_ref)
            if cached is not None and time.monotonic() < cached[1]:
                # A copy: the cached mapping outlives this call, and a caller
                # that mutated what it was handed would corrupt the credential
                # for every later request in the window.
                return dict(cached[0])
            if not self._logged_in:
                self._client.login(self._jwt_file)
                self._logged_in = True
            headers = self._client.read_service_headers(credential_ref)
            # Static SaaS credentials have no provider expiry. Keep the memory
            # window deliberately short so OpenBao rotation takes effect within
            # one minute without a sidecar restart.
            self._cache[credential_ref] = (headers, time.monotonic() + 60)
            return dict(headers)

    def close(self) -> None:
        with self._lock:
            self._client.close()
            self._logged_in = False
            self._cache.clear()


def router_from_managed(managed: dict) -> sc.Router:
    """A sidecar `Router` from a `managed_from_descriptors` dict
    ({name: {url, audience, scheme, host, port, path}}) -- one `ToolRoute` per
    tool, keyed by name so the audience is the manifest resource_id, never the
    URL, and the scheme rides through to the upstream connection."""
    return sc.Router({name: sc.ToolRoute.from_managed(name, entry)
                      for name, entry in managed.items()})


def agent_tool_config(base_url: str, managed: dict, passthrough: dict) -> dict:
    """The mcp.json the AGENT is handed.

    Each managed tool points at this sidecar's loopback `/tools/<name>/mcp` with
    NO credential -- the agent holds nothing; the sidecar attaches the real token
    and the run's mTLS cert. Passthrough tools (no platform authority) are handed
    through untouched. One entry per tool, exactly as the agent's real config had,
    so the agent cannot tell a brokered tool from a direct one.
    """
    out = dict(passthrough)
    base = base_url.rstrip("/")
    for name, entry in managed.items():
        # The tool's DECLARED path, not a hardcoded /mcp: the proxy forwards
        # only to that path, so a tool served at /api/v2/mcp must be addressed
        # there or its every request is refused.
        out[name] = {"type": "http",
                     "url": f"{base}/tools/{name}{entry['path']}"}
    return out


class ToolSidecar:
    """The run's tool sidecar, hosting `andyur/proxy` on loopback for one run's
    life. Same shape as `ToolService`: a daemon thread hosting uvicorn."""

    def __init__(self, *, router: sc.Router, identity: sc.RunIdentity,
                 scope, pin, gateway_url: str, llm_master_key: str = "",
                 enforced_model: str | None = None,
                 trusted_traceparent: str | None = None,
                 exchange_fn=None, host: str = "127.0.0.1",
                 advertise_host: str | None = None,
                 brokered_source=None, dpop_holder=None):
        # exchange_fn is the runner's choice of WHERE the delegated token is
        # minted: `gateway.local_exchange` against Andyur's own /oauth/token, or
        # None for `build_app`'s default (asclient.exchange, the external-AS leg).
        if brokered_source is None and router.has_brokered_tools:
            brokered_source = _BrokeredSource()
        self._server = uvicorn.Server(uvicorn.Config(
            proxy_app.build_app(
                router=router, identity=identity, scope=scope, pin=pin,
                gateway_url=gateway_url, llm_master_key=llm_master_key,
                enforced_model=enforced_model,
                trusted_traceparent=trusted_traceparent,
                exchange_fn=exchange_fn,
                brokered_credential_fn=(brokered_source.get if brokered_source else None),
                brokered_credential_close=(brokered_source.close if brokered_source else None),
                dpop_holder=dpop_holder),
            host=host, port=0, log_level="warning", loop="asyncio",
            # Bound the drain on shutdown. The default waits indefinitely for
            # in-flight connections, and a stop() whose join times out abandons
            # a daemon thread still holding the run's mTLS client and mint
            # closure -- an agent pinning a long SSE stream must not keep the
            # run's credentials serviceable past teardown.
            timeout_graceful_shutdown=config.THREAD_SERVER_GRACEFUL_SHUTDOWN_SECONDS,
        ))
        self._thread: threading.Thread | None = None
        self._host = host
        # The host the agent uses to reach this gateway (its /llm and tools),
        # which differs from the BIND host when we bind all interfaces but the
        # agent is in a separate netns/Pod and must address us by a routable name
        # (Kubernetes proxy Pod IP, or the O1 per-run `sidecar` alias). Mirrors
        # ToolService/ModelProxy; falls back to the bind host so loopback shapes
        # are unchanged. Without this the api+LiteLLM path handed the agent a
        # loopback /llm URL it could not reach from its own netns under O1.
        self._advertise = advertise_host or host
        self.base_url: str | None = None

    def start(self) -> str:
        """Start serving and return the base URL to hand the agent.

        Deadlined, unlike the ToolService/ModelProxy idiom it mirrors: this is
        called inside the runner's never-strand-the-model-proxy block, and a
        uvicorn thread that wedges during startup without dying would otherwise
        hang the runner forever with nothing raised for the caller to catch.
        """
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + START_TIMEOUT
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("the tool sidecar failed to start")
            if time.monotonic() >= deadline:
                self._server.should_exit = True
                raise RuntimeError(
                    f"the tool sidecar did not come up within {START_TIMEOUT}s")
            threading.Event().wait(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        self.base_url = f"http://{self._advertise}:{port}"
        return self.base_url

    def stop(self) -> None:
        """End the run's ability to reach any tool. NEVER RAISES: it runs from
        the runner's fail-closed teardown alongside the model proxy's stop; the
        proxy app's lifespan closes the pooled clients (the run's mTLS material)."""
        self._server.should_exit = True
        thread, self._thread = self._thread, None
        if thread is not None:
            try:
                thread.join(timeout=5)
            except Exception:                              # noqa: BLE001
                pass

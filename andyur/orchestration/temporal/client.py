"""One event loop, in one thread, so a synchronous platform can call an
asynchronous SDK.

Andyur's core is synchronous -- the coordinator, the schedule service, the
drain, and the HTTP endpoints, which Starlette runs in a threadpool. Temporal's
Python client is asynchronous. The interface between them is deliberately
synchronous (see `orchestration/provider.py`), so the asynchrony stops HERE,
inside the provider that needs it, next to its task queues and its retry
policies.

## Why a dedicated loop and not `asyncio.run`

`asyncio.run` inside a synchronous function works from a threadpool endpoint and
**raises** from anywhere already inside a running loop. Andyur has both callers:
`trigger_agent` is a sync endpoint in a threadpool, while `fire_due` and
`drain_pending_work` are called synchronously by the heartbeat from inside its
loop. One bridge has to serve both.

A loop of our own in a daemon thread does. It was measured before this file was
written, not assumed: the naive version fails exactly on the heartbeat path,
which is the one that would have been discovered in production.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Any, Coroutine

from ..errors import ProviderUnavailable
from .config import TemporalConfig


class LoopThread:
    """A private event loop, started on first use and never handed out.

    Nothing outside this module may schedule on it. It exists to run this
    provider's own client calls and nothing else -- a shared loop would make one
    slow call somewhere else into a stalled control-plane request here.
    """

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def _ensure(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is None:
                loop = asyncio.new_event_loop()
                t = threading.Thread(
                    target=loop.run_forever, name="andyur-temporal", daemon=True)
                t.start()
                self._loop = loop
            return self._loop

    def call(self, coro: Coroutine, timeout: float) -> Any:
        """Run a coroutine on the private loop and wait for it.

        BOUNDED, ALWAYS. This is called on request paths, so an unbounded wait
        is a trigger endpoint that hangs rather than fails -- and a caller
        cannot tell those apart.
        """
        loop = self._ensure()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            # `future.cancel()` is NOT called, because it would do nothing and
            # say otherwise: a concurrent.futures Future whose coroutine has
            # already started returns False and leaves it running. The RPC
            # therefore continues on the private loop after this raises.
            #
            # That is acceptable rather than ignored: the loop is this
            # provider's alone, so a slow call cannot block anything else, and
            # the SDK's own call eventually completes or errors. What is NOT
            # acceptable is a caller waiting, so the CALLER is bounded here.
            raise ProviderUnavailable(
                f"the workflow service did not answer within {timeout}s") from None

    def close(self) -> None:
        """Stop the loop. For tests and for a clean shutdown; nothing on a
        request path calls this."""
        with self._lock:
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._loop.stop)
                self._loop = None


class TemporalConnection:
    """A lazily-connected Temporal client, reached synchronously.

    Lazy because importing Andyur must not require a reachable workflow service
    -- a CLI, a test or a migration has no business opening one -- and because
    the registry builds a provider before anyone has asked it to do anything.
    """

    # How long a failed connect is remembered. Without it, every caller queued
    # behind the lock made its own full attempt in turn, so the K-th waited
    # K times the RPC bound -- measured at 3s, 6s and 9s for three callers
    # against an address that drops packets. Remembering the failure briefly
    # is what makes "bounded" true for everyone rather than for the first.
    FAILURE_BACKOFF_SECONDS = 5.0

    def __init__(self, config: TemporalConfig | None = None) -> None:
        self.config = config or TemporalConfig.from_env()
        self._loop = LoopThread()
        self._client: Any = None
        self._client_fingerprint: tuple = ()
        self._lock = threading.Lock()
        self._failed_until = 0.0
        self._failed_fingerprint: tuple = ()
        self._last_error = ""

    def fingerprint(self) -> tuple:
        """What the connection's certificate material currently looks like.

        THE CLIENT WAS NEVER RE-READ, and that was a failure waiting for the
        first network blip. A connection's TLS is fixed when it is made -- the
        SDK can refresh an API key or metadata in place, but not TLS -- and the
        SVID it presents lives fifteen minutes. `spiffe-helper` rewrote the
        files on schedule and nothing read them again, so the process kept the
        bytes it loaded at start. An established connection does not notice,
        because validity is checked at the handshake; the first RECONNECT
        presented an expired certificate and was refused, forever. Proven live:
        a fresh client in the same container connected at once while the
        long-running worker beside it failed continuously.

        A stat, not a read, because this is on the admission path.
        """
        out = []
        for path in (self.config.client_cert_path, self.config.client_key_path,
                     self.config.server_ca_path):
            if not path:
                continue
            try:
                st = os.stat(path)
                out.append((path, st.st_mtime_ns, st.st_size))
            except OSError:
                out.append((path, None, None))
        return tuple(out)

    def client(self) -> Any:
        """The connected client, reconnecting when the certificate files change.

        A FAILED RECONNECT KEEPS THE OLD CLIENT SERVING. `spiffe-helper` writes
        the certificate and then the key, each in place, so a reconnect can
        land between the two and load a pair that does not match. The client
        already held was made with the previous pair, which is still valid --
        SPIRE rotates at half-life -- and an established connection is not
        re-handshaken. Dropping it for the failed replacement turned every
        rotation into up to five seconds of refused starts and halts.

        THE FAILURE MEMO IS FOR THESE FILES ONLY. It exists so callers queued
        behind an unreachable address do not each wait a full connect; it must
        not outlive the material that failed, or a torn read keeps refusing
        after the files have settled.
        """
        fp = self.fingerprint()
        current = self._client
        if current is not None and self._client_fingerprint == fp:
            return current

        # THE WAIT FOR THE LOCK IS BOUNDED TOO. Someone else is reconnecting;
        # the client they are replacing still works, so it is served meanwhile.
        if not self._lock.acquire(timeout=self.config.rpc_timeout_seconds):
            if current is not None:
                return current
            raise ProviderUnavailable(
                "the workflow service connection is busy; gave up waiting after "
                f"{self.config.rpc_timeout_seconds}s")
        try:
            previous = self._client
            if previous is not None and self._client_fingerprint == fp:
                return previous
            if time.monotonic() < self._failed_until and self._failed_fingerprint == fp:
                if previous is not None:
                    return previous
                raise ProviderUnavailable(self._last_error)
            try:
                self._client = self._loop.call(
                    self._connect(), self.config.rpc_timeout_seconds)
            except ProviderUnavailable as exc:
                self._failed_until = time.monotonic() + self.FAILURE_BACKOFF_SECONDS
                self._failed_fingerprint = fp
                self._last_error = str(exc)
                if previous is not None:
                    return previous
                raise
            # The fingerprint taken BEFORE the files were read: if they changed
            # while being read, the next call sees a difference and reconnects.
            self._client_fingerprint = fp
            self._failed_until = 0.0
            return self._client
        finally:
            self._lock.release()

    def connect_kwargs(self) -> dict[str, Any]:
        """Everything `Client.connect` needs, built the one way it is built.

        Shared with the worker so the two cannot drift: connecting by address
        and namespace alone once dropped TLS, the client pair and the API key.
        """
        kwargs: dict[str, Any] = {
            "target_host": self.config.address,
            "namespace": self.config.namespace,
        }
        if self.config.api_key:
            kwargs["api_key"] = self.config.api_key
        if self.config.tls:
            kwargs["tls"] = self._tls()
        # TRACED, and on both sides for the same reason. On the provider's
        # client this carries the caller's trace context INTO the workflow when
        # it starts or is signalled; on the worker's it turns each workflow and
        # activity into spans under that context. Without it a run's trace
        # stopped at the facade and the engine was a gap in the middle of it --
        # the lane shipped that way, with `ANDYUR_OTEL=on` in the manifest and
        # nothing emitted, which is worse than no claim at all.
        from temporalio.contrib.opentelemetry import TracingInterceptor

        kwargs["interceptors"] = [TracingInterceptor()]
        return kwargs

    async def _connect(self) -> Any:
        # Imported HERE, not at module scope, so that `andyur.orchestration`
        # imports cleanly on an installation without the Temporal extra. The
        # registry's lazy construction relies on this: a provider whose SDK is
        # absent must not break the one that is present.
        try:
            from temporalio.client import Client
        except ImportError as exc:
            raise ProviderUnavailable(
                "the Temporal SDK is not installed; install the 'temporal' "
                "extra to use this provider") from exc

        try:
            return await Client.connect(**self.connect_kwargs())
        except Exception as exc:                  # noqa: BLE001 - normalized
            raise ProviderUnavailable(
                f"could not reach the workflow service at "
                f"{self.config.describe()}: {type(exc).__name__}: {exc}") from exc

    def _tls(self) -> Any:
        """The TLS settings, read from disk at CONNECT time.

        From FILES rather than from the Workload API, even though this platform
        can speak it: the files are written by a `spiffe-helper` beside the
        process and REWRITTEN on rotation. Reading them at connect time is only
        half of what makes rotation work -- the other half is that `client()`
        reconnects when `fingerprint()` changes. This docstring used to claim
        the first half was enough, and it was not: the client was cached for
        the life of the process and never connected again.
        """
        from temporalio.service import TLSConfig

        kwargs: dict[str, Any] = {}
        if self.config.client_cert_path and self.config.client_key_path:
            with open(self.config.client_cert_path, "rb") as c, \
                 open(self.config.client_key_path, "rb") as k:
                kwargs["client_cert"] = c.read()
                kwargs["client_private_key"] = k.read()
        if self.config.server_ca_path:
            with open(self.config.server_ca_path, "rb") as a:
                kwargs["server_root_ca_cert"] = a.read()
        return TLSConfig(**kwargs) if kwargs else True

    def run(self, coro: Coroutine) -> Any:
        """Run one client coroutine, bounded by the configured RPC timeout."""
        return self._loop.call(coro, self.config.rpc_timeout_seconds)

    def close(self) -> None:
        self._client = None
        self._loop.close()

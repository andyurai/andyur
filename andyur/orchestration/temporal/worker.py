"""The worker process: where the workflows and activities actually execute.

Run as `python -m andyur.orchestration.temporal.worker`. It is a separate
process from the control plane on purpose -- a workflow worker that shared the
server's process would take the API down with it whenever the engine had a bad
minute, and the point of the seam is that they fail independently.
"""

from __future__ import annotations

import asyncio
import logging

from .config import TemporalConfig

log = logging.getLogger("andyur.temporal-worker")


# Modules that do platform work at import time and therefore cannot be
# re-imported inside the workflow sandbox. LEAVES ONLY: listing any parent of
# `andyur.orchestration.temporal.workflows` -- `andyur`, `andyur.orchestration`
# or `andyur.orchestration.temporal` -- passes the workflow module through as
# well and switches its determinism checks off. See `build_worker`.
SANDBOX_PASSTHROUGH = (
    "andyur.server",
    "andyur.db",
    "andyur.config",
    "andyur.otel",
    "andyur.observability",
    "andyur.orchestration.facade",
    "andyur.orchestration.governance",
    "andyur.orchestration.registry",
)


def build_worker(client, config: TemporalConfig):
    """The worker, configured so its workflows can be loaded AND checked.

    ## What passes through the sandbox, and what must not

    The workflow sandbox re-imports a workflow's module in a restricted
    environment, which is what makes it refuse `time.time()`, `datetime.now()`
    and the rest of what would break replay. It re-imports every module EXCEPT
    the ones passed through -- and a module passes through if it OR ANY PARENT
    is listed.

    This used to pass through `andyur`, the whole package, because importing
    the workflow module pulls in `andyur.orchestration`'s `__init__`, which
    reaches the platform's configuration and calls `pathlib.Path.resolve` --
    refused inside the sandbox, so the worker would not start. That fixed the
    start and quietly turned the sandbox OFF for Andyur's own workflows: the
    workflow module is a child of `andyur`, so it passed through too, and was
    never re-imported or restricted. Measured: a workflow in an `andyur`
    module could call `time.time()` and get a value back.

    An earlier comment in `workflows.py` said the sandbox re-imports that
    module. It did not, and that wrong belief was used to explain a test
    failure that had a different cause.

    So only the HEAVY LEAVES pass through -- the modules that do platform work
    at import. Their parent packages, and the workflow module itself, are
    re-imported inside the sandbox and checked. Measured the same way: under
    this list the same call raises `RestrictedWorkflowAccessError`.

    If `andyur.orchestration` ever imports a new module that touches the
    platform at import time, the worker will refuse to START, naming it. That
    is the right way for this to fail: loud, and before any workflow runs.

    Shared with the tests on purpose: a harness that built its own worker would
    prove nothing about the one that ships.
    """
    from temporalio.worker import Worker
    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner, SandboxRestrictions)

    from .activities import ALL_ACTIVITIES
    from .workflows import ALL_WORKFLOWS

    runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            *SANDBOX_PASSTHROUGH))
    return Worker(client, task_queue=config.task_queue,
                  workflows=ALL_WORKFLOWS, activities=ALL_ACTIVITIES,
                  workflow_runner=runner)


# How often to look for a rotated certificate. SPIRE rotates an SVID well
# before it expires, so checking every twenty seconds reconnects with the new
# one long before the old one lapses.
ROTATION_CHECK_SECONDS = 20.0

# Backoff while the workflow service is unreachable, capped.
RETRY_SECONDS = (1.0, 2.0, 5.0, 10.0, 30.0)


async def _connect(settings, config: TemporalConfig):
    """One connect, bounded: an address that drops packets must not hold the
    loop that also watches the worker."""
    from temporalio.client import Client
    from temporalio.runtime import Runtime

    # THE RUNTIME IS NAMED, not left to default, and the rotation swap depends
    # on it. The SDK's `Worker.client` setter compares the new client's runtime
    # with the worker's by identity; a client connected without one carries
    # `None` while the worker recorded the default runtime, so every swap was
    # refused ("not on the same runtime") -- live, on the first rotation.
    return await asyncio.wait_for(
        Client.connect(**settings.connect_kwargs(), runtime=Runtime.default()),
        config.rpc_timeout_seconds)


async def _run(config: TemporalConfig, build=None) -> None:
    """Serve workflows for as long as the process lives, whatever the engine does.

    ## It never exits, and it never dies quietly

    The worker shares a Pod with the API server, so a process that exits takes
    the control plane's only Service endpoint with it. A failed connect is
    retried with backoff. A worker that stops -- a poll refused, a namespace
    that does not exist -- is logged and rebuilt: `run()` is a task this loop
    watches, because the SDK's context manager re-raised some failures (the
    process exited) and waited forever on others (the container stayed Running
    and polled nothing).

    ## A rotated certificate is swapped in, not rebuilt around

    A connection's TLS is fixed when it is made, and the SVID it presents lives
    fifteen minutes, so the fingerprint of the certificate files is watched and
    a change connects again. The new client is handed to the RUNNING worker.
    Rebuilding the worker instead dropped its workflow cache every rotation --
    every live run's history fetched and replayed about every seven minutes --
    and cancelled the activities in flight. If the new connect fails, the
    current client keeps serving and the next check tries again.

    ## It connects on its OWN event loop

    The connection settings are built by the same function the provider uses,
    so the two cannot drift; the connection is made here, on this loop.
    """
    from .client import TemporalConnection

    settings = TemporalConnection(config)     # settings and fingerprint only
    attempt = 0
    while True:
        fingerprint = settings.fingerprint()
        try:
            client = await _connect(settings, config)
            worker = (build or build_worker)(client, config)
        except Exception as exc:                  # noqa: BLE001 - retried, never fatal
            delay = RETRY_SECONDS[min(attempt, len(RETRY_SECONDS) - 1)]
            attempt += 1
            log.warning("workflow service unreachable at %s (%s: %s); retrying in %ss",
                        config.describe(), type(exc).__name__, exc, delay)
            await asyncio.sleep(delay)
            continue

        running = asyncio.create_task(worker.run())
        log.info("workflow worker up on %s", config.describe())
        while True:
            done, _ = await asyncio.wait({running}, timeout=ROTATION_CHECK_SECONDS)
            if done:
                break
            current = settings.fingerprint()
            if current == fingerprint:
                continue
            try:
                worker.client = await _connect(settings, config)
                fingerprint = current
                attempt = 0
                log.info("certificate material changed; the worker now presents "
                         "the current SVID")
            except Exception as exc:              # noqa: BLE001 - old client still serves
                log.warning("certificate material changed but reconnecting failed "
                            "(%s: %s); the current connection keeps serving",
                            type(exc).__name__, exc)

        failure = running.exception() if not running.cancelled() else None
        delay = RETRY_SECONDS[min(attempt, len(RETRY_SECONDS) - 1)]
        attempt += 1
        log.error("workflow worker stopped (%s: %s); rebuilding in %ss",
                  type(failure).__name__, failure, delay)
        await asyncio.sleep(delay)


def main() -> None:
    # ALL THREE SIGNALS, which is what `setup_tracing` configures -- traces,
    # the structured log pipeline and metrics. This call was simply missing:
    # the server, the daemon and the Kubernetes controller all make it, and
    # this process never did, so the engine's half of every run was invisible.
    from ... import config as andyur_config, otel

    # The same dispatch the server admits under: a scheduled run admitted here
    # must not be dispatched differently from a triggered one.
    problem = andyur_config.temporal_dispatch_problem()
    if problem:
        raise andyur_config.InsecureProfile(
            "refusing to start the workflow worker in production: " + problem)
    otel.setup_tracing("andyur-workflow-worker")
    asyncio.run(_run(TemporalConfig.from_env()))


if __name__ == "__main__":
    main()

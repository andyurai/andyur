"""The engine's execution Activity (Architecture B+, ADR-014 D11).

`execute_run(run_id)` is the ONLY thing the engine asks the execution worker to
do, and the run id is the only thing it carries. The work -- claim the run from
Andyur, launch or adopt it, watch it, contain it -- is `EngineExecutor`'s, which
reuses the worker daemon's launcher; this module only translates between that
and the engine: Andyur's refusals become non-retryable failures, and the
engine's cancellation becomes Andyur containment.

Registered only by the execution worker, on the execution queue. The control
plane's own worker never imports it.
"""
from __future__ import annotations

import asyncio

from temporalio import activity
from temporalio.exceptions import ApplicationError

_EXECUTOR = None


def bind(executor) -> None:
    """Called once by the execution worker, before it serves."""
    global _EXECUTOR
    _EXECUTOR = executor


@activity.defn(name="execute_run")
async def execute_run(run_id: str) -> dict:
    from ...daemon.engine_executor import ExecutionRefused

    executor = _EXECUTOR
    if executor is None:
        raise RuntimeError("the execution worker has no executor bound")
    try:
        return await executor.execute(run_id, activity.heartbeat)
    except ExecutionRefused as exc:
        # ANDYUR SAID NO. Not transient, so never retried: the engine may ask
        # again only by starting a new execution, which Andyur refuses again.
        raise ApplicationError(f"{exc.code}: {exc}", exc.code,
                               type="ExecutionRefused", non_retryable=True) from None
    except asyncio.CancelledError:
        # The engine cancelled this execution. That is a halt only when Andyur
        # says so -- the SDK also cancels on worker shutdown, heartbeat timeout
        # and a superseded attempt -- so the executor asks Andyur before it
        # destroys anything (`EngineExecutor.cancelled`). Shielded so the
        # cancellation that got us here cannot interrupt the containment
        # itself, then the cancellation completes. The workflow waits for this.
        details = activity.cancellation_details()
        await asyncio.shield(executor.cancelled(
            run_id, requested=bool(details and details.cancel_requested)))
        raise


ALL_EXECUTION_ACTIVITIES = [execute_run]

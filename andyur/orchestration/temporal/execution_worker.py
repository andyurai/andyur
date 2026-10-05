"""The engine's execution worker process (Architecture B+, ADR-014 D11).

Polls the engine's EXECUTION queue for `execute_run(run_id)` and runs each one
through `EngineExecutor`: the worker daemon's launcher, reaper and kill path,
in execution mode. It holds its own identity
(spiffe://<trust-domain>/temporal-execution-worker), no run-token signing key,
and no database; capacity is its Activity concurrency, and more of it is more
replicas.

Run: python -m andyur.orchestration.temporal.execution_worker
"""
from __future__ import annotations

import asyncio
import os

from ...daemon.daemon import log
from ...daemon import engine_executor
from . import execution
from .config import TemporalConfig
from .worker import SANDBOX_PASSTHROUGH, _run

# Physical capacity per replica: executions at once. Andyur's policy (one live
# run per agent, workflow caps) is enforced at admission, not here.
DEFAULT_CONCURRENCY = 4

# See build_execution_worker: the longest the engine's cancellation of a
# running execution can go unnoticed by it.
HEARTBEAT_THROTTLE = __import__("datetime").timedelta(seconds=5)


def concurrency() -> int:
    raw = os.environ.get("ANDYUR_EXECUTION_CONCURRENCY", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_CONCURRENCY
    except ValueError:
        raise ValueError(f"ANDYUR_EXECUTION_CONCURRENCY must be an integer, not {raw!r}")
    if value < 1:
        raise ValueError("ANDYUR_EXECUTION_CONCURRENCY must be at least 1")
    return value


def build_execution_worker(client, config: TemporalConfig):
    """The execution queue's worker: the execution workflow and the execution
    Activity, nothing else -- so this process can never be handed the control
    plane's workflows, and the control plane's worker never a launch."""
    from temporalio.worker import Worker
    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner, SandboxRestrictions)

    from .workflows import EXECUTION_WORKFLOWS

    runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            *SANDBOX_PASSTHROUGH))
    return Worker(client, task_queue=config.execution_queue,
                  workflows=EXECUTION_WORKFLOWS,
                  activities=execution.ALL_EXECUTION_ACTIVITIES,
                  workflow_runner=runner,
                  max_concurrent_activities=concurrency(),
                  # HOW FAST A HALT REACHES A RUNNING EXECUTION through the
                  # engine. An Activity learns it was cancelled only when a
                  # heartbeat is actually SENT, and the SDK throttles sends to
                  # 80% of the heartbeat timeout -- 48 s at 60 s, measured: the
                  # engine's cancel alone did not destroy a halted run inside
                  # 40 s. Capped here, so the engine path is seconds, not a
                  # minute, behind Andyur's own condemnation poll.
                  max_heartbeat_throttle_interval=HEARTBEAT_THROTTLE)


async def serve(config: TemporalConfig) -> None:
    from .provider import NAME

    # The provider-neutral controller, hosted for this provider; everything
    # Temporal-shaped (the queue, the worker, the heartbeat throttle) is below.
    async with engine_executor.hosted(NAME) as executor:
        execution.bind(executor)
        log(f"execution worker {executor.daemon.worker_id} up on "
            f"{config.describe()} queue={config.execution_queue} "
            f"concurrency={concurrency()}")
        await _run(config, build=build_execution_worker)


def main() -> None:
    from ... import otel

    otel.setup_tracing(os.environ.get("ANDYUR_SERVICE_NAME", "").strip()
                       or "andyur-execution-worker")
    config = TemporalConfig.from_env()
    if config.dispatch != "engine":
        # Starting an execution worker for a deployment the engine does not
        # dispatch would poll an empty queue forever and look healthy doing it.
        raise SystemExit(
            "the execution worker serves ANDYUR_TEMPORAL_DISPATCH=engine; this "
            f"deployment is configured for {config.dispatch!r}")
    asyncio.run(serve(config))


if __name__ == "__main__":
    main()

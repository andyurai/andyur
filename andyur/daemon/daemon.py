"""Worker daemon.

A deliberately dumb executor: all decisions about who runs and when live on
the server. The daemon just ticks once a second, reaps finished runner
processes, and heartbeats every ~10 seconds. The heartbeat response carries
its assignments: runs the server wants launched, up to the daemon's free
slots. Each assignment becomes one runner subprocess.

If the daemon dies, nothing is lost: in-flight runners keep going and report
their own results, and the server's recovery loop requeues anything the dead
daemon never launched.

Launched as:  python -m andyur.daemon  (or ./run.sh daemon)
"""

import asyncio
import functools
import logging
import os
import secrets
import signal
import socket
import subprocess
import sys
import time

import httpx

from .. import config, identity, observability, otel
from ..config import DATA_DIR, SERVER_URL
from ..execlifecycle import capture_output, exit_error
from ..redact import redact
from ..runfinish import post_finish
from . import orchestrator
from .orchestrator import RunSpec

SLOTS = int(os.environ.get("ANDYUR_WORKER_SLOTS", "2"))
# The mind now lives in object storage behind the server; the only thing the
# daemon writes to disk is each runner's stdout/stderr log, kept locally.
RUNLOG_DIR = DATA_DIR / "runlogs"
HEARTBEAT_INTERVAL = 10.0
# The run TTL the control plane reaps by. Set from the heartbeat, because the
# server is what enforces it; a worker with its own idea of the TTL launches runs
# that outlive their own record. None until the first beat answers.
SERVER_RUN_TTL: int | None = None
# WHICH PROCESS THIS IS, in every log line, span and metric. The worker daemon by
# default; the engine's execution worker imports this same module to launch,
# and was reported as the daemon until it could say otherwise -- an operator
# could not tell the two apart in a trace.
SERVICE = os.environ.get("ANDYUR_SERVICE_NAME", "").strip() or "andyur-daemon"
observability.configure_logging(SERVICE, stream=sys.stdout, root=True)
_tracer = otel.setup_tracing(SERVICE)


def broker_profile_for_orchestrator(
    orchestrator_name: str, setting: str, token: str | None,
) -> tuple[bool, str | None]:
    """Resolve the migration profile at the launch boundary, fail-closed."""
    if orchestrator_name != "kubernetes":
        return False, token
    if setting not in ("on", "off"):
        raise ValueError("ANDYUR_BROKER_ENABLED must be exactly 'on' or 'off'")
    enabled = setting == "on"
    return enabled, (token if enabled else None)

# Sandboxing: when on, each run executes inside its own locked-down container
# (or two-container pod) instead of a host process, so the agent's Bash and file
# tools cannot touch the host. Off by default (runs are plain host subprocesses).
# WHERE a run lands is decided by daemon/orchestrator.py; this daemon only
# decides which runs go and when.
SANDBOX_ON = config.SANDBOX


_logger = logging.getLogger("andyur.daemon")


def log(msg: str) -> None:
    """One daemon log line: redacted, and -- through the andyur.log.v1 JSON
    handler configure_logging installed on stdout -- stamped with the active
    trace/span ids (observability-exit-criteria.md 6). The `[daemon]` prefix
    stays in the message so the gates' log greps and humans read it as before;
    a process with no handler (a bare test) still prints it."""
    text = redact(f"[daemon] {msg}")
    if _logger.handlers or logging.getLogger("andyur").handlers or logging.getLogger().handlers:
        _logger.info(text)
    else:
        print(text, flush=True)


# Bounds on the heartbeat cadence the control plane may set. The interval is the
# bound on how long a condemned run keeps running, so an unvalidated value is a
# way to disable the kill switch by setting it to a day -- and a negative or
# non-numeric one is a way to crash every worker. A worker takes direction from
# the control plane, but not direction that removes its own safety property.
HEARTBEAT_MIN = 1.0
HEARTBEAT_MAX = 60.0
# Kills attempted per beat. Each is up to two docker calls at 15s, so an
# unbounded list is minutes of work; the remainder is not lost, because the
# server keeps condemning whatever is still reported as executing.


def _clamp_interval(value) -> float:
    try:
        wanted = float(value)
    except (TypeError, ValueError):
        return HEARTBEAT_INTERVAL
    # NaN survives float() and loses every comparison, so a naive clamp returns
    # the MAXIMUM -- the worst possible kill latency, reached by sending
    # nonsense. Reject it rather than let it win by being incomparable.
    if wanted != wanted:
        return HEARTBEAT_INTERVAL
    return max(HEARTBEAT_MIN, min(HEARTBEAT_MAX, wanted))


def assert_egress_locked() -> None:
    """In the production profile, VERIFY the run network has no route out.

    Configuring a network name proves nothing: point it at an ordinary bridge
    and every run has the open internet again, with the configuration still
    looking correct. So the property is checked against Docker itself rather
    than trusted from a variable.

    This matters more for an agent than for a normal workload. An agent runs
    code it was talked into running, so the useful question is not "can it be
    tricked" -- assume yes -- but "when it is, where can the data go". An
    internal network answers: nowhere. That is a property, not a filter; no
    prompt argues its way past a missing route.
    """
    if not config.PROD or config.DEPLOYMENT != "docker":
        # Kubernetes isolation is actively checked by OfficialKubernetesApi via
        # KubernetesRunController construction. A Docker-network probe here
        # would both require the wrong runtime and certify the wrong boundary.
        return
    name = config.EGRESS_NETWORK
    try:
        out = subprocess.run(
            ["docker", "network", "inspect", "-f", "{{.Internal}}", name],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except FileNotFoundError:
        raise config.InsecureProfile(
            "ANDYUR_PROFILE=prod needs Docker to verify the run network is internal"
        )
    except subprocess.CalledProcessError:
        raise config.InsecureProfile(
            f"the run network '{name}' does not exist. Create it with:\n"
            f"    docker network create --internal {name}\n"
            "and attach the control plane and broker to it, so runs can reach "
            "those and nothing else."
        )
    if out != "true":
        raise config.InsecureProfile(
            f"the run network '{name}' is NOT internal, so every agent has the "
            "open internet to exfiltrate to. Recreate it with:\n"
            f"    docker network rm {name} && docker network create --internal {name}"
        )
    log(f"egress: runs confined to internal network '{name}'")


class Daemon:
    def __init__(self, *, execution: bool = False) -> None:
        # EXECUTION MODE is the engine's execution worker (Architecture B+,
        # ADR-014 D11): the same launcher, reaper and kill path, but no
        # assignment loop, and each run launched under the generation the
        # control plane recorded for THAT run rather than this process's.
        self.execution = execution
        self._launches: set[asyncio.Task] = set()
        # run id -> the run's traceparent, so the daemon's completion report
        # (its own span) joins the run's trace after the launch span ended
        self._trace_ctx: dict[str, str | None] = {}
        # Kubernetes needs a stable, replica-unique identity so a restarted
        # controller can adopt its own generation without seeing another
        # worker's runs. A StatefulSet Pod name supplied through ANDYUR_WORKER_ID
        # is the intended production value. Local modes keep the old ephemeral
        # identity because they do not share a cluster namespace.
        self.worker_id = (os.environ.get("ANDYUR_WORKER_ID", "").strip()
                          or f"{socket.gethostname()}-{os.getpid()}")
        if execution:
            self.worker_id = f"execution-{socket.gethostname()}-{os.getpid()}"
        self.procs: dict[str, subprocess.Popen] = {}  # run_id -> runner process
        self.stopping = False
        # Kubernetes is the governed BYOA production boundary. Select its narrow
        # adapter explicitly so no code path can accidentally call the legacy
        # global-image Kubernetes launcher. Other runtimes keep the existing
        # orchestrator selection unchanged.
        if config.DEPLOYMENT == "kubernetes":
            from .governed_kubernetes import GovernedKubernetesOrchestrator
            self.orch = (GovernedKubernetesOrchestrator(run_scoped_generations=True)
                         if execution else
                         GovernedKubernetesOrchestrator(owner_generation=self.worker_id))
        elif execution:
            # Only Kubernetes has the run fence, and the fence is what makes a
            # retried launch ADOPT rather than duplicate (D11). Elsewhere the
            # engine's retry could start a second runtime for one run.
            raise config.InsecureProfile(
                "the engine's execution worker launches only with "
                "ANDYUR_DEPLOYMENT=kubernetes, where the run fence makes a "
                "retried launch adopt the run instead of duplicating it")
        else:
            self.orch = orchestrator.select(self.worker_id)

    def launch(self, run_id: str, agent: str, trace_ctx: str | None = None,
               run_token: str | None = None, broker_token: str | None = None,
               run_type: str = "headless",
               registry_agent_id: str | None = None,
               runtime: dict | None = None,
               run_ttl: int | None = None,
               run_input: str | None = None,
               model: str | None = None,
               generation: str | None = None) -> None:
        # run_ttl is THIS run's granted wall clock, resolved by the server.
        # Absent for an agent that declared no lifetime, in which case the
        # platform-wide value the last heartbeat carried still applies.
        RUNLOG_DIR.mkdir(parents=True, exist_ok=True)
        runner_log = (RUNLOG_DIR / f"{run_id}.log").open("a")
        # In pod mode the DAEMON mints the channel credential, because it -- not
        # the sidecar -- launches both halves, so it is the only party that can
        # hand the same secret to each. In every other mode the sidecar mints its
        # own and this stays None.
        channel_token = (secrets.token_urlsafe(32)
                         if ((config.AGENT_SPLIT_POD
                              or config.DEPLOYMENT == "kubernetes")
                             and config.AGENT_SPLIT_TOKENS)
                         else None)
        self._trace_contexts()[run_id] = trace_ctx
        with _tracer.start_as_current_span(
            "daemon.launch", context=otel.context_from(trace_ctx)
        ) as span:
            span.set_attribute("andyur.run_id", run_id)
            span.set_attribute("andyur.agent", agent)
            span.set_attribute("andyur.sandbox", SANDBOX_ON)
            span.set_attribute("andyur.orchestrator", self.orch.name)
            span.set_attribute("andyur.worker_id", self.worker_id)
            # The existing broker_token is also used by Docker/host runners for
            # the established model-broker path. Only Kubernetes stages the
            # new deny-broker sidecar capability; never rewrite legacy tokens.
            broker_enabled, staged_broker_token = broker_profile_for_orchestrator(
                self.orch.name, os.environ.get("ANDYUR_BROKER_ENABLED", "off"),
                broker_token)
            run_spec = RunSpec(
                run_id=run_id, agent=agent, run_token=run_token,
                broker_token=staged_broker_token,
                channel_token=channel_token,
                broker_enabled=broker_enabled,
                server_run_ttl=run_ttl or SERVER_RUN_TTL, run_type=run_type,
                generation=generation or self.worker_id,
                registry_agent_id=registry_agent_id,
                run_input=run_input,
                model=model,
            )
            try:
                if self.orch.name == "kubernetes":
                    proc = self.orch.launch_governed(run_spec, runtime, runner_log)
                else:
                    proc = self.orch.launch(run_spec, runner_log)
            except Exception as exc:
                # The failure BY NAME on the launch span (criterion 1, 4): the
                # exception type, and the shape the daemon reports it as.
                span.add_event("launch_failed", {
                    "andyur.reason": type(exc).__name__,
                    "andyur.finish": "worker-finish"})
                span.set_attribute("andyur.outcome", "failure")
                self._trace_contexts().pop(run_id, None)
                raise
            span.set_attribute("andyur.runner_pid", proc.pid)
            span.set_attribute("andyur.outcome", "success")
        self.procs[run_id] = proc
        # Say WHERE it runs, not just that it ran. Host and container launches
        # were indistinguishable in the log, so nothing could confirm a run had
        # actually been contained -- which is how a runner image that could not
        # even start under ANDYUR_SANDBOX=on went unnoticed. The orchestrator
        # names its own placement, because it is the only thing that knows the
        # shape; the e2e harness asserts against this line.
        log(f"launched run {run_id} for '{agent}' {self.orch.describe(run_id)} "
            f"(pid {proc.pid})")

    def kill(self, run_ids: list[str]) -> None:
        """Destroy the runs the server has condemned.

        RECONCILE, do not command-and-verify. This used to ask, after every
        kill, whether the container was really gone -- distinguishing `created`
        from `exited` from absent, because a wrong answer either left a live
        container nobody would look for again or produced an unbounded retry
        loop against one that could never be killed. Three consecutive reviews
        found a bug in that logic, each in the previous review's fix.

        None of it is needed. The server keeps condemning whatever the worker
        still reports as executing, and the worker reports what Docker still
        lists. So if a kill misses, the next beat kills it again; if it landed,
        the container is gone and never reported. `docker kill` is idempotent,
        which is what makes the loop safe to be simple.

        Every shape takes the whole tree, not the supervising process:
          pod       destroy BOTH containers, sidecar and agent
          container destroy the container, which takes every process in it
          host      signal the process GROUP, which takes the CLI and any shell
                    command the agent started

        SIGKILL rather than a graceful stop, deliberately. A grace period is
        time granted to a process being destroyed precisely because it cannot
        be trusted to use it well, and the run record is already finalized
        server-side, so nothing waits on this process to report.
        """
        if not run_ids:
            return
        self.orch.kill(run_ids)
        for run_id in run_ids:
            proc = self.procs.get(run_id)
            if proc is not None and proc.poll() is None:
                self._kill_group(run_id, proc)
        log(f"killed {len(run_ids)} run(s): {', '.join(run_ids[:5])}"
            + ("..." if len(run_ids) > 5 else ""))

    def _kill_group(self, run_id: str, proc) -> None:
        """Signal the run's process group, never our own.

        The group id equals the leader's pid because both launch paths pass
        start_new_session=True. That invariant is CHECKED rather than trusted:
        if a launch path ever forgets it, the process shares the daemon's group
        and signalling it would kill the daemon, every other run on this worker,
        and whatever supervisor shares the group. A containment mechanism that
        can take out the platform is worse than the gap it closes, so this
        refuses and says so instead."""
        try:
            pgid = os.getpgid(proc.pid)
        except ProcessLookupError:
            return                      # already gone; nothing to signal
        if pgid == os.getpgid(0):
            log(f"kill {run_id}: REFUSED to signal the daemon's own process group "
                "(the run was not launched in its own session); killing the "
                "process alone")
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError):
                pass
            return
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError) as exc:
            # Already dead, or not ours to signal. Either way there is nothing
            # left to stop; log rather than crash the daemon loop.
            log(f"kill {run_id}: {type(exc).__name__}")

    def _cleanup_traced(self, run_id: str) -> None:
        """`daemon.cleanup` in the RUN's trace, on the executor thread: an
        executor inherits no OTel context, so without this the controller's
        delete span (a child of the current span) landed in a trace of its own
        -- found by the OpenSRE gate's read-back (PR B). The outcome is by
        name; a failure propagates to reap's handling unchanged."""
        with _tracer.start_as_current_span(
                "daemon.cleanup",
                context=otel.context_from(self._trace_contexts().get(run_id))) as span:
            span.set_attribute("andyur.run_id", run_id)
            span.set_attribute("andyur.worker_id", self.worker_id)
            try:
                self.orch.cleanup(run_id)
            except Exception as exc:
                span.set_attribute("andyur.outcome", "failure")
                span.set_attribute("andyur.reason", type(exc).__name__)
                raise
            span.set_attribute("andyur.outcome", "success")

    def _trace_contexts(self) -> dict:
        """run id -> traceparent (created lazily: tests build a Daemon bare)."""
        return self.__dict__.setdefault("_trace_ctx", {})

    async def reap(self, api: httpx.AsyncClient) -> None:
        for run_id in list(self.procs):
            await self.reap_one(api, run_id)

    async def reap_one(self, api: httpx.AsyncClient, run_id: str) -> int | None:
        """Reap ONE run if its process has exited. Returns the exit code once
        reaped, or None while it is still running (or its outcome did not land
        yet and it stays for another try). Per run, so the engine's execution
        worker -- one Activity per run, several at once -- reaps only its own.
        """
        proc = self.procs.get(run_id)
        if proc is None:
            return None
        code = proc.poll()
        if code is None:
            return None
        # A stock exec/v1 workload reports no completion of its own -- it
        # starts, works, writes to stdout and exits. For those runs the
        # daemon reads the container exit HERE, before cleanup deletes the
        # Pod, maps it to a run error (D3) and reports the finish the server
        # would otherwise never receive. A no-op for every other shape,
        # whose own reporter already finished the run.
        reported = await self._report_exec_completion(api, run_id)
        if reported is False:
            # The finish did not confirm (server unreachable, transient
            # error). Leave the Pod in place and try again next tick rather
            # than delete the evidence of a run whose outcome never landed.
            return None
        # A RUNNER THAT DIES BEFORE REPORTING LEAVES ITS RUN PENDING FOREVER.
        #
        # Every non-exec shape reports its own finish, so `reported is None`
        # normally means "already handled". It does not mean that when the
        # runner never got far enough to report: it crashed in startup --
        # a 503 fetching /agents/{name}/context, an unreachable model, a bad
        # image -- and the row keeps whatever state it had. `pending` is the
        # bad one. The agent is then PINNED: every later trigger answers 409
        # "agent is not idle", and there is no endpoint that cancels a
        # pending run, so the only way out is halting the workflow.
        #
        # The daemon holds the one fact nobody else has -- the container
        # exited, and with what code -- so it reports it. Safe to attempt
        # blindly: worker-finish keeps the same state guard as /finish, and
        # post_finish counts its 409 as CONFIRMED, so a runner that did
        # report is not overwritten by this.
        #
        # BEFORE CLEANUP, like the exec completion above -- it followed cleanup
        # until the B+ adversarial review. Cleanup releases the run's fence, so
        # a report that then failed, or a worker that died between the two,
        # left a pending record with no fence, and the engine's retry was
        # handed launch material and launched the run a second time.
        # Unconfirmed, the runtime stays and the report is retried next tick.
        if reported is None and code != 0:
            if not await self._report_dead_runner(api, run_id, code):
                return None
        del self.procs[run_id]
        # Release what the run leaves behind: its SPIRE entry (so a future
        # container cannot reuse a stale label->identity binding) and, in
        # pod mode, the agent container -- which has its own lifetime and
        # would otherwise keep running against a network namespace whose
        # owner has exited.
        #
        # OFF the loop and under try/except, like kill: cleanup blocks for
        # the Pod delete (up to DELETE_TIMEOUT), which ran INLINE here and
        # stalled the heartbeat for every reaped run -- and a TimeoutError
        # escaped reap AND run() with the run already popped (R MED-0, PR
        # #21). A cleanup that fails is logged and the loop continues; the
        # namespace sweep and the stranded-run reaper cover what it left.
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._cleanup_traced, run_id)
        except Exception as exc:                           # noqa: BLE001
            log(f"run {run_id}: cleanup failed "
                f"({type(exc).__name__}: {exc}); continuing")
        self._trace_contexts().pop(run_id, None)
        log(f"run {run_id} exited with code {code}")

        return code

    async def _report_dead_runner(self, api: httpx.AsyncClient, run_id: str,
                                  code: int) -> bool:
        """Finish a run whose runner exited without reporting anything.

        Best effort, and deliberately quiet about the ordinary case: a 409 means
        the runner DID report and simply exited non-zero afterwards, which is
        not a problem and not worth a line in the log. Anything else is worth
        saying, because the alternative to this report is a run that never
        leaves `pending` and an agent nobody can trigger.
        """
        confirmed, reason = await post_finish(
            api, run_id, summary=None, error=exit_error(code), attempts=1,
            path=f"/runs/{run_id}/worker-finish",
            extra={"worker_id": self.worker_id})
        if not confirmed:
            log(f"run {run_id}: its runner exited {code} without reporting, and "
                f"the worker could not report for it ({reason}); keeping its "
                "runtime and retrying on the next reap")
        return confirmed

    async def _report_exec_completion(self, api: httpx.AsyncClient,
                                      run_id: str) -> bool | None:
        """Report a stock exec/v1 run's completion, which nothing in its Pod will.

        Returns None when this is not a run the daemon owns (nothing to do, and
        the reaper proceeds to cleanup); True when the completion confirmed; and
        False when it did not, so the reaper leaves the Pod for a retry next tick
        rather than deleting a run whose outcome never landed.

        The container's exit IS the run's outcome (D3): ``exit_error`` maps it to
        an error (or None for a clean completion), the server derives ``failed``
        vs ``done`` from the presence of that error, and the captured output is
        stored diagnostically, bounded and redacted. The report goes to
        ``/runs/{id}/worker-finish`` on the daemon's OWN worker client -- a stock
        process holds no run token, so the worker reports for the run it owns.
        """
        loop = asyncio.get_running_loop()
        # The Pod read (network) and redaction (CPU, over up to the retention
        # window) both run OFF the event loop, so a hostile or merely large
        # output cannot stall the heartbeat or the kill path.
        try:
            completion = await loop.run_in_executor(
                None, self.orch.read_exec_completion, run_id)
        except Exception as exc:
            # A transient Kubernetes API error reading the exit must NOT crash the
            # worker's run loop (a non-404 ApiException once propagated straight
            # out of reap). Leave the Pod and retry next tick, exactly as an
            # unconfirmed finish does.
            log(f"run {run_id}: reading exec/v1 completion failed "
                f"({type(exc).__name__}); retrying next tick")
            return False
        if completion is None:
            return None
        exit_code, stdout, stderr, output_max = completion
        error = exit_error(exit_code)
        # `daemon.exec_completion`: the run's outcome as the daemon read it,
        # in the RUN's trace (observability-exit-criteria.md 1, 4, 5): the
        # container's exit, what was captured (bounded, redacted) and whether
        # the finish confirmed -- with the reason by name when it did not.
        with _tracer.start_as_current_span(
                "daemon.exec_completion",
                context=otel.context_from(self._trace_contexts().get(run_id))) as span:
            span.set_attribute("andyur.run_id", run_id)
            span.set_attribute("andyur.worker_id", self.worker_id)
            span.set_attribute("andyur.exit_code", int(exit_code) if exit_code is not None else -1)
            span.set_attribute("andyur.result", "failed" if error else "done")
            summary = await loop.run_in_executor(None, functools.partial(
                capture_output, stdout, stderr,
                emission_max_bytes=output_max,
                retention_max_bytes=config.OUTPUT_RETENTION_MAX_BYTES))
            span.set_attribute("andyur.captured_bytes", len((summary or "").encode()))
            span.set_attribute("andyur.capture_bound_bytes", int(min(output_max, config.OUTPUT_RETENTION_MAX_BYTES)))
            # ONE attempt per tick, not the 3x1s retry loop. reap already retries at
            # tick cadence by leaving the Pod when a finish is unconfirmed, so an
            # internal loop here only stacks blocking time AHEAD of the heartbeat:
            # a hung server is 10s x 3 + 2s per run, and two runs (64s) exceed
            # WORKER_STALE (45s), marking this worker stale and requeuing its runs.
            started = time.monotonic()
            confirmed, reason = await post_finish(
                api, run_id, summary=summary, error=error, attempts=1,
                path=f"/runs/{run_id}/worker-finish",
                extra={"worker_id": self.worker_id})
            elapsed = time.monotonic() - started
            outcome = "success" if confirmed else "failure"
            span.set_attribute("andyur.finish", "confirmed" if confirmed else
                               f"unconfirmed:{otel.safe_attribute(reason)}")
            span.set_attribute("andyur.finish.seconds", round(elapsed, 3))
            otel.try_record_metric(SERVICE, "andyur.daemon.finish_seconds", elapsed,
                                   andyur__operation="finish", andyur__outcome=outcome)
            otel.try_record_metric(SERVICE, "andyur.daemon.finish_attempts", 1,
                                   andyur__operation="finish", andyur__outcome=outcome)
            if confirmed:
                log(f"run {run_id}: exec/v1 completion reported "
                    f"({'failed' if error else 'done'})")
            else:
                log(f"run {run_id}: exec/v1 finish unconfirmed ({reason}); "
                    "leaving the run for a retry")
        return confirmed

    def adopted_runs(self) -> list[str]:
        """Runs executing on this host that this daemon did not launch.

        Without this, the kill switch cannot see its own second population. It
        condemns runs the worker REPORTS, and the worker reports the processes it
        holds -- which after a restart is nothing. Every container in flight at
        that moment becomes permanently invisible: still executing, still holding
        a run token, and never again eligible to be stopped.

        So the source of truth for "what is running here" is the RUNTIME, not
        this process's memory. The orchestrator answers that question, because
        only it knows what shape a run has on this worker.
        """
        return sorted(set(self.orch.list_running()) - set(self.procs))

    async def heartbeat(self, api: httpx.AsyncClient) -> None:
        # Report what is EXECUTING, which is this daemon's processes plus any
        # container it inherited. An adopted run has no process here, so kill()
        # falls through to destroying the container by name -- which is the only
        # handle that survives a daemon restart anyway.
        adopted = self.adopted_runs()
        if adopted:
            log(f"adopted {len(adopted)} run container(s) from a previous daemon")
        executing = list(self.procs) + adopted
        # ENGINE-LAUNCHED RUNS, reported so the server can condemn them even
        # when the execution worker that launched them is dead (Architecture
        # B+, Gate C). Reported, not counted: they hold no slot here.
        try:
            engine = [run_id for run_id, _ in self.orch.engine_runs()]
        except Exception as exc:                           # noqa: BLE001
            log(f"engine-run listing failed: {type(exc).__name__}: {exc}")
            engine = []
        # Reconcile whatever the run list cannot name. A pod's agent half is
        # deliberately not a run, so nothing above would ever condemn one whose
        # sidecar has gone; this is where that gets cleaned up. No-op in every
        # other shape.
        try:
            self.orch.sweep()
        except Exception as exc:
            log(f"sweep failed: {type(exc).__name__}: {exc}")
        payload = {
            "worker_id": self.worker_id,
            "slots": SLOTS,
            # Adopted runs occupy capacity. Counting only our own processes while
            # REPORTING the adopted ones told the server this worker was free
            # for work it was already doing, so every daemon restart overcommitted
            # the host by however many runs it inherited.
            "slots_free": max(0, SLOTS - len(executing)),
            "running": executing + [r for r in engine if r not in executing],
            # So the control plane can see a worker whose containment does not
            # match its own. The daemon and server are separate processes with
            # separate environments, and only the daemon enforces the sandbox
            # and egress: a dev-profile worker attached to a prod control plane
            # runs every agent unconfined, and nothing would have said so.
            "profile": config.PROFILE,
            # The control plane uses this capability to avoid assigning an
            # unregistered agent to Kubernetes, whose immutable workload labels
            # require a registry identity. Local workers remain able to run
            # explicitly created, unbound development agents.
            "orchestrator": self.orch.name,
        }
        try:
            resp = await api.post("/worker/heartbeat", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log(f"heartbeat failed: {exc}")
            return
        try:
            body = resp.json()
            if not isinstance(body, dict):
                raise ValueError(f"expected an object, got {type(body).__name__}")
        except Exception as exc:
            # A control plane answering 200 with HTML, an empty body or a list is
            # a broken control plane, not a reason for every worker to exit.
            log(f"heartbeat: unusable response ({type(exc).__name__}: {exc})")
            return
        # The server sets the cadence, because the server is what knows how fast
        # a kill has to land. Kill latency is bounded by this interval, so it is
        # the number to lower when revocation speed matters more than chatter --
        # for an autonomous agent, a slow revocation is not a delayed stop, it is
        # more tool calls.
        global HEARTBEAT_INTERVAL
        HEARTBEAT_INTERVAL = _clamp_interval(body.get("heartbeat_interval"))
        global SERVER_RUN_TTL
        try:
            SERVER_RUN_TTL = int(body["run_ttl"])
        except (KeyError, TypeError, ValueError):
            pass   # older control plane, or a bad value: keep what we had
        # Kill first, launch second. If the platform is being halted, spending
        # this beat's slots on new work before stopping the condemned work is
        # exactly backwards.
        kill_list = body.get("kill") or []
        if not isinstance(kill_list, list):
            log(f"heartbeat: ignoring a non-list kill field ({type(kill_list).__name__})")
            kill_list = []
        # One call, off the event loop, for the whole batch. No cap is needed
        # because it is no longer proportional to the number of runs, and no
        # per-run error handling is needed because nothing is verified: a kill
        # that missed comes back next beat. docker missing from PATH raises
        # FileNotFoundError, which would otherwise take the worker down.
        if kill_list:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, self.kill, kill_list)
            except Exception as exc:
                log(f"kill batch failed: {type(exc).__name__}: {exc}")
        assignments = body.get("assignments") or []
        if not isinstance(assignments, list):
            log(f"heartbeat: ignoring a non-list assignments field "
                f"({type(assignments).__name__})")
            assignments = []
        for assignment in assignments:
            # launch spawns `docker run`, which raises FileNotFoundError when
            # docker is absent -- the same failure that justified wrapping kill.
            # A malformed assignment must also cost one run, not the worker.
            #
            # OFF THE EVENT LOOP, like kill. Forming a pod waits for the sidecar
            # container to be running before the agent can join its namespace, and
            # a blocking wait here would stall every other run's reaping,
            # heartbeat and kill for its duration.
            # A TRACKED TASK, not awaited inline: the launch itself runs off
            # the loop, but awaiting it here still serialised launches behind
            # each other and ahead of the next heartbeat -- two slow image
            # pulls in one pass crossed the 45 s stale window (R LOW).
            task = asyncio.create_task(self._launch_assignment(api, assignment))
            self._launches.add(task)
            task.add_done_callback(self._launches.discard)

    async def _launch_assignment(self, api: httpx.AsyncClient, assignment: dict) -> None:
        """Launch one assignment off the loop; a launch that FAILS finishes the
        run as failed, by name, through worker-finish.

        The server marked the run running when it assigned it. A launch that
        raised (a rolled-back run group, an RBAC refusal, docker absent) never
        put a process in `procs`, so nothing later would reap it and no halt
        could reach it: the run sat `running` forever and its agent was never
        idle again (found live on 2026-08-26 -- a stale Role failed the attach,
        and the agent could not be triggered afterwards). The failure is the
        run's outcome; report it as one.
        """
        run_id = assignment.get("id") if isinstance(assignment, dict) else None
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, self.launch,
                assignment["id"], assignment["agent"], assignment.get("trace_ctx"),
                assignment.get("run_token"), assignment.get("broker_token"),
                assignment.get("run_type") or "headless",
                assignment.get("registry_agent_id"), assignment.get("runtime"),
                assignment.get("run_ttl"), assignment.get("input"),
                assignment.get("model"),
            )
        except Exception as exc:
            log(redact(f"launch failed: {type(exc).__name__}: {exc}"))
            if not run_id:
                return                     # malformed: nothing to finish, one run lost
            confirmed, reason = await post_finish(
                api, run_id, summary=None,
                error=redact(f"launch failed: {type(exc).__name__}: {exc}"),
                path=f"/runs/{run_id}/worker-finish",
                extra={"worker_id": self.worker_id})
            if not confirmed:
                log(f"run {run_id}: could not report the failed launch ({reason}); "
                    "the stranded-run reaper will condemn it")

    async def run(self) -> None:
        # refuse to start a production deployment that is not actually contained
        config.assert_profile()
        assert_egress_locked()
        # refuse to launch agents that share this uid while roles are attested by
        # path+uid (they could exec a peer role's binary and take its SVID)
        identity.assert_agent_isolation()
        log(f"worker {self.worker_id} up, {SLOTS} slot(s), server {SERVER_URL}")
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.request_stop)
        last_heartbeat = 0.0
        cert, verify = identity.client_tls("worker")
        async with httpx.AsyncClient(
            base_url=SERVER_URL, timeout=10, auth=identity.httpx_auth(),
            cert=cert, verify=verify,
        ) as api:
            while not self.stopping:
                await self.reap(api)
                if time.monotonic() - last_heartbeat >= HEARTBEAT_INTERVAL:
                    await self.heartbeat(api)
                    last_heartbeat = time.monotonic()
                await asyncio.sleep(1)
        if self.procs:
            # Runtime-v1 runs report their own finish and are safe to leave. A
            # stock exec/v1 run does NOT -- the daemon owns its completion -- so a
            # restart before its reaper runs orphans it until the stranded-run
            # reaper condemns it (its output lost, not its correctness). Disclosed
            # in ROADMAP.md; adoption-time recovery is the real fix.
            log(
                f"stopping; {len(self.procs)} runner(s) still going -- runtime-v1 "
                "runs finish and report on their own; any exec/v1 run the daemon "
                "owns will be condemned by the stranded-run reaper if not adopted"
            )
        else:
            log("stopping; no active runners")

    def request_stop(self) -> None:
        self.stopping = True


def _is_workload_api_failure(exc: BaseException) -> bool:
    """Whether this is "the SPIFFE workload API is not there", in any of its shapes.

    Matched by NAME rather than by importing spiffe's exception classes, because
    the library raises ArgumentError for a missing socket and JwtSourceError for
    one that never answers, and the set has changed across versions. A string
    check that is wrong simply falls through to the old behaviour.
    """
    name = type(exc).__name__
    return name in ("ArgumentError", "JwtSourceError") or "SPIFFE" in str(exc)


def main() -> None:
    # A WORKER THAT CANNOT GET AN SVID DIED WITH A TRACEBACK, FIFTEEN TIMES.
    #
    # The control plane survives an identity-plane restart because identity.py
    # rebuilds its JwtSource per request; the worker's first heartbeat raises
    # instead, run() unwinds, and the process exits non-zero. Observed live on
    # 2026-09-11: the SPIRE agent Pod was recreated, the CSI-mounted socket the
    # worker had was stale, and the worker crashlooped 15 times emitting a
    # spiffe.errors.ArgumentError stack each time.
    #
    # Restarting does not fix that particular cause -- a stale mount needs the POD
    # recreated, not the container -- so the useful change is to say so. Retry
    # briefly, because an agent that is merely still starting IS transient, then
    # exit with a sentence naming the socket and the likely cause rather than a
    # stack trace that buries both.
    for attempt in range(1, 6):
        try:
            asyncio.run(Daemon().run())
            sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as exc:                 # noqa: BLE001 - re-raised below
            if not _is_workload_api_failure(exc):
                raise
            if attempt < 5:
                log(f"no SPIFFE workload API yet ({type(exc).__name__}); "
                    f"attempt {attempt}/5, retrying in 3s")
                time.sleep(3)
                continue
            log(f"giving up: no SPIFFE workload API at {identity.socket_path()} "
                f"after {attempt} attempts.")
            log("  a worker cannot prove who it is, so it cannot heartbeat.")
            log("  if the SPIRE agent was restarted, this Pod's mounted socket is "
                "stale and the POD must be recreated -- restarting this container "
                "will not remount it.")
            sys.exit(1)


if __name__ == "__main__":
    main()

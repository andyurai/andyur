"""The execution port: where a run lands, and what keeps hard kill enforceable.

Stage 7 of the workflow-engine plan asks for a `RunExecutor` extracted around
the Docker and Kubernetes paths. **It already exists.** `daemon/orchestrator.py`
has carried `Orchestrator` since before this lane, with four implementations and
a one-place `select()` factory, and its docstring states the design intent the
plan restates: "the daemon's loop -- reap, heartbeat, kill, launch -- is
orchestrator-agnostic, so moving Andyur to Kubernetes is a new implementation of
the four methods rather than a rewrite of the coordination code."

So this file pins the port that exists rather than wrapping it in a second one,
and the reason that matters is not tidiness. The shape the plan proposes is
WEAKER in two specific ways, and both are the difference between a kill switch
that survives a restart and one that does not:

    plan                              here
    terminate(handle, reason)         kill(run_ids)
    -- keyed on a handle you hold     -- keyed on the platform's own record
    (none)                            list_running()
                                      -- reads the RUNTIME, not this process
    (none)                            sweep()
                                      -- reconciles what list_running cannot name

A restarted daemon holds no handles. `kill(run_ids)` works from run ids the
server condemns, and `list_running()` lets the daemon see what it inherited --
which is also how an execution with no live run record gets condemned at all.
Adopting the plan's shape would have broken its own stated gate, "hard kill
unchanged".
"""

import inspect

import pytest

from andyur.daemon import daemon as daemon_module
from andyur.daemon import orchestrator as orch

# What each shape must provide, and what it may inherit.
#
# `list_running` and `sweep` have working defaults on the base, so forgetting
# them is SILENT: the shape simply reports nothing running and reconciles
# nothing. That is exactly how a gap survives review, so this table is explicit
# per shape rather than asserted against the base class.
REQUIRED = {
    "HostOrchestrator": {"launch", "kill", "describe"},
    "ContainerOrchestrator": {"launch", "kill", "list_running", "cleanup", "describe"},
    "PodOrchestrator": {"launch", "sweep", "cleanup", "describe"},
    "KubernetesOrchestrator": {"launch", "kill", "list_running", "sweep",
                               "cleanup", "read_exec_completion", "describe"},
}


def _provides(cls, name):
    """Whether this class defines the method itself, rather than inheriting a
    default that quietly does nothing."""
    return any(name in k.__dict__ for k in cls.__mro__ if k is not orch.Orchestrator)


@pytest.mark.parametrize("shape", sorted(REQUIRED))
def test_each_execution_shape_provides_what_it_owes(shape):
    cls = getattr(orch, shape)
    missing = {m for m in REQUIRED[shape] if not _provides(cls, m)}

    assert missing == set(), f"{shape} inherits a silent default for {sorted(missing)}"


def test_the_port_is_the_whole_surface_a_scheduler_needs():
    """The interface stays tiny on purpose. A new operation here is a new thing
    every runtime must implement, so it is worth noticing when one appears."""
    surface = {m for m in dir(orch.Orchestrator) if not m.startswith("_")}

    # `engine_runs` arrived with Architecture B+ (ADR-014 D11): the reconciler
    # must see runs an execution worker launched under a run-scoped generation,
    # or a halt with the engine and that worker gone would reach nothing.
    assert surface == {"name", "launch", "kill", "list_running", "sweep",
                       "cleanup", "read_exec_completion", "describe",
                       "engine_runs",
                       # Completion before cleanup on the launch-failure path
                       # (run execution draft R4): a fenced runtime keeps its
                       # fence until the failure is recorded, then this
                       # releases it. Elsewhere it does nothing.
                       "release_after_outcome"}


def test_destroying_runs_is_keyed_on_run_ids_not_handles():
    """THE PROPERTY THAT MAKES HARD KILL SURVIVE A RESTART, and the one the
    plan's proposed shape would have dropped.

    A restarted daemon holds no handles. `kill` takes the run ids the server
    condemned, so it can destroy what it never launched -- including an
    execution with no live run record, which is unaccountable by definition.
    """
    sig = inspect.signature(orch.Orchestrator.kill)
    params = [p for p in sig.parameters if p != "self"]

    assert params == ["run_ids"], (
        "kill must take run ids from the platform's record, not a handle the "
        "caller happens to still hold")


def test_the_port_is_synchronous_like_the_rest_of_the_core():
    """Same reason the workflow provider is: Andyur's core is sync, and an
    async port here would force the daemon's loop to become async for one
    implementation's convenience."""
    for name in ("launch", "kill", "list_running", "sweep", "cleanup"):
        assert not inspect.iscoroutinefunction(getattr(orch.Orchestrator, name)), name


def test_one_place_decides_where_runs_execute():
    """`select()` is the execution layer's registry, and it predates the
    workflow one. The daemon never branches on the sandbox flag, so a new
    runtime is a new class rather than another if-statement threaded through
    launch, kill and reap."""
    assert callable(orch.select)
    source = inspect.getsource(daemon_module)
    assert "orchestrator.select(" in source
    assert source.count("orchestrator.select(") == 1, (
        "more than one place chooses a runtime")


def test_the_daemon_reconciles_on_every_beat():
    """`sweep` is only worth implementing because something calls it. The
    daemon does, every heartbeat, for the case where a run's sidecar has gone
    and its agent is invisible to `list_running`."""
    source = inspect.getsource(daemon_module)

    assert "self.orch.sweep()" in source


def test_a_sweep_failure_does_not_stop_the_beat():
    """Reconciliation is best effort. A sweep that raises must not cost the
    daemon its heartbeat, or one wedged runtime call stops the worker
    reporting at all -- and a worker that stops reporting has its runs
    requeued underneath it."""
    source = inspect.getsource(daemon_module)
    after = source[source.index("self.orch.sweep()"):]

    assert after[:200].strip().startswith("self.orch.sweep()")
    assert "except Exception" in after[:200]


# --- the gap this table found ------------------------------------------------

def test_every_two_part_shape_reconciles_orphaned_agents():
    """THE GAP THIS TABLE FOUND, now closed.

    Both shapes that split a run across two units have the same exposure: the
    agent is discovered through its sidecar, so an agent whose sidecar is gone
    is invisible and nothing condemns it. The Docker pod shape had always
    reconciled it; the Kubernetes one inherited the base no-op, on the
    deployment that matters most.

    Asserted for both, so a third two-part shape cannot be added without
    answering the same question.
    """
    for shape in ("PodOrchestrator", "KubernetesOrchestrator"):
        assert _provides(getattr(orch, shape), "sweep"), (
            f"{shape} splits a run in two but does not reconcile orphans")


def test_the_single_unit_shapes_do_not_need_a_sweep():
    """The negative half, so the rule above reads as a rule rather than a list.
    A host process and a single container ARE the run: there is no second part
    to be orphaned from, and `list_running` sees them directly."""
    for shape in ("HostOrchestrator", "ContainerOrchestrator"):
        assert not _provides(getattr(orch, shape), "sweep"), (
            f"{shape} is one unit; a sweep there would have nothing to reconcile")

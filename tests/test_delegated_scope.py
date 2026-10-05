"""The delegated-tool-exchange scope excludes internal own-storage actions.

A run's sealed scope carries BOTH the internal own-storage actions Andyur governs
(bare files:read/write, restored into every run by registry.with_internal_actions)
and the delegated tool actions an external AS governs. Only the latter may reach
the RFC 8693 exchange: an external AS has no mapping for files:read, and a strict
reference scope map refuses the WHOLE call on an unmapped action -- so a leak here
withholds every tool. This pins runner._delegated_scope, the filter that enforces
it (a live regression the SRE gate found; a no-op mutation of the filter must
redden this test rather than surviving the whole suite).
"""

from andyur.runner.runner import _delegated_scope
from andyur.server import registry


def test_bare_internal_actions_are_stripped_from_the_delegated_scope():
    out = _delegated_scope(
        ["files:read", "files:write", "obs:read", "tickets:comment"])
    assert "files:read" not in out and "files:write" not in out, (
        "bare own-storage actions must not enter a delegated tool exchange")
    assert out == ["obs:read", "tickets:comment"], (
        "every delegated action must survive, in order")


def test_a_qualified_files_action_is_external_data_and_survives():
    # files:read@account=447 names external/pinned DATA, not the agent's own mind,
    # so it is delegated and must NOT be stripped -- the same rule the registry
    # applies to the internal set.
    out = _delegated_scope(["files:read@account=447", "obs:read"])
    assert out == ["files:read@account=447", "obs:read"]


def test_an_unrestricted_scope_passes_through():
    assert _delegated_scope(None) is None


def test_the_filter_uses_the_registry_internal_set_as_its_source_of_truth():
    # Whatever registry.INTERNAL_ACTIONS holds is exactly what is stripped; this
    # keeps the runner's filter and the server's authority model from drifting.
    for action in registry.INTERNAL_ACTIONS:
        assert action not in _delegated_scope([action, "obs:read"])

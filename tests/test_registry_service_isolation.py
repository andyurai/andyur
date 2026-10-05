"""The registry process seams must be symmetric.

`configure_registry_factory` mutates process state, and for a long time nothing
undid it. `reset_configured_registry` drops only the cached snapshot, which is
what a caller wants right after swapping `_factory` by hand, but it leaves an
INSTALLED factory live. Three modules called it in autouse fixtures believing it
isolated them: running `test_registry_digest_stamping` before
`test_registry_binding` rebuilt the stamping module's fixture catalog over a
deleted tmp_path and turned 14 tests red with "unknown registry agent id".

The two operations read alike and mean opposite things, so they are now two
functions: `reset_configured_registry` drops the snapshot, and
`restore_default_registry` is the real inverse of configuring a factory.

These tests assert the PROPERTY a caller depends on -- after a reset the process
resolves the default manifest registry again -- rather than poking the module
globals, so they keep holding if the seam is reimplemented.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

from andyur.registry import service as registry_service
from andyur.registry.manifest_registry import ManifestAgentRegistry
from andyur.registry.models import AgentCatalog


@pytest.fixture(autouse=True)
def _restore_process_registry():
    registry_service.restore_default_registry()
    yield
    registry_service.restore_default_registry()


class _SentinelCatalog(AgentCatalog):
    """A catalog no default lookup could ever return."""

    def get_agent(self, agent_id):  # pragma: no cover - never reached when isolated
        raise AssertionError("the sentinel factory outlived its reset")

    def list_agents(self):  # pragma: no cover - never reached when isolated
        raise AssertionError("the sentinel factory outlived its reset")


def test_restore_undoes_a_configured_factory():
    """The regression: an installed factory must not survive teardown.

    Asserts against the real default registry rather than a fabricated manifest,
    so the test cannot drift away from the shipped manifest schema and cannot
    pass for the wrong reason.
    """
    registry_service.configure_registry_factory(_SentinelCatalog)
    registry_service.restore_default_registry()

    # If the factory leaked, this builds the sentinel and its methods raise.
    resolved = registry_service.configured_registry()
    assert isinstance(resolved, ManifestAgentRegistry)
    assert "agt_bystander" in {a.agent_id for a in resolved.list_agents()}


def test_configure_still_installs_the_factory():
    """Positive control.

    A restore that wiped the factory on every call would make the test above
    pass while destroying the seam's purpose. Configuring must still take effect
    for the caller that asked for it.
    """
    registry_service.configure_registry_factory(_SentinelCatalog)
    assert isinstance(registry_service.configured_registry(), _SentinelCatalog)


def test_reset_keeps_a_hand_swapped_factory():
    """`reset_configured_registry` must NOT restore the default.

    The outage tests in test_registry_binding.py swap `_factory` directly and
    then call the reset to make it take effect. Folding "drop the snapshot" and
    "restore the default" into one function broke exactly those three tests.
    """
    registry_service._factory = _SentinelCatalog
    registry_service.reset_configured_registry()
    assert isinstance(registry_service.configured_registry(), _SentinelCatalog)


def test_restore_is_idempotent():
    """Two restores in a row behave like one; the autouse fixtures do this."""
    registry_service.configure_registry_factory(_SentinelCatalog)
    registry_service.restore_default_registry()
    registry_service.restore_default_registry()
    assert isinstance(registry_service.configured_registry(), ManifestAgentRegistry)


def test_the_registry_modules_pass_in_the_polluting_order():
    """The order-dependence property itself, not just the seam's unit behaviour.

    The tests above prove `restore_default_registry` restores the default. They
    do NOT prove the autouse fixtures actually call it, and the default suite
    never runs the file order that exposes the leak, because `binding` sorts
    before `digest_stamping`. So reverting the fixtures to
    `reset_configured_registry` left every test green while reintroducing the
    exact bug (PR #8 review, MED-3).

    This runs the two modules in the damaging order in a subprocess, which is
    the only way to observe cross-module state leaking through a module-level
    global.

    Note for whoever mutates this next: the protection is REDUNDANT. Reverting
    only the polluter's teardown, or only the victim's setup, leaves this green,
    because whichever fixture still calls the inverse restores the default. Both
    have to go back to `reset_configured_registry` to reproduce the original
    failure, which is the state the tree was actually in. Mutating one and
    seeing green is not evidence that this test cannot fail.
    """
    import subprocess

    result = subprocess.run(
        (sys.executable, "-m", "pytest",
         "tests/test_registry_digest_stamping.py",
         "tests/test_registry_binding.py", "-q", "-p", "no:cacheprovider"),
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        "the registry modules fail when run in this order, so a factory "
        "installed by one module is leaking into the next:\n"
        + result.stdout[-3000:])

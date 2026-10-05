"""Installing a bundle: the refusals matter more than the happy path.

Installing decides which agents may exist and what authority each may ever
hold, so it is the most consequential write on this API. These tests pin the
four properties that make it safe to expose at all -- governed mode refuses,
a name cannot escape the registry directory, nothing moves until everything
parses, and a bad bundle cannot take the running registry down with it.
"""

import json

import pytest

from andyur.registry import bundles as bundle_ops
from andyur.registry.bundles import BundleRefused
from andyur.registry.manifest_registry import ManifestAgentRegistry
from andyur.registry.service import (configured_registry, reload_registry,
                                     reset_configured_registry)


def _doc(agent_id, name, **updates):
    doc = {
        "schema_version": "andyur.agent-resolution/v1",
        "agent_id": agent_id,
        "name": name,
        "instructions": f"Instructions for {name}.",
        "model": None,
        "tools": [],
        "ceiling": {"actions": [], "resources": None},
    }
    doc.update(updates)
    return doc


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """A registry directory with one bundle already in it."""
    monkeypatch.delenv("ANDYUR_REGISTRY", raising=False)
    monkeypatch.setenv("ANDYUR_AGENT_REGISTRY_DIR", str(tmp_path))
    existing = tmp_path / "sre"
    existing.mkdir()
    (existing / "oncall.json").write_text(json.dumps(_doc("agt_oncall", "oncall")))
    reset_configured_registry()
    yield tmp_path
    reset_configured_registry()


def test_install_adds_a_bundle_and_the_live_registry_sees_it(registry):
    """The whole point: no restart. The agent is resolvable through the process
    registry immediately after the call returns."""
    result = bundle_ops.install_bundle(
        registry, "soc", [_doc("agt_triage", "triage")])

    assert result == {"bundle": "soc", "agents": ["triage"], "replaced": False}
    assert configured_registry().resolve("agt_triage").bundle == "soc"


def test_governed_mode_refuses_and_says_how_to_publish_instead(monkeypatch):
    """An uploaded agent carries no signature, in a deployment whose entire
    premise is that every agent came from a signed artifact. There is no
    --force, and the refusal names the operation that IS correct there."""
    monkeypatch.setenv("ANDYUR_REGISTRY", "governed")

    with pytest.raises(BundleRefused) as refusal:
        bundle_ops.registry_directory()

    assert "GOVERNED" in str(refusal.value)
    assert "andyur agents package" in str(refusal.value)


@pytest.mark.parametrize("name", [
    "../escape", "..", "a/b", ".hidden", "/absolute", "soc/../../etc",
])
def test_a_bundle_name_cannot_escape_the_registry_directory(registry, name):
    """Path traversal here writes agent definitions anywhere the server can
    reach. The name pattern admits no dot and no separator, so every one of
    these is refused on the NAME before any path is built."""
    with pytest.raises(BundleRefused) as refusal:
        bundle_ops.install_bundle(registry, name, [_doc("agt_x", "xx")])

    assert "must be lowercase letters" in str(refusal.value)


def test_installing_over_an_existing_bundle_is_refused_without_replace(registry):
    """A typo'd name must not take out somebody else's agents."""
    with pytest.raises(BundleRefused) as refusal:
        bundle_ops.install_bundle(registry, "sre", [_doc("agt_new", "newagent")])

    assert "already installed" in str(refusal.value)
    # And the bundle it declined to overwrite is untouched.
    assert configured_registry().resolve("agt_oncall").name == "oncall"


def test_replace_swaps_the_bundle_and_retires_its_old_agents(registry):
    result = bundle_ops.install_bundle(
        registry, "sre", [_doc("agt_newcall", "newcall")], replace=True)

    assert result["replaced"] is True
    live = configured_registry()
    assert live.resolve("agt_newcall").bundle == "sre"
    with pytest.raises(Exception):
        live.resolve("agt_oncall")


def test_one_bad_document_installs_nothing_at_all(registry):
    """A half-installed bundle is a registry that will not load -- an outage
    caused by an install. The second document is malformed, so the first must
    not reach the registry either."""
    with pytest.raises(BundleRefused):
        bundle_ops.install_bundle(registry, "soc", [
            _doc("agt_good", "goodagent"),
            _doc("agt_bad", "badagent", ceiling="not-an-object"),
        ])

    assert not (registry / "soc").exists()
    with pytest.raises(Exception):
        configured_registry().resolve("agt_good")


def test_a_collision_with_an_installed_bundle_is_refused_on_reload(registry):
    """Two bundles cannot both claim a name. The install is what surfaces it,
    and the previously installed bundle survives."""
    with pytest.raises(Exception):
        bundle_ops.install_bundle(registry, "soc", [_doc("agt_other", "oncall")])

    assert configured_registry().resolve("agt_oncall").bundle == "sre"


def test_a_failed_install_leaves_the_running_registry_intact(registry):
    """THE PROPERTY THAT MAKES THIS SAFE TO EXPOSE.

    A failed reload must cost the install and nothing else. After the refusal
    above the process registry still resolves what it did before, rather than
    being left empty for the next unrelated caller to discover as a 503.
    """
    before = {a.agent_id for a in configured_registry().list_agents()}

    with pytest.raises(Exception):
        bundle_ops.install_bundle(registry, "soc", [_doc("agt_dup", "oncall")])

    assert {a.agent_id for a in configured_registry().list_agents()} == before
    assert before == {"agt_oncall"}


def test_an_empty_bundle_is_refused(registry):
    with pytest.raises(BundleRefused) as refusal:
        bundle_ops.install_bundle(registry, "soc", [])
    assert "at least one agent" in str(refusal.value)


def test_uninstall_removes_it_from_the_catalogue(registry):
    result = bundle_ops.uninstall_bundle(registry, "sre")

    assert result == {"bundle": "sre", "removed": ["oncall"]}
    assert not (registry / "sre").exists()
    with pytest.raises(Exception):
        configured_registry().resolve("agt_oncall")


def test_uninstalling_something_absent_says_so(registry):
    with pytest.raises(BundleRefused) as refusal:
        bundle_ops.uninstall_bundle(registry, "nosuch")
    assert "no bundle named 'nosuch'" in str(refusal.value)


def test_list_reports_bundles_and_loose_manifests_separately(registry):
    (registry / "loose.json").write_text(json.dumps(_doc("agt_loose", "loose")))
    bundle_ops.install_bundle(registry, "soc", [_doc("agt_triage", "triage")])

    listed = {item["bundle"]: item["agents"] for item in
              bundle_ops.list_bundles(registry)}

    assert listed == {"sre": 1, "soc": 1, None: 1}


def test_reload_keeps_the_old_registry_when_the_rebuild_fails(registry):
    """`reload_registry` builds the replacement BEFORE swapping. Dropping the
    cache and rebuilding lazily would instead hand the failure to whoever asked
    next, minutes later, for something unrelated."""
    before = configured_registry()
    (registry / "broken").mkdir()
    (registry / "broken" / "bad.json").write_text("{not json")

    with pytest.raises(Exception):
        reload_registry()

    assert configured_registry() is before


def test_the_staging_directory_is_never_visible_as_a_bundle(registry):
    """Staged outside the registry, so a partially written bundle cannot be
    picked up by the next scan. After a failed install nothing dot-prefixed or
    otherwise is left behind in the registry directory."""
    with pytest.raises(BundleRefused):
        bundle_ops.install_bundle(registry, "soc", [
            _doc("agt_bad", "badagent", ceiling="not-an-object")])

    assert sorted(p.name for p in registry.iterdir()) == ["sre"]
    # And the registry still loads, which it would not if a stub had survived.
    assert len(ManifestAgentRegistry(registry).list_agents()) == 1

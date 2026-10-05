"""A bundle is a subdirectory of agents, and a card is what makes it choosable.

Two gaps this closes, both found by trying to ship a set of agents someone else
would install:

  * The registry read ONE flat directory, so two bundles could only coexist by
    being tipped into a single pile in which nothing recorded what had shipped
    what. A name collision between two vendors' bundles was a startup failure
    whose message named neither of them.
  * A resolution carried no description at all, and `registry list` printed an
    id and a name. Choosing from that catalogue meant resolving every entry to
    discover what any of them was for -- and there was still no way to learn
    that an agent would sit idle without a backend nobody had mentioned.

What is NOT here is as deliberate. A card cannot influence an authority
decision, and a bundle cannot start a process; both are asserted below, because
both are the kind of convenience that would be reasonable to add later and would
quietly turn a catalogue entry into a way past review.
"""

import json

import pytest

from andyur.registry.manifest_registry import ManifestAgentRegistry
from andyur.registry.models import InvalidAgentManifest

BASE = {
    "schema_version": "andyur.agent-resolution/v1",
    "model": None,
    "tools": [],
    "ceiling": {"actions": [], "resources": None},
}


def _agent(path, agent_id, name, **updates):
    doc = dict(BASE, agent_id=agent_id, name=name,
               instructions=f"Instructions for {name}.")
    doc.update(updates)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))
    return doc


CARD = {"summary": "Decides whether a detection is a true positive.",
        "category": "threat detection",
        "requires": ["a reachable Wazuh deployment"]}


def test_two_bundles_share_one_registry_and_keep_their_identity(tmp_path):
    """The point of the whole change: install two, know which is which."""
    _agent(tmp_path / "soc" / "triage.json", "agt_triage", "triage", card=CARD)
    _agent(tmp_path / "sre" / "oncall.json", "agt_oncall", "oncall")

    registry = ManifestAgentRegistry(tmp_path)

    assert registry.resolve("agt_triage").bundle == "soc"
    assert registry.resolve("agt_oncall").bundle == "sre"


def test_a_loose_manifest_still_loads_and_belongs_to_no_bundle(tmp_path):
    """Every registry written before bundles existed keeps working.

    `None` rather than a placeholder bundle name: an ungrouped manifest is not
    a member of a bundle called "default", and a caller filtering by bundle
    must not be handed one that does not exist.
    """
    _agent(tmp_path / "loose.json", "agt_loose", "loose")
    _agent(tmp_path / "soc" / "triage.json", "agt_triage", "triage")

    registry = ManifestAgentRegistry(tmp_path)

    assert registry.resolve("agt_loose").bundle is None
    assert registry.resolve("agt_triage").bundle == "soc"
    assert len(registry.list_agents()) == 2


def test_a_collision_between_bundles_names_the_bundle_that_holds_it(tmp_path):
    """"duplicate agent name 'triage'" is a puzzle once two bundles are
    installed. The message has to say where the other one is, or the operator
    is left grepping a directory tree to find out who they are fighting."""
    _agent(tmp_path / "soc" / "triage.json", "agt_triage", "triage")
    _agent(tmp_path / "vendor" / "theirs.json", "agt_theirs", "triage")

    with pytest.raises(InvalidAgentManifest) as refusal:
        ManifestAgentRegistry(tmp_path)

    assert "duplicate agent name 'triage'" in str(refusal.value)
    assert "bundle 'soc'" in str(refusal.value)


def test_an_id_collision_with_a_loose_manifest_says_it_is_ungrouped(tmp_path):
    """The other half of the message: the holder may not be a bundle at all,
    and calling a loose file "bundle None" would send the operator looking for
    a directory that does not exist."""
    _agent(tmp_path / "loose.json", "agt_same", "one")
    _agent(tmp_path / "soc" / "other.json", "agt_same", "two")

    with pytest.raises(InvalidAgentManifest) as refusal:
        ManifestAgentRegistry(tmp_path)

    assert "duplicate agent_id 'agt_same'" in str(refusal.value)
    assert "an ungrouped manifest" in str(refusal.value)


def test_nesting_is_one_level_so_which_bundle_is_never_ambiguous(tmp_path):
    """A bundle inside a bundle would make the grouping unanswerable, so the
    scan does not recurse. Asserted as "the deep agent is NOT loaded" rather
    than as a refusal: the claim is about what the scan finds, and an empty
    registry is a legal state, so inferring it from an error would stop being
    true the moment empty became legal -- which it since has."""
    _agent(tmp_path / "soc" / "nested" / "deep.json", "agt_deep", "deep")

    assert ManifestAgentRegistry(tmp_path).list_agents() == []


def test_an_existing_but_empty_directory_is_an_empty_catalogue(tmp_path):
    """Removing your last bundle has to leave something that loads. What still
    refuses is a path that is not a directory at all, which is the misconfigured
    ANDYUR_AGENT_REGISTRY_DIR this guard exists for."""
    assert ManifestAgentRegistry(tmp_path).list_agents() == []

    with pytest.raises(InvalidAgentManifest) as refusal:
        ManifestAgentRegistry(tmp_path / "nowhere")
    assert "not a file or directory" in str(refusal.value)


def test_the_card_survives_the_registry_with_its_tri_state_intact(tmp_path):
    _agent(tmp_path / "soc" / "triage.json", "agt_triage", "triage", card=CARD)

    card = ManifestAgentRegistry(tmp_path).resolve("agt_triage").card

    assert card.summary == "Decides whether a detection is a true positive."
    assert card.category == "threat detection"
    assert card.requires == ("a reachable Wazuh deployment",)


def test_no_card_and_an_empty_requires_are_different_answers(tmp_path):
    """The ceiling's tri-state, applied to prerequisites. "states that it needs
    nothing" is a claim the bundle author made; "unstated" is a question nobody
    answered, and an installer should be able to tell them apart."""
    _agent(tmp_path / "a.json", "agt_none", "none")
    _agent(tmp_path / "b.json", "agt_silent", "silent",
           card={"summary": "Says nothing about what it needs."})
    _agent(tmp_path / "c.json", "agt_selfsuff", "selfsuff",
           card={"summary": "Needs nothing.", "requires": []})

    registry = ManifestAgentRegistry(tmp_path)

    assert registry.resolve("agt_none").card is None
    assert registry.resolve("agt_silent").card.requires is None
    assert registry.resolve("agt_selfsuff").card.requires == ()


def test_a_card_cannot_smuggle_a_field_past_review(tmp_path):
    """The registry rejects unknown keys so drift fails at startup rather than
    silently dropping a field the author believed was doing something. That
    guarantee has to hold INSIDE the card too -- a `card.grants` that parsed
    and did nothing would read, to a reviewer, exactly like one that worked."""
    _agent(tmp_path / "x.json", "agt_sneaky", "sneaky",
           card={"summary": "s", "grants": ["admin"]})

    with pytest.raises(InvalidAgentManifest) as refusal:
        ManifestAgentRegistry(tmp_path)

    assert "unknown field(s) ['grants']" in str(refusal.value)


def test_a_card_without_a_summary_is_refused(tmp_path):
    """A card exists to answer "what is this for". One that does not answer it
    is worse than no card: the catalogue shows an entry that looks described."""
    _agent(tmp_path / "x.json", "agt_nosum", "nosum", card={"category": "c"})

    with pytest.raises(InvalidAgentManifest) as refusal:
        ManifestAgentRegistry(tmp_path)

    assert "missing required field 'summary'" in str(refusal.value)


def test_the_card_does_not_touch_the_ceiling(tmp_path):
    """THE SECURITY PROPERTY. Two agents identical but for their cards resolve
    to identical authority. If a card ever gains a field that widens a ceiling,
    this fails -- which is the point, because that field would be a way to
    describe your way into authority the reviewer never granted."""
    _agent(tmp_path / "plain.json", "agt_plain", "plain",
           ceiling={"actions": ["alerts:read"], "resources": None})
    _agent(tmp_path / "carded.json", "agt_carded", "carded",
           ceiling={"actions": ["alerts:read"], "resources": None},
           card={"summary": "Contains every word an attacker might try.",
                 "category": "admin", "requires": ["containment:isolate", "*"]})

    registry = ManifestAgentRegistry(tmp_path)

    assert (registry.resolve("agt_plain").ceiling
            == registry.resolve("agt_carded").ceiling)
    assert registry.resolve("agt_carded").ceiling.actions == ("alerts:read",)


def test_per_agent_ceilings_hold_across_bundles(tmp_path):
    """Each agent brings its OWN ceiling, including the empty one.

    This is the property that makes a bundle safe to install: a read-only agent
    shipped alongside one that can act does not inherit its neighbour's
    authority just by sharing a directory.
    """
    _agent(tmp_path / "soc" / "triage.json", "agt_triage", "triage",
           ceiling={"actions": ["alerts:read"], "resources": None})
    _agent(tmp_path / "soc" / "responder.json", "agt_responder", "responder",
           ceiling={"actions": ["containment:isolate"], "resources": None})
    _agent(tmp_path / "soc" / "muzzled.json", "agt_muzzled", "muzzled",
           ceiling={"actions": [], "resources": None})

    registry = ManifestAgentRegistry(tmp_path)

    assert registry.resolve("agt_triage").ceiling.actions == ("alerts:read",)
    assert registry.resolve("agt_responder").ceiling.actions == ("containment:isolate",)
    assert registry.resolve("agt_muzzled").ceiling.actions == ()


def test_a_bundle_declares_prerequisites_and_can_never_start_one(tmp_path):
    """`requires` is PROSE for a human to provision against.

    A bundle is a file an operator installs from somewhere else. If it could
    describe a process to launch, installing one would be arbitrary code
    execution against the component whose entire job is deciding what may run.
    So the strings stay strings: nothing in the registry consumes them, and the
    tool bindings -- the only thing that reaches outward -- are unaffected by
    what a card claims to need.
    """
    _agent(tmp_path / "soc" / "triage.json", "agt_triage", "triage",
           card={"summary": "Needs a SIEM.",
                 "requires": ["docker run -d --rm wazuh/wazuh-manager"]})

    resolved = ManifestAgentRegistry(tmp_path).resolve("agt_triage")

    # It is carried verbatim, as text, for a person to read...
    assert resolved.card.requires == ("docker run -d --rm wazuh/wazuh-manager",)
    # ...and it bought the agent nothing: no tools, no authority.
    assert resolved.tools == ()
    assert resolved.ceiling.actions == ()

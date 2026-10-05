"""The agent ceiling and the authority intersection.

authority = entitlement AND pin AND ceiling AND audience.

These tests are about ONE property above all: the intersection can only narrow.
Each term is therefore exercised on its own -- with the other three deliberately
unrestricted -- so a test that goes green because some OTHER term happened to
refuse the request is not possible. Each also asserts the positive half (what
DOES survive), because a test whose only assertion is "the list is empty" passes
just as happily when nothing was computed at all.
"""

import json

import pytest

from andyur import db
from andyur.server import registry


def _raw_ceiling(agent: str, actions=None, audiences=None) -> None:
    """Write the ceiling columns RAW, bypassing set_ceiling's validation, so the
    parser can be tested against contents a broken writer or a hand-edited
    database could really contain."""
    with db.connect() as c:
        c.execute(
            "UPDATE agents SET ceiling_actions = ?, ceiling_audiences = ? WHERE name = ?",
            (actions, audiences, agent),
        )


def _stored(agent: str) -> tuple:
    with db.connect() as c:
        row = c.execute(
            "SELECT ceiling_actions, ceiling_audiences FROM agents WHERE name = ?",
            (agent,),
        ).fetchone()
    return row["ceiling_actions"], row["ceiling_audiences"]


# --- each term narrows, independently of the other three ---------------------

def test_the_entitlement_bounds_the_result_even_when_nothing_else_does():
    """Entitlement is the only restricting term here, so the drop is attributable
    to it.

    The previous version of this test asserted `"files:write" not in actions`
    after passing an entitlement that never contained it -- checking the absence
    of something never supplied, which an identity pass-through satisfies. The
    honest form gives the CEILING the wider set and lets entitlement be the thing
    that removes it, so the assertion can only hold if the term is applied."""
    ceiling = {"actions": ["files:read", "files:write"], "audiences": None}
    auth = registry.narrow(["files:read"], None, ceiling, "andyur")
    assert auth["actions"] == ["files:read"], (
        "the ceiling offered write and only the entitlement withheld it")


def test_a_request_beyond_the_ceiling_is_dropped():
    """The user is entitled to write; this agent may never hold write. Only the
    ceiling is restricting here, so the drop is attributable to it."""
    ceiling = {"actions": ["files:read"], "audiences": None}
    auth = registry.narrow(["files:read", "files:write"], None, ceiling, "andyur")
    assert auth["actions"] == ["files:read"]
    assert "files:write" not in auth["actions"]


def test_a_request_beyond_the_pin_is_dropped():
    """The work is about account 447. An entitlement qualified to a DIFFERENT
    account is not authority over this work, and is dropped -- while the same
    entitlement qualified to the pinned account survives."""
    ent = ["files:read@account=447", "files:read@account=999"]
    auth = registry.narrow(ent, {"account": "447"}, None, "andyur")
    assert auth["actions"] == ["files:read@account=447"]
    assert auth["pin"] == {"account": "447"}        # the pin travels with the grant


def test_a_qualifier_the_pin_does_not_cover_is_unverifiable_and_dropped():
    """A qualifier naming a key the pin says nothing about cannot be checked, so
    it is refused rather than waved through. Unqualified actions still survive:
    they inherit the pin instead of asserting their own."""
    ent = ["files:read", "files:read@region=eu", "files:read@account=447,region=eu"]
    auth = registry.narrow(ent, {"account": "447"}, None, "andyur")
    assert auth["actions"] == ["files:read"]


def test_an_audience_above_the_ceiling_empties_the_whole_grant():
    """Audience is a conjunct, not a label. Refused, the grant is empty rather
    than the same authority pointed at a different target."""
    ceiling = {"actions": None, "audiences": ["billing"]}
    ok = registry.narrow(["files:read"], None, ceiling, "billing")
    assert ok["actions"] == ["files:read"] and ok["audience"] == "billing"
    bad = registry.narrow(["files:read"], None, ceiling, "payroll")
    assert bad["actions"] == []          # nothing survives a refused audience
    assert bad["audience"] is None       # and no audience is substituted


def test_an_empty_audience_is_never_permitted(env):
    """A token with no audience is replayable at every target."""
    assert registry.narrow(["files:read"], None, None, "")["actions"] == []
    assert registry.permits_audience("nobody", "") is False


# --- an unrestricted term is not a grant of everything -----------------------

def test_an_unrestricted_term_does_not_grant_everything_downstream():
    """`None` / `"*"` means THAT term restricts nothing. It must not erase the
    terms that do restrict -- the failure mode is one unset column silently
    promoting a run to unlimited authority."""
    # entitlement unrestricted, ceiling restricting -> the ceiling still decides
    a = registry.narrow(None, None, {"actions": ["files:read"]}, "andyur")
    assert a["actions"] == ["files:read"]
    # the wildcard spelling behaves the same as None
    b = registry.narrow(["*"], None, {"actions": ["files:read"]}, "andyur")
    assert b["actions"] == ["files:read"]
    # ceiling unrestricted, entitlement restricting -> the entitlement decides
    c = registry.narrow(["files:read"], None, {"actions": ["*"]}, "andyur")
    assert c["actions"] == ["files:read"]
    # an unrestricted audience ceiling grants THE REQUESTED audience, not "*"
    d = registry.narrow(["files:read"], None, {"audiences": None}, "billing")
    assert d["audience"] == "billing"
    # every term unrestricted is the only case that yields unrestricted actions
    e = registry.narrow(None, None, None, "andyur")
    assert e["actions"] is None


def test_an_unpinned_run_does_not_lose_its_ceiling():
    """The pin being absent is not a reason to skip the other conjuncts."""
    auth = registry.narrow(["files:read", "files:write"], None,
                           {"actions": ["files:read"]}, "andyur")
    assert auth["actions"] == ["files:read"]


# --- the classifier-in-front-of-specialist property --------------------------

def test_a_read_only_ceiling_refuses_a_write_the_user_is_entitled_to(env):
    """Alice may write. The classifier that reads attacker-authored text may not,
    ever, however entitled Alice is -- and the specialist behind it still may, so
    this is a bound on the AGENT and not a broken write path."""
    env.agent("classifier")
    env.agent("specialist")
    registry.set_ceiling("classifier", actions=["files:read"], audiences=["andyur"])
    registry.set_ceiling("specialist", actions=["files:read", "files:write"],
                         audiences=["andyur"])
    entitled = ["files:read", "files:write"]   # the same user in both calls

    front = registry.authority_for("classifier", entitled, None, "andyur")
    assert front["actions"] == ["files:read"]
    assert "files:write" not in front["actions"]

    back = registry.authority_for("specialist", entitled, None, "andyur")
    assert back["actions"] == ["files:read", "files:write"]   # not a dead write path


# --- a run cannot widen its own ceiling --------------------------------------

def test_a_run_cannot_widen_its_own_ceiling(env):
    """The ceiling used is the one in the registry. `authority_for` has no
    parameter through which a caller could offer a different one, so "the run
    supplied a wider ceiling" is not an expressible request; and nothing on this
    path writes to the registry, so a run cannot edit the bound either."""
    env.agent("scout")
    registry.set_ceiling("scout", actions=["files:read"], audiences=["andyur"])
    before = _stored("scout")

    # a compromised run asks for everything it can name, in every term it controls
    auth = registry.authority_for("scout", ["files:read", "files:write", "*"],
                                  {"account": "447"}, "andyur")
    assert auth["actions"] == ["files:read"]
    assert registry.get_ceiling("scout") == {"actions": ["files:read"],
                                             "audiences": ["andyur"]}
    assert _stored("scout") == before          # the registry row is untouched
    assert registry.permits_audience("scout", "payroll") is False


def test_narrowing_an_already_narrowed_authority_never_regrows_it():
    """Composition only shrinks: feeding a result back through the intersection
    is a fixed point, never a recovery of what an earlier term removed."""
    once = registry.narrow(["files:read", "files:write"], None,
                           {"actions": ["files:read"]}, "andyur")
    twice = registry.narrow(once["actions"], None, {"actions": None}, "andyur")
    assert twice["actions"] == ["files:read"]


def test_narrow_does_not_mutate_its_inputs():
    """The caller's lists are not the grant. If narrow handed back the same list
    object it was given, whoever still holds that reference edits a sealed
    authority after the fact."""
    entitlement = ["files:read", "files:write"]
    pin = {"account": "447"}
    ceiling = {"actions": ["files:read"], "audiences": ["andyur"]}
    auth = registry.narrow(entitlement, pin, ceiling, "andyur")
    auth["actions"].append("files:write")
    auth["pin"]["account"] = "999"
    assert entitlement == ["files:read", "files:write"]
    assert pin == {"account": "447"}
    assert ceiling == {"actions": ["files:read"], "audiences": ["andyur"]}


# --- degrading safely on bad stored state ------------------------------------

def test_an_unset_ceiling_reads_as_unrestricted_not_as_denied(env):
    """NULL and blank are what a migration and a sloppy writer leave behind. If
    those denied everything, upgrading a live database would brick every agent."""
    env.agent("fresh")
    assert registry.get_ceiling("fresh") == {"actions": None, "audiences": None}
    _raw_ceiling("fresh", actions="", audiences="   ")
    assert registry.get_ceiling("fresh") == {"actions": None, "audiences": None}
    # ...and "unrestricted" has to MEAN unrestricted downstream, or this reads as
    # a no-op that any stub would satisfy. A set ceiling on the same agent must
    # still bite, which is what distinguishes "no bound" from "not implemented".
    _raw_ceiling("fresh", actions='["files:read"]', audiences=None)
    assert registry.get_ceiling("fresh")["actions"] == ["files:read"]
    assert registry.narrow(["files:read", "files:write"], None,
                           registry.get_ceiling("fresh"), None)["actions"] == ["files:read"]


def test_malformed_ceiling_json_denies_rather_than_raising(env):
    """A ceiling that cannot be read is a limit that cannot be honoured. It fails
    CLOSED, and it does so without raising: an exception escaping here would be a
    500 on a security decision, which downstream retries into a mystery."""
    env.agent("broken")
    _raw_ceiling("broken", actions="{not json", audiences='{"a": 1}')
    ceiling = registry.get_ceiling("broken")           # must not raise
    assert ceiling == {"actions": [], "audiences": []}
    assert registry.permits_audience("broken", "andyur") is False
    assert registry.narrow(["files:read"], None, ceiling, "andyur")["actions"] == []


def test_a_non_string_member_of_a_ceiling_is_dropped(env):
    """A number in the list cannot match any action name, so keeping it would only
    ever create confusion; dropping it narrows."""
    env.agent("mixed")
    _raw_ceiling("mixed", actions=json.dumps(["files:read", 7, None]))
    assert registry.get_ceiling("mixed")["actions"] == ["files:read"]


def test_an_unknown_agent_is_denied_not_unrestricted(env):
    """No registry row means no operator-recorded limits, which must not read as
    the absence of a limit."""
    assert registry.get_ceiling("ghost") == {"actions": [], "audiences": []}
    assert registry.permits_audience("ghost", "andyur") is False
    # authority_for goes further than DENY_ALL and REFUSES. Both grant nothing,
    # but only one of them is legible: a ceiling that denies everything was
    # configured that way deliberately, whereas an unknown agent means the caller
    # named something that does not exist, and a mint that returns an empty grant
    # for that is debugged days later as an outage rather than as a refusal.
    with pytest.raises(registry.UnknownAgent, match="ghost"):
        registry.authority_for("ghost", ["files:read"], None, "andyur")


def test_a_malformed_pin_denies_rather_than_being_ignored():
    """Ignoring an unreadable pin is exactly the widening the pin exists to stop:
    the run would keep its actions with no resource bound at all."""
    auth = registry.narrow(["files:read"], "account=447", None, "andyur")
    assert auth["actions"] == []
    assert auth["pin"] is None


def test_a_malformed_action_qualifier_matches_no_pin():
    auth = registry.narrow(["files:read@nonsense"], {"account": "447"}, None, "andyur")
    assert auth["actions"] == []


# --- the operator write path --------------------------------------------------

def test_set_ceiling_round_trips_and_can_clear(env):
    env.agent("worker")
    registry.set_ceiling("worker", actions=["files:read"], audiences=["andyur"])
    assert registry.get_ceiling("worker") == {"actions": ["files:read"],
                                              "audiences": ["andyur"]}
    registry.set_ceiling("worker", actions=[], audiences=[])
    assert registry.get_ceiling("worker") == {"actions": [], "audiences": []}
    registry.set_ceiling("worker", actions=None, audiences=None)
    assert registry.get_ceiling("worker") == {"actions": None, "audiences": None}


def test_set_ceiling_refuses_malformed_input_and_unknown_agents(env):
    """Loud at the edit, because the alternative is the operator discovering their
    typo as an unexplained outage in some agent's next run."""
    env.agent("worker2")
    with pytest.raises(ValueError):
        registry.set_ceiling("worker2", actions="files:read")     # a string, not a list
    with pytest.raises(ValueError):
        registry.set_ceiling("worker2", actions=["files:read", 7])
    with pytest.raises(ValueError):
        registry.set_ceiling("nosuchagent", actions=["files:read"])
    assert registry.get_ceiling("worker2") == {"actions": None, "audiences": None}


def test_permits_audience_uses_the_registry_not_the_callers_claim(env):
    env.agent("mailer")
    registry.set_ceiling("mailer", audiences=["billing"])
    assert registry.permits_audience("mailer", "billing") is True
    assert registry.permits_audience("mailer", "payroll") is False


# --- what an adversarial review found: terms that failed OPEN, and aliasing ----

@pytest.mark.parametrize("bad", ["files:write", 7, {"a": 1}, 3.5, True])
def test_an_unreadable_entitlement_denies_rather_than_grants_or_raises(bad):
    """A malformed term must fail CLOSED, and two different ways of getting this
    wrong were live.

    A str is iterable, so intersecting it exploded "files:write" into its
    CHARACTERS -- and against an unrestricted ceiling that returned every
    character as a granted action. A malformed input produced a GRANT. An int is
    not iterable, so it raised TypeError straight out of the authority
    computation, which is a crash on the one path whose whole job is to answer
    allow-or-not."""
    out = registry.narrow(entitlement=bad, pin=None,
                          ceiling={"actions": None}, audience=None)
    assert out["actions"] == [], f"{bad!r} was not denied: {out['actions']}"


@pytest.mark.parametrize("bad", ["nope", 7, ["a"]])
def test_an_unreadable_ceiling_denies(bad):
    out = registry.narrow(entitlement=["files:read"], pin=None,
                          ceiling=bad, audience=None)
    assert out["actions"] == []


def test_a_readable_entitlement_is_unaffected_by_the_guard():
    """The guard must not make everything deny -- that would be a 'secure' module
    by being a broken one."""
    out = registry.narrow(entitlement=["files:read", "files:write"], pin=None,
                          ceiling={"actions": ["files:read"]}, audience=None)
    assert out["actions"] == ["files:read"]


def test_the_result_never_aliases_the_caller_on_any_path():
    """The docstring promises inputs are never mutated and the caller cannot hold
    a reference into the sealed result. The audience-REFUSED branch broke that
    promise: the normal path returned dict(pin) but the early return handed back
    the caller's own object, so a caller mutating "their" pin reached inside a
    grant that had already been decided.

    An adversarial reviewer's mutation exploited exactly this shape -- an
    aliasing fast path that returned the caller's entitlement list verbatim --
    and the suite did not notice."""
    ent = ["files:read"]
    pin = {"account": "447"}

    granted = registry.narrow(entitlement=ent, pin=pin,
                              ceiling={"actions": None}, audience=None)
    # The UNPINNED, unrestricted-ceiling shape specifically. The reviewer's
    # surviving mutation was a fast path guarded on `not pin`, so a test that
    # only ever passes a truthy pin never reaches it -- which is how it survived
    # a suite that already claimed to cover aliasing.
    unpinned_ent = ["files:read"]
    unpinned = registry.narrow(entitlement=unpinned_ent, pin=None,
                               ceiling={"actions": None}, audience=None)
    unpinned_ent.append("files:write")
    assert "files:write" not in (unpinned["actions"] or []), (
        "the unpinned fast path returned the caller's entitlement list verbatim")
    refused = registry.narrow(entitlement=ent, pin=pin,
                              ceiling={"audiences": ["other"]}, audience="nope")

    ent.append("files:write")
    pin["account"] = "999"

    assert "files:write" not in (granted["actions"] or []), "the grant aliased the caller's list"
    assert granted["pin"] is None or granted["pin"]["account"] == "447", \
        "the grant aliased the caller's pin"
    assert refused["pin"] is None or refused["pin"]["account"] == "447", \
        "the audience-refused path aliased the caller's pin"


# --- internal control-plane authority is not bounded by the tool ceiling -----
# ADR-010: reading the agent's own mind (files:read) and writing its own
# memory/tasks/messages are INTERNAL authority. The registry ceiling bounds
# DELEGATED tool authority, so it must not strip these -- a live regression
# (found in the SRE gate) 403'd every registry run on GET /context because its
# tool-only ceiling lacked files:read.

def test_own_storage_survives_a_tool_only_ceiling():
    """The exact live scenario: the run asked for files:read/write plus tool
    actions; the agent's registry ceiling grants only the tool actions. Delegated
    actions stay bounded by the ceiling, but the internal own-storage actions are
    restored -- otherwise the run cannot load its own prompt (GET /context 403s)
    nor record its transcript, summary and memory (PUT .../files/... 403s)."""
    requested = ["files:read", "files:write", "obs:read",
                 "tickets:read", "tickets:comment", "tickets:close"]
    ceiling = {"actions": ["obs:read", "tickets:read", "tickets:comment"],
               "audiences": None}
    narrowed = registry.narrow(requested, None, ceiling, None)["actions"]
    # the tool ceiling did its job: own-storage AND the extra tool actions are gone
    assert "files:read" not in narrowed and "files:write" not in narrowed \
        and "tickets:close" not in narrowed
    restored = registry.with_internal_actions(requested, narrowed)
    assert "files:read" in restored                       # own-context read regained
    assert "files:write" in restored                      # own-storage write regained too
    assert "tickets:close" not in restored                # refused tool action not resurrected
    assert set(restored) == {"files:read", "files:write",
                             "obs:read", "tickets:read", "tickets:comment"}


def test_files_read_is_not_invented_when_not_requested():
    """Restoration can only add back the read a run declared, never grant it to a
    run that never asked -- and it never touches delegated actions."""
    restored = registry.with_internal_actions(["obs:read"], ["obs:read"])
    assert "files:read" not in restored
    assert set(restored) == {"obs:read"}


def test_an_unrestricted_result_stays_unrestricted():
    """`actions is None` means no action model restricts the run; there is
    nothing for the ceiling to have stripped, so nothing to restore."""
    assert registry.with_internal_actions(["files:read"], None) is None


def test_an_unrestricted_request_still_regains_its_own_storage():
    """A run with no explicit scope (`requested is None`) is unrestricted, so it
    implies the whole own-storage class; a tool ceiling that narrowed it to the
    tool actions must not leave it unable to read its context or record its run."""
    restored = registry.with_internal_actions(None, ["obs:read"])
    assert set(restored) == {"obs:read", "files:read", "files:write"}


def test_the_internal_set_is_own_storage_read_and_write_only():
    """The set is deliberately the own-storage pair, files:read and files:write.
    A mutation that slipped in a delegated tool action or a cross-agent delegation
    action would make the ceiling un-enforceable for it -- caught here."""
    assert registry.INTERNAL_ACTIONS == frozenset({"files:read", "files:write"})
    for governed in ("obs:read", "tickets:write",
                     "telemetry:read", "tasks:write", "messages:write"):
        assert governed not in registry.INTERNAL_ACTIONS


def test_a_qualified_internal_action_stays_governed_by_the_ceiling():
    """`files:read@account=447` names external/pinned DATA, not the agent's own
    mind, so it is delegated and stays bounded -- only the bare action is
    internal."""
    restored = registry.with_internal_actions(
        ["files:read@account=447"], ["obs:read"])
    assert "files:read@account=447" not in restored
    assert set(restored) == {"obs:read"}


def test_a_qualified_own_storage_write_stays_governed_by_the_ceiling():
    """The write half obeys the same rule as the read half: a QUALIFIED
    `files:write@account=447` writes external/pinned data, not the agent's own
    mind, so it stays ceiling-governed -- only the bare own-storage write is
    internal."""
    restored = registry.with_internal_actions(
        ["files:write@account=447"], ["obs:read"])
    assert "files:write@account=447" not in restored
    assert set(restored) == {"obs:read"}


def test_the_delegated_tool_token_never_carries_own_storage_write():
    """The safety boundary the write-restoration rests on: restoring files:write
    to the RUN scope must not leak it into the DELEGATED tool authority. The tool
    mint uses `narrow` directly (never with_internal_actions), so a tool-only
    ceiling that lacks files:write still strips it from the minted tool token,
    even though the run itself holds it for its own storage."""
    ceiling = {"actions": ["obs:read"], "audiences": None}
    delegated = registry.narrow(["files:write", "obs:read"], None, ceiling, "andyur")
    assert "files:write" not in delegated["actions"]
    assert delegated["actions"] == ["obs:read"]

"""The agent registry ceiling, and the authority intersection it belongs to.

A run's authority is a conjunction of four independent terms:

    authority = entitlement AND pin AND ceiling AND audience

  entitlement  WHO the run acts for, and what that human may do at all (the OIDC
               `sub` and the entitlements attached to it -- see oidc.py).
  pin          WHAT the work is ABOUT: the canonical resources it may touch, e.g.
               {"account": "447"}. Asserted by an authenticated caller and sealed
               server-side; the one thing it must never be is model-supplied.
  ceiling      WHAT THIS AGENT MAY EVER HOLD, independent of how entitled its user
               is. This module owns it: `agents.ceiling_actions` /
               `agents.ceiling_audiences`.
  audience     WHERE the resulting token may be spent. One audience per token, so
               a grant minted for one target cannot be replayed at another.

The ceiling is the term that makes a pipeline safe. A read-only classifier standing
in front of a write-capable specialist is only contained if scope is RE-DERIVED
against each agent's own ceiling at mint time. If scope is instead passed hand to
hand, the classifier -- the agent that reads attacker-authored text for a living --
inherits whatever the entitled user could do, and the specialist's write capability
becomes reachable from the untrusted end of the pipeline.

THE CRITICAL PROPERTY of `narrow()` is that it can only ever narrow. The ACTION
FOLD achieves that by construction: it is a fold of set intersections, and an
intersection has no expression for "add something the terms did not both
contain". It is deliberately not a permission list plus a check that the list
stayed inside its bounds, because a check can be skipped, reordered, or forgotten
on a new path, and a missing intersection step simply yields a narrower answer
instead of a wider one.

BE PRECISE ABOUT THE SCOPE OF THAT CLAIM, because an earlier version of this
docstring was not. "By construction" covers the fold. It does NOT cover the two
guards that run before it -- the malformed-term check and the audience conjunct
-- which are ordinary early returns that a future edit could bypass, and it does
not make the function safe to call with the wrong ceiling. `narrow()` is public
and takes `ceiling` as an argument, so nothing here prevents a caller passing a
ceiling that is not the agent's; use `authority_for()`, which reads the ceiling
itself and gives the caller no say in it. The construction argument is about what
the fold can express, not about what every caller will do.

A term the module cannot READ is denied rather than ignored, and that is a
separate rule from the fold. A str is iterable, so an unguarded intersection
exploded an entitlement of "files:write" into its characters and, against an
unrestricted ceiling, returned each of them as a granted action -- a malformed
input producing a GRANT. An int was not iterable and raised straight out of the
authority computation. Unreadable is never unrestricted, and never a crash on the
one path whose whole job is to answer allow-or-not.

`tokenexchange._narrow()` already states this rule for two terms (parent scope vs
requested scope) and this module keeps its exact semantics -- `None` or a list
containing `"*"` means "this term restricts nothing", and anything requested beyond
a restricting term is silently dropped rather than raising. What is generalised here
is only the arity: four terms instead of two, and one of them (the pin) restricts
RESOURCES rather than actions.

Pin syntax. An action may carry an optional resource qualifier after "@", as
comma-separated key=value pairs:

    "files:read"                 applies to whatever the run is pinned to
    "files:read@account=447"     applies only to account 447

An unqualified action inherits the run's pin, which travels alongside the actions in
the returned authority. A qualified action survives only if every key it names is
present in the pin AND agrees with it: a qualifier naming a key the pin does not
speak to is UNVERIFIABLE, and an unverifiable claim about which resource an action
touches is exactly the widening this design exists to prevent, so it is dropped.

No HTTP lives here. Endpoint wiring is deliberately elsewhere; everything an
endpoint (or the mint path) needs is a function in this module, so the ceiling can
be wired in without any of these rules moving.
"""

from __future__ import annotations

import json
import logging

from .. import db

log = logging.getLogger(__name__)

# The deny-everything ceiling. Returned wherever a ceiling cannot be established:
# an unknown agent, or a column whose contents do not parse as a list of strings.
# Fail CLOSED, because the alternative reading of "we could not determine this
# agent's limits" is "this agent has no limits", and that sentence is the whole
# vulnerability. A bricked agent is a visible operational problem; a silently
# unbounded one is not.
DENY_ALL: dict = {"actions": [], "audiences": []}


# --- reading and writing an agent's ceiling ---------------------------------

def _parse_terms(raw, agent_name: str, column: str):
    """One ceiling column -> a list of strings, `None` (unrestricted), or `[]`
    (deny all). Never raises: this is called on the authorization path, where an
    exception escaping into a mint would be a 500 on a security decision.

    The three cases are deliberately not collapsed:

      NULL / blank   no ceiling has been configured for this agent -> None, i.e.
                     this term restricts nothing. A migration adds the column as
                     NULL, and some writers spell "unset" as an empty string, so
                     both have to mean the same benign thing or upgrading a live
                     database would brick every existing agent.
      valid list     the ceiling, with non-string members dropped.
      anything else  malformed -> DENY ALL. Not "unrestricted", and not an
                     exception: a ceiling we cannot read is a limit we cannot
                     honour, and honouring it as "no limit" would turn a typo in
                     an operator's JSON into universal authority.
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        if not raw.strip():
            return None
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            log.error("agent %s has malformed %s; denying all", agent_name, column)
            return []
    if not isinstance(raw, list):
        log.error("agent %s has non-list %s (%s); denying all",
                  agent_name, column, type(raw).__name__)
        return []
    # A non-string member cannot match anything an action or audience is compared
    # against, so dropping it narrows and never widens.
    return [t for t in raw if isinstance(t, str)]


class UnknownAgent(Exception):
    """No registry row exists for this actor, so no ceiling can be read for it.

    Raised only by `authority_for`, and deliberately NOT folded into DENY_ALL.
    Both mean "grant nothing", but only one of them is an operator error worth a
    distinct message: a ceiling that denies everything was configured that way on
    purpose, whereas an unknown agent means the caller named something that does
    not exist."""


class StoreUnavailable(Exception):
    """The registry could not be read at all, so no ceiling can be established.

    Deliberately NOT folded into DENY_ALL. Both refuse, but a store outage is an
    operational fault an operator must see and fix, whereas DENY_ALL is a
    configured answer -- and a mint that reports "this agent may do nothing"
    during a database blip sends whoever is on call hunting for a policy change
    that never happened."""


def _read_ceiling_row(agent_name: str):
    """One query, returning the row or None. The two public readers share it so
    that "does this agent exist" and "what is its ceiling" are answered from the
    SAME read. Asking twice let an agent be deleted BETWEEN the two questions,
    which turned a legible "unknown actor" error into a silently empty grant --
    exactly the outcome the existence check was added to prevent.

    A store failure is re-raised as StoreUnavailable rather than escaping raw, so
    the one code path whose job is to answer allow-or-not has a typed answer for
    "could not find out" that is neither a crash nor a grant."""
    try:
        with db.connect() as c:
            return c.execute(
                "SELECT ceiling_actions, ceiling_audiences FROM agents WHERE name = ?",
                (agent_name,),
            ).fetchone()
    except Exception as exc:   # noqa: BLE001 -- any store failure is the same answer
        log.error("could not read the ceiling for %s: %s", agent_name, exc)
        raise StoreUnavailable(str(exc)) from exc


def _ceiling_from_row(row, agent_name: str) -> dict:
    return {
        "actions": _parse_terms(row["ceiling_actions"], agent_name, "ceiling_actions"),
        "audiences": _parse_terms(row["ceiling_audiences"], agent_name,
                                  "ceiling_audiences"),
    }


def get_ceiling(agent_name: str) -> dict:
    """This agent's ceiling: {"actions": [...] | None, "audiences": [...] | None}.

    `None` for either term means "no ceiling configured", i.e. that term restricts
    nothing. An UNKNOWN agent is not unrestricted -- it gets DENY_ALL, because an
    agent with no registry row has no operator-recorded limits at all, and the
    absence of a record must not read as the absence of a bound."""
    row = _read_ceiling_row(agent_name)
    if row is None:
        log.warning("ceiling requested for unknown agent %s; denying all", agent_name)
        return dict(DENY_ALL)
    return _ceiling_from_row(row, agent_name)


def _validate(terms, what: str):
    """Operator input on the WRITE path, where failing loudly is correct. Storing
    a malformed ceiling would be read back as DENY_ALL later -- safe, but the
    operator would learn about their typo as a mystery outage in some agent's next
    run, long after the edit. Refusing at the point of the edit is the same
    protection with the failure attached to its cause."""
    if terms is None:
        return None
    if isinstance(terms, str) or not isinstance(terms, (list, tuple)):
        raise ValueError(f"{what} must be a list of strings or None")
    if not all(isinstance(t, str) for t in terms):
        raise ValueError(f"{what} must be a list of strings or None")
    return list(terms)


def set_ceiling(agent_name: str, actions=None, audiences=None) -> None:
    """Operator-level write of an agent's ceiling. `None` clears that term (the
    agent is then unrestricted by it); `[]` denies everything for that term.

    There is intentionally no HTTP surface and no run-token path to this function.
    A ceiling that the holder can raise is not a ceiling, so the only caller that
    may ever reach it is an operator-authenticated one, and the wiring that
    enforces that lives outside this module."""
    actions = _validate(actions, "ceiling actions")
    audiences = _validate(audiences, "ceiling audiences")
    with db.connect() as c:
        cur = c.execute(
            "UPDATE agents SET ceiling_actions = ?, ceiling_audiences = ? "
            "WHERE name = ?",
            (None if actions is None else json.dumps(actions),
             None if audiences is None else json.dumps(audiences),
             agent_name),
        )
        if cur.rowcount == 0:
            # Silence here would leave the operator believing a limit is in force
            # that no row carries.
            raise ValueError(f"no such agent: {agent_name}")


# --- the intersection -------------------------------------------------------

def _unrestricted(term) -> bool:
    """Whether a term restricts nothing. Same spelling as tokenexchange._narrow:
    `None` (no such model active) or a list containing `"*"`."""
    return term is None or "*" in term


def _terms(value, name):
    """A term as a list, as `None` for unrestricted, or DENIAL if unreadable.

    THE STRING IS THE TRAP, and it is why this exists rather than trusting the
    caller. A str is iterable, so `[x for x in a if x in b]` over an entitlement
    of "files:write" silently explodes it into its CHARACTERS and intersects
    those -- which with an unrestricted ceiling returned every character as a
    granted action. A malformed input produced a GRANT. An int was worse in a
    different direction: not iterable, so it raised TypeError out of the
    authority computation entirely.

    Both are the same mistake: a term we cannot read must deny, exactly as a
    malformed pin already does. Unreadable is never unrestricted, and never a
    crash on a path whose whole job is to answer allow-or-not."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [x for x in value if isinstance(x, str)]
    log.error("malformed %s (%s); denying all", name, type(value).__name__)
    return []


def _intersect(a, b):
    """Fold step: the terms both `a` and `b` allow. If either restricts nothing,
    the other one stands alone. This is the ONLY operation the action fold uses,
    which is what makes widening unrepresentable -- there is no branch here that
    can produce a member neither input had."""
    if _unrestricted(a):
        return None if b is None else list(b)
    if _unrestricted(b):
        return list(a)
    return [x for x in a if x in b]


def _qualifier(action: str) -> dict | None:
    """The resource qualifier on an action, or None when it carries no "@" part.

    A malformed qualifier ("files:read@nonsense") returns an empty dict, which
    matches nothing a real pin can satisfy, so it is dropped by _pin_allows. It
    deliberately does not raise: unparseable is exactly the case that must not
    become unrestricted, and the caller cannot tell the difference between a typo
    and an attempt."""
    if "@" not in action:
        return None
    _, _, qual = action.partition("@")
    out: dict = {}
    for part in qual.split(","):
        key, sep, value = part.partition("=")
        if not sep or not key.strip():
            return {}   # malformed: matches no pin
        out[key.strip()] = value.strip()
    return out


def _pin_allows(pin, action: str) -> bool:
    """Whether `action` is within the run's pin.

    An unqualified action inherits the pin and is always allowed -- the pin still
    travels with the authority, so it constrains that action downstream. A
    qualified action must name only keys the pin speaks to, and must agree with
    the pin on every one of them; a qualifier mentioning a key the pin does not
    carry is unverifiable and therefore refused."""
    qual = _qualifier(action)
    if qual is None:
        return True
    if not qual:
        return False    # malformed qualifier
    return all(k in pin and pin[k] == v for k, v in qual.items())


# A run reading its OWN agent's mind. This is INTERNAL -- reading the agent's own
# per-agent context (GET /agents/{name}/context needs files:read), not an
# external tool -- and EVERY run of an agent needs it to load its prompt. So the
# DELEGATED tool ceiling has no business stripping it: a tool-only ceiling that
# lacks files:read 403s the whole run before it can start (ADR-010).
#
# Own-storage authority is the WHOLE class, read and write alike: a run reads its
# prompt and context, and it writes its transcript, summary and memory -- the
# record of its own mind. ADR-010 puts context/memory squarely in the INTERNAL
# plane, which Andyur governs; the DELEGATED tool ceiling has no business over it.
# files:read landed first (the /context regression forced it); files:write is the
# other half of the same class, forced by the live SRE run, whose runner 403'd on
# PUT runs/<id>/transcript.jsonl, prompt.md, summary.json and memory/short_term.md
# under a tool-only ceiling -- so the agent could act but not record what it did.
#
# What stays governed, deliberately:
#   - the DELEGATED tool token still never carries files:write. Only the run scope
#     is restored (coordinator.with_internal_actions); the tool mint uses `narrow`
#     directly, which strips it -- test_ceiling pins that a tool token cannot write.
#   - tasks:write / messages:write create work for and send text to OTHER agents;
#     that is delegation, which the ceiling and the delegation allow-list govern.
#   - qualified variants like `files:write@account=447` name external/pinned DATA,
#     not the agent's own mind, so they stay ceiling-governed -- only the BARE
#     own-storage action is internal. (Same rule already applied to files:read.)
INTERNAL_ACTIONS = frozenset({"files:read", "files:write"})


def with_internal_actions(requested, narrowed_actions):
    """Restore the internal own-storage actions the tool ceiling stripped in
    `narrow`. See INTERNAL_ACTIONS.

    `narrowed_actions is None` means no action model restricts the run at all, so
    every internal action is already implied -- nothing to restore. Otherwise the
    result is the ceiling-narrowed delegated actions PLUS the internal actions the
    run holds: the ones it explicitly requested, or -- for an UNRESTRICTED request
    (`requested is None`) -- all of them, since an unrestricted run implies every
    action and only the tool ceiling should have narrowed it. This can only add
    back own-storage authority, never a delegated action the ceiling refused.
    Pure: inputs unmutated, a fresh sorted list out.
    """
    if narrowed_actions is None:
        return None
    if requested is None:
        internal = set(INTERNAL_ACTIONS)          # unrestricted implies all internal
    else:
        internal = {a for a in _terms(requested, "requested") if a in INTERNAL_ACTIONS}
    return sorted(set(narrowed_actions) | internal)


def narrow(entitlement, pin, ceiling, audience) -> dict:
    """The effective authority: entitlement AND pin AND ceiling AND audience.

    Returns {"actions": [...] | None, "pin": {...} | None, "audience": str | None}.
    `actions is None` means no action model restricts this run; `actions == []`
    means it may do nothing, and consumers must read the empty list as a denial
    rather than as "unset" (pdp.py already distinguishes them this way).

    Each argument is a bound, never a request:
      entitlement  list | None -- what the user may do at all.
      pin          dict | None -- the resources the work is about. `None`/`{}` =
                   unpinned, which restricts nothing. Anything else that is not a
                   dict is MALFORMED and denies everything: silently ignoring a
                   pin we cannot read is precisely the widening this prevents.
      ceiling      {"actions": ..., "audiences": ...} | None -- see get_ceiling.
      audience     str | None -- the single target this grant is for. If the
                   ceiling forbids it, the WHOLE authority is empty: audience is a
                   conjunct, and a conjunction with a false term is false, not
                   "the same authority pointed somewhere else".

    Inputs are never mutated; the caller's lists are copied, so a caller holding a
    reference to the entitlement list cannot observe (or edit) the sealed result.
    """
    if ceiling is not None and not isinstance(ceiling, dict):
        log.error("malformed ceiling (%s); denying all", type(ceiling).__name__)
        return {"actions": [], "pin": None, "audience": None}
    ceiling = ceiling or {}
    ceiling_actions = _terms(ceiling.get("actions"), "ceiling actions")
    ceiling_audiences = _terms(ceiling.get("audiences"), "ceiling audiences")
    entitlement = _terms(entitlement, "entitlement")

    if pin is not None and not isinstance(pin, dict):
        log.error("malformed pin (%s); denying all", type(pin).__name__)
        return {"actions": [], "pin": None, "audience": None}

    # Term 4 first: a refused audience empties the grant, so there is nothing to
    # compute. Checked as "permitted", never as "substitute a permitted one" --
    # rewriting the audience would hand the caller a token for a target it was
    # not asking about and was not granted.
    if audience is not None and not _audience_permitted(ceiling_audiences, audience):
        log.info("audience %r is above the ceiling; granting nothing", audience)
        # dict(pin), NOT pin: the normal path copies, and returning the caller's
        # own object here handed them a reference into the sealed result on one
        # branch and not the other -- so a caller mutating "their" pin could
        # reach inside a grant that had already been decided.
        return {"actions": [], "pin": dict(pin) if pin else pin, "audience": None}

    # Terms 1 and 3, as a fold of intersections. Adding a future term means adding
    # another _intersect step, which can only make the answer smaller.
    actions = None
    for term in (entitlement, ceiling_actions):
        actions = _intersect(actions, term)

    # Term 2. With `actions is None` there is no list to filter, and the pin still
    # travels in the result, so the resource bound is carried either way.
    if actions is not None and pin:
        actions = [a for a in actions if _pin_allows(pin, a)]

    return {
        "actions": actions,
        "pin": dict(pin) if pin else pin,
        "audience": audience,
    }


def _audience_permitted(ceiling_audiences, audience) -> bool:
    """Whether one audience is inside an audience ceiling. An empty audience is
    never permitted: a token with no audience is replayable at every target, which
    is the failure the audience term exists to prevent."""
    if not audience:
        return False
    if _unrestricted(ceiling_audiences):
        return True
    return audience in ceiling_audiences


def permits_audience(agent_name: str, audience: str) -> bool:
    """May this agent EVER hold a token for `audience`? Read from the registry,
    not from anything the run said about itself."""
    return _audience_permitted(get_ceiling(agent_name)["audiences"], audience)


def authority_for(agent_name: str, entitlement, pin, audience) -> dict:
    """`narrow()` with the ceiling read from the registry rather than supplied.

    This is the function a mint path should call. There is no parameter through
    which a caller can offer its own ceiling, so "the run supplied a wider
    ceiling" is not a request that can be expressed -- which is a stronger
    guarantee than validating a ceiling the run handed us.

    Raises UnknownAgent if there is no registry row, from the SAME read that
    produces the ceiling, so a caller cannot check existence and then compute
    authority against a row that stopped existing in between."""
    row = _read_ceiling_row(agent_name)
    if row is None:
        raise UnknownAgent(
            f"no registry entry for agent '{agent_name}': a ceiling cannot be "
            "read, so no authority can be derived for it")
    return narrow(entitlement, pin, _ceiling_from_row(row, agent_name), audience)

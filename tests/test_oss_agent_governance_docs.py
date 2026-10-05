"""Keep the OSS-agent governance position from being re-derived, and keep the
documents that state it TRUE as the code moves under them.

The sibling of `test_egress_architecture_docs.py`, and for the same reason: the
third-party-reach question was answered once by the code's silence and read as a
decision for weeks.

The first version of this file only read `.md` files, and a reviewer killed it
with one mutation: fixing `exec_v1_gate.py` to bound the network makes ADR-011
D11 and production-gaps 24 FALSE, and every test here stayed green. A docs test
that cannot notice the fix it asks for is a test that turns its own documents
into lies the day someone does the work. So the claims ABOUT CODE are pinned
from both ends: the document says it, and the code still matches. When the gate
is fixed, `test_the_gate_still_has_the_hole_the_docs_describe` goes red and the
prose has to be corrected in the same change.
"""

import importlib.util
import re
import types

import pytest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    """The document's text, wherever it now lives.

    Reviews, plans, gap registries and feasibility records moved OUT of the
    published subtree into ../docs-internal/ on 2026-09-11: the public repo is a
    fresh `git init` over agentic-platform/ alone, and those are internal. These
    tests keep documents and code honest with each other, so they must still run
    in the repository that HAS those documents -- hence the second lookup -- and
    must SKIP, naming why, in a clone that does not. Failing there would punish a
    reader for lacking a file they were never meant to receive.
    """
    published = ROOT / rel
    if published.is_file():
        return published.read_text()
    internal = ROOT.parent / "docs-internal" / Path(rel).name
    if internal.is_file():
        return internal.read_text()
    pytest.skip(f"{rel} is an internal document (reviews, plans and gap "
                f"registries are not published) and is absent here")


_HEADING = re.compile(r"^#{2,4} ", re.M)


def _section(rel: str, heading_prefix: str) -> str:
    """The flattened text of ONE section of a document.

    A reviewer named the residual that no single substring pin can close:
    CONTEXT INVERSION. The sentence stays present verbatim but moves under a
    heading like "alternatives we rejected", so every word is still there and
    the document now says the opposite. Scoping a claim to the section that
    must contain it closes that, and pairs with `_states` below.
    """
    text = _read(rel)
    heads = [(m.start(), len(m.group(0).strip())) for m in _HEADING.finditer(text)]
    for i, (start, depth) in enumerate(heads):
        if not text[start:text.index("\n", start)].startswith(heading_prefix):
            continue
        # A section OWNS its subsections. Ending at the next heading of ANY
        # depth truncates a `##` section at its first `###`, which silently
        # narrows what the pin covers -- and a pin that covers less than the
        # reader thinks is the whole failure mode this helper exists to stop.
        end = len(text)
        for later_start, later_depth in heads[i + 1:]:
            if later_depth <= depth:
                end = later_start
                break
        return " ".join(text[start:end].split())
    raise AssertionError(f"{rel}: no section beginning {heading_prefix!r}")


def _states(section: str, claim: str, *negations: str) -> None:
    """Assert a claim is made here AND that its reversal is not made here.

    Present-only is satisfiable by the negation living beside it; absent-only is
    satisfiable by deleting the whole passage. The PAIR is what pins polarity.
    """
    assert claim in section, f"claim missing: {claim!r}"
    for negation in negations:
        assert negation not in section, f"reversal present: {negation!r}"


def _flat(rel: str) -> str:
    """A document with its line wrapping collapsed.

    A phrase pin should break when someone reverses the sentence, not when
    someone reflows the paragraph. Whitespace-insensitive matching keeps the
    polarity these tests exist to protect while dropping the churn.
    """
    return " ".join(_read(rel).split())


# --------------------------------------------------------------------------
# The position itself.
# --------------------------------------------------------------------------

def test_the_position_is_stated_in_the_contract_not_left_to_the_surface():
    adr = _read("docs/adr-011-exec-v1-stock-process-contract.md")
    assert "D11 — Third-party reach" in adr
    assert "only through a\nbinding an approver accepted" in adr
    assert "never holding the credential" in adr
    assert "Undeclared\nreach stays impossible by construction" in adr


def test_the_settled_decision_records_what_was_never_actually_decided():
    decided = _read("docs/decisions.md")
    assert "A stock OSS agent may reach a third party" in decided
    assert '"The workload cannot reach\n   anything" is not the decision' in decided


def test_one_custodian_and_the_three_documents_agree_on_which():
    """The blocker a reviewer found: `decisions.md` said the gateway holds the
    credential and ADR-013 said it never does. The settled-decisions file is
    what the next session reads first, so a contradiction there is worse than
    one anywhere else. Pin the agreement, not one side of it."""
    decided = _read("docs/decisions.md")
    adr = _read("docs/adr-013-third-party-reach-for-stock-workloads.md")
    assert "NEVER holds a vendor\n   credential" in decided
    assert "the gateway in D4 never holds a vendor credential at" in adr
    # And the negation must not survive anywhere in either file.
    for doc, name in ((decided, "decisions.md"), (adr, "adr-013")):
        assert "gateway, which hold the" not in doc, name


def test_the_vendor_is_named_as_the_enforcement_point_not_a_ceiling():
    """The clause with no mechanism is the one a later edit can silently
    delete, so D5 gets pinned harder than the clauses that have one. `ceiling`
    is enforced at the token mint on the `managed` path; a brokered binding
    never mints, so the word must not appear as this path's control."""
    ADR = "docs/adr-013-third-party-reach-for-stock-workloads.md"
    d5 = _section(ADR, "## D5 — The vendor is the enforcement point")
    _states(d5, "Do not call it a ceiling.",
            "the ceiling is the enforcement point of this path")
    _states(d5, "IAM policy or permission set")
    _states(d5, "`AccessDenied`")
    # Read-only is the wrong axis, and the reason has to survive with it.
    _states(d5, "Read-only is the wrong axis", "Read-only is the right axis")
    _states(d5, "`WithDecryption` are both classified Read")
    # The refused class is a decision, not an oversight.
    _states(d5, "the binding is refused and the vendor is reached through a "
                "governed MCP tool surface")


def test_third_party_reach_is_brokered_per_run_and_off_by_default():
    adr = _read("docs/adr-013-third-party-reach-for-stock-workloads.md")
    for transport in ("MCP tool binding", "vendor-SDK binding", "plain HTTP binding"):
        assert transport in adr, transport
    d4 = _section("docs/adr-013-third-party-reach-for-stock-workloads.md",
                  "## D4 — External destinations terminate at an egress gateway")
    _states(d4, "A shared gateway is a confused deputy unless it knows who is calling.",
            "is not a confused deputy")
    _states(d4, "run X509-SVID")
    assert "aws-sigv4-proxy" in adr
    assert "the workload must not sign at all" in adr
    assert "byte-identical to today's" in adr
    # D4 must not claim parity with a control that is empty for this transport.
    assert "Do not describe this as parity with an existing control." in adr


def test_certification_can_ask_for_inputs_and_a_failed_run_can_ask_for_review():
    adr = _read("docs/adr-012-oss-agent-certification.md")
    assert "`changes_requested`" in adr
    assert "A failed run may request a manifest review" in adr
    assert "The platform attaches the run-derived facts, never the requester" in adr
    _states(_flat("docs/adr-012-oss-agent-certification.md"),
            "Filing a request does not suspend anything",
            "Filing a request suspends")
    # ...which is only safe because a separate authorized lever exists.
    assert "separate, authorized SUSPEND action" in adr
    assert "untrusted workload output" in adr
    # And the honest limit of that marking.
    assert "not be DERIVABLE from the summary alone" in adr
    assert "An empty observation is only evidence if something measured it" in adr
    assert "Revocation must reach launches" in adr
    assert "revocation_unavailable" in adr


def test_the_five_state_report_vocabulary_is_closed_and_named():
    adr = _read("docs/adr-012-oss-agent-certification.md")
    for state in ("DECLARED", "OBSERVED", "REFUSED", "NOT EXERCISED", "NOT MEASURED"):
        assert state in adr, state
    assert "are the two states the artifacts of the time" in adr


# --------------------------------------------------------------------------
# The claims about CODE, pinned from both ends.
# --------------------------------------------------------------------------

def _gate_module():
    """The conformance gate, imported for real.

    Loaded rather than read as text because the claim under test is about what
    the gate DOES, and every string-level version of this assertion has been
    one abstraction short of that.
    """
    spec = importlib.util.spec_from_file_location(
        "exec_v1_gate", ROOT / "infra/byoa-spike/exec_v1_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Docker's own alias set for the flag that constrains a container's network.
# `--net` is not redundant with `--network`: Docker accepts both, and a fix
# written with either really does constrain the container (verified by running
# it: `docker run --rm --net none alpine ip -o addr show` reports loopback
# only). A reader who deletes one as redundant reintroduces the gap.
_NETWORK_FLAGS = ("--network", "--net")


def test_the_gate_bounds_the_network_and_measures_it():
    """production-gaps 24 said the gate did not bound the workload's network and
    that E3b could pass vacuously. Both are now closed, so this test asserts the
    NEW truth from both ends and reddens if either half regresses.

    The previous version of this test is the lesson. It asserted no `--network`
    flag in `run_flags()`, and when the fix landed it stayed GREEN, because
    `run_flags` only emits the flag once a bounded network EXISTS and the test
    inspected the unbound default. It caught the E3b wording and missed the
    network entirely. Asserting the default path proves nothing about the path
    the gate actually takes.
    """
    gate = _gate_module()

    def argv_with(bound):
        previous = gate._BOUND
        gate._BOUND = bound
        try:
            launch = types.SimpleNamespace(
                stdin=None, env=[], command=("sh", "-c", "true"), image="alpine:3.20")
            return gate.workload_argv("probe", launch, "probe-volume")
        finally:
            gate._BOUND = previous

    # Bound: the workload is on the internal network and the advertised name
    # points at the relay, not at the host.
    bound = argv_with({"network": "n", "relay": "r", "relay_ip": "10.0.0.2", "ports": [1, 2]})
    assert "--network" in bound and "n" in bound
    assert f"{gate.ADVERTISE}:10.0.0.2" in bound
    assert f"{gate.ADVERTISE}:host-gateway" not in bound

    # Unbound: the host route, which is the shape the gate must NOT run in.
    assert f"{gate.ADVERTISE}:host-gateway" in argv_with(None)

    # The measurement exists and fails closed on a leak or a dead positive
    # control. The edges are covered in test_exec_v1_gate_containment.py; this
    # only proves the gate still HAS the check the documents describe.
    assert set(gate.MUST_DENY) >= {"internet-ip", "external-dns", "host-gateway-direct"}
    leak = "\n".join(["REACHED allowed-front", "REACHED allowed-mcp",
                       "REACHED internet-ip", "DENIED public-dns",
                       "DENIED external-dns", "DENIED host-gateway-direct"])
    assert gate.containment_verdict(leak)["ok"] is False

    # E3b fails closed on a declared-but-unused grant.
    grant = types.SimpleNamespace(server="observability", tools=("read_logs",))
    assert gate.tool_traffic_verdict([], [], (grant,))["ok"] is False
    assert gate.tool_traffic_verdict([], [], ())["ok"] is True

    # And the documents say so, in both places that used to say the opposite.
    adr = _flat("docs/adr-011-exec-v1-stock-process-contract.md")
    _states(adr, "the gate bounds the workload's network and records the destinations it saw",
            "never measured by an `exec/v1` conformance run",
            "passes vacuously when a workload makes no tool request")
    gaps = _flat("docs/production-gaps.md")
    _states(gaps, "The conformance report states absences it never measured",
            "so \"made no other network calls\" was never measured")


# The five-state vocabulary ADR-012 D10 defines. Used here AS a vocabulary
# rather than as prose, which is what it is for.
_STATE_TOKENS = ("NOT MEASURED", "NOT EXERCISED", "OBSERVED", "REFUSED", "DECLARED")
# The one escape from the marker rule: an explicit forward reference. A document
# may describe a gate property that does not exist yet if it names the change
# that delivers it, because that is a statement about another branch and is
# checkable as such.
_FORWARD_REFERENCE = "PR #33"


def gate_state() -> dict:
    """The gate's real state, derived from the gate, in one place.

    THE single source of truth for what the conformance gate does about the
    network. Documents may not describe this except by naming a state from
    `_STATE_TOKENS`, and the test compares that token to this. Two booleans,
    computed from the live argv and the live check wording, never from prose.
    """
    gate = _gate_module()
    launch = types.SimpleNamespace(stdin=None, env=[], command=("sh", "-c", "true"),
                                   image="alpine:3.20")

    # Probe the BOUND path, not the default one. An earlier version of this read
    # `workload_argv` with no bounded network established and concluded the gate
    # does not bound anything -- which is the same defect the gate's own test
    # had: `run_flags` only emits the flag once a network exists, so the default
    # argv proves nothing about the path the gate actually takes. The question
    # here is whether the gate HAS the mechanism and uses it.
    has_mechanism = callable(getattr(gate, "bound_network", None))
    previous = getattr(gate, "_BOUND", None)
    try:
        gate._BOUND = {"network": "probe-net", "relay": "probe-relay",
                       "relay_ip": "10.255.255.254", "ports": [1, 2]}
        argv = gate.workload_argv("probe", launch, "probe-volume")
    finally:
        gate._BOUND = previous
    bounded = has_mechanism and any(a == f or a.startswith(f + "=")
                                    for a in argv for f in ("--network", "--net"))
    fails_closed = "if any, carried the declared bearer" not in _read(
        "infra/byoa-spike/exec_v1_gate.py")
    return {"bounded": bounded, "e3b_fails_closed": fails_closed,
            "containment": "OBSERVED" if bounded else "NOT MEASURED"}


def test_no_document_describes_the_gate_except_by_naming_its_real_state():
    """A MARKER rule, not a blocklist, and the difference is the whole point.

    The first version of this test banned the three exact phrasings that had
    appeared in the offending commit. A reviewer rewrote the identical false
    claim in different words and it passed: "the conformance gate constrains the
    workload's network to a single relay peer ... Containment is OBSERVED", every
    word of it false, green. A list of past instances is a regression test for
    those instances; it is not a rule.

    Inverted here. Any paragraph in a lane document that talks about this gate
    AND its network must either name a state from the closed vocabulary, and
    that state must match `gate_state()`, or name the change that will deliver
    the property it describes. Prose that does neither is not a claim anyone can
    check, so it is refused.

    HONEST LIMIT, so this is not recorded as closing the class: paragraph
    detection is a heuristic over two keywords. A sentence that discusses the
    gate's network without using the word "network", or that splits the claim
    across paragraphs, is not seen. This catches rewordings, which the blocklist
    did not; it does not understand English.
    """
    state = gate_state()
    wrong_token = "OBSERVED" if state["containment"] == "NOT MEASURED" else "NOT MEASURED"

    for doc in _LANE_DOCS:
        for para in _read(doc).split("\n\n"):
            flat = " ".join(para.split())
            mentions_gate = ("gate" in flat.lower()
                             and ("run_flags" in flat or "conformance" in flat.lower()
                                  or "exec_v1_gate" in flat))
            if not (mentions_gate and "network" in flat.lower()):
                continue
            if _FORWARD_REFERENCE in flat:
                continue                       # a statement about another branch
            named = [t for t in _STATE_TOKENS if t in flat]
            assert named, (
                f"{doc}: a paragraph describes the conformance gate's network "
                f"without naming a state from {list(_STATE_TOKENS)} or citing "
                f"{_FORWARD_REFERENCE}. Unverifiable prose about the gate is "
                f"refused, because a rewording of a false claim is still false.\n"
                f"  {flat[:220]}")
            assert wrong_token not in named, (
                f"{doc}: a paragraph names containment as {wrong_token}, but the "
                f"gate's real state is {state['containment']} "
                f"(bounded={state['bounded']}, "
                f"e3b_fails_closed={state['e3b_fails_closed']}).\n  {flat[:220]}")

    # The converse, scoped to that row's own marker: a fixed gate with the
    # documents left behind. `"[CLOSED" in gaps` alone is satisfied by any other
    # closed row in the file, which is how this direction survived its first
    # mutant -- presence-not-value inside the assertion written to catch it.
    if state["bounded"] and state["e3b_fails_closed"]:
        gaps = _flat("docs/production-gaps.md")
        title = "The conformance report states absences it never measured"
        assert title in gaps, "the unmeasured-absences row is gone entirely"
        assert "[CLOSED" in gaps[gaps.index(title):gaps.index(title) + 400], (
            "the gate now bounds the network and E3b fails closed, but the "
            "unmeasured-absences row still reads open")


def test_the_documents_name_the_endpoint_and_the_gate_that_actually_exist():
    """Two citations were wrong in the first draft: the route was named
    `/runs/{id}/tools` (it is `registry-tools`) and the brokered leg was
    credited to the gate that proves the MODEL leg. Both are pinned against
    the tree so a rename breaks the test rather than the reader's trust."""
    app = _read("andyur/server/app.py")
    assert '@app.get("/runs/{run_id}/registry-tools")' in app
    # The per-tool rule really is gated behind an MCP enumeration, which is why
    # ADR-013 D4 must build the check rather than inherit it.
    assert "if tool.mcp_tools is not None:" in app

    run_sh = _read("run.sh")
    assert "svc-cred-verify)" in run_sh
    adr = _read("docs/adr-013-third-party-reach-for-stock-workloads.md")
    assert "`GET /runs/{run_id}/registry-tools`" in adr
    assert "./run.sh svc-cred-verify" in adr


def test_the_new_refusal_names_have_a_vocabulary_owner():
    """ADR-013 D6 adds refusal names. `observability.py` keeps CLOSED sets and
    raises on anything outside them, so the ADR has to say those sets are where
    the names land. If the sets stop being closed, this pin should be revisited
    rather than silently kept."""
    obs = _read("andyur/observability.py")
    for closed_set in ("_METRICS = {", "_RECORD_SCHEMAS = {",
                       "_METRIC_ATTRIBUTES = {", "_REFUSALS = {"):
        assert closed_set in obs, closed_set
    # The equality pin is why "just add a name" is wrong, so pin the pin.
    modelpolicy_test = _read("tests/test_modelpolicy.py")
    assert "observability._REFUSALS == mp.REFUSAL_CODES | {\"none\"}" in modelpolicy_test

    d6 = _section("docs/adr-013-third-party-reach-for-stock-workloads.md",
                  "## D6 — Every new decision is a span")
    # The ADR must describe the tree it will land in: four sets, an equality
    # pin, no bucket for this plane, and a value bound that does not exist yet.
    _states(d6, "closes FOUR relevant vocabularies, not one")
    _states(d6, "pinned by EXACT EQUALITY")
    _states(d6, "the partition has no bucket for this plane")
    _states(d6, "accepts any value until a value bound exists for it")
    # vendor_status is an attribute pair, never a refusal name.
    _states(d6, "`vendor_status` is not a refusal name and must not be added as one",
            "`vendor_status` is added to `_REFUSALS`")


def test_moving_the_enforcement_point_kept_the_audit_trail():
    """D5 hands enforcement to the vendor, so the vendor's denial becomes the
    only evidence that a grant was enforced. A reviewer's point, and the right
    one: if that record is thin, the enforcement point is real and the audit
    trail is not, which is worse than having neither because an operator would
    believe a control they cannot evidence."""
    adr = _flat("docs/adr-013-third-party-reach-for-stock-workloads.md")
    assert "the enforcement point is real and the audit trail is not" in adr
    assert "`vendor_status` carries the weight `action_not_granted` would have carried" in adr
    # The remote free-text trap, closed the same way as the model attribute.
    assert "never the vendor's error MESSAGE verbatim" in adr
    assert "the same trap as `andyur.model.requested`" in adr
    # And the deliberate absence stays deliberate, with its reason attached.
    d6 = _section("docs/adr-013-third-party-reach-for-stock-workloads.md",
                  "## D6 — Every new decision is a span")
    _states(d6, "`action_not_granted` stays deliberately absent",
            "`action_not_granted` is added")
    _states(d6, "no enforcement point of ours produced")


# --------------------------------------------------------------------------
# The pattern, not the instances.
# --------------------------------------------------------------------------

# Every document this lane governs. A rule decided in one of them is a rule
# about all of them, and the failure mode this test exists for is writing the
# rule in one file and violating it in another IN THE SAME COMMIT.
_LANE_DOCS = (
    "docs/adr-011-exec-v1-stock-process-contract.md",
    "docs/adr-012-oss-agent-certification.md",
    "docs/adr-013-third-party-reach-for-stock-workloads.md",
    "docs/certification-phase-1-spec.md",
    "ROADMAP.md",
    "docs/decisions.md",
    "README.md",
)


def test_a_rule_decided_in_one_document_is_not_violated_in_another():
    """A reviewer found three instances of one pattern in a single commit: the
    credential custodian, the read/write axis, and the term "certified". Each
    was a correct rule stated in one file and contradicted in another by the
    same change. Three instances is a pattern, and a pattern wants a test
    rather than three fixes.

    Each entry is (why the formulation is banned, the banned strings). They are
    checked across EVERY lane document including the one that decides the rule.

    The ban covers MENTION as well as USE, and that is deliberate rather than a
    limitation. Writing `Not "read-only or state-changing"` in order to reject
    the phrase put the phrase back in the corpus, and this test caught exactly
    that in its own first run. A substring check cannot distinguish rejecting a
    formulation from requiring one, so the rule is: describe the banned axis,
    do not quote it. A rule you can quote your way around is not a rule.
    """
    banned = (
        ("ADR-013 D5 killed the read/write axis: GetSecretValue is a Read, so "
         "'read-only' is a grant of exfiltration",
         ("read-only or state-changing", "read-only actions by default")),
        # The line falls between an ARTIFACT IDENTITY and a THING THAT RUNS.
        # "certified triple" is fine and is what D14 says an approval is about;
        # "certified agent" or "certified image" ascribes the decision to
        # something that behaves, which is the implication D14 refuses.
        ("ADR-012 D14: an approval is a decision about an exact artifact, never "
         "a property of something that runs",
         ("certified agent", "certified image", "certified workload",
          "certified SRE", "certified manifest")),
        ("ADR-013 records that sre-verify proves the MODEL leg and that its "
         "--full is forwarded and never read, so it cannot be cited for the "
         "brokered tool leg",
         ("sre-verify --full",)),
    )
    for why, phrases in banned:
        for doc in _LANE_DOCS:
            text = _flat(doc)
            for phrase in phrases:
                assert phrase not in text, (
                    f"{doc} uses {phrase!r}, which this lane's own rules ban. {why}")


def test_the_phase_1_spec_pins_the_decisions_it_makes_beyond_adr_012():
    """The spec may decide what ADR-012 left open, but each decision has to
    survive an edit that reverses it OR relocates it under a rejected-
    alternatives heading. Section-scoped with explicit negations, because the
    first version of this test used whole-file substring pins and a reviewer
    walked context inversion straight through seven of its eight."""
    SPEC = "docs/certification-phase-1-spec.md"

    # R1: digest the AUTHORITY document. A reviewer collided the previous rule
    # with two policies that produced byte-identical digests, so both the
    # positive rule and the two rejected candidates are pinned.
    r1 = _section(SPEC, "## 1. Identity: what an approval is actually about")
    _states(r1, "`manifest_digest` is not it",
            "`manifest_digest` is the runtime document digest")
    _states(r1, "the digest of the compiled `AgentResolution`")
    _states(r1, "`policy_revision` is EXCLUDED from the digest",
            "`policy_revision` is included in the digest")
    _states(r1, "the canonicalizer is the tree's, not a new one")
    _states(r1, "RFC 8785")
    _states(r1, "resolved before hashing, never left absent")

    # R8: the mechanism must fail CLOSED. The previous one accumulated failure
    # messages, so a missing rule allowed.
    r8 = _section(SPEC, "## 8. The decision rule")
    _states(r8, "cosign verifies signatures, the platform decides")
    _states(r8, "It fails open.")          # stated as the rejected property
    _states(r8, "`default decision := false`")
    _states(r8, "an unreachable, misspelled or absent\nrule DENIES".replace("\n", " "))
    _states(r8, "the policy is a signed, pinned artifact")
    _states(r8, "capability as well as containment")

    # R10: per launch, in the worker.
    r10 = _section(SPEC, "## 10. Integration point two")
    _states(r10, "`launch_governed`")
    _states(r10, "It runs once per process, not per launch.")
    _states(r10, "It is in the wrong process.")
    _states(r10, "revocation_unavailable")

    # R4 / R6 / D4 / revocation, each with the reversal that made it necessary.
    _states(_section(SPEC, "## 3. The behavior predicate"),
            "becomes `NOT MEASURED`, never `NOT EXERCISED`",
            "becomes `NOT EXERCISED`, never `NOT MEASURED`")
    _states(_section(SPEC, "## 6. The record store is a cache"),
            "No decision is ever read from this table",
            "the launch check reads this table")
    # D4 was unenforceable: the predicate carried no requester, so the rule had
    # nothing to evaluate and its mutant had nothing to detect it with.
    approval = _section(SPEC, "## 5. The approval predicate")
    _states(approval, "otherwise ADR-012 D4 is")
    _states(approval, '"requester": {"identity": "..."}')
    # Revocation has to bind the triple, not one approval among several.
    _states(approval, "One live approval per triple")
    _states(approval, "A revocation is a FLOOR, not a pointer")
    _states(_section(SPEC, "## 4. The request state machine"),
            "signed attestation, not a record",
            "suspension is a record")


def test_the_spec_integrates_where_the_code_actually_is():
    """IMPORT and INSPECT, never grep.

    The previous version read `publisher.py` as a STRING and substring-matched
    it. A reviewer proved what that is worth: make `publisher.py` raise
    ImportError and the test that exists to prove the spec integrates with it
    passed 16/16. Reading a source file as text is still asserting in prose; it
    just happens to be the code's own prose. Renaming a dataclass field, making
    a refusal unreachable, or swapping a verifier for a no-op all held too,
    because a name occurring anywhere in a large file satisfies a presence pin.
    """
    import dataclasses
    import importlib
    import inspect

    publisher = importlib.import_module("andyur.agentspec.publisher")
    governed_kubernetes = importlib.import_module("andyur.daemon.governed_kubernetes")
    models = importlib.import_module("andyur.registry.models")
    runtime_wire = importlib.import_module("andyur.registry.runtime_wire")

    # §9: the parameters the approval check composes with, by SIGNATURE.
    publish = inspect.signature(publisher.publish_snapshot).parameters
    for name in ("conformance_evidence", "conformance_key", "gate_dir"):
        assert name in publish, f"publish_snapshot lost {name}"
    assert callable(getattr(publisher, "_publish_sealed", None))

    # §10: the per-launch entry point in the WORKER, with the envelope argument
    # that makes a per-run check possible at all.
    launch = inspect.signature(
        governed_kubernetes.GovernedKubernetesOrchestrator.launch_governed).parameters
    assert {"spec", "runtime_raw"} <= set(launch), (
        "launch_governed no longer takes the run's runtime envelope, so the "
        "spec's per-launch approval check has nowhere to stand")

    # §1: the fields the triple is built from, by FIELD not by substring. A
    # commented-out dataclass field leaves its name in the file and passes a
    # text pin; dataclasses.fields does not see it.
    runtime_fields = {f.name for f in dataclasses.fields(models.RuntimeResolution)}
    assert {"image_ref", "image_digest", "command", "manifest_digest",
            "policy_revision"} <= runtime_fields
    authority_fields = {f.name for f in dataclasses.fields(models.AgentResolution)}
    assert {"model", "tools", "ceiling"} <= authority_fields, (
        "the authority document lost a field R1 digests")

    # R1b: the canonicalizer the spec adopts is the tree's existing one.
    assert callable(getattr(runtime_wire, "encode_runtime", None))
    # R1c: the lifetime default trap the spec resolves before hashing.
    assert callable(getattr(models, "granted_lifetime_seconds", None))

    # And the spec names each of them, so a rename breaks the doc AND the test.
    spec = _flat("docs/certification-phase-1-spec.md")
    for anchor in ("`publish_snapshot`", "`_publish_sealed`", "`launch_governed`",
                   "`AgentResolution`", "`encode_authority`",
                   "`granted_lifetime_seconds`"):
        assert anchor in spec, anchor


# --------------------------------------------------------------------------
# Reachability: the half of the idiom the first version dropped.
# --------------------------------------------------------------------------

def test_public_entrypoints_link_to_the_three_decisions():
    """`test_egress_architecture_docs.py` pins the topology AND that a reader
    can find it from the README. Three ADRs deciding whether an OSS agent may
    reach AWS are worth no more than their discoverability by a stranger who
    cannot ask us anything."""
    readme = _read("README.md")
    architecture = _read("ARCHITECTURE.md")
    # Discoverability can only be required of a document a stranger RECEIVES.
    # adr-013 is "proposed, nothing here is built" and moved to docs-internal/ on
    # 2026-09-11 with the other unbuilt proposals, so the public entrypoints must
    # NOT link to it -- a link to a file the reader does not have is worse than no
    # link. The requirement therefore follows what is published rather than a
    # hard-coded list, which is also what keeps this test honest if another of
    # these three is ever withdrawn.
    for adr in ("adr-011-exec-v1-stock-process-contract.md",
                "adr-012-oss-agent-certification.md",
                "adr-013-third-party-reach-for-stock-workloads.md"):
        if not (ROOT / "docs" / adr).is_file():
            continue
        for doc, name in ((readme, "README.md"), (architecture, "ARCHITECTURE.md")):
            assert adr in doc, f"{adr} unreachable from {name}"
    # The README's exec/v1 status must not revert to "coming next" now that
    # three unrelated upstream agents have run on it.
    assert "Coming next: `exec/v1`" not in readme


def test_the_local_test_command_and_ci_collect_the_same_suite():
    """Gap 39, pinned from BOTH ends so whichever fix lands must close the row.

    `./run.sh test` execs `pytest tests/` while CI runs bare `pytest -q`, so the
    two collect different sets and the local one is a strict subset -- 8 tests
    in `demos/adsupport/test_app.py` that run only in CI. Both report a large
    green number, so neither side can see the divergence, which is how it
    survived long enough for two sessions to quote "the suite" at each other
    and disagree by exactly those 8.

    This asserts the CURRENT state and its documentation together. When someone
    converges the two commands, this test fails and names the row to close, the
    same way the conformance-gate pins work. It reads the invocations rather
    than running them: collecting twice would double an already slow suite, and
    the defect is in what the commands SAY to collect.
    """
    run_sh = _read("run.sh")
    # THE PRIVATE ROOT CI, which the published subtree does not carry -- and
    # this read used to be unguarded, so extracting the tree produced a suite
    # that FAILED on its very first run. The gaps register it compares against
    # is internal too, so there is nothing here to assert in a public checkout;
    # its thirteen sibling tests already skip for exactly this reason.
    #
    # Skipping is a real weakening and worth saying so: these assertions run
    # privately and vanish publicly. What stops that being silent is that the
    # skip names the file, so a public run reports it rather than passing
    # quietly.
    private_ci = ROOT.parent / ".github/workflows/andyur-ci.yml"
    if not private_ci.exists():
        pytest.skip(
            ".github/workflows/andyur-ci.yml is the private monorepo's CI and "
            "is absent here, as is the internal gaps register this compares "
            "against")
    ci = private_ci.read_text()

    # MECHANICAL, not a list of known places. Four scopes were found one at a
    # time -- I converged two, a reviewer found the third, Session-L found the
    # fourth in the release procedure, and a sweep then found a FIFTH in
    # CONTRIBUTING.md, the file a new contributor is told to run. Pinning the
    # four we knew about would have missed the fifth exactly as the first fix
    # missed the fourth. So: enumerate every place that tells a human to run
    # THE SUITE, and require each to be the canonical invocation.
    #
    # A narrower scope is allowed when it is DELIBERATE and says so -- the
    # redteam target and the per-file examples in supported-envelope.md are not
    # claiming to be the suite. What is refused is a bare `pytest tests/` in a
    # place that IS claiming to be the suite.
    for doc in ("CONTRIBUTING.md", "docs/RELEASING.md"):
        text = _read(doc)
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("pytest "):
                continue
            assert not stripped.startswith("pytest tests/"), (
                f"{doc} tells a reader to run `{stripped}`, which is the SCOPED "
                "subset, not the canonical invocation CI runs. Converging two "
                "commands does not converge a name: every place that documents "
                "'run the suite' is another definition.")

    # The line-start sweep above cannot see an invocation written INLINE in
    # prose, and RELEASING.md's is inline -- making the check "mechanical"
    # made it weaker there, which the mutation caught. Mechanical where the
    # shape allows, specific where it does not, and the gap named rather than
    # papered over.
    releasing = _read("docs/RELEASING.md")
    assert "`pytest tests/` is a strict SUBSET" in releasing, (
        "docs/RELEASING.md no longer warns that the scoped invocation is a "
        "subset; the release procedure may have been re-scoped")
    assert 'pip install ".[dev]"`, then `pytest` --' in releasing, (
        "the documented release verification is not the bare invocation CI uses")

    scoped = 'exec "$VENV/bin/python" -m pytest tests/ "$@"' in run_sh
    bare = "\n        run: .venv/bin/python -m pytest -q\n" in ci
    gaps = _flat("docs/production-gaps.md")
    row = "`./run.sh test` and CI run DIFFERENT suites"

    if scoped and bare:
        assert row in gaps, (
            "run.sh is path-scoped and CI runs bare pytest, so they collect "
            "different suites, but no gaps row records it")
        start = gaps.index(row)
        assert "[open," in gaps[start:start + 300], (
            "the suites still diverge but the row is marked closed")
    else:
        assert row not in gaps or "[CLOSED" in gaps[gaps.index(row):gaps.index(row) + 300], (
            "the invocations no longer diverge as gap 39 describes: converge or "
            "reword the row, and close it")


def test_the_gaps_are_tracked_with_their_status_not_just_their_titles():
    """A title pin passes when a gap is flipped to closed. Pin the status
    marker beside the title, so closing one of these requires touching the
    test that says it is open."""
    gaps = _read("docs/production-gaps.md")
    # Pinned WITHOUT the leading number. The console lane added rows 23-28 on
    # its own branch off the same base, so one of the two sets is renumbered at
    # merge; a number pin would break on a correct renumbering and, worse,
    # could silently come to match someone else's row.
    for row, status in (
        ("**A stock workload cannot reach a third party at all",
         "[decided; ADR-013 proposed 2026-08-26, not built]"),
        ("**The conformance report states absences it never measured",
         "[CLOSED 2026-08-26:"),
        ("**`exec/v1` admits two model protocols",
         "[open, 2026-08-26]"),
        ("**The manifest declares an output contract nothing enforces",
         "[open, 2026-08-26]"),
    ):
        assert row in gaps, row
        start = gaps.index(row)
        assert status in gaps[start:start + 400], f"{row} lost its status marker"
    # Blocking phase 1 is a decision, not a note. Pinned by TITLE as well as
    # number: the console lane added rows 23-28 on its own branch off the same
    # base, so one of the two sets gets renumbered at merge and a pure number
    # pin would either break or, worse, silently point at someone else's row.
    assert "BLOCKS phase 1**" in gaps
    assert "unmeasured absences" in gaps
    adr = _flat("docs/adr-012-oss-agent-certification.md")
    assert "the conformance report states absences it never measured" in adr

"""Pure-Python tests for the simulated ads app: the state machine, the dual-control
authority boundary, and that every scenario is actually SOLVABLE by the intended
coordinated sequence (and NOT by one party alone). No LLM, so this runs fast in CI."""

from demos.adsupport import app as A
from demos.adsupport.app import dispatch
from demos.adsupport.scenarios import SCENARIOS


def test_disapproved_ad_needs_edit_then_resubmit_then_expedite():
    app, c = SCENARIOS["disapproved_ad"].build()
    ad = c["ad_id"]
    assert app.ads[ad].status == "disapproved" and app.ads[ad].violation
    # agent alone cannot fix it: can't expedite a non-in-review ad
    assert app.expedite_ad_review(ad)["ok"] is False
    # advertiser edits with a still-bad headline -> still violating
    assert app.edit_ad_creative(ad, "another miracle cure")["ok"] is False
    # advertiser edits clean -> draft, resubmits -> in_review, agent expedites -> active
    assert app.edit_ad_creative(ad, "Start your morning right")["ok"] is True
    assert app.resubmit_ad(ad)["ok"] is True
    assert app.expedite_ad_review(ad)["status"] == "active"
    assert SCENARIOS["disapproved_ad"].goal(app, c)


def test_payment_limit_needs_advertiser_then_agent():
    app, c = SCENARIOS["payment_limit"].build()
    acct = c["account_id"]
    assert app.accounts[acct].status == "limited"
    # agent alone cannot lift while payment is invalid
    assert app.lift_account_limit(acct)["ok"] is False
    # advertiser fixes payment (only they can), THEN agent lifts, THEN advertiser resumes
    assert app.update_payment_method(acct)["ok"] is True
    assert app.lift_account_limit(acct)["ok"] is True
    assert app.resume_campaign(c["campaign_id"])["ok"] is True
    assert SCENARIOS["payment_limit"].goal(app, c)


def test_paused_and_limited_has_a_strict_order():
    app, c = SCENARIOS["paused_and_limited"].build()
    acct, camp = c["account_id"], c["campaign_id"]
    assert app.accounts[acct].status == "limited"
    assert app.campaigns[camp].status == "paused"
    # cannot resume while the account is limited (ordering dependency)
    assert app.resume_campaign(camp)["ok"] is False
    # correct order: fix payment -> lift limit -> resume
    assert app.update_payment_method(acct)["ok"] is True
    assert app.lift_account_limit(acct)["ok"] is True
    assert app.resume_campaign(camp)["ok"] is True
    assert SCENARIOS["paused_and_limited"].goal(app, c)
    # and lifting alone does NOT auto-resume an EXPLICITLY paused campaign
    app2, c2 = SCENARIOS["paused_and_limited"].build()
    app2.update_payment_method(c2["account_id"])
    app2.lift_account_limit(c2["account_id"])
    assert not SCENARIOS["paused_and_limited"].goal(app2, c2)  # still paused


def test_billing_dispute_waive():
    app, c = SCENARIOS["billing_dispute"].build()
    assert app.waive_charge(c["charge_id"], "confirmed duplicate")["ok"] is True
    assert SCENARIOS["billing_dispute"].goal(app, c)


def test_combined_hard_full_sequence():
    app, c = SCENARIOS["combined_hard"].build()
    acct, ad = c["account_id"], c["ad_id"]
    app.update_payment_method(acct)
    app.lift_account_limit(acct)
    app.edit_ad_creative(ad, "Reach your fitness goals this year")
    app.resubmit_ad(ad)
    app.expedite_ad_review(ad)
    assert SCENARIOS["combined_hard"].goal(app, c)


def test_authority_boundary_is_enforced():
    app, c = SCENARIOS["payment_limit"].build()
    acct = c["account_id"]
    # the advertiser cannot lift their own limit (support-only)
    assert dispatch(app, "advertiser", "lift_account_limit", {"account_id": acct})["ok"] is False
    # the agent cannot update the advertiser's payment method (advertiser-only)
    assert dispatch(app, "agent", "update_payment_method", {"account_id": acct})["ok"] is False
    # each within its surface works
    assert dispatch(app, "advertiser", "update_payment_method", {"account_id": acct})["ok"] is True
    assert dispatch(app, "agent", "lift_account_limit", {"account_id": acct})["ok"] is True


def test_tool_surfaces_are_disjoint_on_mutations():
    # the two mutating surfaces (single-sourced in app.py) must be disjoint, and
    # each must be a subset of its own tool surface only
    assert A.AGENT_MUTATING_TOOLS & A.ADVERTISER_TOOL_NAMES == set()
    assert A.ADVERTISER_MUTATING_TOOLS & A.AGENT_TOOL_NAMES == set()
    assert A.AGENT_MUTATING_TOOLS <= A.AGENT_TOOL_NAMES
    assert A.ADVERTISER_MUTATING_TOOLS <= A.ADVERTISER_TOOL_NAMES


def test_no_scenario_is_solvable_by_one_party_alone():
    # sanity: applying ONLY advertiser ops, or ONLY agent ops, never resolves a
    # dual-control scenario (billing_dispute is agent-solvable by design, skip it)
    for key in ("disapproved_ad", "payment_limit", "combined_hard"):
        s = SCENARIOS[key]
        app, c = s.build()
        # advertiser does everything they can, twice
        for _ in range(2):
            if "ad_id" in c:
                app.edit_ad_creative(c["ad_id"], "A clean compliant headline")
                app.resubmit_ad(c["ad_id"])
            app.update_payment_method(c["account_id"])
            app.resume_campaign(c["campaign_id"])
        assert not s.goal(app, c), f"{key} solved without the agent"

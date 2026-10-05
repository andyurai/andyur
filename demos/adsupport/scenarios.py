"""Scenarios for the ads-support dual-control demo.

Each scenario seeds the simulated app into a broken state, gives the advertiser a
persona and a hidden goal (what the customer actually wants), and defines a goal
predicate over the FINAL app state. Every scenario is designed so that NEITHER
party can resolve it alone: the advertiser can only touch their own account and
creative, support can only exercise admin authority, so the ticket closes only if
both act and coordinate. That is the dual-control property τ²-bench measures.
"""

from dataclasses import dataclass
from typing import Callable

from .app import AdsPlatform


@dataclass
class Scenario:
    name: str
    persona: str            # how the advertiser behaves (attitude, tone, expertise)
    goal_text: str          # the customer's OWN objective (their hidden agenda)
    build: Callable         # () -> (AdsPlatform, ctx: dict of seeded ids)
    goal: Callable          # (app, ctx) -> bool  (resolved?)
    summary: str            # one line for the report
    dual_control: bool = True  # does resolving it REQUIRE both parties to act?


def _disapproved_ad():
    app = AdsPlatform()
    acct = app.add_account("Rivertown Coffee")
    camp = app.add_campaign(acct.id, "Fall Roast Launch")
    ad = app.add_ad(camp.id, "Our miracle cure for a bad morning")  # -> disapproved
    return app, {"account_id": acct.id, "campaign_id": camp.id, "ad_id": ad.id}


def _payment_limit():
    app = AdsPlatform()
    acct = app.add_account("Nomad Backpacks", payment_method="expired")
    camp = app.add_campaign(acct.id, "Summer Trail Sale", status="active")
    app.add_ad(camp.id, "Gear up for the trail")
    app.add_charge(acct.id, 4200, status="failed")  # trips account -> limited
    return app, {"account_id": acct.id, "campaign_id": camp.id}


def _billing_dispute():
    app = AdsPlatform()
    acct = app.add_account("Blue Fox Bakery", balance_cents=0)
    camp = app.add_campaign(acct.id, "Weekend Specials")
    app.add_ad(camp.id, "Fresh sourdough daily")
    bad = app.add_charge(acct.id, 9900, status="settled")   # the disputed charge
    app.add_charge(acct.id, 1500, status="settled")         # a legit one
    return app, {"account_id": acct.id, "campaign_id": camp.id, "charge_id": bad.id}


def _paused_and_limited():
    # TWO distinct blocks: an account-level limit (auto-restores on lift) AND a
    # campaign the advertiser explicitly paused (needs a manual resume). Resume is
    # refused while the account is limited, so the fix has a strict order:
    # advertiser updates payment -> agent lifts limit -> advertiser resumes.
    app = AdsPlatform()
    acct = app.add_account("Tidal Surf Co", payment_method="expired")
    camp = app.add_campaign(acct.id, "Wetsuit Clearance", status="paused")
    app.add_ad(camp.id, "End of season deals")
    app.add_charge(acct.id, 5000, status="failed")  # account -> limited
    return app, {"account_id": acct.id, "campaign_id": camp.id}


def _combined_hard():
    app = AdsPlatform()
    acct = app.add_account("Peak Fitness", payment_method="expired")
    camp = app.add_campaign(acct.id, "New Year Push", status="active")
    ad = app.add_ad(camp.id, "Guaranteed weight loss in 7 days")  # disapproved
    app.add_charge(acct.id, 6000, status="failed")               # account limited
    return app, {"account_id": acct.id, "campaign_id": camp.id, "ad_id": ad.id}


SCENARIOS = {
    "disapproved_ad": Scenario(
        name="disapproved_ad",
        persona=("A small-business owner who is confused and a little anxious. Not "
                 "technical, doesn't know the word 'policy violation'. Polite but "
                 "wants a clear, simple explanation of what to do."),
        goal_text=("Your ad was rejected and you don't know why. You want it running "
                   "again. You are willing to change the wording if support explains "
                   "what's wrong, but you won't know to do that unless they tell you."),
        build=_disapproved_ad,
        goal=lambda app, c: app.ads[c["ad_id"]].status == "active",
        summary="Ad disapproved for a prohibited claim; advertiser must edit + resubmit, "
                "agent must expedite review.",
    ),
    "payment_limit": Scenario(
        name="payment_limit",
        persona=("A busy e-commerce operator, mildly frustrated that their ads stopped. "
                 "Terse. Wants it fixed fast and will do steps if told exactly what to click."),
        goal_text=("Your campaign stopped spending and you want it running again today. "
                   "You suspect it's a billing thing but aren't sure."),
        build=_payment_limit,
        goal=lambda app, c: (app.accounts[c["account_id"]].status == "active"
                             and app.campaigns[c["campaign_id"]].status == "active"),
        summary="Failed payment limited the account (spend blocked account-wide, the "
                "campaign is not individually paused). Advertiser must update payment, "
                "agent must lift the limit; lifting restores spend automatically.",
    ),
    "billing_dispute": Scenario(
        name="billing_dispute",
        persona=("An angry customer who believes they were double-charged. Starts hot, "
                 "threatens to leave, but calms if taken seriously and given a concrete fix."),
        goal_text=("You think a $99 charge is wrong and you want it removed. You are "
                   "frustrated and want acknowledgement, not a runaround."),
        build=_billing_dispute,
        goal=lambda app, c: app.charges[c["charge_id"]].status in ("waived",),
        summary="Advertiser disputes a charge; agent must investigate and waive it; "
                "a frustrated persona to handle. (Single-control by design.)",
        dual_control=False,
    ),
    "paused_and_limited": Scenario(
        name="paused_and_limited",
        persona=("A methodical small-business owner who paused a campaign on purpose "
                 "last month and now can't get it running. Asks clear questions, "
                 "follows steps exactly, wants to understand the order of operations."),
        goal_text=("You paused your 'Wetsuit Clearance' campaign a while back and now "
                   "you want it live again, but something's also off with your account. "
                   "You want it actually spending, not just un-paused."),
        build=_paused_and_limited,
        goal=lambda app, c: (app.accounts[c["account_id"]].status == "active"
                             and app.campaigns[c["campaign_id"]].status == "active"),
        summary="Account limited AND the campaign was explicitly paused. Order matters: "
                "advertiser updates payment, agent lifts the limit, THEN advertiser "
                "resumes (resume is refused while limited).",
    ),
    "combined_hard": Scenario(
        name="combined_hard",
        persona=("An impatient agency manager juggling many clients. Wants both problems "
                 "solved in one go, gets snippy if the agent handles only half."),
        goal_text=("Your ad got rejected AND your account got limited on the same day. "
                   "You want everything back to normal so the campaign runs."),
        build=_combined_hard,
        goal=lambda app, c: (app.accounts[c["account_id"]].status == "active"
                             and app.ads[c["ad_id"]].status == "active"),
        summary="Both a disapproved ad and a payment limit at once; requires the full "
                "coordination from both sides.",
    ),
}


# --- prompt builders (kept next to the personas they read from) -------------

def ids_line(ctx: dict) -> str:
    """Render a context's seeded ids for a system prompt."""
    return ", ".join(f"{k} = {v}" for k, v in ctx.items())


def customer_system(scenario: Scenario, ctx: dict) -> str:
    """The system prompt for the customer simulator: role-play this scenario's
    advertiser, with self-service tools on their own account."""
    return (
        "You are role-playing a real advertiser contacting support. Stay in "
        "character; never say you are an AI.\n\n"
        f"Your persona: {scenario.persona}\n\n"
        f"What you actually want (your goal): {scenario.goal_text}\n\n"
        "You have self-service tools on YOUR OWN account only: get_account, "
        "list_campaigns, get_ad_review, update_payment_method, add_funds, "
        "pause_campaign, resume_campaign, edit_ad_creative, resubmit_ad.\n"
        "When support asks you to do something you CAN do with these tools "
        "(update your payment, edit your ad's headline, resubmit it, resume a "
        "campaign, add funds), ACTUALLY call the tool, then tell support what "
        "happened in plain words. Do not claim you did something you didn't.\n"
        "Behave like your persona: keep messages short and human, react to how "
        "well support is helping. When your problem is actually fixed, say a brief "
        "thanks and stop.\n\n"
        f"Your identifiers: {ids_line(ctx)}."
    )

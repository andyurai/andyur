"""A simulated ads-platform support backend.

This is the shared, mutating "world" for the dual-control demo: one running mock
system that BOTH a support agent and an advertiser (customer) act on, each
through their own asymmetric slice of the API. It is a generic ad-platform model
(accounts, campaigns, ads, charges) -- not any real product -- so it is safe to
reuse across all our tests and to grow over time.

The dual control is the point: some operations only support can do (issue a
credit, lift an account limit, expedite a policy review), and some only the
advertiser can do (update their own payment method, edit their own creative,
pause their campaign). Realistic tickets therefore require BOTH parties to act
and coordinate, which is exactly what a single agent cannot fake alone.

Every operation returns a small structured dict ({"ok": ..., ...}) so an LLM tool
layer can consume it directly, and every mutation is appended to an event log so
an episode is fully auditable.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

# --- policy: creative headlines containing any of these are disapproved --------
BANNED_PHRASES = [
    "miracle cure", "guaranteed weight loss", "get rich quick",
    "100% guaranteed", "cure cancer", "lose 10 pounds overnight",
]

CENTS = 100  # helper for readability


def _policy_violation(headline: str) -> str | None:
    low = (headline or "").lower()
    for p in BANNED_PHRASES:
        if p in low:
            return f"prohibited claim: '{p}'"
    return None


@dataclass
class Account:
    id: str
    name: str
    status: str = "active"            # active | limited | suspended
    limit_reason: str | None = None   # payment_failed | policy_review | None
    balance_cents: int = 0
    payment_method: str = "valid"     # valid | expired | none


@dataclass
class Campaign:
    id: str
    account_id: str
    name: str
    status: str = "active"            # active | paused | draft
    daily_budget_cents: int = 5000
    spend_today_cents: int = 0
    objective: str = "traffic"


@dataclass
class Ad:
    id: str
    campaign_id: str
    headline: str
    status: str = "active"            # active | disapproved | in_review | draft
    violation: str | None = None


@dataclass
class Charge:
    id: str
    account_id: str
    amount_cents: int
    status: str = "settled"           # settled | failed | disputed | waived


@dataclass
class AdsPlatform:
    """The simulated system-of-record. Operations mutate this in place."""
    accounts: dict = field(default_factory=dict)
    campaigns: dict = field(default_factory=dict)
    ads: dict = field(default_factory=dict)
    charges: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    _seq: int = 0

    # -- id + logging helpers ------------------------------------------------
    def _id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}_{self._seq:04d}"

    def _log(self, actor: str, op: str, **kw) -> None:
        self.events.append({"actor": actor, "op": op, **kw})

    # -- fixture builders (used by scenarios) --------------------------------
    def add_account(self, name, status="active", limit_reason=None,
                    balance_cents=0, payment_method="valid") -> Account:
        a = Account(self._id("acct"), name, status, limit_reason,
                    balance_cents, payment_method)
        self.accounts[a.id] = a
        return a

    def add_campaign(self, account_id, name, status="active",
                     daily_budget_cents=5000, spend_today_cents=0,
                     objective="traffic") -> Campaign:
        c = Campaign(self._id("camp"), account_id, name, status,
                     daily_budget_cents, spend_today_cents, objective)
        self.campaigns[c.id] = c
        return c

    def add_ad(self, campaign_id, headline, status=None) -> Ad:
        v = _policy_violation(headline)
        st = status or ("disapproved" if v else "active")
        ad = Ad(self._id("ad"), campaign_id, headline, st, v)
        self.ads[ad.id] = ad
        return ad

    def add_charge(self, account_id, amount_cents, status="settled") -> Charge:
        ch = Charge(self._id("chg"), account_id, amount_cents, status)
        self.charges[ch.id] = ch
        if status == "failed":
            acct = self.accounts.get(account_id)
            if acct and acct.status == "active":
                acct.status, acct.limit_reason = "limited", "payment_failed"
        return ch

    # ======================================================================
    # SHARED READS (agent sees any account; advertiser is scoped by caller)
    # ======================================================================
    def get_account(self, account_id: str) -> dict:
        a = self.accounts.get(account_id)
        if not a:
            return {"ok": False, "error": "no such account"}
        return {"ok": True, **dataclasses.asdict(a)}

    def list_campaigns(self, account_id: str) -> dict:
        rows = [dataclasses.asdict(c) for c in self.campaigns.values()
                if c.account_id == account_id]
        return {"ok": True, "campaigns": rows}

    def get_ad_review(self, ad_id: str) -> dict:
        ad = self.ads.get(ad_id)
        if not ad:
            return {"ok": False, "error": "no such ad"}
        return {"ok": True, "id": ad.id, "status": ad.status,
                "headline": ad.headline, "violation": ad.violation}

    def list_charges(self, account_id: str) -> dict:
        rows = [dataclasses.asdict(c) for c in self.charges.values()
                if c.account_id == account_id]
        return {"ok": True, "charges": rows}

    # ======================================================================
    # AGENT-ONLY OPERATIONS (support / admin authority)
    # ======================================================================
    def issue_credit(self, account_id: str, amount_cents: int, reason: str) -> dict:
        a = self.accounts.get(account_id)
        if not a:
            return {"ok": False, "error": "no such account"}
        a.balance_cents += int(amount_cents)
        self._log("agent", "issue_credit", account_id=account_id,
                  amount_cents=amount_cents, reason=reason)
        return {"ok": True, "new_balance_cents": a.balance_cents}

    def waive_charge(self, charge_id: str, reason: str) -> dict:
        ch = self.charges.get(charge_id)
        if not ch:
            return {"ok": False, "error": "no such charge"}
        ch.status = "waived"
        self._log("agent", "waive_charge", charge_id=charge_id, reason=reason)
        return {"ok": True, "charge_id": charge_id, "status": "waived"}

    def lift_account_limit(self, account_id: str) -> dict:
        """Guarded: the agent can only lift a limit once its UNDERLYING cause is
        resolved. A payment-failed limit needs the advertiser to fix payment
        FIRST -- which the agent cannot do -- so this forces coordination."""
        a = self.accounts.get(account_id)
        if not a:
            return {"ok": False, "error": "no such account"}
        if a.status != "limited":
            return {"ok": True, "note": "account is not limited", "status": a.status}
        if a.limit_reason == "payment_failed" and a.payment_method != "valid":
            return {"ok": False,
                    "error": "cannot lift: payment method is still invalid; the "
                             "advertiser must update their payment method first"}
        if a.limit_reason == "policy_review":
            return {"ok": False,
                    "error": "cannot lift: account is under policy review; escalate "
                             "to the policy team to clear it"}
        a.status, a.limit_reason = "active", None
        self._log("agent", "lift_account_limit", account_id=account_id)
        return {"ok": True, "status": "active"}

    def expedite_ad_review(self, ad_id: str) -> dict:
        """Push an in-review ad to a decision now. A still-violating creative is
        disapproved again -- the agent cannot approve a bad ad, only speed it up."""
        ad = self.ads.get(ad_id)
        if not ad:
            return {"ok": False, "error": "no such ad"}
        if ad.status != "in_review":
            return {"ok": False,
                    "error": f"ad is '{ad.status}', not in review; it must be "
                             "resubmitted for review first"}
        ad.violation = _policy_violation(ad.headline)
        ad.status = "disapproved" if ad.violation else "active"
        self._log("agent", "expedite_ad_review", ad_id=ad_id, result=ad.status)
        return {"ok": True, "status": ad.status, "violation": ad.violation}

    def clear_policy_review(self, account_id: str) -> dict:
        """Resolve a policy-review hold (agent authority)."""
        a = self.accounts.get(account_id)
        if not a:
            return {"ok": False, "error": "no such account"}
        if a.limit_reason != "policy_review":
            return {"ok": True, "note": "no policy review pending"}
        a.limit_reason = None
        if a.status == "limited":
            a.status = "active"
        self._log("agent", "clear_policy_review", account_id=account_id)
        return {"ok": True, "status": a.status}

    # ======================================================================
    # ADVERTISER-ONLY OPERATIONS (self-service on their own account)
    # ======================================================================
    def update_payment_method(self, account_id: str, method: str = "card") -> dict:
        a = self.accounts.get(account_id)
        if not a:
            return {"ok": False, "error": "no such account"}
        a.payment_method = "valid"
        self._log("advertiser", "update_payment_method", account_id=account_id,
                  method=method)
        return {"ok": True, "payment_method": "valid"}

    def add_funds(self, account_id: str, amount_cents: int) -> dict:
        a = self.accounts.get(account_id)
        if not a:
            return {"ok": False, "error": "no such account"}
        a.balance_cents += int(amount_cents)
        self._log("advertiser", "add_funds", account_id=account_id,
                  amount_cents=amount_cents)
        return {"ok": True, "new_balance_cents": a.balance_cents}

    def pause_campaign(self, campaign_id: str) -> dict:
        return self._set_campaign(campaign_id, "paused")

    def resume_campaign(self, campaign_id: str) -> dict:
        c = self.campaigns.get(campaign_id)
        if not c:
            return {"ok": False, "error": "no such campaign"}
        acct = self.accounts.get(c.account_id)
        if acct and acct.status != "active":
            return {"ok": False,
                    "error": f"cannot resume: the account is {acct.status} "
                             f"({acct.limit_reason}); resolve that first"}
        return self._set_campaign(campaign_id, "active")

    def _set_campaign(self, campaign_id: str, status: str) -> dict:
        c = self.campaigns.get(campaign_id)
        if not c:
            return {"ok": False, "error": "no such campaign"}
        c.status = status
        self._log("advertiser", "set_campaign", campaign_id=campaign_id, status=status)
        return {"ok": True, "campaign_id": campaign_id, "status": status}

    def edit_ad_creative(self, ad_id: str, new_headline: str) -> dict:
        """Only the advertiser owns the creative. Editing re-checks policy: a clean
        headline clears the violation and moves the ad to draft (ready to resubmit)."""
        ad = self.ads.get(ad_id)
        if not ad:
            return {"ok": False, "error": "no such ad"}
        ad.headline = new_headline
        ad.violation = _policy_violation(new_headline)
        ad.status = "disapproved" if ad.violation else "draft"
        self._log("advertiser", "edit_ad_creative", ad_id=ad_id,
                  violation=ad.violation)
        if ad.violation:
            return {"ok": False, "status": ad.status, "violation": ad.violation,
                    "error": "the new headline still violates policy"}
        return {"ok": True, "status": "draft",
                "note": "creative is clean; resubmit it for review"}

    def resubmit_ad(self, ad_id: str) -> dict:
        ad = self.ads.get(ad_id)
        if not ad:
            return {"ok": False, "error": "no such ad"}
        if ad.status not in ("draft", "disapproved"):
            return {"ok": False, "error": f"ad is '{ad.status}', nothing to resubmit"}
        if _policy_violation(ad.headline):
            return {"ok": False, "error": "the creative still violates policy; edit it first"}
        ad.status, ad.violation = "in_review", None
        self._log("advertiser", "resubmit_ad", ad_id=ad_id)
        return {"ok": True, "status": "in_review"}

    # -- snapshots for the scorer / cli -------------------------------------
    def snapshot(self) -> dict:
        return {
            "accounts": {k: dataclasses.asdict(v) for k, v in self.accounts.items()},
            "campaigns": {k: dataclasses.asdict(v) for k, v in self.campaigns.items()},
            "ads": {k: dataclasses.asdict(v) for k, v in self.ads.items()},
            "charges": {k: dataclasses.asdict(v) for k, v in self.charges.items()},
        }


# ==========================================================================
# TOOL MANIFESTS: the two asymmetric API surfaces onto the SAME AdsPlatform.
# Each entry: the method name, a description, and a JSON input schema (minus the
# implicit args the harness fills, e.g. the advertiser's own account is bound).
# The dual control lives here: AGENT_TOOLS and ADVERTISER_TOOLS are disjoint on
# every MUTATING op.
# ==========================================================================
_STR = {"type": "string"}
_INT = {"type": "integer"}


def _tool(name, desc, props, required):
    return {"name": name, "description": desc,
            "input_schema": {"type": "object", "properties": props,
                             "required": required}}


AGENT_TOOLS = [
    _tool("get_account", "Look up any advertiser account's full status.",
          {"account_id": _STR}, ["account_id"]),
    _tool("list_campaigns", "List an account's campaigns.",
          {"account_id": _STR}, ["account_id"]),
    _tool("get_ad_review", "Get an ad's review status and any policy violation.",
          {"ad_id": _STR}, ["ad_id"]),
    _tool("list_charges", "List an account's charges.",
          {"account_id": _STR}, ["account_id"]),
    _tool("issue_credit", "Credit an account (support authority).",
          {"account_id": _STR, "amount_cents": _INT, "reason": _STR},
          ["account_id", "amount_cents", "reason"]),
    _tool("waive_charge", "Waive a specific charge (support authority).",
          {"charge_id": _STR, "reason": _STR}, ["charge_id", "reason"]),
    _tool("lift_account_limit",
          "Lift an account limit. Only succeeds once the underlying cause "
          "(e.g. payment) is resolved by the advertiser.",
          {"account_id": _STR}, ["account_id"]),
    _tool("expedite_ad_review",
          "Push an in-review ad to an immediate decision (support authority).",
          {"ad_id": _STR}, ["ad_id"]),
    _tool("clear_policy_review",
          "Clear an account's policy-review hold (support authority).",
          {"account_id": _STR}, ["account_id"]),
]

ADVERTISER_TOOLS = [
    _tool("get_account", "View your own account status.",
          {"account_id": _STR}, ["account_id"]),
    _tool("list_campaigns", "List your own campaigns.",
          {"account_id": _STR}, ["account_id"]),
    _tool("get_ad_review", "Check your ad's review status.",
          {"ad_id": _STR}, ["ad_id"]),
    _tool("update_payment_method",
          "Update your payment method (fixes a failed/expired payment).",
          {"account_id": _STR, "method": _STR}, ["account_id"]),
    _tool("add_funds", "Add prepaid funds to your account.",
          {"account_id": _STR, "amount_cents": _INT}, ["account_id", "amount_cents"]),
    _tool("pause_campaign", "Pause your campaign.",
          {"campaign_id": _STR}, ["campaign_id"]),
    _tool("resume_campaign", "Resume your campaign.",
          {"campaign_id": _STR}, ["campaign_id"]),
    _tool("edit_ad_creative", "Edit your ad's headline to fix a policy violation.",
          {"ad_id": _STR, "new_headline": _STR}, ["ad_id", "new_headline"]),
    _tool("resubmit_ad", "Resubmit your ad for review after editing it.",
          {"ad_id": _STR}, ["ad_id"]),
]

AGENT_TOOL_NAMES = {t["name"] for t in AGENT_TOOLS}
ADVERTISER_TOOL_NAMES = {t["name"] for t in ADVERTISER_TOOLS}

# The MUTATING subset of each surface (the reads are shared by both). Single source
# of truth for the coordination metric (run.py) and the disjointness test.
AGENT_MUTATING_TOOLS = {"issue_credit", "waive_charge", "lift_account_limit",
                        "expedite_ad_review", "clear_policy_review"}
ADVERTISER_MUTATING_TOOLS = {"update_payment_method", "add_funds", "pause_campaign",
                             "resume_campaign", "edit_ad_creative", "resubmit_ad"}


def dispatch(app: AdsPlatform, actor: str, name: str, args: dict) -> dict:
    """Execute a tool call against the app, enforcing the actor's authority.
    A caller that names a tool outside its surface is refused -- the dual-control
    boundary is enforced here, not left to the model's goodwill."""
    allowed = AGENT_TOOL_NAMES if actor == "agent" else ADVERTISER_TOOL_NAMES
    if name not in allowed:
        return {"ok": False, "error": f"'{name}' is not available to the {actor}"}
    method = getattr(app, name, None)
    if method is None:
        return {"ok": False, "error": f"unknown operation '{name}'"}
    try:
        return method(**args)
    except TypeError as e:
        return {"ok": False, "error": f"bad arguments for '{name}': {e}"}

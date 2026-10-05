# Andyur authorization policy.
#
# This file is the rules that used to live in Python, in server/pdp.py. Nothing
# here is new behaviour: it is the SAME decision, expressed as data the engine
# loads rather than code the server ships. That is the whole point -- change this
# file and authorization changes, with no rebuild and no redeploy.
#
# Read a Rego rule as: "decision is true IF all of these hold." Several rules
# with the same name are OR'd; conditions inside one rule are AND'd. Order is
# irrelevant, unlike an ACL where first match wins.

package andyur.authz

import rego.v1

# Deny unless a rule below proves otherwise. This single line is what makes the
# policy fail-closed by construction: a typo in a rule name silently denies
# rather than silently permits.
default decision := false

# A decision is a permit that nothing restricts.
#
# This shape matters. Rules with the same name are OR'd, so a policy made only of
# `decision if ...` rules can only ever be made MORE permissive by adding to it --
# there is no way to layer on a restriction. Splitting permit from restricted is
# what makes the policy extensible in both directions, and it is why a new module
# can tighten authorization without editing this file.
decision if {
	permit
	not restricted
}

# No restrictions by default, so this file alone behaves exactly like the builtin
# PDP. Additional modules in this package may define `restricted` rules.
default restricted := false

# --- operators -------------------------------------------------------------

permit if input.subject.properties.is_operator

# --- enforcement time: may this RUN perform this action right now? ----------
# The run carries the scope sealed into its grant, so the PDP stays stateless:
# it is told the run's authority rather than looking it up in Andyur's database.

# scope == null means no scope model is active for this run (backward compatible).
# Note this is an explicit null check, NOT `not input...scope`: in Rego, null is
# a defined value, so `not null` is false and that spelling would deny here.
permit if {
	input.subject.type == "run"
	input.subject.properties.scope == null
}

permit if {
	input.subject.type == "run"
	"*" in input.subject.properties.scope
}

permit if {
	input.subject.type == "run"
	input.action.name in input.subject.properties.scope
}

# --- grant time: may a run for this USER hold this scope? -------------------
# Asked once per scope the task declared. Andyur keeps the ones that come back
# true, so the intersection is an outcome here rather than an operation there.

permit if {
	input.subject.type == "user"
	"*" in input.subject.properties.entitlements
}

permit if {
	input.subject.type == "user"
	input.action.name in input.subject.properties.entitlements
}

# --- why: the decider's own reason, for the audit trail ---------------------
# AuthZEN carries `reason_admin` for exactly this: the reason a DECIDER can give
# an administrator, as distinct from `reason_user`, which is what may safely be
# shown to the caller. Without it the enforcement point has to guess why its own
# request was refused, and every denial in the log looks identical.
#
# It is deliberately coarse. A reason string is read by whoever can read logs,
# so it says which class of rule decided, never which scopes the subject holds
# or what would have been sufficient -- a denial message that explains how to
# succeed is an oracle for probing the policy.
#
# The four rules below are mutually exclusive by construction. Rego requires it:
# two complete rules of the same name producing different values at once is a
# conflict error at evaluation time, which would fail the query rather than
# return a wrong answer, but it would fail it in production.

default reason_admin := "denied: no rule permits this subject for this action"

reason_admin := "permitted: operator" if {
	input.subject.properties.is_operator
	not restricted
}

reason_admin := "denied: permitted by base policy, then restricted by an additional module" if {
	permit
	restricted
}

reason_admin := "permitted: within the authority already granted" if {
	permit
	not restricted
	not input.subject.properties.is_operator
}

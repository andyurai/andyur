# Authorization for OPA'S OWN API.
#
# THE HOLE THIS CLOSES. OPA's REST API is unauthenticated and fully writable by
# default. Anyone who can reach the port runs
#
#     curl -X PUT http://opa:8181/v1/policies/pwn --data-binary @evil.rego
#
# and replaces the authorization policy of the entire platform. Every scope
# check, every entitlement, every restriction is then whatever the attacker
# wrote. The policy engine is a higher-value target than the thing it protects,
# because compromising it compromises every decision at once, silently, with no
# code change and nothing in the application's audit trail.
#
# The counterintuitive part: the fix is not authentication, it is AUTHORIZATION.
# A token alone would still let whoever holds it rewrite policy. So this file
# grants the one client we have exactly one capability -- ask a question -- and
# grants NOBODY the ability to change an answer. Policy arrives only by signed
# bundle (see opa-config.yaml), which is a path this API cannot reach.
#
# Loaded at startup with:  --authentication=token --authorization=basic
# OPA evaluates system.authz.allow for EVERY API request, including this one's
# own package, before the request is served.

package system.authz

import rego.v1

# Deny every request that no rule below explicitly allows. With
# --authorization=basic an undefined or misspelled rule denies rather than
# permits, so a mistake in this file fails closed like the rest of the platform.
default allow := false

# The token the policy enforcement point presents. Read from OPA's environment
# rather than baked in, so the token is a deployment secret and this file stays
# safe to publish.
#
# If the variable is unset this rule is UNDEFINED, not empty-string, so every
# authenticated route denies rather than matching a caller who sent no token.
# That is the desired failure: an operator who forgets to set the token gets a
# dead PDP (loud, fail-closed), never an open one.
query_token := opa.runtime().env.OPA_QUERY_TOKEN

# --- what is allowed -------------------------------------------------------

# Liveness, unauthenticated. Orchestrators and start-up scripts must be able to
# probe readiness without holding a credential, and /health discloses nothing
# beyond "the process is up".
allow if {
	input.method == "GET"
	input.path == ["health"]
}

# The decision query, and nothing else. This is the whole capability granted to
# the enforcement point: POST a question to one fixed policy path.
#
# Least privilege applied to our own client: the shim's token can ASK but can
# never WRITE, so stealing it buys an attacker the ability to learn decisions,
# not to change them. Separating those two is the entire point of this file.
allow if {
	input.method == "POST"
	input.path == ["v1", "data", "andyur", "authz"]
	input.identity == query_token
}

# Everything else -- PUT/PATCH/DELETE on /v1/policies, writes to /v1/data,
# raw policy reads, /v1/query, /v1/compile, the diagnostic endpoints -- falls
# through to `default allow := false`. There is deliberately no administrative
# identity: no credential exists that can mutate this engine over HTTP, so
# there is no credential to steal, phish, or leak. Policy changes go through
# the signed bundle pipeline instead.
#
# Known limitation, stated rather than hidden: `==` on the token is not a
# constant-time comparison (Rego exposes no constant-time primitive), so this
# check is theoretically distinguishable by timing. It is a fixed-length
# high-entropy token over a local/internal network, and the realistic attacker
# path is stealing the token from the shim's environment, not timing OPA. If
# that threat model changes, terminate auth in a proxy that can compare safely.

# What the decision log must NOT record.
#
# A decision log is an audit trail, and an audit trail is a copy of your inputs
# in a place with different access controls than the original. The verdict and
# the action are what an auditor needs; the caller's identity and the exact
# authority they hold are not, and writing them into a shared log stream would
# spread the very material the rest of the platform works to confine.
#
# So this erases the identifying and credential-shaped fields before the entry
# is written, keeping the audit answer ("was files:write permitted, and why")
# without the audit leak ("run r1 for user alice holds files:read, tasks:write").
#
# Loaded from disk, not from the bundle, because it lives under the `system`
# root that no bundle is allowed to own (see opa-config.yaml).

package system.log

import rego.v1

# Who asked. Under user delegation this is an OIDC subject, so it is personal
# data as well as a decision input.
mask contains "/input/subject/id"

# The authority the run currently holds. An attacker reading logs should not be
# able to inventory which runs carry which scopes and pick the richest target.
mask contains "/input/subject/properties/scope"

# The same for the user's full entitlement set at grant time.
mask contains "/input/subject/properties/entitlements"

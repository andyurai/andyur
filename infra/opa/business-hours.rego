# A restriction that Andyur's Python could not express.
#
# The builtin PDP decides by set membership: is this action in the granted scope.
# It has no notion of when a request was made, and adding one would mean a code
# change, a review, a build and a deploy. This file adds that rule as DATA, loaded
# into a running engine, with no Andyur change of any kind.
#
# Note this defines `restricted`, not `decision`. Rules with the same name are
# OR'd, so a module can only ever add permits; the base policy's
# `decision if { permit; not restricted }` shape is what makes a module able to
# TIGHTEN authorization rather than only loosen it.

package andyur.authz

import rego.v1

# No writes before 09:00 UTC.
restricted if {
	endswith(input.action.name, ":write")
	time.clock(time.parse_rfc3339_ns(input.context.time))[0] < 9
}

# ...or from 18:00 UTC.
restricted if {
	endswith(input.action.name, ":write")
	time.clock(time.parse_rfc3339_ns(input.context.time))[0] >= 18
}

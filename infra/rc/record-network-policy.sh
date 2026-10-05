#!/usr/bin/env bash
# Record ONE current network-containment probe.
#
# verify-network-policy.sh writes its own dated artifact and REFUSES TO
# OVERWRITE one, which is right -- recorded evidence is not something a re-run
# should silently replace. It also means the second run on any given day fails
# with "refusing to overwrite evidence", which is what happened to the RC
# gate's containment line: a refusal about a FILE, reported as a containment
# failure.
#
# One gate, one current record. The prior one is removed BEFORE the probe runs,
# so a failed probe leaves no record at all rather than leaving yesterday's
# reading where today's should be.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$HERE"
rm -f infra/kubernetes/result-network-policy-*.json
exec bash infra/kubernetes/verify-network-policy.sh

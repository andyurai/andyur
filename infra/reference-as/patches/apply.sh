#!/usr/bin/env bash
# Build a patched go-oidc for the reference AS, without vendoring upstream source
# into this repository.
#
# WHY A PATCH AT ALL. go-oidc's exchange handler is the only place that knows the
# SUBJECT -- it is what resolves the subject token -- but it does not receive the
# requested scope or authorization_details. Those are validated earlier, in this
# order (internal/token/exchange.go at v0.25.0):
#
#     47   validateScopes
#     51   validateResources
#     55   validateAuthDetails
#     92   ctx.TokenExchangeHandle(...)   <- the subject is learned HERE
#    105   NewGrant(...)
#
# So a subject-aware policy over scope or RAR has nowhere to live: everything that
# could judge them runs before the subject exists. The patch adds two fields that
# are ALREADY PARSED at line 92 and simply not passed through.
#
# This is filed upstream (see UPSTREAM-ISSUE.md). When it merges, delete this
# directory and the `replace` line in go.mod.
#
# The generated tree is gitignored: only the patch and this script are ours to
# keep, and a copy of somebody else's repository does not belong in git history.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${GOIDC_VERSION:-v0.25.0}"
EXPECTED_COMMIT="${GOIDC_EXPECTED_COMMIT:-6aeac93f370044ca9a59a556b9230cd10bd96868}"
OUT="${GOIDC_OUT:-$HERE/go-oidc}"

command -v git >/dev/null || { echo "git is required"; exit 1; }
command -v go  >/dev/null || { echo "go is required"; exit 1; }

if [ -d "$OUT" ]; then
  echo "already present: $OUT  (rm -rf it to rebuild)"
  exit 0
fi

echo "cloning go-oidc $VERSION"
git clone -q --depth 1 --branch "$VERSION" https://github.com/luikyv/go-oidc.git "$OUT"
actual_commit="$(git -C "$OUT" rev-parse HEAD)"
[ "$actual_commit" = "$EXPECTED_COMMIT" ] || {
  echo "go-oidc commit $actual_commit does not match $EXPECTED_COMMIT" >&2
  exit 1
}

echo "applying $(basename "$HERE")/0001-*.patch"
( cd "$OUT" && git apply "$HERE"/0001-*.patch )

echo "building"
( cd "$OUT" && go build ./... )

echo
echo "patched go-oidc ready at $OUT"
echo "reference-as/go.mod already points at it via a replace directive."

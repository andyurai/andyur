module github.com/andyur/reference-as

go 1.26.4

require (
	github.com/luikyv/go-oidc v0.25.0
	github.com/spiffe/go-spiffe/v2 v2.8.1
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
)

// The exchange handler is the only place that knows the subject, and it does not
// receive the requested scope or authorization_details -- so a subject-aware
// policy has nowhere to run. See patches/UPSTREAM-ISSUE.md for the ordering
// evidence. Build the patched tree with ./patches/apply.sh; the tree itself is
// gitignored, only the patch is ours to keep. Delete both when this merges.
replace github.com/luikyv/go-oidc => ./patches/go-oidc

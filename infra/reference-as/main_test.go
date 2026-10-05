package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDPoPRequiredProfileIsExplicit(t *testing.T) {
	t.Setenv("ANDYUR_REFAS_DPOP_REQUIRED", "")
	if got := len(dpopOptions()); got != 0 {
		t.Fatalf("default DPoP options = %d, want optional profile", got)
	}
	t.Setenv("ANDYUR_REFAS_DPOP_REQUIRED", "1")
	if got := len(dpopOptions()); got != 1 {
		t.Fatalf("required DPoP options = %d, want 1", got)
	}
}

func TestNumericDateRequiresAnInteger(t *testing.T) {
	want := time.Unix(123, 0)
	got, err := numericDate(float64(123))
	if err != nil || !got.Equal(want) {
		t.Fatalf("numericDate(123) = (%v, %v), want (%v, nil)", got, err, want)
	}
	for _, value := range []any{nil, "123", 123, 123.5} {
		if _, err := numericDate(value); err == nil {
			t.Fatalf("numericDate(%#v) unexpectedly succeeded", value)
		}
	}
}

func clearActorProofEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"ANDYUR_REFAS_ACTOR_SPIFFE_BUNDLE",
		"ANDYUR_REFAS_ACTOR_AUDIENCE",
		"ANDYUR_REFAS_ACTOR_EXPECTED_ID",
		"ANDYUR_REFAS_ACTOR_MAX_LIFETIME_SECONDS",
	} {
		t.Setenv(name, "")
	}
}

func TestActorVerifierIsOffOnlyWhenEveryInputIsAbsent(t *testing.T) {
	clearActorProofEnv(t)
	verifier, err := loadActorVerifier()
	if err != nil || verifier != nil {
		t.Fatalf("unconfigured actor verifier = (%v, %v), want (nil, nil)", verifier, err)
	}

	t.Setenv("ANDYUR_REFAS_ACTOR_AUDIENCE", "https://as.example/token")
	if _, err := loadActorVerifier(); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial actor verifier error = %v", err)
	}
}

func TestActorVerifierRejectsInvalidLifetimeConfiguration(t *testing.T) {
	clearActorProofEnv(t)
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(bundle, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANDYUR_REFAS_ACTOR_SPIFFE_BUNDLE", bundle)
	t.Setenv("ANDYUR_REFAS_ACTOR_AUDIENCE", "https://as.example/token")
	t.Setenv("ANDYUR_REFAS_ACTOR_EXPECTED_ID", "spiffe://andyur.local/run/r-1")
	t.Setenv("ANDYUR_REFAS_ACTOR_MAX_LIFETIME_SECONDS", "0")
	if _, err := loadActorVerifier(); err == nil || !strings.Contains(err.Error(), "positive integer") {
		t.Fatalf("invalid lifetime error = %v", err)
	}
}

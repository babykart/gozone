package oidc

import (
	"encoding/json"
	"testing"
)

func rawClaims(t *testing.T, j string) map[string]json.RawMessage {
	t.Helper()
	m := make(map[string]json.RawMessage)
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		t.Fatalf("unmarshal raw claims: %v", err)
	}
	return m
}

func TestClaimStrings_ToplevelArray(t *testing.T) {
	raw := rawClaims(t, `{"groups":["admins","devs","ops"]}`)
	got := ClaimStrings(raw, "groups")
	want := []string{"admins", "devs", "ops"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestClaimStrings_SingleString(t *testing.T) {
	raw := rawClaims(t, `{"role":"admin"}`)
	got := ClaimStrings(raw, "role")
	if len(got) != 1 || got[0] != "admin" {
		t.Errorf("got %v, want [admin]", got)
	}
}

func TestClaimStrings_NestedPath(t *testing.T) {
	// Keycloak-style realm_access.roles.
	raw := rawClaims(t, `{"realm_access":{"roles":["default-roles","admin"]}}`)
	got := ClaimStrings(raw, "realm_access.roles")
	if len(got) != 2 || got[0] != "default-roles" || got[1] != "admin" {
		t.Errorf("got %v, want [default-roles admin]", got)
	}
}

func TestClaimStrings_MissingClaim(t *testing.T) {
	raw := rawClaims(t, `{"email":"x@y.z"}`)
	if got := ClaimStrings(raw, "groups"); got != nil {
		t.Errorf("expected nil for missing claim, got %v", got)
	}
}

func TestClaimStrings_EmptyPath(t *testing.T) {
	raw := rawClaims(t, `{"groups":["a"]}`)
	if got := ClaimStrings(raw, ""); got != nil {
		t.Errorf("expected nil for empty path, got %v", got)
	}
}

func TestClaimStrings_NonStringArray(t *testing.T) {
	// Heterogeneous array: numbers are skipped, strings kept.
	raw := rawClaims(t, `{"groups":["admins", 42, "devs"]}`)
	got := ClaimStrings(raw, "groups")
	if len(got) != 2 || got[0] != "admins" || got[1] != "devs" {
		t.Errorf("got %v, want [admins devs]", got)
	}
}

func TestClaimStrings_NumericValue(t *testing.T) {
	// A bare number is neither a string nor an array → nil.
	raw := rawClaims(t, `{"level":5}`)
	if got := ClaimStrings(raw, "level"); got != nil {
		t.Errorf("expected nil for numeric value, got %v", got)
	}
}

func TestClaimStrings_NilMap(t *testing.T) {
	if got := ClaimStrings(nil, "groups"); got != nil {
		t.Errorf("expected nil for nil map, got %v", got)
	}
}

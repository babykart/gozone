package oidc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestGiteaPresetRegistered(t *testing.T) {
	p, ok := LookupPreset("gitea")
	if !ok {
		t.Fatal("gitea preset must be registered")
	}
	if p.DisplayName != "Gitea" {
		t.Errorf("gitea DisplayName = %q, want %q", p.DisplayName, "Gitea")
	}
	if p.Icon != "gitea" {
		t.Errorf("gitea Icon = %q, want %q", p.Icon, "gitea")
	}
	// Gitea OIDC scopes: openid must be present.
	found := false
	for _, s := range p.DefaultScopes {
		if s == ScopeOpenID {
			found = true
		}
	}
	if !found {
		t.Errorf("gitea DefaultScopes missing %q: %v", ScopeOpenID, p.DefaultScopes)
	}
}

func TestStandardPresetsRegistered(t *testing.T) {
	for _, name := range []string{"google", "github", "gitlab", "keycloak", "authentik", "azure"} {
		if _, ok := LookupPreset(name); !ok {
			t.Errorf("standard preset %q must be registered", name)
		}
	}
}

func TestLookupPresetUnknownIsGeneric(t *testing.T) {
	p, ok := LookupPreset("acme-corp")
	if ok {
		t.Error("unknown provider name should not match a preset")
	}
	if p.Type != "" || p.DisplayName != "" {
		t.Errorf("unknown preset should be zero-value, got %+v", p)
	}
}

func TestPresetNamesIncludesGitea(t *testing.T) {
	names := PresetNames()
	if len(names) == 0 {
		t.Fatal("PresetNames returned empty list")
	}
	if names[0] != "gitea" {
		t.Errorf("gitea must be the first preset name, got %q", names[0])
	}
	// No duplicates.
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate preset name %q", n)
		}
		seen[n] = true
	}
}

func TestDefaultScopesFor(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		provider     []string
		global       []string
		wantFirst    string
		wantContains []string
	}{
		{name: "provider overrides", providerName: "gitea", provider: []string{"openid", "email", "groups"}, global: nil, wantFirst: "openid", wantContains: []string{"email", "groups"}},
		{name: "preset fallback", providerName: "gitea", provider: nil, global: nil, wantFirst: "openid", wantContains: []string{"profile", "email"}},
		{name: "global fallback for unknown", providerName: "acme", provider: nil, global: []string{"openid", "profile"}, wantFirst: "openid", wantContains: []string{"profile"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scopes := DefaultScopesFor(tc.providerName, tc.provider, tc.global)
			if len(scopes) == 0 {
				t.Fatal("expected non-empty scopes")
			}
			if scopes[0] != tc.wantFirst {
				t.Errorf("first scope = %q, want %q", scopes[0], tc.wantFirst)
			}
			for _, want := range tc.wantContains {
				found := false
				for _, got := range scopes {
					if got == want {
						found = true
					}
				}
				if !found {
					t.Errorf("scopes %v missing %q", scopes, want)
				}
			}
		})
	}
}

func TestNormalizeScopesOpenIDOnce(t *testing.T) {
	scopes := normalizeScopes([]string{"email", "openid", "profile", "email", "openid"})
	if len(scopes) < 3 {
		t.Fatalf("expected at least 3 scopes, got %v", scopes)
	}
	if scopes[0] != ScopeOpenID {
		t.Errorf("first scope must be openid, got %q", scopes[0])
	}
	count := 0
	for _, s := range scopes {
		if s == ScopeOpenID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("openid must appear exactly once, got %d in %v", count, scopes)
	}
}

func TestStateTokenRoundTrip(t *testing.T) {
	key := []byte("test-state-key-32-bytes-long-000")
	state, verifier, challenge, nonce, err := newStateToken(key, "gitea")
	if err != nil {
		t.Fatalf("newStateToken: %v", err)
	}
	if state == "" || verifier == "" || challenge == "" || nonce == "" {
		t.Fatal("expected non-empty state fields")
	}
	// Challenge must be the S256 of the verifier.
	if challenge != s256Challenge(verifier) {
		t.Error("challenge does not match S256(verifier)")
	}

	payload, err := verifyStateToken(key, state)
	if err != nil {
		t.Fatalf("verifyStateToken: %v", err)
	}
	if payload.Provider != "gitea" {
		t.Errorf("provider = %q, want gitea", payload.Provider)
	}
	if payload.Nonce != nonce {
		t.Errorf("nonce mismatch: %q != %q", payload.Nonce, nonce)
	}
	if payload.Verifier != verifier {
		t.Errorf("verifier mismatch: %q != %q", payload.Verifier, verifier)
	}
}

func TestStateTokenTamperRejected(t *testing.T) {
	key := []byte("test-state-key-32-bytes-long-000")
	state, _, _, _, err := newStateToken(key, "gitea")
	if err != nil {
		t.Fatalf("newStateToken: %v", err)
	}
	// Flip the last character of the token (ciphertext / nonce) so the AES-GCM
	// authentication tag no longer verifies.
	tampered := state[:len(state)-1]
	last := state[len(state)-1]
	if last == 'a' {
		tampered += "b"
	} else {
		tampered += "a"
	}
	if _, err := verifyStateToken(key, tampered); err == nil {
		t.Error("tampered state token must fail verification")
	}
}

func TestStateTokenWrongKeyRejected(t *testing.T) {
	key := []byte("test-state-key-32-bytes-long-000")
	state, _, _, _, err := newStateToken(key, "gitea")
	if err != nil {
		t.Fatalf("newStateToken: %v", err)
	}
	other := []byte("a-different-key-32-bytes-long-11")
	if _, err := verifyStateToken(other, state); err == nil {
		t.Error("state token verified with the wrong key")
	}
}

func TestStateTokenExpiry(t *testing.T) {
	key := []byte("test-state-key-32-bytes-long-000")
	// Build a token with an already-expired timestamp by encrypting a payload
	// directly, then assert verification rejects it on the expiry check (which
	// runs after the successful AES-GCM decryption).
	payload := statePayload{
		Provider: "gitea",
		Nonce:    "n",
		Verifier: "v",
		Exp:      time.Now().Add(-time.Minute).Unix(),
	}
	state, err := encryptState(key, payload)
	if err != nil {
		t.Fatalf("encryptState: %v", err)
	}
	if _, err := verifyStateToken(key, state); err == nil {
		t.Error("expired state token must fail verification")
	}
}

func TestS256Challenge(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := s256Challenge(v); got != want {
		t.Errorf("s256Challenge mismatch: got %q want %q", got, want)
	}
}

func TestRandomCodeVerifierUnique(t *testing.T) {
	a, err := randomCodeVerifier()
	if err != nil {
		t.Fatalf("randomCodeVerifier: %v", err)
	}
	b, err := randomCodeVerifier()
	if err != nil {
		t.Fatalf("randomCodeVerifier: %v", err)
	}
	if a == b {
		t.Error("two verifiers must differ")
	}
	if len(a) < 43 || len(a) > 128 {
		t.Errorf("verifier length %d out of [43,128]", len(a))
	}
}

func TestRandomStringEntropy(t *testing.T) {
	s, err := randomString(16)
	if err != nil {
		t.Fatalf("randomString: %v", err)
	}
	if len(s) != 32 { // 16 bytes → 32 hex chars
		t.Errorf("randomString length = %d, want 32", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("randomString not hex: %v", err)
	}
}

func TestRandomCodeVerifierUsesCryptoRand(t *testing.T) {
	// Sanity: ensure the package's random source is crypto/rand by checking it
	// does not panic and yields distinct values (crypto/rand cannot be tested
	// for "true" randomness, but distinctness guards against a constant source).
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		v, err := randomCodeVerifier()
		if err != nil {
			t.Fatalf("randomCodeVerifier: %v", err)
		}
		if seen[v] {
			t.Fatal("duplicate verifier — source not random")
		}
		seen[v] = true
	}
	_ = rand.Reader // ensure crypto/rand import is exercised
}

func TestByteIndex(t *testing.T) {
	if got := byteIndex("enc.sig", '.'); got != 3 {
		t.Errorf("byteIndex present = %d, want 3", got)
	}
	if got := byteIndex("no-separator", '.'); got != -1 {
		t.Errorf("byteIndex missing = %d, want -1", got)
	}
	if got := byteIndex("", '.'); got != -1 {
		t.Errorf("byteIndex empty = %d, want -1", got)
	}
}

// TestStateTokenPayloadEncrypted is the B1 regression: the PKCE verifier,
// nonce, and provider name MUST NOT be recoverable from the opaque state value.
// Before the fix the payload was only HMAC-signed, so anyone observing the
// state (URL, server logs, Referer) could base64-decode the verifier. AES-GCM
// encryption makes the payload confidential while the GCM tag preserves
// integrity.
func TestStateTokenPayloadEncrypted(t *testing.T) {
	key := []byte("test-state-key-32-bytes-long-000")
	state, verifier, _, nonce, err := newStateToken(key, "gitea")
	if err != nil {
		t.Fatalf("newStateToken: %v", err)
	}

	// The plaintext secrets must not appear in the token string itself.
	if strings.Contains(state, verifier) {
		t.Error("state token leaks the PKCE verifier in cleartext")
	}
	if strings.Contains(state, nonce) {
		t.Error("state token leaks the nonce in cleartext")
	}
	if strings.Contains(state, "gitea") {
		t.Error("state token leaks the provider name in cleartext")
	}

	// ...nor in the base64-decoded bytes (nonce segment + ciphertext segment).
	var raw []byte
	for _, seg := range strings.SplitN(state, ".", 2) {
		if b, derr := base64.RawURLEncoding.DecodeString(seg); derr == nil {
			raw = append(raw, b...)
		}
	}
	if bytes.Contains(raw, []byte(verifier)) {
		t.Error("decoded state token contains the PKCE verifier (payload not encrypted)")
	}
	if bytes.Contains(raw, []byte("gitea")) {
		t.Error("decoded state token contains the provider name (payload not encrypted)")
	}
}

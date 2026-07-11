package oidc

import (
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

// newTestService builds a minimal Service with a single provider whose oauth2
// config points at a dummy auth endpoint — enough to exercise AuthCodeURL
// without a live IdP.
func newTestService(t *testing.T) *Service {
	t.Helper()
	return &Service{
		stateKey: []byte("test-state-key-32-bytes-long-0000"),
		providers: map[string]*ProviderInstance{
			"test": {
				Name: "test",
				oauth2: &oauth2.Config{
					ClientID: "cid",
					Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example.com/auth"},
				},
			},
		},
	}
}

// TestAuthCodeURL_SendsNonce is the C-1 regression test: AuthCodeURL must send
// the nonce to the IdP as an authorization-request parameter. Before the fix
// the nonce minted in newStateToken was discarded ("_"), so the IdP never
// received one, never echoed it in the id_token, and HandleCallback's
// idToken.Nonce != payload.Nonce check failed on every login — breaking SSO
// entirely. This test fails the moment the oidc.Nonce(nonce) option is removed
// from AuthCodeURL.
func TestAuthCodeURL_SendsNonce(t *testing.T) {
	svc := newTestService(t)
	authURL, err := svc.AuthCodeURL("test", "https://gozone.example.com/auth/oidc/test/callback")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := parsed.Query()

	// PKCE must be present too (guards against a broader regression).
	if q.Get("code_challenge") == "" {
		t.Error("expected a code_challenge (PKCE) in the auth URL")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}

	nonce := q.Get("nonce")
	if nonce == "" {
		t.Fatal("auth URL must carry a nonce parameter (C-1: the nonce was previously discarded and SSO could never succeed)")
	}

	// The nonce sent to the IdP must match the one embedded in the signed
	// state token, so HandleCallback can compare it against the id_token claim.
	state := q.Get("state")
	if state == "" {
		t.Fatal("auth URL must carry a state parameter")
	}
	payload, err := verifyStateToken(svc.stateKey, state)
	if err != nil {
		t.Fatalf("verifyStateToken: %v", err)
	}
	if payload.Nonce != nonce {
		t.Errorf("state nonce %q != URL nonce %q (they must match for the callback check to pass)", payload.Nonce, nonce)
	}
}

// TestAuthCodeURL_EmbedsProviderInState confirms the provider name is bound
// into the state, so a callback for the wrong provider is rejected.
func TestAuthCodeURL_EmbedsProviderInState(t *testing.T) {
	svc := newTestService(t)
	authURL, err := svc.AuthCodeURL("test", "https://gozone.example.com/auth/oidc/test/callback")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	parsed, _ := url.Parse(authURL)
	payload, err := verifyStateToken(svc.stateKey, parsed.Query().Get("state"))
	if err != nil {
		t.Fatalf("verifyStateToken: %v", err)
	}
	if payload.Provider != "test" {
		t.Errorf("state provider = %q, want test", payload.Provider)
	}
}

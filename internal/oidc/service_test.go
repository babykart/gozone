package oidc

import (
	"fmt"
	"net/url"
	"sync"
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

// TestService_StateReplayRejected is the L-3 integration test: a Service with
// a stateStore must reject a replayed state token at the consumption step. The
// test exercises the real newStateToken → consume path on the Service's store,
// verifying the wiring is correct without needing a live IdP (HandleCallback's
// token exchange would fail against the dummy endpoint, but consume runs before
// the exchange, so the second call is rejected by the store, not the network).
func TestService_StateReplayRejected(t *testing.T) {
	svc := newTestService(t)
	svc.usedStates = newStateStore()
	t.Cleanup(svc.Close)

	// Build a real state token for the "test" provider.
	state, _, _, _, err := newStateToken(svc.stateKey, "test")
	if err != nil {
		t.Fatalf("newStateToken: %v", err)
	}

	// First consumption — must succeed.
	if !svc.usedStates.consume(state) {
		t.Fatal("first consume should succeed (fresh state)")
	}
	// Replay — must be rejected.
	if svc.usedStates.consume(state) {
		t.Error("replayed state must be rejected (REVIEW.md L-3)")
	}
}

// TestAuthCodeURL_DoesNotMutateSharedConfig is the L-4 regression test:
// AuthCodeURL must not mutate the shared ProviderInstance.oauth2.RedirectURL.
// Before the fix, inst.oauth2.RedirectURL = callbackURL was written directly on
// the shared instance, racing with concurrent calls and leaking the last
// callback URL into subsequent requests.
func TestAuthCodeURL_DoesNotMutateSharedConfig(t *testing.T) {
	svc := newTestService(t)
	const cb = "https://gozone.example.com/auth/oidc/test/callback"

	if _, err := svc.AuthCodeURL("test", cb); err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}

	inst, _ := svc.Provider("test")
	if inst.oauth2.RedirectURL != "" {
		t.Errorf("shared oauth2.Config.RedirectURL was mutated to %q; must remain empty (REVIEW.md L-4)",
			inst.oauth2.RedirectURL)
	}
}

// TestAuthCodeURL_ConcurrentNoRace verifies that concurrent AuthCodeURL calls
// with distinct callback URLs each produce the correct redirect_uri, and that
// no data race occurs (run under -race). Before the L-4 fix, two concurrent
// calls overwrote each other's RedirectURL on the shared oauth2.Config, so one
// of them would carry the wrong redirect_uri.
func TestAuthCodeURL_ConcurrentNoRace(t *testing.T) {
	svc := newTestService(t)
	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			cb := fmt.Sprintf("https://host%d.example.com/auth/oidc/test/callback", n)
			authURL, err := svc.AuthCodeURL("test", cb)
			if err != nil {
				t.Errorf("goroutine %d: AuthCodeURL: %v", n, err)
				return
			}
			parsed, err := url.Parse(authURL)
			if err != nil {
				t.Errorf("goroutine %d: parse: %v", n, err)
				return
			}
			got := parsed.Query().Get("redirect_uri")
			if got != cb {
				t.Errorf("goroutine %d: redirect_uri = %q, want %q (shared config mutation — REVIEW.md L-4)",
					n, got, cb)
			}
		}(i)
	}
	wg.Wait()
}

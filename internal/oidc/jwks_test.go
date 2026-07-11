package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// jwksServer is a controllable mock jwks_uri endpoint. It counts requests and
// can swap the served key set or return a failure status on demand.
type jwksServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	body    []byte
	fail    bool
	counter atomic.Int64
}

func newJWKSServer(t *testing.T, body []byte) *jwksServer {
	t.Helper()
	j := &jwksServer{body: body}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.counter.Add(1)
		j.mu.Lock()
		fail, body := j.fail, j.body
		j.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) // #nosec G104
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwksServer) setBody(b []byte) {
	j.mu.Lock()
	j.body = b
	j.fail = false
	j.mu.Unlock()
}

func (j *jwksServer) setFail(f bool) {
	j.mu.Lock()
	j.fail = f
	j.mu.Unlock()
}

func (j *jwksServer) count() int64 { return j.counter.Load() }

// makeSigningKey generates an RSA key + its public JWKS JSON + a signer that
// emits the given kid in the JWS header.
func makeSigningKey(t *testing.T, kid string) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privJWK := jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: "RS256", Use: "sig"}
	pubJWK := privJWK.Public()
	body, err := json.Marshal(struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}{Keys: []jose.JSONWebKey{pubJWK}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return priv, body
}

// signToken signs an arbitrary JSON payload with priv, carrying kid in the
// header, and returns the compact JWS string.
func signToken(t *testing.T, priv *rsa.PrivateKey, kid string, payload map[string]string) string {
	t.Helper()
	payloadBytes, _ := json.Marshal(payload)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": kid}},
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	obj, err := signer.Sign(payloadBytes)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("compact serialize: %v", err)
	}
	return compact
}

func TestCachedKeySet_VerifyFromCache(t *testing.T) {
	priv, body := makeSigningKey(t, "kid-1")
	srv := newJWKSServer(t, body)
	ks := newCachedKeySet(srv.srv.URL, 0) // no proactive goroutine → deterministic
	defer ks.Close()

	tok := signToken(t, priv, "kid-1", map[string]string{"sub": "alice"})

	payload, err := ks.VerifySignature(context.Background(), tok)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if string(payload) == "" {
		t.Error("expected non-empty payload")
	}
	if got := srv.count(); got != 1 {
		t.Errorf("expected 1 fetch after first verify, got %d", got)
	}

	// Second verify is served from cache → no new fetch.
	if _, err := ks.VerifySignature(context.Background(), tok); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if got := srv.count(); got != 1 {
		t.Errorf("expected still 1 fetch (cache hit), got %d", got)
	}
}

func TestCachedKeySet_ReactiveRefreshOnUnknownKid(t *testing.T) {
	priv1, body1 := makeSigningKey(t, "kid-1")
	srv := newJWKSServer(t, body1)
	ks := newCachedKeySet(srv.srv.URL, 0)
	defer ks.Close()

	tok1 := signToken(t, priv1, "kid-1", map[string]string{"sub": "alice"})
	if _, err := ks.VerifySignature(context.Background(), tok1); err != nil {
		t.Fatalf("verify kid-1: %v", err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("expected 1 fetch, got %d", got)
	}

	// Rotate: the JWKS now also advertises kid-2.
	priv2, body2 := makeSigningKey(t, "kid-2")
	merged := mergeJWKS(t, body1, body2)
	srv.setBody(merged)
	tok2 := signToken(t, priv2, "kid-2", map[string]string{"sub": "bob"})

	// kid-2 is unknown to the cache → reactive refresh, then it verifies.
	if _, err := ks.VerifySignature(context.Background(), tok2); err != nil {
		t.Fatalf("verify kid-2 after rotation: %v", err)
	}
	if got := srv.count(); got != 2 {
		t.Errorf("expected 2 fetches (reactive refresh on unknown kid), got %d", got)
	}
}

func TestCachedKeySet_FailedRefreshKeepsCachedKeys(t *testing.T) {
	priv, body := makeSigningKey(t, "kid-1")
	srv := newJWKSServer(t, body)
	ks := newCachedKeySet(srv.srv.URL, 0)
	defer ks.Close()

	tok := signToken(t, priv, "kid-1", map[string]string{"sub": "alice"})
	if _, err := ks.VerifySignature(context.Background(), tok); err != nil {
		t.Fatalf("prime cache: %v", err)
	}

	// The JWKS endpoint starts failing. An explicit refresh must return an error
	// but MUST NOT wipe the cached keys.
	srv.setFail(true)
	if err := ks.refresh(context.Background()); err == nil {
		t.Error("expected refresh to fail when the endpoint returns 500")
	}
	if got := srv.count(); got != 2 {
		t.Errorf("expected 2 fetches (prime + failed refresh), got %d", got)
	}

	// Verification still succeeds from the retained cache (no new fetch).
	if _, err := ks.VerifySignature(context.Background(), tok); err != nil {
		t.Errorf("verify must still work with cached keys after a failed refresh: %v", err)
	}
	if got := srv.count(); got != 2 {
		t.Errorf("expected no new fetch (cache retained), got %d", got)
	}
}

func TestCachedKeySet_ProactiveRefreshAndClose(t *testing.T) {
	priv, body := makeSigningKey(t, "kid-1")
	srv := newJWKSServer(t, body)
	// Short TTL → the background goroutine refreshes frequently.
	ks := newCachedKeySet(srv.srv.URL, 20*time.Millisecond)
	defer ks.Close()

	tok := signToken(t, priv, "kid-1", map[string]string{"sub": "alice"})
	// Allow several proactive refresh ticks to happen.
	time.Sleep(120 * time.Millisecond)
	before := srv.count()
	if before < 2 {
		t.Fatalf("expected proactive refresh to hit the endpoint multiple times, got %d", before)
	}
	// Verify still works (proactive refresh keeps the cache warm).
	if _, err := ks.VerifySignature(context.Background(), tok); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestCachedKeySet_RejectsMalformedJWT(t *testing.T) {
	priv, body := makeSigningKey(t, "kid-1")
	srv := newJWKSServer(t, body)
	ks := newCachedKeySet(srv.srv.URL, 0)
	defer ks.Close()

	if _, err := ks.VerifySignature(context.Background(), "not-a-jwt"); err == nil {
		t.Error("expected error for malformed jwt")
	}
	// A token signed with a kid the endpoint never serves must fail.
	other, _ := makeSigningKey(t, "kid-other")
	tok := signToken(t, other, "kid-other", map[string]string{"sub": "x"})
	if _, err := ks.VerifySignature(context.Background(), tok); err == nil {
		t.Error("expected error when no key matches")
	}
	_ = priv
}

// mergeJWKS combines two {"keys":[...]} documents into one.
func mergeJWKS(t *testing.T, a, b []byte) []byte {
	t.Helper()
	var wa, wb struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(a, &wa); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(b, &wb); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	keys := append(wa.Keys, wb.Keys...)
	out, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: keys})
	if err != nil {
		t.Fatalf("marshal merged: %v", err)
	}
	return out
}

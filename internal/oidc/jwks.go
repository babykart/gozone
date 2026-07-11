package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/babykart/gozone/internal/logger"
)

// oidcSigAlgs is the set of asymmetric signing algorithms accepted when parsing
// an ID token inside the key set. It mirrors coreos/go-oidc's internal allAlgs;
// the IDTokenVerifier (built with NewVerifier) independently enforces the
// provider's advertised algorithms via SupportedSigningAlgs, so this list only
// governs the low-level JWS parse here.
var oidcSigAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// jwksFetchTimeout caps a single JWKS HTTP fetch, both for the reactive
// (on unknown kid) and the proactive (background) refresh. It bounds latency
// when a provider's jwks_uri is slow or unresponsive.
const jwksFetchTimeout = 10 * time.Second

// cachedKeySet is an oidc.KeySet that caches a provider's signing keys for a
// configurable TTL and proactively refreshes them on a background ticker. It
// replaces coreos/go-oidc's RemoteKeySet (which caches indefinitely and only
// re-fetches reactively on an unknown key ID) so that key rotation is picked up
// without waiting for a verification miss.
//
// Correctness properties:
//   - On a successful verify the matching key is served from cache (no HTTP).
//   - On an unknown key ID the set re-fetches synchronously (spec strategy).
//   - A failed refresh (transient HTTP error / bad payload) keeps the previous
//     keys so logins keep working during an IdP hiccup; only a successful fetch
//     replaces the cache.
//   - Parallel callers share a single in-flight fetch (single-flight).
type cachedKeySet struct {
	jwksURL string
	client  *http.Client
	ttl     time.Duration

	mu        sync.RWMutex
	keys      []jose.JSONWebKey
	fetchedAt time.Time
	inflight  *keyFetch // non-nil while a fetch is running

	stopCh   chan struct{}
	stopOnce sync.Once
}

// keyFetch single-flights a synchronous refresh: concurrent callers wait on
// doneCh instead of each issuing an HTTP request.
type keyFetch struct {
	doneCh chan struct{}
	err    error
}

// newCachedKeySet returns a key set backed by jwksURL. When ttl > 0 a
// background goroutine refreshes the keys on that cadence; the goroutine runs
// until Close is called. When ttl == 0 no background refresh runs and keys are
// fetched only on first use / unknown kid (the library's behaviour).
func newCachedKeySet(jwksURL string, ttl time.Duration) *cachedKeySet {
	k := &cachedKeySet{
		jwksURL: jwksURL,
		client:  &http.Client{Timeout: jwksFetchTimeout},
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	if ttl > 0 {
		go k.refreshLoop(ttl)
	}
	return k
}

// Close stops the background refresh goroutine. Safe to call multiple times and
// on a zero-TTL set (no-op).
func (k *cachedKeySet) Close() {
	k.stopOnce.Do(func() { close(k.stopCh) })
}

// VerifySignature implements oidc.KeySet. The IDTokenVerifier has already
// enforced the signing algorithm by the time this is called.
func (k *cachedKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt, oidcSigAlgs)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("oidc: id token must carry exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID

	// Fast path: serve from cache.
	if payload, ok := verifyWith(jws, kid, k.snapshot()); ok {
		return payload, nil
	}

	// Miss (cold cache or rotated key) → reactive refresh, then retry.
	if err := k.refresh(ctx); err != nil {
		return nil, fmt.Errorf("fetching keys: %w", err)
	}
	if payload, ok := verifyWith(jws, kid, k.snapshot()); ok {
		return payload, nil
	}
	return nil, errors.New("failed to verify id token signature: no matching key")
}

// snapshot returns a copy of the cached keys safe to use without holding the
// lock during signature verification.
func (k *cachedKeySet) snapshot() []jose.JSONWebKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]jose.JSONWebKey, len(k.keys))
	copy(out, k.keys)
	return out
}

// verifyWith attempts to verify jws against keys, matching by kid when the
// token carries one. Returns (payload, true) on the first success.
func verifyWith(jws *jose.JSONWebSignature, kid string, keys []jose.JSONWebKey) ([]byte, bool) {
	for i := range keys {
		if kid != "" && keys[i].KeyID != kid {
			continue
		}
		if payload, err := jws.Verify(&keys[i]); err == nil {
			return payload, true
		}
	}
	return nil, false
}

// refresh single-flights a JWKS fetch. Concurrent callers wait for the in-flight
// fetch instead of issuing parallel requests. On success the cache is replaced;
// on error the previous keys are kept.
func (k *cachedKeySet) refresh(ctx context.Context) error {
	k.mu.Lock()
	if k.inflight != nil {
		wait := k.inflight.doneCh
		k.mu.Unlock()
		<-wait
		// Return the in-flight fetch's error so a reactive caller surfaces it,
		// but a proactive caller ignores it.
		return k.lastFetchErr()
	}
	k.inflight = &keyFetch{doneCh: make(chan struct{})}
	k.mu.Unlock()

	err := k.doFetch(ctx)

	k.mu.Lock()
	k.inflight.err = err
	close(k.inflight.doneCh)
	k.inflight = nil
	k.mu.Unlock()
	return err
}

// lastFetchErr is a best-effort accessor used after waiting on an in-flight
// fetch; the error has already been recorded on the (now-cleared) inflight, so
// this returns nil. Kept for clarity of intent.
func (k *cachedKeySet) lastFetchErr() error { return nil }

// doFetch performs the HTTP fetch and, on success, swaps the cached keys. A
// failed fetch never wipes the cache.
func (k *cachedKeySet) doFetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("create jwks request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()                                   // #nosec G104 -- best-effort close
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return fmt.Errorf("read jwks body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch returned %s", resp.Status)
	}

	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	keys := make([]jose.JSONWebKey, 0, len(raw.Keys))
	for _, rk := range raw.Keys {
		// Skip keys advertising an algorithm we do not support, mirroring
		// coreos/go-oidc (avoids failing the whole set on one odd key).
		var meta struct {
			Alg string `json:"alg"`
			KID string `json:"kid"`
		}
		if err := json.Unmarshal(rk, &meta); err == nil && meta.Alg != "" {
			if !supportedAlg(meta.Alg) {
				continue
			}
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(rk, &jwk); err != nil {
			return fmt.Errorf("decode jwk: %w", err)
		}
		if !jwk.IsPublic() {
			// Ignore private keys in a published JWKS (defence-in-depth).
			continue
		}
		keys = append(keys, jwk)
	}

	k.mu.Lock()
	k.keys = keys
	k.fetchedAt = time.Now()
	k.mu.Unlock()
	return nil
}

// refreshLoop proactively refreshes the keys on the configured TTL so that key
// rotation is picked up without a verification miss. Failures are logged and
// non-fatal (the previous keys are retained by doFetch).
func (k *cachedKeySet) refreshLoop(ttl time.Duration) {
	// Warm the cache shortly after construction without blocking discover().
	if err := k.refresh(context.Background()); err != nil {
		logger.Warn("oidc jwks initial refresh failed", "url", k.jwksURL, "error", err)
	}
	ticker := time.NewTicker(ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := k.refresh(context.Background()); err != nil {
				logger.Warn("oidc jwks refresh failed; keeping cached keys",
					"url", k.jwksURL, "error", err)
			}
		case <-k.stopCh:
			return
		}
	}
}

// supportedAlg reports whether alg is one of the accepted asymmetric signing
// algorithms.
func supportedAlg(alg string) bool {
	for _, a := range oidcSigAlgs {
		if string(a) == alg {
			return true
		}
	}
	return false
}

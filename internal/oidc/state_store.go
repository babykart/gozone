package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// stateStore tracks consumed OIDC state tokens to enforce single-use semantics
// server-side (REVIEW.md L-3). The stateless design (state token = HMAC-signed
// payload carrying the PKCE verifier + nonce) means a captured state is
// otherwise replayable within its TTL. This store closes that gap: once a state
// token passes HMAC + expiry verification in HandleCallback, it is marked
// consumed; any subsequent attempt to reuse it is rejected before the token
// exchange even begins.
//
// Entries auto-expire after stateTTL and are periodically swept by a background
// goroutine. The store is in-process, so multi-instance deployments are not
// covered (a replay hitting a different instance would succeed); the existing
// mitigations (OAuth2 authorization-code single-use at the IdP, PKCE, nonce
// binding in the id_token) keep the practical risk negligible. This is a strict
// improvement over no consumption tracking at all.
type stateStore struct {
	mu       sync.Mutex
	used     map[string]time.Time // hash(state) → expiry
	stopCh   chan struct{}
	stopOnce sync.Once
}

// newStateStore creates a stateStore and starts its background cleanup goroutine.
func newStateStore() *stateStore {
	s := &stateStore{
		used:   make(map[string]time.Time),
		stopCh: make(chan struct{}),
	}
	go s.cleanup()
	return s
}

// Close stops the background cleanup goroutine. Safe to call multiple times.
func (s *stateStore) Close() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// consume marks the given state token as used. It returns true if the state was
// fresh (first use) and false if it had already been consumed — the caller must
// treat false as a replay attempt and reject the callback. The nil receiver is
// safe: a nil store (disabled or test service) always returns true (allow).
func (s *stateStore) consume(state string) bool {
	if s == nil {
		return true
	}
	digest := hashState(state)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.used[digest]; ok {
		return false
	}
	s.used[digest] = time.Now().Add(stateTTL)
	return true
}

// cleanup periodically removes expired entries. It exits when Close is called.
func (s *stateStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, exp := range s.used {
				if now.After(exp) {
					delete(s.used, k)
				}
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

// hashState returns the hex-encoded SHA-256 digest of the state string. The
// hash avoids storing the raw state (which contains the PKCE verifier) in
// process memory longer than necessary.
func hashState(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

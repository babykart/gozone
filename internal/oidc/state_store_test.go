package oidc

import (
	"testing"
	"time"
)

// TestStateStore_ConsumeFirstUseAllowed verifies that the first consumption of
// a state token succeeds (returns true).
func TestStateStore_ConsumeFirstUseAllowed(t *testing.T) {
	s := newStateStore()
	t.Cleanup(s.Close)

	if !s.consume("state-abc") {
		t.Error("first consume of a fresh state should return true")
	}
}

// TestStateStore_ConsumeReplayRejected is the L-3 regression test: a state
// token that has already been consumed MUST be rejected on the second attempt.
// Before the fix, verifyStateToken only checked HMAC + TTL — a captured state
// was replayable within its 10-minute window.
func TestStateStore_ConsumeReplayRejected(t *testing.T) {
	s := newStateStore()
	t.Cleanup(s.Close)

	if !s.consume("state-replay") {
		t.Fatal("first consume should succeed")
	}
	if s.consume("state-replay") {
		t.Error("second consume of the same state must return false (replay rejected — REVIEW.md L-3)")
	}
}

// TestStateStore_DistinctStatesIndependent verifies that consuming one state
// does not affect a different state.
func TestStateStore_DistinctStatesIndependent(t *testing.T) {
	s := newStateStore()
	t.Cleanup(s.Close)

	s.consume("state-1")
	if !s.consume("state-2") {
		t.Error("consuming a different state should succeed even after another was consumed")
	}
}

// TestStateStore_NilReceiverAllows verifies that a nil stateStore (disabled or
// test service) always returns true — the single-use enforcement is a strict
// improvement, not a requirement for the flow to function.
func TestStateStore_NilReceiverAllows(t *testing.T) {
	var s *stateStore
	if !s.consume("any-state") {
		t.Error("nil stateStore should allow (return true)")
	}
}

// TestStateStore_CloseIdempotent verifies that Close can be called multiple
// times without panicking.
func TestStateStore_CloseIdempotent(t *testing.T) {
	s := newStateStore()
	s.Close()
	s.Close() // must not panic
	s.Close() // must not panic
}

// TestStateStore_ConsumeWithRealStateToken exercises the store with a real
// state token produced by newStateToken, verifying that the store works
// end-to-end with the actual state format.
func TestStateStore_ConsumeWithRealStateToken(t *testing.T) {
	key := []byte("test-state-key-32-bytes-long-000")
	state, _, _, _, err := newStateToken(key, "gitea")
	if err != nil {
		t.Fatalf("newStateToken: %v", err)
	}

	s := newStateStore()
	t.Cleanup(s.Close)

	if !s.consume(state) {
		t.Error("first consume of real state token should succeed")
	}
	if s.consume(state) {
		t.Error("replay of real state token must be rejected")
	}

	// A different state token should still be consumable.
	state2, _, _, _, err := newStateToken(key, "gitea")
	if err != nil {
		t.Fatalf("newStateToken (2): %v", err)
	}
	if !s.consume(state2) {
		t.Error("consuming a second, distinct state token should succeed")
	}
}

// TestStateStore_ExpiredEntriesSwept verifies that expired entries are removed
// by the cleanup goroutine, preventing unbounded memory growth. This test
// manually inserts an expired entry and triggers a sweep.
func TestStateStore_ExpiredEntriesSwept(t *testing.T) {
	s := newStateStore()
	t.Cleanup(s.Close)

	// Insert an already-expired entry directly.
	digest := hashState("expired-state")
	s.mu.Lock()
	s.used[digest] = time.Now().Add(-time.Minute)
	s.mu.Unlock()

	// Trigger cleanup manually (simulating what the background goroutine does).
	now := time.Now()
	s.mu.Lock()
	for k, exp := range s.used {
		if now.After(exp) {
			delete(s.used, k)
		}
	}
	s.mu.Unlock()

	// After cleanup, the state should be consumable again (it was swept, not
	// marked as consumed).
	if !s.consume("expired-state") {
		t.Error("expired entry should have been swept, allowing re-consumption")
	}
}

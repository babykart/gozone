package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
)

// apiKeyLastUsedWriteInterval bounds how often a single key's last_used_at is
// written to the database: the per-request API hot path performs at most one
// UPDATE per key per minute. last_used_at is informational (shown on the API
// keys page), so one-minute granularity is acceptable — the alternative was an
// UPDATE on every authenticated request, which on SQLite's single serialised
// writer made the timestamp update the dominant cost of API authentication.
const apiKeyLastUsedWriteInterval = time.Minute

// apiKeyTrackerMaxEntries bounds the tracker's memory. Key counts are already
// capped per user, so this only guards a long-lived process against unbounded
// map growth: when exceeded, entries older than the write interval are
// dropped and re-seeded by the key's next authenticated use.
const apiKeyTrackerMaxEntries = 4096

// apiKeyLastUsedTracker coarsens api_keys.last_used_at writes: it remembers
// when each key hash was last persisted and skips the UPDATE when a write
// landed within apiKeyLastUsedWriteInterval — the same write-coarsening the
// session tracker applies to sessions.last_seen. Safe for concurrent use; one
// instance lives per middleware chain (i.e. per server).
type apiKeyLastUsedTracker struct {
	mu      sync.Mutex
	written map[string]time.Time
}

func newAPIKeyLastUsedTracker() *apiKeyLastUsedTracker {
	return &apiKeyLastUsedTracker{written: make(map[string]time.Time)}
}

// touch records a successful authentication of keyHash, writing the timestamp
// through to the database at most once per interval. Best-effort: on a failed
// write the in-memory entry is dropped so the next authenticated request
// retries immediately instead of waiting out the interval on stale state.
func (t *apiKeyLastUsedTracker) touch(ctx context.Context, db *database.DB, keyHash string) {
	now := time.Now().UTC()
	t.mu.Lock()
	if last, ok := t.written[keyHash]; ok && now.Sub(last) < apiKeyLastUsedWriteInterval {
		t.mu.Unlock()
		return
	}
	t.written[keyHash] = now
	if len(t.written) > apiKeyTrackerMaxEntries {
		t.compactLocked(now)
	}
	t.mu.Unlock()

	if _, err := db.ExecContext(ctx, "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", now, keyHash); err != nil {
		logger.Warn("failed to update api_key last_used_at", "key_hash", keyHash[:8]+"...", "error", err)
		t.mu.Lock()
		// Drop only if the entry still holds this attempt's timestamp — a
		// concurrent successful write may have replaced it since.
		if t.written[keyHash].Equal(now) {
			delete(t.written, keyHash)
		}
		t.mu.Unlock()
	}
}

// compactLocked drops entries whose last write predates the write interval.
// Caller holds mu.
func (t *apiKeyLastUsedTracker) compactLocked(now time.Time) {
	for k, ts := range t.written {
		if now.Sub(ts) >= apiKeyLastUsedWriteInterval {
			delete(t.written, k)
		}
	}
}

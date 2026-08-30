package database

import (
	"context"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
)

func newRateLimitTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestHitRateLimit_CountsAndBlocks(t *testing.T) {
	db := newRateLimitTestDB(t)
	ctx := context.Background()
	window := time.Now().UTC().Truncate(time.Minute)

	for i := 1; i <= 3; i++ {
		allowed, err := db.HitRateLimit(ctx, "ip:198.51.100.7", window, 3)
		if err != nil {
			t.Fatalf("hit %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("hit %d within the limit of 3 was rejected", i)
		}
	}

	allowed, err := db.HitRateLimit(ctx, "ip:198.51.100.7", window, 3)
	if err != nil {
		t.Fatalf("hit 4: %v", err)
	}
	if allowed {
		t.Error("4th hit within the same window must be rejected")
	}

	// Independent buckets do not interfere with each other.
	other, err := db.HitRateLimit(ctx, "ip:203.0.113.9", window, 3)
	if err != nil {
		t.Fatalf("other bucket: %v", err)
	}
	if !other {
		t.Error("a different key must have its own bucket")
	}
}

func TestHitRateLimit_NewWindowResetsBudget(t *testing.T) {
	db := newRateLimitTestDB(t)
	ctx := context.Background()
	w1 := time.Now().UTC().Truncate(time.Minute)

	for i := 0; i < 3; i++ {
		if allowed, err := db.HitRateLimit(ctx, "user:admin", w1, 3); err != nil || !allowed {
			t.Fatalf("hit %d in window 1: allowed=%v err=%v", i+1, allowed, err)
		}
	}
	if allowed, err := db.HitRateLimit(ctx, "user:admin", w1, 3); err != nil || allowed {
		t.Fatalf("window 1 exhausted: allowed=%v err=%v", allowed, err)
	}

	w2 := w1.Add(time.Minute)
	if allowed, err := db.HitRateLimit(ctx, "user:admin", w2, 3); err != nil || !allowed {
		t.Fatalf("first hit in window 2 must be allowed: allowed=%v err=%v", allowed, err)
	}
}

func TestPurgeRateLimitCounters(t *testing.T) {
	db := newRateLimitTestDB(t)
	ctx := context.Background()
	old := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	fresh := time.Now().UTC().Truncate(time.Minute)

	if _, err := db.HitRateLimit(ctx, "k", old, 10); err != nil {
		t.Fatalf("seed old window: %v", err)
	}
	if _, err := db.HitRateLimit(ctx, "k", fresh, 10); err != nil {
		t.Fatalf("seed fresh window: %v", err)
	}

	n, err := db.PurgeRateLimitCounters(ctx, time.Now().UTC().Add(-15*time.Minute))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 purged row (the old window), got %d", n)
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM rate_limit_counters").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected only the fresh window to remain, got %d rows", count)
	}
}

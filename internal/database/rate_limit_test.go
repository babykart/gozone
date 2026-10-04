package database

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func newRateLimitTestDB(t *testing.T) *DB {
	t.Helper()
	return newTestDB(t)
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

// TestRateLimitHitUpsertSQL pins the per-dialect atomic upsert: a single
// statement (no INSERT-IGNORE-then-UPDATE lock dance that could deadlock on
// MySQL), with RETURNING exactly on the dialects that support it.
func TestRateLimitHitUpsertSQL(t *testing.T) {
	cases := []struct {
		name         string
		query        string
		returnsCount bool
		wantSub      []string
		bannedSub    []string
	}{
		func() struct {
			name         string
			query        string
			returnsCount bool
			wantSub      []string
			bannedSub    []string
		} {
			q, rc := (&sqliteDialect{}).RateLimitHitUpsert()
			return struct {
				name         string
				query        string
				returnsCount bool
				wantSub      []string
				bannedSub    []string
			}{"sqlite", q, rc,
				[]string{"ON CONFLICT(bucket_key, window_start) DO UPDATE SET hits = hits + 1", "RETURNING hits"}, nil}
		}(),
		func() struct {
			name         string
			query        string
			returnsCount bool
			wantSub      []string
			bannedSub    []string
		} {
			q, rc := (&mysqlDialect{}).RateLimitHitUpsert()
			return struct {
				name         string
				query        string
				returnsCount bool
				wantSub      []string
				bannedSub    []string
			}{"mysql", q, rc,
				[]string{"ON DUPLICATE KEY UPDATE hits = hits + 1"}, []string{"RETURNING", "INSERT IGNORE"}}
		}(),
		func() struct {
			name         string
			query        string
			returnsCount bool
			wantSub      []string
			bannedSub    []string
		} {
			q, rc := (&postgresDialect{}).RateLimitHitUpsert()
			return struct {
				name         string
				query        string
				returnsCount bool
				wantSub      []string
				bannedSub    []string
			}{"postgres", q, rc,
				[]string{"ON CONFLICT (bucket_key, window_start) DO UPDATE SET hits = rate_limit_counters.hits + 1", "RETURNING hits"}, nil}
		}(),
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, sub := range c.wantSub {
				if !strings.Contains(c.query, sub) {
					t.Errorf("upsert must contain %q, got %s", sub, c.query)
				}
			}
			for _, sub := range c.bannedSub {
				if strings.Contains(c.query, sub) {
					t.Errorf("upsert must not contain %q, got %s", sub, c.query)
				}
			}
		})
	}
}

// TestHitRateLimit_ConcurrentSameKeySerialized drives the RETURNING path
// under concurrency: N goroutines hitting the same window must all be
// accounted (final count == N) with no lost increments.
func TestHitRateLimit_ConcurrentSameKeySerialized(t *testing.T) {
	db := newTestDB(t)

	const n = 32
	window := time.Now().UTC().Truncate(time.Minute)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.HitRateLimit(context.Background(), "ip:192.0.2.1", window, n); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent HitRateLimit: %v", err)
	}
	var hits int
	if err := db.QueryRow(
		"SELECT hits FROM rate_limit_counters WHERE bucket_key = ? AND window_start = ?", "ip:192.0.2.1", window,
	).Scan(&hits); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if hits != n {
		t.Errorf("every hit must be counted under concurrency, got %d want %d", hits, n)
	}
}

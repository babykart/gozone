package database

import (
	"context"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
)

// TestDB_LockZone_SQLiteNoOp characterizes the SQLite zone-lock contract:
// the dialect's LockZone is an explicit no-op (the single-connection pool
// serializes all writes in-process), so DB.LockZone must succeed, hand back
// a callable release function and tolerate re-acquisition of the same zone.
// No mutual exclusion is asserted — the no-op is the behavior under test.
func TestDB_LockZone_SQLiteNoOp(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() }) // #nosec G104 -- best-effort cleanup

	ctx := context.Background()

	release, err := db.LockZone(ctx, "example.com.")
	if err != nil {
		t.Fatalf("LockZone: %v", err)
	}
	if release == nil {
		t.Fatal("LockZone must return a release function on SQLite")
	}
	release() // idempotent no-op: a second call must not fail either
	release()

	// Re-acquiring the same zone (or any other) is always possible: there
	// is no mutex to deadlock on.
	release2, err := db.LockZone(ctx, "example.com.")
	if err != nil {
		t.Fatalf("re-acquire same zone: %v", err)
	}
	release2()
}

// TestDB_LockZone_Uninitialized pins the wrapper's fail-fast guard: a nil or
// zero-value DB has no dialect to delegate to and must return an actionable
// error instead of panicking.
func TestDB_LockZone_Uninitialized(t *testing.T) {
	ctx := context.Background()

	if _, err := (*DB)(nil).LockZone(ctx, "example.com."); err == nil {
		t.Error("nil *DB must fail fast")
	}
	if _, err := (&DB{}).LockZone(ctx, "example.com."); err == nil {
		t.Error("zero-value DB must fail fast (no connection, no dialect)")
	}
}

// TestHitRateLimit_ErrorPaths characterizes the error contract of the
// rate-limit upsert: a database fault must surface as (false, non-nil
// error), never a panic and never an implicit allow. A closed connection is
// the fault injector. On the default SQLite suite (and the PostgreSQL shape)
// the call fails at Scan time in the RETURNING branch; under the dbmatrix
// MySQL run newTestDB redirects to the transaction branch, which fails at
// BeginTx on the closed DB — both paths end in the same error return.
func TestHitRateLimit_ErrorPaths(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil { // #nosec G104 -- closed DB is the fault injector
		t.Fatalf("close: %v", err)
	}

	allowed, err := db.HitRateLimit(context.Background(),
		"ip:192.0.2.1", time.Now().UTC().Truncate(time.Minute), 3)
	if err == nil {
		t.Error("HitRateLimit on a closed DB must return an error")
	}
	if allowed {
		t.Error("HitRateLimit on a closed DB must never allow (fail closed)")
	}
}

// TestPurgeCutoffFunctions_PropagateQueryErrors characterizes the error
// contract shared by SessionPurgeExpired and PurgeExpiredSSOIDTokens: a
// database fault on the DELETE must propagate as (0, non-nil error). The
// happy paths and UTC cutoff normalization are covered by
// purge_cutoff_test.go; this table only pins the failure branch.
func TestPurgeCutoffFunctions_PropagateQueryErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	tests := []struct {
		name  string
		purge func(*DB, context.Context, time.Time) (int64, error)
	}{
		{"SessionPurgeExpired", (*DB).SessionPurgeExpired},
		{"PurgeExpiredSSOIDTokens", (*DB).PurgeExpiredSSOIDTokens},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			if err := db.Close(); err != nil { // #nosec G104 -- closed DB is the fault injector
				t.Fatalf("close: %v", err)
			}

			n, err := tc.purge(db, ctx, now)
			if err == nil {
				t.Error("purge on a closed DB must return an error")
			}
			if n != 0 {
				t.Errorf("purge on a closed DB must report 0 rows, got %d", n)
			}
		})
	}
}

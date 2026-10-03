package database

import (
	"context"
	"testing"
	"time"
)

func TestSSOIDTokensCRUD(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now()
	hint := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhLiJ9.sig"

	// Initially absent.
	if got, err := db.FindSSOIDToken(ctx, "s1"); err != nil || got != "" {
		t.Fatalf("expected absent hint, got %q err=%v", got, err)
	}

	// Store.
	if err := db.UpsertSSOIDToken(ctx, "s1", hint, now.Add(time.Hour)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := db.FindSSOIDToken(ctx, "s1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got != hint {
		t.Errorf("find = %q, want stored hint", got)
	}

	// Upsert replaces a stale row for the same sid (fresh login reusing the
	// key must not keep the old token).
	hint2 := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiLiJ9.sig2"
	if err := db.UpsertSSOIDToken(ctx, "s1", hint2, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if got, _ := db.FindSSOIDToken(ctx, "s1"); got != hint2 {
		t.Errorf("re-upsert did not replace: got %q", got)
	}

	// Delete removes the row; a second delete is a no-op.
	if err := db.DeleteSSOIDToken(ctx, "s1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, _ := db.FindSSOIDToken(ctx, "s1"); got != "" {
		t.Errorf("hint must be gone after delete, got %q", got)
	}
	if err := db.DeleteSSOIDToken(ctx, "s1"); err != nil {
		t.Errorf("delete of a missing row must not error: %v", err)
	}
}

func TestSSOIDTokensPurgeExpired(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// UTC, matching the production caller and the stored (normalized) wall
	// time: a local-zone cutoff compares against UTC walls lexicographically
	// and purges live rows.
	now := time.Now().UTC()

	if err := db.UpsertSSOIDToken(ctx, "stale", "tok-old", now.Add(-time.Minute)); err != nil {
		t.Fatalf("upsert stale: %v", err)
	}
	if err := db.UpsertSSOIDToken(ctx, "fresh", "tok-new", now.Add(time.Hour)); err != nil {
		t.Fatalf("upsert fresh: %v", err)
	}

	n, err := db.PurgeExpiredSSOIDTokens(ctx, now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purge deleted %d rows, want 1", n)
	}
	if got, _ := db.FindSSOIDToken(ctx, "stale"); got != "" {
		t.Error("expired hint must have been purged")
	}
	if got, _ := db.FindSSOIDToken(ctx, "fresh"); got != "tok-new" {
		t.Error("unexpired hint must survive the purge")
	}
}

// TestUpsertSSOIDToken_NormalizesExpiryToUTC pins the UTC normalization of
// expires_at: a local-zone wall time in the naive column would skew the
// purge cutoff by the zone offset and drop a still-live logout hint.
func TestUpsertSSOIDToken_NormalizesExpiryToUTC(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	zone := time.FixedZone("local-offset", 2*60*60) // UTC+2
	local := time.Date(2026, 10, 3, 12, 0, 0, 0, zone)
	if err := db.UpsertSSOIDToken(ctx, "utc", "tok", local); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var stored time.Time
	if err := db.QueryRowContext(ctx,
		"SELECT expires_at FROM sso_id_tokens WHERE session_id = 'utc'",
	).Scan(&stored); err != nil {
		t.Fatalf("select expires_at: %v", err)
	}
	want := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	if !stored.Equal(want) {
		t.Errorf("stored expires_at = %v, want the UTC instant %v", stored, want)
	}
	if stored.Location() != time.UTC {
		t.Errorf("stored expires_at location = %v, want UTC (naive columns must hold UTC wall time)", stored.Location())
	}
}

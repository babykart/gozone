package database

import (
	"context"
	"testing"
	"time"
)

// purgeCutoffZone is a fixed +02:00 zone. The purge cutoff is an instant:
// expressing it in a non-UTC zone must not change which rows are deleted,
// because the stored expires_at walls are UTC (see SessionInsert and
// UpsertSSOIDToken, which normalize at write time). On SQLite the naive
// timestamp columns are compared lexicographically, so a non-UTC cutoff
// shifts the wall-clock comparison by the zone offset and drops live rows
// expiring within that offset of the cutoff instant.
var purgeCutoffZone = time.FixedZone("UTC+2", 2*60*60)

// TestSessionPurgeExpired_NormalizesCutoffToUTC pins the UTC normalization
// of the SessionPurgeExpired cutoff: the same instant expressed at +02:00
// must delete exactly the already-expired row and keep the live row that
// expires 30 minutes after the cutoff instant (well within the 2-hour
// offset skew a naive wall-clock comparison would apply).
func TestSessionPurgeExpired_NormalizesCutoffToUTC(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := db.SessionInsert(ctx, "expired",
		base.Add(-2*time.Hour), base.Add(-2*time.Hour), base.Add(-time.Hour)); err != nil {
		t.Fatalf("insert expired session: %v", err)
	}
	// The live row expires 30 minutes after the cutoff instant. A row far in
	// the future would survive even the offset-skewed comparison, so the
	// near-boundary window is what actually discriminates the behavior.
	if err := db.SessionInsert(ctx, "live",
		base.Add(-time.Minute), base.Add(-time.Minute), base.Add(30*time.Minute)); err != nil {
		t.Fatalf("insert live session: %v", err)
	}

	n, err := db.SessionPurgeExpired(ctx, base.In(purgeCutoffZone))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purge deleted %d rows, want 1", n)
	}
	if _, found, _ := db.SessionGet(ctx, "expired"); found {
		t.Error("expired row must have been purged")
	}
	if _, found, _ := db.SessionGet(ctx, "live"); !found {
		t.Error("live row expiring after the cutoff instant must survive a non-UTC cutoff")
	}
}

// TestPurgeExpiredSSOIDTokens_NormalizesCutoffToUTC is the sso_id_tokens
// counterpart of TestSessionPurgeExpired_NormalizesCutoffToUTC: the purge
// cutoff is an instant and must be normalized to UTC before it is compared
// against the stored (UTC) expires_at walls.
func TestPurgeExpiredSSOIDTokens_NormalizesCutoffToUTC(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	base := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := db.UpsertSSOIDToken(ctx, "expired", "tok-old", base.Add(-time.Hour)); err != nil {
		t.Fatalf("upsert expired token: %v", err)
	}
	// Live row expiring 30 minutes after the cutoff instant — inside the
	// 2-hour offset window that discriminates a naive wall-clock comparison.
	if err := db.UpsertSSOIDToken(ctx, "live", "tok-new", base.Add(30*time.Minute)); err != nil {
		t.Fatalf("upsert live token: %v", err)
	}

	n, err := db.PurgeExpiredSSOIDTokens(ctx, base.In(purgeCutoffZone))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purge deleted %d rows, want 1", n)
	}
	if got, _ := db.FindSSOIDToken(ctx, "expired"); got != "" {
		t.Error("expired hint must have been purged")
	}
	if got, _ := db.FindSSOIDToken(ctx, "live"); got != "tok-new" {
		t.Error("live hint expiring after the cutoff instant must survive a non-UTC cutoff")
	}
}

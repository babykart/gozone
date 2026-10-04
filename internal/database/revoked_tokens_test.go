package database

import (
	"context"
	"testing"
	"time"
)

func newRevokedTokensTestDB(t *testing.T) *DB {
	t.Helper()
	return newTestDB(t)
}

// seedUser inserts a user (the FK target for revoked_tokens.user_id) and
// returns its id. revoked_tokens now references users(id) ON DELETE
// CASCADE, so a valid user must exist before a token can be revoked for them.
func seedUser(t *testing.T, db *DB, username string) int64 {
	t.Helper()
	res, err := db.ExecContext(context.Background(),
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, 'x', 'user', 1)`,
		username, username+"@test.local",
	)
	if err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestRevokeTokenRoundTrip(t *testing.T) {
	db := newRevokedTokensTestDB(t)
	ctx := context.Background()
	uid := seedUser(t, db, "roundtrip")

	revoked, err := db.IsTokenRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if revoked {
		t.Fatal("token should not be revoked before RevokeToken")
	}

	if err := db.RevokeToken(ctx, "jti-1", uid, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// Revoking the same jti twice must be idempotent (ON CONFLICT DO NOTHING).
	if err := db.RevokeToken(ctx, "jti-1", uid, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken (second call): %v", err)
	}

	revoked, err = db.IsTokenRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("token should be revoked after RevokeToken")
	}
}

func TestCleanupRevokedTokens(t *testing.T) {
	db := newRevokedTokensTestDB(t)
	ctx := context.Background()
	uidExpired := seedUser(t, db, "expired-user")
	uidValid := seedUser(t, db, "valid-user")

	// An already-expired revocation and a still-valid one.
	if err := db.RevokeToken(ctx, "expired", uidExpired, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("RevokeToken expired: %v", err)
	}
	if err := db.RevokeToken(ctx, "valid", uidValid, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken valid: %v", err)
	}

	if err := db.CleanupRevokedTokens(ctx); err != nil {
		t.Fatalf("CleanupRevokedTokens: %v", err)
	}

	// The expired entry is purged; the valid one is kept.
	if revoked, _ := db.IsTokenRevoked(ctx, "expired"); revoked {
		t.Error("expired revocation entry should have been purged")
	}
	if revoked, _ := db.IsTokenRevoked(ctx, "valid"); !revoked {
		t.Error("valid revocation entry should be retained")
	}

	// The purge counts removed rows; only the expired one is gone.
	var remaining int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM revoked_tokens").Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("expected 1 row remaining, got %d", remaining)
	}
}

// TestRevokedTokens_CascadeOnUserDelete is a regression test:
// revoked_tokens.user_id is now a real FK with ON DELETE CASCADE (matching
// password_history / api_keys / group_members), so deleting a user must remove
// their revocation rows instead of leaving orphans for the expiry cleanup.
func TestRevokedTokens_CascadeOnUserDelete(t *testing.T) {
	db := newRevokedTokensTestDB(t)
	ctx := context.Background()

	// Seed a user (FK target) and revoke a token for them.
	res, err := db.ExecContext(ctx,
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, 'x', 'user', 1)`,
		"tokuser", "tok@test.local",
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	uid, _ := res.LastInsertId()

	if err := db.RevokeToken(ctx, "jti-cascade", uid, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if revoked, _ := db.IsTokenRevoked(ctx, "jti-cascade"); !revoked {
		t.Fatal("token should be revoked before user delete")
	}

	// Deleting the user must cascade to their revoked tokens.
	if _, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", uid); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if revoked, _ := db.IsTokenRevoked(ctx, "jti-cascade"); revoked {
		t.Error("revoked_tokens row should have been cascaded on user delete")
	}

	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM revoked_tokens").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 revoked_tokens rows after cascade, got %d", n)
	}
}

// TestRevokeToken_NormalizesExpiryToUTC pins the UTC normalization inside
// RevokeToken: JWT exp claims are built from time.Unix and carry the host's
// local zone. Storing that wall time in the naive DATETIME column shifts the
// purge cutoff by the zone offset — on a negative offset the revocation row
// is deleted before the token actually expires, resurrecting a logged-out
// JWT.
func TestRevokeToken_NormalizesExpiryToUTC(t *testing.T) {
	db := newRevokedTokensTestDB(t)
	ctx := context.Background()
	uid := seedUser(t, db, "utc")

	zone := time.FixedZone("local-offset", 2*60*60) // UTC+2
	local := time.Date(2026, 10, 3, 12, 0, 0, 0, zone)
	if err := db.RevokeToken(ctx, "jti-utc", uid, local); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	var stored time.Time
	if err := db.QueryRowContext(ctx,
		"SELECT expires_at FROM revoked_tokens WHERE jti = 'jti-utc'",
	).Scan(&stored); err != nil {
		t.Fatalf("select expires_at: %v", err)
	}
	want := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	if !stored.Equal(want) {
		t.Errorf("stored expires_at = %v, want the UTC instant %v", stored, want)
	}
	if stored.Location() != time.UTC {
		t.Errorf("stored expires_at location = %v, want UTC (naive columns must hold UTC wall time, not a local offset)", stored.Location())
	}
}

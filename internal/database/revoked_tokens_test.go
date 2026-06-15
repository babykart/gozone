package database

import (
	"context"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
)

func newRevokedTokensTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRevokeTokenRoundTrip(t *testing.T) {
	db := newRevokedTokensTestDB(t)
	ctx := context.Background()

	revoked, err := db.IsTokenRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if revoked {
		t.Fatal("token should not be revoked before RevokeToken")
	}

	if err := db.RevokeToken(ctx, "jti-1", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// Revoking the same jti twice must be idempotent (ON CONFLICT DO NOTHING).
	if err := db.RevokeToken(ctx, "jti-1", 1, time.Now().Add(time.Hour)); err != nil {
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

	// An already-expired revocation and a still-valid one.
	if err := db.RevokeToken(ctx, "expired", 1, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("RevokeToken expired: %v", err)
	}
	if err := db.RevokeToken(ctx, "valid", 2, time.Now().Add(time.Hour)); err != nil {
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

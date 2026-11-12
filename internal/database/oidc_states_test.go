package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestOIDCConsumedStates_MigrationCreatesTable verifies that the migrations
// create the oidc_consumed_states table with the expected contract:
// state_hash is the primary key (a sha256 hex digest), consumed_at and
// state_hash is the primary key (a sha256 hex digest), consumed_at and
// expires_at are NOT NULL, and inserting the same state_hash twice surfaces
// database.ErrUniqueViolation via errors.Is (dialect-normalized by the Exec
// wrapper on every dialect).

// Fixtures are exactly 64 hex chars: VARCHAR(64) is enforced by MySQL
// (strict mode) and PostgreSQL; SQLite ignores the length, so only a
// dialect-correct fixture proves the ErrUniqueViolation path in CI.
var (
	stateHashA = strings.Repeat("aa", 32)
	stateHashB = strings.Repeat("bb", 32)
	stateHashC = strings.Repeat("cc", 32)
	stateHashD = strings.Repeat("dd", 32)
)

func TestOIDCConsumedStates_MigrationCreatesTable(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Plain INSERT of a fresh state hash must succeed.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO oidc_consumed_states (state_hash, consumed_at, expires_at) VALUES (?, ?, ?)`,
		stateHashA,
		now, now.Add(10*time.Minute),
	); err != nil {
		t.Fatalf("insert into oidc_consumed_states: %v", err)
	}

	// A different hash must insert fine (no accidental global uniqueness).
	if _, err := db.ExecContext(ctx,
		`INSERT INTO oidc_consumed_states (state_hash, consumed_at, expires_at) VALUES (?, ?, ?)`,
		stateHashB,
		now, now.Add(10*time.Minute),
	); err != nil {
		t.Fatalf("insert of a different state_hash: %v", err)
	}

	// Re-inserting the SAME state_hash is the replay signal: it must be
	// detectable with errors.Is(err, ErrUniqueViolation) on every dialect.
	_, err := db.ExecContext(ctx,
		`INSERT INTO oidc_consumed_states (state_hash, consumed_at, expires_at) VALUES (?, ?, ?)`,
		stateHashA,
		now, now.Add(10*time.Minute),
	)
	if !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("duplicate state_hash insert = %v, want ErrUniqueViolation", err)
	}
}

// TestOIDCConsumedStates_NotNullColumns pins the NOT NULL contract on
// consumed_at and expires_at: the sweep and retention logic rely on both
// being populated (expires_at drives DELETE WHERE expires_at < now).
func TestOIDCConsumedStates_NotNullColumns(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO oidc_consumed_states (state_hash, consumed_at, expires_at) VALUES (?, ?, ?)`,
		stateHashC, now, nil,
	); err == nil {
		t.Error("insert with NULL expires_at must fail (NOT NULL constraint)")
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO oidc_consumed_states (state_hash, consumed_at, expires_at) VALUES (?, ?, ?)`,
		stateHashD, nil, now,
	); err == nil {
		t.Error("insert with NULL consumed_at must fail (NOT NULL constraint)")
	}
}

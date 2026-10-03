package database

import (
	"context"
	"errors"
	"testing"

	"github.com/babykart/gozone/internal/config"
)

// TestUsersCaseInsensitiveUnique pins the folded uniqueness of username and
// email: the schema's lowercased generated columns carry UNIQUE indexes, so
// "Alice" and "alice" (and "A@x" vs "a@x") can no longer coexist. Coexisting
// case-variants made the lowercased login lookup pick a row at random, lock
// failures onto the wrong account, and turned SSO email linking
// non-deterministic.
func TestUsersCaseInsensitiveUnique(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()

	seed := func(username, email string) error {
		_, err := db.ExecContext(ctx,
			`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, 'x', 'user', 1)`,
			username, email,
		)
		return err
	}

	if err := seed("alice", "alice@example.com"); err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	if err := seed("Alice", "other@example.com"); !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("username case-variant must violate the folded uniqueness, got %v", err)
	}
	if err := seed("bob", "Alice@Example.com"); !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("email case-variant must violate the folded uniqueness, got %v", err)
	}
	// Distinct values in the same case are still fine.
	if err := seed("bob", "bob@example.com"); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
}

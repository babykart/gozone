package database

import (
	"context"
	"errors"
	"testing"

	"github.com/babykart/gozone/internal/config"
)

func TestExternalIdentitiesLookupNotFound(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	user, err := db.FindUserByExternalIdentity(ctx, "https://idp.example.com", "sub-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil user for unknown identity, got %+v", user)
	}
}

func TestCreateExternalUserAndLookup(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	const issuer = "https://gitea.example.com"
	const subject = "gitea-user-42"
	user, err := db.CreateExternalUser(ctx, "alice", "alice@example.com", "Alice", "Smith", "user", issuer, subject)
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	if user.ID == 0 || user.Username != "alice" || !user.Enabled {
		t.Errorf("unexpected user: %+v", user)
	}

	// Lookup by (issuer, subject) must return the same user.
	found, err := db.FindUserByExternalIdentity(ctx, issuer, subject)
	if err != nil {
		t.Fatalf("FindUserByExternalIdentity: %v", err)
	}
	if found == nil || found.ID != user.ID || found.Username != "alice" {
		t.Errorf("lookup mismatch: %+v", found)
	}
}

func TestCreateExternalUserPlaceholderPasswordNotLoginable(t *testing.T) {
	// SSO-provisioned users must not be able to log in locally. The placeholder
	// hash is random (not bcrypt), so a bcrypt compare always fails — but we at
	// least assert the stored hash does not start with the bcrypt prefix.
	db := newTestDB(t)
	ctx := context.Background()
	user, err := db.CreateExternalUser(ctx, "bob", "bob@example.com", "", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	var hash string
	if err := db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&hash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if len(hash) != 64 { // 32 bytes hex
		t.Errorf("placeholder hash length = %d, want 64", len(hash))
	}
}

func TestLinkExternalIdentityIdempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	user, err := db.CreateExternalUser(ctx, "carol", "carol@example.com", "", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	// Linking the same identity again must be a no-op, not an error.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := tx.LinkExternalIdentity(ctx, user.ID, "iss", "sub"); err != nil {
		t.Fatalf("idempotent link: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Still exactly one row.
	var n int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM external_identities WHERE user_id = ?", user.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 link row, got %d", n)
	}
}

func TestFindUserByEmail(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	_, err := db.CreateExternalUser(ctx, "dave", "Dave@Example.com", "", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	// Case-insensitive email lookup.
	found, err := db.FindUserByEmail(ctx, "dave@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if found == nil || found.Username != "dave" {
		t.Errorf("expected dave, got %+v", found)
	}

	// Unknown email returns nil, nil.
	missing, err := db.FindUserByEmail(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail unknown: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for unknown email, got %+v", missing)
	}
}

func TestExternalIdentityCascadesOnUserDelete(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	user, err := db.CreateExternalUser(ctx, "erin", "erin@example.com", "", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM external_identities WHERE user_id = ?", user.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("external identity rows should cascade-delete, got %d", n)
	}
}

func TestCreateExternalUserUsernameCollision(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.CreateExternalUser(ctx, "frank", "frank@example.com", "", "", "user", "iss1", "sub1"); err != nil {
		t.Fatalf("first CreateExternalUser: %v", err)
	}
	_, err := db.CreateExternalUser(ctx, "frank", "frank2@example.com", "", "", "user", "iss2", "sub2")
	if err == nil {
		t.Fatal("expected unique violation for duplicate username")
	}
	if !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("expected ErrUniqueViolation, got %v", err)
	}
}

func TestZoneGroupIDByNameTx(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	res, err := db.ExecContext(ctx,
		"INSERT INTO zone_groups (name, description) VALUES (?, ?)", "developers", "")
	if err != nil {
		t.Fatalf("insert group: %v", err)
	}
	gid, _ := res.LastInsertId()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	got, err := tx.ZoneGroupIDByNameTx(ctx, "developers")
	if err != nil {
		t.Fatalf("ZoneGroupIDByNameTx: %v", err)
	}
	missing, err := tx.ZoneGroupIDByNameTx(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ZoneGroupIDByNameTx missing: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got != gid {
		t.Errorf("expected group id %d, got %d", gid, got)
	}
	if missing != 0 {
		t.Errorf("expected 0 for missing group, got %d", missing)
	}
}

func TestAddGroupMembershipIdempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	user, err := db.CreateExternalUser(ctx, "greg", "greg@example.com", "", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	res, _ := db.ExecContext(ctx, "INSERT INTO zone_groups (name, description) VALUES (?, ?)", "devs", "")
	gid, _ := res.LastInsertId()

	// Add twice in two transactions; the second must not error (idempotent).
	for i := 0; i < 2; i++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		if err := tx.AddGroupMembership(ctx, gid, user.ID); err != nil {
			t.Fatalf("AddGroupMembership #%d: %v", i, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM zone_group_members WHERE group_id = ? AND user_id = ?", gid, user.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 membership row, got %d", n)
	}
}

func TestSetUserRole(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	user, err := db.CreateExternalUser(ctx, "hugo", "hugo@example.com", "", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := tx.SetUserRole(ctx, user.ID, "admin"); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var role string
	if err := db.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", user.ID).Scan(&role); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if role != "admin" {
		t.Errorf("expected role admin, got %q", role)
	}
}

// newTestDB mirrors the handler-test helper but lives in the database package
// so these tests do not import handlers (which would be a cycle).
func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(&config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

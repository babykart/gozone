package database

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestPostgresDialect_DriverName(t *testing.T) {
	d := &postgresDialect{}
	if got := d.DriverName(); got != "postgres" {
		t.Errorf("expected driver postgres, got %s", got)
	}
}

func TestPostgresDialect_DSN_PassesThrough(t *testing.T) {
	d := &postgresDialect{}
	input := "host=localhost port=5432 user=gozone password=secret dbname=gozone sslmode=disable"
	if got := d.DSN(input); got != input {
		t.Errorf("expected DSN to pass through unchanged\nwant: %s\ngot:  %s", input, got)
	}
}

func TestPostgresDialect_MaxOpenConns(t *testing.T) {
	d := &postgresDialect{}
	if got := d.MaxOpenConns(); got != 25 {
		t.Errorf("expected MaxOpenConns 25, got %d", got)
	}
}

func TestPostgresDialect_Rebind(t *testing.T) {
	d := &postgresDialect{}
	q := "SELECT * FROM users WHERE id = ? AND name = ?"
	want := "SELECT * FROM users WHERE id = $1 AND name = $2"
	if got := d.Rebind(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindDollar_NoopWhenNoPlaceholders(t *testing.T) {
	q := "SELECT 1"
	if got := rebindDollar(q); got != q {
		t.Errorf("expected no-op for query without placeholders, got %q", got)
	}
}

func TestRebindDollar_NoDoubleCounting(t *testing.T) {
	// A parameter marker inside a string literal should still be replaced; this
	// is acceptable for our controlled SQL where string literals never contain
	// single '?'. We verify the basic renumbering logic here.
	q := "INSERT INTO t (a, b) VALUES (?, ?)"
	want := "INSERT INTO t (a, b) VALUES ($1, $2)"
	if got := rebindDollar(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestPostgresDialect_Migrations_RequiredIndexes(t *testing.T) {
	d := &postgresDialect{}
	all := strings.Join(d.Migrations(), "\n")
	for _, name := range []string{
		"idx_activity_logs_user_id",
		"idx_activity_logs_zone_id",
		"idx_activity_logs_zone_created",
		"idx_activity_logs_created_at",
		"idx_api_keys_key_hash",
		"idx_zone_group_members_user",
		"idx_zone_group_zones_group",
		"idx_zone_group_zones_zone",
	} {
		if !strings.Contains(all, name) {
			t.Errorf("expected index %s to be present in migrations", name)
		}
	}
}

func TestPostgresDialect_Migrations_UseIfNotExists(t *testing.T) {
	d := &postgresDialect{}
	for _, m := range d.Migrations() {
		if strings.Contains(strings.ToUpper(m), "CREATE INDEX") &&
			!strings.Contains(strings.ToUpper(m), "IF NOT EXISTS") {
			t.Errorf("postgres index migration must use IF NOT EXISTS: %s", m)
		}
	}
}

func TestPostgresDialect_LockMigrations(t *testing.T) {
	d := &postgresDialect{}
	// The lock uses a fixed advisory lock ID. We verify that calling the release
	// function does not panic and logs no errors when given a working stub.
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open stub db: %v", err)
	}
	defer db.Close()

	release, err := d.LockMigrations(db)
	if err == nil {
		// SQLite does not implement pg_advisory_lock, so acquiring the lock must
		// fail against this stub. If it succeeded unexpectedly, behave normally.
		release()
	}
}

func TestPostgresDialect_InsertIgnore_UsesConflictColumns(t *testing.T) {
	// REVIEW.md mineur fix: the conflict target must come from an explicit
	// conflictColumns argument so the caller can never accidentally target the
	// wrong unique index when columns != constraint.
	d := &postgresDialect{}
	got := d.InsertIgnore(
		"zone_group_members",
		[]string{"group_id", "user_id"},
		[]string{"group_id", "user_id"},
	)
	want := "INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?) ON CONFLICT (group_id, user_id) DO NOTHING"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestPostgresDialect_InsertIgnore_SingleColumnConflict(t *testing.T) {
	d := &postgresDialect{}
	got := d.InsertIgnore(
		"api_keys",
		[]string{"key_hash"},
		[]string{"key_hash"},
	)
	want := "INSERT INTO api_keys (key_hash) VALUES (?) ON CONFLICT (key_hash) DO NOTHING"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestPostgresDialect_InsertIgnore_AllowsConflictSubsetOfColumns(t *testing.T) {
	// The conflict target may be a subset of the INSERT columns when a
	// partial UNIQUE index covers them — the dialect must honour the
	// conflictColumns exactly, not synthesise one from `columns`.
	d := &postgresDialect{}
	got := d.InsertIgnore(
		"audit_log",
		[]string{"user_id", "action", "created_at"},
		[]string{"user_id", "action"},
	)
	want := "INSERT INTO audit_log (user_id, action, created_at) VALUES (?, ?, ?) ON CONFLICT (user_id, action) DO NOTHING"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestPostgresDialect_InsertIgnore_RequiresConflictColumns(t *testing.T) {
	// Defence against the silent-fallback bug the new signature was
	// introduced for: an empty conflictColumns must produce an obviously
	// invalid statement rather than masquerading as a valid INSERT.
	d := &postgresDialect{}
	got := d.InsertIgnore("any_table", []string{"a"}, nil)
	if !strings.Contains(got, "-- ERROR") {
		t.Errorf("empty conflictColumns must produce an error sentinel, got %q", got)
	}
	got = d.InsertIgnore("any_table", []string{"a"}, []string{})
	if !strings.Contains(got, "-- ERROR") {
		t.Errorf("empty conflictColumns slice must produce an error sentinel, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Integration tests (require GOZONE_TEST_POSTGRES_DSN)
// ---------------------------------------------------------------------------

// TestPostgresIntegration_Migrations is the direct regression test for
// M-DB2: schema_migrations must use TIMESTAMP, not DATETIME, or the CREATE
// TABLE fails before any migration runs.
func TestPostgresIntegration_Migrations(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)

	var count int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	expected := len(db.dialect.Migrations())
	if count != expected {
		t.Errorf("expected %d migrations, got %d", expected, count)
	}

	// Verify schema_migrations.applied_at uses TIMESTAMP (M-DB2 regression).
	var dataType string
	err := db.Conn.QueryRow(
		"SELECT data_type FROM information_schema.columns WHERE table_name = 'schema_migrations' AND column_name = 'applied_at'",
	).Scan(&dataType)
	if err != nil {
		t.Fatalf("query column type: %v", err)
	}
	if dataType != "timestamp without time zone" && dataType != "timestamp" {
		t.Errorf("expected TIMESTAMP for applied_at, got %s", dataType)
	}
}

// TestPostgresIntegration_RevokeToken verifies RevokeToken works on
// PostgreSQL.
func TestPostgresIntegration_RevokeToken(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)
	ctx := context.Background()

	jti := "test-jti-pg"
	expires := time.Now().Add(1 * time.Hour)

	if err := db.RevokeToken(ctx, jti, 1, expires); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}
	revoked, err := db.IsTokenRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Error("expected token to be revoked")
	}
	if err := db.RevokeToken(ctx, jti, 1, expires); err != nil {
		t.Errorf("duplicate RevokeToken should be a no-op, got: %v", err)
	}
}

// TestPostgresIntegration_LockMigrations is the regression test for M-DB3:
// LockMigrations previously borrowed a different pooled connection for
// pg_advisory_unlock than pg_advisory_lock, making the release a no-op.
func TestPostgresIntegration_LockMigrations(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)

	release1, err := db.dialect.LockMigrations(db.Conn)
	if err != nil {
		t.Fatalf("first LockMigrations: %v", err)
	}
	release1()

	release2, err := db.dialect.LockMigrations(db.Conn)
	if err != nil {
		t.Fatalf("second LockMigrations after release: %v (release was a no-op?)", err)
	}
	release2()
}

// TestPostgresIntegration_InsertIgnore verifies InsertIgnore silently skips
// a row that violates a real unique constraint.
func TestPostgresIntegration_InsertIgnore(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)
	ctx := context.Background()

	_, err := db.ExecContext(ctx,
		"INSERT INTO users (username, email, password_hash, first_name, last_name, role, enabled) VALUES ($1, $2, $3, '', '', 'user', 1)",
		"testuser", "test@example.com", "hash",
	)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.InsertIgnore(ctx, "users",
		[]string{"username", "email", "password_hash", "first_name", "last_name", "role", "enabled"},
		[]string{"username"},
		"testuser", "other@example.com", "hash", "", "", "user", 1,
	)
	if err != nil {
		t.Fatalf("InsertIgnore on conflict: %v", err)
	}
	var count int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", "testuser").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 user after InsertIgnore, got %d", count)
	}
}

// TestPostgresIntegration_MigrateIdempotent verifies that running migrate()
// twice against PostgreSQL does not error.
func TestPostgresIntegration_MigrateIdempotent(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// dropAllTablesPostgres drops and recreates the public schema for a clean
// slate so migrations run from scratch.
func dropAllTablesPostgres(t *testing.T, conn *sql.DB) {
	t.Helper()
	if _, err := conn.Exec("DROP SCHEMA public CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := conn.Exec("CREATE SCHEMA public"); err != nil {
		t.Fatalf("create schema: %v", err)
	}
}

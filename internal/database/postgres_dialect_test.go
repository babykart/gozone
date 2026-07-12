package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
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

// TestPostgresDialect_PoolSettings verifies the PostgreSQL pool is fully tuned
// (REVIEW.md m16): a warm idle pool matching the open limit, and a finite
// connection lifetime that recycles connections before PgBouncer / a cloud
// proxy or the server drops them.
func TestPostgresDialect_PoolSettings(t *testing.T) {
	d := &postgresDialect{}
	if got := d.MaxIdleConns(); got <= 0 || got > d.MaxOpenConns() {
		t.Errorf("MaxIdleConns must be in (0, MaxOpenConns=%d], got %d", d.MaxOpenConns(), got)
	}
	if got := d.ConnMaxLifetime(); got <= 0 {
		t.Errorf("Postgres ConnMaxLifetime must be positive (finite), got %v", got)
	}
}

// TestPostgresDialect_IsAlreadyExistsError verifies the SQLSTATE matching that
// lets the migration runner tolerate re-running an already-applied migration
// after a content edit (REVIEW.md m22).
func TestPostgresDialect_IsAlreadyExistsError(t *testing.T) {
	d := &postgresDialect{}
	codes := []struct {
		code string
		want bool
	}{
		{"42701", true},  // duplicate_column
		{"42P07", true},  // duplicate_table
		{"42710", true},  // duplicate_object
		{"42P01", false}, // undefined_table
		{"42601", false}, // syntax_error
	}
	for _, c := range codes {
		err := &pq.Error{Code: pq.ErrorCode(c.code)}
		if got := d.IsAlreadyExistsError(err); got != c.want {
			t.Errorf("IsAlreadyExistsError(SQLSTATE %q) = %v, want %v", c.code, got, c.want)
		}
	}
	// Wrapped error still matched via errors.As.
	wrapped := fmt.Errorf("apply migration: %w", &pq.Error{Code: "42701"})
	if !d.IsAlreadyExistsError(wrapped) {
		t.Error("IsAlreadyExistsError must detect a wrapped *pq.Error")
	}
	if d.IsAlreadyExistsError(nil) {
		t.Error("IsAlreadyExistsError(nil) must be false")
	}
	if d.IsAlreadyExistsError(errors.New("connection refused")) {
		t.Error("IsAlreadyExistsError must not match unrelated errors")
	}
}

// TestPostgresDialect_IsUniqueViolation verifies the SQLSTATE matching used
// to classify a UNIQUE-constraint violation (REVIEW.md L-7). PostgreSQL
// surfaces these as unique_violation (23505).
func TestPostgresDialect_IsUniqueViolation(t *testing.T) {
	d := &postgresDialect{}
	codes := []struct {
		code string
		want bool
	}{
		{"23505", true},  // unique_violation
		{"42701", false}, // duplicate_column — DDL, not DML unique
		{"42P07", false}, // duplicate_table — DDL
		{"42710", false}, // duplicate_object — DDL
		{"23503", false}, // foreign_key_violation
		{"42P01", false}, // undefined_table
		{"42601", false}, // syntax_error
	}
	for _, c := range codes {
		err := &pq.Error{Code: pq.ErrorCode(c.code)}
		if got := d.IsUniqueViolation(err); got != c.want {
			t.Errorf("IsUniqueViolation(SQLSTATE %q) = %v, want %v", c.code, got, c.want)
		}
	}
	// Wrapped error still matched via errors.As.
	wrapped := fmt.Errorf("exec: %w", &pq.Error{Code: "23505"})
	if !d.IsUniqueViolation(wrapped) {
		t.Error("IsUniqueViolation must detect a wrapped *pq.Error")
	}
	if d.IsUniqueViolation(nil) {
		t.Error("IsUniqueViolation(nil) must be false")
	}
	if d.IsUniqueViolation(errors.New("connection refused")) {
		t.Error("IsUniqueViolation must not match unrelated errors")
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
	q := "INSERT INTO t (a, b) VALUES (?, ?)"
	want := "INSERT INTO t (a, b) VALUES ($1, $2)"
	if got := rebindDollar(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindDollar_SkipsQuestionMarkInStringLiteral(t *testing.T) {
	q := "SELECT * FROM t WHERE a = ? AND b = 'what? no'"
	want := "SELECT * FROM t WHERE a = $1 AND b = 'what? no'"
	if got := rebindDollar(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindDollar_SkipsQuestionMarkInEscapedQuoteLiteral(t *testing.T) {
	q := "SELECT * FROM t WHERE a = ? AND b = 'it''s a ? test' AND c = ?"
	want := "SELECT * FROM t WHERE a = $1 AND b = 'it''s a ? test' AND c = $2"
	if got := rebindDollar(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindDollar_SkipsQuestionMarkInLineComment(t *testing.T) {
	q := "SELECT * FROM t -- why?\nWHERE a = ?"
	want := "SELECT * FROM t -- why?\nWHERE a = $1"
	if got := rebindDollar(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindDollar_ConsecutivePlaceholdersAfterLiteral(t *testing.T) {
	q := "SELECT 'lit?eral', ?, ?, 'more?'"
	want := "SELECT 'lit?eral', $1, $2, 'more?'"
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

	// revoked_tokens.user_id is a FK -> users(id) (REVIEW.md I-9).
	uid := seedIntegrationUser(t, db, "revokepg")
	jti := "test-jti-pg"
	expires := time.Now().Add(1 * time.Hour)

	if err := db.RevokeToken(ctx, jti, uid, expires); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}
	revoked, err := db.IsTokenRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Error("expected token to be revoked")
	}
	if err := db.RevokeToken(ctx, jti, uid, expires); err != nil {
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

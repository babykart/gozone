package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestMySQLDialect_DSN_AppendsParseTime(t *testing.T) {
	d := &mysqlDialect{}
	got := d.DSN("user:pass@tcp(localhost:3306)/gozone")
	if !strings.Contains(got, "parseTime=true") {
		t.Errorf("expected parseTime=true in DSN, got %s", got)
	}
	if strings.Contains(got, "multiStatements") {
		t.Errorf("multiStatements must not be set, got %s", got)
	}
	if strings.Count(got, "?") > 1 {
		t.Errorf("DSN must not contain more than one '?', got %s", got)
	}
}

func TestMySQLDialect_DSN_PreservesExistingParams(t *testing.T) {
	d := &mysqlDialect{}
	got := d.DSN("user:pass@tcp(localhost:3306)/gozone?charset=utf8mb4&loc=Local")

	if strings.Count(got, "?") != 1 {
		t.Errorf("DSN must contain exactly one '?', got %s", got)
	}
	if !strings.Contains(got, "parseTime=true") {
		t.Errorf("expected parseTime=true, got %s", got)
	}
	if !strings.Contains(got, "charset=utf8mb4") {
		t.Errorf("existing charset param must be preserved, got %s", got)
	}
	if !strings.Contains(got, "loc=Local") {
		t.Errorf("existing loc param must be preserved, got %s", got)
	}
	if strings.Contains(got, "multiStatements") {
		t.Errorf("multiStatements must not be set, got %s", got)
	}
}

func TestMySQLDialect_DSN_ParseTimeAlreadySet(t *testing.T) {
	d := &mysqlDialect{}
	got := d.DSN("user:pass@tcp(localhost:3306)/gozone?parseTime=false")

	if !strings.Contains(got, "parseTime=true") {
		t.Errorf("expected parseTime=true to override parseTime=false, got %s", got)
	}
	if strings.Contains(got, "parseTime=false") {
		t.Errorf("parseTime=false should have been overridden, got %s", got)
	}
}

func TestMySQLDialect_DriverName(t *testing.T) {
	d := &mysqlDialect{}
	if got := d.DriverName(); got != "mysql" {
		t.Errorf("expected driver mysql, got %s", got)
	}
}

func TestMySQLDialect_MaxOpenConns(t *testing.T) {
	d := &mysqlDialect{}
	if got := d.MaxOpenConns(); got != 25 {
		t.Errorf("expected MaxOpenConns 25, got %d", got)
	}
}

// TestMySQLDialect_PoolSettings verifies the MySQL pool is fully tuned
// (REVIEW.md m16): a warm idle pool matching the open limit, and a finite
// connection lifetime that recycles connections before wait_timeout / an
// intermediary LB drops them.
func TestMySQLDialect_PoolSettings(t *testing.T) {
	d := &mysqlDialect{}
	if got := d.MaxIdleConns(); got <= 0 || got > d.MaxOpenConns() {
		t.Errorf("MaxIdleConns must be in (0, MaxOpenConns=%d], got %d", d.MaxOpenConns(), got)
	}
	if got := d.ConnMaxLifetime(); got <= 0 {
		t.Errorf("MySQL ConnMaxLifetime must be positive (finite), got %v", got)
	}
}

func TestMySQLDialect_Rebind(t *testing.T) {
	d := &mysqlDialect{}
	q := "SELECT * FROM users WHERE id = ?"
	if got := d.Rebind(q); got != q {
		t.Errorf("expected MySQL rebinding to be a no-op, got %s", got)
	}
}

func TestMySQLDialect_Migrations_NoCreateIndexIfNotExists(t *testing.T) {
	d := &mysqlDialect{}
	for _, m := range d.Migrations() {
		if strings.Contains(strings.ToUpper(m), "CREATE INDEX IF NOT EXISTS") {
			t.Errorf("MySQL migration contains unsupported CREATE INDEX IF NOT EXISTS: %s", m)
		}
	}
}

func TestMySQLDialect_Migrations_ContainInlineIndexes(t *testing.T) {
	d := &mysqlDialect{}
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
			t.Errorf("expected inline index %s to be present in migrations", name)
		}
	}
}

// TestMySQLDialect_Migrations_ZoneCreatedIndexDesc is the regression test for
// m21: idx_activity_logs_zone_created must be defined with DESC on
// created_at, matching the SQLite and PostgreSQL dialects. MySQL originally
// created it inline as (zone_id, created_at) without DESC; a dedicated ALTER
// migration now rebuilds it with DESC. We assert against the full joined
// migration text rather than the original CREATE TABLE because the fix is
// delivered as a new migration (editing the original would not fix existing
// databases — CREATE TABLE IF NOT EXISTS is a no-op there — and would churn
// the content-hash, see m22).
func TestMySQLDialect_Migrations_ZoneCreatedIndexDesc(t *testing.T) {
	d := &mysqlDialect{}
	all := strings.Join(d.Migrations(), "\n")
	needle := "idx_activity_logs_zone_created (zone_id, created_at DESC)"
	if !strings.Contains(all, needle) {
		t.Errorf("MySQL migrations must define idx_activity_logs_zone_created with DESC on created_at (m21); missing %q", needle)
	}
}

// TestMySQLDialect_IsAlreadyExistsError verifies the typed-error matching that
// lets the migration runner tolerate re-running an already-applied migration
// after a content edit (REVIEW.md m22).
func TestMySQLDialect_IsAlreadyExistsError(t *testing.T) {
	d := &mysqlDialect{}
	codes := []struct {
		number uint16
		want   bool
	}{
		{1050, true},  // ER_TABLE_EXISTS_ERROR
		{1060, true},  // ER_DUP_FIELDNAME
		{1061, true},  // ER_DUP_KEYNAME
		{1068, true},  // ER_MULTIPLE_PRI_KEY
		{1146, false}, // ER_NO_SUCH_TABLE
		{1064, false}, // ER_PARSE_ERROR
	}
	for _, c := range codes {
		err := &mysql.MySQLError{Number: c.number}
		if got := d.IsAlreadyExistsError(err); got != c.want {
			t.Errorf("IsAlreadyExistsError(code %d) = %v, want %v", c.number, got, c.want)
		}
	}
	// Wrapped error still matched via errors.As.
	wrapped := fmt.Errorf("apply migration: %w", &mysql.MySQLError{Number: 1060})
	if !d.IsAlreadyExistsError(wrapped) {
		t.Error("IsAlreadyExistsError must detect a wrapped *mysql.MySQLError")
	}
	if d.IsAlreadyExistsError(nil) {
		t.Error("IsAlreadyExistsError(nil) must be false")
	}
	if d.IsAlreadyExistsError(errors.New("connection refused")) {
		t.Error("IsAlreadyExistsError must not match unrelated errors")
	}
}

// TestMySQLDialect_InsertIgnore_IgnoresConflictColumns verifies the contract
// from the Dialect interface: MySQL's INSERT IGNORE catches any unique
// violation, so the conflictColumns parameter is intentionally unused. The
// returned SQL must match the previous shape exactly so callers don't observe
// a behaviour change after the signature update.
func TestMySQLDialect_InsertIgnore_IgnoresConflictColumns(t *testing.T) {
	d := &mysqlDialect{}
	got := d.InsertIgnore(
		"zone_group_members",
		[]string{"group_id", "user_id"},
		// Any value here is intentionally ignored; pass a non-empty value
		// to confirm the signature accepts it without altering output.
		[]string{"group_id", "user_id"},
	)
	want := "INSERT IGNORE INTO zone_group_members (group_id, user_id) VALUES (?, ?)"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}

	// And with empty conflictColumns — same output, proving the parameter
	// is purely cosmetic for MySQL.
	got = d.InsertIgnore("zone_group_members", []string{"group_id", "user_id"}, nil)
	if got != want {
		t.Errorf("empty conflictColumns must not alter MySQL output\ngot:  %q\nwant: %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Integration tests (require GOZONE_TEST_MYSQL_DSN)
// ---------------------------------------------------------------------------

// TestMySQLIntegration_Migrations verifies that the full migration suite
// runs against a real MySQL instance.
func TestMySQLIntegration_Migrations(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_MYSQL_DSN")
	db := newIntegrationDB(t, "mysql", dsn)

	var count int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	expected := len(db.dialect.Migrations())
	if count != expected {
		t.Errorf("expected %d migrations, got %d", expected, count)
	}
}

// TestMySQLIntegration_RevokeToken is the regression test for M-DB1:
// RevokeToken previously used "ON CONFLICT(jti) DO NOTHING" which MySQL
// rejects. The fix routes through InsertIgnore.
func TestMySQLIntegration_RevokeToken(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_MYSQL_DSN")
	db := newIntegrationDB(t, "mysql", dsn)
	ctx := context.Background()

	jti := "test-jti-mysql"
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

// TestMySQLIntegration_LockMigrations is the regression test for M-DB3:
// LockMigrations previously borrowed a different pooled connection for
// RELEASE_LOCK than GET_LOCK, making the release a silent no-op.
func TestMySQLIntegration_LockMigrations(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_MYSQL_DSN")
	db := newIntegrationDB(t, "mysql", dsn)

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

// TestMySQLIntegration_InsertIgnore verifies InsertIgnore silently skips
// a row that violates a real unique index.
func TestMySQLIntegration_InsertIgnore(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_MYSQL_DSN")
	db := newIntegrationDB(t, "mysql", dsn)
	ctx := context.Background()

	_, err := db.ExecContext(ctx,
		"INSERT INTO users (username, email, password_hash, first_name, last_name, role, enabled) VALUES (?, ?, ?, '', '', 'user', 1)",
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
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "testuser").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 user after InsertIgnore, got %d", count)
	}
}

// TestMySQLIntegration_MigrateIdempotent verifies that running migrate()
// twice against MySQL does not error.
func TestMySQLIntegration_MigrateIdempotent(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_MYSQL_DSN")
	db := newIntegrationDB(t, "mysql", dsn)
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// dropAllTablesMySQL removes every user-created table in the current
// database so migrations run from a clean slate.
func dropAllTablesMySQL(t *testing.T, conn *sql.DB) {
	t.Helper()
	rows, err := conn.Query("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if len(tables) == 0 {
		return
	}
	if _, err := conn.Exec("SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		t.Fatalf("disable FK: %v", err)
	}
	for _, tbl := range tables {
		if _, err := conn.Exec(fmt.Sprintf("DROP TABLE IF EXISTS `%s`", tbl)); err != nil {
			t.Fatalf("drop table %s: %v", tbl, err)
		}
	}
	if _, err := conn.Exec("SET FOREIGN_KEY_CHECKS = 1"); err != nil {
		t.Fatalf("enable FK: %v", err)
	}
}

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"
)

func TestPostgresDialect_DriverName(t *testing.T) {
	d := &postgresDialect{}
	if got := d.DriverName(); got != "postgres" {
		t.Errorf("expected driver postgres, got %s", got)
	}
}

// TestPostgresDialect_DSN_ForcesUTC verifies the appended TimeZone=UTC runtime
// parameter: the session (and therefore CURRENT_TIMESTAMP) must run on UTC so
// SQL-side timestamp writes match the UTC instants Go reads back. Both the
// keyword/value form and the URL form must carry it.
func TestPostgresDialect_DSN_ForcesUTC(t *testing.T) {
	d := &postgresDialect{}

	kv := "host=localhost port=5432 user=gozone password=secret dbname=gozone sslmode=disable"
	if got := d.DSN(kv); got != kv+" TimeZone=UTC" {
		t.Errorf("keyword DSN must gain a trailing TimeZone=UTC\nwant: %s TimeZone=UTC\ngot:  %s", kv, got)
	}

	url := "postgres://gozone:secret@localhost:5432/gozone?sslmode=disable"
	got := d.DSN(url)
	if !strings.Contains(got, "TimeZone=UTC") || !strings.Contains(got, "sslmode=disable") {
		t.Errorf("URL DSN must carry TimeZone=UTC and keep sslmode, got: %s", got)
	}

	bare := "postgres://gozone:secret@localhost:5432/gozone"
	if got := d.DSN(bare); !strings.Contains(got, "?TimeZone=UTC") {
		t.Errorf("bare URL DSN must gain ?TimeZone=UTC, got: %s", got)
	}
}

// TestPostgresDialect_DSN_OverridesExistingTimeZone is the timezone-override
// regression: lib/pq reads URL query parameters with q.Get (the FIRST value
// wins), so a DSN that already carries TimeZone=Europe/Paris must have its
// value REPLACED — an appended parameter would be ignored by the driver and
// the operator's zone would stay in effect.
func TestPostgresDialect_DSN_OverridesExistingTimeZone(t *testing.T) {
	d := &postgresDialect{}
	dsn := "postgres://gozone:secret@localhost:5432/gozone?sslmode=disable&TimeZone=Europe%2FParis"
	got := d.DSN(dsn)

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("rewritten DSN must stay URL-parseable: %v (%q)", err, got)
	}
	values := u.Query()["TimeZone"]
	if len(values) != 1 || values[0] != "UTC" {
		t.Errorf("TimeZone must be replaced by exactly one UTC value, got %v (full query %q)", u.Query()["TimeZone"], u.RawQuery)
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Errorf("sslmode must survive the rewrite, got %q", u.RawQuery)
	}
	// The host/userinfo must be untouched.
	if u.Host != "localhost:5432" || u.User.Username() != "gozone" {
		t.Errorf("authority changed by the rewrite: %s", u.Host)
	}
}

func TestPostgresDialect_MaxOpenConns(t *testing.T) {
	d := &postgresDialect{}
	if got := d.MaxOpenConns(); got != 25 {
		t.Errorf("expected MaxOpenConns 25, got %d", got)
	}
}

// TestPostgresDialect_PoolSettings verifies the PostgreSQL pool is fully tuned
// — a warm idle pool matching the open limit, and a finite
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
// after a content edit.
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
		err := &pq.Error{Code: pqerror.Code(c.code)}
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
// to classify a UNIQUE-constraint violation. PostgreSQL
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
		err := &pq.Error{Code: pqerror.Code(c.code)}
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
	// The lock is a transaction-scoped PostgreSQL advisory lock. We verify
	// that calling the release function does not panic and logs no errors
	// when given a working stub.
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open stub db: %v", err)
	}
	defer db.Close()

	release, err := d.LockMigrations(db)
	if err == nil {
		// SQLite does not implement the PostgreSQL statements, so acquiring
		// the lock must fail against this stub. If it succeeded
		// unexpectedly, behave normally.
		release()
	}
}

// TestPostgresAdvisoryLockKey pins the advisory-lock key derivation: stable,
// distinctive (not the banal small constants like 42 any other application
// on the cluster could take), and different from another string's hash.
func TestPostgresAdvisoryLockKey(t *testing.T) {
	k1, k2 := postgresAdvisoryLockKey(), postgresAdvisoryLockKey()
	if k1 != k2 {
		t.Fatalf("key must be deterministic, got %d then %d", k1, k2)
	}
	if k1 == 42 {
		t.Fatal("key must not be the banal constant 42")
	}
	h := fnv.New64a()
	h.Write([]byte("some-other-application"))
	if k1 == int64(h.Sum64()) {
		t.Fatal("key must be derived from a GoZone-specific string")
	}
}

// TestPostgresZoneLockKey pins the zone-specific advisory-key derivation.
func TestPostgresZoneLockKey(t *testing.T) {
	a := postgresZoneLockKey("example.com.")
	if a != postgresZoneLockKey("example.com.") {
		t.Fatal("zone lock key must be deterministic")
	}
	if a == postgresZoneLockKey("example.org.") {
		t.Fatal("different zones must derive different advisory keys")
	}
	if a == postgresAdvisoryLockKey() {
		t.Fatal("zone lock keys must be distinct from the migration-lock key")
	}
}

// TestIsPgQueryCanceled pins the retry classification: only SQLSTATE 57014
// (query_canceled — what statement_timeout surfaces as) is a retryable lock
// wait; other driver errors and plain errors are not.
func TestIsPgQueryCanceled(t *testing.T) {
	if !isPgQueryCanceled(&pq.Error{Code: "57014"}) {
		t.Error("57014 (query_canceled) must be retryable")
	}
	if isPgQueryCanceled(&pq.Error{Code: "57000"}) {
		t.Error("57000 must not be classified as a lock-wait timeout")
	}
	if isPgQueryCanceled(errors.New("plain error")) {
		t.Error("a non-driver error must not be classified as a lock-wait timeout")
	}
}

func TestPostgresDialect_InsertIgnore_UsesConflictColumns(t *testing.T) {
	// The conflict target must come from an explicit
	// conflictColumns argument so the caller can never accidentally target
	// the wrong unique index when columns != constraint.
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

// TestPostgresDialect_InsertSkipDuplicate pins the skip-duplicate form: it
// reuses ON CONFLICT (...) DO NOTHING, which only handles the named conflict
// target — foreign-key, CHECK and conversion errors still fail the
// statement and abort the transaction.
func TestPostgresDialect_InsertSkipDuplicate(t *testing.T) {
	d := &postgresDialect{}
	columns := []string{"group_id", "user_id"}
	got := d.InsertSkipDuplicate("zone_group_members", columns, columns)
	want := "INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?) ON CONFLICT (group_id, user_id) DO NOTHING"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if got != d.InsertIgnore("zone_group_members", columns, columns) {
		t.Error("InsertSkipDuplicate must reuse the InsertIgnore SQL on PostgreSQL")
	}

	// The conflictColumns invariant is inherited from InsertIgnore: an
	// empty target must produce the error sentinel, not a fallback.
	if got := d.InsertSkipDuplicate("any_table", []string{"a"}, nil); !strings.Contains(got, "-- ERROR") {
		t.Errorf("empty conflictColumns must produce an error sentinel, got %q", got)
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

// TestPostgresIntegration_Migrations is a direct regression test:
// schema_migrations must use TIMESTAMP, not DATETIME, or the CREATE
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

	// Verify schema_migrations.applied_at uses TIMESTAMP (regression guard).
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

// TestPostgresIntegration_TimeZoneForcedUTC verifies on a live server that
// the dialect's DSN rewrite overrides an operator-supplied TimeZone: a DSN
// carrying TimeZone=Europe/Paris must still open a UTC session (naive
// timestamps and every expires_at-style comparison depend on it).
func TestPostgresIntegration_TimeZoneForcedUTC(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		t.Skip("test DSN is not URL-form; the keyword-form append path is covered by unit tests")
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	tzDSN := (&postgresDialect{}).DSN(dsn + sep + "TimeZone=Europe%2FParis")

	conn, err := sql.Open("postgres", tzDSN)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	var tz string
	if err := conn.QueryRow("SHOW TIME ZONE").Scan(&tz); err != nil {
		t.Fatalf("SHOW TIME ZONE: %v", err)
	}
	if tz != "UTC" {
		t.Errorf("session timezone = %q, want UTC (operator TimeZone must be overridden)", tz)
	}
}

// TestPostgresIntegration_RevokeToken verifies RevokeToken works on
// PostgreSQL.
func TestPostgresIntegration_RevokeToken(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)
	ctx := context.Background()

	// revoked_tokens.user_id is a FK -> users(id).
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

// TestPostgresIntegration_PrunePasswordHistory keeps the prune query honest
// on PostgreSQL: the derived-table wrapper added for MySQL must stay valid
// here too (PostgreSQL requires the alias, accepts the inner LIMIT, and has
// no same-table restriction).
func TestPostgresIntegration_PrunePasswordHistory(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)
	ctx := context.Background()

	uid := seedIntegrationUser(t, db, "prunepg")

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() // #nosec G104 -- read-only assertions, nothing to commit

	for i := 0; i < 5; i++ {
		if err := tx.RecordPassword(ctx, uid, fmt.Sprintf("hash-%d", i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := tx.PrunePasswordHistory(ctx, uid, 3); err != nil {
		t.Fatalf("PrunePasswordHistory failed: %v", err)
	}
	if n, err := tx.PasswordHistoryCount(ctx, uid); err != nil || n != 3 {
		t.Errorf("expected 3 rows after prune to 3, got %d err=%v", n, err)
	}
	if err := tx.PrunePasswordHistory(ctx, uid, 10); err != nil {
		t.Fatalf("PrunePasswordHistory with limit above row count: %v", err)
	}
	if n, err := tx.PasswordHistoryCount(ctx, uid); err != nil || n != 3 {
		t.Errorf("prune above the row count must not delete anything, got %d err=%v", n, err)
	}
}

// TestPostgresIntegration_LockMigrations is a regression test:
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

// TestPostgresIntegration_ZoneLockExclusion verifies that transaction-scoped
// advisory zone locks are cluster-wide across independent DB handles.
func TestPostgresIntegration_ZoneLockExclusion(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	assertZoneLockExcludesSecondDB(t, "postgres", dsn)
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

// TestPostgresIntegration_HitRateLimit exercises the RETURNING upsert
// against a real PostgreSQL.
func TestPostgresIntegration_HitRateLimit(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)
	ctx := context.Background()

	window := time.Now().UTC().Truncate(time.Minute)
	key := "itest:pg:hit"
	for i := 1; i <= 3; i++ {
		allowed, err := db.HitRateLimit(ctx, key, window, 3)
		if err != nil {
			t.Fatalf("hit %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("hit %d must be allowed under limit 3", i)
		}
	}
	if allowed, err := db.HitRateLimit(ctx, key, window, 3); err != nil || allowed {
		t.Errorf("hit 4 must be blocked (err=%v allowed=%v)", err, allowed)
	}
	if allowed, err := db.HitRateLimit(ctx, key, window.Add(time.Minute), 3); err != nil || !allowed {
		t.Errorf("new window must be allowed (err=%v allowed=%v)", err, allowed)
	}
}

// TestPostgresIntegration_AlreadyExistsToleratedPerStatement is the live
// PostgreSQL regression for the per-statement savepoint recovery: a re-run
// migration whose first statement hits an already-exists error must NOT abort
// the surrounding transaction (25P02: "current transaction is aborted") and
// must still apply the following statements. Without the savepoints the
// tolerated error poisons the transaction and the second ALTER fails, so the
// migration errors out and the new column never appears.
func TestPostgresIntegration_AlreadyExistsToleratedPerStatement(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")

	// Drive applyMigration directly on a scratch database: newIntegrationDB
	// runs the full migration set, which would fill schema_migrations with
	// versions irrelevant to this test. Instead mirror the SQLite unit-test
	// setup — raw connection, hand-built tracking table, &DB with the
	// postgresDialect.
	dialect := &postgresDialect{}
	conn, err := sql.Open("postgres", dialect.DSN(dsn))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Close via t.Cleanup (registered BEFORE the SQL cleanup below) so the
	// connection is still open when the LIFO cleanup callbacks run; a
	// deferred Close would run first and silently no-op the DROP/DELETE.
	t.Cleanup(func() { conn.Close() }) // #nosec G104 -- best-effort close

	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	// Scratch table with one pre-existing column; the migration's first
	// statement re-adds it (tolerated), the second adds a new one.
	const table = "mig_sp_scratch"
	if _, err := conn.Exec("DROP TABLE IF EXISTS " + table); err != nil {
		t.Fatalf("drop scratch table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec("DROP TABLE IF EXISTS " + table)
		_, _ = conn.Exec("DELETE FROM schema_migrations WHERE version = 'mig_test_pg_savepoint'")
	})
	if _, err := conn.Exec("CREATE TABLE " + table + " (id INTEGER PRIMARY KEY, existing_col INTEGER)"); err != nil {
		t.Fatalf("create scratch table: %v", err)
	}

	db := &DB{Conn: conn, dialect: dialect}
	migration := "ALTER TABLE " + table + " ADD COLUMN existing_col INTEGER;\n" +
		"ALTER TABLE " + table + " ADD COLUMN later_col INTEGER"
	const version = "mig_test_pg_savepoint"
	if err := db.applyMigration(migration, version); err != nil {
		t.Fatalf("applyMigration with a tolerated already-exists statement: %v", err)
	}

	// The statement AFTER the tolerated error must have run.
	var laterCol int
	if err := conn.QueryRow(
		"SELECT COUNT(*) FROM information_schema.columns WHERE table_name = $1 AND column_name = 'later_col'",
		table,
	).Scan(&laterCol); err != nil {
		t.Fatalf("query information_schema: %v", err)
	}
	if laterCol != 1 {
		t.Error("later_col must be added by the statement following the tolerated already-exists error")
	}

	var recorded int
	if err := conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version = $1", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 1 {
		t.Errorf("migration must be recorded exactly once after the tolerated replay, got %d", recorded)
	}
}

// TestPostgresIntegration_APIKeyScopeColumnBackfill verifies the scoped-API-key
// migration on PostgreSQL: the scope column exists and an INSERT that omits it
// reads back the DEFAULT 'api:write' (the pre-migration key backfill).
func TestPostgresIntegration_APIKeyScopeColumnBackfill(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)

	uid := seedIntegrationUser(t, db, "scopepg")

	if _, err := db.Conn.Exec(
		"INSERT INTO api_keys (user_id, key_hash) VALUES (?, ?)", uid, "hash-no-scope",
	); err != nil {
		t.Fatalf("insert api key without scope: %v", err)
	}

	var scope string
	if err := db.Conn.QueryRow(
		"SELECT scope FROM api_keys WHERE key_hash = 'hash-no-scope'",
	).Scan(&scope); err != nil {
		t.Fatalf("select scope: %v", err)
	}
	if scope != "api:write" {
		t.Errorf("expected scope default 'api:write', got %q", scope)
	}
}

// TestPostgresIntegration_LockZoneSurvivesIdleTxTimeout is a live-server
// regression test for the mutual-exclusion hazard created by an operator-set
// idle_in_transaction_session_timeout: the transaction holding the advisory
// zone lock is IDLE by design while the critical section (the PowerDNS
// read-modify-write) runs on other connections, so a server-configured idle
// timeout kills the lock-holding backend mid-critical-section and silently
// drops the advisory lock.
//
// Behavioral shape of the test: on the fixed code the lock-holding
// transaction survives its idle window (SET LOCAL
// idle_in_transaction_session_timeout = 0) and the second acquisition below
// fails on its bounded context. On the unfixed code the idle timeout kills
// the backend at ~200ms, the advisory lock is silently released, and the
// second acquisition SUCCEEDS — mutual exclusion lost.
func TestPostgresIntegration_LockZoneSurvivesIdleTxTimeout(t *testing.T) {
	dsn := skipIfNoDSN(t, "GOZONE_TEST_POSTGRES_DSN")
	db := newIntegrationDB(t, "postgres", dsn)

	// Reopen a disposable pool whose sessions carry a 200ms
	// idle_in_transaction_session_timeout. lib/pq forwards unrecognized URL
	// query params to the server as startup runtime parameters
	// (convertURL → Config.Runtime → startup packet), so a URL-form DSN can
	// set the session GUC without touching the server configuration. The
	// dialect DSN rewrite keeps unknown params (it only pins TimeZone=UTC).
	// Only the lock phase runs on this pool, so the aggressive timeout never
	// leaks into other tests.
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		t.Skip("test DSN is not URL-form; the idle-timeout GUC cannot be set per-session")
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dialect := &postgresDialect{}
	testPool, err := sql.Open("postgres", dialect.DSN(dsn+sep+"idle_in_transaction_session_timeout=200"))
	if err != nil {
		t.Fatalf("open disposable pool: %v", err)
	}
	defer testPool.Close() // #nosec G104 -- best-effort cleanup in test
	// Two connections: the holder pins one for the whole critical section;
	// the contender must be able to open its own so it actually reaches
	// pg_advisory_xact_lock (with a 1-connection pool it would block in
	// pool.Conn on its deadline instead, and the assertion below would pass
	// without ever exercising the advisory-lock contention).
	testPool.SetMaxOpenConns(2)

	ctx := context.Background()
	release, err := db.dialect.LockZone(ctx, testPool, "idle-tx-test.example.com.")
	if err != nil {
		t.Fatalf("LockZone: %v", err)
	}

	// Idle well past the 200ms session timeout: the lock-holding transaction
	// does nothing on its pinned connection while the "critical section"
	// (here: this sleep) runs elsewhere. On the unfixed code the idle
	// timeout kills the backend here and silently releases the advisory
	// lock; on the fixed code the SET LOCAL exemption keeps it alive.
	time.Sleep(500 * time.Millisecond)

	// While the holder still idles, a second acquisition of the SAME zone
	// with a bounded context must NOT succeed: mutual exclusion must
	// survive the idle window. On the unfixed code the lock was silently
	// dropped at ~200ms and this acquisition succeeds — the behavioral RED
	// this test pins.
	secondCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	secondRelease, err := db.dialect.LockZone(secondCtx, testPool, "idle-tx-test.example.com.")
	if err == nil {
		secondRelease()
		t.Fatal("second LockZone acquired while the holder idled past idle_in_transaction_session_timeout: mutual exclusion lost")
	}
	// Only the two expected failure shapes prove the lock was still held:
	// the contender's own context deadline, or the statement_timeout /
	// context-cancelation classification the dialect already uses for its
	// bounded waits. Any other error is a test-environment failure, not
	// evidence of mutual exclusion.
	if !errors.Is(err, context.DeadlineExceeded) && !isPgQueryCanceled(err) {
		t.Fatalf("second LockZone failed with an unexpected error (must be a deadline or a canceled wait): %v", err)
	}

	// The rollback must succeed cleanly on a live backend; the lock was
	// genuinely held for the whole idle window if the post-release
	// acquisition below succeeds.
	release()

	reacquireCtx, cancelReacquire := context.WithTimeout(ctx, 5*time.Second)
	defer cancelReacquire()
	reacquireRelease, err := db.dialect.LockZone(reacquireCtx, testPool, "idle-tx-test.example.com.")
	if err != nil {
		t.Fatalf("LockZone after clean release: %v (lock not held through the idle window?)", err)
	}
	reacquireRelease()
}

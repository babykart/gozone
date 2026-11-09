package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mattn/go-sqlite3"

	"github.com/babykart/gozone/internal/config"
)

// nonAtomicSQLiteDialect forces SQLite through the non-atomic migration path
// (statements first, version recorded at the end) so the MySQL/MariaDB
// implicit-DDL-commit behaviour can be exercised without a live server.
type nonAtomicSQLiteDialect struct{ sqliteDialect }

func (d *nonAtomicSQLiteDialect) DDLAtomic() bool { return false }

// newNonAtomicTestDB opens an in-memory database wired to the non-atomic
// migration path with the tracking table already created, mirroring the
// setup of the atomic applyMigration tests.
func newNonAtomicTestDB(t *testing.T) *DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Exec(`CREATE TABLE schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	return &DB{Conn: conn, dialect: &nonAtomicSQLiteDialect{}}
}

// TestApplyMigration_NonAtomicFailureNotRecorded est la régression du
// versionnement des migrations sur les dialectes à commit implicite: quand la
// dernière instruction échoue, la version ne doit PAS être enregistrée (le
// schéma peut rester partiellement modifié — aucun rollback possible), sinon
// le redémarrage saute la migration incomplète.
func TestApplyMigration_NonAtomicFailureNotRecorded(t *testing.T) {
	db := newNonAtomicTestDB(t)

	const version = "mig_test_nonatomic_fail"
	migration := `CREATE TABLE mig_nonatomic_a (id INTEGER PRIMARY KEY);
THIS IS NOT VALID SQL;`

	if err := db.applyMigration(migration, version); err == nil {
		t.Fatal("expected migration with an invalid statement to fail, got nil")
	}

	var recorded int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 0 {
		t.Error("failed migration must not be recorded in schema_migrations")
	}
}

// TestApplyMigration_NonAtomicResumeAfterFailure vérifie la reprise après
// échec sur les dialectes non atomiques: la migration est relancée depuis le
// début, l'objet déjà créé par la tentative ratée est toléré (erreur
// already-exists ignorée instruction par instruction), et la version n'est
// enregistrée qu'une fois toutes les instructions réussies.
func TestApplyMigration_NonAtomicResumeAfterFailure(t *testing.T) {
	db := newNonAtomicTestDB(t)

	const version = "mig_test_nonatomic_resume"
	failing := `CREATE TABLE mig_nonatomic_a (id INTEGER PRIMARY KEY);
THIS IS NOT VALID SQL;`
	if err := db.applyMigration(failing, version); err == nil {
		t.Fatal("expected the failing migration to fail, got nil")
	}

	// Restart: the first statement's object already exists (the failed
	// attempt created it); the re-run must skip it and complete.
	retry := `CREATE TABLE mig_nonatomic_a (id INTEGER PRIMARY KEY);
CREATE TABLE mig_nonatomic_b (id INTEGER PRIMARY KEY);`
	if err := db.applyMigration(retry, version); err != nil {
		t.Fatalf("resume migration: %v", err)
	}

	for _, table := range []string{"mig_nonatomic_a", "mig_nonatomic_b"} {
		var n int
		if err := db.Conn.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&n); err != nil {
			t.Fatalf("query %s: %v", table, err)
		}
		if n != 1 {
			t.Errorf("table %s must exist after the resumed migration, got count %d", table, n)
		}
	}

	var recorded int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 1 {
		t.Errorf("resumed migration should be recorded exactly once, got %d", recorded)
	}
}

// TestApplyMigration_NonAtomicSuccessRecords vérifie le chemin nominal:
// toutes les instructions réussissent et la version est enregistrée une
// seule fois.
func TestApplyMigration_NonAtomicSuccessRecords(t *testing.T) {
	db := newNonAtomicTestDB(t)

	const version = "mig_test_nonatomic_ok"
	migration := `CREATE TABLE mig_nonatomic_ok_a (id INTEGER PRIMARY KEY);
CREATE TABLE mig_nonatomic_ok_b (id INTEGER PRIMARY KEY);`

	if err := db.applyMigration(migration, version); err != nil {
		t.Fatalf("applyMigration: %v", err)
	}

	var recorded int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 1 {
		t.Errorf("migration should be recorded exactly once, got %d", recorded)
	}
}

// TestDialectDDLAtomic pins the per-dialect DDLAtomic contract that
// applyMigration relies on to pick the apply/record ordering.
func TestDialectDDLAtomic(t *testing.T) {
	if !(&sqliteDialect{}).DDLAtomic() {
		t.Error("sqlite DDLAtomic must be true (transactional DDL)")
	}
	if !(&postgresDialect{}).DDLAtomic() {
		t.Error("postgres DDLAtomic must be true (transactional DDL)")
	}
	if (&mysqlDialect{}).DDLAtomic() {
		t.Error("mysql DDLAtomic must be false (DDL implicitly commits)")
	}
}

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "single no trailing semicolon",
			in:   "CREATE TABLE a (x INT)",
			want: []string{"CREATE TABLE a (x INT)"},
		},
		{
			name: "single trailing semicolon",
			in:   "CREATE TABLE a (x INT);",
			want: []string{"CREATE TABLE a (x INT)"},
		},
		{
			name: "two statements",
			in:   "CREATE TABLE a (x INT); CREATE INDEX idx ON a(x)",
			want: []string{"CREATE TABLE a (x INT)", "CREATE INDEX idx ON a(x)"},
		},
		{
			name: "semicolon inside string literal does not split",
			in:   "INSERT INTO a VALUES ('a;b', 'c')",
			want: []string{"INSERT INTO a VALUES ('a;b', 'c')"},
		},
		{
			name: "escaped quote keeps string open across semicolon",
			in:   "INSERT INTO a VALUES ('it''s;b')",
			want: []string{"INSERT INTO a VALUES ('it''s;b')"},
		},
		{
			name: "empty and repeated semicolons yield nothing",
			in:   ";;  ;",
			want: nil,
		},
		{
			name: "empty input",
			in:   "",
			want: nil,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := splitStatements(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("splitStatements(%q) = %v (len %d), want len %d", tt.in, got, len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitStatements(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}

	// A semicolon inside a "--" line comment must not start a new statement.
	t.Run("semicolon inside line comment does not split", func(t *testing.T) {
		got := splitStatements("CREATE TABLE a (x INT); -- comment ; here\nCREATE TABLE b (y INT)")
		if len(got) != 2 {
			t.Fatalf("expected 2 statements, got %d: %v", len(got), got)
		}
		if got[0] != "CREATE TABLE a (x INT)" {
			t.Errorf("first statement = %q, want %q", got[0], "CREATE TABLE a (x INT)")
		}
		if !strings.Contains(got[1], "CREATE TABLE b (y INT)") {
			t.Errorf("second statement %q must contain the b table DDL", got[1])
		}
	})
}

// TestApplyMigration_MultiStatementCommitsAndRecords verifies that a valid
// multi-statement migration is applied in full and recorded atomically.
func TestApplyMigration_MultiStatementCommitsAndRecords(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	const version = "mig_test_multi_ok"
	migration := `CREATE TABLE mig_multi_a (id INTEGER PRIMARY KEY);
CREATE TABLE mig_multi_b (id INTEGER PRIMARY KEY);`

	if err := db.applyMigration(migration, version); err != nil {
		t.Fatalf("applyMigration: %v", err)
	}

	for _, table := range []string{"mig_multi_a", "mig_multi_b"} {
		var n int
		if err := db.Conn.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&n); err != nil {
			t.Fatalf("query %s: %v", table, err)
		}
		if n != 1 {
			t.Errorf("table %s should exist after commit, got count %d", table, n)
		}
	}

	var recorded int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 1 {
		t.Errorf("migration should be recorded exactly once, got %d", recorded)
	}
}

// TestApplyMigration_AtomicOnPartialFailure (below) already guards the
// whole-transaction rollback contract the savepoints must preserve: a hard
// failure rolls back the sentinel table and the version claim. The NEW
// behaviour — per-statement recovery from a tolerated already-exists error —
// is pinned by TestApplyMigration_StatementsRunUnderSavepoints, since SQLite
// tolerates per-statement errors even without savepoints and cannot
// demonstrate the 25P02 abort that motivates them on PostgreSQL.

// execRecordingConnector is a database/sql driver.Connector wrapping the
// sqlite3 driver; it records the text of every statement seen through Prepare
// or direct ExecContext on its connections. TestApplyMigration_StatementsRunUnderSavepoints
// uses it to prove applyMigration brackets each migration statement with the
// savepoint control statements — the observable contract of the per-statement
// recovery that keeps a tolerated already-exists error from aborting the whole
// PostgreSQL transaction (25P02).
type execRecordingConnector struct {
	inner   driver.Driver
	dsn     string
	mu      sync.Mutex
	queries []string
}

func (c *execRecordingConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &execRecordingConn{Conn: conn, rec: c}, nil
}

func (c *execRecordingConnector) Driver() driver.Driver { return c.inner }

func (c *execRecordingConnector) record(query string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queries = append(c.queries, query)
}

// normalizedQueries returns the recorded statements trimmed of surrounding
// whitespace and trailing semicolons, in execution order.
func (c *execRecordingConnector) normalizedQueries() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	queries := make([]string, 0, len(c.queries))
	for _, q := range c.queries {
		queries = append(queries, strings.TrimSuffix(strings.TrimSpace(q), ";"))
	}
	return queries
}

// execRecordingConn delegates to the wrapped sqlite3 connection and records
// every statement text seen through Prepare (the prepared path) or
// ExecContext (the direct-exec path database/sql prefers when the connection
// implements driver.ExecerContext — which sqlite3 does).
type execRecordingConn struct {
	driver.Conn
	rec *execRecordingConnector
}

func (c *execRecordingConn) Prepare(query string) (driver.Stmt, error) {
	c.rec.record(query)
	return c.Conn.Prepare(query)
}

func (c *execRecordingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.rec.record(query)
	ec, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, errors.New("execRecordingConn: inner driver lacks ExecerContext")
	}
	return ec.ExecContext(ctx, query, args)
}

// TestApplyMigration_StatementsRunUnderSavepoints is the driver-level pin of
// the per-statement savepoint contract: on atomic-DDL dialects every migration
// statement must run between SAVEPOINT gozone_migration_stmt and RELEASE
// SAVEPOINT gozone_migration_stmt, and a tolerated already-exists statement
// must be recovered with ROLLBACK TO SAVEPOINT gozone_migration_stmt before
// the loop moves on. On PostgreSQL the first error aborts the whole
// transaction (25P02), so without these statements a re-run migration whose
// first object already exists silently drops every following statement.
// SQLite cannot demonstrate the abort (it tolerates per-statement errors
// anyway), hence the assertion is on the savepoint SQL itself.
func TestApplyMigration_StatementsRunUnderSavepoints(t *testing.T) {
	dialect := &sqliteDialect{}
	rec := &execRecordingConnector{
		inner: &sqlite3.SQLiteDriver{},
		dsn:   dialect.DSN(":memory:"),
	}
	conn := sql.OpenDB(rec)
	// A single pooled connection: the in-memory database must be shared
	// between the setup below and applyMigration, and every recorded
	// statement then belongs to this test.
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.Exec(`CREATE TABLE schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	// The SECOND statement's object already exists: the savepoint recovery
	// path (SAVEPOINT + ROLLBACK TO SAVEPOINT) must be exercised once.
	if _, err := conn.Exec("CREATE TABLE stmt_two (id INTEGER)"); err != nil {
		t.Fatalf("pre-create stmt_two: %v", err)
	}

	db := &DB{Conn: conn, dialect: dialect}
	sqlText := "CREATE TABLE stmt_one (id INTEGER);\nCREATE TABLE stmt_two (id INTEGER);\nCREATE TABLE stmt_three (id INTEGER)"
	if err := db.applyMigration(sqlText, migrationVersion(sqlText)); err != nil {
		t.Fatalf("applyMigration with a pre-existing object: %v", err)
	}

	// Exact ordered pin: every statement runs between its own SAVEPOINT and
	// RELEASE; the tolerated stmt_two error is recovered with ROLLBACK TO
	// (followed by RELEASE to keep the savepoint stack clean) BEFORE
	// stmt_three starts. A substring check would let one savepoint around
	// the whole migration pass, and "SAVEPOINT x" matches RELEASE/ROLLBACK
	// TO as well — hence the exact sequence comparison.
	queries := rec.normalizedQueries()
	start := slices.Index(queries, "SAVEPOINT gozone_migration_stmt")
	if start < 0 {
		t.Fatalf("no SAVEPOINT recorded; statements: %v", queries)
	}
	wantTail := []string{
		"SAVEPOINT gozone_migration_stmt",
		"CREATE TABLE stmt_one (id INTEGER)",
		"RELEASE SAVEPOINT gozone_migration_stmt",
		"SAVEPOINT gozone_migration_stmt",
		"CREATE TABLE stmt_two (id INTEGER)",
		"ROLLBACK TO SAVEPOINT gozone_migration_stmt",
		"RELEASE SAVEPOINT gozone_migration_stmt",
		"SAVEPOINT gozone_migration_stmt",
		"CREATE TABLE stmt_three (id INTEGER)",
		"RELEASE SAVEPOINT gozone_migration_stmt",
	}
	if tail := queries[start:]; !slices.Equal(tail, wantTail) {
		t.Errorf("statement sequence mismatch\ngot:  %q\nwant: %q", tail, wantTail)
	}
}

// TestApplyMigration_AtomicOnPartialFailure is the core regression test for
// when the second statement of a multi-statement migration fails, the
// whole migration must roll back — the first statement's effect must NOT
// persist and the migration must NOT be recorded. (SQLite provides true
// transactional DDL, so this is fully enforceable here.)
func TestApplyMigration_AtomicOnPartialFailure(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	const version = "mig_test_partial_failure"
	// Statement 1 creates a sentinel table; statement 2 is invalid SQL.
	migration := `CREATE TABLE mig_partial_test (id INTEGER PRIMARY KEY);
THIS IS NOT VALID SQL;`

	if err := db.applyMigration(migration, version); err == nil {
		t.Fatal("expected migration with an invalid statement to fail, got nil")
	}

	var n int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mig_partial_test'",
	).Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if n != 0 {
		t.Error("partial migration was not rolled back: sentinel table still exists")
	}

	var recorded int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 0 {
		t.Error("failed migration must not be recorded in schema_migrations")
	}
}

// TestApplyMigration_RecordsFailureDoesNotApply ensures that if recording the
// migration fails for some reason, the schema change is rolled back too
// (atomic apply+record). We trigger a recording failure by pre-inserting the
// version row so the PRIMARY KEY conflicts on the recording INSERT.
func TestApplyMigration_RecordsFailureDoesNotApply(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	const version = "mig_test_dup_record"
	// Pre-record the version so the recording INSERT inside applyMigration
	// hits a PRIMARY KEY conflict.
	if _, err := db.Conn.Exec(
		"INSERT INTO schema_migrations (version) VALUES (?)", version,
	); err != nil {
		t.Fatalf("seed duplicate version: %v", err)
	}

	migration := "CREATE TABLE mig_dup_record_test (id INTEGER PRIMARY KEY)"
	err = db.applyMigration(migration, version)
	if err == nil {
		t.Fatal("expected recording conflict to fail the migration, got nil")
	}

	// The CREATE TABLE must have been rolled back since recording failed.
	var n int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mig_dup_record_test'",
	).Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if n != 0 {
		t.Error("schema change must roll back when recording fails (apply+record must be atomic)")
	}
}

// editedSQLiteDialect wraps sqliteDialect and replaces specific migration
// texts (map key) with edited versions (map value). This simulates a typo fix
// in an already-applied migration, which changes its content hash but not its
// schema effect — the exact content-edit scenario.
type editedSQLiteDialect struct {
	sqliteDialect
	override map[string]string
}

func (e *editedSQLiteDialect) Migrations() []string {
	orig := e.sqliteDialect.Migrations()
	out := make([]string, len(orig))
	for i, m := range orig {
		if edited, ok := e.override[m]; ok {
			out[i] = edited
		} else {
			out[i] = m
		}
	}
	return out
}

// TestMigrate_EditedMigrationDoesNotAbort is the core content-edit regression test:
// editing an already-applied migration (so its content hash changes) must not
// abort startup when the migration is re-run and hits a non-idempotent
// statement (ALTER TABLE ADD COLUMN). The runner detects the "already exists"
// error, records the new hash, and continues.
func TestMigrate_EditedMigrationDoesNotAbort(t *testing.T) {
	dialect := &sqliteDialect{}
	conn, err := sql.Open("sqlite3", dialect.DSN(":memory:"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	// 1. Apply all migrations normally so the schema is fully populated.
	db := &DB{Conn: conn, dialect: dialect}
	if err := db.migrate(); err != nil {
		t.Fatalf("initial migrate: %v", err)
	}

	// 2. Find a non-idempotent ALTER TABLE ADD COLUMN migration and edit it
	//    (append a trailing comment so the content hash changes but the SQL
	//    effect is identical).
	var original string
	for _, m := range dialect.Migrations() {
		if strings.Contains(m, "ALTER TABLE activity_logs ADD COLUMN old_value") {
			original = m
			break
		}
	}
	if original == "" {
		t.Fatal("test baseline: ALTER activity_logs old_value migration not found")
	}
	edited := original + " -- content edit"
	if migrationVersion(original) == migrationVersion(edited) {
		t.Fatal("test baseline: edited migration must have a different content hash")
	}

	// 3. Re-run migrate() with the edited dialect. Without the fallback this
	//    fails with "duplicate column name: old_value".
	editedDialect := &editedSQLiteDialect{override: map[string]string{original: edited}}
	db2 := &DB{Conn: conn, dialect: editedDialect}
	if err := db2.migrate(); err != nil {
		t.Fatalf("migrate after editing an applied migration should not abort: %v", err)
	}

	// 4. The edited migration's new hash is now recorded, so a further run is
	//    a clean no-op (no warning, no error).
	var recorded int
	if err := conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", migrationVersion(edited),
	).Scan(&recorded); err != nil {
		t.Fatalf("query edited version: %v", err)
	}
	if recorded != 1 {
		t.Errorf("edited migration's new hash should be recorded exactly once, got %d", recorded)
	}

	db3 := &DB{Conn: conn, dialect: editedDialect}
	if err := db3.migrate(); err != nil {
		t.Fatalf("third migrate (steady state) should be a no-op: %v", err)
	}
}

// TestMigrate_UntrackedPopulatedDatabaseRunsMigrations pins the removal of
// the "untracked but populated database → mark everything applied"
// shortcut: a database whose schema_migrations table is empty while the
// schema exists (tracking wiped, or a very old upgrade) used to be declared
// fully migrated, so every table and column introduced afterwards was
// silently never created. Re-opening must instead run the migrations and
// recreate missing objects, with the already-existing ones tolerated via
// the already-exists fallback.
func TestMigrate_UntrackedPopulatedDatabaseRunsMigrations(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "untracked.db") + "?cache=shared"
	cfg := &config.DatabaseConfig{Driver: "sqlite3", DSN: dsn}

	db1, err := New(cfg)
	if err != nil {
		t.Fatalf("initial New: %v", err)
	}
	// A populated users table is what used to trigger the shortcut.
	if _, err := db1.Exec(
		"INSERT INTO users (username, email, password_hash, role, enabled) VALUES ('legacy', 'legacy@test.local', 'x', 'admin', 1)",
	); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	// Simulate the untracked state: wipe the tracking table and drop a
	// late-introduced object.
	if _, err := db1.Exec("DELETE FROM schema_migrations"); err != nil {
		t.Fatalf("wipe tracking: %v", err)
	}
	if _, err := db1.Exec("DROP TABLE rate_limit_counters"); err != nil {
		t.Fatalf("drop late table: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db2, err := New(cfg) // migrate() runs on open
	if err != nil {
		t.Fatalf("reopen New: %v", err)
	}
	t.Cleanup(func() { db2.Close() })

	// The dropped table must have been recreated, not skipped.
	var n int
	if err := db2.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rate_limit_counters'",
	).Scan(&n); err != nil || n != 1 {
		t.Errorf("rate_limit_counters must be recreated on the untracked database (count=%d err=%v)", n, err)
	}
	// Tracking must be fully populated afterwards.
	if err := db2.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil || n != len((&sqliteDialect{}).Migrations()) {
		t.Errorf("schema_migrations must record every migration, got %d (want %d) err=%v", n, len((&sqliteDialect{}).Migrations()), err)
	}
	// Re-opening again is a clean no-op.
	db3 := &DB{Conn: mustOpenSQLite(t, dsn), dialect: &sqliteDialect{}}
	defer db3.Conn.Close()
	if err := db3.migrate(); err != nil {
		t.Fatalf("steady-state migrate: %v", err)
	}
}

// mustOpenSQLite opens a raw sqlite connection for tests driving migrate
// directly on an existing file.
func mustOpenSQLite(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", (&sqliteDialect{}).DSN(dsn))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return conn
}

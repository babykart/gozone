package database

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/config"
)

func TestNewInMemory(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}
	db, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Verify pragmas are set correctly
	var journalMode string
	err = db.Conn.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Errorf("failed to query journal_mode: %v", err)
	}
	// In-memory databases use 'memory' journal mode, not 'wal'
	if journalMode != "wal" && journalMode != "memory" {
		t.Errorf("expected journal_mode wal or memory, got %s", journalMode)
	}
	// In-memory databases use 'memory' journal mode, not 'wal'
	if journalMode != "wal" && journalMode != "memory" {
		t.Errorf("expected journal_mode wal or memory, got %s", journalMode)
	}

	var enabled int
	err = db.Conn.QueryRow("PRAGMA foreign_keys").Scan(&enabled) // Corrected variable name
	if err != nil {
		t.Errorf("failed to query foreign_keys: %v", err)
	}
	if enabled != 1 {
		t.Errorf("expected foreign_keys=1, got %d", enabled)
	}

	// Verify tables exist
	tables := []string{"users", "settings", "activity_logs", "api_keys", "schema_migrations"}
	for _, table := range tables {
		var name string
		err := db.Conn.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}
}

func TestNewUnsupportedDriver(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "oracle",
		DSN:    ":memory:",
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
	if !strings.Contains(err.Error(), "unsupported database driver") {
		t.Errorf("expected unsupported driver error, got: %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}
	db, err := New(cfg)
	if err != nil {
		t.Fatalf("first New failed: %v", err)
	}
	defer db.Close()

	// Verify migration tracking table has recorded all migrations
	var migrationCount int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("failed to query schema_migrations: %v", err)
	}
	expected := len(db.dialect.Migrations())
	if migrationCount != expected {
		t.Errorf("expected %d recorded migrations, got %d", expected, migrationCount)
	}

	// Running migrate again should succeed and not re-apply anything
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}

	// Verify count hasn't changed
	var afterCount int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&afterCount); err != nil {
		t.Fatalf("failed to query schema_migrations: %v", err)
	}
	if afterCount != migrationCount {
		t.Errorf("migration count changed after re-run: %d -> %d", migrationCount, afterCount)
	}
}

func TestMigrate_UpgradeDetection(t *testing.T) {
	// Simulate an existing database (pre-migration-tracking) by creating tables
	// directly and then calling migrate() with the new code.
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}

	dialect := &sqliteDialect{}
	dsn := dialect.DSN(cfg.DSN)
	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	// Create the baseline tables manually (as if from old migration code)
	baseline := []string{
		`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'user', enabled INTEGER NOT NULL DEFAULT 1, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, value TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, zone_id TEXT, action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL)`,
	}
	for _, m := range baseline {
		if _, err := conn.Exec(m); err != nil {
			t.Fatalf("create baseline: %v", err)
		}
	}

	// Wrap the raw conn in our DB type (bypassing New to avoid auto-migrate)
	db := &DB{
		Conn:    conn,
		dialect: dialect,
	}

	// This should detect the existing database and pre-fill schema_migrations
	if err := db.migrate(); err != nil {
		t.Fatalf("migrate on existing database failed: %v", err)
	}

	var migrationCount int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("failed to query schema_migrations: %v", err)
	}
	expected := len(dialect.Migrations())
	if migrationCount != expected {
		t.Errorf("expected %d recorded migrations, got %d", expected, migrationCount)
	}

	// Verify all tables exist (should have been created during baseline)
	tables := []string{"users", "settings", "activity_logs", "schema_migrations"}
	for _, table := range tables {
		var name string
		err := db.Conn.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found after upgrade migration: %v", table, err)
		}
	}

	// Calling migrate again should be a no-op
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate on existing database failed: %v", err)
	}
}

func TestClose(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}
	db, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestForeignKeyEnforcement(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}
	db, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	var enabled int
	err = db.Conn.QueryRow("PRAGMA foreign_keys").Scan(&enabled)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Errorf("expected foreign_keys=1, got %d", enabled)
	}
}

func TestIndexUsage(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}
	db, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	queries := []struct {
		name string
		sql  string
	}{
		{
			"api_key lookup",
			"SELECT user_id, expires_at FROM api_keys WHERE key_hash = 'test'",
		},
		{
			"zone activity",
			"SELECT al.id, u.username FROM activity_logs al LEFT JOIN users u ON al.user_id = u.id WHERE al.zone_id = 'test' ORDER BY al.created_at DESC LIMIT 50",
		},
		{
			"dashboard activity",
			"SELECT al.id, u.username FROM activity_logs al LEFT JOIN users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT 20",
		},
		{
			"user lookup by username",
			"SELECT id FROM users WHERE username = 'admin' AND enabled = 1",
		},
	}

	for _, q := range queries {
		t.Run(q.name, func(t *testing.T) {
			rows, err := db.Conn.Query("EXPLAIN QUERY PLAN " + q.sql)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()

			var plan []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}

			foundIndex := false
			for _, d := range plan {
				if strings.Contains(d, "USING INDEX") || strings.Contains(d, "COVERING INDEX") || strings.Contains(d, "USING COVERING INDEX") {
					foundIndex = true
				}
			}
			if !foundIndex {
				t.Errorf("query %q should use an index, plan: %v", q.name, plan)
			}
		})
	}
}

func TestSanitizeDSN_MySQL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"user:password@tcp(localhost:3306)/gozone",
			"user:***@tcp(localhost:3306)/gozone",
		},
		{
			"root:secret@tcp(127.0.0.1:3306)/dbname?parseTime=true&multiStatements=true",
			"root:***@tcp(127.0.0.1:3306)/dbname?parseTime=true&multiStatements=true",
		},
		{
			"admin:p@ss:w0rd@tcp(host)/mydb",
			"admin:***@tcp(host)/mydb",
		},
	}

	for _, tt := range tests {
		got := sanitizeDSN(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeDSN(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSanitizeDSN_PostgreSQL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"host=localhost port=5432 user=gozone password=secret dbname=gozone sslmode=disable",
			"host=localhost port=5432 user=gozone password=*** dbname=gozone sslmode=disable",
		},
		{
			"host=db.example.com user=admin password=changeme dbname=prod",
			"host=db.example.com user=admin password=*** dbname=prod",
		},
		{
			"user=app password=very-secret-pwd! database=mydb",
			"user=app password=*** database=mydb",
		},
	}

	for _, tt := range tests {
		got := sanitizeDSN(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeDSN(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSanitizeDSN_SQLite(t *testing.T) {
	tests := []string{
		"./data/gozone.db",
		":memory:",
		"/var/lib/gozone/data.db",
	}

	for _, input := range tests {
		got := sanitizeDSN(input)
		if got != input {
			t.Errorf("sanitizeDSN(%q) = %q, want unchanged", input, got)
		}
	}
}

func TestSanitizeDSN_NoCredentials(t *testing.T) {
	got := sanitizeDSN("host@tcp(localhost)/db")
	if got != "host@tcp(localhost)/db" {
		t.Errorf("DSN without password should remain unchanged: got %q", got)
	}

	got = sanitizeDSN("user=admin host=localhost dbname=prod")
	if got != "user=admin host=localhost dbname=prod" {
		t.Errorf("Postgres DSN without password should remain unchanged: got %q", got)
	}
}

func TestMigrationVersion_Stability(t *testing.T) {
	v1 := migrationVersion("CREATE TABLE t (id INTEGER)")
	v2 := migrationVersion("CREATE TABLE t (id INTEGER)")
	if v1 != v2 {
		t.Errorf("migrationVersion should be stable: %q vs %q", v1, v2)
	}
	if v1 == migrationVersion("CREATE TABLE t (id TEXT)") {
		t.Error("different SQL should produce different versions")
	}
}

func TestMigrate_ReorderSafe(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}
	dialect := &sqliteDialect{}
	dsn := dialect.DSN(cfg.DSN)
	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	db := &DB{Conn: conn, dialect: dialect}
	if err := db.migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var countAfterFirst int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&countAfterFirst); err != nil {
		t.Fatalf("count: %v", err)
	}

	// Simulate slice reordering by creating a new dialect whose Migrations()
	// returns a copy of the original slice in reverse order. The content-based
	// version identifiers must remain stable, so no new migrations run.
	reversed := &reversedSQLiteDialect{sqliteDialect{}}
	db2 := &DB{Conn: conn, dialect: reversed}
	if err := db2.migrate(); err != nil {
		t.Fatalf("migrate after reorder: %v", err)
	}

	var countAfterReorder int
	if err := db2.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&countAfterReorder); err != nil {
		t.Fatalf("count after reorder: %v", err)
	}
	if countAfterReorder != countAfterFirst {
		t.Errorf("reordering migrations changed count: %d -> %d", countAfterFirst, countAfterReorder)
	}
}

func TestMigrate_LegacyVersionsMigrated(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}
	dialect := &sqliteDialect{}
	dsn := dialect.DSN(cfg.DSN)
	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	// Simulate a database where the first three table-creating migrations were
	// applied under the old index-based scheme. Execute the actual migration SQL
	// so the schema matches what the versions claim.
	migrations := dialect.Migrations()
	for i := 0; i < 3 && i < len(migrations); i++ {
		if _, err := conn.Exec(migrations[i]); err != nil {
			t.Fatalf("apply baseline migration %d: %v", i, err)
		}
	}

	// Create tracking table with legacy index-based versions.
	if _, err := conn.Exec(`CREATE TABLE schema_migrations (version VARCHAR(255) PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, v := range []string{"v000", "v001", "v002"} {
		if _, err := conn.Exec("INSERT INTO schema_migrations (version) VALUES (?)", v); err != nil {
			t.Fatalf("insert legacy %s: %v", v, err)
		}
	}

	db := &DB{Conn: conn, dialect: dialect}
	if err := db.migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	rows, err := db.Conn.Query("SELECT version FROM schema_migrations")
	if err != nil {
		t.Fatalf("query versions: %v", err)
	}
	defer rows.Close()

	var legacyCount int
	var hashCount int
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if oldVersionRegex.MatchString(v) {
			legacyCount++
		}
		if strings.HasPrefix(v, "mig_") {
			hashCount++
		}
	}
	if legacyCount != 0 {
		t.Errorf("expected no legacy versions remaining, got %d", legacyCount)
	}
	expected := len(dialect.Migrations())
	if hashCount != expected {
		t.Errorf("expected %d hash versions, got %d", expected, hashCount)
	}
}

// reversedSQLiteDialect returns migrations in reverse order to test that
// content-based versioning survives slice reordering.
type reversedSQLiteDialect struct {
	sqliteDialect
}

func (r *reversedSQLiteDialect) Migrations() []string {
	orig := r.sqliteDialect.Migrations()
	rev := make([]string, len(orig))
	for i := range orig {
		rev[len(orig)-1-i] = orig[i]
	}
	return rev
}

type spyDialect struct {
	sqliteDialect
	rebinds []string
}

func (d *spyDialect) Rebind(query string) string {
	d.rebinds = append(d.rebinds, query)
	return query
}

func TestTx_Rebind(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	}

	dialect := &spyDialect{}
	conn, err := sql.Open("sqlite3", cfg.DSN)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	db := &DB{Conn: conn, dialect: dialect}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if _, err := tx.Exec("INSERT INTO t (name) VALUES (?)", "a"); err != nil {
		t.Fatalf("exec insert: %v", err)
	}

	rows, err := tx.Query("SELECT id, name FROM t WHERE name = ?", "a")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var found bool
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "a" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find row via tx.Query")
	}

	var id int
	var name string
	if err := tx.QueryRow("SELECT id, name FROM t WHERE name = ?", "a").Scan(&id, &name); err != nil {
		t.Fatalf("query row: %v", err)
	}
	if name != "a" {
		t.Errorf("expected name a, got %q", name)
	}

	expected := []string{
		"CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)",
		"INSERT INTO t (name) VALUES (?)",
		"SELECT id, name FROM t WHERE name = ?",
		"SELECT id, name FROM t WHERE name = ?",
	}
	if len(dialect.rebinds) != len(expected) {
		t.Fatalf("expected %d Rebind calls, got %d", len(expected), len(dialect.rebinds))
	}
	for i, want := range expected {
		if dialect.rebinds[i] != want {
			t.Errorf("rebind call %d: expected %q, got %q", i, want, dialect.rebinds[i])
		}
	}
}

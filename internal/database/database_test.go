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

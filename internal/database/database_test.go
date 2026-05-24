package database

import (
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
	tables := []string{"users", "settings", "activity_logs", "api_keys"}
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
		Driver: "postgres",
		DSN:    ":memory:",
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported driver")
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

	// Running migrate again should succeed
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate failed: %v", err)
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

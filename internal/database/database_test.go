package database

import (
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

	// Running migrate again should succeed
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}
	db.Close()
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

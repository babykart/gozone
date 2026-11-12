package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/config"
)

// Tests for the configurable connection pool size (DatabaseConfig.MaxOpenConns).
//
// Contract under test:
//   - The effective pool size is resolved ONCE inside newWithOpener: the
//     config value when > 0, otherwise the dialect default (25 for
//     mysql/postgres), and applied to BOTH pools — the application pool
//     (DB.Conn) and the per-zone advisory-lock pool (DB.zoneLockPool).
//   - SQLite stays pinned to its dialect value (1) regardless of the config
//     value: the single-connection pool is a documented correctness design,
//     so newWithOpener honours it defensively even when a config bypasses
//     Load's validation.
//
// The mysql-dialect cases run through NewWithoutMigrationsWithOpener over the
// shared countingConnector: with migrations skipped, startup performs only
// the ping, so the ping-capable fake needs no query emulation.

func openPoolSizeDB(t *testing.T, cfg *config.DatabaseConfig) *DB {
	t.Helper()
	db, err := NewWithoutMigrationsWithOpener(cfg, func(string, string) (*sql.DB, error) {
		return sql.OpenDB(&countingConnector{}), nil
	})
	if err != nil {
		t.Fatalf("NewWithoutMigrationsWithOpener: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewWithOpener_MaxOpenConnsAppliedToBothPools(t *testing.T) {
	db := openPoolSizeDB(t, &config.DatabaseConfig{
		Driver:       "mysql",
		DSN:          "user:pass@tcp(127.0.0.1:3306)/gozone",
		MaxOpenConns: 7,
	})

	if got := db.Conn.Stats().MaxOpenConnections; got != 7 {
		t.Errorf("application pool MaxOpenConnections = %d, want 7 (config override)", got)
	}
	if db.zoneLockPool == nil {
		t.Fatal("zoneLockPool must exist for network dialects")
	}
	if got := db.zoneLockPool.Stats().MaxOpenConnections; got != 7 {
		t.Errorf("zone-lock pool MaxOpenConnections = %d, want 7 (same effective size as the app pool)", got)
	}
}

func TestNewWithOpener_MaxOpenConnsDialectDefault(t *testing.T) {
	db := openPoolSizeDB(t, &config.DatabaseConfig{
		Driver: "mysql",
		DSN:    "user:pass@tcp(127.0.0.1:3306)/gozone",
		// MaxOpenConns 0 (default) = dialect default.
	})

	if got := db.Conn.Stats().MaxOpenConnections; got != 25 {
		t.Errorf("application pool MaxOpenConnections = %d, want 25 (mysql dialect default)", got)
	}
	if db.zoneLockPool == nil {
		t.Fatal("zoneLockPool must exist for network dialects")
	}
	if got := db.zoneLockPool.Stats().MaxOpenConnections; got != 25 {
		t.Errorf("zone-lock pool MaxOpenConnections = %d, want 25 (mysql dialect default)", got)
	}
}

func TestNew_SQLiteMaxOpenConnsStaysPinnedToOne(t *testing.T) {
	// Defensive guard: even if a config bypasses Load's validation, the
	// sqlite path must keep the dialect's single-connection pool.
	db, err := New(&config.DatabaseConfig{
		Driver:       "sqlite3",
		DSN:          filepath.Join(t.TempDir(), "pool.db"),
		MaxOpenConns: 9,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if got := db.Conn.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("sqlite pool MaxOpenConnections = %d, want 1 (dialect value wins over config)", got)
	}
	if db.zoneLockPool != nil {
		t.Error("sqlite must not create a zone-lock pool")
	}
}

// TestNewWithoutMigrations_DoesNotRunMigrations pins the seam the `gozone
// user` emergency commands rely on: the constructor performs the full startup
// flow (dialect selection, DSN rewrite, pool tuning, ping) but leaves the
// schema untouched — a newer emergency binary must not silently migrate a
// database deployed from another version.
func TestNewWithoutMigrations_DoesNotRunMigrations(t *testing.T) {
	db, err := NewWithoutMigrations(&config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    filepath.Join(t.TempDir(), "nomigrate.db"),
	})
	if err != nil {
		t.Fatalf("NewWithoutMigrations: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM schema_migrations").Scan(new(int64)); err == nil ||
		!strings.Contains(err.Error(), "no such table") {
		t.Errorf("expected a no-such-table error on a non-migrated database, got: %v", err)
	}
}

package config

import (
	"strings"
	"testing"
)

// Tests for the configurable database connection pool size
// (database.max_open_conns / GOZONE_DB_MAX_OPEN_CONNS).
//
// Semantics under test:
//   - 0 (default) means "dialect default" — the field stays 0 in the loaded
//     config and internal/database resolves the dialect value at open time.
//   - A negative value is meaningless and must fail Load with an error
//     naming the database.max_open_conns key.
//   - SQLite's single-connection pool is a documented correctness design,
//     so a non-zero value together with the sqlite3 driver must fail Load;
//     an explicit 0 remains valid.

func TestLoad_DatabaseMaxOpenConns_Default(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Database.MaxOpenConns != 0 {
		t.Errorf("expected default database.max_open_conns 0 (dialect default), got %d", cfg.Database.MaxOpenConns)
	}
}

func TestLoad_DatabaseMaxOpenConns_YAML(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, `
database:
  driver: mysql
  dsn: "user:pass@tcp(127.0.0.1:3306)/gozone"
  max_open_conns: 40
`))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Database.MaxOpenConns != 40 {
		t.Errorf("expected database.max_open_conns 40, got %d", cfg.Database.MaxOpenConns)
	}
}

func TestLoad_DatabaseMaxOpenConns_EnvOverride(t *testing.T) {
	t.Setenv("GOZONE_DB_MAX_OPEN_CONNS", "40")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Database.MaxOpenConns != 40 {
		t.Errorf("expected GOZONE_DB_MAX_OPEN_CONNS to override to 40, got %d", cfg.Database.MaxOpenConns)
	}
}

func TestLoad_DatabaseMaxOpenConns_RejectsNegative(t *testing.T) {
	tests := []struct {
		name string
		load func(t *testing.T) error
	}{
		{
			name: "yaml negative",
			load: func(t *testing.T) error {
				t.Helper()
				_, err := Load(writeTempConfig(t, `
database:
  driver: mysql
  dsn: "user:pass@tcp(127.0.0.1:3306)/gozone"
  max_open_conns: -5
`))
				return err
			},
		},
		{
			name: "env negative",
			load: func(t *testing.T) error {
				t.Helper()
				t.Setenv("GOZONE_DB_MAX_OPEN_CONNS", "-5")
				_, err := Load("")
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.load(t)
			if err == nil {
				t.Fatal("expected a negative database.max_open_conns to fail Load")
			}
			if !strings.Contains(err.Error(), "database.max_open_conns") {
				t.Errorf("error must name the database.max_open_conns key, got: %v", err)
			}
		})
	}
}

func TestLoad_DatabaseMaxOpenConns_RejectsNonZeroWithSQLite(t *testing.T) {
	_, err := Load(writeTempConfig(t, `
database:
  driver: sqlite3
  dsn: "/tmp/gozone.db"
  max_open_conns: 10
`))
	if err == nil {
		t.Fatal("expected a non-zero database.max_open_conns with the sqlite3 driver to fail Load")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "max_open_conns") {
		t.Errorf("error must name the max_open_conns key, got: %v", err)
	}
	if !strings.Contains(msg, "sqlite") {
		t.Errorf("error must name the sqlite driver, got: %v", err)
	}
}

func TestLoad_DatabaseMaxOpenConns_ZeroWithSQLiteValid(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, `
database:
  driver: sqlite3
  dsn: "/tmp/gozone.db"
  max_open_conns: 0
`))
	if err != nil {
		t.Fatalf("explicit database.max_open_conns 0 with sqlite3 must stay valid: %v", err)
	}
	if cfg.Database.MaxOpenConns != 0 {
		t.Errorf("expected database.max_open_conns 0, got %d", cfg.Database.MaxOpenConns)
	}
}

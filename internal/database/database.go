// Package database manages the SQLite database connection and schema migrations
// for GoZone. It handles DSN validation, directory creation, and automatic table
// initialization on first connection.
package database

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/constants"
)

// DB wraps the sql.DB connection pool.
type DB struct {
	Conn *sql.DB
}

// New opens a SQLite database connection and runs migrations.
//
// It validates the DSN, ensures the parent directory exists, and appends
// WAL journal mode and foreign key enforcement parameters automatically.
// In-memory databases (":memory:") are supported for testing.
// SQLite connections are capped at 1 to serialize concurrent writes.
//
// Parameters:
//   - cfg: database configuration containing driver name and DSN
//
// Returns a ready-to-use DB handle or an error if connection or migration fails.
func New(cfg *config.DatabaseConfig) (*DB, error) {
	if cfg.Driver != "sqlite3" {
		return nil, fmt.Errorf("unsupported database driver: %s (only sqlite3 is supported)", cfg.Driver)
	}

	// Ensure the directory exists
	dir := filepath.Dir(cfg.DSN)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	// Safely append parameters to the DSN
	var finalDSN string
	if cfg.DSN == ":memory:" {
		// Special case for in-memory database
		finalDSN = ":memory:?_journal_mode=WAL&_foreign_keys=on"
	} else {
		// Parse the DSN as a URL
		u, err := url.Parse(cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DSN '%s': %w", cfg.DSN, err)
		}

		queryParams := u.Query()
		queryParams.Set("_journal_mode", "WAL")
		queryParams.Set("_foreign_keys", "on")
		u.RawQuery = queryParams.Encode()

		finalDSN = u.String()
	}

	conn, err := sql.Open("sqlite3", finalDSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(constants.MaxOpenConns) // SQLite serializes writes

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	db := &DB{Conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	log.Println("[db] connected to SQLite database:", cfg.DSN)
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.Conn.Close()
}

// migrate creates the initial schema.
func (db *DB) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			first_name TEXT NOT NULL DEFAULT '',
			last_name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT 'user',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL UNIQUE,
			value TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			zone_id TEXT,
			action TEXT NOT NULL,
			details TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			last_used_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_zone_id ON activity_logs(zone_id)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)`,
	}

	for _, m := range migrations {
		if _, err := db.Conn.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	log.Println("[db] migrations completed successfully")
	return nil
}

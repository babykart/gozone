// Package database manages database connections and schema migrations for
// GoZone. It supports SQLite (default), MySQL/MariaDB, and PostgreSQL through
// a driver abstraction layer that handles dialect-specific SQL generation.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/logger"

	_ "github.com/mattn/go-sqlite3"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// DB wraps the sql.DB connection pool with dialect-aware query rebinding.
type DB struct {
	Conn    *sql.DB
	dialect Dialect
}

// New opens a database connection and runs migrations.
//
// Supported drivers:
//   - "sqlite3" (default, local file or ":memory:")
//   - "mysql" / "mariadb"
//   - "postgres" / "postgresql"
//
// Parameters:
//   - cfg: database configuration containing driver name and DSN
//
// Returns a ready-to-use DB handle or an error if connection or migration fails.
func New(cfg *config.DatabaseConfig) (*DB, error) {
	dialect, err := selectDialect(cfg.Driver)
	if err != nil {
		return nil, err
	}

	if cfg.Driver == "sqlite3" {
		dir := filepath.Dir(cfg.DSN)
		if dir != "." {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return nil, fmt.Errorf("create database directory: %w", err)
			}
		}
	}

	dsn := dialect.DSN(cfg.DSN)
	conn, err := sql.Open(dialect.DriverName(), dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(dialect.MaxOpenConns())

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	db := &DB{Conn: conn, dialect: dialect}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	logger.Info("connected to database", "driver", cfg.Driver, "dsn", cfg.DSN)
	return db, nil
}

// Exec executes a query with automatic placeholder rebinding.
func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.Conn.Exec(db.dialect.Rebind(query), args...)
}

// Query executes a query that returns rows with automatic placeholder rebinding.
func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.Conn.Query(db.dialect.Rebind(query), args...)
}

// QueryRow executes a query that returns at most one row with automatic
// placeholder rebinding.
func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	return db.Conn.QueryRow(db.dialect.Rebind(query), args...)
}

// Ping verifies a connection to the database.
func (db *DB) Ping() error {
	return db.Conn.Ping()
}

// Close closes the database connection pool.
func (db *DB) Close() error {
	return db.Conn.Close()
}

// Begin starts a transaction with automatic placeholder rebinding.
func (db *DB) Begin() (*Tx, error) {
	tx, err := db.Conn.Begin()
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx, dialect: db.dialect}, nil
}

// Tx wraps a database transaction with automatic placeholder rebinding.
type Tx struct {
	*sql.Tx
	dialect Dialect
}

// Exec executes a query within the transaction with automatic placeholder
// rebinding.
func (tx *Tx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.Tx.Exec(tx.dialect.Rebind(query), args...)
}

// migrate creates the initial schema using dialect-specific SQL.
func (db *DB) migrate() error {
	for _, m := range db.dialect.Migrations() {
		if _, err := db.Conn.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}
	logger.Info("migrations completed")
	return nil
}

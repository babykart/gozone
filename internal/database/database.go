// Package database manages database connections and schema migrations for
// GoZone. It supports SQLite (default), MySQL/MariaDB, and PostgreSQL through
// a driver abstraction layer that handles dialect-specific SQL generation.
package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

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

	logger.Info("connected to database", "driver", cfg.Driver, "dsn", sanitizeDSN(cfg.DSN))
	return db, nil
}

// Exec executes a query with automatic placeholder rebinding.
func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.ExecContext(context.Background(), query, args...)
}

// ExecContext executes a query with automatic placeholder rebinding and
// supports cancellation through the provided context.
func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.Conn.ExecContext(ctx, db.dialect.Rebind(query), args...)
}

// Query executes a query that returns rows with automatic placeholder rebinding.
func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.QueryContext(context.Background(), query, args...)
}

// QueryContext executes a query that returns rows with automatic placeholder
// rebinding and supports cancellation through the provided context.
func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return db.Conn.QueryContext(ctx, db.dialect.Rebind(query), args...)
}

// QueryRow executes a query that returns at most one row with automatic
// placeholder rebinding.
func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	return db.QueryRowContext(context.Background(), query, args...)
}

// QueryRowContext executes a query that returns at most one row with automatic
// placeholder rebinding and supports cancellation through the provided context.
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return db.Conn.QueryRowContext(ctx, db.dialect.Rebind(query), args...)
}

// Ping verifies a connection to the database.
func (db *DB) Ping() error {
	return db.Conn.Ping()
}

// Close closes the database connection pool.
func (db *DB) Close() error {
	return db.Conn.Close()
}

// RevokeToken records a JWT ID (jti) in the revocation list so that the
// corresponding token can no longer be used, even if it has not expired.
func (db *DB) RevokeToken(ctx context.Context, jti string, userID int64, expiresAt time.Time) error {
	_, err := db.ExecContext(ctx,
		"INSERT INTO revoked_tokens (jti, user_id, expires_at) VALUES (?, ?, ?) ON CONFLICT(jti) DO NOTHING",
		jti, userID, expiresAt,
	)
	return err
}

// IsTokenRevoked reports whether the given JWT ID has been revoked.
func (db *DB) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?",
		jti,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CleanupRevokedTokens removes revocation entries that have already expired,
// preventing the table from growing indefinitely.
func (db *DB) CleanupRevokedTokens(ctx context.Context) error {
	_, err := db.ExecContext(ctx,
		"DELETE FROM revoked_tokens WHERE expires_at <= ?",
		time.Now(),
	)
	return err
}

// PurgeActivityLogs deletes activity log entries older than the configured
// retention period. The operation is executed in batches of batchSize rows to
// avoid locking the database on large purges. A retentionDays value of zero
// keeps all logs and returns 0 deleted rows without running any query.
func (db *DB) PurgeActivityLogs(ctx context.Context, retentionDays, batchSize int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	if batchSize <= 0 {
		batchSize = 1000
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	const query = `DELETE FROM activity_logs
	WHERE id IN (
		SELECT id FROM (
			SELECT id FROM activity_logs
			WHERE created_at < ?
			ORDER BY id
			LIMIT ?
		) AS _batch
	)`

	var totalDeleted int64
	for {
		res, err := db.ExecContext(ctx, query, cutoff, batchSize)
		if err != nil {
			return totalDeleted, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return totalDeleted, err
		}
		totalDeleted += n
		if n < int64(batchSize) {
			break
		}
		if err := ctx.Err(); err != nil {
			return totalDeleted, err
		}
	}
	return totalDeleted, nil
}

// Begin starts a transaction with automatic placeholder rebinding.
func (db *DB) Begin() (*Tx, error) {
	return db.BeginTx(context.Background(), nil)
}

// BeginTx starts a transaction with automatic placeholder rebinding and the
// given transaction options. The context is used until the transaction is
// committed or rolled back.
func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := db.Conn.BeginTx(ctx, opts)
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
	return tx.ExecContext(context.Background(), query, args...)
}

// ExecContext executes a query within the transaction with automatic placeholder
// rebinding and supports cancellation through the provided context.
func (tx *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return tx.Tx.ExecContext(ctx, tx.dialect.Rebind(query), args...)
}

// Query executes a query within the transaction that returns rows with
// automatic placeholder rebinding.
func (tx *Tx) Query(query string, args ...any) (*sql.Rows, error) {
	return tx.QueryContext(context.Background(), query, args...)
}

// QueryContext executes a query within the transaction that returns rows with
// automatic placeholder rebinding and supports cancellation through the
// provided context.
func (tx *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return tx.Tx.QueryContext(ctx, tx.dialect.Rebind(query), args...)
}

// QueryRow executes a query within the transaction that returns at most one
// row with automatic placeholder rebinding.
func (tx *Tx) QueryRow(query string, args ...any) *sql.Row {
	return tx.QueryRowContext(context.Background(), query, args...)
}

// QueryRowContext executes a query within the transaction that returns at most
// one row with automatic placeholder rebinding and supports cancellation
// through the provided context.
func (tx *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return tx.Tx.QueryRowContext(ctx, tx.dialect.Rebind(query), args...)
}

// migrationVersion returns a stable identifier for a migration based on the
// SHA-256 hash of its SQL content. Using a content hash instead of a slice
// index means reordering or renaming the migrations slice does not corrupt
// the applied-migration tracking table.
func migrationVersion(sql string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(sql)))
	return "mig_" + hex.EncodeToString(h[:])[:16]
}

var oldVersionRegex = regexp.MustCompile(`^v(\d{3})$`)

// migrate creates the initial schema using dialect-specific SQL.
// It tracks applied migrations in the schema_migrations table to ensure
// idempotent execution across restarts. Migrations are identified by a
// content hash so that reordering the migrations slice does not corrupt
// tracking. A dialect-specific cluster-wide lock prevents multiple instances
// from running migrations concurrently.
func (db *DB) migrate() error {
	release, err := db.dialect.LockMigrations(db.Conn)
	if err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer release()

	// Create the migration tracking table first (safe across all dialects)
	if _, err := db.Conn.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	// Migrate any old vNNN version identifiers to content hashes. This only
	// happens once when upgrading from the index-based versioning scheme.
	if err := db.migrateOldVersions(); err != nil {
		return fmt.Errorf("migrate old version identifiers: %w", err)
	}

	// Detect upgrade from pre-migration-tracking version: if schema_migrations
	// is empty but tables already exist, mark all current migrations as applied
	// so they are not re-executed.
	var recorded int
	if err := db.Conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&recorded); err != nil {
		return fmt.Errorf("check migration count: %w", err)
	}
	if recorded == 0 {
		var exists int
		if err := db.Conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&exists); err == nil && exists > 0 {
			for _, m := range db.dialect.Migrations() {
				version := migrationVersion(m)
				if _, err := db.Conn.Exec(db.dialect.Rebind("INSERT INTO schema_migrations (version) VALUES (?)"), version); err != nil {
					return fmt.Errorf("record migration %s: %w", version, err)
				}
			}
			logger.Info("existing database detected, marking all migrations as applied")
			return nil
		}
	}

	for _, m := range db.dialect.Migrations() {
		version := migrationVersion(m)

		var applied int
		if err := db.Conn.QueryRow(db.dialect.Rebind("SELECT COUNT(*) FROM schema_migrations WHERE version = ?"), version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied > 0 {
			continue
		}

		if _, err := db.Conn.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}

		if _, err := db.Conn.Exec(db.dialect.Rebind("INSERT INTO schema_migrations (version) VALUES (?)"), version); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}

		logger.Info("applied migration", "version", version)
	}
	logger.Info("migrations completed")
	return nil
}

// migrateOldVersions converts legacy vNNN version identifiers stored in
// schema_migrations to content-based hashes. This preserves tracking when
// upgrading from the previous index-based scheme.
func (db *DB) migrateOldVersions() error {
	rows, err := db.Conn.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("list existing versions: %w", err)
	}
	defer rows.Close()

	migrations := db.dialect.Migrations()
	var toUpdate []struct{ old, new string }
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("scan version: %w", err)
		}
		matches := oldVersionRegex.FindStringSubmatch(version)
		if matches == nil {
			continue
		}
		idx, err := strconv.Atoi(matches[1])
		if err != nil || idx < 0 || idx >= len(migrations) {
			continue
		}
		toUpdate = append(toUpdate, struct{ old, new string }{version, migrationVersion(migrations[idx])})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate versions: %w", err)
	}

	for _, u := range toUpdate {
		if _, err := db.Conn.Exec(
			db.dialect.Rebind("UPDATE schema_migrations SET version = ? WHERE version = ?"),
			u.new, u.old,
		); err != nil {
			return fmt.Errorf("update version %s -> %s: %w", u.old, u.new, err)
		}
		logger.Info("migrated legacy migration version", "old", u.old, "new", u.new)
	}
	return nil
}

// sanitizeDSN redacts passwords from database connection strings for safe
// logging. It handles MySQL-style (user:password@tcp(...)), PostgreSQL
// (password=secret), and SQLite (file path) DSN formats.
func sanitizeDSN(dsn string) string {
	// MySQL-style: user:password@tcp(host)/db
	sep := "@tcp("
	if idx := strings.Index(dsn, sep); idx >= 0 {
		prefix := dsn[:idx]
		if colon := strings.Index(prefix, ":"); colon >= 0 {
			return prefix[:colon+1] + "***" + dsn[idx:]
		}
		return dsn
	}
	// PostgreSQL-style: password=secret
	re := regexp.MustCompile(`password=[^ ]+`)
	if re.MatchString(dsn) {
		return re.ReplaceAllString(dsn, "password=***")
	}
	// SQLite: file path, no credentials
	return dsn
}

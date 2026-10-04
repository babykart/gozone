// Package database manages database connections and schema migrations for
// GoZone. It supports SQLite (default), MySQL/MariaDB, and PostgreSQL through
// a driver abstraction layer that handles dialect-specific SQL generation.
package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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

// ErrUniqueViolation is the sentinel error wrapping any driver-level
// UNIQUE-constraint violation returned by DB.ExecContext / Tx.ExecContext
// (the code paths that run INSERT/UPDATE/DELETE statements where such
// violations arise). Handlers can detect it idiomatically with
// errors.Is(err, database.ErrUniqueViolation) instead of pattern-matching
// driver-specific error text ("UNIQUE constraint failed", "Duplicate entry",
// "duplicate key value violates unique constraint").
//
// The wrapping uses fmt.Errorf("%w: %w", ErrUniqueViolation, err) so that
// errors.As against the underlying typed driver error (e.g. *mysql.MySQLError,
// *pq.Error) still traverses the chain, preserving existing call sites that
// surface the driver error to logs or typed branches.
var ErrUniqueViolation = errors.New("unique constraint violation")

// wrapUniqueViolation returns an error that wraps both ErrUniqueViolation and
// the original driver error when the active dialect classifies the latter as
// a UNIQUE-constraint violation. Returns nil for a nil err and returns err
// unchanged when the dialect does not match — so non-unique errors
// (constraint-check, deadlock, connection-lost, ...) keep their original
// identity. Used by the DB / Tx ExecContext wrappers.
func wrapUniqueViolation(d Dialect, err error) error {
	if err == nil {
		return nil
	}
	if d.IsUniqueViolation(err) {
		return fmt.Errorf("%w: %w", ErrUniqueViolation, err)
	}
	return err
}

// isNoRows reports whether err is (or wraps) sql.ErrNoRows. Using errors.Is
// instead of a direct == comparison keeps the check correct when a driver or
// an intermediate wrapper layers an error around sql.ErrNoRows.
func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

// IsUniqueViolation reports whether err is (or wraps) a driver-level
// UNIQUE-constraint violation according to the active dialect. Convenience
// helper for callers that hold a *DB and prefer a boolean check; equivalent
// to errors.Is(err, database.ErrUniqueViolation) for errors returned by
// DB.Exec / DB.ExecContext / Tx equivalents, but also classifies raw driver
// errors that have not been wrapped (e.g. obtained via *sql.Row.Scan).
func (db *DB) IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrUniqueViolation) {
		return true
	}
	return db.dialect.IsUniqueViolation(err)
}

// openFunc opens a *sql.DB for the given driver name and DSN. It is the
// injection seam that lets tests substitute a counting connector and assert
// that New's failure paths close the pool.
type openFunc func(driverName, dsn string) (*sql.DB, error)

// New opens a database connection and runs the schema migrations.
//
// Supported drivers:
//   - "sqlite3" (default, local file or ":memory:")
//   - "mysql" / "mariadb"
//   - "postgres" / "postgresql"
//
// Parameters:
//   - cfg: database configuration containing driver name and DSN
//
// Returns a ready-to-use DB handle or an error if connection or migration
// fails. On failure the pool is closed: leaking it would keep the SQLite
// sweep goroutines and any pinned migration-lock connection alive for the
// process lifetime, compounding on callers that retry New.
func New(cfg *config.DatabaseConfig) (*DB, error) {
	return newWithOpener(cfg, sql.Open)
}

func newWithOpener(cfg *config.DatabaseConfig, open openFunc) (*DB, error) {
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
	conn, err := open(dialect.DriverName(), dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(dialect.MaxOpenConns())
	conn.SetMaxIdleConns(dialect.MaxIdleConns())
	conn.SetConnMaxLifetime(dialect.ConnMaxLifetime())

	// From here on conn is open: every failure path must close it, or the
	// pool (and its background machinery — the SQLite sweep goroutines, the
	// pinned migration-lock connection) leaks for the lifetime of the
	// process. Callers retrying New in a loop would compound the leak.
	if err := conn.Ping(); err != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on error path
		return nil, fmt.Errorf("ping database: %w", err)
	}

	db := &DB{Conn: conn, dialect: dialect}
	if err := db.migrate(); err != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on error path
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
// supports cancellation through the provided context. A driver-level
// UNIQUE-constraint violation is wrapped so callers can detect it with
// errors.Is(err, database.ErrUniqueViolation).
func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	res, err := db.Conn.ExecContext(ctx, db.dialect.Rebind(query), args...)
	return res, wrapUniqueViolation(db.dialect, err)
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

// InsertIgnore inserts a row into table, silently skipping rows that would
// violate a unique constraint. The exact SQL syntax is chosen by the active
// dialect so it works on SQLite, MySQL/MariaDB and PostgreSQL.
//
// columns lists the INSERT column list and the bound parameter order.
// conflictColumns lists the columns that form the conflict target —
// typically the columns covered by a PRIMARY KEY or UNIQUE constraint on
// the table. For PostgreSQL this MUST match an existing unique index; for
// SQLite and MySQL the value is ignored because INSERT OR IGNORE / INSERT
// IGNORE catch any unique violation. Passing the columns and the conflict
// target separately removes the implicit "all columns form the unique
// constraint" assumption that the older signature relied on.
func (db *DB) InsertIgnore(ctx context.Context, table string, columns, conflictColumns []string, values ...any) (sql.Result, error) {
	query := db.dialect.InsertIgnore(table, columns, conflictColumns)
	return db.ExecContext(ctx, query, values...)
}

// ExecReturnID executes an INSERT statement and returns the auto-generated
// primary key of the inserted row. It abstracts the dialect difference that
// made raw result.LastInsertId() non-portable:
//
//   - On dialects supporting INSERT ... RETURNING (PostgreSQL, SQLite) the
//     clause " RETURNING id" is appended and the id is read back via
//     QueryRowContext. PostgreSQL's lib/pq does not implement
//     sql.Result.LastInsertId at all, so RETURNING is the only option there;
//     routing SQLite through the same path also exercises it under the
//     in-memory test suite.
//   - On MySQL (Oracle), which has no RETURNING clause, the statement runs via
//     ExecContext and result.LastInsertId() is used (go-sql-driver/mysql
//     supports it).
//
// query must be an INSERT without a trailing semicolon or RETURNING clause;
// every GoZone table uses an integer primary key named "id". A driver-level
// UNIQUE-constraint violation is wrapped in ErrUniqueViolation on both paths
// so callers can keep using errors.Is(err, database.ErrUniqueViolation).
func (db *DB) ExecReturnID(ctx context.Context, query string, args ...any) (int64, error) {
	if db.dialect.SupportsInsertReturning() {
		var id int64
		if err := db.QueryRowContext(ctx, query+" RETURNING id", args...).Scan(&id); err != nil {
			return 0, wrapUniqueViolation(db.dialect, err)
		}
		return id, nil
	}
	res, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read inserted id: %w", err)
	}
	return id, nil
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
// Uses InsertIgnore for dialect-portable conflict handling (SQLite: INSERT
// OR IGNORE, MySQL: INSERT IGNORE, PostgreSQL: ON CONFLICT DO NOTHING).
func (db *DB) RevokeToken(ctx context.Context, jti string, userID int64, expiresAt time.Time) error {
	// Normalize to UTC at this choke point: callers routinely pass JWT exp
	// claims built from time.Unix (local zone). A non-UTC wall time stored in
	// a naive DATETIME/TIMESTAMP column shifts the purge cutoff by the zone
	// offset, which on a negative offset deletes the revocation before the
	// token actually expires and resurrects a logged-out JWT.
	_, err := db.InsertIgnore(ctx,
		"revoked_tokens",
		[]string{"jti", "user_id", "expires_at"},
		[]string{"jti"},
		jti, userID, expiresAt.UTC(),
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
// preventing the table from growing indefinitely. The cutoff uses UTC to match
// how expiries are written (RevokeToken normalizes every expires_at to UTC),
// avoiding a TZ skew that would retain already-expired rows until the local
// clock catches up.
func (db *DB) CleanupRevokedTokens(ctx context.Context) error {
	_, err := db.ExecContext(ctx,
		"DELETE FROM revoked_tokens WHERE expires_at <= ?",
		time.Now().UTC(),
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

// RecordLoginAttempt stores a login attempt in the login_attempts audit table.
// userID may be 0 when the attempted username does not exist. The success flag
// distinguishes successful from failed attempts for forensics.
func (db *DB) RecordLoginAttempt(ctx context.Context, username, ipAddress string, userID int64, success bool) error {
	var uid any
	if userID > 0 {
		uid = userID
	}
	successInt := 0
	if success {
		successInt = 1
	}
	_, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, user_id, ip_address, success) VALUES (?, ?, ?, ?)",
		username, uid, ipAddress, successInt,
	)
	return err
}

// PurgeLoginAttempts removes login attempt rows older than retentionHours.
// Returns the number of deleted rows.
func (db *DB) PurgeLoginAttempts(ctx context.Context, retentionHours int) (int64, error) {
	if retentionHours <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionHours) * time.Hour)
	res, err := db.ExecContext(ctx,
		"DELETE FROM login_attempts WHERE attempted_at < ?",
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// IncrementFailedLoginsInTx is the single source of truth for the atomic
// failed-login increment + conditional lockout. It runs inside the caller's
// transaction: the increment and the lockout are applied as a single atomic
// UPDATE, and the SELECT reading the new count back runs in the same
// transaction, under the row lock held by that UPDATE, so it always sees the
// value this call wrote — removing the read-modify-write race where two
// concurrent failures could each observe a stale count and disagree on whether
// the lockout threshold was reached.
//
// Returns the new failed_login_attempts count and whether a lockout was
// applied (count reached threshold). A caller that needs to override the
// lockout decision (e.g. the last-admin exemption in the login handler) does
// so in the same transaction after this call returns locked=true.
func (tx *Tx) IncrementFailedLoginsInTx(ctx context.Context, userID int64, threshold int, lockFor time.Duration) (count int, locked bool, err error) {
	lockedUntil := time.Now().UTC().Add(lockFor)
	// Atomic increment + conditional lock: the CASE references the pre-update
	// failed_login_attempts, so "failed_login_attempts + 1" is the new count.
	if _, err = tx.ExecContext(ctx, `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1,
		    locked_until = CASE WHEN failed_login_attempts + 1 >= ? THEN ? ELSE locked_until END
		WHERE id = ?`,
		threshold, lockedUntil, userID,
	); err != nil {
		return 0, false, err
	}
	if err = tx.QueryRowContext(ctx,
		"SELECT failed_login_attempts FROM users WHERE id = ?", userID,
	).Scan(&count); err != nil {
		return 0, false, err
	}
	return count, count >= threshold, nil
}

// ResetFailedLogins clears the failed-login counter and every lockout (both
// the automatic brute-force lock and a manual admin lock) when the user
// successfully authenticates. Safe to call when no counter is set.
func (db *DB) ResetFailedLogins(ctx context.Context, userID int64) error {
	_, err := db.ExecContext(ctx,
		"UPDATE users SET failed_login_attempts = 0, locked_until = NULL, manual_lock_until = NULL WHERE id = ?",
		userID,
	)
	return err
}

// UserLockStatus reports whether the user is currently locked and, if so,
// the timestamp at which the lockout expires.
func (db *DB) UserLockStatus(ctx context.Context, userID int64) (locked bool, until time.Time, err error) {
	var rawUntil sql.NullTime
	row := db.QueryRowContext(ctx,
		"SELECT locked_until FROM users WHERE id = ?", userID,
	)
	if err := row.Scan(&rawUntil); err != nil {
		if isNoRows(err) {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, err
	}
	if !rawUntil.Valid {
		return false, time.Time{}, nil
	}
	locked = rawUntil.Time.After(time.Now())
	return locked, rawUntil.Time, nil
}

// AdminLockUser locks the user account for the given duration, resetting the
// failed-login counter so the lockout window starts fresh. Used by the admin
// manual-lock UI; the per-account automatic lockout uses the
// transaction-scoped IncrementFailedLoginsInTx core directly.
//
// A manual lock also revokes every active session by bumping
// tokens_valid_after: an admin who locks an account expects it frozen on all
// devices immediately, not just blocked at the next login. The automatic
// brute-force lockout deliberately does NOT do this,
// so an attacker triggering the threshold cannot kick the legitimate user off
// their other sessions (DoS amplification) — only the manual, admin-initiated
// lock cuts sessions. The user recovers by logging in again once the lock
// expires or is cleared.
//
// Both locked_until and manual_lock_until are set to the same expiry: the
// former keeps the existing locked_until-based display and UserLockStatus
// working unchanged, while the latter is the marker the login path checks
// unconditionally so that a manual lock stays enforced even when
// max_failed_attempts = 0 disables the automatic lockout.
func (db *DB) AdminLockUser(ctx context.Context, userID int64, lockFor time.Duration) error {
	if lockFor <= 0 {
		return fmt.Errorf("lockFor must be positive, got %v", lockFor)
	}
	now := time.Now().UTC()
	lockedUntil := now.Add(lockFor)
	// tokens_valid_after is written from the Go clock (UTC, truncated to the
	// second) instead of the SQL CURRENT_TIMESTAMP: the Auth middleware
	// compares it against JWT iat claims, which are second-granularity. A
	// SQL-side value can carry sub-second precision (PostgreSQL TIMESTAMP
	// keeps microseconds) or a non-UTC session offset (MySQL/PostgreSQL),
	// either of which breaks the cutoff comparison.
	_, err := db.ExecContext(ctx,
		"UPDATE users SET locked_until = ?, manual_lock_until = ?, failed_login_attempts = 0, tokens_valid_after = ? WHERE id = ?",
		lockedUntil, lockedUntil, now.Truncate(time.Second), userID,
	)
	return err
}

// IsManualLock reports whether the account is currently under an admin-imposed
// manual lock (manual_lock_until in the future). Unlike the automatic
// brute-force lockout, a manual lock is enforced at login regardless of the
// max_failed_attempts setting. Returns false (no error) for a missing user.
func (db *DB) IsManualLock(ctx context.Context, userID int64) (bool, error) {
	var manualUntil sql.NullTime
	if err := db.QueryRowContext(ctx,
		"SELECT manual_lock_until FROM users WHERE id = ?", userID,
	).Scan(&manualUntil); err != nil {
		if isNoRows(err) {
			return false, nil
		}
		return false, err
	}
	return manualUntil.Valid && manualUntil.Time.After(time.Now()), nil
}

// AdminUnlockUser clears the lockout and resets the failed-login counter. Safe
// to call when the user is not currently locked.
func (db *DB) AdminUnlockUser(ctx context.Context, userID int64) error {
	return db.ResetFailedLogins(ctx, userID)
}

// Begin starts a transaction with automatic placeholder rebinding.
func (db *DB) Begin() (*Tx, error) {
	return db.BeginTx(context.Background(), nil)
}

// CountEnabledAdmins returns the number of enabled admin users. On MySQL and
// PostgreSQL it appends FOR UPDATE so the count is protected against concurrent
// deletions inside a transaction. SQLite omits the locking clause because its
// single-writer mode (MaxOpenConns=1) already serializes writers.
func (tx *Tx) CountEnabledAdmins(ctx context.Context) (int, error) {
	query := "SELECT id FROM users WHERE role = 'admin' AND enabled = 1"
	if tx.dialect.DriverName() != "sqlite3" {
		query += " FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

// IsLastEnabledAdmin reports whether userID is the only enabled admin in the
// database, with the same FOR UPDATE semantics as CountEnabledAdmins so the
// answer is stable for the lifetime of the calling transaction. Returns
// false if the user does not exist, is not an admin, or is not enabled, or
// if there is at least one other enabled admin. Used by the login lockout
// to refuse to lock the last admin out of the instance.
//
// Lock order: the enabled-admin set is acquired FIRST (via CountEnabledAdmins'
// FOR UPDATE) and the target row second. This matches UpdateUser/DeleteUser/
// BulkDeleteUsers, which all call CountEnabledAdmins before touching their
// target row. Acquiring the target row first and the admin set second (the
// previous order) inverted this and could deadlock against a concurrent
// UpdateUser/DeleteUser when each held one lock and waited on the other.
func (tx *Tx) IsLastEnabledAdmin(ctx context.Context, userID int64) (bool, error) {
	count, err := tx.CountEnabledAdmins(ctx)
	if err != nil {
		return false, err
	}
	query := "SELECT role, enabled FROM users WHERE id = ?"
	if tx.dialect.DriverName() != "sqlite3" {
		query += " FOR UPDATE"
	}
	var role string
	var enabled int
	if err := tx.QueryRowContext(ctx, query, userID).Scan(&role, &enabled); err != nil {
		if isNoRows(err) {
			return false, nil
		}
		return false, err
	}
	if role != "admin" || enabled != 1 {
		return false, nil
	}
	return count <= 1, nil
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
// rebinding and supports cancellation through the provided context. A
// driver-level UNIQUE-constraint violation is wrapped so callers can detect it
// with errors.Is(err, database.ErrUniqueViolation).
func (tx *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	res, err := tx.Tx.ExecContext(ctx, tx.dialect.Rebind(query), args...)
	return res, wrapUniqueViolation(tx.dialect, err)
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

// InsertIgnore runs a dialect-portable INSERT that silently skips a row that
// would violate a unique constraint, executed within the transaction. Mirrors
// DB.InsertIgnore for use inside a Tx (e.g. provisioning an SSO user and
// linking its external identity atomically).
func (tx *Tx) InsertIgnore(ctx context.Context, table string, columns, conflictColumns []string, values ...any) (sql.Result, error) {
	query := tx.dialect.InsertIgnore(table, columns, conflictColumns)
	return tx.ExecContext(ctx, query, values...)
}

// ExecReturnID runs an INSERT inside the transaction and returns the new row's
// auto-generated "id" primary key. It is the transaction-scoped counterpart of
// DB.ExecReturnID and abstracts the same lib/pq vs. LastInsertId portability
// issue. See DB.ExecReturnID for the dialect strategy and the
// query contract (INSERT without RETURNING; integer PK named "id").
func (tx *Tx) ExecReturnID(ctx context.Context, query string, args ...any) (int64, error) {
	if tx.dialect.SupportsInsertReturning() {
		var id int64
		if err := tx.QueryRowContext(ctx, query+" RETURNING id", args...).Scan(&id); err != nil {
			return 0, wrapUniqueViolation(tx.dialect, err)
		}
		return id, nil
	}
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read inserted id: %w", err)
	}
	return id, nil
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
		// The dialect's LockMigrations already wraps its error with
		// "acquire migration lock:" (and a connection-acquire variant), so
		// propagate it directly — re-wrapping here duplicated the prefix
		// ("acquire migration lock: acquire migration lock: ...").
		return err
	}
	defer release()

	// Create the migration tracking table first (safe across all dialects).
	// PostgreSQL uses TIMESTAMP instead of DATETIME.
	tsType := db.dialect.TimestampType()
	if _, err := db.Conn.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at %s NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`, tsType)); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	// Migrate any old vNNN version identifiers to content hashes. This only
	// happens once when upgrading from the index-based versioning scheme.
	if err := db.migrateOldVersions(); err != nil {
		return fmt.Errorf("migrate old version identifiers: %w", err)
	}

	// There is deliberately NO "untracked but populated database → mark
	// everything applied" shortcut here: it declared a database whose
	// schema_migrations table was empty (wiped, or a very old upgrade)
	// fully migrated, so every table and column introduced afterwards was
	// silently never created. Instead, every migration simply runs: the
	// CREATE statements are IF NOT EXISTS / InsertIgnore-idempotent, and an
	// ALTER that hits an already-existing object fails with an
	// already-exists error that the loop below records as applied — re-runs
	// are safe and missing objects get created.

	for _, m := range db.dialect.Migrations() {
		version := migrationVersion(m)

		var applied int
		if err := db.Conn.QueryRow(db.dialect.Rebind("SELECT COUNT(*) FROM schema_migrations WHERE version = ?"), version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied > 0 {
			continue
		}

		// Apply the migration and record it inside a single transaction so a
		// failure midway never leaves the schema changed but unrecorded (or
		// vice-versa). See applyMigration.
		if err := db.applyMigration(m, version); err != nil {
			// Another process (e.g. the server and the CLI starting
			// together) claimed the migration between the outside check and
			// the in-transaction claim: it owns this migration, skip quietly.
			if errors.Is(err, errMigrationAppliedElsewhere) {
				logger.Info("migration applied concurrently by another instance; skipping", "version", version)
				continue
			}
			return err
		}

		logger.Info("applied migration", "version", version)
	}
	logger.Info("migrations completed")
	return nil
}

// errMigrationAppliedElsewhere reports that applyMigration lost the claim on a
// migration version to another process that is applying (or has applied) it.
// The caller skips the migration instead of failing startup.
var errMigrationAppliedElsewhere = errors.New("migration claimed by another instance")

// firstLine returns the first line of a SQL statement, for log brevity.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// applyMigration runs a single migration's statements and records it in
// schema_migrations inside one transaction, so a failure midway never leaves
// the schema changed but unrecorded (or vice-versa). The migration SQL is
// split into individual statements because the MySQL driver runs with
// MultiStatements disabled for defense-in-depth; executing each statement
// separately also lets every dialect apply a multi-step migration atomically
// inside the transaction.
//
// The version row is CLAIMED at the start of the transaction with a
// dialect-portable insert-ignore, not appended at the end: the outside
// "already applied" check races against another process (the server and the
// CLI can start together — on SQLite the file lock only serializes
// transactions, not the check-then-insert sequence), and the loser used to
// abort with a primary-key violation on schema_migrations. A zero-rows claim
// means another instance owns the migration: the transaction rolls back and
// errMigrationAppliedElsewhere is returned for the caller to skip.
//
// Note: MySQL/MariaDB implicitly commit on most DDL statements, so on those
// dialects a multi-statement migration is not fully rollback-able. This is a
// documented engine limitation; SQLite and PostgreSQL provide true atomicity.
func (db *DB) applyMigration(sqlText, version string) error {
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", version, err)
	}
	defer tx.Rollback() // no-op after Commit

	// Claim the version row inside the transaction (dialect-portable
	// insert-ignore with automatic placeholder rebinding).
	res, err := tx.InsertIgnore(ctx, "schema_migrations", []string{"version"}, []string{"version"}, version)
	if err != nil {
		return fmt.Errorf("claim migration %s: %w", version, err)
	}
	if n, rerr := res.RowsAffected(); rerr == nil && n == 0 {
		// Another instance recorded this version between the outside check
		// and this claim. Its transaction owns the migration; ours must not
		// run the statements a second time.
		return errMigrationAppliedElsewhere
	}

	for _, stmt := range splitStatements(sqlText) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			// An already-existing object is skipped STATEMENT BY STATEMENT:
			// a re-run migration (edited content hash, or a database whose
			// objects predate tracking) used to abort at its first
			// already-exists error and every FOLLOWING statement was silently
			// dropped — on MySQL, where DDL implicitly commits, that left a
			// partially applied migration recorded as fully applied. Skipping
			// just the offending statement lets the remaining ones run.
			if db.dialect.IsAlreadyExistsError(err) {
				logger.Warn("migration statement skipped: object already exists",
					"version", version, "statement", firstLine(stmt), "error", err)
				continue
			}
			return fmt.Errorf("migration %s failed: %w\nSQL: %s", version, err, stmt)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", version, err)
	}
	return nil
}

// splitStatements splits a possibly multi-statement SQL string into individual
// statements. It is needed so a migration can carry several statements and
// still be applied uniformly across dialects within one transaction, given the
// MySQL driver has MultiStatements disabled.
//
// The splitter honours single-quoted string literals (with ” escaping) and
// "--" line comments, so a ';' inside a literal or comment does not start a
// new statement. Block comments and dollar-quoted strings are intentionally
// unsupported; GoZone migrations are plain DDL and use neither.
func splitStatements(sql string) []string {
	var (
		out      []string
		sb       strings.Builder
		inString bool
	)
	flush := func() {
		s := strings.TrimSpace(sb.String())
		if s != "" {
			out = append(out, s)
		}
		sb.Reset()
	}
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		// Line comment: copy through to the newline without treating ';' as
		// a separator.
		if !inString && c == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			for i < len(sql) && sql[i] != '\n' {
				sb.WriteByte(sql[i])
				i++
			}
			if i < len(sql) {
				sb.WriteByte(sql[i])
			}
			continue
		}
		if c == '\'' {
			sb.WriteByte(c)
			if inString {
				// Escaped '' keeps the string open; otherwise this closes it.
				if i+1 < len(sql) && sql[i+1] == '\'' {
					sb.WriteByte(sql[i+1])
					i++
				} else {
					inString = false
				}
			} else {
				inString = true
			}
			continue
		}
		if c == ';' && !inString {
			flush()
			continue
		}
		sb.WriteByte(c)
	}
	flush()
	return out
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
// logging. Recognised forms:
//   - MySQL DSNs with an explicit protocol: user:password@tcp(host)/db and
//     user:password@unix(/path)/db;
//   - URL-style DSNs carrying userinfo credentials: postgres://user:secret@host/db,
//     postgresql://…, mysql://…;
//   - MySQL DSNs with the default protocol: user:password@/db;
//   - PostgreSQL keyword/value DSNs: password=secret;
//   - SQLite file paths: no credentials, returned unchanged.
func sanitizeDSN(dsn string) string {
	// MySQL-style userinfo: user:password@<protocol>(<addr>)/db, where
	// <protocol> is tcp or unix. Searching for the "@tcp(" / "@unix(" delimiter
	// (rather than a bare "@") redacts passwords that themselves contain '@'
	// correctly: strings.Index lands on the '@' immediately before the protocol
	// keyword.
	for _, sep := range []string{"@unix(", "@tcp("} {
		if idx := strings.Index(dsn, sep); idx >= 0 {
			prefix := dsn[:idx]
			if colon := strings.Index(prefix, ":"); colon >= 0 {
				return prefix[:colon+1] + "***" + dsn[idx:]
			}
			return dsn // no password present in userinfo
		}
	}
	// URL-style DSNs: scheme://user:password@host:port/db?param=value. url.Parse
	// is used as a detector: the branch is only taken when the string carries
	// both a scheme and a userinfo authority, so the MySQL and keyword/value
	// forms handled above and below fall through untouched. Redaction is done
	// by string surgery on the original DSN — mirroring net/url's own split
	// (userinfo ends at the last '@' of the authority, password starts after
	// the first ':') — so every byte outside the password, percent-encoding
	// included, is logged verbatim. A URL whose password fails to parse
	// (invalid percent-encoding) would also be rejected by the driver, so it
	// never reaches the log line.
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" && u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			if i := strings.Index(dsn, "://"); i >= 0 {
				rest := dsn[i+3:]
				end := strings.IndexAny(rest, "/?#")
				if end < 0 {
					end = len(rest)
				}
				authority := rest[:end]
				if at := strings.LastIndex(authority, "@"); at >= 0 {
					userinfo := authority[:at]
					if colon := strings.Index(userinfo, ":"); colon >= 0 {
						return dsn[:i+3] + userinfo[:colon+1] + "***" + dsn[i+3+at:]
					}
				}
			}
		}
	}
	// MySQL default-protocol form: user:password@/db (no tcp()/unix() group).
	// The colon must be a userinfo separator, not a scheme separator: skipping
	// a colon directly followed by "/" leaves URL-form DSNs without a password
	// (e.g. postgres://user@host/db) unmangled.
	if idx := strings.Index(dsn, "@/"); idx >= 0 {
		prefix := dsn[:idx]
		if colon := strings.Index(prefix, ":"); colon >= 0 &&
			(colon+1 >= len(prefix) || prefix[colon+1] != '/') {
			return prefix[:colon+1] + "***" + dsn[idx:]
		}
		return dsn // no password present in userinfo
	}
	// PostgreSQL-style: password=secret
	re := regexp.MustCompile(`password=[^ ]+`)
	if re.MatchString(dsn) {
		return re.ReplaceAllString(dsn, "password=***")
	}
	// SQLite: file path, no credentials
	return dsn
}

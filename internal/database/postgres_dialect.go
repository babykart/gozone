package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/logger"

	"github.com/lib/pq"
)

type postgresDialect struct{}

func (p *postgresDialect) DriverName() string { return "postgres" }

func (p *postgresDialect) TimestampType() string { return "TIMESTAMP" }

// DSN appends TimeZone=UTC to the connection string: lib/pq sends unrecognized
// keys to the server as runtime parameters, so the session (and therefore
// CURRENT_TIMESTAMP) runs on UTC, and the driver parses the naive `timestamp
// without time zone` columns in the zone the server reports — UTC as well.
// Like the SQLite pragmas, this is a correctness setting, not a tuning knob:
// an existing value is overridden by the appended one (the server keeps the
// last occurrence).
func (p *postgresDialect) DSN(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		return dsn + sep + "TimeZone=UTC"
	}
	return dsn + " TimeZone=UTC"
}

func (p *postgresDialect) MaxOpenConns() int { return 25 }

// MaxIdleConns keeps the pool warm at the open limit so bursts don't pay the
// connect/auth cost.
func (p *postgresDialect) MaxIdleConns() int { return defaultMaxIdleConns }

// ConnMaxLifetime recycles connections before PgBouncer/cloud proxies or the
// server drop them.
func (p *postgresDialect) ConnMaxLifetime() time.Duration { return defaultConnMaxLifetime }

func (p *postgresDialect) Rebind(query string) string { return rebindDollar(query) }

// SupportsInsertReturning returns true: PostgreSQL supports RETURNING and
// lib/pq does NOT implement sql.Result.LastInsertId, so RETURNING is the only
// portable way to obtain the inserted row's id.
func (p *postgresDialect) SupportsInsertReturning() bool { return true }

// RateLimitHitUpsert: ON CONFLICT ... DO UPDATE ... RETURNING — one
// statement, one exclusive row lock, count returned in the same round-trip.
func (p *postgresDialect) RateLimitHitUpsert() (string, bool) {
	return `INSERT INTO rate_limit_counters (bucket_key, window_start, hits)
		VALUES (?, ?, 1)
		ON CONFLICT (bucket_key, window_start) DO UPDATE SET hits = rate_limit_counters.hits + 1
		RETURNING hits`, true
}

func (p *postgresDialect) InsertIgnore(table string, columns, conflictColumns []string) string {
	// conflictColumns is REQUIRED for PostgreSQL: ON CONFLICT (col1, col2, ...)
	// must match an existing UNIQUE constraint or PRIMARY KEY on the table.
	// Reject the call early so a silent fallback to the wrong index can never
	// happen — the older helper that reused `columns` here masked a real
	// invariant the caller was responsible for maintaining.
	if len(conflictColumns) == 0 {
		return "-- ERROR: postgresDialect.InsertIgnore requires non-empty conflictColumns matching a UNIQUE constraint or PRIMARY KEY"
	}
	cols := strings.Join(columns, ", ")
	target := strings.Join(conflictColumns, ", ")
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING",
		table, cols, placeholders(len(columns)), target)
}

// postgresAdvisoryLockKey derives the migration advisory-lock key from the
// module path. The previous constant 42 was banal enough that any other
// application sharing the PostgreSQL cluster could take (or hold) it. A
// stable FNV-1a hash of a GoZone-specific string gives a distinctive,
// deterministic key.
func postgresAdvisoryLockKey() int64 {
	h := fnv.New64a()
	// #nosec G104 -- hash.Hash's Write never returns an error.
	h.Write([]byte("github.com/babykart/gozone/schema-migrations"))
	// #nosec G115 -- intentional bit-pattern reinterpretation: PostgreSQL
	// advisory-lock keys are signed int64, and an arbitrary (possibly
	// "negative") key is exactly what we want from a hash.
	return int64(h.Sum64())
}

// Bounds for the PostgreSQL migration-lock acquisition: the per-attempt wait
// (statement_timeout) and the total number of attempts before giving up
// (≈ 5 minutes with the backoff). Migrations finish in seconds; the bound
// exists so a stuck holder cannot pin a replica's startup forever.
const (
	postgresLockTimeoutSecs = 60
	postgresLockMaxAttempts = 5
	postgresLockBackoff     = 5 * time.Second
)

// LockMigrations acquires a PostgreSQL advisory lock so only one instance
// runs migrations at a time. The lock is released by the returned function.
//
// The lock is transaction-scoped (pg_advisory_xact_lock) and held by an open
// transaction on a single pinned *sql.Conn:
//
//   - It auto-releases at COMMIT/ROLLBACK, so the release can never silently
//     miss the session, and it works behind PgBouncer in transaction pooling
//     mode, where a session-level pg_advisory_lock can be taken on one server
//     session and released on another, leaking the lock until that session
//     dies.
//   - The wait is bounded: SET LOCAL statement_timeout caps each attempt
//     (advisory-lock waits honour it) and the acquisition is retried with a
//     backoff. The previous unqualified pg_advisory_lock waited FOREVER,
//     pinning a pooled connection and every replica's startup behind a slow
//     or stuck holder.
//   - The key is derived from the module path instead of the banal 42.
func (p *postgresDialect) LockMigrations(pool *sql.DB) (func(), error) {
	ctx := context.Background()
	conn, err := pool.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for migration lock: %w", err)
	}
	key := postgresAdvisoryLockKey()

	var tx *sql.Tx
	for attempt := 1; ; attempt++ {
		if tx, err = conn.BeginTx(ctx, nil); err != nil {
			conn.Close() // #nosec G104 -- best-effort cleanup on error path
			return nil, fmt.Errorf("acquire migration lock: %w", err)
		}
		if _, err = tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = '%ds'", postgresLockTimeoutSecs)); err != nil {
			_ = tx.Rollback()
			conn.Close() // #nosec G104 -- best-effort cleanup on error path
			return nil, fmt.Errorf("acquire migration lock (set statement_timeout): %w", err)
		}
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", key); err == nil {
			break // lock held by this open transaction
		}
		// The canceled statement aborts the transaction; retry on a fresh one.
		_ = tx.Rollback()
		if isPgQueryCanceled(err) && attempt < postgresLockMaxAttempts {
			logger.Warn("pg_advisory_xact_lock timed out; retrying",
				"attempt", attempt, "of", postgresLockMaxAttempts, "backoff", postgresLockBackoff.String())
			time.Sleep(postgresLockBackoff)
			continue
		}
		conn.Close() // #nosec G104 -- best-effort cleanup on error path
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}

	released := false
	release := func() {
		if released {
			return
		}
		released = true
		// The transaction did nothing but hold the lock: rolling it back
		// releases the advisory lock deterministically.
		if err := tx.Rollback(); err != nil {
			logger.Error("failed to release postgres migration lock", "error", err)
		}
		conn.Close() // #nosec G104 -- best-effort cleanup; the connection returns to the pool
	}
	return release, nil
}

// isPgQueryCanceled reports whether err is PostgreSQL's query_canceled
// SQLSTATE (57014) — the error a statement terminated by statement_timeout
// surfaces as, used to distinguish "lock wait timed out, retry" from a real
// failure.
func isPgQueryCanceled(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "57014"
}

// postgresAlreadyExistsSQLSTATEs are PostgreSQL SQLSTATE codes indicating a
// DDL operation tried to create an object that is already present. Used by
// IsAlreadyExistsError so the migration runner tolerates re-running a
// previously-applied migration whose content hash changed.
var postgresAlreadyExistsSQLSTATEs = map[string]bool{
	"42701": true, // duplicate_column
	"42P07": true, // duplicate_table
	"42710": true, // duplicate_object
	"42723": true, // duplicate_function
}

// IsAlreadyExistsError reports whether err is a PostgreSQL "object already
// exists" DDL error, via its SQLSTATE code.
func (p *postgresDialect) IsAlreadyExistsError(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return postgresAlreadyExistsSQLSTATEs[string(pqErr.Code)]
	}
	return false
}

// postgresUniqueViolationSQLSTATE is the PostgreSQL SQLSTATE code for a
// unique-constraint violation: unique_violation (23505). Used by
// IsUniqueViolation.
const postgresUniqueViolationSQLSTATE = "23505"

// IsUniqueViolation reports whether err is a PostgreSQL unique_violation
// (SQLSTATE 23505), detected via the typed *pq.Error so the check is
// independent of the driver message wording.
func (p *postgresDialect) IsUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code) == postgresUniqueViolationSQLSTATE
	}
	return false
}

func (p *postgresDialect) Migrations() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) NOT NULL UNIQUE,
			email VARCHAR(255) NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			first_name VARCHAR(255) NOT NULL DEFAULT '',
			last_name VARCHAR(255) NOT NULL DEFAULT '',
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			enabled SMALLINT NOT NULL DEFAULT 1,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			id SERIAL PRIMARY KEY,
			key VARCHAR(255) NOT NULL UNIQUE,
			value TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id SERIAL PRIMARY KEY,
			user_id INT,
			zone_id VARCHAR(255),
			action VARCHAR(255) NOT NULL,
			details TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id SERIAL PRIMARY KEY,
			user_id INT NOT NULL,
			key_hash VARCHAR(255) NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			last_used_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_zone_id ON activity_logs(zone_id)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_zone_created ON activity_logs(zone_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)`,
		`CREATE TABLE IF NOT EXISTS zone_groups (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS zone_group_members (
			group_id INT NOT NULL,
			user_id INT NOT NULL,
			PRIMARY KEY (group_id, user_id),
			FOREIGN KEY (group_id) REFERENCES zone_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS zone_group_zones (
			group_id INT NOT NULL,
			zone_id VARCHAR(255) NOT NULL,
			PRIMARY KEY (group_id, zone_id),
			FOREIGN KEY (group_id) REFERENCES zone_groups(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_group_members_user ON zone_group_members(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_group_zones_group ON zone_group_zones(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_group_zones_zone ON zone_group_zones(zone_id)`,
		`CREATE TABLE IF NOT EXISTS zone_templates (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			is_builtin SMALLINT NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS zone_template_records (
			id SERIAL PRIMARY KEY,
			template_id INT NOT NULL,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(16) NOT NULL,
			content TEXT NOT NULL,
			ttl INT NOT NULL DEFAULT 3600,
			priority INT NOT NULL DEFAULT 0,
			disabled SMALLINT NOT NULL DEFAULT 0,
			FOREIGN KEY (template_id) REFERENCES zone_templates(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
			jti VARCHAR(255) PRIMARY KEY,
			user_id INT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at)`,
		`ALTER TABLE activity_logs ADD COLUMN old_value TEXT NOT NULL DEFAULT '', ADD COLUMN new_value TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN locked_until TIMESTAMP`,
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) NOT NULL,
			user_id INTEGER,
			ip_address VARCHAR(64) NOT NULL DEFAULT '',
			success SMALLINT NOT NULL DEFAULT 0,
			attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username, attempted_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, attempted_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id, attempted_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_attempted_at ON login_attempts(attempted_at)`,
		`CREATE TABLE IF NOT EXISTS password_history (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_password_history_user_created ON password_history(user_id, created_at DESC)`,
		`ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`,
		`ALTER TABLE users ADD COLUMN must_change_password SMALLINT NOT NULL DEFAULT 0`,
		// Covering index for ListAPIKeys (WHERE user_id = ?
		// ORDER BY created_at DESC). Without it the only index on api_keys is
		// idx_api_keys_key_hash (auth lookup), so per-user listing degrades to
		// a full table scan as the table grows across all users.
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user_created ON api_keys(user_id, created_at DESC)`,
		// revoked_tokens.user_id had no FK, so deleting a user
		// left orphan revocation rows until the expiry cleanup — unlike
		// password_history / api_keys / group_members which all cascade. Add a
		// real FK with ON DELETE CASCADE, matching the other user_id tables.
		// Pre-existing orphans are removed first so the constraint can be added.
		`DELETE FROM revoked_tokens WHERE user_id NOT IN (SELECT id FROM users);
		ALTER TABLE revoked_tokens ADD CONSTRAINT fk_revoked_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`,
		// OpenID Connect / OAuth2: see sqlite_dialect.go for the rationale.
		`CREATE TABLE IF NOT EXISTS external_identities (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			issuer VARCHAR(255) NOT NULL,
			subject VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (issuer, subject),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_external_identities_issuer_subject ON external_identities(issuer, subject)`,
		// Session lifetime tracking (idle/absolute enforcement, shared across
		// instances). See sqlite_dialect.go for the rationale.
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id VARCHAR(255) PRIMARY KEY,
			first_seen TIMESTAMP NOT NULL,
			last_seen TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		// Lowercased email column + index for case-insensitive
		// SSO account-linking lookup (FindUserByEmail). PostgreSQL only supports
		// STORED generated columns (since 12); the index turns the lookup into
		// an equality seek instead of wrapping the UNIQUE-indexed column in
		// LOWER(), which forced a full scan.
		`ALTER TABLE users ADD COLUMN email_lc VARCHAR(255) GENERATED ALWAYS AS (LOWER(email)) STORED`,
		`CREATE INDEX IF NOT EXISTS idx_users_email_lc ON users(email_lc)`,
		// Per-user session-revocation cutoff. See
		// sqlite_dialect.go for the rationale.
		`ALTER TABLE users ADD COLUMN tokens_valid_after TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00'`,
		// Distinct marker for an admin-imposed manual lock. See
		// sqlite_dialect.go for the rationale.
		`ALTER TABLE users ADD COLUMN manual_lock_until TIMESTAMP`,
		// Server-side storage of SSO ID tokens for RP-initiated logout
		// (id_token_hint). See sqlite_dialect.go for the rationale.
		`CREATE TABLE IF NOT EXISTS sso_id_tokens (
			session_id VARCHAR(64) PRIMARY KEY,
			id_token TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_id_tokens_expires_at ON sso_id_tokens(expires_at)`,
		// Cluster-wide fixed-window rate-limit counters. See
		// sqlite_dialect.go for the rationale. TIMESTAMP (not DATETIME) per
		// the schema_migrations regression: PostgreSQL has no DATETIME.
		`CREATE TABLE IF NOT EXISTS rate_limit_counters (
			bucket_key TEXT NOT NULL,
			window_start TIMESTAMP NOT NULL,
			hits INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_key, window_start)
		)`,
		// Case-insensitive uniqueness for username and email: PostgreSQL's
		// UNIQUE constraints are binary while the lookups fold the case, so
		// "Alice" and "alice" could coexist. UNIQUE indexes on the generated
		// lowercased columns enforce the folded uniqueness and serve the
		// equality lookups. On a database with pre-existing case-duplicates
		// this fails loudly at startup; dedupe first (see sqlite_dialect.go).
		`ALTER TABLE users ADD COLUMN username_lc VARCHAR(255) GENERATED ALWAYS AS (LOWER(username)) STORED`,
		`DROP INDEX IF EXISTS idx_users_email_lc`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lc ON users(username_lc)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lc ON users(email_lc)`,
	}
}

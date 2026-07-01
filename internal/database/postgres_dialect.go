package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/logger"

	"github.com/lib/pq"
)

type postgresDialect struct{}

func (p *postgresDialect) DriverName() string { return "postgres" }

func (p *postgresDialect) TimestampType() string { return "TIMESTAMP" }

func (p *postgresDialect) DSN(dsn string) string { return dsn }

func (p *postgresDialect) MaxOpenConns() int { return 25 }

// MaxIdleConns keeps the pool warm at the open limit so bursts don't pay the
// connect/auth cost. See REVIEW.md m16.
func (p *postgresDialect) MaxIdleConns() int { return defaultMaxIdleConns }

// ConnMaxLifetime recycles connections before PgBouncer/cloud proxies or the
// server drop them. See REVIEW.md m16.
func (p *postgresDialect) ConnMaxLifetime() time.Duration { return defaultConnMaxLifetime }

func (p *postgresDialect) Rebind(query string) string { return rebindDollar(query) }

func (p *postgresDialect) InsertIgnore(table string, columns, conflictColumns []string) string {
	// conflictColumns is REQUIRED for PostgreSQL: ON CONFLICT (col1, col2, ...)
	// must match an existing UNIQUE constraint or PRIMARY KEY on the table.
	// Reject the call early so a silent fallback to the wrong index can never
	// happen — the older helper that reused `columns` here masked a real
	// invariant the caller was responsible for maintaining (REVIEW.md
	// mineur "InsertIgnore Postgres réutilise toutes les colonnes comme cible").
	if len(conflictColumns) == 0 {
		return "-- ERROR: postgresDialect.InsertIgnore requires non-empty conflictColumns matching a UNIQUE constraint or PRIMARY KEY"
	}
	cols := strings.Join(columns, ", ")
	target := strings.Join(conflictColumns, ", ")
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING",
		table, cols, placeholders(len(columns)), target)
}

// LockMigrations acquires a PostgreSQL advisory lock so only one instance
// runs migrations at a time. The lock is released by the returned function.
//
// pg_advisory_lock and pg_advisory_unlock are session-scoped: they must
// execute on the same connection. A single *sql.Conn is pinned from the
// pool for the entire acquire/release lifecycle. Without this pinning,
// *sql.DB.Exec borrows a different connection per call and the unlock is
// a silent no-op, leaking the lock until the original connection is closed.
func (p *postgresDialect) LockMigrations(pool *sql.DB) (func(), error) {
	ctx := context.Background()
	conn, err := pool.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for migration lock: %w", err)
	}
	const lockID = 42
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on error path
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID); err != nil {
			logger.Error("failed to release postgres migration lock", "error", err)
		}
		conn.Close() // #nosec G104 -- best-effort cleanup; the connection returns to the pool
	}
	return release, nil
}

// postgresAlreadyExistsSQLSTATEs are PostgreSQL SQLSTATE codes indicating a
// DDL operation tried to create an object that is already present. Used by
// IsAlreadyExistsError so the migration runner tolerates re-running a
// previously-applied migration whose content hash changed. See REVIEW.md m22.
var postgresAlreadyExistsSQLSTATEs = map[string]bool{
	"42701": true, // duplicate_column
	"42P07": true, // duplicate_table
	"42710": true, // duplicate_object
	"42723": true, // duplicate_function
}

// IsAlreadyExistsError reports whether err is a PostgreSQL "object already
// exists" DDL error, via its SQLSTATE code. See REVIEW.md m22.
func (p *postgresDialect) IsAlreadyExistsError(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return postgresAlreadyExistsSQLSTATEs[string(pqErr.Code)]
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
	}
}

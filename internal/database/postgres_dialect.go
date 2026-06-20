package database

import (
	"database/sql"
	"fmt"

	"github.com/babykart/gozone/internal/logger"
)

type postgresDialect struct{}

func (p *postgresDialect) DriverName() string { return "postgres" }

func (p *postgresDialect) DSN(dsn string) string { return dsn }

func (p *postgresDialect) MaxOpenConns() int { return 25 }

func (p *postgresDialect) Rebind(query string) string { return rebindDollar(query) }

// LockMigrations acquires a PostgreSQL advisory lock so only one instance
// runs migrations at a time. The lock is released by the returned function.
func (p *postgresDialect) LockMigrations(conn *sql.DB) (func(), error) {
	const lockID = 42
	_, err := conn.Exec("SELECT pg_advisory_lock($1)", lockID)
	if err != nil {
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	release := func() {
		if _, err := conn.Exec("SELECT pg_advisory_unlock($1)", lockID); err != nil {
			logger.Error("failed to release postgres migration lock", "error", err)
		}
	}
	return release, nil
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
	}
}

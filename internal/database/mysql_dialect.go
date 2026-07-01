package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/logger"

	"github.com/go-sql-driver/mysql"
)

type mysqlDialect struct{}

func (m *mysqlDialect) DriverName() string { return "mysql" }

func (m *mysqlDialect) TimestampType() string { return "DATETIME" }

func (m *mysqlDialect) DSN(dsn string) string {
	// ParseDSN preserves existing query parameters, avoids the double '?' bug
	// when the DSN already contains options, and lets us set ParseTime cleanly.
	// MultiStatements is intentionally left disabled for defense-in-depth.
	cfg, err := mysql.ParseDSN(dsn)
	if err == nil {
		cfg.ParseTime = true
		return cfg.FormatDSN()
	}

	// Fallback for unparseable DSNs: append parseTime without producing '??'.
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "parseTime=true"
}

func (m *mysqlDialect) MaxOpenConns() int { return 25 }

// MaxIdleConns keeps the pool warm at the open limit so bursts don't pay the
// connect/auth cost. See REVIEW.md m16.
func (m *mysqlDialect) MaxIdleConns() int { return defaultMaxIdleConns }

// ConnMaxLifetime recycles connections before MySQL's wait_timeout or an
// intermediary LB/proxy silently drops them. See REVIEW.md m16.
func (m *mysqlDialect) ConnMaxLifetime() time.Duration { return defaultConnMaxLifetime }

func (m *mysqlDialect) Rebind(query string) string { return query }

func (m *mysqlDialect) InsertIgnore(table string, columns, _ []string) string {
	return fmt.Sprintf("INSERT IGNORE INTO %s (%s) VALUES (%s)", table, strings.Join(columns, ", "), placeholders(len(columns)))
}

// LockMigrations acquires a named MySQL lock so only one instance runs
// migrations at a time. The lock is released by the returned function.
//
// GET_LOCK and RELEASE_LOCK are session-scoped: they must execute on the
// same database connection. A single *sql.Conn is pinned from the pool for
// the entire acquire/release lifecycle so the release runs on the same
// session that holds the lock. Without this pinning, *sql.DB.Exec borrows
// a different connection per call and the release is a silent no-op,
// leaking the lock until the original connection is closed by the pool.
func (m *mysqlDialect) LockMigrations(pool *sql.DB) (func(), error) {
	ctx := context.Background()
	conn, err := pool.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for migration lock: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT GET_LOCK('gozone_migrations', -1)"); err != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on error path
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if _, err := conn.ExecContext(ctx, "SELECT RELEASE_LOCK('gozone_migrations')"); err != nil {
			logger.Error("failed to release mysql migration lock", "error", err)
		}
		conn.Close() // #nosec G104 -- best-effort cleanup; the connection returns to the pool
	}
	return release, nil
}

// mysqlAlreadyExistsCodes are MySQL error numbers that indicate a DDL operation
// tried to create an object that is already present. Used by
// IsAlreadyExistsError so the migration runner can tolerate re-running a
// previously-applied migration whose content hash changed. See REVIEW.md m22.
var mysqlAlreadyExistsCodes = map[uint16]bool{
	1050: true, // ER_TABLE_EXISTS_ERROR  - Table already exists
	1060: true, // ER_DUP_FIELDNAME       - Duplicate column name
	1061: true, // ER_DUP_KEYNAME         - Duplicate key name (index)
	1068: true, // ER_MULTIPLE_PRI_KEY    - Multiple primary key defined
}

// IsAlreadyExistsError reports whether err is a MySQL "object already exists"
// DDL error (duplicate table/column/index/key). See REVIEW.md m22.
func (m *mysqlDialect) IsAlreadyExistsError(err error) bool {
	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		return mysqlAlreadyExistsCodes[myErr.Number]
	}
	return false
}

func (m *mysqlDialect) Migrations() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) NOT NULL UNIQUE,
			email VARCHAR(255) NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			first_name VARCHAR(255) NOT NULL DEFAULT '',
			last_name VARCHAR(255) NOT NULL DEFAULT '',
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			enabled TINYINT NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS settings (
			id INT AUTO_INCREMENT PRIMARY KEY,
			` + "`key`" + ` VARCHAR(255) NOT NULL UNIQUE,
			value TEXT NOT NULL DEFAULT ''
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT,
			zone_id VARCHAR(255),
			action VARCHAR(255) NOT NULL,
			details TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
			KEY idx_activity_logs_user_id (user_id),
			KEY idx_activity_logs_zone_id (zone_id),
			KEY idx_activity_logs_zone_created (zone_id, created_at),
			KEY idx_activity_logs_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			key_hash VARCHAR(255) NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			last_used_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			KEY idx_api_keys_key_hash (key_hash)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS zone_groups (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS zone_group_members (
			group_id INT NOT NULL,
			user_id INT NOT NULL,
			PRIMARY KEY (group_id, user_id),
			FOREIGN KEY (group_id) REFERENCES zone_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			KEY idx_zone_group_members_user (user_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS zone_group_zones (
			group_id INT NOT NULL,
			zone_id VARCHAR(255) NOT NULL,
			PRIMARY KEY (group_id, zone_id),
			FOREIGN KEY (group_id) REFERENCES zone_groups(id) ON DELETE CASCADE,
			KEY idx_zone_group_zones_group (group_id),
			KEY idx_zone_group_zones_zone (zone_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS zone_templates (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			is_builtin TINYINT NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS zone_template_records (
			id INT AUTO_INCREMENT PRIMARY KEY,
			template_id INT NOT NULL,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(16) NOT NULL,
			content TEXT NOT NULL,
			ttl INT NOT NULL DEFAULT 3600,
			priority INT NOT NULL DEFAULT 0,
			disabled TINYINT NOT NULL DEFAULT 0,
			FOREIGN KEY (template_id) REFERENCES zone_templates(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
			jti VARCHAR(255) PRIMARY KEY,
			user_id INT NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			KEY idx_revoked_tokens_expires_at (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`ALTER TABLE activity_logs ADD COLUMN old_value TEXT NOT NULL DEFAULT '', ADD COLUMN new_value TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN failed_login_attempts INT NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN locked_until DATETIME NULL`,
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) NOT NULL,
			user_id INT,
			ip_address VARCHAR(64) NOT NULL DEFAULT '',
			success TINYINT NOT NULL DEFAULT 0,
			attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
			KEY idx_login_attempts_username (username, attempted_at),
			KEY idx_login_attempts_ip (ip_address, attempted_at),
			KEY idx_login_attempts_user (user_id, attempted_at),
			KEY idx_login_attempts_attempted_at (attempted_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		// m21: idx_activity_logs_zone_created was originally created inline
		// above as (zone_id, created_at) without DESC, unlike the SQLite and
		// PostgreSQL dialects which both order created_at DESC. Rebuild the
		// index with DESC so zone-scoped activity queries (ORDER BY
		// created_at DESC) are served in index order. This is a NEW migration
		// rather than an edit of the original CREATE TABLE: migrations are
		// content-hashed (REVIEW.md m22), so editing the original would just
		// re-run a no-op "CREATE TABLE IF NOT EXISTS" on existing databases
		// and leave the index unchanged; a new ALTER migration fixes both
		// fresh and existing databases. (MySQL < 8.0 parses DESC but ignores
		// it; MySQL 8.0+ / modern MariaDB build a real descending index.)
		`ALTER TABLE activity_logs DROP INDEX idx_activity_logs_zone_created, ADD INDEX idx_activity_logs_zone_created (zone_id, created_at DESC)`,
	}
}

package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/constants"
)

type sqliteDialect struct{}

func (s *sqliteDialect) DriverName() string { return "sqlite3" }

func (s *sqliteDialect) TimestampType() string { return "DATETIME" }

// DSN appends the pragmas the GoZone SQLite deployments rely on:
//
//   - `_journal_mode=WAL`: readers never block the writer and vice versa.
//     Within one GoZone process the pool is a single connection anyway (see
//     MaxOpenConns), but WAL also makes cross-process access sane — the
//     recovery CLI (`gozone user unlock`, `reset-password`) opens the same
//     database file while the server may be running.
//   - `_foreign_keys=on`: enforce referential integrity the way MySQL and
//     PostgreSQL do by default (SQLite leaves FK enforcement off unless
//     asked).
//   - `_busy_timeout=5000`: SQLite's default on lock contention is to fail
//     immediately with SQLITE_BUSY. With a short wait, transient
//     writer/writer contention between the server process and a CLI run (or
//     any second process) resolves itself instead of surfacing as an error.
//
// An existing value for any of these keys in the caller's DSN is overwritten:
// they are correctness settings, not tuning knobs.
//
// The pragmas are appended by string concatenation, never by re-encoding the
// DSN through net/url: u.String() percent-encodes the path, and the SQLite
// driver does NOT percent-decode file paths — "./data/my db.db" used to open
// the different, empty file "my%20db.db" (silently re-seeding the admin), and
// a '#' in the filename truncated the path as a URL fragment. Only the first
// '?' splits the path from the parameter list; everything before it stays
// byte-identical to the caller's input.
func (s *sqliteDialect) DSN(dsn string) string {
	const pragmas = "_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000"
	if dsn == ":memory:" {
		return ":memory:?" + pragmas
	}
	path, query, hasQuery := strings.Cut(dsn, "?")
	if !hasQuery {
		return dsn + "?" + pragmas
	}
	// Drop caller-provided values for the pragma keys so the appended ones
	// win, keeping every other parameter verbatim (no re-encoding).
	var kept []string
	for _, param := range strings.Split(query, "&") {
		if key, _, _ := strings.Cut(param, "="); sqlitePragmaKeys[key] {
			continue
		}
		if param != "" {
			kept = append(kept, param)
		}
	}
	if len(kept) == 0 {
		return path + "?" + pragmas
	}
	return path + "?" + strings.Join(kept, "&") + "&" + pragmas
}

// sqlitePragmaKeys are the correctness pragmas DSN always overwrites.
var sqlitePragmaKeys = map[string]bool{
	"_journal_mode": true,
	"_foreign_keys": true,
	"_busy_timeout": true,
}

// MaxOpenConns pins the pool to a single connection. SQLite allows exactly
// one writer at a time; funnelling everything through one connection makes
// the database/sql pool that guarantee instead of relying on lock waits, and
// sidesteps the SQLITE_BUSY-on-lock-upgrade deadlocks that multi-connection
// pools can hit. The throughput ceiling this creates is a documented design
// decision — see the "SQLite Single-Connection Pool" section in
// docs/ARCHITECTURE.md; deployments that outgrow it move to MySQL or
// PostgreSQL, which use a normal pool.
func (s *sqliteDialect) MaxOpenConns() int { return constants.MaxOpenConns }

// MaxIdleConns matches MaxOpenConns (1): keeping the single connection warm in
// the idle pool avoids reconnect overhead on every query. database/sql clamps
// idle to open anyway, so this is belt-and-braces.
func (s *sqliteDialect) MaxIdleConns() int { return constants.MaxOpenConns }

// ConnMaxLifetime is zero (unlimited) for SQLite: there is a single local
// connection to a file and no proxy/LB in between that could silently drop it,
// so recycling would only add needless reconnect cost.
func (s *sqliteDialect) ConnMaxLifetime() time.Duration { return 0 }

func (s *sqliteDialect) Rebind(query string) string { return query }

func (s *sqliteDialect) InsertIgnore(table string, columns, _ []string) string {
	return fmt.Sprintf("INSERT OR IGNORE INTO %s (%s) VALUES (%s)", table, strings.Join(columns, ", "), placeholders(len(columns)))
}

// SupportsInsertReturning returns true: the bundled SQLite is 3.53.2, well past
// the 3.35 release that added RETURNING. This also exercises the RETURNING code
// path under the in-memory SQLite test suite, giving confidence that the
// PostgreSQL path (which lacks LastInsertId support) works identically.
func (s *sqliteDialect) SupportsInsertReturning() bool { return true }

// RateLimitHitUpsert: ON CONFLICT ... DO UPDATE ... RETURNING — one
// statement, one exclusive row lock, and the resulting count comes back
// with the same round-trip (SQLite supports RETURNING since 3.35; the
// bundled build is well past it).
func (s *sqliteDialect) RateLimitHitUpsert() (string, bool) {
	return `INSERT INTO rate_limit_counters (bucket_key, window_start, hits)
		VALUES (?, ?, 1)
		ON CONFLICT(bucket_key, window_start) DO UPDATE SET hits = hits + 1
		RETURNING hits`, true
}

// LockMigrations is a no-op for SQLite. SQLite serializes writers at the
// database-file level and MaxOpenConns is set to 1, so concurrent migration
// races from a single process are impossible. Cross-process concurrency (the
// server and the CLI starting together on the same file) is handled by the
// migration runner itself: each migration claims its version row with an
// in-transaction INSERT OR IGNORE (see applyMigration), so the loser skips
// instead of failing with a primary-key violation — file locking alone only
// serializes individual transactions, not the check-then-insert sequence.
func (s *sqliteDialect) LockMigrations(conn *sql.DB) (func(), error) {
	return func() {}, nil
}

// IsAlreadyExistsError matches go-sqlite3's DDL-already-exists messages. The
// driver exposes no typed error codes for these, so we match on the stable
// message text.
func (s *sqliteDialect) IsAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate column name") ||
		strings.Contains(msg, "already exists")
}

// IsUniqueViolation matches go-sqlite3's UNIQUE-constraint-failed error. The
// driver exposes no typed error code for this, so we match on the stable
// message prefix "UNIQUE constraint failed: ..." that every SQLite version
// emits (sqlite3.c azType table + sqlite3VdbeMakeReady).
func (s *sqliteDialect) IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (s *sqliteDialect) Migrations() []string {
	return []string{
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
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_zone_created ON activity_logs(zone_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)`,
		`CREATE TABLE IF NOT EXISTS zone_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS zone_group_members (
			group_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			PRIMARY KEY (group_id, user_id),
			FOREIGN KEY (group_id) REFERENCES zone_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS zone_group_zones (
			group_id INTEGER NOT NULL,
			zone_id TEXT NOT NULL,
			PRIMARY KEY (group_id, zone_id),
			FOREIGN KEY (group_id) REFERENCES zone_groups(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_group_members_user ON zone_group_members(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_group_zones_group ON zone_group_zones(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_group_zones_zone ON zone_group_zones(zone_id)`,
		`CREATE TABLE IF NOT EXISTS zone_templates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			is_builtin INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS zone_template_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			template_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			content TEXT NOT NULL,
			ttl INTEGER NOT NULL DEFAULT 3600,
			priority INTEGER NOT NULL DEFAULT 0,
			disabled INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (template_id) REFERENCES zone_templates(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
			jti TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at)`,
		`ALTER TABLE activity_logs ADD COLUMN old_value TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE activity_logs ADD COLUMN new_value TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN locked_until DATETIME`,
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			user_id INTEGER,
			ip_address TEXT NOT NULL DEFAULT '',
			success INTEGER NOT NULL DEFAULT 0,
			attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username, attempted_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, attempted_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id, attempted_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_attempted_at ON login_attempts(attempted_at)`,
		`CREATE TABLE IF NOT EXISTS password_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_password_history_user_created ON password_history(user_id, created_at DESC)`,
		// SQLite rejects ADD COLUMN with a non-constant default once the
		// table holds rows ("Cannot add a column with non-constant
		// default"), and users is never empty on an upgraded database (the
		// seed admin always exists). Add the column with a constant epoch
		// default — same convention as tokens_valid_after below — then
		// backfill existing rows with a follow-up UPDATE in the same
		// migration. New rows are expected to set password_changed_at
		// explicitly; the epoch default is only a NOT NULL filler.
		`ALTER TABLE users ADD COLUMN password_changed_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
		UPDATE users SET password_changed_at = CURRENT_TIMESTAMP`,
		`ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`,
		// Covering index for ListAPIKeys (WHERE user_id = ?
		// ORDER BY created_at DESC). Without it the only index on api_keys is
		// idx_api_keys_key_hash (auth lookup), so per-user listing degrades to
		// a full table scan as the table grows across all users.
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user_created ON api_keys(user_id, created_at DESC)`,
		// revoked_tokens.user_id had no FK, so deleting a user
		// left orphan revocation rows until the expiry cleanup — unlike
		// password_history / api_keys / group_members which all cascade. SQLite
		// cannot ALTER TABLE to add a FK, so the table is rebuilt with the FK.
		// Pre-existing orphans are removed first so the FK can be added; on a
		// fresh DB both steps are no-ops. Mirrors the ON DELETE CASCADE used by
		// the other user_id tables.
		`DELETE FROM revoked_tokens WHERE user_id NOT IN (SELECT id FROM users);
		CREATE TABLE revoked_tokens_new (
			jti TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		INSERT INTO revoked_tokens_new (jti, user_id, expires_at, revoked_at) SELECT jti, user_id, expires_at, revoked_at FROM revoked_tokens;
		DROP TABLE revoked_tokens;
		ALTER TABLE revoked_tokens_new RENAME TO revoked_tokens;
		CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at)`,
		// OpenID Connect / OAuth2: link table mapping an external identity
		// (issuer, subject) to a local GoZone user. A single user may be linked
		// to several providers (one row per issuer), and each (issuer, subject)
		// pair maps to at most one local user. The issuer column stores the IdP
		// issuer URL as reported in the ID token "iss" claim, NOT the provider
		// name, so renaming a configured provider does not break the linkage.
		`CREATE TABLE IF NOT EXISTS external_identities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			issuer TEXT NOT NULL,
			subject TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (issuer, subject),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_external_identities_issuer_subject ON external_identities(issuer, subject)`,
		// Session lifetime tracking (idle/absolute enforcement). Shared state so
		// multi-instance deployments enforce the same idle/absolute window: each
		// instance throttled-writes last_seen here and reads other instances'
		// activity on a cache miss. Purged by expires_at.
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id TEXT PRIMARY KEY,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		// Case-insensitive email lookup for SSO account
		// linking (FindUserByEmail). A generated lowercased email column + index
		// lets the lookup use an equality seek (email_lc = LOWER(?)) instead of
		// wrapping the indexed column in LOWER(), which defeated the UNIQUE
		// index and forced a full scan on MySQL/PostgreSQL. SQLite ALTER TABLE
		// ADD COLUMN only supports VIRTUAL generated columns (STORED is
		// rejected); VIRTUAL generated columns are indexable.
		`ALTER TABLE users ADD COLUMN email_lc TEXT GENERATED ALWAYS AS (LOWER(email)) VIRTUAL`,
		`CREATE INDEX IF NOT EXISTS idx_users_email_lc ON users(email_lc)`,
		// Per-user session-revocation cutoff. An access token
		// whose iat predates tokens_valid_after is rejected by the Auth
		// middleware, so a password change/reset or an account disable
		// invalidates every outstanding session (incl. a stolen JWT) without
		// tracking active jtis. Epoch default keeps existing sessions valid on
		// upgrade — the column is only bumped to now at credential-changing
		// events.
		`ALTER TABLE users ADD COLUMN tokens_valid_after DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00'`,
		// Distinct marker for an admin-imposed manual lock. The login path
		// honours manual_lock_until unconditionally, while the automatic brute-force locked_until is only enforced when
		// max_failed_attempts > 0 — so disabling the auto lockout (0) no longer
		// de-enforces an existing manual lock. AdminLockUser sets both columns
		// to the same expiry so the existing locked_until-based display and
		// UserLockStatus keep working unchanged.
		`ALTER TABLE users ADD COLUMN manual_lock_until DATETIME`,
		// Server-side storage of SSO ID tokens for RP-initiated logout
		// (id_token_hint). Keycloak-like IdPs require the hint at their
		// end_session_endpoint, but the ID token can exceed what fits in the
		// ~4 KiB session cookie (many realm roles/groups), so the hint is
		// persisted keyed by the session ID instead. Purged by expires_at
		// (aligned with the session's maximum possible lifetime).
		`CREATE TABLE IF NOT EXISTS sso_id_tokens (
			session_id TEXT PRIMARY KEY,
			id_token TEXT NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sso_id_tokens_expires_at ON sso_id_tokens(expires_at)`,
		// Cluster-wide fixed-window rate-limit counters. One row per
		// (bucket, window): the shared primary key makes the counter durable
		// across instances, so the login rate limits no longer scale with the
		// replica count. hits starts at 0 so the incrementing UPDATE below can
		// run unconditionally after the INSERT OR IGNORE seeding. Purged by
		// the hourly background job (windows are one minute wide; anything
		// older than a few minutes is dead).
		`CREATE TABLE IF NOT EXISTS rate_limit_counters (
			bucket_key TEXT NOT NULL,
			window_start DATETIME NOT NULL,
			hits INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_key, window_start)
		)`,
		// Case-insensitive uniqueness for username and email. The plain
		// UNIQUE constraints are binary (case-sensitive) on SQLite, so
		// "Alice" and "alice" could coexist while Login looked them up via
		// the lowercased form — the lookup then picked a row at random and
		// failed attempts locked the wrong account. Generated lowercased
		// columns carry UNIQUE indexes, which both enforce the folded
		// uniqueness and let the equality lookups seek. On a database that
		// already holds case-duplicates the index creation fails loudly at
		// startup: dedupe first with e.g.
		//   SELECT LOWER(username), COUNT(*) FROM users GROUP BY LOWER(username) HAVING COUNT(*) > 1;
		`ALTER TABLE users ADD COLUMN username_lc TEXT GENERATED ALWAYS AS (LOWER(username)) VIRTUAL`,
		`DROP INDEX IF EXISTS idx_users_email_lc`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lc ON users(username_lc)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lc ON users(email_lc)`,
	}
}

package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Pool-tuning defaults for network databases (MySQL/PostgreSQL). SQLite uses
// its own single-connection values (see sqliteDialect).
const (
	// defaultMaxIdleConns is the idle pool size. It matches MaxOpenConns (25)
	// so the pool stays warm under typical load instead of churning
	// connections open/close on every burst.
	defaultMaxIdleConns = 25
	// defaultConnMaxLifetime caps how long a connection is reused before being
	// recycled. Network databases sit behind TCP, load balancers and proxies
	// (PgBouncer, ProxySQL, cloud RDS proxies) that silently drop idle or
	// long-lived connections; recycling proactively avoids "connection killed"
	// errors mid-request. 30 minutes is well under MySQL's default wait_timeout
	// (8h) and typical LB idle timeouts, while being long enough to amortize
	// the TLS/auth handshake cost.
	defaultConnMaxLifetime = 30 * time.Minute
)

type Dialect interface {
	DriverName() string
	DSN(dsn string) string
	Migrations() []string
	MaxOpenConns() int
	// MaxIdleConns returns the maximum number of idle connections retained in
	// the pool. It must be <= MaxOpenConns for the dialect (database/sql clamps
	// it otherwise). See REVIEW.md m16.
	MaxIdleConns() int
	// ConnMaxLifetime returns the maximum amount of time a connection may be
	// reused before being closed and replaced. A zero value means connections
	// are reused forever (appropriate for the single local SQLite connection).
	// See REVIEW.md m16.
	ConnMaxLifetime() time.Duration
	Rebind(query string) string
	// TimestampType returns the dialect-specific SQL column type for
	// timestamps. PostgreSQL uses TIMESTAMP (it has no DATETIME type);
	// SQLite and MySQL use DATETIME.
	TimestampType() string
	// InsertIgnore returns an INSERT statement that silently skips rows which
	// would violate a unique constraint, using dialect-specific syntax.
	//
	// columns lists the INSERT column list and the bound parameter order.
	// conflictColumns lists the columns that form the conflict target —
	// typically the columns covered by a PRIMARY KEY or UNIQUE constraint
	// on the target table. PostgreSQL requires this target to match an
	// existing unique index exactly; for SQLite and MySQL the parameter is
	// ignored because INSERT OR IGNORE / INSERT IGNORE catch any unique
	// violation regardless of column. Callers must pass conflictColumns
	// explicitly so the Postgres dialect cannot silently fall back to the
	// wrong index when columns != unique constraint.
	InsertIgnore(table string, columns, conflictColumns []string) string
	// LockMigrations acquires a cluster-wide lock so that only one instance
	// runs migrations at a time. The returned release function must be called
	// when migrations are finished.
	LockMigrations(conn *sql.DB) (release func(), err error)
	// IsAlreadyExistsError reports whether err indicates a DDL operation tried
	// to create an object (column, table, index, constraint) that already
	// exists. The migration runner uses this to tolerate re-running a
	// previously-applied migration whose content — and therefore content hash —
	// changed (e.g. a typo fix), so a non-idempotent ALTER TABLE ADD COLUMN no
	// longer aborts startup. See REVIEW.md m22.
	IsAlreadyExistsError(err error) bool
}

// placeholders returns a comma-separated list of n question-mark placeholders.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("?")
	}
	return b.String()
}

func selectDialect(driver string) (Dialect, error) {
	switch driver {
	case "sqlite3":
		return &sqliteDialect{}, nil
	case "mysql", "mariadb":
		return &mysqlDialect{}, nil
	case "postgres", "postgresql":
		return &postgresDialect{}, nil
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}
}

func rebindDollar(query string) string {
	var out strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			out.WriteString(fmt.Sprintf("$%d", n))
		} else {
			out.WriteRune(c)
		}
	}
	return out.String()
}

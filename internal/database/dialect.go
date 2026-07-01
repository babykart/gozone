package database

import (
	"database/sql"
	"fmt"
	"strings"
)

type Dialect interface {
	DriverName() string
	DSN(dsn string) string
	Migrations() []string
	MaxOpenConns() int
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

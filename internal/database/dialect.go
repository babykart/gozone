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
	// LockMigrations acquires a cluster-wide lock so that only one instance
	// runs migrations at a time. The returned release function must be called
	// when migrations are finished.
	LockMigrations(conn *sql.DB) (release func(), err error)
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

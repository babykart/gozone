package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/babykart/gozone/internal/config"
)

// newTestDB returns a dialect-agnostic test database: in-memory SQLite by
// default, or a per-test database on the live server named by
// GOZONE_TEST_DB_DRIVER/GOZONE_TEST_DB_DSN (the variables the CI
// test-mysql/test-postgres jobs export alongside the dbmatrix tag). Routing
// the generic data-path suites through it is what lets them join the
// dialect matrix — the SQLite-only hard-coding is exactly how a
// MySQL-incompatible statement once shipped green.
//
// This mirrors testutil.NewTestDB/NewTestDBDialect rather than calling it:
// testutil imports this package, so its internal test files cannot import
// testutil back (import cycle in test).
func newTestDB(t *testing.T) *DB {
	t.Helper()
	driver := os.Getenv("GOZONE_TEST_DB_DRIVER")
	dsn := os.Getenv("GOZONE_TEST_DB_DSN")
	if driver == "" || dsn == "" || driver == "sqlite3" {
		db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() }) // #nosec G104
		return db
	}
	return newLiveTestDB(t, driver, dsn)
}

// newLiveTestDB provisions a uniquely named database on the server behind
// dsn, migrates it and returns a ready handle; the database is dropped when
// the test finishes.
func newLiveTestDB(t *testing.T, driver, dsn string) *DB {
	t.Helper()

	var adminDriver string
	var withDB func(dsn, db string) (string, error)
	switch driver {
	case "mysql", "mariadb":
		adminDriver = "mysql"
		withDB = mysqlTestDSNWithDB
	case "postgres", "postgresql":
		adminDriver = "postgres"
		withDB = postgresTestDSNWithDB
	default:
		t.Fatalf("unsupported dialect test driver %q (use mysql or postgres)", driver)
	}

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("generate database name: %v", err)
	}
	name := "gozone_test_" + hex.EncodeToString(buf[:])

	// CREATE/DROP DATABASE cannot use query placeholders on any driver; the
	// identifier is crypto/rand hex, never from caller input.
	admin, err := sql.Open(adminDriver, dsn)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE %s", name)); err != nil { // #nosec G201 -- name is crypto/rand hex, not user input; identifiers cannot be parameterized
		t.Fatalf("create database %s: %v", name, err)
	}
	if err := admin.Close(); err != nil { // #nosec G104 -- best-effort cleanup, creation already succeeded
		t.Logf("close admin connection: %v", err)
	}
	t.Cleanup(func() {
		drop, err := sql.Open(adminDriver, dsn)
		if err != nil {
			t.Logf("open drop connection for %s: %v", name, err)
			return
		}
		defer drop.Close()                                                                    // #nosec G104 -- best-effort cleanup
		if _, err := drop.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", name)); err != nil { // #nosec G201 -- name is crypto/rand hex, not user input
			t.Logf("drop database %s: %v", name, err)
		}
	})

	testDSN, err := withDB(dsn, name)
	if err != nil {
		t.Fatal(err)
	}
	db, err := New(&config.DatabaseConfig{Driver: driver, DSN: testDSN})
	if err != nil {
		t.Fatalf("open %s test database: %v", driver, err)
	}
	t.Cleanup(func() { db.Close() }) // #nosec G104
	return db
}

// mysqlTestDSNWithDB replaces the database name of a go-sql-driver DSN.
func mysqlTestDSNWithDB(dsn, db string) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("parse MySQL DSN: %w", err)
	}
	cfg.DBName = db
	return cfg.FormatDSN(), nil
}

// postgresTestDSNWithDB replaces the database name of a URL-style
// PostgreSQL DSN (lib/pq also accepts key=value strings, but rewriting
// those reliably is not worth the complexity — pass a URL-form DSN).
func postgresTestDSNWithDB(dsn, db string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("postgres DSN must be URL-style (postgres://user:pass@host:port/db), got %q", dsn)
	}
	u.Path = "/" + db
	return u.String(), nil
}

//go:build dbmatrix

// Dialect-matrix build: when GOZONE_TEST_DB_DRIVER and GOZONE_TEST_DB_DSN
// are both set, every NewTestDB call is redirected to NewTestDBDialect, so
// the entire suite (not just the database-package integration tests) runs
// against a live MySQL or PostgreSQL server. The build tag keeps the
// redirection opt-in: plain `go test ./...` on a developer machine ignores
// the environment variables entirely and stays on in-memory SQLite.
package testutil

import (
	"os"
	"testing"
)

// testDBDialectOverride reports the dialect/DSN a NewTestDB call should use
// instead of in-memory SQLite, from GOZONE_TEST_DB_DRIVER/GOZONE_TEST_DB_DSN.
func testDBDialectOverride(t *testing.T) (driver, dsn string, ok bool) {
	t.Helper()
	driver = os.Getenv("GOZONE_TEST_DB_DRIVER")
	dsn = os.Getenv("GOZONE_TEST_DB_DSN")
	if driver == "" || dsn == "" {
		return "", "", false
	}
	return driver, dsn, true
}

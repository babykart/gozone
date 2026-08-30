//go:build !dbmatrix

// Default build (no dbmatrix tag): the dialect override hook is inert, so
// NewTestDB always builds an in-memory SQLite database — identical behavior
// to before the dialect matrix existed.
package testutil

import "testing"

// testDBDialectOverride reports the dialect/DSN a NewTestDB call should use
// instead of in-memory SQLite. Always nil in default builds; see
// dbmatrix_on.go for the tagged variant.
func testDBDialectOverride(t *testing.T) (driver, dsn string, ok bool) {
	return "", "", false
}

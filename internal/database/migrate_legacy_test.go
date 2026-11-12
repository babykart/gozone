package database

import (
	"context"
	"strings"
	"testing"
)

// TestMigrateOldVersions_OutOfRangeLegacyVersionFails pins the fail-closed
// behavior of migrateOldVersions on a legacy vNNN row whose index exceeds
// the migrations slice: silently skipping it would leave a version row that
// claims a migration was applied while the tracking no longer maps to any
// real migration. The conversion must abort with an error naming the
// offending version, and the row must be left untouched for inspection.
//
// The in-range conversion path is covered by TestMigrate_LegacyVersionsMigrated
// (database_test.go), which converts v000/v001/v002 through the full migrate.
func TestMigrateOldVersions_OutOfRangeLegacyVersionFails(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"INSERT INTO schema_migrations (version) VALUES ('v999')"); err != nil {
		t.Fatalf("insert legacy version row: %v", err)
	}

	err := db.migrateOldVersions()
	if err == nil {
		t.Fatal("migrateOldVersions must fail on an out-of-range legacy version, got nil")
	}
	if !strings.Contains(err.Error(), "v999") {
		t.Errorf("error %q must name the offending legacy version v999", err)
	}

	var version string
	if err := db.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations WHERE version = 'v999'").Scan(&version); err != nil {
		t.Errorf("out-of-range legacy row must be left untouched: %v", err)
	}
}

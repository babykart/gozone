package cmd

import (
	"errors"
	"testing"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
)

// TestUserMigrateOpenerRouting pins WHICH opener the `gozone user` emergency
// commands use: by default they must open via the non-migrating opener
// (a newer emergency binary must not silently migrate the production DB);
// with the explicit --migrate flag they must open via the migrating one.
//
// The routing is observed through sentinel errors: both opener vars are
// swapped for stubs that fail with a distinguishable error, and the test
// asserts which sentinel the command surfaces. The commands' database effects
// are covered by the resetaudit suite; the migration behavior of each
// constructor is pinned in internal/database (TestNewWithoutMigrations_
// DoesNotRunMigrations and the migrate() tests).
func TestUserMigrateOpenerRouting(t *testing.T) {
	errOpenDefault := errors.New("sentinel: non-migrating opener selected")
	errOpenMigrate := errors.New("sentinel: migrating opener selected")

	tests := []struct {
		name        string
		subCmd      string
		withMigrate bool
		want        error
	}{
		{"unlock/default_no_migrate", "unlock", false, errOpenDefault},
		{"unlock/migrate_flag", "unlock", true, errOpenMigrate},
		{"reset-password/default_no_migrate", "reset-password", false, errOpenDefault},
		{"reset-password/migrate_flag", "reset-password", true, errOpenMigrate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgPath, _ := writeUnlockTestConfig(t)

			origOpen, origMigrate := openDB, openDBMigrate
			t.Cleanup(func() { openDB, openDBMigrate = origOpen, origMigrate })
			openDB = func(*config.DatabaseConfig) (*database.DB, error) {
				return nil, errOpenDefault
			}
			openDBMigrate = func(*config.DatabaseConfig) (*database.DB, error) {
				return nil, errOpenMigrate
			}

			args := []string{"--config", cfgPath}
			if tt.withMigrate {
				args = append(args, "--migrate")
			}
			if tt.subCmd == "reset-password" {
				args = append(args, "--password", "newpass-secret")
			}
			args = append(args, "admin")

			var err error
			if tt.subCmd == "unlock" {
				err = executeUnlock(args...)
			} else {
				err = executeResetPassword(args...)
			}
			if err == nil {
				t.Fatal("expected the sentinel error from the stubbed opener")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("opener routing mismatch: got %v, want it to wrap %v", err, tt.want)
			}
		})
	}
}

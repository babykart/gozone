package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
)

// writeUnlockTestConfig writes a minimal config file pointing at a fresh
// file-based SQLite (`:memory:` would be a separate DB on every sql.Open,
// so we use a tmpfile the test cleanup removes).
func writeUnlockTestConfig(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "test.db")
	cfgPath = filepath.Join(dir, "config.yaml")
	cfg := `
database:
  driver: sqlite3
  dsn: "` + dbPath + `"
auth:
  bcrypt_cost: 4
login_lock:
  max_failed_attempts: 10
  lockout_duration_minutes: 15
admin:
  username: admin
  password: admin
  email: admin@test.local
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath
}

// openUnlockTestDB opens the configured database and seeds the admin user
// using SeedAdminUser, then returns the handle. Tests use this to set up
// state without launching the HTTP server.
func openUnlockTestDB(t *testing.T, cfgPath string) *database.DB {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	db, err := database.New(&cfg.Database)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return db
}

func TestRunUnlock_MissingUserFlag(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	err := runUnlock([]string{"-config", cfgPath})
	if err == nil {
		t.Fatal("expected error for missing --user")
	}
	if !strings.Contains(err.Error(), "--user is required") {
		t.Errorf("expected --user required error, got: %v", err)
	}
}

func TestRunUnlock_UserNotFound(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)
	_ = db // just to seed

	err := runUnlock([]string{"-config", cfgPath, "-user", "ghost"})
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestRunUnlock_ByID(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}
	if err := db.AdminLockUser(context.Background(), adminID, 60_000_000_000); err != nil { // 1 minute
		t.Fatalf("pre-lock: %v", err)
	}

	if err := runUnlock([]string{"-config", cfgPath, "-user", "1"}); err != nil {
		t.Fatalf("runUnlock: %v", err)
	}

	locked, _, err := db.UserLockStatus(context.Background(), adminID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected user to be unlocked after runUnlock")
	}
	var count int
	if err := db.QueryRowContext(context.Background(),
		"SELECT failed_login_attempts FROM users WHERE id = ?", adminID).Scan(&count); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if count != 0 {
		t.Errorf("expected counter=0 after unlock, got %d", count)
	}
}

func TestRunUnlock_ByUsername(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}
	if err := db.AdminLockUser(context.Background(), adminID, 60_000_000_000); err != nil {
		t.Fatalf("pre-lock: %v", err)
	}

	if err := runUnlock([]string{"-config", cfgPath, "-user", "admin"}); err != nil {
		t.Fatalf("runUnlock: %v", err)
	}

	locked, _, err := db.UserLockStatus(context.Background(), adminID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected admin to be unlocked by username lookup")
	}
}

func TestRunUnlock_LogsActivity(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}
	if err := db.AdminLockUser(context.Background(), adminID, 60_000_000_000); err != nil {
		t.Fatalf("pre-lock: %v", err)
	}

	if err := runUnlock([]string{"-config", cfgPath, "-user", "admin"}); err != nil {
		t.Fatalf("runUnlock: %v", err)
	}

	var (
		logUserID  sql.NullInt64
		logAction  string
		logDetails string
	)
	if err := db.QueryRowContext(context.Background(),
		"SELECT user_id, action, details FROM activity_logs WHERE action='unlock_user_cli'").Scan(
		&logUserID, &logAction, &logDetails); err != nil {
		t.Fatalf("query activity: %v", err)
	}

	// user_id must be NULL — the actor is the shell operator, not a GoZone
	// user (m4). Logging the unlocked user's ID here falsely attributed the
	// action to the victim.
	if logUserID.Valid {
		t.Errorf("expected user_id NULL (operator is not a GoZone user), got %d", logUserID.Int64)
	}

	// Details must mention the operator identity (username@hostname).
	if !strings.Contains(logDetails, "operator") {
		t.Errorf("details should mention the operator, got %q", logDetails)
	}
}

func TestRun_RoutesToUnlock(t *testing.T) {
	// Verify the main run() dispatcher picks up the "unlock" subcommand.
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}
	if err := db.AdminLockUser(context.Background(), adminID, 60_000_000_000); err != nil {
		t.Fatalf("pre-lock: %v", err)
	}

	if err := run([]string{"unlock", "-config", cfgPath, "-user", "admin"}); err != nil {
		t.Fatalf("run unlock: %v", err)
	}

	locked, _, err := db.UserLockStatus(context.Background(), adminID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected admin unlocked after run(unlock ...)")
	}
}

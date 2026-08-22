package database

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/logger"
	"golang.org/x/crypto/bcrypt"
)

// captureLog redirects os.Stderr to a pipe, reinitialises the logger to write
// to that pipe, runs fn, then restores both. Returns the captured log output.
// Must NOT be called from parallel tests — it mutates global logger state.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = pw
	logger.Init("info")
	fn()
	pw.Close()
	os.Stderr = oldStderr
	logger.Init("info")
	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

func TestSeedAdminUser_DefaultPasswordWarning(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4

	out := captureLog(t, func() {
		if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "CHANGE THE DEFAULT ADMIN PASSWORD IMMEDIATELY") {
		t.Error("expected default-password warning in log output, got: " + out)
	}
}

func TestSeedAdminUser_CustomPasswordNoWarning(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4
	cfg.Admin.Password = "my-secure-password-123"

	out := captureLog(t, func() {
		if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
			t.Fatal(err)
		}
	})

	if strings.Contains(out, "CHANGE THE DEFAULT ADMIN PASSWORD IMMEDIATELY") {
		t.Error("unexpected default-password warning when custom password is set")
	}
}

func TestSeedAdminUser_FirstStartup(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4

	if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 user, got %d", count)
	}

	var username, email, firstName, lastName, role string
	var passwordHash string
	if err := db.QueryRow(
		"SELECT username, email, first_name, last_name, password_hash, role FROM users WHERE id=1",
	).Scan(&username, &email, &firstName, &lastName, &passwordHash, &role); err != nil {
		t.Fatal(err)
	}
	if username != "admin" {
		t.Errorf("expected admin, got %s", username)
	}
	if email != "admin@gozone.local" {
		t.Errorf("expected admin@gozone.local, got %s", email)
	}
	if firstName != "Admin" {
		t.Errorf("expected Admin, got %s", firstName)
	}
	if lastName != "User" {
		t.Errorf("expected User, got %s", lastName)
	}
	if role != "admin" {
		t.Errorf("expected admin role, got %s", role)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("admin")); err != nil {
		t.Errorf("default password should be admin: %v", err)
	}
}

func TestSeedAdminUser_ExistingUsers(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4

	// First seed
	if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatal(err)
	}

	// Second seed should be a no-op
	if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected still 1 user, got %d", count)
	}
}

func TestSeedAdminUser_EnvVarOverride(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	t.Setenv("GOZONE_ADMIN_PASSWORD", "custom-secret")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.BcryptCost = 4

	if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatal(err)
	}

	var passwordHash string
	if err := db.QueryRow(
		"SELECT password_hash FROM users WHERE id=1",
	).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("custom-secret")); err != nil {
		t.Errorf("password should match GOZONE_ADMIN_PASSWORD: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("admin")); err == nil {
		t.Error("default password should NOT match when env var is set")
	}
}

func TestSeedAdminUser_CustomConfig(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4
	cfg.Admin.Username = "root"
	cfg.Admin.Password = "custom-pass"
	cfg.Admin.Email = "root@example.com"
	cfg.Admin.FirstName = "Super"
	cfg.Admin.LastName = "Admin"

	if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatal(err)
	}

	var username, email, firstName, lastName, role string
	var passwordHash string
	if err := db.QueryRow(
		"SELECT username, email, first_name, last_name, password_hash, role FROM users WHERE id=1",
	).Scan(&username, &email, &firstName, &lastName, &passwordHash, &role); err != nil {
		t.Fatal(err)
	}

	if username != "root" {
		t.Errorf("expected root, got %s", username)
	}
	if email != "root@example.com" {
		t.Errorf("expected root@example.com, got %s", email)
	}
	if firstName != "Super" {
		t.Errorf("expected Super, got %s", firstName)
	}
	if lastName != "Admin" {
		t.Errorf("expected Admin, got %s", lastName)
	}
	if role != "admin" {
		t.Errorf("expected admin role, got %s", role)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("custom-pass")); err != nil {
		t.Errorf("password should match custom-pass: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("admin")); err == nil {
		t.Error("default password should NOT match when custom is set")
	}
}

func TestSeedAdminUser_RecordsPasswordHistory(t *testing.T) {
	// REVIEW.md L-15a: the seed password hash must be recorded in
	// password_history even when history is disabled (HistorySize == 0), so
	// that enabling history later catches a revert to the seed password.
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4
	if cfg.Password.HistorySize != 0 {
		t.Fatalf("precondition: expected default HistorySize 0, got %d", cfg.Password.HistorySize)
	}

	if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatal(err)
	}

	var pwHash string
	var adminID int64
	if err := db.QueryRow(
		"SELECT id, password_hash FROM users WHERE username = ?", cfg.Admin.Username,
	).Scan(&adminID, &pwHash); err != nil {
		t.Fatalf("read admin: %v", err)
	}

	var n int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM password_history WHERE user_id = ?", adminID,
	).Scan(&n); err != nil {
		t.Fatalf("count password_history: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 password_history row for seed admin, got %d", n)
	}
	var histHash string
	if err := db.QueryRow(
		"SELECT password_hash FROM password_history WHERE user_id = ?", adminID,
	).Scan(&histHash); err != nil {
		t.Fatalf("read password_history hash: %v", err)
	}
	if histHash != pwHash {
		t.Error("password_history hash must match the seed admin password_hash")
	}
}

func TestSeedAdminUser_ConcurrentBootstrapIsIdempotent(t *testing.T) {
	// REVIEW.md L-15b: two instances starting concurrently on a fresh database
	// must not race — InsertIgnore turns the loser's insert into a silent
	// no-op instead of aborting with ErrUniqueViolation. SQLite serializes
	// writers (MaxOpenConns == 1) so the real race window only reproduces on
	// MySQL/PostgreSQL, but the test still guards idempotency and duplicate
	// avoidance under concurrent invocation (mirrors the M-2 approach).
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4

	const n = 20
	errs := make(chan error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			errs <- SeedAdminUser(context.Background(), db, cfg)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent SeedAdminUser returned error: %v", err)
		}
	}

	var userCount, histCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM password_history").Scan(&histCount); err != nil {
		t.Fatalf("count password_history: %v", err)
	}
	if userCount != 1 {
		t.Errorf("expected exactly 1 user after concurrent bootstrap, got %d", userCount)
	}
	if histCount != 1 {
		t.Errorf("expected exactly 1 password_history row after concurrent bootstrap, got %d", histCount)
	}
}

// TestSeedAdminUser_PasswordChangedAtSet locks the age anchor of the bootstrap
// password: the seed INSERT must record password_changed_at explicitly so
// password expiry (password.max_age_days) applies to the initial admin from
// the first login — the account most likely to still carry the default
// password must not be the one exempt from ageing. The value was previously
// filled only by the schema-level column DEFAULT, an implicit mechanism no
// test verified. must_change_password stays 0: forcing a change on first
// login is a separate, deliberate bootstrap exemption.
func TestSeedAdminUser_PasswordChangedAtSet(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4
	before := time.Now().UTC()
	if err := SeedAdminUser(context.Background(), db, cfg); err != nil {
		t.Fatal(err)
	}

	var changedAt time.Time
	var mustChange int
	if err := db.QueryRow(
		"SELECT password_changed_at, must_change_password FROM users WHERE username = 'admin'",
	).Scan(&changedAt, &mustChange); err != nil {
		t.Fatalf("select seeded admin: %v", err)
	}
	if changedAt.IsZero() {
		t.Fatal("seeded admin must carry a password_changed_at value so the bootstrap password ages")
	}
	if d := changedAt.Sub(before); d < 0 || d > 5*time.Minute {
		t.Errorf("password_changed_at = %v, want ~now UTC (seeded between %v and now, skew %v)", changedAt, before, d)
	}
	if mustChange != 0 {
		t.Errorf("bootstrap exemption: must_change_password = %d, want 0", mustChange)
	}
}

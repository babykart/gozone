package database

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

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

	os.Setenv("GOZONE_ADMIN_PASSWORD", "custom-secret")
	defer os.Unsetenv("GOZONE_ADMIN_PASSWORD")

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

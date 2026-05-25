package database

import (
	"os"
	"testing"

	"github.com/babykart/gozone/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestSeedAdminUser_FirstStartup(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4

	if err := SeedAdminUser(db, cfg); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 user, got %d", count)
	}

	var username, role string
	var passwordHash string
	if err := db.QueryRow(
		"SELECT username, password_hash, role FROM users WHERE id=1",
	).Scan(&username, &passwordHash, &role); err != nil {
		t.Fatal(err)
	}
	if username != "admin" {
		t.Errorf("expected admin, got %s", username)
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
	if err := SeedAdminUser(db, cfg); err != nil {
		t.Fatal(err)
	}

	// Second seed should be a no-op
	if err := SeedAdminUser(db, cfg); err != nil {
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

	cfg := config.DefaultConfig()
	cfg.Auth.BcryptCost = 4

	if err := SeedAdminUser(db, cfg); err != nil {
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

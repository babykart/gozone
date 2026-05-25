package database

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/logger"
)

// SeedAdminUser creates an admin user if no users exist in the database.
//
// The default credentials are admin/admin. The password can be overridden
// via the GOZONE_ADMIN_PASSWORD environment variable.
//
// The bcrypt cost is taken from cfg.Auth.BcryptCost.
//
// Returns an error if the database query or user insertion fails.
func SeedAdminUser(db *DB, cfg *config.Config) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("seed admin: count users: %w", err)
	}
	if count > 0 {
		return nil
	}

	password := os.Getenv("GOZONE_ADMIN_PASSWORD")
	if password == "" {
		password = "admin"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cfg.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("seed admin: hash password: %w", err)
	}

	_, err = db.Exec(
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"admin", "admin@gozone.local", string(hash), "Admin", "User", "admin",
	)
	if err != nil {
		return fmt.Errorf("seed admin: insert user: %w", err)
	}

	logger.Info("seeded admin user", "username", "admin")
	logger.Warn("CHANGE THE DEFAULT ADMIN PASSWORD IMMEDIATELY")
	return nil
}

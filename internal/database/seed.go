package database

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/logger"
)

// SeedAdminUser creates an admin user if no users exist in the database.
//
// The admin credentials are taken from cfg.Admin (username, password, email,
// first_name, last_name). These can be configured via config.yaml or the
// GOZONE_ADMIN_* environment variables.
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

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.Admin.Password), cfg.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("seed admin: hash password: %w", err)
	}

	_, err = db.Exec(
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		cfg.Admin.Username, cfg.Admin.Email, string(hash),
		cfg.Admin.FirstName, cfg.Admin.LastName, "admin",
	)
	if err != nil {
		return fmt.Errorf("seed admin: insert user: %w", err)
	}

	logger.Info("seeded admin user", "username", cfg.Admin.Username)
	logger.Warn("CHANGE THE DEFAULT ADMIN PASSWORD IMMEDIATELY")
	return nil
}

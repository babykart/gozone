package database

import (
	"context"
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
// The insert is idempotent and race-safe: a COUNT(*) fast-path skips the
// expensive bcrypt hash on an already-populated database, and the actual
// insert uses InsertIgnore so two instances starting concurrently on a fresh
// database no longer race — the loser's insert becomes a silent no-op instead
// of aborting startup with ErrUniqueViolation (REVIEW.md L-15b).
//
// The seed password hash is recorded in password_history unconditionally
// (not gated on password.history_size): history may be disabled at bootstrap
// and enabled later, and the seed password must be present so reverting to it
// is caught as a reuse at that point. This is the only password-set site that
// records without the HistorySize > 0 gate, justified by the one-time
// bootstrap nature; the row is harmless while history is disabled and is
// pruned to history_size on the next password change once enabled
// (REVIEW.md L-15a).
//
// Returns an error if the database query or user insertion fails.
func SeedAdminUser(ctx context.Context, db *DB, cfg *config.Config) error {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("seed admin: count users: %w", err)
	}
	if count > 0 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.Admin.Password), cfg.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("seed admin: hash password: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("seed admin: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// InsertIgnore makes the bootstrap idempotent across instances: the
	// advisory migration lock is no longer held here, so two instances could
	// both pass the COUNT==0 fast-path above. A plain INSERT would abort the
	// loser with ErrUniqueViolation; InsertIgnore turns that into a silent
	// no-op (RowsAffected == 0). The conflict target is the UNIQUE(username)
	// constraint — the race always seeds the same admin (REVIEW.md L-15b).
	res, err := tx.InsertIgnore(ctx, "users",
		[]string{"username", "email", "password_hash", "first_name", "last_name", "role"},
		[]string{"username"},
		cfg.Admin.Username, cfg.Admin.Email, string(hash),
		cfg.Admin.FirstName, cfg.Admin.LastName, "admin",
	)
	if err != nil {
		return fmt.Errorf("seed admin: insert user: %w", err)
	}

	inserted, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("seed admin: rows affected: %w", err)
	}
	if inserted == 0 {
		// Another instance won the bootstrap race; nothing to record.
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("seed admin: commit (no-op): %w", err)
		}
		committed = true
		return nil
	}

	// Look up the new admin id portably: InsertIgnore cannot return the id on
	// the skip path (and LastInsertId is unsupported by lib/pq — REVIEW.md
	// H-1), so a targeted SELECT by the UNIQUE username is the portable
	// choice on the insert path.
	var adminID int64
	if err := tx.QueryRowContext(ctx,
		"SELECT id FROM users WHERE username = ?", cfg.Admin.Username,
	).Scan(&adminID); err != nil {
		return fmt.Errorf("seed admin: read new admin id: %w", err)
	}
	if err := tx.RecordPassword(ctx, adminID, string(hash)); err != nil {
		return fmt.Errorf("seed admin: record password history: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("seed admin: commit: %w", err)
	}
	committed = true

	logger.Info("seeded admin user", "username", cfg.Admin.Username)
	// Only warn when the admin was seeded with the built-in default password;
	// a custom password set via config.yaml or GOZONE_ADMIN_PASSWORD is fine.
	if cfg.Admin.Password == config.DefaultAdminPassword {
		logger.Warn("CHANGE THE DEFAULT ADMIN PASSWORD IMMEDIATELY")
	}
	return nil
}

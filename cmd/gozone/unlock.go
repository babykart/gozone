package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
)

// newUnlockCmd builds the `gozone unlock` emergency CLI.
//
// Usage:
//
//	gozone unlock --user <id|username> [--config <path>]
//
// It opens the configured database, resolves the user (by numeric ID or
// username), clears their lockout and failed-login counter, then exits.
// Designed for operators who have shell access to the host but lost the
// admin password or got themselves locked out by a brute-force storm —
// the web UI alone is not enough to recover.
func newUnlockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "unlock",
		Short:         "Clear a user's account lockout (emergency recovery)",
		Long:          "Clears the lockout and failed-login counter of a GoZone user directly in the database, bypassing the HTTP flow. Used when all admin accounts are locked and the Web UI is unreachable.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return fmt.Errorf("read --config flag: %w", err)
			}
			userFlag, err := cmd.Flags().GetString("user")
			if err != nil {
				return fmt.Errorf("read --user flag: %w", err)
			}
			if userFlag == "" {
				return fmt.Errorf("--user is required (use --user <id> or --user <username>)")
			}

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("load configuration: %w", err)
			}
			return unlockUser(cfg, userFlag)
		},
	}
	cmd.Flags().StringP("user", "u", "", "user ID or username to unlock (required)")
	return cmd
}

// unlockUser resolves the target user (by numeric ID or username), clears
// their lockout, and records an audit entry attributing the action to the
// shell operator (not a GoZone user).
func unlockUser(cfg *config.Config, userFlag string) error {
	logger.Init(cfg.Logging.Level)

	db, err := database.New(&cfg.Database)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		userID     int64
		username   string
		resolveErr error
	)
	if id, perr := strconv.ParseInt(userFlag, 10, 64); perr == nil && id > 0 {
		userID = id
		resolveErr = db.QueryRowContext(ctx,
			`SELECT username FROM users WHERE id = ?`,
			id,
		).Scan(&username)
		if resolveErr != nil {
			if resolveErr == sql.ErrNoRows {
				return fmt.Errorf("user id=%d not found", id)
			}
			return fmt.Errorf("lookup user id=%d: %w", id, resolveErr)
		}
	} else {
		// Username lookup — case-insensitive; the Login handler does the same.
		resolveErr = db.QueryRowContext(ctx,
			`SELECT id, username FROM users WHERE lower(username) = lower(?)`,
			userFlag,
		).Scan(&userID, &username)
		if resolveErr != nil {
			if resolveErr == sql.ErrNoRows {
				return fmt.Errorf("user %q not found", userFlag)
			}
			return fmt.Errorf("lookup user %q: %w", userFlag, resolveErr)
		}
	}

	logger.Info("unlocking user via CLI", "user_id", userID, "username", username)

	if err := db.AdminUnlockUser(ctx, userID); err != nil {
		return fmt.Errorf("unlock user %d: %w", userID, err)
	}

	// Log with user_id=NULL: the actor is the shell operator, not a GoZone
	// user. Capture the OS identity (username@hostname) for audit (m4).
	if _, err := db.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (NULL, 'unlock_user_cli', ?)",
		fmt.Sprintf("Unlocked user id=%d username=%q by CLI operator %s", userID, username, operatorIdentity()),
	); err != nil {
		// Best-effort: the unlock itself succeeded, so we don't fail the CLI.
		logger.Warn("failed to log CLI unlock activity", "user_id", userID, "error", err)
	}

	logger.Info("user unlocked", "user_id", userID, "username", username)
	return nil
}

// operatorIdentity returns a string identifying the shell user running the
// CLI, for audit purposes. Best-effort: falls back to "unknown" when the OS
// user or hostname cannot be determined.
func operatorIdentity() string {
	var username, host string
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	if h, err := os.Hostname(); err == nil {
		host = h
	}
	if username == "" {
		username = "unknown"
	}
	if host == "" {
		host = "unknown"
	}
	return username + "@" + host
}

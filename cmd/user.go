package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
)

// newUserCmd builds the `gozone user` parent command. It is a namespace for
// emergency user-account operations that bypass the HTTP flow and talk
// directly to the configured database (used when the Web UI is unreachable:
// all admins locked, admin password lost, etc.).
func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "user",
		Short:         "User account operations (direct DB access, emergency recovery)",
		Long:          "Emergency user-account operations that bypass the HTTP flow and talk directly to the configured database. Used when the Web UI is unreachable: `gozone user unlock` clears a lockout, `gozone user reset-password` sets a new password.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(newUnlockCmd())
	cmd.AddCommand(newResetPasswordCmd())
	return cmd
}

// newUnlockCmd builds `gozone user unlock <id|username>`. It resolves the
// target user, clears their lockout and failed-login counter, then exits.
func newUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "unlock <id|username>",
		Short:         "Clear a user's account lockout (emergency recovery)",
		Long:          "Clears the lockout and failed-login counter of a GoZone user directly in the database, bypassing the HTTP flow. Used when all admin accounts are locked and the Web UI is unreachable.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return fmt.Errorf("read --config flag: %w", err)
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("load configuration: %w", err)
			}
			return unlockUser(cfg, args[0])
		},
	}
}

// newResetPasswordCmd builds `gozone user reset-password <id|username>`. It
// sets a new bcrypt password hash for the target user directly in the
// database. By default the password is read from a no-echo prompt; --password
// or piped stdin cover non-interactive use.
func newResetPasswordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "reset-password <id|username>",
		Short:         "Reset a user's password (emergency recovery)",
		Long:          "Sets a new bcrypt password hash for a GoZone user directly in the database, bypassing the HTTP flow. The password is read from a no-echo prompt by default, or from --password / stdin for non-interactive use. Replaces the hand-rolled `UPDATE users SET password_hash = ...` recovery path documented in the README.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return fmt.Errorf("read --config flag: %w", err)
			}
			pwFlag, err := cmd.Flags().GetString("password")
			if err != nil {
				return fmt.Errorf("read --password flag: %w", err)
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("load configuration: %w", err)
			}
			password, err := readPassword(pwFlag)
			if err != nil {
				return err
			}
			if password == "" {
				return fmt.Errorf("password must not be empty")
			}
			return resetUserPassword(cfg, args[0], password)
		},
	}
	cmd.Flags().String("password", "", "new password (less secure: visible in the process list and shell history; prefer the prompt or stdin)")
	return cmd
}

// resolveUser resolves a user by numeric ID or (case-insensitive) username,
// returning the numeric ID and the canonical username. It is shared by the
// unlock and reset-password subcommands.
func resolveUser(ctx context.Context, db *database.DB, ident string) (int64, string, error) {
	if id, perr := strconv.ParseInt(ident, 10, 64); perr == nil && id > 0 {
		var username string
		err := db.QueryRowContext(ctx, `SELECT username FROM users WHERE id = ?`, id).Scan(&username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, "", fmt.Errorf("user id=%d not found", id)
			}
			return 0, "", fmt.Errorf("lookup user id=%d: %w", id, err)
		}
		return id, username, nil
	}
	// Username lookup — case-insensitive; the Login handler does the same.
	var (
		userID   int64
		username string
	)
	err := db.QueryRowContext(ctx,
		`SELECT id, username FROM users WHERE lower(username) = lower(?)`,
		ident,
	).Scan(&userID, &username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", fmt.Errorf("user %q not found", ident)
		}
		return 0, "", fmt.Errorf("lookup user %q: %w", ident, err)
	}
	return userID, username, nil
}

// unlockUser resolves the target user, clears their lockout, and records an
// audit entry attributing the action to the shell operator (not a GoZone user).
func unlockUser(cfg *config.Config, ident string) error {
	logger.Init(cfg.Logging.Level)

	db, err := database.New(&cfg.Database)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userID, username, err := resolveUser(ctx, db, ident)
	if err != nil {
		return err
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

// resetUserPassword resolves the target user, hashes the new password with the
// configured bcrypt cost, writes it, and records an audit entry attributing
// the action to the shell operator.
func resetUserPassword(cfg *config.Config, ident, password string) error {
	logger.Init(cfg.Logging.Level)

	db, err := database.New(&cfg.Database)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userID, username, err := resolveUser(ctx, db, ident)
	if err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cfg.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	res, err := db.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		string(hash), userID,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user id=%d not found", userID)
	}

	// Log with user_id=NULL: the actor is the shell operator, not a GoZone
	// user. Capture the OS identity (username@hostname) for audit (m4).
	if _, err := db.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (NULL, 'reset_password_cli', ?)",
		fmt.Sprintf("Reset password for user id=%d username=%q by CLI operator %s", userID, username, operatorIdentity()),
	); err != nil {
		// Best-effort: the reset itself succeeded, so we don't fail the CLI.
		logger.Warn("failed to log CLI reset-password activity", "user_id", userID, "error", err)
	}

	logger.Info("password reset via CLI", "user_id", userID, "username", username)
	return nil
}

// readPassword obtains the new password. If passwordFlag is non-empty it is
// used directly; otherwise a no-echo prompt is used on a TTY (with a
// confirmation prompt), and a single line is read from stdin when input is
// piped (non-interactive use).
func readPassword(passwordFlag string) (string, error) {
	if passwordFlag != "" {
		return passwordFlag, nil
	}
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "New password: ")
		p1, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		fmt.Fprint(os.Stderr, "Confirm password: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		if string(p1) != string(p2) {
			return "", fmt.Errorf("passwords do not match")
		}
		return string(p1), nil
	}
	// Non-interactive: read a single line from stdin.
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
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

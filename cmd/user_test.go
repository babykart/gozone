package cmd

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/database"
)

// executeResetPassword builds a fresh root command and runs
// `gozone user reset-password` with the given args.
func executeResetPassword(args ...string) error {
	cmd := newRootCmd()
	cmd.SetArgs(append([]string{"user", "reset-password"}, args...))
	return cmd.Execute()
}

// withStdin temporarily replaces os.Stdin with a pipe that yields data, for the
// duration of fn. Used to drive the non-interactive (piped) password path
// deterministically, regardless of whether the test process has a real TTY.
func withStdin(t *testing.T, data string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(data); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	fn()
}

// storedPasswordHash returns the current password_hash for userID.
func storedPasswordHash(t *testing.T, db *database.DB, userID int64) string {
	t.Helper()
	var hash string
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash); err != nil {
		t.Fatalf("select password_hash: %v", err)
	}
	return hash
}

func TestResetPassword_RequiresUserArg(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	err := executeResetPassword("--config", cfgPath, "--password", "x")
	if err == nil {
		t.Fatal("expected error for missing user argument")
	}
	if !strings.Contains(err.Error(), "arg") {
		t.Errorf("expected an arg-count error, got: %v", err)
	}
}

func TestResetPassword_NotFound(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	openUnlockTestDB(t, cfgPath) // seed

	err := executeResetPassword("--config", cfgPath, "--password", "x", "ghost")
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

func TestResetPassword_EmptyRejected(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	openUnlockTestDB(t, cfgPath)

	var err error
	withStdin(t, "\n", func() { // empty line → empty password
		err = executeResetPassword("--config", cfgPath, "admin")
	})
	if err == nil {
		t.Fatal("expected error for empty password")
	}
	if !strings.Contains(err.Error(), "password must not be empty") {
		t.Errorf("expected empty-password error, got: %v", err)
	}
}

func TestResetPassword_Flag(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}
	oldHash := storedPasswordHash(t, db, adminID)

	if err := executeResetPassword("--config", cfgPath, "--password", "newpass-secret", "admin"); err != nil {
		t.Fatalf("reset-password: %v", err)
	}

	newHash := storedPasswordHash(t, db, adminID)
	if newHash == oldHash {
		t.Error("expected password_hash to change after reset")
	}
	// The new hash must validate against the new password...
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("newpass-secret")); err != nil {
		t.Errorf("new hash does not match new password: %v", err)
	}
	// ...and reject the old one.
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("admin")); err == nil {
		t.Error("new hash must not validate the old password")
	}
}

func TestResetPassword_Stdin(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}

	var err error
	withStdin(t, "piped-secret\n", func() {
		err = executeResetPassword("--config", cfgPath, "admin")
	})
	if err != nil {
		t.Fatalf("reset-password via stdin: %v", err)
	}

	hash := storedPasswordHash(t, db, adminID)
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("piped-secret")); err != nil {
		t.Errorf("hash from stdin password does not match: %v", err)
	}
}

func TestResetPassword_AuditLog(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)
	db := openUnlockTestDB(t, cfgPath)

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}

	if err := executeResetPassword("--config", cfgPath, "--password", "newpass-secret", "admin"); err != nil {
		t.Fatalf("reset-password: %v", err)
	}

	var (
		logUserID sql.NullInt64
		logAction string
		details   string
	)
	if err := db.QueryRowContext(context.Background(),
		"SELECT user_id, action, details FROM activity_logs WHERE action='reset_password_cli'").Scan(
		&logUserID, &logAction, &details); err != nil {
		t.Fatalf("query activity: %v", err)
	}
	// user_id must be NULL — the actor is the shell operator, not a GoZone
	// user (m4, same as `gozone user unlock`).
	if logUserID.Valid {
		t.Errorf("expected user_id NULL (operator is not a GoZone user), got %d", logUserID.Int64)
	}
	if !strings.Contains(details, "operator") {
		t.Errorf("details should mention the operator, got %q", details)
	}
	if !strings.Contains(details, "reset password") && !strings.Contains(details, "Reset password") {
		t.Errorf("details should mention the reset action, got %q", details)
	}
}

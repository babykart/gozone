package database

import (
	"context"
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHistoryReused reports whether newPassword matches any of the user's
// `limit` most recent stored password hashes (bcrypt compare). It is the
// "password reuse" check: the caller has just accepted the new password
// against the complexity policy and now verifies it was not used recently.
// limit <= 0 disables the check (returns false, nil).
//
// Because every password (including the very first one set on an account) is
// recorded via RecordPassword, the current password is part of the history —
// so reusing the current password is rejected too.
func (tx *Tx) PasswordHistoryReused(ctx context.Context, userID int64, newPassword string, limit int) (bool, error) {
	if limit <= 0 {
		return false, nil
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?`,
		userID, limit,
	)
	if err != nil {
		return false, fmt.Errorf("load password history: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return false, fmt.Errorf("scan password history: %w", err)
		}
		// bcrypt.CompareHashAndPassword returns nil on a match. A mismatch
		// (or a corrupt hash) is non-fatal: just keep checking the rest.
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)) == nil {
			return true, nil
		}
	}
	return false, rows.Err()
}

// RecordPassword stores a password hash in the user's history. Called on every
// password set (user creation, update, CLI reset) so future changes can detect
// reuse via PasswordHistoryReused.
func (tx *Tx) RecordPassword(ctx context.Context, userID int64, passwordHash string) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)`,
		userID, passwordHash,
	); err != nil {
		return fmt.Errorf("insert password history: %w", err)
	}
	return nil
}

// PrunePasswordHistory keeps only the `limit` most recent password-history rows
// for the user, deleting older entries. limit <= 0 is a no-op (history retention
// disabled). It uses the auto-increment id as a chronology proxy (older rows
// have smaller ids).
func (tx *Tx) PrunePasswordHistory(ctx context.Context, userID int64, limit int) error {
	if limit <= 0 {
		return nil
	}
	// Delete every row that is NOT among the newest `limit` for this user.
	// The subquery selects the ids to keep; the outer DELETE removes the rest.
	// This is portable across SQLite/MySQL/PostgreSQL (no LIMIT in a DELETE,
	// which MySQL/SQLite support but PostgreSQL does not).
	query := `DELETE FROM password_history WHERE user_id = ? AND id NOT IN (
		SELECT id FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?
	)`
	if _, err := tx.ExecContext(ctx, query, userID, userID, limit); err != nil {
		return fmt.Errorf("prune password history: %w", err)
	}
	return nil
}

// PasswordHistoryCount returns the number of stored password-history rows for
// the user. Primarily a test helper.
func (tx *Tx) PasswordHistoryCount(ctx context.Context, userID int64) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM password_history WHERE user_id = ?`, userID,
	).Scan(&n); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("count password history: %w", err)
	}
	return n, nil
}

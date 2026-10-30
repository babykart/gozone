package database

import (
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHistoryReused reports whether newPassword matches any of the user's
// `limit` most recent stored password hashes (bcrypt compare). It is the
// "password reuse" check: the caller has just accepted the new password
// against the complexity policy and now verifies it was not used recently.
// limit <= 0 disables the check (returns false, nil).
//
// The current password counts as "used" via an explicit comparison against
// the live users row — it cannot be assumed to sit in password_history,
// because accounts created before history was activated carry no record of
// it. Every loaded hash is compared — the loop does NOT short-circuit on
// the first match. The number of bcrypt comparisons therefore depends only
// on the number of history rows (capped at limit) plus one constant, never
// on the position of a reuse. Returning at the first match would let an
// authenticated user infer "how recently this password was last used" from
// the response time. The extra cost (comparing the remaining hashes after a
// match) is confined to the rejection path; the happy (no-reuse) path
// already compares every hash.
func (tx *Tx) PasswordHistoryReused(ctx context.Context, userID int64, newPassword string, limit int) (bool, error) {
	if limit <= 0 {
		return false, nil
	}
	// The current password is compared explicitly against the live users
	// row, NOT assumed to be present in password_history: accounts created
	// before history was activated carry no record of the password they
	// were using at that moment, and without this comparison a user could
	// re-submit the current password the first time history applied to
	// them. Every hash (current + history) is compared — no short-circuit —
	// so timing reveals only the row count, not the rank of a reuse.
	var current string
	if err := tx.QueryRowContext(ctx,
		"SELECT password_hash FROM users WHERE id = ?", userID,
	).Scan(&current); err != nil {
		return false, fmt.Errorf("load current password hash: %w", err)
	}
	reused := bcrypt.CompareHashAndPassword([]byte(current), []byte(newPassword)) == nil
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
		// (or a corrupt hash) is non-fatal: keep checking the rest.
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(newPassword)) == nil {
			reused = true
		}
	}
	return reused, rows.Err()
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
	// The keep-set is wrapped in a derived table for MySQL, which rejects a
	// bare LIMIT inside an IN-subquery (error 1235) and a DELETE whose
	// subquery reads the target table directly (error 1093): materializing
	// the derived table satisfies both, and the statement stays valid
	// SQLite/PostgreSQL SQL. No LIMIT on the DELETE itself — PostgreSQL
	// does not support it.
	query := `DELETE FROM password_history WHERE user_id = ? AND id NOT IN (
		SELECT id FROM (
			SELECT id FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?
		) AS _keep
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
		if isNoRows(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("count password history: %w", err)
	}
	return n, nil
}

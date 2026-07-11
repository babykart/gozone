package database

import (
	"context"
	"fmt"
	"time"
)

// SessionLifetime is the per-session bookkeeping persisted for idle/absolute
// enforcement. It is shared across instances via the sessions table.
type SessionLifetime struct {
	FirstSeen time.Time
	LastSeen  time.Time
}

// SessionGet loads the persisted lifetime for a session ID. found is false (with
// a nil error) when no row exists.
func (db *DB) SessionGet(ctx context.Context, sessionID string) (SessionLifetime, bool, error) {
	var sl SessionLifetime
	err := db.QueryRowContext(ctx,
		"SELECT first_seen, last_seen FROM sessions WHERE session_id = ?", sessionID,
	).Scan(&sl.FirstSeen, &sl.LastSeen)
	if isNoRows(err) {
		return SessionLifetime{}, false, nil
	}
	if err != nil {
		return SessionLifetime{}, false, fmt.Errorf("get session: %w", err)
	}
	return sl, true, nil
}

// SessionInsert records a new session's lifetime. It is idempotent on the
// session_id primary key (InsertIgnore): an existing row is left untouched so
// the earliest first_seen is preserved across instances.
func (db *DB) SessionInsert(ctx context.Context, sessionID string, firstSeen, lastSeen, expiresAt time.Time) error {
	_, err := db.InsertIgnore(ctx, "sessions",
		[]string{"session_id", "first_seen", "last_seen", "expires_at"},
		[]string{"session_id"},
		sessionID, firstSeen, lastSeen, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// SessionTouch updates a session's last activity and hard expiry. first_seen is
// intentionally not modified (the absolute budget is anchored at first login).
// The returned bool reports whether a row matched: false means the row no
// longer exists (e.g. it was deleted by another instance's idle denial or by
// an explicit logout), so callers must not treat the touch as a resurrection
// signal (REVIEW.md M-3).
func (db *DB) SessionTouch(ctx context.Context, sessionID string, lastSeen, expiresAt time.Time) (bool, error) {
	res, err := db.ExecContext(ctx,
		"UPDATE sessions SET last_seen = ?, expires_at = ? WHERE session_id = ?",
		lastSeen, expiresAt, sessionID,
	)
	if err != nil {
		return false, fmt.Errorf("touch session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("touch session: rows affected: %w", err)
	}
	return n > 0, nil
}

// SessionDelete removes a session row (e.g. after an idle-timeout denial so the
// session is gone cluster-wide).
func (db *DB) SessionDelete(ctx context.Context, sessionID string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// SessionPurgeExpired removes session rows whose expires_at has passed, bounding
// the table size. Returns the number of deleted rows.
func (db *DB) SessionPurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ?", now)
	if err != nil {
		return 0, fmt.Errorf("purge expired sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge expired sessions: rows affected: %w", err)
	}
	return n, nil
}

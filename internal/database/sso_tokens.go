package database

import (
	"context"
	"fmt"
	"time"
)

// UpsertSSOIDToken stores the raw IdP ID token for an SSO session, keyed by the
// session ID (sid claim of the GoZone session JWT). The Logout handler reads it
// back to forward id_token_hint at the IdP end_session_endpoint — required by
// providers like Keycloak, whose ID tokens (many realm roles/groups) can exceed
// what fits in the ~4 KiB session cookie. expiresAt bounds retention (aligned
// with the session's maximum possible lifetime) and drives the periodic purge.
// A DELETE+INSERT pair inside one transaction replaces any stale row for the
// same sid portably across dialects (no dialect-specific upsert SQL needed).
func (db *DB) UpsertSSOIDToken(ctx context.Context, sessionID, idToken string, expiresAt time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "DELETE FROM sso_id_tokens WHERE session_id = ?", sessionID); err != nil {
		return fmt.Errorf("clear sso id token: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO sso_id_tokens (session_id, id_token, expires_at) VALUES (?, ?, ?)",
		sessionID, idToken, expiresAt,
	); err != nil {
		return fmt.Errorf("insert sso id token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// FindSSOIDToken returns the stored ID token for sessionID, or "" when no row
// exists. expires_at is a retention bound only: the token is returned even once
// it has passed, because IdPs resolve the session from the (signed) hint and a
// logout may legitimately happen after the ID token's own exp.
func (db *DB) FindSSOIDToken(ctx context.Context, sessionID string) (string, error) {
	var idToken string
	err := db.QueryRowContext(ctx,
		"SELECT id_token FROM sso_id_tokens WHERE session_id = ?", sessionID,
	).Scan(&idToken)
	if isNoRows(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find sso id token: %w", err)
	}
	return idToken, nil
}

// DeleteSSOIDToken removes the stored hint for sessionID (called after the
// logout redirect has been built). Missing rows are not an error.
func (db *DB) DeleteSSOIDToken(ctx context.Context, sessionID string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM sso_id_tokens WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("delete sso id token: %w", err)
	}
	return nil
}

// PurgeExpiredSSOIDTokens removes hint rows whose expires_at has passed,
// bounding the table size. Returns the number of deleted rows.
func (db *DB) PurgeExpiredSSOIDTokens(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM sso_id_tokens WHERE expires_at <= ?", now)
	if err != nil {
		return 0, fmt.Errorf("purge expired sso id tokens: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge expired sso id tokens: rows affected: %w", err)
	}
	return n, nil
}

package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/babykart/gozone/internal/models"
)

// FindUserByExternalIdentity loads the local user linked to the given external
// identity (issuer, subject), returning the full user record used to establish
// a session. Returns (nil, nil) when no link exists — the caller decides
// whether to just-in-time provision or refuse the login.
func (db *DB) FindUserByExternalIdentity(ctx context.Context, issuer, subject string) (*models.User, error) {
	row := db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.email, u.password_hash, u.first_name, u.last_name,
		        u.role, u.enabled, u.created_at, u.updated_at,
		        u.password_changed_at, u.must_change_password
		 FROM external_identities ei
		 JOIN users u ON u.id = ei.user_id
		 WHERE ei.issuer = ? AND ei.subject = ?`, issuer, subject)
	u, err := scanLinkedUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// FindUserByEmail loads an enabled local user by lowercased email, used to link
// an existing local account to an SSO identity on first login (the ROADMAP
// "Existing local user linking by email match" path). Returns (nil, nil) when
// no such user exists.
func (db *DB) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id, username, email, password_hash, first_name, last_name,
		        role, enabled, created_at, updated_at,
		        password_changed_at, must_change_password
		 FROM users WHERE LOWER(email) = LOWER(?) AND enabled = 1`, email)
	u, err := scanLinkedUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// rowScanner abstracts *sql.Row and *sql.Rows so scanLinkedUser can serve both
// the single-row lookups above and a future iterator.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanLinkedUser(row rowScanner) (*models.User, error) {
	var u models.User
	var enabled, mustChange int
	if err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.Role, &enabled, &u.CreatedAt, &u.UpdatedAt,
		&u.PasswordChangedAt, &mustChange,
	); err != nil {
		return nil, err
	}
	u.Enabled = enabled == 1
	u.MustChangePassword = mustChange == 1
	return &u, nil
}

// LinkExternalIdentity links an external identity (issuer, subject) to a local
// user. It is idempotent for an existing (issuer, subject) → user_id mapping
// but rejects re-linking the same (issuer, subject) to a different user via the
// UNIQUE constraint. Intended to run inside the provisioning transaction.
func (tx *Tx) LinkExternalIdentity(ctx context.Context, userID int64, issuer, subject string) error {
	_, err := tx.InsertIgnore(ctx, "external_identities",
		[]string{"user_id", "issuer", "subject"},
		[]string{"issuer", "subject"},
		userID, issuer, subject)
	if err != nil {
		return fmt.Errorf("link external identity: %w", err)
	}
	return nil
}

// CreateExternalUser provisions a local user from an SSO login and links the
// external identity, in a single transaction. The created user has a random,
// non-bcrypt password hash so local username/password login is impossible for
// SSO-only accounts (the bcrypt compare in the Login handler always fails).
// Returns the newly created user.
func (db *DB) CreateExternalUser(ctx context.Context, username, email, firstName, lastName, role, issuer, subject string) (*models.User, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Random placeholder hash: not a valid bcrypt hash, so local login always
	// fails. 32 bytes hex (64 chars) keeps it within the password_hash column.
	placeholder, err := randomLoginHash()
	if err != nil {
		return nil, fmt.Errorf("generate placeholder hash: %w", err)
	}

	result, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, 1)`,
		username, email, placeholder, firstName, lastName, role,
	)
	if err != nil {
		return nil, err
	}
	userID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read new user id: %w", err)
	}
	if err := tx.LinkExternalIdentity(ctx, userID, issuer, subject); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'sso_provision', ?)",
		userID, fmt.Sprintf("Auto-provisioned user %s via SSO (%s)", username, issuer),
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	committed = true

	return &models.User{
		ID:                userID,
		Username:          username,
		Email:             email,
		FirstName:         firstName,
		LastName:          lastName,
		Role:              role,
		Enabled:           true,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
		PasswordChangedAt: time.Now().UTC(),
	}, nil
}

// randomLoginHash returns a random hex string used as a non-loginable password
// hash for SSO-provisioned accounts.
func randomLoginHash() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

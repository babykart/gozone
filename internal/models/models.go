// Package models defines the data structures used throughout GoZone,
// including users, API keys, activity logs, zones, and DNS records.
// Models are strictly JSON-serializable for PowerDNS API communication,
// with sensitive fields (passwords, key hashes) excluded from JSON output
// via struct tags.
package models

import "time"

// User represents an application user.
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Role         string `json:"role"`
	Enabled      bool   `json:"enabled"`
	// LockedUntil is the timestamp at which the account stops being locked.
	// A null value (or a value in the past) means the account is not locked.
	// It is populated by the admin lock UI and by the automatic lockout
	// triggered after repeated failed login attempts.
	LockedUntil *time.Time `json:"locked_until,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	// PasswordChangedAt is the timestamp the password was last set. Used to
	// compute password age for expiry (config Password.MaxAgeDays).
	PasswordChangedAt time.Time `json:"-"`
	// MustChangePassword forces a password change on next login. Set when an
	// admin/operator resets a user's password and when a password expires.
	MustChangePassword bool `json:"-"`
	// TokensValidAfter is the cutoff before which every session JWT is
	// considered revoked. The Auth middleware rejects any access
	// token whose iat predates this instant, so rotating the credential
	// (password change/reset) or disabling the account invalidates every
	// outstanding session — including a stolen JWT — without enumerating active
	// jtis. Defaults to the Unix epoch (no revocation) and is bumped to now at
	// every credential-changing event.
	TokensValidAfter time.Time `json:"-"`
}

// IsAdmin returns true if the user has the admin role.
func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

// IsLocked reports whether the account is currently locked, either by an
// admin manual lock or by the automatic failed-login threshold.
func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

// ActivityLog represents an activity log entry.
type ActivityLog struct {
	ID        int64     `json:"id"`
	UserID    *int64    `json:"user_id"`
	ZoneID    *string   `json:"zone_id"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	OldValue  string    `json:"old_value"`
	NewValue  string    `json:"new_value"`
	CreatedAt time.Time `json:"created_at"`
	Username  string    `json:"username"`
}

// APIKey represents an API key.
type APIKey struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"user_id"`
	KeyHash     string     `json:"-"`
	Description string     `json:"description"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// Setting represents a key-value application setting.
type Setting struct {
	ID    int64  `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func TestPasswordExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		maxAge    int
		changedAt time.Time
		want      bool
	}{
		{"disabled", 0, now.Add(-100 * 24 * time.Hour), false},
		{"zero changedAt", 90, time.Time{}, false},
		{"recent", 90, now.Add(-10 * 24 * time.Hour), false},
		{"just under limit", 90, now.Add(-89 * 24 * time.Hour), false},
		{"just over limit", 90, now.Add(-91 * 24 * time.Hour), true},
		{"way beyond limit", 90, now.Add(-365 * 24 * time.Hour), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := passwordExpired(tt.maxAge, tt.changedAt); got != tt.want {
				t.Errorf("passwordExpired(%d, %v) = %v, want %v", tt.maxAge, tt.changedAt, got, tt.want)
			}
		})
	}
}

func TestPasswordExpiryWarnDays(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		maxAge    int
		warn      int
		changedAt time.Time
		want      int
	}{
		{"disabled maxAge", 0, 15, now, 0},
		{"disabled warn", 90, 0, now, 0},
		{"outside window", 90, 15, now.Add(-10 * 24 * time.Hour), 0}, // remaining 80 > 15
		{"inside window", 90, 15, now.Add(-80 * 24 * time.Hour), 10}, // remaining 10
		{"already expired", 90, 15, now.Add(-95 * 24 * time.Hour), 0},
		{"just inside window", 90, 15, now.Add(-75 * 24 * time.Hour), 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := passwordExpiryWarnDays(tt.maxAge, tt.warn, tt.changedAt); got != tt.want {
				t.Errorf("passwordExpiryWarnDays(%d,%d,%v) = %d, want %d", tt.maxAge, tt.warn, tt.changedAt, got, tt.want)
			}
		})
	}
}

// TestChangePassword_Success exercises the self-service change flow: a forced
// user (must_change=1) changes their password; the hash rotates, the policy is
// enforced, and must_change_password is cleared.
func TestChangePassword_Success(t *testing.T) {
	h := strictPolicyHandler(t)
	_ = seedAdminUser(t, h)
	uid := testutil.SeedTestUser(t, h.DB, "target", "Oldpass1!", "user", true)
	h.DB.Exec("UPDATE users SET must_change_password = 1 WHERE id = ?", uid)

	var hash string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id = ?", uid).Scan(&hash)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: uid, Username: "target", Role: "user", PasswordHash: hash, MustChangePassword: true})

	body := "current_password=Oldpass1!&new_password=Newpass2!&confirm_password=Newpass2!"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.ChangePassword(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d (body: %s)", w.Code, w.Body.String())
	}

	var newHash string
	var mustChange int
	h.DB.QueryRow("SELECT password_hash, must_change_password FROM users WHERE id = ?", uid).Scan(&newHash, &mustChange)
	if newHash == hash {
		t.Error("expected password hash to change after self-service change")
	}
	if mustChange != 0 {
		t.Errorf("expected must_change_password cleared (0), got %d", mustChange)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("Newpass2!")); err != nil {
		t.Errorf("new hash should validate the new password: %v", err)
	}
}

// TestChangePassword_WrongCurrentRejected verifies the current-password check.
func TestChangePassword_WrongCurrentRejected(t *testing.T) {
	h := strictPolicyHandler(t)
	_ = seedAdminUser(t, h)
	uid := testutil.SeedTestUser(t, h.DB, "target", "Oldpass1!", "user", true)
	var hash string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id = ?", uid).Scan(&hash)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: uid, Username: "target", Role: "user", PasswordHash: hash})

	body := "current_password=wrong&new_password=Newpass2!&confirm_password=Newpass2!"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.ChangePassword(w, r)

	if w.Code == http.StatusSeeOther {
		t.Errorf("wrong current password should not be accepted (got redirect 303)")
	}
	var unchanged string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id = ?", uid).Scan(&unchanged)
	if unchanged != hash {
		t.Error("password hash should be unchanged after rejected change")
	}
}

// TestChangePassword_WorksWithoutHashInContext is the L-9 regression test:
// loadUser no longer selects password_hash, so the *models.User placed in
// the request context carries an empty PasswordHash. ChangePassword must
// refetch the hash inside its transaction rather than reading the context,
// otherwise every forced-change / self-service change would compare against
// an empty hash and reject every submission. This test seeds the user the
// same way production does (no hash in the context struct) and asserts the
// flow still succeeds.
func TestChangePassword_WorksWithoutHashInContext(t *testing.T) {
	h := strictPolicyHandler(t)
	_ = seedAdminUser(t, h)
	uid := testutil.SeedTestUser(t, h.DB, "target2", "Oldpass1!", "user", true)
	h.DB.Exec("UPDATE users SET must_change_password = 1 WHERE id = ?", uid)

	var hash string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id = ?", uid).Scan(&hash)

	// Mirror what the Auth middleware now stores: user WITHOUT PasswordHash.
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: uid, Username: "target2", Role: "user", MustChangePassword: true})

	body := "current_password=Oldpass1!&new_password=Newpass2!&confirm_password=Newpass2!"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.ChangePassword(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d (body: %s)", w.Code, w.Body.String())
	}

	var newHash string
	var mustChange int
	h.DB.QueryRow("SELECT password_hash, must_change_password FROM users WHERE id = ?", uid).Scan(&newHash, &mustChange)
	if newHash == hash {
		t.Error("expected password hash to change even when context carried no hash")
	}
	if mustChange != 0 {
		t.Errorf("expected must_change_password cleared (0), got %d", mustChange)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(newHash), []byte("Newpass2!")); err != nil {
		t.Errorf("new hash should validate the new password: %v", err)
	}
}

// TestLogin_MustChangePassword_RedirectsToChangePassword verifies the login
// flow redirects a forced-change user to /change-password instead of /dashboard.
func TestLogin_MustChangePassword_RedirectsToChangePassword(t *testing.T) {
	h := newTestHandler(t)
	uid := testutil.SeedTestUser(t, h.DB, "alice", "Alicepass1!", "user", true)
	h.DB.Exec("UPDATE users SET must_change_password = 1 WHERE id = ?", uid)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=Alicepass1!"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasSuffix(loc, "/change-password") {
		t.Errorf("expected redirect to /change-password, got %q", loc)
	}
}

// TestLogin_ExpiredPasswordForcesChange verifies that an expired password (per
// max_age_days) flips must_change_password on login and redirects to change.
func TestLogin_ExpiredPasswordForcesChange(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.Password.MaxAgeDays = 90
	h.Cfg.Password.ExpiryWarnDays = 0
	uid := testutil.SeedTestUser(t, h.DB, "bob", "Bobpass1!", "user", true)
	// Backdate the password beyond the 90-day limit. The timestamp is
	// computed in Go (UTC, per the project convention) instead of SQLite's
	// datetime('now', …) so the update runs identically on every dialect.
	old := time.Now().Add(-100 * 24 * time.Hour).UTC()
	h.DB.Exec("UPDATE users SET password_changed_at = ?, must_change_password = 0 WHERE id = ?", old, uid)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=bob&password=Bobpass1!"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasSuffix(loc, "/change-password") {
		t.Errorf("expired password: expected redirect to /change-password, got %q", loc)
	}
	var mustChange int
	h.DB.QueryRow("SELECT must_change_password FROM users WHERE id = ?", uid).Scan(&mustChange)
	if mustChange != 1 {
		t.Errorf("expired password: expected must_change_password persisted as 1, got %d", mustChange)
	}
}

// TestCreateUser_SetsMustChangePassword verifies that an admin-created user is
// flagged must_change_password when the "force password change" option is on
// (admin-set initial password → rotate on first login).
func TestCreateUser_SetsMustChangePassword(t *testing.T) {
	h := strictPolicyHandler(t)
	admin := seedAdminUser(t, h)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "username=svc&email=svc@example.com&password=Abcdef1!&role=user&force_password_change=1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	var mustChange int
	h.DB.QueryRow("SELECT must_change_password FROM users WHERE username='svc'").Scan(&mustChange)
	if mustChange != 1 {
		t.Errorf("admin-created user should have must_change_password=1, got %d", mustChange)
	}
}

// TestCreateUser_NoForcePasswordChange verifies that when the admin leaves the
// "force password change on first login" box unchecked, the new account is
// created without the must_change_password flag so it can log straight in.
func TestCreateUser_NoForcePasswordChange(t *testing.T) {
	h := strictPolicyHandler(t)
	admin := seedAdminUser(t, h)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// force_password_change omitted entirely (unchecked checkbox sends nothing).
	body := "username=svc&email=svc@example.com&password=Abcdef1!&role=user"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	var mustChange int
	h.DB.QueryRow("SELECT must_change_password FROM users WHERE username='svc'").Scan(&mustChange)
	if mustChange != 0 {
		t.Errorf("user created without force flag should have must_change_password=0, got %d", mustChange)
	}
}

// TestUpdateUser_SetsMustChangePassword verifies that an admin password reset
// flags the target user must_change_password.
func TestUpdateUser_SetsMustChangePassword(t *testing.T) {
	h := strictPolicyHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('user2', 'u2@e.com', 'oldhash', 'user')`)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "email=u2@e.com&first_name=&last_name=&role=user&password=Str0ng!aa"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	var mustChange int
	h.DB.QueryRow("SELECT must_change_password FROM users WHERE id=2").Scan(&mustChange)
	if mustChange != 1 {
		t.Errorf("admin-reset user should have must_change_password=1, got %d", mustChange)
	}
}

// TestChangePassword_RevokesOtherSessions is the M1 regression for the
// self-service flow: changing the password bumps tokens_valid_after (so every
// other session is rejected by the Auth middleware) AND re-issues the current
// session token so the user stays logged in on this device.
func TestChangePassword_RevokesOtherSessions(t *testing.T) {
	h := strictPolicyHandler(t)
	_ = seedAdminUser(t, h)
	uid := testutil.SeedTestUser(t, h.DB, "target3", "Oldpass1!", "user", true)
	h.DB.Exec("UPDATE users SET must_change_password = 1 WHERE id = ?", uid)

	var hash string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id = ?", uid).Scan(&hash)
	var tvaBefore time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id = ?", uid).Scan(&tvaBefore)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: uid, Username: "target3", Role: "user", PasswordHash: hash, MustChangePassword: true})

	body := "current_password=Oldpass1!&new_password=Newpass2!&confirm_password=Newpass2!"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.ChangePassword(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d (body: %s)", w.Code, w.Body.String())
	}

	// tokens_valid_after must move past the epoch default.
	var tvaAfter time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id = ?", uid).Scan(&tvaAfter)
	if !tvaAfter.After(tvaBefore) {
		t.Error("expected tokens_valid_after to be bumped after self-service password change (M1)")
	}

	// A fresh session cookie must be issued so the user is not logged out on
	// the device that just changed the password.
	var sessionValue string
	for _, c := range w.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			sessionValue = c.Value
		}
	}
	if sessionValue == "" {
		t.Error("expected a fresh session cookie after password change (M1); user must stay logged in")
	}
}

// TestUpdateUser_PasswordResetRevokesSessions is the M1 regression for the
// admin reset path: setting a new password bumps tokens_valid_after so the
// target must re-authenticate on every device.
func TestUpdateUser_PasswordResetRevokesSessions(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(`INSERT INTO users (username, email, password_hash, role, enabled) VALUES ('user2', 'u2@e.com', 'oldhash', 'user', 1)`)
	var tvaBefore time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id=2").Scan(&tvaBefore)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	body := "email=u2@e.com&first_name=&last_name=&role=user&password=newpass&enabled=1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	var tvaAfter time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id=2").Scan(&tvaAfter)
	if !tvaAfter.After(tvaBefore) {
		t.Error("expected tokens_valid_after to be bumped after admin password reset (M1)")
	}
}

// TestUpdateUser_DisableRevokesSessions is the M1 regression for the account
// disable path: disabling a user bumps tokens_valid_after so active sessions
// are cut immediately.
func TestUpdateUser_DisableRevokesSessions(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(`INSERT INTO users (username, email, password_hash, role, enabled) VALUES ('victim', 'victim@example.com', 'hash', 'user', 1)`)
	var tvaBefore time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id=2").Scan(&tvaBefore)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	// enabled omitted → requestedEnabled=false → disable transition.
	body := "email=victim@example.com&first_name=&last_name=&role=user"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	var tvaAfter time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id=2").Scan(&tvaAfter)
	if !tvaAfter.After(tvaBefore) {
		t.Error("expected tokens_valid_after to be bumped when disabling a user (M1)")
	}
}

// TestUpdateUser_ProfileEditDoesNotRevokeSessions guards the inverse: a
// profile-only edit (no password change, account stays enabled) must NOT bump
// tokens_valid_after, so the user's legitimate sessions survive.
func TestUpdateUser_ProfileEditDoesNotRevokeSessions(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(`INSERT INTO users (username, email, password_hash, role, enabled) VALUES ('victim', 'victim@example.com', 'hash', 'user', 1)`)
	var tvaBefore time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id=2").Scan(&tvaBefore)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	body := "email=victim@example.com&first_name=New&last_name=Name&role=user&enabled=1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}
	var tvaAfter time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id=2").Scan(&tvaAfter)
	if !tvaAfter.Equal(tvaBefore) {
		t.Errorf("tokens_valid_after must not change on a profile-only edit (M1): before=%v after=%v", tvaBefore, tvaAfter)
	}
}

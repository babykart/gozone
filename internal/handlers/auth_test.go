package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

func TestLoginPage(t *testing.T) {
	h := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	h.LoginPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestLoginPage_WithError(t *testing.T) {
	h := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login?error=invalid_credentials", nil)
	h.LoginPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestLogin_Success(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 4)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"testuser", "test@example.com", string(hash), "user",
	)

	body := "username=testuser&password=testpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	// Should have a session cookie
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == constants.SessionCookieName {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected gozone_session cookie")
	}

	// Activity log should exist
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='login'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 login activity log, got %d", count)
	}
}

// TestLogin_CaseInsensitiveAndTrimmedUsername guards REVIEW.md L-5: the DB
// lookup must be case-insensitive (LOWER(username) = ?) and the input must be
// trimmed, matching the per-username rate limiter's normalisation
// (cmd/server.go loginUsernameKey). A user who registered as "TestUser" must be
// able to log in as "testuser", "TESTUSER", or " TestUser ". Without the
// case-insensitive lookup, Postgres (case-sensitive =) would resolve these to
// different rows / no row while the rate limiter treats them as one bucket.
func TestLogin_CaseInsensitiveAndTrimmedUsername(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 4)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"TestUser", "test@example.com", string(hash), "user",
	)

	for _, raw := range []string{"testuser", "TESTUSER", " TestUser "} {
		body := url.Values{"username": {raw}, "password": {"testpass"}}.Encode()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)

		if w.Code != http.StatusSeeOther {
			t.Errorf("username=%q: expected 303 redirect, got %d", raw, w.Code)
		}
		var found bool
		for _, c := range w.Result().Cookies() {
			if c.Name == constants.SessionCookieName {
				found = true
			}
		}
		if !found {
			t.Errorf("username=%q: expected gozone_session cookie", raw)
		}
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	h := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=admin&password=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
}

func TestLogin_FailedAttemptsRecorded(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, err := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	var count int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0", "victim").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 failed login_attempts, got %d", count)
	}

	var failed int
	if err := h.DB.QueryRow("SELECT failed_login_attempts FROM users WHERE id = ?", uid).Scan(&failed); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if failed != 3 {
		t.Errorf("expected failed_login_attempts=3, got %d", failed)
	}
}

func TestLogin_LocksAccountAfterThreshold(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	// Default threshold is 10 — push 10 failures, then verify the next attempt
	// (even with the correct password) is rejected with the lockout error.
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	locked, until, err := h.DB.UserLockStatus(context.Background(), uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Fatal("expected user to be locked after 10 failed attempts")
	}
	if !until.After(time.Now()) {
		t.Errorf("expected locked_until in the future, got %v", until)
	}

	// Even the correct password must be rejected while locked. The user-facing
	// redirect target must match the wrong-password / unknown-user path
	// (account enumeration defence — see REVIEW.md).
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=goodpass"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, invalidCredentialsError) {
		t.Errorf("locked-account redirect must use the generic %q error code, got %q", invalidCredentialsError, loc)
	}
	if strings.Contains(loc, "account_locked") {
		t.Errorf("locked-account response must not leak the lockout state, got %q", loc)
	}
}

func TestLogin_SuccessfulLoginResetsCounter(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=goodpass"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303 after successful login, got %d", w.Code)
	}

	var failed int
	if err := h.DB.QueryRow("SELECT failed_login_attempts FROM users WHERE id = ?", uid).Scan(&failed); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if failed != 0 {
		t.Errorf("expected counter reset to 0, got %d", failed)
	}
}

func TestLogin_UnknownUsername_RecordsAttempt(t *testing.T) {
	h := newTestHandler(t)

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=ghost&password=anything"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	var count int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM login_attempts WHERE username = 'ghost'").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 login_attempts for unknown username, got %d", count)
	}
}

func TestLogin_DisabledLockoutWhenZeroThreshold(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.LoginLock.MaxFailedAttempts = 0

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	// 100 failures — with threshold 0 the counter must not move and the
	// account must not lock.
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	locked, _, err := h.DB.UserLockStatus(context.Background(), uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected no lockout when max_failed_attempts is 0")
	}

	var failed int
	if err := h.DB.QueryRow("SELECT failed_login_attempts FROM users WHERE id = ?", uid).Scan(&failed); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if failed != 0 {
		t.Errorf("expected counter to stay at 0, got %d", failed)
	}
}

func TestLogout(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), 4)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"testuser", "test@example.com", string(hash), "user",
	)

	user := &models.User{ID: 1, Username: "testuser", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	token, err := middleware.GenerateToken(user, h.Cfg.Server.JWTKey, time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r = r.WithContext(ctx)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: token})
	h.Logout(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	// Cookie should be cleared
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == constants.SessionCookieName && c.Value != "" {
			t.Error("expected empty session cookie")
		}
	}

	// Activity log should exist
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='logout'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 logout activity log, got %d", count)
	}

	// Token should be revoked
	claims, err := middleware.ParseToken(token, h.Cfg.Server.JWTKey)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	revoked, err := h.DB.IsTokenRevoked(context.Background(), claims.ID)
	if err != nil {
		t.Fatalf("check revocation: %v", err)
	}
	if !revoked {
		t.Error("expected token to be revoked after logout")
	}
}

func TestProfilePage(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "testuser", Role: "user", Email: "test@example.com"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/profile", nil)
	r = r.WithContext(ctx)
	h.ProfilePage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestLogin_LastAdmin_NotLocked verifies the REVIEW.md fix: an attacker that
// fails to log in as the SOLE enabled admin must not be able to lock them
// out. The counter is incremented up to maxAttempts-1 (so the next failure
// still counts) but locked_until stays NULL.
func TestLogin_LastAdmin_NotLocked(t *testing.T) {
	h := newTestHandler(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"soleadmin", "sole@admin.local", string(hash), "admin",
	)
	uid, _ := res.LastInsertId()

	// Trigger the threshold (10 by default) — each call with a wrong password
	// calls recordFailedAttempt. We do 12 to make sure the counter caps at 9.
	for i := 0; i < 12; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=soleadmin&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	locked, _, err := h.DB.UserLockStatus(context.Background(), uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("sole admin must NOT be locked by failed-login attempts")
	}

	var count int
	if err := h.DB.QueryRow("SELECT failed_login_attempts FROM users WHERE id = ?", uid).Scan(&count); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if count >= 10 {
		t.Errorf("counter should stay below threshold after last-admin exemption, got %d", count)
	}
}

// TestLogin_NonAdmin_StillLocked verifies the exemption only applies to
// the last enabled admin. A non-last-admin must still get locked normally
// once the threshold is reached.
func TestLogin_NonAdmin_StillLocked(t *testing.T) {
	h := newTestHandler(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	// Two admins so neither is "last" + a user to be locked.
	for _, u := range []struct {
		name, role string
	}{
		{"admin1", "admin"},
		{"admin2", "admin"},
		{"victim", "user"},
	} {
		h.DB.Exec(
			`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
			u.name, u.name+"@test.local", string(hash), u.role,
		)
	}

	// 12 wrong attempts against victim.
	for i := 0; i < 12; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	var victimID int64
	if err := h.DB.QueryRow("SELECT id FROM users WHERE username = 'victim'").Scan(&victimID); err != nil {
		t.Fatalf("find victim: %v", err)
	}
	locked, _, err := h.DB.UserLockStatus(context.Background(), victimID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Error("non-admin user must be locked after threshold even when admins exist")
	}
}

// TestLogin_TwoAdmins_LastAdminLocked verifies that when two admins exist
// and one of them is targeted, the last-admin exemption does NOT trigger —
// the targeted admin can still be locked because there is another admin
// available.
func TestLogin_TwoAdmins_TargetedAdminLocked(t *testing.T) {
	h := newTestHandler(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	for _, name := range []string{"admin1", "admin2"} {
		h.DB.Exec(
			`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
			name, name+"@admin.local", string(hash), "admin",
		)
	}

	for i := 0; i < 12; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=admin1&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	var adminID int64
	if err := h.DB.QueryRow("SELECT id FROM users WHERE username = 'admin1'").Scan(&adminID); err != nil {
		t.Fatalf("find admin1: %v", err)
	}
	locked, _, err := h.DB.UserLockStatus(context.Background(), adminID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Error("admin1 should be locked when admin2 still exists — there is no last-admin exemption for it")
	}
}

// TestLogin_ErrorMessage_NoEnumeration verifies the REVIEW.md fix: the
// user-facing redirect target is identical whether the username is
// unknown, the password is wrong, or the account is locked. An attacker
// who triggers a lockout on a guessed username must not be able to
// distinguish the locked-account response from the wrong-password response.
func TestLogin_ErrorMessage_NoEnumeration(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	// Drive the existing user over the lockout threshold (10 by default).
	for i := 0; i < 11; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=wrong"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
	}

	// Confirm the account is locked before sampling the responses — otherwise
	// the "locked" branch would silently fall back to the wrong-password path.
	locked, _, err := h.DB.UserLockStatus(context.Background(), uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Fatalf("precondition: account must be locked for this test to be meaningful")
	}

	cases := []struct {
		name     string
		username string
		password string
	}{
		{"unknown_user", "ghost", "anything"},
		{"wrong_password", "victim", "wrong"},
		{"locked_account", "victim", "goodpass"},
	}

	var redirectLocs []string
	for _, tc := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username="+tc.username+"&password="+tc.password))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)
		redirectLocs = append(redirectLocs, w.Header().Get("Location"))
	}

	for i, tc := range cases {
		if !strings.Contains(redirectLocs[i], "error="+invalidCredentialsError) {
			t.Errorf("%s: redirect must use the generic %q error code, got %q",
				tc.name, invalidCredentialsError, redirectLocs[i])
		}
		if strings.Contains(redirectLocs[i], "account_locked") {
			t.Errorf("%s: response must not leak the lockout state, got %q", tc.name, redirectLocs[i])
		}
	}

	// All three redirect targets must be byte-for-byte identical. This is
	// the strongest guarantee that no enumeration vector remains.
	for i := 1; i < len(redirectLocs); i++ {
		if redirectLocs[i] != redirectLocs[0] {
			t.Errorf("redirect mismatch: %s case=%q vs base %q",
				cases[i].name, redirectLocs[i], redirectLocs[0])
		}
	}

	// The loginErrorBanner lookup is the second half of the defence: even
	// if the query code accidentally regressed, the banner mapping must
	// collapse every authentication failure to the same message.
	banner := loginErrorBanner(invalidCredentialsError)
	if banner == "" {
		t.Fatalf("missing banner for %q", invalidCredentialsError)
	}
}

// TestLogin_LockedAccountPerformsBcrypt guards the M-SEC1 fix: the locked-
// account branch must perform a dummy bcrypt compare so its response time
// matches the wrong-password / unknown-user paths. Before the fix the locked
// branch returned in ~0 ms, creating a timing oracle that let an attacker
// distinguish a locked-but-valid account from an unknown username.
//
// With the default bcrypt cost (12) the dummy compare takes ~250 ms; we assert
// a conservative lower bound well above the sub-millisecond no-bcrypt path.
func TestLogin_LockedAccountPerformsBcrypt(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), h.Cfg.Auth.BcryptCost)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	// Lock the account directly instead of grinding 11 failed attempts.
	if _, err := h.DB.Exec(
		`UPDATE users SET locked_until = ? WHERE id = ?`,
		time.Now().Add(15*time.Minute).UTC(), uid,
	); err != nil {
		t.Fatalf("failed to lock account: %v", err)
	}

	locked, _, err := h.DB.UserLockStatus(context.Background(), uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Fatal("precondition: account must be locked")
	}

	// The locked-account login must take long enough that bcrypt clearly ran.
	// bcrypt cost 12 ≈ 250 ms; a 15 ms floor is safely above the <1 ms no-op
	// redirect and safely below real bcrypt even on a loaded CI runner.
	const minBcryptElapsed = 15 * time.Millisecond
	body := "username=victim&password=whatever"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	start := time.Now()
	h.Login(w, r)
	elapsed := time.Since(start)

	if !strings.Contains(w.Header().Get("Location"), "error="+invalidCredentialsError) {
		t.Errorf("locked account must redirect to generic error, got %q", w.Header().Get("Location"))
	}
	if elapsed < minBcryptElapsed {
		t.Errorf("locked-account login took %v, expected ≥ %v (bcrypt work missing — timing oracle regression, M-SEC1)",
			elapsed, minBcryptElapsed)
	}
}

// TestLogin_LockedAccountExtendsLockout guards the M-SEC5 fix: a login
// attempt on an already-locked account must extend locked_until (sliding
// expiration) so an attacker cannot get one free guess per lockout window.
func TestLogin_LockedAccountExtendsLockout(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	// Lock the account with a SHORT window (1 minute) so we can detect
	// extension. failed_login_attempts is already at the threshold so
	// recordFailedAttempt will push locked_until out by a full lockoutDuration.
	shortUntil := time.Now().Add(1 * time.Minute).UTC()
	if _, err := h.DB.Exec(
		`UPDATE users SET locked_until = ?, failed_login_attempts = ? WHERE id = ?`,
		shortUntil, h.Cfg.LoginLock.MaxFailedAttempts, uid,
	); err != nil {
		t.Fatalf("failed to lock account: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=wrong"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	if !strings.Contains(w.Header().Get("Location"), "error="+invalidCredentialsError) {
		t.Fatalf("locked account must redirect to generic error, got %q", w.Header().Get("Location"))
	}

	// The lockout must have been extended. Default lockout is 15 minutes, so
	// locked_until should now be ~15 min in the future — well beyond the
	// original 1-minute window. Use a 2-minute tolerance for execution time.
	lockoutDuration := time.Duration(h.Cfg.LoginLock.LockoutDurationMinutes) * time.Minute
	_, newUntil, err := h.DB.UserLockStatus(context.Background(), uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	expectedMin := time.Now().Add(lockoutDuration - 2*time.Minute)
	if !newUntil.After(expectedMin) {
		t.Errorf("lockout not extended (M-SEC5): locked_until=%v, expected at least %v",
			newUntil, expectedMin)
	}
}

// TestLogin_LockoutCheckErrorFailsClosed guards the m34 fix: when the lockout
// status cannot be read from the DB, the login must be DENIED (fail-closed)
// even with the correct password — otherwise a DB error would bypass the
// lockout for an account that is actually locked.
func TestLogin_LockoutCheckErrorFailsClosed(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"victim", "victim@example.com", string(hash), "user",
	)

	// Break UserLockStatus (SELECT locked_until ...) while leaving the user
	// fetch — which does not reference locked_until — working, so the handler
	// reaches the lockout check and sees a DB error there.
	if _, err := h.DB.Exec(`ALTER TABLE users DROP COLUMN locked_until`); err != nil {
		t.Fatalf("drop locked_until column: %v (SQLite too old for DROP COLUMN?)", err)
	}

	body := "username=victim&password=goodpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error="+invalidCredentialsError) {
		t.Fatalf("fail-closed: expected redirect to generic login error even with correct password, got %q", loc)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			t.Errorf("fail-closed: login must not issue a session cookie when lockout status is uncheckable, got %s", c.Name)
		}
	}
}

// TestLoginErrorBanner_Mapping guards the message lookup so future login
// error codes cannot accidentally bypass the mapping and echo raw query
// values into the banner.
func TestLoginErrorBanner_Mapping(t *testing.T) {
	if got := loginErrorBanner(invalidCredentialsError); got == "" {
		t.Errorf("missing banner for %q", invalidCredentialsError)
	}
	// CSRF failures must show a banner (m5 — previously empty).
	if got := loginErrorBanner(csrfInvalidError); got == "" {
		t.Errorf("missing banner for %q", csrfInvalidError)
	}
	if got := loginErrorBanner("nonexistent_code"); got != "" {
		t.Errorf("unknown code must map to empty banner, got %q", got)
	}
	if got := loginErrorBanner(""); got != "" {
		t.Errorf("empty code must map to empty banner, got %q", got)
	}
	// Defence against regression: the historical "account_locked" code must
	// no longer map to a distinct banner (otherwise the enumeration vector
	// returns).
	if _, exists := loginErrorMessages["account_locked"]; exists {
		t.Errorf("loginErrorMessages must not contain account_locked (enumeration vector)")
	}
}

func TestDebugLogin(t *testing.T) {
	h := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login?error=invalid_credentials", nil)
	h.LoginPage(w, r)
	t.Logf("Body length: %d", w.Body.Len())
	t.Logf("Body: %q", w.Body.String())
	t.Logf("Code: %d", w.Code)
	// Try executing directly
	data := map[string]interface{}{
		"Title":   "Login - " + h.Cfg.Server.AppName,
		"Error":   loginErrorBanner(r.URL.Query().Get("error")),
		"AppName": h.Cfg.Server.AppName,
	}
	t.Logf("Data: %+v", data)
	if err := h.Tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		t.Logf("Template error: %v", err)
		t.Logf("Body after error: %q", w.Body.String())
	}
	t.Logf("Final body: %q", w.Body.String())
}

// TestLogin_ManualLockHonoredWhenAutoLockoutDisabled is the B3 regression: a
// manual admin lock must block login even when max_failed_attempts = 0 disables
// the automatic brute-force lockout. Before the fix, 0 de-enforced manual
// locks too (the whole lockout check was gated on max_failed_attempts > 0).
func TestLogin_ManualLockHonoredWhenAutoLockoutDisabled(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.LoginLock.MaxFailedAttempts = 0 // disable the automatic lockout feature

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, 1)`,
		"victim", "victim@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	// Admin manually locks the account (sets locked_until + manual_lock_until).
	if err := h.DB.AdminLockUser(context.Background(), uid, time.Hour); err != nil {
		t.Fatalf("AdminLockUser: %v", err)
	}

	// Even with the correct password and the auto-lockout feature OFF, the
	// manual lock must block the login.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=goodpass"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, invalidCredentialsError) {
		t.Errorf("manual lock must block login even with auto-lockout disabled; got %q", loc)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			t.Error("manual lock must not issue a session cookie")
		}
	}
}

// TestLogin_StaleAutoLockIgnoredWhenAutoLockoutDisabled guards the I-2
// contract that B3 must NOT regress: with max_failed_attempts = 0, a stale
// automatic lock (locked_until set while the feature was on) is ignored at
// login — the manual-lock enforcement added for B3 must not leak into the
// auto path.
func TestLogin_StaleAutoLockIgnoredWhenAutoLockoutDisabled(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.LoginLock.MaxFailedAttempts = 0

	hash, _ := bcrypt.GenerateFromPassword([]byte("goodpass"), 4)
	res, _ := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, 1)`,
		"stale", "stale@example.com", string(hash), "user",
	)
	uid, _ := res.LastInsertId()

	// Simulate a stale auto-lock: locked_until set, but no manual_lock_until
	// (the account was auto-locked while the feature was on, then the operator
	// set max_failed_attempts = 0).
	if _, err := h.DB.Exec("UPDATE users SET locked_until = ? WHERE id = ?", time.Now().Add(time.Hour), uid); err != nil {
		t.Fatalf("set stale locked_until: %v", err)
	}

	// With the feature off, the stale auto-lock is ignored and login succeeds.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=stale&password=goodpass"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	loc := w.Header().Get("Location")
	if strings.Contains(loc, "error=") {
		t.Errorf("stale auto-lock must be ignored when the feature is disabled (I-2); got %q", loc)
	}
	var hasSession bool
	for _, c := range w.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			hasSession = true
		}
	}
	if !hasSession {
		t.Error("expected a session cookie after successful login past a stale auto-lock (I-2)")
	}
}

// TestOidcPostLogoutURL mirrors TestOidcCallbackURL: when server.external_url
// is configured, the post_logout_redirect_uri handed to the IdP at RP-initiated
// logout is built from that canonical base — the client-controlled Host header
// must not influence it. When empty, the URL keeps the original per-request
// derivation (resolved scheme + Host).
func TestOidcPostLogoutURL(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.Host = "spoofed.example.com"

	if got, want := oidcPostLogoutURL("", r), "http://spoofed.example.com/login"; got != want {
		t.Errorf("oidcPostLogoutURL (derived) = %q, want %q", got, want)
	}
	if got, want := oidcPostLogoutURL("https://dns.example.com", r), "https://dns.example.com/login"; got != want {
		t.Errorf("oidcPostLogoutURL (external_url) = %q, want %q", got, want)
	}
}

// TestLogout_TokenWithoutExpiryDoesNotPanic guards the nil-ExpiresAt path of
// the logout revocation. Every issuance path embeds an exp today, but a JWT
// without one parses fine — Logout used to dereference claims.ExpiresAt.Time
// unconditionally, so a future issuance change would have turned the token
// cookie into a guaranteed panic (the middleware session-policy path already
// guards the same field). Such a token never expires on its own, so its
// revocation row must carry a far-future expiry instead of being pruned with
// the token still usable.
func TestLogout_TokenWithoutExpiryDoesNotPanic(t *testing.T) {
	h := newTestHandler(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), 4)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"noexp", "noexp@example.com", string(hash), "user",
	)

	user := &models.User{ID: 1, Username: "noexp", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Mint a token with NO ExpiresAt claim, mimicking a hypothetical issuance
	// path that omits it (ParseToken does not require exp to succeed).
	noExpToken := jwt.NewWithClaims(jwt.SigningMethodHS256, middleware.Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "no-exp-jti",
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Issuer:   "gozone",
		},
	})
	signed, err := noExpToken.SignedString(h.Cfg.Server.JWTKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r = r.WithContext(ctx)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: signed})
	h.Logout(w, r) // must not panic

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	// The token must still be revoked — with a far-future expiry so the
	// revoked_tokens purge does not drop the row while the token remains
	// usable (it never expires on its own).
	revoked, err := h.DB.IsTokenRevoked(context.Background(), "no-exp-jti")
	if err != nil {
		t.Fatalf("check revocation: %v", err)
	}
	if !revoked {
		t.Error("expected the exp-less token to be revoked on logout")
	}
	var expiresAt time.Time
	if err := h.DB.QueryRow("SELECT expires_at FROM revoked_tokens WHERE jti = ?", "no-exp-jti").Scan(&expiresAt); err != nil {
		t.Fatalf("read revocation row: %v", err)
	}
	if time.Until(expiresAt) < 99*365*24*time.Hour {
		t.Errorf("revocation of an exp-less token must carry a far-future expiry, got %v", expiresAt)
	}
}

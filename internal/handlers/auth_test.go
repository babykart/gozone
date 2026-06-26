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

	// Even the correct password must be rejected while locked.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=victim&password=goodpass"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "account_locked") {
		t.Errorf("expected redirect to account_locked, got %q", loc)
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

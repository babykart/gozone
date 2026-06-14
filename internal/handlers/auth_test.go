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

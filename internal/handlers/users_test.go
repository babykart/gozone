package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

func seedAdminUser(t *testing.T, h *Handler) *models.User {
	t.Helper()
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"admin", "admin@example.com", "hash", "admin",
	)
	return &models.User{ID: 1, Username: "admin", Email: "admin@example.com", Role: "admin"}
}

func TestListUsers_Admin(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r = r.WithContext(ctx)
	h.ListUsers(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListUsers_NonAdmin(t *testing.T) {
	h := newTestHandler(t)
	user := &models.User{ID: 1, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r = r.WithContext(ctx)
	h.ListUsers(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCreateUserPage_Admin(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/new", nil)
	r = r.WithContext(ctx)
	h.CreateUserPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCreateUserPage_NonAdmin(t *testing.T) {
	h := newTestHandler(t)
	user := &models.User{ID: 1, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/new", nil)
	r = r.WithContext(ctx)
	h.CreateUserPage(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCreateUser_Success(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "username=newuser&email=new@example.com&password=testpass&role=user"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	// User should exist
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='newuser'").Scan(&count)
	if count != 1 {
		t.Errorf("expected user to exist")
	}

	// Activity log should exist
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_user'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestCreateUser_NonAdmin(t *testing.T) {
	h := newTestHandler(t)
	user := &models.User{ID: 1, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader("username=new&email=new@test.com&password=pass"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCreateUser_EmptyFields(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Missing required fields
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader("username=&email=&password="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
}

func TestEditUserPage_Admin(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	seedAdminUser(t, h) // seed again to get user ID 2... actually this won't work due to unique constraint
	// Let's create a second user
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user2", "user2@example.com", "hash", "user",
	)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/2/edit", nil)
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.EditUserPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestEditUserPage_NotFound(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/999/edit", nil)
	r.SetPathValue("user_id", "999")
	r = r.WithContext(ctx)
	h.EditUserPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
	}
}

func TestUpdateUser_Success(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user2", "user2@example.com", "hash", "user",
	)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "email=updated@example.com&first_name=Updated&last_name=User&role=user"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var email string
	h.DB.QueryRow("SELECT email FROM users WHERE id=2").Scan(&email)
	if email != "updated@example.com" {
		t.Errorf("expected updated@example.com, got %s", email)
	}
}

func TestUpdateUser_WithPassword(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user2", "user2@example.com", "oldhash", "user",
	)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "email=user2@example.com&first_name=&last_name=&role=user&password=newpass"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var hash string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id=2").Scan(&hash)
	if hash == "oldhash" {
		t.Error("expected password hash to be updated")
	}
}

func TestDeleteUser_Success(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user2", "user2@example.com", "hash", "user",
	)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/delete", strings.NewReader("user_id=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id=2").Scan(&count)
	if count != 0 {
		t.Errorf("expected user to be deleted")
	}
}

func TestDeleteUser_Self(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/delete", strings.NewReader("user_id=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	// Admin user should still exist
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id=1").Scan(&count)
	if count != 1 {
		t.Errorf("admin user should not be deleted")
	}
}

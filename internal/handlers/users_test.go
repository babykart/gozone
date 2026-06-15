package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func seedAdminUser(t *testing.T, h *Handler) *models.User {
	t.Helper()
	adminID := testutil.SeedTestUser(t, h.DB, "admin", "adminpass", "admin", true)
	return &models.User{ID: adminID, Username: "admin", Email: "admin@test.local", Role: "admin"}
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
	middleware.RequireAdmin(http.HandlerFunc(h.ListUsers)).ServeHTTP(w, r)

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
	middleware.RequireAdmin(http.HandlerFunc(h.CreateUserPage)).ServeHTTP(w, r)

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
	middleware.RequireAdmin(http.HandlerFunc(h.CreateUser)).ServeHTTP(w, r)

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

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
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

func TestUpdateUser_SelfRoleChangeBlocked(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Admin tries to demote themselves to user
	body := "email=admin@test.local&first_name=&last_name=&role=user&enabled=1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/1/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "1")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var role string
	h.DB.QueryRow("SELECT role FROM users WHERE id=1").Scan(&role)
	if role != "admin" {
		t.Errorf("expected admin role to remain, got %s", role)
	}
}

func TestUpdateUser_SelfDisableBlocked(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Admin tries to disable themselves; no enabled field means disabled
	body := "email=admin@test.local&first_name=&last_name=&role=admin"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/1/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "1")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var enabled int
	h.DB.QueryRow("SELECT enabled FROM users WHERE id=1").Scan(&enabled)
	if enabled != 1 {
		t.Errorf("expected admin to remain enabled")
	}
}

func TestUpdateUser_LastEnabledAdminBlocked(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, ?)`,
		"user2", "user2@example.com", "hash", "user", 0,
	)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Try to disable the only enabled admin
	body := "email=admin@test.local&first_name=&last_name=&role=admin"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/1/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "1")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var enabled int
	h.DB.QueryRow("SELECT enabled FROM users WHERE id=1").Scan(&enabled)
	if enabled != 1 {
		t.Errorf("expected last admin to remain enabled")
	}
}

func TestUpdateUser_SelfAllowedFields(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Admin may update their own email/name without changing role/enabled
	body := "email=admin-new@test.local&first_name=New&last_name=Name&role=admin&enabled=1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/1/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "1")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var email, firstName, lastName string
	h.DB.QueryRow("SELECT email, first_name, last_name FROM users WHERE id=1").Scan(&email, &firstName, &lastName)
	if email != "admin-new@test.local" || firstName != "New" || lastName != "Name" {
		t.Errorf("expected email/name update, got %s %s %s", email, firstName, lastName)
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

func TestDeleteUser_LastEnabledAdminBlocked(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	// Add a second admin, but disabled. Disabled admins still reach the handler,
	// so this tests that the last *enabled* admin cannot be deleted.
	disabledAdminID := testutil.SeedTestUser(t, h.DB, "admin2", "adminpass", "admin", false)
	actor := &models.User{ID: disabledAdminID, Username: "admin2", Role: "admin"}

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, actor)

	body := fmt.Sprintf("user_id=%d", admin.ID)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var userCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", admin.ID).Scan(&userCount)
	if userCount != 1 {
		t.Errorf("last enabled admin should not be deleted")
	}
}

func TestDeleteUser_SecondAdminAllowed(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	// Insert a second enabled admin.
	res, err := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, ?)`,
		"admin2", "admin2@test.local", "hash", "admin", 1,
	)
	if err != nil {
		t.Fatalf("insert second admin: %v", err)
	}
	secondAdminID, _ := res.LastInsertId()

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/delete", strings.NewReader(fmt.Sprintf("user_id=%d", secondAdminID)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM users WHERE id=%d", secondAdminID)).Scan(&count)
	if count != 0 {
		t.Errorf("second admin should have been deleted")
	}
}

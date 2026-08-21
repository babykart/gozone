package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

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

func TestListUsers_PaginationAndSearch(t *testing.T) {
	h := newTestHandler(t)
	_ = seedAdminUser(t, h)
	testutil.SeedTestUser(t, h.DB, "alice", "pass", "user", true)
	testutil.SeedTestUser(t, h.DB, "bob", "pass", "user", true)
	testutil.SeedTestUser(t, h.DB, "charlie", "pass", "user", true)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, &models.User{ID: 1, Username: "admin", Role: "admin"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users?search=ali&PerPage=1&Page=1", nil)
	r = r.WithContext(ctx)
	h.ListUsers(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "alice") {
		t.Errorf("expected search to return alice, body: %s", body)
	}
	if strings.Contains(body, "bob") || strings.Contains(body, "charlie") {
		t.Errorf("did not expect bob or charlie in filtered results, body: %s", body)
	}
	if !strings.Contains(body, "PageInfo=") || !strings.Contains(body, "Search=ali") {
		t.Errorf("expected pagination info in response, body: %s", body)
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

// TestCreateUser_RejectsInvalidRole is the I-3 regression test: an unsupported
// role must be rejected with 400 instead of being silently downgraded to "user".
func TestCreateUser_RejectsInvalidRole(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	for _, role := range []string{"superadmin", "", "Admin", "user;--"} {
		w := httptest.NewRecorder()
		body := "username=validuser&email=valid@example.com&password=testpass&role=" + role
		r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(ctx)
		h.CreateUser(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("role=%q: expected 400, got %d", role, w.Code)
		}
		if !strings.Contains(w.Body.String(), "Invalid role") {
			t.Errorf("role=%q: expected 'Invalid role' in error page, got: %s", role, w.Body.String())
		}
	}

	// No user must have been created.
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='validuser'").Scan(&count)
	if count != 0 {
		t.Errorf("expected no user created for invalid role, got %d", count)
	}
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_user'").Scan(&count)
	if count != 0 {
		t.Errorf("expected no activity log for invalid role, got %d", count)
	}
}

// TestCreateUser_DuplicateRejected is the L-7 regression test: creating a user
// with a username or email that already exists must return a friendly 400
// message instead of a generic 500. Before the fix, the UNIQUE constraint
// violation surfaced as an undifferentiated internal error.
func TestCreateUser_DuplicateRejected(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	// admin user already exists with username "admin", email "admin@test.local"

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Duplicate username.
	w := httptest.NewRecorder()
	body := "username=admin&email=other@test.local&password=testpass&role=user"
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate username: expected 400, got %d (REVIEW.md L-7)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("expected 'already exists' in error page, got: %s", w.Body.String())
	}

	// Duplicate email (different username but email collides).
	w2 := httptest.NewRecorder()
	body2 := "username=other&email=admin@test.local&password=testpass&role=user"
	r2 := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body2))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2 = r2.WithContext(ctx)
	h.CreateUser(w2, r2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("duplicate email: expected 400, got %d (REVIEW.md L-7)", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "already exists") {
		t.Errorf("expected 'already exists' in error page, got: %s", w2.Body.String())
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

// TestUpdateUser_RejectsInvalidRole is the I-3 regression test: an unsupported
// role must be rejected with 400 instead of being silently downgraded to "user".
// The existing role must be left untouched.
func TestUpdateUser_RejectsInvalidRole(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user2", "user2@example.com", "hash", "admin",
	)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	for _, role := range []string{"superadmin", "", "Admin", "user;--"} {
		w := httptest.NewRecorder()
		body := "email=user2@example.com&first_name=&last_name=&role=" + role
		r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetPathValue("user_id", "2")
		r = r.WithContext(ctx)
		h.UpdateUser(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("role=%q: expected 400, got %d", role, w.Code)
		}
		if !strings.Contains(w.Body.String(), "Invalid role") {
			t.Errorf("role=%q: expected 'Invalid role' in error page, got: %s", role, w.Body.String())
		}
	}

	// The existing role must be unchanged (not silently downgraded to "user").
	var storedRole string
	h.DB.QueryRow("SELECT role FROM users WHERE id=2").Scan(&storedRole)
	if storedRole != "admin" {
		t.Errorf("expected role to remain 'admin' after invalid-role rejection, got %q", storedRole)
	}
}

// TestUpdateUser_RejectsEmptyEmail is the L-6 regression test: UpdateUser must
// require a non-empty email, consistent with CreateUser. Before the fix, an
// empty email bypassed ValidateEmail entirely and could overwrite a valid
// address with "".
func TestUpdateUser_RejectsEmptyEmail(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"user2", "user2@example.com", "hash", "user",
	)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	body := "email=&first_name=&last_name=&role=user"
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty email, got %d (REVIEW.md L-6)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid email") {
		t.Errorf("expected 'Invalid email' in error page, got: %s", w.Body.String())
	}

	// The existing email must be unchanged.
	var stored string
	h.DB.QueryRow("SELECT email FROM users WHERE id=2").Scan(&stored)
	if stored != "user2@example.com" {
		t.Errorf("email was overwritten to %q; must remain user2@example.com", stored)
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

// TestUpdateUser_LastAdminDemotionBlocked is the M-BIZ2 regression test:
// demoting the only enabled admin (role admin→user) must be refused, and
// the guard must execute inside the transaction (same pattern as DeleteUser).
func TestUpdateUser_LastAdminDemotionBlocked(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Try to demote the only enabled admin: role=admin → role=user
	body := "email=admin@test.local&first_name=&last_name=&role=user&enabled=1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/1/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "1")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for last-admin demotion, got %d", w.Code)
	}

	var role string
	h.DB.QueryRow("SELECT role FROM users WHERE id=1").Scan(&role)
	if role != "admin" {
		t.Errorf("expected last admin to remain admin, got role=%q", role)
	}
}

// TestUpdateUser_DemotionWithTwoAdminsAllowed verifies that demotion succeeds
// when there is a second enabled admin (the guard inside the tx sees count=2).
func TestUpdateUser_DemotionWithTwoAdminsAllowed(t *testing.T) {
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
	secondID, _ := res.LastInsertId()

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Demote the second admin (admin → user).
	body := fmt.Sprintf("email=admin2@test.local&first_name=&last_name=&role=user&enabled=1")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/users/%d/update", secondID), strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", fmt.Sprintf("%d", secondID))
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303 for demotion with 2 admins, got %d", w.Code)
	}

	var role string
	h.DB.QueryRow("SELECT role FROM users WHERE id=?", secondID).Scan(&role)
	if role != "user" {
		t.Errorf("expected second admin to be demoted to user, got role=%q", role)
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

// TestDeleteUser_AuditFailureRollsBack guards REVIEW.md B-8 (suppression case):
// the delete_user audit write runs inside the same transaction as the DELETE,
// so a failure to write the audit trail must roll the delete back — a user can
// never be deleted without leaving an audit entry. The audit INSERT is forced
// to fail by dropping the activity_logs table; the target must survive and the
// handler must return 500 (not a redirect).
func TestDeleteUser_AuditFailureRollsBack(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	targetID := testutil.SeedTestUser(t, h.DB, "victim", "p", "user", true)

	// Force every activity_logs INSERT to fail.
	if _, err := h.DB.Exec("DROP TABLE activity_logs"); err != nil {
		t.Fatalf("drop activity_logs: %v", err)
	}

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/delete", strings.NewReader(fmt.Sprintf("user_id=%d", targetID)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteUser(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the audit write fails, got %d (B-8: delete must not succeed without an audit trail)", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", targetID).Scan(&count)
	if count != 1 {
		t.Errorf("expected the delete to be rolled back (user survives), got count=%d (B-8 regression: delete committed without audit)", count)
	}
}

// TestUpdateUser_AuditFailureRollsBack guards REVIEW.md B-8 (admin-demotion
// case): the update_user audit write runs inside the same transaction as the
// UPDATE, so a failure to write the audit trail must roll the role change back
// — an admin can never be demoted without leaving an audit entry.
func TestUpdateUser_AuditFailureRollsBack(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	// A second enabled admin so the last-admin guard allows the demotion.
	res, err := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, ?)`,
		"admin2", "admin2@test.local", "hash", "admin", 1,
	)
	if err != nil {
		t.Fatalf("insert second admin: %v", err)
	}
	secondID, _ := res.LastInsertId()

	// Force every activity_logs INSERT to fail.
	if _, err := h.DB.Exec("DROP TABLE activity_logs"); err != nil {
		t.Fatalf("drop activity_logs: %v", err)
	}

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	body := "email=admin2@test.local&first_name=&last_name=&role=user&enabled=1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/users/%d/update", secondID), strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", fmt.Sprintf("%d", secondID))
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the audit write fails, got %d (B-8: demotion must not succeed without an audit trail)", w.Code)
	}

	var role string
	h.DB.QueryRow("SELECT role FROM users WHERE id = ?", secondID).Scan(&role)
	if role != "admin" {
		t.Errorf("expected the demotion to be rolled back (role stays admin), got role=%q (B-8 regression: demotion committed without audit)", role)
	}
}

func TestLockUser_Success(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	targetID := testutil.SeedTestUser(t, h.DB, "victim", "p", "user", true)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/users/%d/lock", targetID), nil)
	r.SetPathValue("user_id", fmt.Sprintf("%d", targetID))
	r = r.WithContext(ctx)
	h.LockUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	locked, until, err := h.DB.UserLockStatus(context.Background(), targetID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Error("expected target to be locked")
	}
	if !until.After(time.Now()) {
		t.Errorf("expected locked_until in the future, got %v", until)
	}

	var activityCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='lock_user'").Scan(&activityCount)
	if activityCount != 1 {
		t.Errorf("expected 1 lock_user activity log, got %d", activityCount)
	}
}

// TestLockUser_RevokesSessions is the M2 regression: the admin "Lock user"
// action cuts every active session (tokens_valid_after bumped), so the locked
// user is frozen on all devices immediately — not just blocked at the next
// login.
func TestLockUser_RevokesSessions(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	targetID := testutil.SeedTestUser(t, h.DB, "victim", "p", "user", true)

	var tvaBefore time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id = ?", targetID).Scan(&tvaBefore)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/users/%d/lock", targetID), nil)
	r.SetPathValue("user_id", fmt.Sprintf("%d", targetID))
	r = r.WithContext(ctx)
	h.LockUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	var tvaAfter time.Time
	h.DB.QueryRow("SELECT tokens_valid_after FROM users WHERE id = ?", targetID).Scan(&tvaAfter)
	if !tvaAfter.After(tvaBefore) {
		t.Error("expected tokens_valid_after to be bumped when an admin locks a user (M2)")
	}
}

func TestLockUser_SelfBlocked(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/users/%d/lock", admin.ID), nil)
	r.SetPathValue("user_id", fmt.Sprintf("%d", admin.ID))
	r = r.WithContext(ctx)
	h.LockUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for self-lock, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "cannot lock your own account") {
		t.Errorf("expected self-lock rejection message, got %s", w.Body.String())
	}

	locked, _, err := h.DB.UserLockStatus(context.Background(), admin.ID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("admin must not be locked after self-lock attempt")
	}
}

func TestLockUser_SecondAdminAllowed(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	secondAdminID := testutil.SeedTestUser(t, h.DB, "admin2", "p", "admin", true)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/users/%d/lock", secondAdminID), nil)
	r.SetPathValue("user_id", fmt.Sprintf("%d", secondAdminID))
	r = r.WithContext(ctx)
	h.LockUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	locked, _, err := h.DB.UserLockStatus(context.Background(), secondAdminID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Error("second admin should have been locked")
	}
}

func TestLockUser_NotFound(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/99999/lock", nil)
	r.SetPathValue("user_id", "99999")
	r = r.WithContext(ctx)
	h.LockUser(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestLockUser_InvalidID(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/abc/lock", nil)
	r.SetPathValue("user_id", "abc")
	r = r.WithContext(ctx)
	h.LockUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid id, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid user id") {
		t.Errorf("expected invalid-user-id message, got %s", w.Body.String())
	}
}

func TestUnlockUser_Success(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	targetID := testutil.SeedTestUser(t, h.DB, "victim", "p", "user", true)

	// Pre-lock the user via direct DB call.
	if err := h.DB.AdminLockUser(context.Background(), targetID, time.Hour); err != nil {
		t.Fatalf("AdminLockUser: %v", err)
	}

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/users/%d/unlock", targetID), nil)
	r.SetPathValue("user_id", fmt.Sprintf("%d", targetID))
	r = r.WithContext(ctx)
	h.UnlockUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	locked, _, err := h.DB.UserLockStatus(context.Background(), targetID)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected target to be unlocked")
	}

	var activityCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='unlock_user'").Scan(&activityCount)
	if activityCount != 1 {
		t.Errorf("expected 1 unlock_user activity log, got %d", activityCount)
	}
}

func TestUnlockUser_NotFound(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/99999/unlock", nil)
	r.SetPathValue("user_id", "99999")
	r = r.WithContext(ctx)
	h.UnlockUser(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// strictPolicyHandler returns a test handler with the production-default
// strict password policy (min 8 + all character classes) applied.
func strictPolicyHandler(t *testing.T) *Handler {
	t.Helper()
	h := newTestHandler(t)
	h.Cfg.Password.MinLength = 8
	h.Cfg.Password.RequireUppercase = true
	h.Cfg.Password.RequireLowercase = true
	h.Cfg.Password.RequireDigit = true
	h.Cfg.Password.RequireSpecial = true
	return h
}

func TestCreateUser_WeakPasswordRejected(t *testing.T) {
	h := strictPolicyHandler(t)
	admin := seedAdminUser(t, h)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "username=weakuser&email=weak@example.com&password=short&role=user"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	// Must NOT redirect (success path) and the user must not have been created.
	if w.Code == http.StatusSeeOther {
		t.Errorf("weak password should not be accepted (got redirect 303)")
	}
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='weakuser'").Scan(&count)
	if count != 0 {
		t.Errorf("weak-password user should not have been created, got count=%d", count)
	}
}

func TestCreateUser_StrongPasswordRecordsHistory(t *testing.T) {
	h := strictPolicyHandler(t)
	h.Cfg.Password.HistorySize = 3 // enable history retention
	admin := seedAdminUser(t, h)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "username=stronguser&email=strong@example.com&password=Abcdef1!&role=user"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303 for strong password, got %d (body: %s)", w.Code, w.Body.String())
	}
	// The initial password must be recorded in history so future changes can
	// detect reuse.
	var histCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM password_history WHERE user_id=2").Scan(&histCount)
	if histCount != 1 {
		t.Errorf("expected 1 password_history row for the new user, got %d", histCount)
	}
}

func TestUpdateUser_WeakPasswordRejected(t *testing.T) {
	h := strictPolicyHandler(t)
	admin := seedAdminUser(t, h)
	h.DB.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('user2', 'u2@e.com', 'oldhash', 'user')`)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := "email=u2@e.com&first_name=&last_name=&role=user&password=weak"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("user_id", "2")
	r = r.WithContext(ctx)
	h.UpdateUser(w, r)

	if w.Code == http.StatusSeeOther {
		t.Errorf("weak password should not be accepted (got redirect 303)")
	}
	var hash string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id=2").Scan(&hash)
	if hash != "oldhash" {
		t.Errorf("password hash should be unchanged after weak-password rejection, got %q", hash)
	}
}

func TestUpdateUser_PasswordHistoryReuse(t *testing.T) {
	h := strictPolicyHandler(t)
	h.Cfg.Password.HistorySize = 3
	admin := seedAdminUser(t, h)
	h.DB.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('user2', 'u2@e.com', 'oldhash', 'user')`)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	doUpdate := func(password string) int {
		body := "email=u2@e.com&first_name=&last_name=&role=user&password=" + password
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/users/2/update", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetPathValue("user_id", "2")
		r = r.WithContext(ctx)
		h.UpdateUser(w, r)
		return w.Code
	}

	// First change to a strong password: accepted and recorded in history.
	if code := doUpdate("Str0ng!aa"); code != http.StatusSeeOther {
		t.Fatalf("first change expected redirect 303, got %d", code)
	}
	var hashAfterFirst string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id=2").Scan(&hashAfterFirst)

	// Reusing the same password must be rejected by the history check.
	if code := doUpdate("Str0ng!aa"); code == http.StatusSeeOther {
		t.Errorf("reusing the same password should be rejected (got redirect 303)")
	}
	var hashAfterReuse string
	h.DB.QueryRow("SELECT password_hash FROM users WHERE id=2").Scan(&hashAfterReuse)
	if hashAfterReuse != hashAfterFirst {
		t.Errorf("password hash should be unchanged after a rejected reuse, got %q (want %q)", hashAfterReuse, hashAfterFirst)
	}

	// A different strong password is accepted.
	if code := doUpdate("Str0ng!bb"); code != http.StatusSeeOther {
		t.Errorf("different strong password expected redirect 303, got %d", code)
	}
}

func TestBulkDeleteUsers_Success(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	u2 := testutil.SeedTestUser(t, h.DB, "user2", "p", "user", true)
	u3 := testutil.SeedTestUser(t, h.DB, "user3", "p", "user", true)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Delete u2 and u3; u2 duplicated to exercise dedupe.
	body := fmt.Sprintf("user_id=%d&user_id=%d&user_id=%d", u2, u3, u2)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteUsers(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Deleted int      `json:"deleted"`
		Failed  []string `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Deleted != 2 || len(resp.Failed) != 0 {
		t.Errorf("expected deleted=2 failed=[], got %+v", resp)
	}

	var remaining int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id IN (?, ?)", u2, u3).Scan(&remaining)
	if remaining != 0 {
		t.Errorf("expected u2 and u3 gone, got %d remaining", remaining)
	}
	var logCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_user'").Scan(&logCount)
	if logCount != 2 {
		t.Errorf("expected 2 delete_user logs, got %d", logCount)
	}
}

func TestBulkDeleteUsers_SelfSkipped(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	u2 := testutil.SeedTestUser(t, h.DB, "user2", "p", "user", true)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	// Self (admin.ID) + a real user.
	body := fmt.Sprintf("user_id=%d&user_id=%d", admin.ID, u2)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteUsers(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Deleted int      `json:"deleted"`
		Failed  []string `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Deleted != 1 {
		t.Errorf("expected deleted=1, got %d", resp.Deleted)
	}
	if len(resp.Failed) != 1 || resp.Failed[0] != fmt.Sprintf("%d", admin.ID) {
		t.Errorf("expected failed=[%d (self)], got %+v", admin.ID, resp.Failed)
	}

	var adminCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id=?", admin.ID).Scan(&adminCount)
	if adminCount != 1 {
		t.Errorf("admin should not have been deleted (self guard)")
	}
}

// TestBulkDeleteUsers_LastAdminGuard verifies the per-iteration last-admin
// guard: deleting 2 of 3 enabled admins is allowed (each check sees count>1),
// but a disabled-admin actor cannot remove the only enabled admin.
func TestBulkDeleteUsers_LastAdminGuard(t *testing.T) {
	h := newTestHandler(t)
	enabledAdmin := seedAdminUser(t, h) // id 1, enabled
	// Disabled admin acts; they reach the handler (RequireAdmin checks role,
	// not enabled) but the last-enabled-admin guard must still protect id 1.
	disabledAdminID := testutil.SeedTestUser(t, h.DB, "admin2", "p", "admin", false)
	actor := &models.User{ID: disabledAdminID, Username: "admin2", Role: "admin"}
	u3 := testutil.SeedTestUser(t, h.DB, "user3", "p", "user", true)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, actor)

	// enabledAdmin (last enabled admin) must be refused; u3 (regular user) ok.
	body := fmt.Sprintf("user_id=%d&user_id=%d", enabledAdmin.ID, u3)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteUsers(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (best-effort), got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Deleted int      `json:"deleted"`
		Failed  []string `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Deleted != 1 {
		t.Errorf("expected deleted=1 (user3), got %d", resp.Deleted)
	}
	if len(resp.Failed) != 1 || resp.Failed[0] != fmt.Sprintf("%d", enabledAdmin.ID) {
		t.Errorf("expected failed=[%d (last admin)], got %+v", enabledAdmin.ID, resp.Failed)
	}

	var stillThere int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id=?", enabledAdmin.ID).Scan(&stillThere)
	if stillThere != 1 {
		t.Errorf("last enabled admin must not be deleted")
	}
}

// TestBulkDeleteUsers_MultipleAdminsAllowed verifies that selecting several
// enabled admins still leaves at least one: each successful DELETE lowers the
// CountEnabledAdmins seen by the next iteration.
func TestBulkDeleteUsers_MultipleAdminsAllowed(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h) // id 1, enabled, the actor (survives)
	a2 := testutil.SeedTestUser(t, h.DB, "admin2", "p", "admin", true)
	a3 := testutil.SeedTestUser(t, h.DB, "admin3", "p", "admin", true)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	body := fmt.Sprintf("user_id=%d&user_id=%d", a2, a3)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteUsers(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Deleted int      `json:"deleted"`
		Failed  []string `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Deleted != 2 || len(resp.Failed) != 0 {
		t.Errorf("expected deleted=2 failed=[], got %+v", resp)
	}

	var enabledAdmins int
	h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1").Scan(&enabledAdmins)
	if enabledAdmins != 1 {
		t.Errorf("expected exactly 1 enabled admin remaining (the actor), got %d", enabledAdmins)
	}
}

func TestBulkDeleteUsers_NoSelection(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/bulk-delete", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteUsers(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty selection, got %d", w.Code)
	}
}

// TestCreateUser_PasswordTooLongGetsClearMessage verifies that a passphrase
// longer than 72 bytes is rejected by the password policy with an actionable
// byte-based message. Previously no upper bound existed: bcrypt refused the
// hash and the admin saw an opaque "Failed to hash password" that read like a
// server fault — for exactly the long passphrases a password manager produces.
func TestCreateUser_PasswordTooLongGetsClearMessage(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.Password.MaxLength = 72
	admin := seedAdminUser(t, h)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, admin)

	tooLong := strings.Repeat("a", 73)
	body := "username=longuser&email=long@example.com&password=" + tooLong + "&role=user"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateUser(w, r)

	if w.Code == http.StatusSeeOther {
		t.Fatal("73-byte password must not create the user")
	}
	page := w.Body.String()
	if !strings.Contains(page, "at most 72 bytes") {
		t.Errorf("expected the byte-based validation message, got: %s", page)
	}
	if strings.Contains(page, "Failed to hash password") {
		t.Error("the opaque hashing failure must not be the surfaced message")
	}
}

// TestPasswordHashErrorMessage pins the bcrypt sentinel translation: an
// over-long password reads as an actionable limit, anything else stays the
// generic hashing failure.
func TestPasswordHashErrorMessage(t *testing.T) {
	if got := passwordHashErrorMessage(bcrypt.ErrPasswordTooLong); !strings.Contains(got, "72 bytes") {
		t.Errorf("ErrPasswordTooLong message = %q, want it to mention the 72-byte limit", got)
	}
	if got := passwordHashErrorMessage(errors.New("some other failure")); got != "Failed to hash password" {
		t.Errorf("unrelated error message = %q, want the generic failure", got)
	}
}

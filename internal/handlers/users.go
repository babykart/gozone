package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// ListUsers renders the user management page (GET /users).
//
// Admin-only. Lists all users ordered by username.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	rows, err := h.DB.Query(
		`SELECT id, username, email, first_name, last_name, role, enabled, created_at, updated_at
		 FROM users ORDER BY username`,
	)
	if err != nil {
		h.renderError(w, r, "Failed to fetch users: "+err.Error())
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		var enabled int
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
			&u.Role, &enabled, &u.CreatedAt, &u.UpdatedAt)
		u.Enabled = enabled == 1
		users = append(users, u)
	}

	data := map[string]interface{}{
		"Title": "Users - GoZone",
		"User":  user,
		"Users": users,
	}
	h.render(w, r, "users.html", data)
}

// CreateUserPage renders the user creation form (GET /users/new).
//
// Admin-only.
func (h *Handler) CreateUserPage(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	data := map[string]interface{}{
		"Title": "Create User - GoZone",
		"User":  admin,
	}
	h.render(w, r, "user_create.html", data)
}

// CreateUser creates a new user from form data (POST /users/create).
//
// Admin-only. Accepts username, email, password, first_name, last_name, and role.
// The password is hashed with bcrypt before storage.
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := strings.TrimSpace(r.FormValue("password"))
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	role := strings.TrimSpace(r.FormValue("role"))

	if username == "" || email == "" || password == "" {
		http.Redirect(w, r, "/users/new", http.StatusSeeOther)
		return
	}

	if err := validators.ValidateUsername(username); err != nil {
		h.renderError(w, r, "Invalid username: "+err.Error())
		return
	}
	if err := validators.ValidateEmail(email); err != nil {
		h.renderError(w, r, "Invalid email: "+err.Error())
		return
	}

	if role != "admin" && role != "user" {
		role = "user"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.Cfg.Auth.BcryptCost)
	if err != nil {
		h.renderError(w, r, "Failed to hash password")
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		h.renderError(w, r, "Failed to begin transaction: "+err.Error())
		return
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		username, email, string(hash), firstName, lastName, role,
	)
	if err != nil {
		h.renderError(w, r, "Failed to create user: "+err.Error())
		return
	}

	userID, _ := result.LastInsertId()
	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'create_user', ?)",
		admin.ID, fmt.Sprintf("Created user %s (id: %d)", username, userID),
	)
	if err != nil {
		h.renderError(w, r, "Failed to log activity: "+err.Error())
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderError(w, r, "Failed to commit transaction: "+err.Error())
		return
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// EditUserPage renders the user edit form (GET /users/{user_id}/edit).
//
// Admin-only. Loads the target user by user_id path parameter.
func (h *Handler) EditUserPage(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	userIDStr := r.PathValue("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid user ID")
		return
	}

	var target models.User
	var enabled int
	err = h.DB.QueryRow(
		`SELECT id, username, email, first_name, last_name, role, enabled, created_at, updated_at
		 FROM users WHERE id = ?`, userID,
	).Scan(&target.ID, &target.Username, &target.Email, &target.FirstName, &target.LastName,
		&target.Role, &enabled, &target.CreatedAt, &target.UpdatedAt)
	target.Enabled = enabled == 1

	if err != nil {
		h.renderError(w, r, "User not found")
		return
	}

	data := map[string]interface{}{
		"Title":      "Edit User - GoZone",
		"User":       admin,
		"TargetUser": target,
	}
	h.render(w, r, "user_edit.html", data)
}

// UpdateUser updates a user's profile from form data (POST /users/{user_id}/update).
//
// Admin-only. Updates email, first_name, last_name, role, and enabled status.
// If a new password is provided, it is hashed and stored separately.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	userIDStr := r.PathValue("user_id")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	role := strings.TrimSpace(r.FormValue("role"))
	enabled := r.FormValue("enabled") == "on"
	newPassword := strings.TrimSpace(r.FormValue("password"))

	if role != "admin" && role != "user" {
		role = "user"
	}

	if email != "" {
		if err := validators.ValidateEmail(email); err != nil {
			h.renderError(w, r, "Invalid email: "+err.Error())
			return
		}
	}

	enabledVal := 0
	if enabled {
		enabledVal = 1
	}

	tx, err := h.DB.Begin()
	if err != nil {
		h.renderError(w, r, "Failed to begin transaction: "+err.Error())
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`UPDATE users SET email = ?, first_name = ?, last_name = ?, role = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		email, firstName, lastName, role, enabledVal, userID,
	)
	if err != nil {
		h.renderError(w, r, "Failed to update user: "+err.Error())
		return
	}

	// Update password if provided
	if newPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), h.Cfg.Auth.BcryptCost)
		if err != nil {
			h.renderError(w, r, "Failed to hash password")
			return
		}
		_, err = tx.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), userID)
		if err != nil {
			h.renderError(w, r, "Failed to update password: "+err.Error())
			return
		}
	}

	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'update_user', ?)",
		admin.ID, fmt.Sprintf("Updated user %d", userID),
	)
	if err != nil {
		h.renderError(w, r, "Failed to log activity: "+err.Error())
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderError(w, r, "Failed to commit transaction: "+err.Error())
		return
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// DeleteUser deletes a user by user_id form value (POST /users/delete).
//
// Admin-only. An admin cannot delete themselves.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	userIDStr := r.FormValue("user_id")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	// Don't allow deleting yourself
	if userID == admin.ID {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		h.renderError(w, r, "Failed to begin transaction: "+err.Error())
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		h.renderError(w, r, "Failed to delete user: "+err.Error())
		return
	}

	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_user', ?)",
		admin.ID, fmt.Sprintf("Deleted user %d", userID),
	)
	if err != nil {
		h.renderError(w, r, "Failed to log activity: "+err.Error())
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderError(w, r, "Failed to commit transaction: "+err.Error())
		return
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

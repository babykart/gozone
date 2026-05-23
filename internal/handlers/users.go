package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// ListUsers displays all users (admin only).
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if !user.IsAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rows, err := h.DB.Query(
		`SELECT id, username, email, first_name, last_name, role, enabled, created_at, updated_at
		 FROM users ORDER BY username`,
	)
	if err != nil {
		h.renderError(w, "Failed to fetch users: "+err.Error())
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
	h.render(w, "users.html", data)
}

// CreateUserPage displays the user creation form.
func (h *Handler) CreateUserPage(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)
	if !admin.IsAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	data := map[string]interface{}{
		"Title": "Create User - GoZone",
		"User":  admin,
	}
	h.render(w, "user_create.html", data)
}

// CreateUser handles user creation.
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)
	if !admin.IsAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

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

	if role != "admin" && role != "user" {
		role = "user"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.Cfg.Auth.BcryptCost)
	if err != nil {
		h.renderError(w, "Failed to hash password")
		return
	}

	result, err := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		username, email, string(hash), firstName, lastName, role,
	)
	if err != nil {
		h.renderError(w, "Failed to create user: "+err.Error())
		return
	}

	userID, _ := result.LastInsertId()
	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'create_user', ?)",
		admin.ID, fmt.Sprintf("Created user %s (id: %d)", username, userID),
	)

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// EditUserPage displays the user edit form.
func (h *Handler) EditUserPage(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)
	if !admin.IsAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	userIDStr := r.PathValue("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		h.renderError(w, "Invalid user ID")
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
		h.renderError(w, "User not found")
		return
	}

	data := map[string]interface{}{
		"Title":      "Edit User - GoZone",
		"User":       admin,
		"TargetUser": target,
	}
	h.render(w, "user_edit.html", data)
}

// UpdateUser handles user updates.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)
	if !admin.IsAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

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

	enabledVal := 0
	if enabled {
		enabledVal = 1
	}

	_, err := h.DB.Exec(
		`UPDATE users SET email = ?, first_name = ?, last_name = ?, role = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		email, firstName, lastName, role, enabledVal, userID,
	)
	if err != nil {
		h.renderError(w, "Failed to update user: "+err.Error())
		return
	}

	// Update password if provided
	if newPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), h.Cfg.Auth.BcryptCost)
		if err != nil {
			h.renderError(w, "Failed to hash password")
			return
		}
		h.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), userID)
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'update_user', ?)",
		admin.ID, fmt.Sprintf("Updated user %d", userID),
	)

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// DeleteUser handles user deletion.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)
	if !admin.IsAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

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

	_, err := h.DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		h.renderError(w, "Failed to delete user: "+err.Error())
		return
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_user', ?)",
		admin.ID, fmt.Sprintf("Deleted user %d", userID),
	)

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// Unused import guard
var _ = sql.ErrNoRows

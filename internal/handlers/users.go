package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// ListUsers renders the user management page (GET /users).
//
// Admin-only. Lists users ordered by username with optional search, pagination,
// and per-page sizing pushed to the database.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	where, args := buildSearchLikeWhere(search, "username", "email", "first_name", "last_name")

	countQuery := "SELECT COUNT(*) FROM users"
	selectQuery := `SELECT id, username, email, first_name, last_name, role, enabled, locked_until, created_at, updated_at
		FROM users`
	if where != "" {
		countQuery += " WHERE " + where
		selectQuery += " WHERE " + where
	}
	selectQuery += " ORDER BY username"

	var total int
	if err := h.DB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		h.renderInternalError(w, r, "Failed to count users", err)
		return
	}

	page, perPage := parsePaginationParams(r, 10)
	pageInfo := pageInfoFromTotal(total, page, perPage)

	var rows *sql.Rows
	var err error
	if perPage > 0 {
		offset := (pageInfo.Current - 1) * perPage
		selectArgs := append([]any(nil), args...)
		selectArgs = append(selectArgs, perPage, offset)
		rows, err = h.DB.Query(selectQuery+" LIMIT ? OFFSET ?", selectArgs...)
	} else {
		rows, err = h.DB.Query(selectQuery, args...)
	}
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch users", err)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		var enabled int
		var lockedUntil sql.NullTime
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
			&u.Role, &enabled, &lockedUntil, &u.CreatedAt, &u.UpdatedAt); err != nil {
			logger.Error("failed to scan user row", "error", err)
			continue
		}
		u.Enabled = enabled == 1
		if lockedUntil.Valid {
			t := lockedUntil.Time
			u.LockedUntil = &t
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for users list", "error", err)
	}

	if users == nil {
		users = []models.User{}
	}

	data := map[string]interface{}{
		"Title":    "Users - " + h.Cfg.Server.AppName,
		"User":     user,
		"Users":    users,
		"PageInfo": pageInfo,
		"Search":   search,
	}
	h.render(w, r, "users.html", data)
}

// CreateUserPage renders the user creation form (GET /users/new).
//
// Admin-only.
func (h *Handler) CreateUserPage(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	data := map[string]interface{}{
		"Title": "Create User - " + h.Cfg.Server.AppName,
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

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := strings.TrimSpace(r.FormValue("password"))
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	role := strings.TrimSpace(r.FormValue("role"))
	// Optional "force password change on first login" toggle. Secure-by-default:
	// the form renders the checkbox checked, so an admin-set initial password is
	// rotated on first login unless the admin explicitly opts out.
	forceChangeStr := strings.TrimSpace(r.FormValue("force_password_change"))
	forceChange := forceChangeStr == "1" || forceChangeStr == "on" || forceChangeStr == "true"
	mustChangeVal := 0
	if forceChange {
		mustChangeVal = 1
	}

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
	if err := validators.ValidatePassword(password, h.Cfg.Password.Policy()); err != nil {
		h.renderError(w, r, err.Error())
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
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role, must_change_password)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		username, email, string(hash), firstName, lastName, role, mustChangeVal,
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to create user", err)
		return
	}

	userID, _ := result.LastInsertId()
	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'create_user', ?)",
		admin.ID, fmt.Sprintf("Created user %s (id: %d)", username, userID),
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to log activity", err)
		return
	}

	// Record the initial password in history so future changes can detect
	// reuse (no reuse check here — this is the account's first password).
	if h.Cfg.Password.HistorySize > 0 {
		if err := tx.RecordPassword(r.Context(), userID, string(hash)); err != nil {
			h.renderInternalError(w, r, "Failed to record password history", err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
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
		h.renderErrorStatus(w, r, http.StatusNotFound, "User not found")
		return
	}

	data := map[string]interface{}{
		"Title":      "Edit User - " + h.Cfg.Server.AppName,
		"User":       admin,
		"TargetUser": target,
		"IsSelf":     target.ID == admin.ID,
	}
	h.render(w, r, "user_edit.html", data)
}

// UpdateUser updates a user's profile from form data (POST /users/{user_id}/update).
//
// Admin-only. Updates email, first_name, last_name, role, and enabled status.
// If a new password is provided, it is hashed and stored separately.
// An admin cannot change their own role or enabled status, and the last
// enabled admin cannot be demoted or disabled.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	userIDStr := r.PathValue("user_id")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	email := strings.TrimSpace(r.FormValue("email"))
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	role := strings.TrimSpace(r.FormValue("role"))
	enabledStr := strings.TrimSpace(r.FormValue("enabled"))
	enabled := enabledStr == "1" || enabledStr == "on" || enabledStr == "true"
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
	if newPassword != "" {
		if err := validators.ValidatePassword(newPassword, h.Cfg.Password.Policy()); err != nil {
			h.renderError(w, r, err.Error())
			return
		}
	}

	// Fetch the target user to compare current role/enabled and enforce guards.
	var target models.User
	var targetEnabled int
	err := h.DB.QueryRow(
		`SELECT id, username, email, first_name, last_name, role, enabled
		 FROM users WHERE id = ?`, userID,
	).Scan(&target.ID, &target.Username, &target.Email, &target.FirstName, &target.LastName,
		&target.Role, &targetEnabled)
	if err != nil {
		h.renderErrorStatus(w, r, http.StatusNotFound, "User not found")
		return
	}
	target.Enabled = targetEnabled == 1

	requestedRole := role
	requestedEnabled := enabled

	// Self-edit: role and enabled status are immutable.
	if userID == admin.ID && (requestedRole != target.Role || requestedEnabled != target.Enabled) {
		h.renderError(w, r, "You cannot change your own role or enabled status")
		return
	}

	enabledVal := 0
	if requestedEnabled {
		enabledVal = 1
	}

	tx, err := h.DB.Begin()
	if err != nil {
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	// Last enabled admin guard: refuse to demote or disable the only enabled
	// admin. Checked INSIDE the transaction to prevent TOCTOU (M-BIZ2): two
	// concurrent UpdateUser calls demoting the last two admins must not both
	// observe adminCount==2 and proceed, leaving zero admins.
	if target.Role == "admin" && target.Enabled && (requestedRole != "admin" || !requestedEnabled) {
		adminCount, err := tx.CountEnabledAdmins(r.Context())
		if err != nil {
			h.renderInternalError(w, r, "Failed to count admins", err)
			return
		}
		if adminCount <= 1 {
			h.renderError(w, r, "Cannot demote or disable the last enabled admin")
			return
		}
	}

	_, err = tx.Exec(
		`UPDATE users SET email = ?, first_name = ?, last_name = ?, role = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		email, firstName, lastName, requestedRole, enabledVal, userID,
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to update user", err)
		return
	}

	// Update password if provided
	if newPassword != "" {
		// Prevent reuse of a recent password (includes the current one, which
		// is part of the history). Checked inside the transaction.
		if h.Cfg.Password.HistorySize > 0 {
			reused, err := tx.PasswordHistoryReused(r.Context(), userID, newPassword, h.Cfg.Password.HistorySize)
			if err != nil {
				h.renderInternalError(w, r, "Failed to check password history", err)
				return
			}
			if reused {
				h.renderError(w, r, "Password was used recently; choose a different one")
				return
			}
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), h.Cfg.Auth.BcryptCost)
		if err != nil {
			h.renderError(w, r, "Failed to hash password")
			return
		}
		_, err = tx.Exec("UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, must_change_password = 1 WHERE id = ?", string(hash), userID)
		if err != nil {
			h.renderInternalError(w, r, "Failed to update password", err)
			return
		}
		if h.Cfg.Password.HistorySize > 0 {
			if err := tx.RecordPassword(r.Context(), userID, string(hash)); err != nil {
				h.renderInternalError(w, r, "Failed to record password history", err)
				return
			}
			if err := tx.PrunePasswordHistory(r.Context(), userID, h.Cfg.Password.HistorySize); err != nil {
				h.renderInternalError(w, r, "Failed to prune password history", err)
				return
			}
		}
	}

	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'update_user', ?)",
		admin.ID, fmt.Sprintf("Updated user %d", userID),
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to log activity", err)
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
		return
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// DeleteUser deletes a user by user_id form value (POST /users/delete).
//
// Admin-only. An admin cannot delete themselves.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	userIDStr := r.FormValue("user_id")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	// Don't allow deleting yourself
	if userID == admin.ID {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	// Fetch the target user and verify they exist.
	var target models.User
	var targetEnabled int
	if err := tx.QueryRow(
		`SELECT id, username, role, enabled FROM users WHERE id = ?`,
		userID,
	).Scan(&target.ID, &target.Username, &target.Role, &targetEnabled); err != nil {
		h.renderErrorStatus(w, r, http.StatusNotFound, "User not found")
		return
	}
	target.Enabled = targetEnabled == 1

	// Last enabled admin guard: refuse to delete the only enabled admin.
	if target.Role == "admin" && target.Enabled {
		adminCount, err := tx.CountEnabledAdmins(r.Context())
		if err != nil {
			h.renderInternalError(w, r, "Failed to count admins", err)
			return
		}
		if adminCount <= 1 {
			h.renderError(w, r, "Cannot delete the last enabled admin")
			return
		}
	}

	_, err = tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to delete user", err)
		return
	}

	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_user', ?)",
		admin.ID, fmt.Sprintf("Deleted user %d", userID),
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to log activity", err)
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
		return
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// BulkDeleteUsers deletes several users by user_id
// (POST /users/bulk-delete).
//
// Admin-only. Preserves the two DeleteUser invariants per selected user:
//   - an admin cannot delete themselves (self is reported as failed);
//   - the last enabled admin can never be removed.
//
// The last-admin guard is checked per user INSIDE the single batch transaction,
// so a selection containing several enabled admins still leaves at least one:
// each successful DELETE lowers the CountEnabledAdmins value seen by the next
// iteration (the transaction's own view includes its uncommitted deletes).
// Failures (self, not-found, last admin) are skipped and reported in `failed`
// without aborting the rest. Returns JSON {deleted, failed}.
func (h *Handler) BulkDeleteUsers(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid form data"})
		return
	}

	// Dedupe while preserving order; drop anything that is not a positive int.
	seen := make(map[int64]struct{})
	var userIDs []int64
	for _, idStr := range r.PostForm["user_id"] {
		id, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		userIDs = append(userIDs, id)
	}

	if len(userIDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No users selected"})
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		logger.Error("BulkDeleteUsers: begin tx", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to begin transaction"})
		return
	}
	defer tx.Rollback()

	deleted := 0
	var failed []string
	for _, userID := range userIDs {
		// Guard 1: an admin cannot delete themselves.
		if userID == admin.ID {
			failed = append(failed, strconv.FormatInt(userID, 10))
			continue
		}
		// Fetch the target to enforce the last-admin guard.
		var role string
		var enabled int
		switch err := tx.QueryRow(`SELECT role, enabled FROM users WHERE id = ?`, userID).Scan(&role, &enabled); {
		case errors.Is(err, sql.ErrNoRows):
			failed = append(failed, strconv.FormatInt(userID, 10))
			continue
		case err != nil:
			logger.Error("BulkDeleteUsers: fetch user", "user_id", userID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch user"})
			return
		}
		// Guard 2: never delete the last enabled admin.
		if role == "admin" && enabled == 1 {
			adminCount, err := tx.CountEnabledAdmins(r.Context())
			if err != nil {
				logger.Error("BulkDeleteUsers: count admins", "error", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to count admins"})
				return
			}
			if adminCount <= 1 {
				failed = append(failed, strconv.FormatInt(userID, 10))
				continue
			}
		}
		if _, err := tx.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
			logger.Error("BulkDeleteUsers: delete user", "user_id", userID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete user"})
			return
		}
		if _, err := tx.Exec(
			"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_user', ?)",
			admin.ID, fmt.Sprintf("Deleted user %d", userID),
		); err != nil {
			logger.Error("BulkDeleteUsers: log activity", "user_id", userID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to log activity"})
			return
		}
		deleted++
	}

	if err := tx.Commit(); err != nil {
		logger.Error("BulkDeleteUsers: commit", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to commit transaction"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}

// LockUser locks a user account for the configured auto-lockout duration
// (POST /users/{user_id}/lock). Admin-only. Refuses to lock the requesting
// admin themselves to avoid self-DOS — this is the only effective last-admin
// guard since the route is also wrapped by RequireAdmin (a non-admin cannot
// reach the handler).
//
// The action is idempotent: locking an already-locked user extends the window
// and resets the failed-login counter to zero.
func (h *Handler) LockUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)
	targetID, err := strconv.ParseInt(r.PathValue("user_id"), 10, 64)
	if err != nil || targetID <= 0 {
		h.renderError(w, r, "Invalid user id")
		return
	}

	if admin.ID == targetID {
		h.renderError(w, r, "You cannot lock your own account")
		return
	}

	ctx := r.Context()

	if _, err := h.loadTargetUser(ctx, targetID); err != nil {
		h.renderErrorStatus(w, r, http.StatusNotFound, "User not found")
		return
	}

	lockFor := time.Duration(h.Cfg.LoginLock.LockoutDurationMinutes) * time.Minute
	if lockFor <= 0 {
		lockFor = 15 * time.Minute
	}
	if err := h.DB.AdminLockUser(ctx, targetID, lockFor); err != nil {
		h.renderInternalError(w, r, "Failed to lock user", err)
		return
	}

	if _, err := h.DB.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'lock_user', ?)",
		admin.ID, fmt.Sprintf("Locked user id=%d", targetID),
	); err != nil {
		logger.Error("failed to log lock_user activity", "target_id", targetID, "error", err)
	}

	logger.Info("user locked by admin", "admin", admin.Username, "target_id", targetID, "duration", lockFor.String())
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// UnlockUser clears the lockout on a user account and resets the failed-login
// counter (POST /users/{user_id}/unlock). Admin-only. The action is idempotent
// — unlocking a non-locked user is a no-op on the database side but still
// writes an activity-log entry so admins have an audit trail of "unlock"
// attempts.
func (h *Handler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUser(r)
	targetID, err := strconv.ParseInt(r.PathValue("user_id"), 10, 64)
	if err != nil || targetID <= 0 {
		h.renderError(w, r, "Invalid user id")
		return
	}

	ctx := r.Context()

	target, err := h.loadTargetUser(ctx, targetID)
	if err != nil {
		h.renderErrorStatus(w, r, http.StatusNotFound, "User not found")
		return
	}

	if err := h.DB.AdminUnlockUser(ctx, targetID); err != nil {
		h.renderInternalError(w, r, "Failed to unlock user", err)
		return
	}

	if _, err := h.DB.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'unlock_user', ?)",
		admin.ID, fmt.Sprintf("Unlocked user %s (id=%d)", target.Username, targetID),
	); err != nil {
		logger.Error("failed to log unlock_user activity", "target_id", targetID, "error", err)
	}

	logger.Info("user unlocked by admin", "admin", admin.Username, "target", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// loadTargetUser fetches a user by id, returning sql.ErrNoRows via the wrapped
// error path so callers can render 404s.
func (h *Handler) loadTargetUser(ctx context.Context, id int64) (*models.User, error) {
	var u models.User
	var enabled int
	var lockedUntil sql.NullTime
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, username, email, password_hash, first_name, last_name, role, enabled, locked_until, created_at, updated_at
		 FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash,
		&u.FirstName, &u.LastName, &u.Role, &enabled, &lockedUntil,
		&u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled == 1
	if lockedUntil.Valid {
		t := lockedUntil.Time
		u.LockedUntil = &t
	}
	return &u, nil
}

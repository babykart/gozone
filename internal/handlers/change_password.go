package handlers

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/validators"
)

// ChangePasswordPage renders the self-service password-change form
// (GET /change-password). Reached either voluntarily from the profile area or
// forcibly after a login where must_change_password was set (admin reset or
// password expiry).
func (h *Handler) ChangePasswordPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	data := map[string]interface{}{
		"Title": "Change Password - " + h.Cfg.Server.AppName,
		"User":  user,
		// MustChange is surfaced to the template so the forced-change page can
		// explain why the user is here (admin reset / expiry) vs. a voluntary
		// change.
		"MustChange": user != nil && user.MustChangePassword,
	}
	h.render(w, r, "change_password.html", data)
}

// ChangePassword handles a self-service password change (POST /change-password).
//
// It verifies the current password, validates the new one against the policy
// and history, writes the new hash, and clears must_change_password so the
// force-change gate reopens. The whole operation runs in a transaction.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	currentPassword := r.FormValue("current_password")
	newPassword := strings.TrimSpace(r.FormValue("new_password"))
	confirm := strings.TrimSpace(r.FormValue("confirm_password"))

	// Verify the current password. This is meaningful for both flows: a user
	// whose password an admin reset knows the temp password (enter it as
	// "current"), and an expired-password user knows their old password.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		h.renderError(w, r, "Current password is incorrect")
		return
	}
	if newPassword == "" {
		h.renderError(w, r, "New password must not be empty")
		return
	}
	if newPassword != confirm {
		h.renderError(w, r, "New password and confirmation do not match")
		return
	}
	if err := validators.ValidatePassword(newPassword, h.Cfg.Password.Policy()); err != nil {
		h.renderError(w, r, err.Error())
		return
	}

	ctx := r.Context()
	tx, err := h.DB.Begin()
	if err != nil {
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	if h.Cfg.Password.HistorySize > 0 {
		reused, err := tx.PasswordHistoryReused(ctx, user.ID, newPassword, h.Cfg.Password.HistorySize)
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

	if _, err := tx.Exec(
		"UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, must_change_password = 0 WHERE id = ?",
		string(hash), user.ID,
	); err != nil {
		h.renderInternalError(w, r, "Failed to update password", err)
		return
	}

	if h.Cfg.Password.HistorySize > 0 {
		if err := tx.RecordPassword(ctx, user.ID, string(hash)); err != nil {
			h.renderInternalError(w, r, "Failed to record password history", err)
			return
		}
		if err := tx.PrunePasswordHistory(ctx, user.ID, h.Cfg.Password.HistorySize); err != nil {
			h.renderInternalError(w, r, "Failed to prune password history", err)
			return
		}
	}

	if _, err := tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'change_password', ?)",
		user.ID, "User changed their own password",
	); err != nil {
		h.renderInternalError(w, r, "Failed to log activity", err)
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
		return
	}

	logger.Info("user changed their own password", "user_id", user.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

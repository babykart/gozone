package handlers

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/constants"
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
//
// The current password hash is refetched inside the transaction rather than
// read from the request context: loadUser no longer selects password_hash
// (REVIEW.md L-9), and reading it under the tx closes the TOCTOU window
// between the verify and the UPDATE — the hash we compare is the same one we
// will overwrite a few statements down.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	currentPassword := r.FormValue("current_password")
	newPassword := strings.TrimSpace(r.FormValue("new_password"))
	confirm := strings.TrimSpace(r.FormValue("confirm_password"))

	// Validate the form first (cheap, no DB) so an invalid submission does
	// not needlessly open a transaction or run bcrypt.
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
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	// Refetch the current hash inside the tx so the verify-and-replace
	// sequence is atomic (REVIEW.md L-9): loadUser no longer carries the
	// hash in the request context, and reading it under the transaction
	// means the hash we bcrypt-compare is the same row we UPDATE below.
	var currentHash string
	if err := tx.QueryRowContext(ctx,
		"SELECT password_hash FROM users WHERE id = ?", user.ID,
	).Scan(&currentHash); err != nil {
		h.renderInternalError(w, r, "Failed to verify current password", err)
		return
	}
	// Verify the current password. This is meaningful for both flows: a user
	// whose password an admin reset knows the temp password (enter it as
	// "current"), and an expired-password user knows their old password.
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(currentPassword)); err != nil {
		h.renderError(w, r, "Current password is incorrect")
		return
	}

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
		h.renderError(w, r, passwordHashErrorMessage(err))
		return
	}

	if _, err := tx.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, must_change_password = 0, tokens_valid_after = CURRENT_TIMESTAMP WHERE id = ?",
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

	if err := logActivity(ctx, tx, activityEntry{UserID: user.ID, Action: "change_password", Details: "User changed their own password"}); err != nil {
		h.renderInternalError(w, r, "Failed to log activity", err)
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
		return
	}

	// Re-issue the current session so the user stays logged in:
	// tokens_valid_after was just bumped to now, which invalidates every access
	// token minted before this instant — including the cookie this request
	// arrived with, and any session on another device / a stolen JWT. A fresh
	// token carries an iat >= the cutoff and so survives the Auth middleware's
	// check on the next request; the overwritten cookie drops the stale one.
	duration := time.Duration(h.Cfg.Auth.SessionDurationHours) * time.Hour
	newToken, err := middleware.GenerateToken(user, h.Cfg.Server.JWTKey, duration)
	if err != nil {
		h.renderInternalError(w, r, "Failed to issue session token", err)
		return
	}
	// #nosec G124 -- Secure flag set dynamically via isSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     constants.SessionCookieName,
		Value:    newToken,
		Path:     "/",
		Expires:  time.Now().Add(duration),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecure(r),
	})

	logger.Info("user changed their own password", "user_id", user.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

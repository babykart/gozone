package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// Login error codes returned in the ?error=<code> query string on the login
// page. The user-facing banner always maps the same code to a single generic
// message so an attacker cannot enumerate valid usernames by triggering the
// lockout and observing a different error (the historic "account_locked"
// banner). Future codes (CSRF, expired session, etc.) get their own lookup
// entries in loginErrorMessages.
const (
	// #nosec G101 -- error code identifier, not a credential.
	invalidCredentialsError = "invalid_credentials"
)

// loginErrorMessages maps a query-string error code to the user-facing banner.
// Every authentication failure (unknown user, wrong password, locked account)
// resolves to invalidCredentialsError to block account enumeration. The map
// itself is the authoritative lookup; the login template MUST NOT echo the
// raw query parameter.
var loginErrorMessages = map[string]string{
	invalidCredentialsError: "Invalid username or password.",
}

// loginErrorRedirect builds the /login?error=<code> redirect target. Used by
// the Login handler so every failure path goes through the same URL builder
// (and any future escaping/changes happen in one place).
func loginErrorRedirect(code string) string {
	return "/login?error=" + url.QueryEscape(code)
}

// loginErrorBanner returns the user-facing message for the given query code,
// or "" when the code is unknown (the template renders nothing in that case).
func loginErrorBanner(code string) string {
	return loginErrorMessages[code]
}

func ensureDummyHash(cost int) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("constant-time-dummy"), cost)
	})
}

// LoginPage renders the login form (GET /login).
func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":   "Login - " + h.Cfg.Server.AppName,
		"Error":   loginErrorBanner(r.URL.Query().Get("error")),
		"AppName": h.Cfg.Server.AppName,
	}
	h.render(w, r, "login.html", data)
}

// Login authenticates a user from a POST form submission (POST /login).
//
// On success, it generates a JWT stored in the "gozone_session" cookie and
// redirects to /dashboard. On failure, redirects to /login?error=invalid_credentials
// with an identical message regardless of the underlying cause (unknown user,
// wrong password, locked account). The single response code is what blocks
// account-enumeration via the error banner; the lockout and timing defences
// below cover the response-time channel.
//
// Defences (in addition to the route-level per-IP and per-username rate
// limiters applied in cmd/gozone/main.go):
//   - Persistent per-account lockout: failed_login_attempts and locked_until on
//     users. After MaxFailedAttempts consecutive failures the account is locked
//     for LoginLockConfig.LockoutDurationMinutes; every further failure extends
//     the lockout so a sliding-window attack cannot recover.
//   - Constant-time dummy bcrypt compare on missing users so an attacker cannot
//     enumerate valid usernames via timing.
//   - Every attempt (success or failure, valid or unknown username) is recorded
//     in login_attempts for forensics, and a periodic purge keeps the table
//     bounded.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientIP := chimw.GetClientIP(r.Context())
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	maxAttempts := h.Cfg.LoginLock.MaxFailedAttempts
	lockoutDuration := time.Duration(h.Cfg.LoginLock.LockoutDurationMinutes) * time.Minute

	var user models.User
	var enabled int
	ensureDummyHash(h.Cfg.Auth.BcryptCost)
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, username, email, password_hash, first_name, last_name, role, enabled, created_at, updated_at
		 FROM users WHERE username = ? AND enabled = 1`, username,
	).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Role, &enabled,
		&user.CreatedAt, &user.UpdatedAt,
	)
	user.Enabled = enabled == 1

	if err == sql.ErrNoRows {
		// Constant-time dummy bcrypt compare so missing-vs-wrong-password
		// cannot be distinguished by response time.
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // #nosec G104 — intentional timing side-channel mitigation
		h.recordFailedAttempt(ctx, username, 0, clientIP, maxAttempts, lockoutDuration)
		http.Redirect(w, r, loginErrorRedirect(invalidCredentialsError), http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Reject locked accounts. The user-facing message is identical to a
	// wrong-password attempt so the lockout state cannot be used to enumerate
	// valid usernames via the error banner. A dummy bcrypt compare is still
	// performed so the response time matches the wrong-password path: without
	// it, a locked account would return in ~0 ms while a wrong password takes
	// ~250 ms (bcrypt), letting an attacker distinguish a locked-but-valid
	// account from an unknown one (timing oracle / account enumeration).
	//
	// M-SEC5: recordFailedAttempt is called even on an already-locked account
	// so each further failure extends the lockout window (sliding expiration).
	// Without this an attacker gets one free guess per lockout window.
	if maxAttempts > 0 {
		locked, until, lerr := h.DB.UserLockStatus(ctx, user.ID)
		if lerr != nil {
			logger.Error("failed to check lockout status", "user_id", user.ID, "error", lerr)
		} else if locked {
			logger.Warn("login attempt on locked account", "username", user.Username, "locked_until", until)
			bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // #nosec G104 — intentional timing side-channel mitigation
			h.recordFailedAttempt(ctx, username, user.ID, clientIP, maxAttempts, lockoutDuration)
			http.Redirect(w, r, loginErrorRedirect(invalidCredentialsError), http.StatusSeeOther)
			return
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		h.recordFailedAttempt(ctx, username, user.ID, clientIP, maxAttempts, lockoutDuration)
		http.Redirect(w, r, loginErrorRedirect(invalidCredentialsError), http.StatusSeeOther)
		return
	}

	// Generate JWT token
	duration := time.Duration(h.Cfg.Auth.SessionDurationHours) * time.Hour
	token, err := middleware.GenerateToken(&user, h.Cfg.Server.JWTKey, duration)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// #nosec G124 -- Secure flag set dynamically via isSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     constants.SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(time.Duration(h.Cfg.Auth.SessionDurationHours) * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecure(r),
	})

	// Reset the failed-login counter on successful authentication. Best-effort:
	// a transient DB error should not prevent the user from logging in.
	if maxAttempts > 0 {
		if err := h.DB.ResetFailedLogins(ctx, user.ID); err != nil {
			logger.Error("failed to reset failed-login counter", "user_id", user.ID, "error", err)
		}
	}

	if _, err := h.DB.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'login', ?)",
		user.ID, fmt.Sprintf("User %s logged in", user.Username),
	); err != nil {
		logger.Error("failed to log login activity", "user_id", user.ID, "error", err)
	}

	if err := h.DB.RecordLoginAttempt(ctx, username, clientIP, user.ID, true); err != nil {
		logger.Error("failed to record successful login attempt", "username", username, "error", err)
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// recordFailedAttempt logs a failed login to login_attempts and, when
// maxAttempts > 0, increments the per-account counter (possibly triggering a
// lockout). Errors are logged but never abort the login flow.
//
// Last-admin exemption: when the threshold is reached on the only enabled
// admin, the lockout is refused — the counter is reset to maxAttempts-1 so
// the next failure still counts, and a CRITICAL warning is logged. This
// prevents a distributed attacker from locking every admin out of the
// instance by spraying wrong passwords at admin accounts. Recovery paths:
//   - another admin (or the same one, when there is one) logs in successfully
//     (the per-IP/per-username rate limiters will throttle the attacker);
//   - the CLI `gozone unlock --user <id|username>` command;
//   - the admin Lock/Unlock UI on /users.
func (h *Handler) recordFailedAttempt(ctx context.Context, username string, userID int64, ip string, maxAttempts int, lockout time.Duration) {
	if err := h.DB.RecordLoginAttempt(ctx, username, ip, userID, false); err != nil {
		logger.Error("failed to record failed login attempt", "username", username, "error", err)
	}
	if maxAttempts <= 0 || userID <= 0 {
		return
	}

	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin tx for failed-login counter", "user_id", userID, "error", err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	last, err := tx.IsLastEnabledAdmin(ctx, userID)
	if err != nil {
		logger.Error("failed to check last-admin status", "user_id", userID, "error", err)
		return
	}

	// Bump the counter and read the new value back. Mirrors DB.IncrementFailedLogins
	// but executes inside the calling tx so we can both check last-admin and
	// react under the same FOR UPDATE row lock (MySQL/Postgres).
	if _, err := tx.ExecContext(ctx,
		"UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
		userID,
	); err != nil {
		logger.Error("failed to increment failed-login counter", "user_id", userID, "error", err)
		return
	}
	var count int
	if err := tx.QueryRowContext(ctx,
		"SELECT failed_login_attempts FROM users WHERE id = ?", userID,
	).Scan(&count); err != nil {
		logger.Error("failed to read failed-login counter", "user_id", userID, "error", err)
		return
	}

	if count >= maxAttempts && last {
		// Refuse to lock the last admin out. Reset the counter to one below
		// the threshold so the next failure still counts towards a lockout
		// (and so concurrent failure storms do not bypass future locks once
		// the situation changes).
		if _, err := tx.ExecContext(ctx,
			"UPDATE users SET failed_login_attempts = ?, locked_until = NULL WHERE id = ?",
			maxAttempts-1, userID,
		); err != nil {
			logger.Error("failed to reset last-admin counter", "user_id", userID, "error", err)
			return
		}
		logger.Warn("refused to lock the last enabled admin",
			"user_id", userID, "username", username, "count", count, "threshold", maxAttempts)
		if err := tx.Commit(); err != nil {
			logger.Error("failed to commit last-admin reset", "user_id", userID, "error", err)
		} else {
			committed = true
		}
		return
	}

	if count >= maxAttempts {
		lockedUntil := time.Now().UTC().Add(lockout)
		if _, err := tx.ExecContext(ctx,
			"UPDATE users SET locked_until = ? WHERE id = ?",
			lockedUntil, userID,
		); err != nil {
			logger.Error("failed to set locked_until", "user_id", userID, "error", err)
			return
		}
		logger.Warn("account locked after failed attempts", "user_id", userID, "count", count)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit failed-login counter", "user_id", userID, "error", err)
		return
	}
	committed = true
}

// Logout clears the session cookie, revokes the current JWT, and redirects to /login.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := middleware.GetUser(r)

	// Revoke the current session token so it cannot be reused after logout.
	if user != nil {
		tokenString := ""
		if cookie, err := r.Cookie(constants.SessionCookieName); err == nil && cookie.Value != "" {
			tokenString = cookie.Value
		}
		if tokenString == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if tokenString != "" {
			if claims, err := middleware.ParseToken(tokenString, h.Cfg.Server.JWTKey); err == nil && claims.ID != "" {
				if err := h.DB.RevokeToken(ctx, claims.ID, user.ID, claims.ExpiresAt.Time); err != nil {
					logger.Error("failed to revoke token on logout", "user_id", user.ID, "error", err)
				}
			}
		}

		if _, err := h.DB.ExecContext(ctx,
			"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'logout', ?)",
			user.ID, fmt.Sprintf("User %s logged out", user.Username),
		); err != nil {
			logger.Error("failed to log logout activity", "user_id", user.ID, "error", err)
		}
	}

	// #nosec G124 -- Secure flag set dynamically via isSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     constants.SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ProfilePage renders the authenticated user's profile (GET /profile).
func (h *Handler) ProfilePage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	data := map[string]interface{}{
		"Title": "Profile - " + h.Cfg.Server.AppName,
		"User":  user,
	}
	h.render(w, r, "profile.html", data)
}

// isSecure detects whether the current request uses HTTPS.
//
// It checks r.TLS (direct TLS) and the X-Forwarded-Proto header
// for reverse proxy setups. Returns false for plain HTTP.
func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

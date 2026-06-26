package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
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

func ensureDummyHash(cost int) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("constant-time-dummy"), cost)
	})
}

// LoginPage renders the login form (GET /login).
func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Login - " + h.Cfg.Server.AppName,
		"Error": r.URL.Query().Get("error"),
	}
	h.render(w, r, "login.html", data)
}

// Login authenticates a user from a POST form submission (POST /login).
//
// On success, it generates a JWT stored in the "gozone_session" cookie and
// redirects to /dashboard. On failure, redirects to /login?error=invalid_credentials.
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
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Reject locked accounts before doing any bcrypt work so an attacker
	// cannot grind the lockout window by hammering the endpoint.
	if maxAttempts > 0 {
		locked, until, lerr := h.DB.UserLockStatus(ctx, user.ID)
		if lerr != nil {
			logger.Error("failed to check lockout status", "user_id", user.ID, "error", lerr)
		} else if locked {
			logger.Warn("login attempt on locked account", "username", user.Username, "locked_until", until)
			http.Redirect(w, r, "/login?error=account_locked", http.StatusSeeOther)
			return
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		h.recordFailedAttempt(ctx, username, user.ID, clientIP, maxAttempts, lockoutDuration)
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
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
func (h *Handler) recordFailedAttempt(ctx context.Context, username string, userID int64, ip string, maxAttempts int, lockout time.Duration) {
	if err := h.DB.RecordLoginAttempt(ctx, username, ip, userID, false); err != nil {
		logger.Error("failed to record failed login attempt", "username", username, "error", err)
	}
	if maxAttempts > 0 && userID > 0 {
		count, err := h.DB.IncrementFailedLogins(ctx, userID, maxAttempts, lockout)
		if err != nil {
			logger.Error("failed to increment failed-login counter", "user_id", userID, "error", err)
		} else if count >= maxAttempts {
			logger.Warn("account locked after failed attempts", "user_id", userID, "count", count)
		}
	}
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

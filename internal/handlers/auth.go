package handlers

import (
	"context"
	"database/sql"
	"errors"
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
	// csrfInvalidError is set by the CSRF middleware in cmd/server.go
	// when a form submission fails token validation (expired session,
	// missing token, tampered token). It gets its own banner so the user
	// sees an actionable message instead of a blank page.
	csrfInvalidError = "csrf_invalid"
	// ssoError is set by the OIDC handlers when the SSO flow fails (state
	// mismatch, token verification, disabled account, provisioning refused).
	// A single generic message avoids leaking which step failed.
	ssoError = "sso_error"
)

// loginErrorMessages maps a query-string error code to the user-facing banner.
// Every authentication failure (unknown user, wrong password, locked account)
// resolves to invalidCredentialsError to block account enumeration. The CSRF
// failure gets its own code so the user understands the form timed out rather
// than seeing a blank page. The map itself is the authoritative lookup; the
// login template MUST NOT echo the raw query parameter.
var loginErrorMessages = map[string]string{
	invalidCredentialsError: "Invalid username or password.",
	csrfInvalidError:        "Session expired or security token invalid. Please try again.",
	ssoError:                "Single sign-on failed. Please try again or contact an administrator.",
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
		h, err := bcrypt.GenerateFromPassword([]byte("constant-time-dummy"), cost)
		if err != nil {
			// bcrypt.GenerateFromPassword only fails on an out-of-range cost
			// (the config loader validates cost ∈ [4,31], so this branch is
			// unreachable in practice). Fail the process closed rather than
			// leaving dummyHash nil: a nil hash would make the
			// CompareHashAndPassword calls on the unknown-user and locked-
			// account login paths return immediately, reopening the
			// username-enumeration timing channel the dummy compare exists
			// to close (REVIEW.md L-3).
			logger.Fatal("failed to generate constant-time dummy bcrypt hash", "cost", cost, "error", err)
		}
		dummyHash = h
	})
}

// LoginPage renders the login form (GET /login).
func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":   "Login - " + h.Cfg.Server.AppName,
		"Error":   loginErrorBanner(r.URL.Query().Get("error")),
		"AppName": h.Cfg.Server.AppName,
	}
	// Expose SSO providers so the template can render "Sign in with X" buttons.
	// When SSO is enabled and allow_local_login is false, the local form is
	// hidden (the POST /login endpoint stays wired for existing tooling).
	if h.OIDC != nil && h.OIDC.Enabled() {
		data["OIDCProviders"] = h.OIDC.Providers()
		if !h.Cfg.OIDC.AllowLocalLogin {
			data["HideLocalLogin"] = true
		}
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
// limiters applied in cmd/server.go):
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
	// Normalise the username the same way the per-username rate limiter does
	// (cmd/server.go loginUsernameKey: trim + lowercase). The DB lookup below
	// uses LOWER(username) = ? so the match is case-insensitive — without this,
	// Postgres (case-sensitive =) resolves "Admin" and "admin" to different
	// rows while the rate limiter treats them as one bucket, and a user who
	// registered as "Admin" could not log in as "admin" (REVIEW.md L-5).
	// Lowercasing the input also keeps login_attempts.username aligned with the
	// rate-limit bucket for forensics.
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	password := r.FormValue("password")
	clientIP := chimw.GetClientIP(r.Context())
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	maxAttempts := h.Cfg.LoginLock.MaxFailedAttempts
	lockoutDuration := time.Duration(h.Cfg.LoginLock.LockoutDurationMinutes) * time.Minute

	var user models.User
	var enabled int
	var mustChange int
	ensureDummyHash(h.Cfg.Auth.BcryptCost)
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, username, email, password_hash, first_name, last_name, role, enabled, created_at, updated_at, password_changed_at, must_change_password
		 FROM users WHERE LOWER(username) = ? AND enabled = 1`, username,
	).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Role, &enabled,
		&user.CreatedAt, &user.UpdatedAt, &user.PasswordChangedAt, &mustChange,
	)
	user.Enabled = enabled == 1
	user.MustChangePassword = mustChange == 1

	if errors.Is(err, sql.ErrNoRows) {
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
	// A manual admin lock is enforced UNCONDITIONALLY, independent of the
	// brute-force feature flag: an account an admin froze must stay frozen
	// even when max_failed_attempts = 0. The automatic brute-force lockout
	// below still follows the flag (I-2): with max_failed_attempts = 0 a stale
	// auto-lock is ignored at login. The two are decoupled by tracking the
	// manual lock in its own column (manual_lock_until), set alongside
	// locked_until by AdminLockUser.
	if manualLocked, merr := h.DB.IsManualLock(ctx, user.ID); merr != nil {
		// Fail-closed (m34): if the manual-lock status cannot be read we
		// cannot confirm the account is not frozen, so deny. A dummy bcrypt
		// compare keeps the response time in the wrong-password band.
		logger.Error("failed to check manual lock status; denying login (fail-closed)", "user_id", user.ID, "error", merr)
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // #nosec G104 — intentional timing side-channel mitigation
		http.Redirect(w, r, loginErrorRedirect(invalidCredentialsError), http.StatusSeeOther)
		return
	} else if manualLocked {
		logger.Warn("login attempt on manually locked account", "username", user.Username)
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // #nosec G104 — intentional timing side-channel mitigation
		http.Redirect(w, r, loginErrorRedirect(invalidCredentialsError), http.StatusSeeOther)
		return
	}

	// Automatic brute-force lockout. This whole block (status check +
	// enforcement + sliding-window extension) is gated on MaxFailedAttempts >
	// 0 by design (REVIEW.md I-2): when an operator sets max_failed_attempts =
	// 0 the automatic lockout feature is considered off, so a stale auto-lock
	// (locked while the setting was > 0) is not honoured and the account can
	// log in again without clearing it. Manual admin locks are NOT affected —
	// they are checked above unconditionally. The per-IP and per-username rate
	// limiters still apply, and clearing a specific auto-lock without enabling
	// the feature is available via the admin Unlock action or
	// `gozone user unlock`. See config.LoginLockConfig.MaxFailedAttempts.
	//
	// M-SEC5: recordFailedAttempt is called even on an already-locked account
	// so each further failure extends the lockout window (sliding expiration).
	// Without this an attacker gets one free guess per lockout window.
	if maxAttempts > 0 {
		locked, until, lerr := h.DB.UserLockStatus(ctx, user.ID)
		if lerr != nil {
			// Fail-closed (m34): if the lockout status cannot be determined,
			// deny the login rather than falling through to bcrypt. Otherwise a
			// DB error would bypass the lockout for an account that is actually
			// locked. A dummy bcrypt compare keeps the response time in the same
			// band as the wrong-password path. The failed-login counter is NOT
			// incremented: this is a system-side inability to check status, not
			// an authentication failure, and bumping it could unfairly lock
			// users out during transient DB issues.
			logger.Error("failed to check lockout status; denying login (fail-closed)", "user_id", user.ID, "error", lerr)
			bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // #nosec G104 — intentional timing side-channel mitigation
			http.Redirect(w, r, loginErrorRedirect(invalidCredentialsError), http.StatusSeeOther)
			return
		}
		if locked {
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

	if err := logActivity(ctx, h.DB, activityEntry{UserID: user.ID, Action: "login", Details: fmt.Sprintf("User %s logged in", user.Username)}); err != nil {
		logger.Error("failed to log login activity", "user_id", user.ID, "error", err)
	}

	if err := h.DB.RecordLoginAttempt(ctx, username, clientIP, user.ID, true); err != nil {
		logger.Error("failed to record successful login attempt", "username", username, "error", err)
	}

	// Password expiry: when max_age_days is configured and the password is
	// older than the limit, force a change. The flag is persisted so the Auth
	// middleware's force-change gate keeps the session restricted to
	// /change-password until the user rotates the password.
	if !user.MustChangePassword && passwordExpired(h.Cfg.Password.MaxAgeDays, user.PasswordChangedAt) {
		user.MustChangePassword = true
		if _, err := h.DB.ExecContext(ctx,
			"UPDATE users SET must_change_password = 1 WHERE id = ?", user.ID,
		); err != nil {
			logger.Error("failed to set must_change_password on expiry", "user_id", user.ID, "error", err)
		}
	}

	redirectTarget := "/dashboard"
	if user.MustChangePassword {
		redirectTarget = "/change-password"
	}
	http.Redirect(w, r, redirectTarget, http.StatusSeeOther)
}

// recordFailedAttempt logs a failed login to login_attempts and, when
// maxAttempts > 0, increments the per-account counter (possibly triggering a
// lockout). Errors are logged but never abort the login flow.
//
// The increment + conditional lockout reuse the single core implementation
// (Tx.IncrementFailedLoginsInTx, shared with DB.IncrementFailedLogins); this
// handler only layers the last-admin exemption on top, so there is no longer a
// second parallel lockout code path.
//
// Lock order: IsLastEnabledAdmin is evaluated FIRST — it locks the
// enabled-admin set (via CountEnabledAdmins' FOR UPDATE) before the target
// row — then the increment locks the target row. This matches
// UpdateUser/DeleteUser and avoids the inverted-order deadlock documented on
// Tx.IsLastEnabledAdmin.
//
// Last-admin exemption: when the threshold is reached on the only enabled
// admin, the lockout is refused — the lock this call just applied is undone
// and the counter is reset to maxAttempts-1 so the next failure still counts,
// with a CRITICAL warning logged. This prevents a distributed attacker from
// locking every admin out of the instance by spraying wrong passwords at admin
// accounts. Recovery paths:
//   - another admin (or the same one, when there is one) logs in successfully
//     (the per-IP/per-username rate limiters will throttle the attacker);
//   - the CLI `gozone user unlock <id|username>` command;
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

	count, locked, err := tx.IncrementFailedLoginsInTx(ctx, userID, maxAttempts, lockout)
	if err != nil {
		logger.Error("failed to increment failed-login counter", "user_id", userID, "error", err)
		return
	}

	if locked && last {
		// Refuse to lock the last enabled admin. Undo the lockout this call
		// just applied (same transaction, so it is never observable committed)
		// and reset the counter to one below the threshold so the next failure
		// still counts (and so concurrent failure storms cannot bypass future
		// locks once the situation changes).
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

	if locked {
		logger.Warn("account locked after failed attempts", "user_id", userID, "count", count)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit failed-login counter", "user_id", userID, "error", err)
		return
	}
	committed = true
}

// Logout clears the session cookie, revokes the current JWT, and redirects to
// /login. When the session was established via SSO and the provider advertises
// an end_session_endpoint, the browser is redirected there (RP-initiated
// logout) with a post_logout_redirect_uri back to /login so the IdP SSO cookie
// is cleared too.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := middleware.GetUser(r)

	// Resolve the auth provider + current token claims up front so we can route
	// to RP-initiated logout after local cleanup.
	var authProvider, idTokenHint, sessionID string
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
			authProvider = claims.AuthProvider
			sessionID = claims.SessionID
			// Fast path: sessions issued by ≤ v0.16.7 embedded the hint in
			// the JWT itself. Newer sessions store it server-side.
			idTokenHint = claims.IDTokenHint
			if user != nil {
				if err := h.DB.RevokeToken(ctx, claims.ID, user.ID, claims.ExpiresAt.Time); err != nil {
					logger.Error("failed to revoke token on logout", "user_id", user.ID, "error", err)
				}
			}
		}
	}

	// Revoke the current session token so it cannot be reused after logout.
	if user != nil {
		if err := logActivity(ctx, h.DB, activityEntry{UserID: user.ID, Action: "logout", Details: fmt.Sprintf("User %s logged out", user.Username)}); err != nil {
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

	// RP-initiated logout: when the session came from an OIDC provider that
	// advertises an end_session_endpoint, redirect there so the IdP clears its
	// own SSO cookie. post_logout_redirect_uri sends the browser back to /login
	// and id_token_hint lets the IdP identify the session to end (required by
	// some providers, e.g. Keycloak). authProvider "" / "local" means a password
	// login → no IdP round-trip.
	if h.OIDC != nil && authProvider != "" && authProvider != "local" {
		if endSession := h.OIDC.EndSessionURL(authProvider); endSession != "" {
			// The hint is embedded in the JWT only for legacy (≤ v0.16.7)
			// sessions; current sessions store it server-side keyed by sid
			// (large IdP ID tokens would overflow the session cookie).
			if idTokenHint == "" && sessionID != "" {
				if stored, err := h.DB.FindSSOIDToken(ctx, sessionID); err != nil {
					logger.Error("oidc logout: failed to load stored id_token_hint",
						"provider", authProvider, "error", err)
				} else {
					idTokenHint = stored
				}
			}
			postLogout := oidcPostLogoutURL(h.Cfg.Server.ExternalURL, r)
			target := appendQuery(endSession, "post_logout_redirect_uri", postLogout)
			if idTokenHint != "" {
				target = appendQuery(target, "id_token_hint", idTokenHint)
				// The hint is single-purpose: drop it once consumed.
				if sessionID != "" {
					if err := h.DB.DeleteSSOIDToken(ctx, sessionID); err != nil {
						logger.Error("oidc logout: failed to delete stored id_token_hint",
							"provider", authProvider, "error", err)
					}
				}
			} else {
				// No id_token_hint available: either the session predates hint
				// storage, or the server-side write failed at login (see the
				// "failed to store id_token_hint" warning). Strict providers
				// (Keycloak) reject the logout without it — a re-login mints a
				// session whose hint is stored correctly.
				logger.Warn("oidc logout: SSO session has no id_token_hint; provider may reject the logout",
					"provider", authProvider)
			}
			if isAbsoluteHTTPURLAuth(target) {
				// #nosec G710 -- target is the server-side discovered
				// end_session_endpoint, validated as absolute http(s) here.
				http.Redirect(w, r, target, http.StatusSeeOther)
				return
			}
			logger.Warn("oidc logout: end_session_endpoint is not absolute; skipping RP logout",
				"provider", authProvider, "url", endSession)
		}
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// oidcPostLogoutURL builds the fully-qualified /login URL to hand the IdP as
// post_logout_redirect_uri. When externalURL is configured
// (server.external_url) it is used as the base, ignoring the client-controlled
// Host header — the same defense-in-depth as the OIDC callback URL: the IdP
// validates post_logout_redirect_uri against its allow-list, but the app
// should not derive the value from an untrusted header when a canonical base
// is known. Otherwise the URL is derived per-request from the resolved scheme
// (trusted-proxy aware) and r.Host.
func oidcPostLogoutURL(externalURL string, r *http.Request) string {
	if externalURL != "" {
		return externalURL + "/login"
	}
	scheme := "http"
	if middleware.IsHTTPS(r) {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/login", scheme, r.Host)
}

// appendQuery adds a query parameter to a URL string, preserving any existing
// query. It does not validate the base URL; the caller is responsible for that.
func appendQuery(baseURL, key, value string) string {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	return baseURL + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}

// isAbsoluteHTTPURLAuth reports whether u is an absolute http(s) URL with a
// host. It guards the RP-initiated logout redirect against a malformed
// end_session_endpoint.
func isAbsoluteHTTPURLAuth(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
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

// isSecure detects whether the current request is effectively HTTPS.
//
// It delegates to middleware.IsHTTPS, which trusts r.TLS (genuine transport)
// and the HTTPSResolver-stashed decision (trusted-proxy-gated
// X-Forwarded-Proto, m40/M-SEC4). Returns false for plain HTTP. This drives
// the Secure flag on session cookies.
func isSecure(r *http.Request) bool {
	return middleware.IsHTTPS(r)
}

// Package middleware provides HTTP middleware for authentication, authorization,
// and user context propagation in the GoZone web application.
//
// # Timestamp convention
//
// Every timestamp bound for the database (sessions.first_seen/last_seen/
// expires_at, api_keys.last_used_at, revoked_tokens.expires_at) is produced in
// UTC. SQLite (mattn/go-sqlite3) serializes time.Time with its offset and the
// engine compares those strings lexicographically; mixing offsets across DST
// transitions or multi-TZ deployments would skew the comparisons. Instant-only
// comparisons in memory (time.Time.Before/After/Sub) are unaffected and are not
// annotated (REVIEW.md M-1).
package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
)

type contextKey string

const (
	// UserContextKey is the context key used to store the authenticated User pointer
	// in the request context. Use GetUser(r) to retrieve the user.
	UserContextKey contextKey = "user"
)

// Claims represents the JWT claims for a session.
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	// AuthProvider records how the session was established: "" or "local" for
	// username/password login, or the OIDC provider name (e.g. "gitea") for
	// single sign-on. Used by the Logout handler to decide whether to perform
	// RP-initiated logout at the IdP end_session_endpoint.
	AuthProvider string `json:"auth_provider,omitempty"`
	// SessionID is a stable identifier for the logical session, preserved
	// across access-token refreshes (the jti rotates on every refresh; the
	// SessionID does not). The SessionTracker keys idle/absolute bookkeeping
	// by SessionID so a refreshed token keeps the same inactivity/age budget.
	SessionID string `json:"sid,omitempty"`
	// IDTokenHint carries the raw OIDC ID token received at SSO login, so the
	// Logout handler can pass it as id_token_hint to the IdP
	// end_session_endpoint (RP-initiated logout). Some providers — notably
	// Keycloak — require it to identify the SSO session to end. Empty for
	// local sessions. Preserved across access-token refreshes.
	IDTokenHint string `json:"id_token_hint,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken creates a signed JWT token for the given user.
//
// It produces an HMAC-SHA256 token containing the user ID, username, role, and
// a unique JWT ID (jti). The token expires after the given duration from the
// current time. The session is treated as a local login (AuthProvider empty);
// SSO sessions use GenerateSessionToken with the provider name.
//
// Parameters:
//   - user: the authenticated user to encode in the token
//   - secret: the HMAC signing key (must not be empty in production)
//   - duration: the token validity period from now
//
// Returns the encoded JWT string and any signing error.
func GenerateToken(user *models.User, secret []byte, duration time.Duration) (string, error) {
	return GenerateSessionToken(user, secret, duration, "", "")
}

// GenerateSessionToken creates a signed JWT token, recording the authentication
// provider and minting a fresh SessionID. provider is "" / "local" for password
// login, or the OIDC provider slug for single sign-on. idTokenHint is the raw
// ID token to carry for RP-initiated logout (id_token_hint); pass "" for local
// sessions. provider and idTokenHint are embedded in the claims so the Logout
// handler can route SSO sessions to the IdP end_session_endpoint.
func GenerateSessionToken(user *models.User, secret []byte, duration time.Duration, provider, idTokenHint string) (string, error) {
	sid, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return generateSessionToken(user, secret, duration, provider, sid.String(), idTokenHint)
}

// RefreshSessionToken re-issues an access token for an existing session,
// preserving the AuthProvider, SessionID and IDTokenHint so the refreshed
// token keeps the same SSO logout routing and the same idle/absolute budget in
// the tracker. The old jti MUST be revoked by the caller (the refresh path
// does so).
func RefreshSessionToken(user *models.User, secret []byte, duration time.Duration, provider, sessionID, idTokenHint string) (string, error) {
	return generateSessionToken(user, secret, duration, provider, sessionID, idTokenHint)
}

// generateSessionToken is the single signing primitive: a fresh jti is always
// minted (so each access token is independently revocable), while the provider,
// sessionID and idTokenHint are caller-supplied (preserved across refreshes).
func generateSessionToken(user *models.User, secret []byte, duration time.Duration, provider, sessionID, idTokenHint string) (string, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	claims := Claims{
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
		AuthProvider: provider,
		SessionID:    sessionID,
		IDTokenHint:  idTokenHint,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "gozone",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// ParseToken validates and parses a JWT token string.
//
// It verifies the HMAC signature and extracts the embedded claims.
// Only HS256 is accepted, matching the algorithm used by GenerateToken.
// Other HMAC variants (HS384/HS512) and non-HMAC algorithms are rejected.
//
// Parameters:
//   - tokenString: the raw JWT token to parse
//   - secret: the HMAC key used to verify the signature
//
// Returns the parsed Claims on success, or an error if the token is invalid,
// expired, or uses an unsupported algorithm.
func ParseToken(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrSignatureInvalid
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

// Auth returns a middleware that validates JWT tokens for web UI requests,
// with no session lifetime policy (a token is valid until its exp, unless
// revoked). It is a thin wrapper around AuthWithPolicy with a nil tracker.
// Callers that configure idle/absolute session limits use AuthWithPolicy with a
// SessionTracker.
func Auth(db *database.DB, secret []byte) func(http.Handler) http.Handler {
	return AuthWithPolicy(db, secret, nil, 0)
}

// AuthWithPolicy is the session-aware Auth middleware. When tracker is nil (or
// the policy is zero), behaviour is identical to Auth. When a policy is
// configured it additionally:
//   - forces re-authentication after auth.idle_timeout_minutes of inactivity;
//   - forces re-authentication once auth.absolute_session_timeout_hours elapse
//     since the session began (the absolute refresh cap);
//   - transparently refreshes (re-issues) the access JWT when it is within the
//     refresh threshold of expiry, sliding the session up to the absolute cap.
//
// accessTTL is the access-token lifetime (auth.session_duration_hours) used to
// compute the refresh threshold; pass 0 to disable refresh.
func AuthWithPolicy(db *database.DB, secret []byte, tracker *SessionTracker, accessTTL time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			// Try cookie first
			cookie, err := r.Cookie(constants.SessionCookieName)
			if err == nil && cookie.Value != "" {
				tokenString = cookie.Value
			}

			// Fall back to Authorization header
			if tokenString == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenString = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if tokenString == "" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			claims, err := ParseToken(tokenString, secret)
			if err != nil {
				clearSessionCookie(w, r)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			if claims.ID == "" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			revoked, err := db.IsTokenRevoked(r.Context(), claims.ID)
			if err != nil {
				logger.Error("failed to check token revocation", "error", err)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if revoked {
				clearSessionCookie(w, r)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Load full user from database
			user, err := loadUser(r.Context(), db, claims.UserID)
			if err != nil || !user.Enabled {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Bulk-revoke outstanding sessions when the credential rotated or
			// the account was disabled. Any access token whose iat
			// predates the user's tokens_valid_after cutoff is stale and must
			// re-authenticate — this is what makes a stolen JWT useless once the
			// password changes, without enumerating active jtis. The guard skips
			// tokens without an iat (e.g. none — API keys use a separate path and
			// their own revocation lifecycle); CURRENT_TIMESTAMP writes are UTC so
			// the instant comparison is sound (see package timestamp convention).
			if claims.IssuedAt != nil && !claims.IssuedAt.Time.IsZero() &&
				claims.IssuedAt.Time.Before(user.TokensValidAfter) {
				clearSessionCookie(w, r)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Force-change gate: a user flagged must_change_password (admin reset
			// or password expiry) may only reach the change-password page and
			// logout until they set a new password. Everything else redirects to
			// /change-password so the session cannot be used until the password
			// is rotated.
			if user.MustChangePassword && !mustChangeAllowedPath(r.URL.Path) {
				http.Redirect(w, r, "/change-password", http.StatusSeeOther)
				return
			}

			// Session lifetime policy (idle / absolute / transparent refresh).
			// All branches are no-ops when the tracker is nil or the relevant
			// duration is zero, so the default config behaves exactly like Auth.
			// When the policy denies the session (idle/absolute exceeded) it has
			// already written a /login redirect; abort the chain.
			if !applySessionPolicy(w, r, db, secret, tracker, accessTTL, claims, user) {
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// applySessionPolicy enforces the idle/absolute limits and, when appropriate,
// transparently refreshes the access JWT. It runs after the token is validated
// and the user loaded, so a refreshed cookie lands on the response before the
// handler runs. It returns false (after writing a /login redirect + clearing
// the cookie) when the session is denied for idle/absolute expiry, so the
// caller can abort the chain. Refresh and pass-through return true.
//
// The session is keyed by Claims.SessionID when present (stable across
// refreshes), falling back to the jti for tokens issued before SessionID
// existed.
func applySessionPolicy(w http.ResponseWriter, r *http.Request, db *database.DB, secret []byte, tracker *SessionTracker, accessTTL time.Duration, claims *Claims, user *models.User) bool {
	if tracker == nil {
		return true
	}
	sid := claims.SessionID
	if sid == "" {
		sid = claims.ID
	}
	// UTC: now flows into sessions table writes (SessionTouch/SessionInsert)
	// whose expires_at is compared lexicographically by SQLite (REVIEW.md M-1).
	now := time.Now().UTC()
	ctx := r.Context()

	if !tracker.Touch(ctx, sid, claims.IssuedAt.Time, now) {
		// Idle window exceeded → force re-authentication.
		clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}

	if tracker.policy.Absolute <= 0 {
		return true
	}
	firstSeen := tracker.FirstSeen(ctx, sid, claims.IssuedAt.Time, now)
	if now.Sub(firstSeen) >= tracker.policy.Absolute {
		// Absolute cap reached → force re-authentication.
		clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}

	// Transparent refresh: when the access token is within the refresh
	// threshold of expiry, re-issue it (new jti, preserved SessionID) and
	// revoke the old jti. The session keeps its absolute budget via the
	// unchanged SessionID.
	if accessTTL <= 0 || claims.ExpiresAt == nil {
		return true
	}
	threshold := tracker.policy.RefreshThreshold()
	if claims.ExpiresAt.Time.Sub(now) >= threshold {
		return true
	}
	newToken, err := RefreshSessionToken(user, secret, accessTTL, claims.AuthProvider, sid, claims.IDTokenHint)
	if err != nil {
		logger.Error("failed to refresh session token", "user_id", user.ID, "error", err)
		return true
	}
	// Best-effort: revoke the superseded access token so it cannot be replayed.
	// A revocation failure does not block the refresh — the old token is near
	// expiry anyway.
	if err := db.RevokeToken(r.Context(), claims.ID, user.ID, claims.ExpiresAt.Time); err != nil {
		logger.Error("failed to revoke refreshed token", "user_id", user.ID, "error", err)
	}
	setSessionCookie(w, r, newToken, now.Add(accessTTL))
	tracker.remember(ctx, sid, firstSeen, now)
	return true
}

// clearSessionCookie invalidates the session cookie in the browser, matching
// the Secure flag the issue site used (trusted-proxy-gated, m40/M-SEC4) so a
// TLS-terminating proxy does not leave a non-Secure clearing cookie that the
// browser refuses to drop (REVIEW.md M-1).
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- clearing cookie, Secure set via IsHTTPS(r) (m40/M-SEC4).
	http.SetCookie(w, &http.Cookie{
		Name:     constants.SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   IsHTTPS(r),
	})
}

// setSessionCookie writes a session cookie with the same attributes the Login
// handler uses, so a transparently-refreshed token is indistinguishable from a
// freshly-issued one to the browser.
func setSessionCookie(w http.ResponseWriter, r *http.Request, value string, expiresAt time.Time) {
	// #nosec G124 -- Secure flag set dynamically via IsHTTPS(r).
	http.SetCookie(w, &http.Cookie{
		Name:     constants.SessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   IsHTTPS(r),
	})
}

// APIKeyAuth returns a middleware that validates API key tokens for REST API requests.
//
// The API key can be provided via:
//  1. X-API-Key header
//  2. Authorization header with "Bearer " prefix
//
// The incoming key is SHA-256 hashed before comparison against stored hashes.
// Expired API keys return HTTP 401 with the message "api_key_expired".
// The authenticated user is stored in the request context via UserContextKey
// and the API key's last_used_at timestamp is updated on each request.
func APIKeyAuth(db *database.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("X-API-Key")
			if authHeader == "" {
				authHeader = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}

			if authHeader == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			keyHash := hashAPIKey(authHeader)

			var userID int64
			var expiresAt sql.NullTime
			err := db.QueryRowContext(r.Context(),
				"SELECT user_id, expires_at FROM api_keys WHERE key_hash = ?",
				keyHash,
			).Scan(&userID, &expiresAt)

			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if expiresAt.Valid && expiresAt.Time.Before(time.Now()) {
				http.Error(w, `{"error":"api_key_expired"}`, http.StatusUnauthorized)
				return
			}

			user, err := loadUser(r.Context(), db, userID)
			if err != nil || !user.Enabled {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Record last use only once the key has authenticated a valid, enabled
			// user (m36). Updating it earlier bumped last_used_at for orphaned keys
			// (user deleted) and disabled-user keys, misrepresenting real usage.
			// UTC keeps the column consistent across TZ/DST (REVIEW.md M-1).
			if _, err := db.ExecContext(r.Context(), "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", time.Now().UTC(), keyHash); err != nil {
				logger.Warn("failed to update api_key last_used_at", "key_hash", keyHash[:8]+"...", "error", err)
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func hashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// RequireAdmin is a middleware that restricts access to users with the admin role.
//
// It must be placed after Auth or APIKeyAuth in the middleware chain so that
// a user is available in the request context. Returns HTTP 403 if the user is
// not authenticated or does not have the "admin" role.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r)
		if user == nil || !user.IsAdmin() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mustChangeAllowedPath reports the paths a forced-change user may reach
// without having changed their password yet: the change-password form/handler
// and logout. Every other authenticated route redirects to /change-password.
func mustChangeAllowedPath(p string) bool {
	switch p {
	case "/change-password", "/logout":
		return true
	default:
		return false
	}
}

// GetUser retrieves the currently authenticated user from the request context.
//
// Returns nil if no user was stored by Auth or APIKeyAuth middleware.
func GetUser(r *http.Request) *models.User {
	user, ok := r.Context().Value(UserContextKey).(*models.User)
	if !ok {
		return nil
	}
	return user
}

// loadUser fetches the user record needed by request-time middleware
// (Auth / APIKeyAuth). It deliberately does NOT select password_hash: the
// hash is only required at the ChangePassword site, which refetches it inside
// its own transaction (REVIEW.md L-9). Carrying the hash in the per-request
// *models.User stored in the context exposed it for the whole request
// lifetime on every authenticated call — including API requests that never
// need it — for no benefit (json:"-" already excluded it from responses, but
// defence-in-depth wants the secret out of memory unless it is actively
// used). Login and admin user-management load the hash via their own
// dedicated SELECTs and are unaffected.
func loadUser(ctx context.Context, db *database.DB, userID int64) (*models.User, error) {
	user := &models.User{}
	var enabled int
	var mustChange int
	err := db.QueryRowContext(ctx,
		`SELECT id, username, email, first_name, last_name, role, enabled, created_at, updated_at, password_changed_at, must_change_password, tokens_valid_after
		 FROM users WHERE id = ?`, userID,
	).Scan(
		&user.ID, &user.Username, &user.Email,
		&user.FirstName, &user.LastName, &user.Role, &enabled,
		&user.CreatedAt, &user.UpdatedAt, &user.PasswordChangedAt, &mustChange,
		&user.TokensValidAfter,
	)
	user.Enabled = enabled == 1
	user.MustChangePassword = mustChange == 1
	if err != nil {
		return nil, err
	}
	return user, nil
}

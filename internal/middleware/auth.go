// Package middleware provides HTTP middleware for authentication, authorization,
// and user context propagation in the GoZone web application.
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
	return GenerateSessionToken(user, secret, duration, "")
}

// GenerateSessionToken creates a signed JWT token, recording the authentication
// provider. provider is "" / "local" for password login, or the OIDC provider
// slug for single sign-on. It is embedded as AuthProvider in the claims so the
// Logout handler can route SSO sessions to the IdP end_session_endpoint.
func GenerateSessionToken(user *models.User, secret []byte, duration time.Duration, provider string) (string, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	claims := Claims{
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
		AuthProvider: provider,
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

// Auth returns a middleware that validates JWT tokens for web UI requests.
//
// Authentication is attempted in the following order:
//  1. Cookie named constants.SessionCookieName
//  2. Authorization header with "Bearer " prefix
//
// If authentication fails, the user is redirected to /login. Invalid cookies
// are cleared automatically. The authenticated user is loaded from the database
// and stored in the request context via UserContextKey.
//
// Parameters:
//   - db: the database connection for loading the user record
//   - secret: the HMAC key used to verify JWT signatures
func Auth(db *database.DB, secret []byte) func(http.Handler) http.Handler {
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
				// Clear invalid cookie
				// #nosec G124 -- clearing cookie, Secure set via IsHTTPS(r)
				// (trusted-proxy-gated X-Forwarded-Proto, m40/M-SEC4) so it
				// matches the Secure flag the Login handler used to issue the
				// cookie. With r.TLS != nil a TLS-terminating proxy left the
				// clearing cookie non-Secure and browsers refused to drop the
				// revoked original (REVIEW.md M-1).
				http.SetCookie(w, &http.Cookie{
					Name:     constants.SessionCookieName,
					Value:    "",
					Path:     "/",
					Expires:  time.Unix(0, 0),
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Secure:   IsHTTPS(r),
				})
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
				// Clear revoked cookie
				// #nosec G124 -- clearing cookie, Secure set via IsHTTPS(r)
				// (trusted-proxy-gated X-Forwarded-Proto, m40/M-SEC4) so it
				// matches the Secure flag the Login handler used to issue the
				// cookie. With r.TLS != nil a TLS-terminating proxy left the
				// clearing cookie non-Secure and browsers refused to drop the
				// revoked original (REVIEW.md M-1).
				http.SetCookie(w, &http.Cookie{
					Name:     constants.SessionCookieName,
					Value:    "",
					Path:     "/",
					Expires:  time.Unix(0, 0),
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Secure:   IsHTTPS(r),
				})
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Load full user from database
			user, err := loadUser(r.Context(), db, claims.UserID)
			if err != nil || !user.Enabled {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Force-change gate: a user flagged must_change_password (admin reset
			// or password expiry) may only reach the change-password page and
			// logout until they set a new password. Everything else redirects to
			// /change-password so the session cannot be used until the password is
			// rotated.
			if user.MustChangePassword && !mustChangeAllowedPath(r.URL.Path) {
				http.Redirect(w, r, "/change-password", http.StatusSeeOther)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
			if _, err := db.ExecContext(r.Context(), "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", time.Now(), keyHash); err != nil {
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
		`SELECT id, username, email, first_name, last_name, role, enabled, created_at, updated_at, password_changed_at, must_change_password
		 FROM users WHERE id = ?`, userID,
	).Scan(
		&user.ID, &user.Username, &user.Email,
		&user.FirstName, &user.LastName, &user.Role, &enabled,
		&user.CreatedAt, &user.UpdatedAt, &user.PasswordChangedAt, &mustChange,
	)
	user.Enabled = enabled == 1
	user.MustChangePassword = mustChange == 1
	if err != nil {
		return nil, err
	}
	return user, nil
}

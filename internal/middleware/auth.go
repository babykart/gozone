// Package middleware provides HTTP middleware for authentication, authorization,
// and user context propagation in the GoZone web application.
package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

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
	jwt.RegisteredClaims
}

// GenerateToken creates a signed JWT token for the given user.
//
// It produces an HMAC-SHA256 token containing the user ID, username, and role.
// The token expires after the given duration from the current time.
//
// Parameters:
//   - user: the authenticated user to encode in the token
//   - secret: the HMAC signing key (must not be empty in production)
//   - duration: the token validity period from now
//
// Returns the encoded JWT string and any signing error.
func GenerateToken(user *models.User, secret []byte, duration time.Duration) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
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
// Only HS256-family signing methods are accepted.
//
// Parameters:
//   - tokenString: the raw JWT token to parse
//   - secret: the HMAC key used to verify the signature
//
// Returns the parsed Claims on success, or an error if the token is invalid,
// expired, or uses an unsupported algorithm.
func ParseToken(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
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
//  1. Cookie named "gozone_session"
//  2. Authorization header with "Bearer " prefix
//
// If authentication fails, the user is redirected to /login. Invalid cookies
// are cleared automatically. The authenticated user is loaded from the database
// and stored in the request context via UserContextKey.
//
// Parameters:
//   - db: the database connection for loading the user record
//   - secret: the HMAC key used to verify JWT signatures
func Auth(db *sql.DB, secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			// Try cookie first
			cookie, err := r.Cookie("gozone_session")
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
				http.SetCookie(w, &http.Cookie{
					Name:     "gozone_session",
					Value:    "",
					Path:     "/",
					Expires:  time.Unix(0, 0),
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Load full user from database
			user, err := loadUser(db, claims.UserID)
			if err != nil || !user.Enabled {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
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
// Expired API keys return HTTP 401 with the message "api_key_expired".
// The authenticated user is stored in the request context via UserContextKey
// and the API key's last_used_at timestamp is updated on each request.
//
// Note: In production, the incoming key should be hashed before comparison.
func APIKeyAuth(db *sql.DB) func(http.Handler) http.Handler {
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

			// Look up API key hash
			var userID int64
			var expiresAt sql.NullTime
			// For API key auth, we compare hashes
			// In production, hash the incoming key with SHA-256 before comparing
			err := db.QueryRow(
				"SELECT user_id, expires_at FROM api_keys WHERE key_hash = ?",
				authHeader,
			).Scan(&userID, &expiresAt)

			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if expiresAt.Valid && expiresAt.Time.Before(time.Now()) {
				http.Error(w, `{"error":"api_key_expired"}`, http.StatusUnauthorized)
				return
			}

			// Update last used
			db.Exec("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", time.Now(), authHeader)

			user, err := loadUser(db, userID)
			if err != nil || !user.Enabled {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

func loadUser(db *sql.DB, userID int64) (*models.User, error) {
	user := &models.User{}
	var enabled int
	err := db.QueryRow(
		`SELECT id, username, email, password_hash, first_name, last_name, role, enabled, created_at, updated_at
		 FROM users WHERE id = ?`, userID,
	).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Role, &enabled,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	user.Enabled = enabled == 1
	return user, nil
}

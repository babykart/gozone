package handlers

import (
	"database/sql"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/constants"
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
		"Title": "Login - GoZone",
		"Error": r.URL.Query().Get("error"),
	}
	h.render(w, r, "login.html", data)
}

// Login authenticates a user from a POST form submission (POST /login).
//
// On success, it generates a JWT stored in the "gozone_session" cookie and
// redirects to /dashboard. On failure, redirects to /login?error=invalid_credentials.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var user models.User
	var enabled int
	ensureDummyHash(h.Cfg.Auth.BcryptCost)
	err := h.DB.QueryRow(
		`SELECT id, username, email, password_hash, first_name, last_name, role, enabled, created_at, updated_at
		 FROM users WHERE username = ? AND enabled = 1`, username,
	).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Role, &enabled,
		&user.CreatedAt, &user.UpdatedAt,
	)
	user.Enabled = enabled == 1

	if err == sql.ErrNoRows {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // #nosec G104 — intentional timing side-channel mitigation
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
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
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Logout clears the session cookie and redirects to /login.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
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
		"Title": "Profile - GoZone",
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

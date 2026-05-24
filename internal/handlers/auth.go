package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

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
	token, err := middleware.GenerateToken(&user, []byte(h.Cfg.Server.SecretKey), duration)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "gozone_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(duration),
		HttpOnly: true,
		Secure:   false, // Set true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Log activity
	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'login', ?)",
		user.ID, "User logged in",
	)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Logout clears the session cookie, records the logout activity, and redirects
// to /login (GET /logout).
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user != nil {
		h.DB.Exec(
			"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'logout', ?)",
			user.ID, "User logged out",
		)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "gozone_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
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

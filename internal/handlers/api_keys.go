package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

func hashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

func generateAPIKey() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := "gozone_" + base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
	return raw, hashAPIKey(raw), nil
}

func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	rows, err := h.DB.Query(
		`SELECT id, user_id, description, last_used_at, created_at, expires_at
		 FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`, user.ID,
	)
	if err != nil {
		h.renderError(w, r, "Failed to fetch API keys: "+err.Error())
		return
	}
	defer rows.Close()

	var keys []models.APIKey
	for rows.Next() {
		var k models.APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Description, &k.LastUsedAt, &k.CreatedAt, &k.ExpiresAt); err != nil {
			logger.Error("failed to scan API key row", "error", err)
			continue
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for API keys", "error", err)
	}

	flash := r.URL.Query().Get("flash")
	newKey := r.URL.Query().Get("new_key")
	errorMsg := r.URL.Query().Get("error")

	data := map[string]interface{}{
		"Title":   "API Keys - GoZone",
		"User":    user,
		"APIKeys": keys,
		"Flash":   flash,
		"NewKey":  newKey,
		"Error":   errorMsg,
	}
	h.render(w, r, "api_keys.html", data)
}

func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/profile/api-keys", http.StatusSeeOther)
		return
	}

	description := strings.TrimSpace(r.FormValue("description"))
	if description == "" {
		description = "API Key"
	}

	rawKey, keyHash, err := generateAPIKey()
	if err != nil {
		h.renderError(w, r, "Failed to generate API key")
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		h.renderError(w, r, "Failed to begin transaction: "+err.Error())
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		"INSERT INTO api_keys (user_id, key_hash, description) VALUES (?, ?, ?)",
		user.ID, keyHash, description,
	)
	if err != nil {
		h.renderError(w, r, "Failed to create API key: "+err.Error())
		return
	}

	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'create_api_key', ?)",
		user.ID, fmt.Sprintf("Created API key: %s", description),
	)
	if err != nil {
		h.renderError(w, r, "Failed to log activity: "+err.Error())
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderError(w, r, "Failed to commit transaction: "+err.Error())
		return
	}

	http.Redirect(w, r, "/profile/api-keys?flash=created&new_key="+url.QueryEscape(rawKey), http.StatusSeeOther)
}

func (h *Handler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/profile/api-keys", http.StatusSeeOther)
		return
	}

	keyID := strings.TrimSpace(r.FormValue("key_id"))

	var keyUserID int64
	err := h.DB.QueryRow("SELECT user_id FROM api_keys WHERE id = ?", keyID).Scan(&keyUserID)
	if err == sql.ErrNoRows {
		http.Redirect(w, r, "/profile/api-keys?error=not_found", http.StatusSeeOther)
		return
	}
	if err != nil {
		h.renderError(w, r, "Failed to find API key: "+err.Error())
		return
	}

	if keyUserID != user.ID {
		http.Redirect(w, r, "/profile/api-keys?error=forbidden", http.StatusSeeOther)
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		h.renderError(w, r, "Failed to begin transaction: "+err.Error())
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM api_keys WHERE id = ?", keyID)
	if err != nil {
		h.renderError(w, r, "Failed to delete API key: "+err.Error())
		return
	}

	_, err = tx.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_api_key', ?)",
		user.ID, fmt.Sprintf("Deleted API key %s", keyID),
	)
	if err != nil {
		h.renderError(w, r, "Failed to log activity: "+err.Error())
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderError(w, r, "Failed to commit transaction: "+err.Error())
		return
	}

	http.Redirect(w, r, "/profile/api-keys?flash=deleted", http.StatusSeeOther)
}

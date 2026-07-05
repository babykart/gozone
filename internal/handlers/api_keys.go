package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/constants"
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

// apiKeyValidFlashCodes / apiKeyValidErrorCodes are the allow-lists of ?flash
// and ?error query codes the server actually emits for /profile/api-keys
// (CreateAPIKey -> flash=created, DeleteAPIKey -> flash=deleted /
// error=not_found). ListAPIKeys validates the incoming query params against
// these sets so a crafted link such as ?flash=Your+account+is+compromised
// cannot inject arbitrary text into the page — the handler is the trust
// boundary, mirroring loginErrorBanner (REVIEW.md L-1). The template already
// gates display on {{if eq .Flash "…"}} so this is defence-in-depth against a
// future template edit that renders the value verbatim.
var (
	apiKeyValidFlashCodes = map[string]struct{}{
		"created": {},
		"deleted": {},
	}
	apiKeyValidErrorCodes = map[string]struct{}{
		"not_found": {},
	}
)

// allowListedCode returns code only if it is present in allowed, "" otherwise.
// Used to filter untrusted query-string codes before they reach the template.
func allowListedCode(code string, allowed map[string]struct{}) string {
	if _, ok := allowed[code]; ok {
		return code
	}
	return ""
}

func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := middleware.GetUser(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	where := "user_id = ?"
	args := []any{user.ID}
	if search != "" {
		searchWhere, searchArgs := buildSearchLikeWhere(search, "description")
		where = where + " AND " + searchWhere
		args = append(args, searchArgs...)
	}

	countQuery := "SELECT COUNT(*) FROM api_keys WHERE " + where
	selectQuery := `SELECT id, user_id, description, last_used_at, created_at, expires_at
		FROM api_keys WHERE ` + where + " ORDER BY created_at DESC"

	var total int
	if err := h.DB.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		h.renderInternalError(w, r, "Failed to count API keys", err)
		return
	}

	page, perPage := parsePaginationParams(r, 10)
	pageInfo := pageInfoFromTotal(total, page, perPage)

	var rows *sql.Rows
	var err error
	if perPage > 0 {
		offset := (pageInfo.Current - 1) * perPage
		selectArgs := append([]any(nil), args...)
		selectArgs = append(selectArgs, perPage, offset)
		rows, err = h.DB.QueryContext(ctx, selectQuery+" LIMIT ? OFFSET ?", selectArgs...)
	} else {
		rows, err = h.DB.QueryContext(ctx, selectQuery, args...)
	}
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch API keys", err)
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

	if keys == nil {
		keys = []models.APIKey{}
	}

	flash := allowListedCode(r.URL.Query().Get("flash"), apiKeyValidFlashCodes)
	newKey := ""
	errorMsg := allowListedCode(r.URL.Query().Get("error"), apiKeyValidErrorCodes)

	if c, err := r.Cookie(constants.NewAPIKeyCookieName); err == nil && c.Value != "" {
		newKey = c.Value
		// Clear the one-time flash cookie immediately after reading it.
		// #nosec G124 -- Secure flag set dynamically via isSecure(r)
		http.SetCookie(w, &http.Cookie{
			Name:     constants.NewAPIKeyCookieName,
			Value:    "",
			Path:     "/profile/api-keys",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   isSecure(r),
			SameSite: http.SameSiteStrictMode,
		})
	}

	data := map[string]interface{}{
		"Title":    "API Keys - " + h.Cfg.Server.AppName,
		"User":     user,
		"APIKeys":  keys,
		"PageInfo": pageInfo,
		"Search":   search,
		"Flash":    flash,
		"NewKey":   newKey,
		"Error":    errorMsg,
	}
	h.render(w, r, "api_keys.html", data)
}

func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := middleware.GetUser(r)

	description := strings.TrimSpace(r.FormValue("description"))
	if description == "" {
		description = "API Key"
	}

	rawKey, keyHash, err := generateAPIKey()
	if err != nil {
		h.renderError(w, r, "Failed to generate API key")
		return
	}

	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO api_keys (user_id, key_hash, description) VALUES (?, ?, ?)",
		user.ID, keyHash, description,
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to create API key", err)
		return
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'create_api_key', ?)",
		user.ID, fmt.Sprintf("Created API key: %s", description),
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to log activity", err)
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
		return
	}

	// #nosec G124 -- Secure flag set dynamically via isSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     constants.NewAPIKeyCookieName,
		Value:    rawKey,
		Path:     "/profile/api-keys",
		MaxAge:   60,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/profile/api-keys?flash=created", http.StatusSeeOther)
}

func (h *Handler) DeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := middleware.GetUser(r)

	keyID := strings.TrimSpace(r.FormValue("key_id"))

	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	// Ownership-scoped delete mirrors BulkDeleteAPIKeys (DELETE ... WHERE
	// id = ? AND user_id = ?). RowsAffected==0 means the key does not exist
	// OR belongs to another user; both cases collapse into the same
	// ?error=not_found so a probing user cannot distinguish them (REVIEW.md
	// M-2 — IDOR existence oracle). The prior SELECT + distinct
	// ?error=forbidden branch leaked key-id existence regardless of ownership.
	res, err := tx.ExecContext(ctx, "DELETE FROM api_keys WHERE id = ? AND user_id = ?", keyID, user.ID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to delete API key", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Redirect(w, r, "/profile/api-keys?error=not_found", http.StatusSeeOther)
		return
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_api_key', ?)",
		user.ID, fmt.Sprintf("Deleted API key %s", keyID),
	)
	if err != nil {
		h.renderInternalError(w, r, "Failed to log activity", err)
		return
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
		return
	}

	http.Redirect(w, r, "/profile/api-keys?flash=deleted", http.StatusSeeOther)
}

// BulkDeleteAPIKeys deletes several of the current user's own API keys
// (POST /profile/api-keys/bulk-delete).
//
// Not admin-only — every authenticated user manages their own keys. Ownership
// is enforced per key via "DELETE ... WHERE id = ? AND user_id = ?": a key the
// user does not own (or that no longer exists) is reported as failed and
// skipped without aborting the rest. The whole batch runs in one transaction so
// the deletes and their activity-log entries commit atomically. Returns JSON
// {deleted, failed} for the AJAX toolbar.
func (h *Handler) BulkDeleteAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := middleware.GetUser(r)

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid form data"})
		return
	}

	// Dedupe while preserving order so a duplicated checkbox value can't double-
	// delete or double-log.
	seen := make(map[string]struct{})
	var keyIDs []string
	for _, id := range r.PostForm["key_id"] {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		keyIDs = append(keyIDs, id)
	}

	if len(keyIDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No API keys selected"})
		return
	}

	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		h.renderInternalError(w, r, "Failed to begin transaction", err)
		return
	}
	defer tx.Rollback()

	deleted := 0
	var failed []string
	for _, keyID := range keyIDs {
		// Ownership-scoped delete: RowsAffected==0 means not owned or already
		// gone — report as failed and continue without aborting the batch.
		res, err := tx.ExecContext(ctx, "DELETE FROM api_keys WHERE id = ? AND user_id = ?", keyID, user.ID)
		if err != nil {
			h.renderInternalError(w, r, "Failed to delete API key", err)
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			failed = append(failed, keyID)
			continue
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_api_key', ?)",
			user.ID, fmt.Sprintf("Deleted API key %s", keyID),
		); err != nil {
			h.renderInternalError(w, r, "Failed to log activity", err)
			return
		}
		deleted++
	}

	if err := tx.Commit(); err != nil {
		h.renderInternalError(w, r, "Failed to commit transaction", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}

package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// ListTSIGKeys renders the TSIG keys listing page (GET /tsigkeys).
func (h *Handler) ListTSIGKeys(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	keys, err := h.PDNS.ListTSIGKeys(r.Context())
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch TSIG keys", err)
		return
	}

	searchLower := strings.ToLower(search)
	var total int
	for _, k := range keys {
		if search == "" || strings.Contains(strings.ToLower(k.Name), searchLower) {
			total++
		}
	}

	page, perPage := parsePaginationParams(r, 10)
	pageInfo := pageInfoFromTotal(total, page, perPage)

	// start/end depend only on the page window, so compute them once instead
	// of on every iteration (REVIEW.md L-16b).
	start := (pageInfo.Current - 1) * pageInfo.PerPage
	end := pageInfo.Current * pageInfo.PerPage
	var paginated []models.TSIGKey
	var idx int
	for _, k := range keys {
		if search != "" && !strings.Contains(strings.ToLower(k.Name), searchLower) {
			continue
		}
		if perPage <= 0 || (idx >= start && idx < end) {
			paginated = append(paginated, k)
		}
		idx++
		if perPage > 0 && idx >= end {
			break
		}
	}

	if paginated == nil {
		paginated = []models.TSIGKey{}
	}

	data := map[string]interface{}{
		"Title":    "TSIG Keys - " + h.Cfg.Server.AppName,
		"User":     user,
		"Keys":     paginated,
		"PageInfo": pageInfo,
		"Search":   search,
		"IsAdmin":  user.IsAdmin(),
	}
	h.render(w, r, "tsigkeys.html", data)
}

// CreateTSIGKeyPage renders the TSIG key creation form (GET /tsigkeys/new).
func (h *Handler) CreateTSIGKeyPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	data := map[string]interface{}{
		"Title":      "Create TSIG Key - " + h.Cfg.Server.AppName,
		"User":       user,
		"Algorithms": tsigAlgorithms(),
	}
	h.render(w, r, "tsigkey_create.html", data)
}

// CreateTSIGKey creates a new TSIG key (POST /tsigkeys/create).
// If the key material is left empty, a random 64-byte secret is
// generated server-side before sending to PowerDNS.
func (h *Handler) CreateTSIGKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	name := strings.TrimSpace(r.FormValue("name"))
	algorithm := strings.TrimSpace(r.FormValue("algorithm"))
	key := strings.TrimSpace(r.FormValue("key"))

	if name == "" {
		h.renderError(w, r, "Key name is required")
		return
	}
	if algorithm == "" {
		h.renderError(w, r, "Algorithm is required")
		return
	}
	if err := validators.ValidateTSIGAlgorithm(algorithm); err != nil {
		h.renderError(w, r, "Invalid algorithm: "+err.Error())
		return
	}
	if key == "" {
		var err error
		key, err = generateTSIGSecret()
		if err != nil {
			h.renderInternalError(w, r, "Failed to generate TSIG secret", err)
			return
		}
	}

	tsigKey, err := h.PDNS.CreateTSIGKey(r.Context(), models.TSIGKey{
		Name:      name,
		Algorithm: algorithm,
		Key:       key,
		Type:      "TSIGKey",
	})
	if err != nil {
		h.renderInternalError(w, r, "Failed to create TSIG key", err)
		return
	}

	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, Action: "create_tsigkey", Details: fmt.Sprintf("Created TSIG key %s (alg: %s)", tsigKey.Name, tsigKey.Algorithm)}); err != nil {
		logger.Error("failed to log create_tsigkey activity", "key_id", tsigKey.ID, "error", err)
	}

	http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
}

// EditTSIGKeyPage renders the TSIG key edit form (GET /tsigkeys/{key_id}/edit).
func (h *Handler) EditTSIGKeyPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	keyID := r.PathValue("key_id")

	tsigKey, err := h.PDNS.GetTSIGKey(r.Context(), keyID)
	if err != nil {
		h.renderInternalError(w, r, "TSIG key not found", err)
		return
	}

	// I-1: never re-expose the TSIG key material in the edit form. GoZone has no
	// need for the plaintext after creation (PowerDNS is the consumer); an empty
	// key field on submit is treated as "keep current" by UpdateTSIGKey.
	tsigKey.Key = ""

	data := map[string]interface{}{
		"Title":      "Edit TSIG Key - " + h.Cfg.Server.AppName,
		"User":       user,
		"Key":        tsigKey,
		"Algorithms": tsigAlgorithms(),
	}
	h.render(w, r, "tsigkey_edit.html", data)
}

// UpdateTSIGKey updates an existing TSIG key (POST /tsigkeys/{key_id}/update).
// The key material field is optional: leaving it blank keeps the current secret
// (I-1) — PowerDNS PUT replaces the whole resource, so the existing material is
// re-fetched and forwarded unchanged.
func (h *Handler) UpdateTSIGKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	keyID := r.PathValue("key_id")
	algorithm := strings.TrimSpace(r.FormValue("algorithm"))
	key := strings.TrimSpace(r.FormValue("key"))

	if algorithm == "" {
		h.renderError(w, r, "Algorithm is required")
		return
	}
	if err := validators.ValidateTSIGAlgorithm(algorithm); err != nil {
		h.renderError(w, r, "Invalid algorithm: "+err.Error())
		return
	}
	if key == "" {
		// I-1: blank key material = keep current secret. PowerDNS's PUT replaces
		// the resource, so re-fetch the existing material and forward it back.
		existing, err := h.PDNS.GetTSIGKey(r.Context(), keyID)
		if err != nil {
			h.renderInternalError(w, r, "Failed to fetch current TSIG key", err)
			return
		}
		key = existing.Key
	}

	tsigKey := models.TSIGKey{
		Name:      keyID,
		Algorithm: algorithm,
		Key:       key,
		Type:      "TSIGKey",
	}

	if err := h.PDNS.UpdateTSIGKey(r.Context(), keyID, tsigKey); err != nil {
		h.renderInternalError(w, r, "Failed to update TSIG key", err)
		return
	}

	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, Action: "update_tsigkey", Details: fmt.Sprintf("Updated TSIG key %s (alg: %s)", keyID, algorithm)}); err != nil {
		logger.Error("failed to log update_tsigkey activity", "key_id", keyID, "error", err)
	}

	http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
}

// DeleteTSIGKey deletes a TSIG key (POST /tsigkeys/delete).
func (h *Handler) DeleteTSIGKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	keyID := strings.TrimSpace(r.FormValue("key_id"))
	if keyID == "" {
		http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
		return
	}

	if err := h.PDNS.DeleteTSIGKey(r.Context(), keyID); err != nil {
		h.renderInternalError(w, r, "Failed to delete TSIG key", err)
		return
	}

	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, Action: "delete_tsigkey", Details: fmt.Sprintf("Deleted TSIG key %s", keyID)}); err != nil {
		logger.Error("failed to log delete_tsigkey activity", "key_id", keyID, "error", err)
	}

	http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
}

// BulkDeleteTSIGKeys deletes several TSIG keys by key_id
// (POST /tsigkeys/bulk-delete).
//
// Admin-only. The selection arrives as repeated "key_id" form values (one per
// checked row). Each key is removed with its own DELETE (PowerDNS has no batch
// API); the operation is best-effort — a failure on one key does not abort the
// rest, and each successfully removed key gets its own 'delete_tsigkey' activity
// log entry. Returns JSON {deleted, failed} for the AJAX toolbar.
func (h *Handler) BulkDeleteTSIGKeys(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No TSIG keys selected"})
		return
	}

	deleted := 0
	var failed []string
	for _, keyID := range keyIDs {
		if err := h.PDNS.DeleteTSIGKey(r.Context(), keyID); err != nil {
			logger.Error("bulk delete tsig key failed", "key_id", keyID, "error", err)
			failed = append(failed, keyID)
			continue
		}
		deleted++
		if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, Action: "delete_tsigkey", Details: fmt.Sprintf("Deleted TSIG key %s", keyID)}); err != nil {
			logger.Error("failed to log delete_tsigkey activity", "key_id", keyID, "error", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}

func tsigAlgorithms() []string {
	return []string{
		"hmac-md5",
		"hmac-sha1",
		"hmac-sha256",
		"hmac-sha512",
	}
}

// generateTSIGSecret produces a cryptographically random 64-byte secret
// encoded as a base64 string, suitable for use as a TSIG key material
// (default for hmac-sha512).
func generateTSIGSecret() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate tsig secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

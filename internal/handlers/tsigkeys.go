package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// ListTSIGKeys renders the TSIG keys listing page (GET /tsigkeys).
func (h *Handler) ListTSIGKeys(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	keys, err := h.PDNS.ListTSIGKeys()
	if err != nil {
		h.renderError(w, r, "Failed to fetch TSIG keys: "+err.Error())
		return
	}

	data := map[string]interface{}{
		"Title":   "TSIG Keys - GoZone",
		"User":    user,
		"Keys":    keys,
		"IsAdmin": user.IsAdmin(),
	}
	h.render(w, r, "tsigkeys.html", data)
}

// CreateTSIGKeyPage renders the TSIG key creation form (GET /tsigkeys/new).
func (h *Handler) CreateTSIGKeyPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	data := map[string]interface{}{
		"Title":      "Create TSIG Key - GoZone",
		"User":       user,
		"Algorithms": tsigAlgorithms(),
	}
	h.render(w, r, "tsigkey_create.html", data)
}

// CreateTSIGKey creates a new TSIG key (POST /tsigkeys/create).
func (h *Handler) CreateTSIGKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
		return
	}

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
	if key == "" {
		h.renderError(w, r, "Key material is required")
		return
	}

	tsigKey, err := h.PDNS.CreateTSIGKey(models.TSIGKey{
		Name:      name,
		Algorithm: algorithm,
		Key:       key,
		Type:      "TSIGKey",
	})
	if err != nil {
		h.renderError(w, r, "Failed to create TSIG key: "+err.Error())
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'create_tsigkey', ?)",
		user.ID, fmt.Sprintf("Created TSIG key %s (alg: %s)", tsigKey.Name, tsigKey.Algorithm),
	); err != nil {
		logger.Error("failed to log create_tsigkey activity", "key_id", tsigKey.ID, "error", err)
	}

	http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
}

// EditTSIGKeyPage renders the TSIG key edit form (GET /tsigkeys/{key_id}/edit).
func (h *Handler) EditTSIGKeyPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	keyID := r.PathValue("key_id")

	tsigKey, err := h.PDNS.GetTSIGKey(keyID)
	if err != nil {
		h.renderError(w, r, "TSIG key not found: "+err.Error())
		return
	}

	data := map[string]interface{}{
		"Title":      "Edit TSIG Key - GoZone",
		"User":       user,
		"Key":        tsigKey,
		"Algorithms": tsigAlgorithms(),
	}
	h.render(w, r, "tsigkey_edit.html", data)
}

// UpdateTSIGKey updates an existing TSIG key (POST /tsigkeys/{key_id}/update).
func (h *Handler) UpdateTSIGKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
		return
	}

	keyID := r.PathValue("key_id")
	algorithm := strings.TrimSpace(r.FormValue("algorithm"))
	key := strings.TrimSpace(r.FormValue("key"))

	if algorithm == "" {
		h.renderError(w, r, "Algorithm is required")
		return
	}
	if key == "" {
		h.renderError(w, r, "Key material is required")
		return
	}

	tsigKey := models.TSIGKey{
		Name:      keyID,
		Algorithm: algorithm,
		Key:       key,
		Type:      "TSIGKey",
	}

	if err := h.PDNS.UpdateTSIGKey(keyID, tsigKey); err != nil {
		h.renderError(w, r, "Failed to update TSIG key: "+err.Error())
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'update_tsigkey', ?)",
		user.ID, fmt.Sprintf("Updated TSIG key %s (alg: %s)", keyID, algorithm),
	); err != nil {
		logger.Error("failed to log update_tsigkey activity", "key_id", keyID, "error", err)
	}

	http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
}

// DeleteTSIGKey deletes a TSIG key (POST /tsigkeys/delete).
func (h *Handler) DeleteTSIGKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
		return
	}

	keyID := strings.TrimSpace(r.FormValue("key_id"))
	if keyID == "" {
		http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
		return
	}

	if err := h.PDNS.DeleteTSIGKey(keyID); err != nil {
		h.renderError(w, r, "Failed to delete TSIG key: "+err.Error())
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'delete_tsigkey', ?)",
		user.ID, fmt.Sprintf("Deleted TSIG key %s", keyID),
	); err != nil {
		logger.Error("failed to log delete_tsigkey activity", "key_id", keyID, "error", err)
	}

	http.Redirect(w, r, "/tsigkeys", http.StatusSeeOther)
}

func tsigAlgorithms() []string {
	return []string{
		"hmac-md5",
		"hmac-sha1",
		"hmac-sha256",
		"hmac-sha512",
	}
}

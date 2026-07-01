package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// CreateCryptokey creates a new DNSSEC key for a zone.
func (h *Handler) CreateCryptokey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	keyType := r.FormValue("keytype")
	if keyType != "ksk" && keyType != "zsk" {
		h.renderError(w, r, "Key type must be ksk or zsk")
		return
	}

	algorithm := r.FormValue("algorithm")
	if algorithm == "" {
		algorithm = "ecdsa256"
	}
	if err := validators.ValidateDNSSECAlgorithm(algorithm); err != nil {
		h.renderError(w, r, "Invalid algorithm: "+err.Error())
		return
	}

	key, err := h.PDNS.CreateCryptokey(r.Context(), zoneID, keyType, true, algorithm)
	if err != nil {
		h.renderInternalError(w, r, "Failed to create cryptokey", err)
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_cryptokey', ?)",
		user.ID, zoneID, fmt.Sprintf("Created %s key %d (%s)", keyType, key.ID, algorithm),
	); err != nil {
		logger.Error("failed to log create_cryptokey", "zone_id", zoneID, "error", err)
	}

	if err := h.PDNS.RectifyZone(r.Context(), zoneID); err != nil {
		h.renderInternalError(w, r, "Key created but rectification failed", err)
		return
	}

	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther) // #nosec G710
}

// ToggleCryptokey activates or deactivates a DNSSEC key.
func (h *Handler) ToggleCryptokey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	keyIDStr := r.PathValue("key_id")
	keyID, err := strconv.Atoi(keyIDStr)
	if err != nil {
		h.renderError(w, r, "Invalid key ID")
		return
	}

	active := r.FormValue("active") == "true"

	if err := h.PDNS.ToggleCryptokey(r.Context(), zoneID, keyID, active); err != nil {
		h.renderInternalError(w, r, "Failed to toggle cryptokey", err)
		return
	}

	action := "deactivate"
	if active {
		action = "activate"
	}
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'cryptokey_"+action+"', ?)",
		user.ID, zoneID, fmt.Sprintf("%s key %d", action, keyID),
	); err != nil {
		logger.Error("failed to log cryptokey toggle", "zone_id", zoneID, "error", err)
	}

	if err := h.PDNS.RectifyZone(r.Context(), zoneID); err != nil {
		h.renderInternalError(w, r, "Key toggled but rectification failed", err)
		return
	}

	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther) // #nosec G710
}

// DeleteCryptokey deletes a DNSSEC key from a zone.
func (h *Handler) DeleteCryptokey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	keyIDStr := r.PathValue("key_id")
	keyID, err := strconv.Atoi(keyIDStr)
	if err != nil {
		h.renderError(w, r, "Invalid key ID")
		return
	}

	if err := h.PDNS.DeleteCryptokey(r.Context(), zoneID, keyID); err != nil {
		h.renderInternalError(w, r, "Failed to delete cryptokey", err)
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'delete_cryptokey', ?)",
		user.ID, zoneID, fmt.Sprintf("Deleted key %d", keyID),
	); err != nil {
		logger.Error("failed to log delete_cryptokey", "zone_id", zoneID, "error", err)
	}

	if err := h.PDNS.RectifyZone(r.Context(), zoneID); err != nil {
		h.renderInternalError(w, r, "Key deleted but rectification failed", err)
		return
	}

	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther) // #nosec G710
}

// GetDNSSECAlgorithms returns the list of supported DNSSEC algorithms.
func GetDNSSECAlgorithms() []models.DNSSECAlgorithm {
	return models.DNSSECAlgorithms()
}

// ClearZoneCache invalidates the local cache for a zone so the next read
// fetches fresh data from PowerDNS. Available to any authenticated user
// with group access to the zone.
func (h *Handler) ClearZoneCache(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	h.PDNS.InvalidateZoneCache(r.Context(), zoneID)

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'clear_zone_cache', ?)",
		user.ID, zoneID, fmt.Sprintf("Cleared cache for zone %s", zoneID),
	); err != nil {
		logger.Error("failed to log clear_zone_cache", "zone_id", zoneID, "error", err)
	}

	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther) // #nosec G710
}

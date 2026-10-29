package handlers

import (
	"net/http"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/logger"
)

// zoneLocks aliases the shared per-zone locker that lives in the dnsops
// service layer. The Handler holds a pointer to the service's instance so
// REST, web and MCP record writes on the same zone serialize against each
// other in this process and across database-sharing instances. See
// dnsops.ZoneLocks for the rationale.
type zoneLocks = dnsops.ZoneLocks

// lockZone acquires the zone lock for an HTML handler. On failure it renders
// the standard internal-error page and reports false.
func (h *Handler) lockZone(w http.ResponseWriter, r *http.Request, zoneID string) (func(), bool) {
	release, err := h.zoneLocks.Lock(r.Context(), zoneID)
	if err != nil {
		logger.Error("failed to acquire zone lock", "zone_id", zoneID, "error", err)
		h.renderInternalError(w, r, "Failed to acquire the zone lock", err)
		return nil, false
	}
	return release, true
}

// lockZoneAPI acquires the zone lock for a JSON handler. On failure it writes
// the standard JSON error and reports false.
func (h *Handler) lockZoneAPI(w http.ResponseWriter, r *http.Request, zoneID string) (func(), bool) {
	release, err := h.zoneLocks.Lock(r.Context(), zoneID)
	if err != nil {
		logger.Error("failed to acquire zone lock", "zone_id", zoneID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to acquire the zone lock"})
		return nil, false
	}
	return release, true
}

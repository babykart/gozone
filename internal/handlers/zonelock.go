package handlers

import (
	"errors"
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

// zoneLockErrorResponse maps a zone-lock acquisition failure to an HTTP
// status and a client-facing message: dnsops.ErrZoneBusy (bare or wrapped in
// a StageError) is a client-retryable 409, anything else is a generic 500.
func zoneLockErrorResponse(err error) (status int, msg string) {
	if errors.Is(err, dnsops.ErrZoneBusy) {
		return http.StatusConflict, "Zone is busy with another operation; try again later"
	}
	return http.StatusInternalServerError, "Failed to acquire the zone lock"
}

// lockZone acquires the zone lock for an HTML handler. On failure it renders
// an error response — a 409 conflict page for contention, the standard
// internal-error page otherwise — and reports false.
func (h *Handler) lockZone(w http.ResponseWriter, r *http.Request, zoneID string) (func(), bool) {
	release, err := h.zoneLocks.Lock(r.Context(), zoneID)
	if err != nil {
		logger.Error("failed to acquire zone lock", "zone_id", zoneID, "error", err)
		status, msg := zoneLockErrorResponse(err)
		if status == http.StatusConflict {
			http.Error(w, msg, status)
			return nil, false
		}
		h.renderInternalError(w, r, msg, err)
		return nil, false
	}
	return release, true
}

// lockZoneAPI acquires the zone lock for a JSON handler. On failure it writes
// a JSON error — 409 for contention, 500 otherwise — and reports false.
func (h *Handler) lockZoneAPI(w http.ResponseWriter, r *http.Request, zoneID string) (func(), bool) {
	release, err := h.zoneLocks.Lock(r.Context(), zoneID)
	if err != nil {
		logger.Error("failed to acquire zone lock", "zone_id", zoneID, "error", err)
		status, msg := zoneLockErrorResponse(err)
		writeJSON(w, status, map[string]string{"error": msg})
		return nil, false
	}
	return release, true
}

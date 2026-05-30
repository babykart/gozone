package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// Standardized API error codes.
const (
	ErrCodeInvalidJSON     = "INVALID_JSON"
	ErrCodeValidationError = "VALIDATION_ERROR"
	ErrCodeZoneNotFound    = "ZONE_NOT_FOUND"
	ErrCodeZoneCreateError = "ZONE_CREATE_ERROR"
	ErrCodeZoneDeleteError = "ZONE_DELETE_ERROR"
	ErrCodeRecordError     = "RECORD_ERROR"
	ErrCodeRecordNotFound  = "RECORD_NOT_FOUND"
	ErrCodeInternalError   = "INTERNAL_ERROR"
	ErrCodeStatsError      = "STATS_ERROR"
)

// apiError is the standardized error response body.
type apiError struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeAPIError sends a standardized error response and logs the underlying cause.
func writeAPIError(w http.ResponseWriter, status int, code, label string) {
	resp := apiError{
		Error:   label,
		Code:    code,
		Message: label,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp) // #nosec G104
}

// writeAPIErrorWithCause logs the cause and returns a generic error to the client.
func (h *Handler) writeAPIErrorWithCause(w http.ResponseWriter, r *http.Request, status int, code string, label string, err error) {
	logger.Error("api error", "method", r.Method, "path", r.URL.Path, "error", err, "user_id", apiUserID(r))
	writeAPIError(w, status, code, label)
}

// apiUserID extracts a user identifier from request context for logging.
func apiUserID(r *http.Request) string {
	user := middleware.GetUser(r)
	if user != nil {
		return fmt.Sprintf("%d", user.ID)
	}
	return "unknown"
}

// -- Zone API ---

// APIListZones returns all PowerDNS zones as a JSON array (GET /api/v1/zones).
func (h *Handler) APIListZones(w http.ResponseWriter, r *http.Request) {
	zones, err := h.PDNS.ListZones()
	if err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to list zones", err)
		return
	}
	zones, _ = h.filterZonesForUser(r, zones)
	if zones == nil {
		zones = []models.Zone{}
	}
	writeJSON(w, http.StatusOK, zones)
}

// APIGetZone returns a single zone by zone_id as JSON (GET /api/v1/zones/{zone_id}).
func (h *Handler) APIGetZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	zone, err := h.PDNS.GetZone(zoneID)
	if err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusNotFound, ErrCodeZoneNotFound, "zone not found", err)
		return
	}
	writeJSON(w, http.StatusOK, zone)
}

// APICreateZone creates a zone from a JSON body (POST /api/v1/zones).
//
// Expects a models.ZoneCreateRequest payload. Returns the created zone
// with HTTP 201 on success.
func (h *Handler) APICreateZone(w http.ResponseWriter, r *http.Request) {
	var req models.ZoneCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := validators.ValidateDomainName(req.Name); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	zone, err := h.PDNS.CreateZone(req)
	if err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeZoneCreateError, "failed to create zone", err)
		return
	}
	writeJSON(w, http.StatusCreated, zone)
}

// APIDeleteZone deletes a zone by zone_id (DELETE /api/v1/zones/{zone_id}).
func (h *Handler) APIDeleteZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	if err := h.PDNS.DeleteZone(zoneID); err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeZoneDeleteError, "failed to delete zone", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "zone deleted"})
}

// -- Record API ---

// APIListRecords returns all records (RRSets) for a zone as JSON (GET /api/v1/zones/{zone_id}/records).
func (h *Handler) APIListRecords(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	records, err := h.PDNS.ListRecords(zoneID)
	if err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeRecordNotFound, "failed to list records", err)
		return
	}
	if records == nil {
		records = []models.RRSet{}
	}
	writeJSON(w, http.StatusOK, records)
}

// APICreateRecord creates a record (RRSet) in a zone from a JSON body (POST /api/v1/zones/{zone_id}/records).
//
// Expects a models.RRSet payload. Returns HTTP 201 on success.
func (h *Handler) APICreateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	var rrset models.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rrset); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := validators.ValidateRecordType(rrset.Type); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	for _, r := range rrset.Records {
		if err := validators.ValidateRecordContent(rrset.Type, r.Content); err != nil {
			writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
			return
		}
	}

	if err := h.PDNS.CreateRecord(zoneID, rrset); err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeRecordError, "failed to create record", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "record created"})
}

// APIUpdateRecord replaces a record (RRSet) in a zone from a JSON body (PUT /api/v1/zones/{zone_id}/records).
//
// Uses the REPLACE changetype to ensure idempotent updates.
func (h *Handler) APIUpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	var rrset models.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rrset); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := validators.ValidateRecordType(rrset.Type); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	for _, r := range rrset.Records {
		if err := validators.ValidateRecordContent(rrset.Type, r.Content); err != nil {
			writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
			return
		}
	}

	if err := h.PDNS.UpdateRecord(zoneID, rrset); err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeRecordError, "failed to update record", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "record updated"})
}

// APIDeleteRecord deletes a record from a zone by name and type (DELETE /api/v1/zones/{zone_id}/records).
//
// Expects a JSON body with "name" and "type" fields.
func (h *Handler) APIDeleteRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")

	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := validators.ValidateRecordType(req.Type); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	if err := h.PDNS.DeleteRecord(zoneID, req.Name, req.Type); err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeRecordError, "failed to delete record", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "record deleted"})
}

// APIStats returns PowerDNS server statistics combined with the zone count (GET /api/v1/stats).
func (h *Handler) APIStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.PDNS.GetStatistics()
	if err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeStatsError, "failed to get statistics", err)
		return
	}

	zones, _ := h.PDNS.ListZones()
	zones, _ = h.filterZonesForUser(r, zones)
	zoneCount := 0
	if zones != nil {
		zoneCount = len(zones)
	}

	response := map[string]interface{}{
		"statistics": stats,
		"zone_count": zoneCount,
	}
	writeJSON(w, http.StatusOK, response)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) // #nosec G104
}

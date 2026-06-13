package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
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
	ErrCodeConflict        = "CONFLICT"
	ErrCodeUnauthorized    = "UNAUTHORIZED"
)

// pdnsErrorStatus maps a typed PowerDNS client error to the appropriate HTTP
// status code and API error code. notFoundCode lets callers distinguish a
// missing zone from a missing record.
func pdnsErrorStatus(err error, notFoundCode string) (int, string) {
	switch {
	case errors.Is(err, pdns.ErrNotFound):
		return http.StatusNotFound, notFoundCode
	case errors.Is(err, pdns.ErrValidation):
		return http.StatusBadRequest, ErrCodeValidationError
	case errors.Is(err, pdns.ErrConflict):
		return http.StatusConflict, ErrCodeConflict
	case errors.Is(err, pdns.ErrUnauthorized):
		return http.StatusUnauthorized, ErrCodeUnauthorized
	default:
		return http.StatusInternalServerError, ErrCodeInternalError
	}
}

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
	zones, err := h.PDNS.ListZones(r.Context())
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
	zone, err := h.PDNS.GetZone(r.Context(), zoneID)
	if err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeZoneNotFound)
		h.writeAPIErrorWithCause(w, r, status, code, "zone not found", err)
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

	if req.Kind == "" {
		req.Kind = "Native"
	}

	if err := validators.ValidateZoneKind(req.Kind); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	zone, err := h.PDNS.CreateZone(r.Context(), req)
	if err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeZoneCreateError)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to create zone", err)
		return
	}
	writeJSON(w, http.StatusCreated, zone)
}

// APIDeleteZone deletes a zone by zone_id (DELETE /api/v1/zones/{zone_id}).
func (h *Handler) APIDeleteZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	if err := h.PDNS.DeleteZone(r.Context(), zoneID); err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeZoneNotFound)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to delete zone", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "zone deleted"})
}

// -- Record API ---

// APIListRecords returns all records (RRSets) for a zone as JSON (GET /api/v1/zones/{zone_id}/records).
func (h *Handler) APIListRecords(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	records, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeRecordNotFound)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to list records", err)
		return
	}
	if records == nil {
		records = []models.RRSet{}
	}
	writeJSON(w, http.StatusOK, records)
}

// prepareAPIRecordSet validates and normalises an RRSet from an API request for
// the PDNS PATCH API, mirroring the web write path: it canonicalises the name
// (trailing dot, relative-to-zone), then embeds the MX/SRV priority into each
// record's content and quotes TXT/SPF. Content is validated in its bare form
// (priority carried in RecordInfo.Priority), which matches what APIListRecords
// returns, so a read-modify-write round trip works. Returns a validation error
// for a 400, or nil when the RRSet is valid.
func prepareAPIRecordSet(rrset *models.RRSet, zoneID string) error {
	if err := validators.ValidateRecordType(rrset.Type); err != nil {
		return err
	}
	if err := validators.ValidateRecordName(rrset.Name); err != nil {
		return err
	}
	for i := range rrset.Records {
		if err := validators.ValidateRecordContent(rrset.Type, rrset.Records[i].Content); err != nil {
			return err
		}
	}

	rrset.Name = normalizeRecordName(rrset.Name, zoneID)
	for i := range rrset.Records {
		rrset.Records[i].Content, rrset.Records[i].Priority =
			prepareRecordContent(rrset.Type, rrset.Records[i].Content, rrset.Records[i].Priority)
	}
	return nil
}

// APICreateRecord creates a record (RRSet) in a zone from a JSON body (POST /api/v1/zones/{zone_id}/records).
//
// Expects a models.RRSet payload. For MX/SRV, the priority is taken from each
// record's "priority" field and embedded into the content for PowerDNS. Returns
// HTTP 201 on success.
func (h *Handler) APICreateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	var rrset models.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rrset); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := prepareAPIRecordSet(&rrset, zoneID); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	if err := h.PDNS.CreateRecord(r.Context(), zoneID, rrset); err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeRecordError)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to create record", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "record created"})
}

// APIUpdateRecord replaces a record (RRSet) in a zone from a JSON body (PUT /api/v1/zones/{zone_id}/records).
//
// Uses the REPLACE changetype to ensure idempotent updates. As with creation,
// MX/SRV priority is taken from the "priority" field and embedded into content.
func (h *Handler) APIUpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	var rrset models.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rrset); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := prepareAPIRecordSet(&rrset, zoneID); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, rrset); err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeRecordError)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to update record", err)
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

	if err := h.PDNS.DeleteRecord(r.Context(), zoneID, req.Name, req.Type); err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeRecordError)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to delete record", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "record deleted"})
}

// APIStats returns PowerDNS server statistics combined with the zone count (GET /api/v1/stats).
func (h *Handler) APIStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.PDNS.GetStatistics(r.Context())
	if err != nil {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeStatsError, "failed to get statistics", err)
		return
	}

	zones, _ := h.PDNS.ListZones(r.Context())
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

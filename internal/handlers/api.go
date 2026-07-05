package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
	"github.com/babykart/gozone/internal/validators"
)

// Standardized API error codes.
const (
	ErrCodeInvalidJSON        = "INVALID_JSON"
	ErrCodeValidationError    = "VALIDATION_ERROR"
	ErrCodeZoneNotFound       = "ZONE_NOT_FOUND"
	ErrCodeZoneCreateError    = "ZONE_CREATE_ERROR"
	ErrCodeZoneDeleteError    = "ZONE_DELETE_ERROR"
	ErrCodeRecordError        = "RECORD_ERROR"
	ErrCodeRecordNotFound     = "RECORD_NOT_FOUND"
	ErrCodeInternalError      = "INTERNAL_ERROR"
	ErrCodeStatsError         = "STATS_ERROR"
	ErrCodeConflict           = "CONFLICT"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeLuaUpdatesDisabled = "LUA_UPDATES_DISABLED"
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
	case errors.Is(err, pdns.ErrLuaUpdatesDisabled):
		return http.StatusBadRequest, ErrCodeLuaUpdatesDisabled
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
	filtered, filterErr := h.filterZonesForUser(r, zones)
	if filterErr != nil {
		logger.Error("failed to filter zones for user", "error", filterErr)
	}
	zones = filtered
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

	// Canonicalise the zone name and nameservers (lowercase + trailing dot)
	// so the API accepts "example.com" without requiring the trailing dot
	// that PowerDNS mandates internally.
	req.Name = normalizeZoneName(req.Name)
	for i := range req.Nameservers {
		req.Nameservers[i] = normalizeZoneName(req.Nameservers[i])
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

	// Audit trail: mirror the web DeleteZone handler so API-driven deletes show
	// up in the activity log. user_id is the API key owner (set by APIKeyAuth);
	// the guard keeps this panic-free if the route is ever exposed unauthenticated.
	var userID any
	if user := middleware.GetUser(r); user != nil {
		userID = user.ID
	}
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'delete_zone', ?)",
		userID, zoneID, fmt.Sprintf("Deleted zone %s via API", zoneID),
	); err != nil {
		logger.Error("failed to log delete_zone activity", "zone_id", zoneID, "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "zone deleted"})
}

// -- Record API ---

// APIListRecords returns records (RRSets) for a zone as JSON
// (GET /api/v1/zones/{zone_id}/records).
//
// Without query parameters the entire zone is returned as a JSON array.
// With optional `name` and `type` query parameters, the response is filtered
// to RRSets matching those values (mirroring the PowerDNS API rrset_name and
// rrset_type query parameters):
//
//   - ?name=www.example.com.       → all RRSets with that name (any type)
//   - ?name=www.example.com.&type=A → the single RRSet for that name+type
//   - ?type=A                     → invalid alone (PowerDNS requires rrset_name with rrset_type)
//
// The `name` query value is canonicalised against the zone the same way the
// write path does: trailing dot is added if missing, `@` resolves to the
// apex, bare labels ("www") are expanded against the zone. Without this
// normalisation PowerDNS silently returns an empty list for names that are
// syntactically valid but missing the canonical trailing dot (e.g.
// "www.example.com" vs "www.example.com.").
//
// The response is always a JSON array (possibly empty), so clients do not need
// to handle a different shape when filters are applied.
func (h *Handler) APIListRecords(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	rrType := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("type")))

	if rrType != "" && name == "" {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, "the 'type' query parameter requires 'name'")
		return
	}

	if name != "" {
		// Canonicalise against the zone so PDNS rrset_name matching sees the
		// same FQDN the write path sends (e.g. "www.example.com" →
		// "www.example.com."). Lowercase is part of the canonical form too.
		name = normalizeRecordName(name, zoneID)
	}

	var (
		records []models.RRSet
		err     error
	)
	if name == "" {
		records, err = h.PDNS.ListRecords(r.Context(), zoneID)
	} else {
		records, err = h.PDNS.ListRecord(r.Context(), zoneID, name, rrType)
	}
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
		if err := validators.ValidateRecordPriority(rrset.Type, rrset.Records[i].Priority); err != nil {
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
//
// The body also accepts an optional GoZone-only sentinel `clear_comments`
// (bool). When set to true it translates to a PDNS "comments":[] purge before
// the request is forwarded: all existing comments on the RRSet are dropped,
// any `comments` array supplied in the same body is discarded. This is the
// REST counterpart of the web form's `comment_clear` checkbox; the field is
// write-only and is never returned by GET /records.
func (h *Handler) APIUpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	var req apiRRSetUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if req.ClearComments != nil && *req.ClearComments {
		req.RRSet.Comments = &models.CommentPatch{Clear: true}
	}

	if err := prepareAPIRecordSet(&req.RRSet, zoneID); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, req.RRSet); err != nil {
		status, code := pdnsErrorStatus(err, ErrCodeRecordError)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to update record", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "record updated"})
}

// apiRRSetUpdateRequest is the JSON body shape accepted by PUT /api/v1/zones/{zone_id}/records.
// It embeds models.RRSet so the documented RRSet fields stay flat in the wire
// payload, and adds the GoZone-only `clear_comments` sentinel that lets clients
// purge existing RRSet comments without resorting to the round-trip-unsafe
// "comments":[] convention (which UnmarshalJSON normalises to "preserve").
type apiRRSetUpdateRequest struct {
	models.RRSet
	ClearComments *bool `json:"clear_comments,omitempty"`
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
	if err := validators.ValidateRecordName(req.Name); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}
	req.Name = normalizeRecordName(req.Name, zoneID)

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
	filtered, filterErr := h.filterZonesForUser(r, zones)
	if filterErr != nil {
		logger.Error("failed to filter zones for user", "error", filterErr)
	}
	zones = filtered
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

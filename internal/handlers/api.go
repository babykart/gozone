package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/dnsops"
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
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeInternalError      = "INTERNAL_ERROR"
	ErrCodeStatsError         = "STATS_ERROR"
	ErrCodeConflict           = "CONFLICT"
	ErrCodeUpstreamAuthError  = "UPSTREAM_AUTH_ERROR"
	ErrCodeLuaUpdatesDisabled = "LUA_UPDATES_DISABLED"
)

// pdnsErrorStatus maps a typed PowerDNS client error to the appropriate HTTP
// status code and API error code. notFoundCode lets callers distinguish a
// missing zone from a missing record.
//
// A PowerDNS 401/403 is NOT passed through as this server's own 401: the
// client's API key was already validated by GoZone's middleware, and a 401
// here would tell a correctly-authenticated client its key is invalid. The
// GoZone→PowerDNS credential is broken — an upstream/gateway failure — so it
// maps to 502 UPSTREAM_AUTH_ERROR.
func pdnsErrorStatus(err error, notFoundCode string) (int, string) {
	switch {
	case errors.Is(err, pdns.ErrNotFound):
		return http.StatusNotFound, notFoundCode
	case errors.Is(err, pdns.ErrValidation):
		return http.StatusBadRequest, ErrCodeValidationError
	case errors.Is(err, pdns.ErrConflict):
		return http.StatusConflict, ErrCodeConflict
	case errors.Is(err, pdns.ErrUnauthorized):
		return http.StatusBadGateway, ErrCodeUpstreamAuthError
	case errors.Is(err, pdns.ErrLuaUpdatesDisabled):
		return http.StatusBadRequest, ErrCodeLuaUpdatesDisabled
	default:
		return http.StatusInternalServerError, ErrCodeInternalError
	}
}

// writeServiceAuthzError maps the service layer's authorization errors to
// HTTP responses: a genuine denial (dnsops.ErrForbidden) is a 403, and a
// failed authorization lookup (dnsops.StageError with StageZoneAccess — a
// database fault, fail-closed) is a distinguishable 500. authzLabel is the
// message label used for the 500 ("failed to load zone access" on list
// endpoints, "zone access check failed" on zone-scoped endpoints).
//
// Returns true when the error was handled and the response written.
func (h *Handler) writeServiceAuthzError(w http.ResponseWriter, r *http.Request, err error, authzLabel string) bool {
	if errors.Is(err, dnsops.ErrForbidden) {
		writeAPIError(w, http.StatusForbidden, ErrCodeForbidden, "forbidden")
		return true
	}
	var se *dnsops.StageError
	if errors.As(err, &se) && se.Stage == dnsops.StageZoneAccess {
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeInternalError, authzLabel, err)
		return true
	}
	return false
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
	zones, err := h.Ops.ListZones(r.Context(), middleware.GetUser(r))
	if err != nil {
		// A failed zone-access lookup is a database fault, not an empty
		// result: returning 200 with [] would present an outage as "you
		// have no zones". Fail closed WITH a visible error — no zone is
		// ever disclosed either way.
		if h.writeServiceAuthzError(w, r, err, "failed to load zone access") {
			return
		}
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to list zones", err)
		return
	}
	if zones == nil {
		zones = []models.Zone{}
	}
	writeJSON(w, http.StatusOK, zones)
}

// APIGetZone returns a single zone by zone_id as JSON (GET /api/v1/zones/{zone_id}).
func (h *Handler) APIGetZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	zone, err := h.Ops.GetZone(r.Context(), middleware.GetUser(r), zoneID)
	if err != nil {
		if h.writeServiceAuthzError(w, r, err, "zone access check failed") {
			return
		}
		status, code := pdnsErrorStatus(err, ErrCodeZoneNotFound)
		// The label must follow the status: a 500 that answers "zone not
		// found" tells the client to delete/recreate a zone that exists.
		label := "failed to load zone"
		if status == http.StatusNotFound {
			label = "zone not found"
		}
		h.writeAPIErrorWithCause(w, r, status, code, label, err)
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

	req, err := dnsops.ValidateZoneCreate(req)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	zone, err := h.Ops.CreateZone(r.Context(), middleware.GetUser(r), req, dnsops.SourceAPI)
	if err != nil {
		if h.writeServiceAuthzError(w, r, err, "zone access check failed") {
			return
		}
		status, code := pdnsErrorStatus(err, ErrCodeZoneCreateError)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to create zone", err)
		return
	}

	writeJSON(w, http.StatusCreated, zone)
}

// APIDeleteZone deletes a zone by zone_id (DELETE /api/v1/zones/{zone_id}).
func (h *Handler) APIDeleteZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	if err := h.Ops.DeleteZone(r.Context(), middleware.GetUser(r), zoneID, dnsops.SourceAPI); err != nil {
		if h.writeServiceAuthzError(w, r, err, "zone access check failed") {
			return
		}
		status, code := pdnsErrorStatus(err, ErrCodeZoneNotFound)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to delete zone", err)
		return
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

	records, err := h.Ops.ListRecords(r.Context(), middleware.GetUser(r), zoneID, name, rrType)
	if err != nil {
		if h.writeServiceAuthzError(w, r, err, "zone access check failed") {
			return
		}
		status, code := pdnsErrorStatus(err, ErrCodeRecordNotFound)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to list records", err)
		return
	}
	if records == nil {
		records = []models.RRSet{}
	}
	writeJSON(w, http.StatusOK, records)
}

// validateAPIRecordSet validates and canonicalises an RRSet from an API request,
// without normalising record content (priority embedding / quoting / trailing
// dots). APICreateRecord uses it before the service merges the new records
// into an existing RRSet: content normalization must run AFTER the merge so
// each record keeps its original priority in the Priority field until the
// single final prepareRecordContent pass (prepareRecordContent is not
// idempotent for MX/SRV — a second pass would strip the embedded priority and
// re-embed the now-zeroed Priority field). See dnsops.ValidateRecordSet.
func validateAPIRecordSet(rrset *models.RRSet, zoneID string) error {
	return dnsops.ValidateRecordSet(rrset, zoneID)
}

// prepareAPIRecordSet validates the RRSet fields and canonicalizes the type
// (uppercase), the name and each record's content (priority embedding /
// quoting / trailing dots) in one pass. APIUpdateRecord uses it before the
// service replaces the RRSet — a plain REPLACE has no merge, so content
// normalization can run immediately. See dnsops.PrepareValidatedRecordSet.
func prepareAPIRecordSet(rrset *models.RRSet, zoneID string) error {
	return dnsops.PrepareValidatedRecordSet(rrset, zoneID)
}

// APICreateRecord creates a record (RRSet) in a zone from a JSON body (POST /api/v1/zones/{zone_id}/records).
//
// Expects a models.RRSet payload. POST appends to an existing RRSet (preserving
// sibling records) rather than replacing it, matching the web UI and REST
// POST=append semantics; PUT /records remains the explicit REPLACE operation.
// For MX/SRV, the priority is taken from each record's "priority" field and
// embedded into the content for PowerDNS. Returns HTTP 201 on success.
func (h *Handler) APICreateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")

	var rrset models.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rrset); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeInvalidJSON, "invalid JSON body")
		return
	}

	if err := validateAPIRecordSet(&rrset, zoneID); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}

	if err := h.Ops.CreateRecord(r.Context(), middleware.GetUser(r), zoneID, rrset, dnsops.SourceAPI); err != nil {
		if h.writeServiceAuthzError(w, r, err, "zone access check failed") {
			return
		}
		// The fetch stage of the service merge maps a missing zone to 404
		// ZONE_NOT_FOUND (the fetch fails before anything was created, and
		// the caller can act on the zone); the PATCH stage maps to
		// RECORD_ERROR like every record write.
		var se *dnsops.StageError
		if errors.As(err, &se) && se.Stage == dnsops.StageFetch {
			status, code := pdnsErrorStatus(se.Err, ErrCodeZoneNotFound)
			label := "failed to fetch existing records"
			if status == http.StatusNotFound {
				label = "zone not found"
			}
			h.writeAPIErrorWithCause(w, r, status, code, label, err)
			return
		}
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

	if err := h.Ops.UpdateRecord(r.Context(), middleware.GetUser(r), zoneID, req.RRSet, dnsops.SourceAPI); err != nil {
		if h.writeServiceAuthzError(w, r, err, "zone access check failed") {
			return
		}
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

	req.Type = canonicalRecordType(req.Type)
	if err := validators.ValidateRecordType(req.Type); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}
	if err := validators.ValidateRecordName(req.Name); err != nil {
		writeAPIError(w, http.StatusBadRequest, ErrCodeValidationError, err.Error())
		return
	}
	req.Name = normalizeRecordName(req.Name, zoneID)

	if err := h.Ops.DeleteRecord(r.Context(), middleware.GetUser(r), zoneID, req.Name, req.Type, dnsops.SourceAPI); err != nil {
		if h.writeServiceAuthzError(w, r, err, "zone access check failed") {
			return
		}
		status, code := pdnsErrorStatus(err, ErrCodeRecordError)
		h.writeAPIErrorWithCause(w, r, status, code, "failed to delete record", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "record deleted"})
}

// APIStats returns PowerDNS server statistics combined with the zone count (GET /api/v1/stats).
func (h *Handler) APIStats(w http.ResponseWriter, r *http.Request) {
	stats, zoneCount, err := h.Ops.Stats(r.Context(), middleware.GetUser(r))
	if err != nil {
		// The service tags which composite stage failed; the REST mapping
		// differs per stage (a failed statistics call is STATS_ERROR, a raw
		// upstream zone-list failure falls through pdnsErrorStatus to
		// INTERNAL_ERROR, and a failed zone-access lookup is INTERNAL_ERROR
		// without any stats body). A failed zone list must not surface as
		// zone_count: 0 — a caller would read an empty tenant instead of an
		// outage.
		var se *dnsops.StageError
		if errors.As(err, &se) {
			switch se.Stage {
			case dnsops.StageStatistics:
				h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeStatsError, "failed to get statistics", err)
				return
			case dnsops.StageZoneList:
				status, code := pdnsErrorStatus(se.Err, ErrCodeStatsError)
				h.writeAPIErrorWithCause(w, r, status, code, "failed to list zones", err)
				return
			default:
				h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to load zone access", err)
				return
			}
		}
		h.writeAPIErrorWithCause(w, r, http.StatusInternalServerError, ErrCodeStatsError, "failed to get statistics", err)
		return
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

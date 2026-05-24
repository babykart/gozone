package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// -- Zone API ---

// APIListZones returns all PowerDNS zones as a JSON array (GET /api/v1/zones).
func (h *Handler) APIListZones(w http.ResponseWriter, r *http.Request) {
	zones, err := h.PDNS.ListZones()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
	zone, err := h.PDNS.GetZone(zoneID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if err := validators.ValidateDomainName(req.Name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid zone name: " + err.Error()})
		return
	}

	zone, err := h.PDNS.CreateZone(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, zone)
}

// APIDeleteZone deletes a zone by zone_id (DELETE /api/v1/zones/{zone_id}).
func (h *Handler) APIDeleteZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	if err := h.PDNS.DeleteZone(zoneID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if err := validators.ValidateRecordType(rrset.Type); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid record type: " + err.Error()})
		return
	}

	if err := h.PDNS.CreateRecord(zoneID, rrset); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if err := validators.ValidateRecordType(rrset.Type); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid record type: " + err.Error()})
		return
	}

	if err := h.PDNS.UpdateRecord(zoneID, rrset); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if err := validators.ValidateRecordType(req.Type); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid record type: " + err.Error()})
		return
	}

	if err := h.PDNS.DeleteRecord(zoneID, req.Name, req.Type); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "record deleted"})
}

// APIStats returns PowerDNS server statistics combined with the zone count (GET /api/v1/stats).
func (h *Handler) APIStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.PDNS.GetStatistics()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	zones, _ := h.PDNS.ListZones()
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
	json.NewEncoder(w).Encode(data)
}

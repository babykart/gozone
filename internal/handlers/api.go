package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/babykart/gozone/internal/models"
)

// --- Zone API ---

// APIListZones returns all zones as JSON.
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

// APIGetZone returns a single zone as JSON.
func (h *Handler) APIGetZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	zone, err := h.PDNS.GetZone(zoneID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, zone)
}

// APICreateZone creates a zone from JSON body.
func (h *Handler) APICreateZone(w http.ResponseWriter, r *http.Request) {
	var req models.ZoneCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	zone, err := h.PDNS.CreateZone(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, zone)
}

// APIDeleteZone deletes a zone.
func (h *Handler) APIDeleteZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	if err := h.PDNS.DeleteZone(zoneID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "zone deleted"})
}

// --- Record API ---

// APIListRecords returns all records for a zone.
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

// APICreateRecord creates a record in a zone.
func (h *Handler) APICreateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	var rrset models.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rrset); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if err := h.PDNS.CreateRecord(zoneID, rrset); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "record created"})
}

// APIUpdateRecord updates a record in a zone.
func (h *Handler) APIUpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	var rrset models.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rrset); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if err := h.PDNS.UpdateRecord(zoneID, rrset); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "record updated"})
}

// APIDeleteRecord deletes a record from a zone.
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

	if err := h.PDNS.DeleteRecord(zoneID, req.Name, req.Type); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "record deleted"})
}

// APIStats returns server statistics.
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

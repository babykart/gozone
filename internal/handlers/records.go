package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// CreateRecordPage renders the record creation form for a zone (GET /zones/{zone_id}/records/new).
func (h *Handler) CreateRecordPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	zone, err := h.PDNS.GetZone(zoneID)
	if err != nil {
		h.renderError(w, "Zone not found")
		return
	}

	data := map[string]interface{}{
		"Title":       "Add Record - " + zone.Name + " - GoZone",
		"User":        user,
		"Zone":        zone,
		"RecordTypes": GetRecordTypes(),
	}
	h.render(w, "record_create.html", data)
}

// CreateRecord creates a DNS record in a zone from form data (POST /zones/{zone_id}/records/create).
//
// Accepts name, type, content, ttl, and priority form values. Defaults TTL to 3600.
func (h *Handler) CreateRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	recordType := strings.TrimSpace(r.FormValue("type"))
	content := strings.TrimSpace(r.FormValue("content"))
	ttlStr := strings.TrimSpace(r.FormValue("ttl"))
	priorityStr := strings.TrimSpace(r.FormValue("priority"))

	ttl, err := strconv.Atoi(ttlStr)
	if err != nil || ttl <= 0 {
		ttl = 3600
	}

	priority := 0
	if priorityStr != "" {
		priority, _ = strconv.Atoi(priorityStr)
	}

	if name == "" || recordType == "" || content == "" {
		http.Redirect(w, r, "/zones/"+zoneID+"/records/new", http.StatusSeeOther)
		return
	}

	if err := validators.ValidateRecordType(recordType); err != nil {
		h.renderError(w, "Invalid record type: "+err.Error())
		return
	}

	rrset := models.RRSet{
		Name: name,
		Type: recordType,
		TTL:  ttl,
		Records: []models.RecordInfo{
			{
				Content:  content,
				Priority: priority,
				Disabled: false,
			},
		},
	}

	if err := h.PDNS.CreateRecord(zoneID, rrset); err != nil {
		h.renderError(w, "Failed to create record: "+err.Error())
		return
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_record', ?)",
		user.ID, zoneID, fmt.Sprintf("Created %s record %s -> %s", recordType, name, content),
	)

	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// EditRecordPage renders the record edit form (GET /zones/{zone_id}/records/edit?name=...&type=...).
//
// The record to edit is identified by the "name" and "type" query parameters.
func (h *Handler) EditRecordPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")
	recordQuery := r.URL.Query()

	recordName := recordQuery.Get("name")
	recordType := recordQuery.Get("type")

	zone, err := h.PDNS.GetZone(zoneID)
	if err != nil {
		h.renderError(w, "Zone not found")
		return
	}

	records, err := h.PDNS.ListRecords(zoneID)
	if err != nil {
		h.renderError(w, "Failed to fetch records")
		return
	}

	var targetRRSet *models.RRSet
	for _, rr := range records {
		if rr.Name == recordName && rr.Type == recordType {
			targetRRSet = &rr
			break
		}
	}

	if targetRRSet == nil {
		h.renderError(w, "Record not found")
		return
	}

	data := map[string]interface{}{
		"Title":       "Edit Record - " + zone.Name + " - GoZone",
		"User":        user,
		"Zone":        zone,
		"Record":      targetRRSet,
		"RecordTypes": GetRecordTypes(),
	}
	h.render(w, "record_edit.html", data)
}

// UpdateRecord replaces a DNS record in a zone from form data (POST /zones/{zone_id}/records/update).
//
// Uses the REPLACE changetype to ensure idempotent updates. Accepts name, type,
// content, ttl, priority, and disabled form values.
func (h *Handler) UpdateRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	recordType := strings.TrimSpace(r.FormValue("type"))
	content := strings.TrimSpace(r.FormValue("content"))
	ttlStr := strings.TrimSpace(r.FormValue("ttl"))
	priorityStr := strings.TrimSpace(r.FormValue("priority"))
	disabled := r.FormValue("disabled") == "on"

	ttl, err := strconv.Atoi(ttlStr)
	if err != nil || ttl <= 0 {
		ttl = 3600
	}

	priority := 0
	if priorityStr != "" {
		priority, _ = strconv.Atoi(priorityStr)
	}

	if err := validators.ValidateRecordType(recordType); err != nil {
		h.renderError(w, "Invalid record type: "+err.Error())
		return
	}

	rrset := models.RRSet{
		Name: name,
		Type: recordType,
		TTL:  ttl,
		Records: []models.RecordInfo{
			{
				Content:  content,
				Priority: priority,
				Disabled: disabled,
			},
		},
	}

	if err := h.PDNS.UpdateRecord(zoneID, rrset); err != nil {
		h.renderError(w, "Failed to update record: "+err.Error())
		return
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'update_record', ?)",
		user.ID, zoneID, fmt.Sprintf("Updated %s record %s", recordType, name),
	)

	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// DeleteRecord deletes a DNS record from a zone (POST /zones/{zone_id}/records/delete).
//
// Identifies the record by "name" and "type" form values.
func (h *Handler) DeleteRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
		return
	}

	recordName := r.FormValue("name")
	recordType := r.FormValue("type")

	if err := h.PDNS.DeleteRecord(zoneID, recordName, recordType); err != nil {
		h.renderError(w, "Failed to delete record: "+err.Error())
		return
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'delete_record', ?)",
		user.ID, zoneID, fmt.Sprintf("Deleted %s record %s", recordType, recordName),
	)

	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/logger"
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
		h.renderError(w, r, "Zone not found")
		return
	}

	data := map[string]interface{}{
		"Title":       "Add Record - " + zone.Name + " - GoZone",
		"User":        user,
		"Zone":        zone,
		"RecordTypes": GetRecordTypes(),
	}
	h.render(w, r, "record_create.html", data)
}

// CreateRecord creates a DNS record in a zone from form data (POST /zones/{zone_id}/records/create).
//
// Accepts name, type, content, ttl, and priority form values. Defaults TTL to 3600.
func (h *Handler) CreateRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if r.Method != http.MethodPost {
		// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
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
		// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
		http.Redirect(w, r, "/zones/"+zoneID+"/records/new", http.StatusSeeOther)
		return
	}

	if err := validators.ValidateRecordType(recordType); err != nil {
		h.renderError(w, r, "Invalid record type: "+err.Error())
		return
	}

	if err := validators.ValidateRecordContent(recordType, content); err != nil {
		h.renderError(w, r, "Invalid record content: "+err.Error())
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
		h.renderError(w, r, "Failed to create record: "+err.Error())
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_record', ?)",
		user.ID, zoneID, fmt.Sprintf("Created %s record %s -> %s", recordType, name, content),
	); err != nil {
		logger.Error("failed to log create_record activity", "zone_id", zoneID, "error", err)
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
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
		h.renderError(w, r, "Zone not found")
		return
	}

	records, err := h.PDNS.ListRecords(zoneID)
	if err != nil {
		h.renderError(w, r, "Failed to fetch records")
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
		h.renderError(w, r, "Record not found")
		return
	}

	data := map[string]interface{}{
		"Title":       "Edit Record - " + zone.Name + " - GoZone",
		"User":        user,
		"Zone":        zone,
		"Record":      targetRRSet,
		"RecordTypes": GetRecordTypes(),
	}
	h.render(w, r, "record_edit.html", data)
}

// UpdateRecord replaces a DNS record in a zone from form data (POST /zones/{zone_id}/records/update).
//
// Uses the REPLACE changetype to ensure idempotent updates. Accepts name, type,
// content, ttl, priority, and disabled form values.
func (h *Handler) UpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")

	if r.Method != http.MethodPost {
		// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
		http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
		return
	}

	name, recordType, content, ttl, priority, disabled, err := parseRecordForm(r)
	if err != nil {
		h.renderError(w, r, err.Error())
		return
	}
	if name == "" || recordType == "" || content == "" {
		h.renderError(w, r, "Name, type, and content are required")
		return
	}

	if err := validators.ValidateRecordType(recordType); err != nil {
		h.renderError(w, r, "Invalid record type: "+err.Error())
		return
	}

	if err := validators.ValidateRecordContent(recordType, content); err != nil {
		h.renderError(w, r, "Invalid record content: "+err.Error())
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
		h.renderError(w, r, "Failed to update record: "+err.Error())
		return
	}

	user := middleware.GetUser(r)
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'update_record', ?)",
		user.ID, zoneID, fmt.Sprintf("Updated %s record %s", recordType, name),
	); err != nil {
		logger.Error("failed to log update_record activity", "zone_id", zoneID, "error", err)
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// InlineUpdateRecord updates a record via AJAX and returns JSON (POST /zones/{zone_id}/records/inline-update).
func (h *Handler) InlineUpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")

	name, recordType, content, ttl, priority, disabled, err := parseRecordForm(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if name == "" || recordType == "" || content == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Name, type, and content are required"})
		return
	}

	if err := validators.ValidateRecordType(recordType); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid record type: " + err.Error()})
		return
	}

	if err := validators.ValidateRecordContent(recordType, content); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid record content: " + err.Error()})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
		return
	}

	user := middleware.GetUser(r)
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'update_record', ?)",
		user.ID, zoneID, fmt.Sprintf("Updated %s record %s", recordType, name),
	); err != nil {
		logger.Error("failed to log update_record activity", "zone_id", zoneID, "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"record":  rrset,
	})
}

// BatchCreateRecords creates multiple DNS records in a zone (POST /zones/{zone_id}/records/batch-create).
func (h *Handler) BatchCreateRecords(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if err := r.ParseForm(); err != nil {
		// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
		http.Redirect(w, r, "/zones/"+zoneID+"/records/new", http.StatusSeeOther)
		return
	}

	names := r.PostForm["name"]
	types := r.PostForm["type"]
	contents := r.PostForm["content"]

	if len(names) == 0 || len(types) == 0 || len(contents) == 0 {
		h.renderError(w, r, "At least one record is required")
		return
	}

	var rrsets []models.RRSet
	for i := 0; i < len(names); i++ {
		name := strings.TrimSpace(names[i])
		recordType := strings.TrimSpace(types[i])
		content := strings.TrimSpace(contents[i])

		if name == "" || recordType == "" || content == "" {
			continue
		}

		ttl := 3600
		priority := 0

		if err := validators.ValidateRecordType(recordType); err != nil {
			h.renderError(w, r, "Invalid record type '"+recordType+"': "+err.Error())
			return
		}
		if err := validators.ValidateRecordContent(recordType, content); err != nil {
			h.renderError(w, r, "Invalid record content: "+err.Error())
			return
		}

		rrsets = append(rrsets, models.RRSet{
			Name: name,
			Type: recordType,
			TTL:  ttl,
			Records: []models.RecordInfo{
				{Content: content, Priority: priority, Disabled: false},
			},
		})

		if _, err := h.DB.Exec(
			"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_record', ?)",
			user.ID, zoneID, fmt.Sprintf("Created %s record %s -> %s", recordType, name, content),
		); err != nil {
			logger.Error("failed to log create_record activity", "zone_id", zoneID, "error", err)
		}
	}

	if len(rrsets) == 0 {
		h.renderError(w, r, "No valid records to create")
		return
	}

	if err := h.PDNS.CreateRecords(zoneID, rrsets); err != nil {
		h.renderError(w, r, "Failed to create records: "+err.Error())
		return
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

func parseRecordForm(r *http.Request) (name, recordType, content string, ttl, priority int, disabled bool, err error) {
	name = strings.TrimSpace(r.FormValue("name"))
	recordType = strings.TrimSpace(r.FormValue("type"))
	content = strings.TrimSpace(r.FormValue("content"))
	ttlStr := strings.TrimSpace(r.FormValue("ttl"))
	priorityStr := strings.TrimSpace(r.FormValue("priority"))
	disabled = r.FormValue("disabled") == "on" || r.FormValue("disabled") == "true"

	ttl, err = strconv.Atoi(ttlStr)
	if err != nil || ttl <= 0 {
		ttl = 3600
		err = nil
	}

	priority = 0
	if priorityStr != "" {
		priority, _ = strconv.Atoi(priorityStr)
	}
	return
}

// DeleteRecord deletes a DNS record from a zone (POST /zones/{zone_id}/records/delete).
//
// Identifies the record by "name" and "type" form values.
func (h *Handler) DeleteRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if r.Method != http.MethodPost {
		// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
		http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
		return
	}

	recordName := r.FormValue("name")
	recordType := r.FormValue("type")

	if err := h.PDNS.DeleteRecord(zoneID, recordName, recordType); err != nil {
		h.renderError(w, r, "Failed to delete record: "+err.Error())
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'delete_record', ?)",
		user.ID, zoneID, fmt.Sprintf("Deleted %s record %s", recordType, recordName),
	); err != nil {
		logger.Error("failed to log delete_record activity", "zone_id", zoneID, "error", err)
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

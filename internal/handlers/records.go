package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// CreateRecordPage displays the record creation form.
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

// CreateRecord handles record creation.
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

// EditRecordPage displays the record edit form.
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

// UpdateRecord handles record updates.
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

// DeleteRecord handles record deletion.
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

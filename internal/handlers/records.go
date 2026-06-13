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

	zone, err := h.PDNS.GetZone(r.Context(), zoneID)
	if err != nil {
		h.renderErrorStatus(w, r, http.StatusNotFound, "Zone not found")
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
// Merges into existing RRSet when name+type matches, preserving sibling records.
func (h *Handler) CreateRecord(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

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

	name = normalizeRecordName(name, zoneID)

	if err := validators.ValidateRecordName(name); err != nil {
		h.renderError(w, r, "Invalid record name: "+err.Error())
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

	allRecords, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch existing records", err)
		return
	}

	var existingRRSet *models.RRSet
	for _, rr := range allRecords {
		if rr.Name == name && rr.Type == recordType {
			existingRRSet = &rr
			break
		}
	}

	var records []models.RecordInfo
	newRecord := models.RecordInfo{Content: content, Priority: priority, Disabled: false}
	if existingRRSet != nil {
		records = mergeRecordIntoRRSet(existingRRSet.Records, "", 0, newRecord)
	} else {
		records = []models.RecordInfo{newRecord}
	}

	for i := range records {
		records[i].Content, records[i].Priority =
			prepareRecordContent(recordType, records[i].Content, records[i].Priority)
	}

	rrset := models.RRSet{
		Name:    name,
		Type:    recordType,
		TTL:     ttl,
		Records: records,
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, rrset); err != nil {
		h.renderInternalError(w, r, "Failed to create record", err)
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

	zone, err := h.PDNS.GetZone(r.Context(), zoneID)
	if err != nil {
		h.renderErrorStatus(w, r, http.StatusNotFound, "Zone not found")
		return
	}

	records, err := h.PDNS.ListRecords(r.Context(), zoneID)
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
		h.renderErrorStatus(w, r, http.StatusNotFound, "Record not found")
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
// Fetches the existing RRSet from PDNS, merges the edited record identified by
// original_content + original_priority, and sends the complete RRSet with REPLACE
// to preserve any sibling records.
func (h *Handler) UpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")

	name, recordType, content, ttl, priority, disabled, err := parseRecordForm(r)
	if err != nil {
		h.renderInternalError(w, r, "Invalid record form", err)
		return
	}
	if name == "" || recordType == "" || content == "" {
		h.renderError(w, r, "Name, type, and content are required")
		return
	}

	originalContent := strings.TrimSpace(r.FormValue("original_content"))
	originalPriority, _ := strconv.Atoi(r.FormValue("original_priority"))

	name = normalizeRecordName(name, zoneID)

	if err := validators.ValidateRecordName(name); err != nil {
		h.renderError(w, r, "Invalid record name: "+err.Error())
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

	allRecords, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch existing records", err)
		return
	}

	var existingRRSet *models.RRSet
	for _, rr := range allRecords {
		if rr.Name == name && rr.Type == recordType {
			existingRRSet = &rr
			break
		}
	}

	var updatedRecords []models.RecordInfo
	if existingRRSet != nil {
		updatedRecords = mergeRecordIntoRRSet(existingRRSet.Records, originalContent, originalPriority,
			models.RecordInfo{Content: content, Priority: priority, Disabled: disabled})
	} else {
		updatedRecords = []models.RecordInfo{{Content: content, Priority: priority, Disabled: disabled}}
	}

	for i := range updatedRecords {
		updatedRecords[i].Content, updatedRecords[i].Priority =
			prepareRecordContent(recordType, updatedRecords[i].Content, updatedRecords[i].Priority)
	}

	rrset := models.RRSet{
		Name:    name,
		Type:    recordType,
		TTL:     ttl,
		Records: updatedRecords,
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, rrset); err != nil {
		h.renderInternalError(w, r, "Failed to update record", err)
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
//
// Fetches the existing RRSet from PDNS, merges the edited record identified by
// original_content + original_priority, and sends the complete RRSet with REPLACE
// to preserve any sibling records.
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

	originalContent := strings.TrimSpace(r.FormValue("original_content"))
	originalPriority, _ := strconv.Atoi(r.FormValue("original_priority"))

	name = normalizeRecordName(name, zoneID)

	if err := validators.ValidateRecordName(name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid record name: " + err.Error()})
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

	allRecords, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch existing records"})
		return
	}

	var existingRRSet *models.RRSet
	for _, rr := range allRecords {
		if rr.Name == name && rr.Type == recordType {
			existingRRSet = &rr
			break
		}
	}

	var updatedRecords []models.RecordInfo
	if existingRRSet != nil {
		updatedRecords = mergeRecordIntoRRSet(existingRRSet.Records, originalContent, originalPriority,
			models.RecordInfo{Content: content, Priority: priority, Disabled: disabled})
	} else {
		updatedRecords = []models.RecordInfo{{Content: content, Priority: priority, Disabled: disabled}}
	}

	for i := range updatedRecords {
		updatedRecords[i].Content, updatedRecords[i].Priority =
			prepareRecordContent(recordType, updatedRecords[i].Content, updatedRecords[i].Priority)
	}

	rrset := models.RRSet{
		Name:    name,
		Type:    recordType,
		TTL:     ttl,
		Records: updatedRecords,
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, rrset); err != nil {
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
	ttls := r.PostForm["ttl"]
	priorities := r.PostForm["priority"]

	if len(names) == 0 || len(types) == 0 || len(contents) == 0 {
		h.renderError(w, r, "At least one record is required")
		return
	}

	type logEntry struct {
		recordType string
		name       string
		content    string
	}

	// name/type/content are parallel form arrays; iterate only over indices
	// present in all three so a mismatched POST can't index out of range.
	count := min(len(names), len(types), len(contents))

	var rrsets []models.RRSet
	var logEntries []logEntry
	for i := 0; i < count; i++ {
		name := strings.TrimSpace(names[i])
		recordType := strings.TrimSpace(types[i])
		content := strings.TrimSpace(contents[i])

		if name == "" || recordType == "" || content == "" {
			continue
		}

		name = normalizeRecordName(name, zoneID)

		if err := validators.ValidateRecordName(name); err != nil {
			h.renderError(w, r, "Invalid record name '"+name+"': "+err.Error())
			return
		}

		ttl := 3600
		if i < len(ttls) {
			if t, err := strconv.Atoi(strings.TrimSpace(ttls[i])); err == nil && t > 0 {
				ttl = t
			}
		}
		priority := 0
		if i < len(priorities) {
			if p, err := strconv.Atoi(strings.TrimSpace(priorities[i])); err == nil && p > 0 {
				priority = p
			}
		}

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
		logEntries = append(logEntries, logEntry{recordType, name, content})
	}

	if len(rrsets) == 0 {
		h.renderError(w, r, "No valid records to create")
		return
	}

	// Fetch existing RRSets to merge new records into
	existing, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch existing records", err)
		return
	}
	existingMap := make(map[string]*models.RRSet)
	for i := range existing {
		existingMap[existing[i].Name+"|"+existing[i].Type] = &existing[i]
	}

	// Group new records by name+type, merging into existing RRSets
	mergedMap := make(map[string]*models.RRSet)
	for _, newRR := range rrsets {
		key := newRR.Name + "|" + newRR.Type
		if ex, ok := existingMap[key]; ok {
			if m, seen := mergedMap[key]; seen {
				m.Records = append(m.Records, newRR.Records...)
			} else {
				clone := *ex
				for _, nr := range newRR.Records {
					clone.Records = mergeRecordIntoRRSet(clone.Records, "", 0, nr)
				}
				clone.TTL = newRR.TTL
				mergedMap[key] = &clone
			}
		} else {
			if m, seen := mergedMap[key]; seen {
				m.Records = append(m.Records, newRR.Records...)
			} else {
				mergedMap[key] = &newRR
			}
		}
	}

	var merged []models.RRSet
	for _, rr := range mergedMap {
		for i := range rr.Records {
			rr.Records[i].Content, rr.Records[i].Priority =
				prepareRecordContent(rr.Type, rr.Records[i].Content, rr.Records[i].Priority)
		}
		merged = append(merged, *rr)
	}

	if err := h.PDNS.CreateRecords(r.Context(), zoneID, merged); err != nil {
		h.renderInternalError(w, r, "Failed to create records", err)
		return
	}

	for _, e := range logEntries {
		if _, err := h.DB.Exec(
			"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_record', ?)",
			user.ID, zoneID, fmt.Sprintf("Created %s record %s -> %s", e.recordType, e.name, e.content),
		); err != nil {
			logger.Error("failed to log create_record activity", "zone_id", zoneID, "error", err)
		}
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// prepareRecordContent normalises record content for the PDNS PATCH API,
// returning the wire content and the value to store in RecordInfo.Priority.
// MX/SRV priority is embedded in the content (and the separate Priority element
// cleared, since PDNS rejects it); TXT/SPF content is quoted. See the codec in
// internal/models for the per-type rules.
func prepareRecordContent(recordType, content string, priority int) (string, int) {
	switch {
	case models.TypeHasPriority(recordType):
		return models.JoinPriority(recordType, priority, content), 0
	case models.TypeIsQuoted(recordType):
		return models.QuoteContent(recordType, content), priority
	default:
		return content, priority
	}
}

// mergeRecordIntoRRSet replaces the record matching originalContent+originalPriority
// with replacement. If no match is found, replacement is appended.
func mergeRecordIntoRRSet(existing []models.RecordInfo, originalContent string, originalPriority int, replacement models.RecordInfo) []models.RecordInfo {
	result := make([]models.RecordInfo, len(existing))
	copy(result, existing)
	for i, r := range result {
		if r.Content == originalContent && r.Priority == originalPriority {
			result[i] = replacement
			return result
		}
	}
	result = append(result, replacement)
	return result
}

// normalizeRecordName ensures a user-supplied record name is fully qualified
// with trailing dot for the PDNS PATCH API. PDNS requires canonical names
// (e.g., "www.example.com."). Names without trailing dot are treated as
// relative to the zone. "@" is mapped to the zone name.
func normalizeRecordName(name, zoneName string) string {
	name = strings.TrimSpace(name)
	zone := zoneName
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	root := strings.TrimSuffix(zone, ".")
	if name == "@" || name == "" {
		return zone
	}
	// Already fully qualified (ends with dot)
	if strings.HasSuffix(name, ".") {
		if strings.EqualFold(name, zone) {
			return zone
		}
		return name
	}
	// Just the zone root (e.g., "example.com")
	if strings.EqualFold(name, root) {
		return zone
	}
	// Ends with zone suffix without trailing dot (e.g., "www.example.com")
	if strings.HasSuffix(name, "."+root) {
		return name + "."
	}
	// Bare name — append zone with dot (e.g., "www" -> "www.example.com.")
	return name + "." + zone
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

	recordName := r.FormValue("name")
	recordType := r.FormValue("type")

	if err := h.PDNS.DeleteRecord(r.Context(), zoneID, recordName, recordType); err != nil {
		h.renderInternalError(w, r, "Failed to delete record", err)
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

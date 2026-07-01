package handlers

import (
	"encoding/json"
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
		"Title":       "Add Record - " + zone.Name + " - " + h.Cfg.Server.AppName,
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
	comment := r.FormValue("comment")
	commentClear := r.FormValue("comment_clear") == "1" || r.FormValue("comment_clear") == "true"

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
		Name:     name,
		Type:     recordType,
		TTL:      ttl,
		Records:  records,
		Comments: buildCommentPatch(comment, commentClear),
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, rrset); err != nil {
		h.renderInternalError(w, r, "Failed to create record", err)
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details, old_value, new_value) VALUES (?, ?, 'create_record', ?, ?, ?)",
		user.ID, zoneID, fmt.Sprintf("Created %s record %s -> %s", recordType, name, content),
		rrsetSnapshot(existingRRSet), rrsetSnapshot(&rrset),
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
		"Title":       "Edit Record - " + zone.Name + " - " + h.Cfg.Server.AppName,
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

	rrset, oldRRSet, err := h.updateRecordFromForm(r)
	if err != nil {
		switch e := err.(type) {
		case *recordValidationError:
			h.renderError(w, r, e.Message)
		default:
			h.renderInternalError(w, r, "Failed to update record", err)
		}
		return
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, *rrset); err != nil {
		h.renderInternalError(w, r, "Failed to update record", err)
		return
	}

	user := middleware.GetUser(r)
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details, old_value, new_value) VALUES (?, ?, 'update_record', ?, ?, ?)",
		user.ID, zoneID, fmt.Sprintf("Updated %s record %s", rrset.Type, rrset.Name),
		rrsetSnapshot(oldRRSet), rrsetSnapshot(rrset),
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

	rrset, oldRRSet, err := h.updateRecordFromForm(r)
	if err != nil {
		switch e := err.(type) {
		case *recordValidationError:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": e.Message})
		default:
			logger.Error("InlineUpdateRecord: failed to build update", "zone_id", zoneID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
		}
		return
	}

	if err := h.PDNS.UpdateRecord(r.Context(), zoneID, *rrset); err != nil {
		logger.Error("InlineUpdateRecord: UpdateRecord failed", "zone_id", zoneID, "name", rrset.Name, "type", rrset.Type, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update record"})
		return
	}

	user := middleware.GetUser(r)
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details, old_value, new_value) VALUES (?, ?, 'update_record', ?, ?, ?)",
		user.ID, zoneID, fmt.Sprintf("Updated %s record %s", rrset.Type, rrset.Name),
		rrsetSnapshot(oldRRSet), rrsetSnapshot(rrset),
	); err != nil {
		logger.Error("failed to log update_record activity", "zone_id", zoneID, "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"record":  rrset,
	})
}

// recordValidationError marks an input validation failure so callers can
// choose the appropriate response format (HTML page vs JSON).
type recordValidationError struct {
	Message string
}

func (e *recordValidationError) Error() string { return e.Message }

// updateRecordFromForm parses and validates a record update request, builds the
// merged RRSet and returns it along with the original RRSet (if any). It is
// shared by UpdateRecord and InlineUpdateRecord.
func (h *Handler) updateRecordFromForm(r *http.Request) (*models.RRSet, *models.RRSet, error) {
	zoneID := r.PathValue("zone_id")

	name, recordType, content, ttl, priority, disabled, err := parseRecordForm(r)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid record form: %w", err)
	}
	if name == "" || recordType == "" || content == "" {
		return nil, nil, &recordValidationError{Message: "Name, type, and content are required"}
	}

	originalContent := strings.TrimSpace(r.FormValue("original_content"))
	originalPriority, _ := strconv.Atoi(r.FormValue("original_priority"))

	name = normalizeRecordName(name, zoneID)

	if err := validators.ValidateRecordName(name); err != nil {
		return nil, nil, &recordValidationError{Message: "Invalid record name: " + err.Error()}
	}

	if err := validators.ValidateRecordType(recordType); err != nil {
		return nil, nil, &recordValidationError{Message: "Invalid record type: " + err.Error()}
	}

	if err := validators.ValidateRecordContent(recordType, content); err != nil {
		return nil, nil, &recordValidationError{Message: "Invalid record content: " + err.Error()}
	}

	allRecords, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		return nil, nil, err
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

	return &models.RRSet{
		Name:     name,
		Type:     recordType,
		TTL:      ttl,
		Records:  updatedRecords,
		Comments: buildCommentPatch(r.FormValue("comment"), r.FormValue("comment_clear") == "1"),
	}, existingRRSet, nil
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
	comments := r.PostForm["comment"]
	commentClears := r.PostForm["comment_clear"]

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
	// pendingComments collects user-provided comments grouped by name+type so
	// rows that merge into the same RRSet contribute their comments together.
	// Each entry carries the textarea text and an explicit "clear" flag so
	// per-row clear signals survive the merge.
	type pendingComment struct {
		text  string
		clear bool
	}
	pendingComments := make(map[string][]pendingComment)
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

		var rowComment string
		if i < len(comments) {
			rowComment = strings.TrimSpace(comments[i])
		}
		rowCommentClear := false
		if i < len(commentClears) {
			rowCommentClear = commentClears[i] == "1" || commentClears[i] == "true"
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

		key := name + "|" + recordType
		if rowComment != "" || rowCommentClear {
			pendingComments[key] = append(pendingComments[key], pendingComment{text: rowComment, clear: rowCommentClear})
		}
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
	for key, rr := range mergedMap {
		for i := range rr.Records {
			rr.Records[i].Content, rr.Records[i].Priority =
				prepareRecordContent(rr.Type, rr.Records[i].Content, rr.Records[i].Priority)
		}
		// DNS RRs in an RRSet are a set, so drop records that produced
		// identical wire content — e.g. duplicate batch rows, or a new row
		// that duplicates an existing record. PowerDNS rejects duplicates.
		// Comparison is post-normalization (MX/SRV priority is embedded in
		// the content, so targets with different priorities are kept).
		rr.Records = dedupRecordsByContent(rr.Records)
		// Combine all user comments for this name+type into a single text
		// payload so buildCommentsPatch splits them into one Comment per line.
		// PowerDNS PATCH `comments` REPLACES the RRSet's comment list, so we
		// also preserve any existing comments from the cloned RRSet.
		var existing []models.Comment
		if rr.Comments != nil {
			existing = rr.Comments.Items
		}
		if userComments := pendingComments[key]; len(userComments) > 0 {
			lines := make([]string, 0, len(userComments))
			clear := false
			for _, uc := range userComments {
				lines = append(lines, uc.text)
				if uc.clear {
					clear = true
				}
			}
			rr.Comments = buildCommentsPatch(existing, clear, lines...)
		}
		merged = append(merged, *rr)
	}

	if err := h.PDNS.CreateRecords(r.Context(), zoneID, merged); err != nil {
		h.renderInternalError(w, r, "Failed to create records", err)
		return
	}

	for _, e := range logEntries {
		key := e.name + "|" + e.recordType
		if _, err := h.DB.Exec(
			"INSERT INTO activity_logs (user_id, zone_id, action, details, old_value, new_value) VALUES (?, ?, 'create_record', ?, '', ?)",
			user.ID, zoneID, fmt.Sprintf("Created %s record %s -> %s", e.recordType, e.name, e.content),
			rrsetSnapshot(mergedMap[key]),
		); err != nil {
			logger.Error("failed to log create_record activity", "zone_id", zoneID, "error", err)
		}
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// rrsetSnapshot serialises an RRSet to JSON for storage in activity_logs.
// It returns an empty string for a nil RRSet (e.g. create on a new RRSet or
// delete when the RRSet could not be fetched).
func rrsetSnapshot(rrset *models.RRSet) string {
	if rrset == nil {
		return ""
	}
	b, err := json.Marshal(rrset)
	if err != nil {
		return ""
	}
	return string(b)
}

// prepareRecordContent normalises record content for the PDNS PATCH API,
// returning the wire content and the value to store in RecordInfo.Priority.
// MX/SRV priority is embedded in the content (and the separate Priority element
// cleared, since PDNS rejects it); TXT/SPF content is quoted. See the codec in
// internal/models for the per-type rules.
func prepareRecordContent(recordType, content string, priority int) (string, int) {
	switch {
	case models.TypeHasPriority(recordType):
		// MX/SRV: embed priority first, then ensure the FQDN target (the
		// last space-separated field) ends with a trailing dot.
		return models.EnsureTrailingDot(models.JoinPriority(recordType, priority, content)), 0
	case models.TypeIsQuoted(recordType):
		return models.QuoteContent(recordType, content), priority
	case models.TypeIsFQDNTarget(recordType):
		// CNAME/NS/PTR/ALIAS/DNAME/AFSDB/NAPTR: the entire content or the
		// last space-separated field is a DNS name target.
		return models.EnsureTrailingDot(content), priority
	case models.TypeHasFQDNFields(recordType):
		// SOA/RP/MINFO/NSEC: specific fields are FQDNs but not in the last
		// position, so per-field normalisation is required.
		return models.EnsureTrailingDotFields(content, models.FQDNFieldIndices(recordType)), priority
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

// dedupRecordsByContent removes records with identical wire content within an
// RRSet. DNS RRs in an RRSet are a set — duplicates are meaningless and
// PowerDNS rejects them. The first occurrence wins (preserving its Disabled
// flag and priority). Call this after prepareRecordContent so that inputs
// canonicalising to the same content (e.g. a CNAME target with and without a
// trailing dot, or duplicate batch rows) collapse correctly; for MX/SRV the
// priority is embedded in the content, so targets with different priorities
// are kept.
func dedupRecordsByContent(records []models.RecordInfo) []models.RecordInfo {
	if len(records) < 2 {
		return records
	}
	seen := make(map[string]struct{}, len(records))
	out := make([]models.RecordInfo, 0, len(records))
	for _, r := range records {
		if _, ok := seen[r.Content]; ok {
			continue
		}
		seen[r.Content] = struct{}{}
		out = append(out, r)
	}
	return out
}

// buildCommentPatch constructs a *CommentPatch from a multi-line textarea value
// and an explicit clear signal.
//
//   - clear=true                                 -> Clear patch (purge)
//   - clear=false and text has at least one line -> Items patch (replace)
//   - clear=false and text is blank              -> nil (preserve; field omitted)
//
// PowerDNS PATCH semantics: omitting "comments" preserves existing comments,
// while a present-but-empty array purges them.
func buildCommentPatch(text string, clear bool) *models.CommentPatch {
	if clear {
		return &models.CommentPatch{Clear: true}
	}
	var items []models.Comment
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		items = append(items, models.Comment{Content: line})
	}
	if len(items) == 0 {
		return nil
	}
	return &models.CommentPatch{Items: items}
}

// buildCommentsPatch constructs the patch for an RRSet that previously held
// `existing` comments and now gains the given user-provided lines. PowerDNS
// REPLACES the entire comment list when the `comments` field is present, so
// existing comments are echoed back (with deduplication against the new lines)
// unless clear=true (which emits an empty array and purges everything).
//
//   - clear=true                                  -> Clear patch (purge)
//   - clear=false and no new lines                -> nil (preserve; field omitted)
//   - clear=false and at least one new line       -> Items patch (replace)
func buildCommentsPatch(existing []models.Comment, clear bool, newLines ...string) *models.CommentPatch {
	if clear {
		return &models.CommentPatch{Clear: true}
	}
	cleaned := make([]string, 0, len(newLines))
	for _, line := range newLines {
		if line = strings.TrimSpace(line); line != "" {
			cleaned = append(cleaned, line)
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	out := make([]models.Comment, 0, len(existing)+len(cleaned))
	for _, c := range existing {
		out = append(out, c)
	}
	for _, line := range cleaned {
		// Deduplicate against both the preserved existing list and earlier
		// new lines so replaying the same batch never grows the list.
		dup := false
		for _, c := range out {
			if c.Content == line {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		out = append(out, models.Comment{Content: line})
	}
	return &models.CommentPatch{Items: out}
}

// normalizeRecordName ensures a user-supplied record name is fully qualified
// with trailing dot for the PDNS PATCH API. PDNS requires canonical names
// (e.g., "www.example.com."). Names without trailing dot are treated as
// relative to the zone. "@" is mapped to the zone name.
func normalizeRecordName(name, zoneName string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	zone := strings.ToLower(zoneName)
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

	recordName := strings.TrimSpace(r.FormValue("name"))
	recordType := strings.TrimSpace(r.FormValue("type"))

	if recordName == "" || recordType == "" {
		h.renderError(w, r, "Record name and type are required")
		return
	}

	recordName = normalizeRecordName(recordName, zoneID)
	if err := validators.ValidateRecordName(recordName); err != nil {
		h.renderError(w, r, "Invalid record name: "+err.Error())
		return
	}
	if err := validators.ValidateRecordType(recordType); err != nil {
		h.renderError(w, r, "Invalid record type: "+err.Error())
		return
	}

	var oldRRSet *models.RRSet
	allRecords, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err == nil {
		for _, rr := range allRecords {
			if rr.Name == recordName && rr.Type == recordType {
				oldRRSet = &rr
				break
			}
		}
	}

	if err := h.PDNS.DeleteRecord(r.Context(), zoneID, recordName, recordType); err != nil {
		h.renderInternalError(w, r, "Failed to delete record", err)
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details, old_value, new_value) VALUES (?, ?, 'delete_record', ?, ?, '')",
		user.ID, zoneID, fmt.Sprintf("Deleted %s record %s", recordType, recordName),
		rrsetSnapshot(oldRRSet),
	); err != nil {
		logger.Error("failed to log delete_record activity", "zone_id", zoneID, "error", err)
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

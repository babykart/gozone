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

// defaultRecordTTL is applied when a record is created without an explicit
// TTL preference (empty form field) and no existing RRSet TTL can be
// inherited.
const defaultRecordTTL = 3600

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
// Accepts name, type, content, ttl, and priority form values. An empty TTL
// means "no preference": when the record merges into an existing RRSet the
// RRSet's current TTL is kept (adding a sibling record must not silently
// rewrite it), and for a brand-new RRSet the 3600 default applies. An explicit
// TTL is applied as submitted, including on a merge.
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

	// An empty TTL means "no preference" (kept as 0 until resolution below);
	// an explicit non-numeric or non-positive value is rejected so the
	// activity log records what the user actually typed, not a silent
	// substitution.
	ttl := 0
	if ttlStr != "" {
		v, err := strconv.Atoi(ttlStr)
		if err != nil || v <= 0 {
			h.renderError(w, r, "Invalid TTL: must be a positive integer")
			return
		}
		ttl = v
	}

	priority := 0
	if priorityStr != "" {
		v, err := strconv.Atoi(priorityStr)
		if err != nil || v < 0 {
			h.renderError(w, r, "Invalid priority: must be a non-negative integer")
			return
		}
		priority = v
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

	if err := validators.ValidateRecordPriority(recordType, priority); err != nil {
		h.renderError(w, r, "Invalid priority: "+err.Error())
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

	// Resolve an unspecified TTL. On a merge the RRSet's current TTL wins:
	// PowerDNS applies the RRSet-level TTL to every record in the set, so
	// submitting the form default here would silently rewrite the TTL of the
	// pre-existing sibling records (e.g. a deliberately short 300s TTL jumps
	// to 3600 just by adding a second A record). For a brand-new RRSet the
	// 3600 default applies. An explicitly submitted TTL bypasses this
	// resolution entirely and is applied as typed.
	if ttl == 0 {
		if existingRRSet != nil {
			ttl = existingRRSet.TTL
		} else {
			ttl = defaultRecordTTL
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

	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, ZoneID: zoneID, Action: "create_record", Details: fmt.Sprintf("Created %s record %s -> %s", recordType, name, content), OldValue: rrsetSnapshot(existingRRSet), NewValue: rrsetSnapshot(&rrset)}); err != nil {
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
		h.renderInternalError(w, r, "Failed to fetch records", err)
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
	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, ZoneID: zoneID, Action: "update_record", Details: fmt.Sprintf("Updated %s record %s", rrset.Type, rrset.Name), OldValue: rrsetSnapshot(oldRRSet), NewValue: rrsetSnapshot(rrset)}); err != nil {
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
	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, ZoneID: zoneID, Action: "update_record", Details: fmt.Sprintf("Updated %s record %s", rrset.Type, rrset.Name), OldValue: rrsetSnapshot(oldRRSet), NewValue: rrsetSnapshot(rrset)}); err != nil {
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
		// parseRecordForm returns *recordValidationError for bad TTL/priority;
		// pass it through so the caller renders a 400 rather than wrapping it
		// into a generic error that would render as a 500 (REVIEW.md L-4).
		return nil, nil, err
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

	if err := validators.ValidateRecordPriority(recordType, priority); err != nil {
		return nil, nil, &recordValidationError{Message: "Invalid priority: " + err.Error()}
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
		// If the merge didn't find a match (originalContent no longer matches
		// any existing record — stale page data, e.g. the SOA serial was
		// bumped by PowerDNS between page load and save via SOA-EDIT), the
		// merge appended a new record. For a single-record RRSet this would
		// produce two records, which PowerDNS rejects for types like SOA or
		// CNAME ("only one such record allowed"). Replace the sole record
		// instead, implementing last-write-wins for the edit the user
		// explicitly submitted.
		if len(updatedRecords) > len(existingRRSet.Records) && len(existingRRSet.Records) == 1 {
			updatedRecords = []models.RecordInfo{{Content: content, Priority: priority, Disabled: disabled}}
		}
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
//
// The flow is split into three focused helpers so the handler stays a short,
// readable outline:
//   - collectBatchRows parses and validates the parallel form arrays;
//   - mergeBatchRRSets merges the new rows into the existing RRSets by name+type;
//   - finalizeBatchRRSets normalises content, deduplicates and assembles comments.
func (h *Handler) BatchCreateRecords(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if err := r.ParseForm(); err != nil {
		// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
		http.Redirect(w, r, "/zones/"+zoneID+"/records/new", http.StatusSeeOther)
		return
	}

	if len(r.PostForm["name"]) == 0 || len(r.PostForm["type"]) == 0 || len(r.PostForm["content"]) == 0 {
		h.renderError(w, r, "At least one record is required")
		return
	}

	rrsets, logEntries, pendingComments, err := collectBatchRows(
		r.PostForm["name"], r.PostForm["type"], r.PostForm["content"],
		r.PostForm["ttl"], r.PostForm["priority"],
		r.PostForm["comment"], r.PostForm["comment_clear"],
		zoneID,
	)
	if err != nil {
		h.renderError(w, r, err.Error())
		return
	}
	if len(rrsets) == 0 {
		h.renderError(w, r, "No valid records to create")
		return
	}

	existing, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch existing records", err)
		return
	}

	mergedMap := mergeBatchRRSets(rrsets, existing)
	merged := finalizeBatchRRSets(mergedMap, pendingComments)

	if err := h.PDNS.CreateRecords(r.Context(), zoneID, merged); err != nil {
		h.renderInternalError(w, r, "Failed to create records", err)
		return
	}

	// A single summary entry instead of one activity_logs row per form row —
	// the same write-amplification fix as the zone import: each row was its
	// own implicit transaction, and a large batch serialized the whole
	// application behind the loop on SQLite's single connection. The summary
	// counts records after merge/dedup (what PowerDNS actually received)
	// alongside the submitted row count.
	batchRecordCount := 0
	for _, rr := range merged {
		batchRecordCount += len(rr.Records)
	}
	if err := logActivity(r.Context(), h.DB, activityEntry{
		UserID:  user.ID,
		ZoneID:  zoneID,
		Action:  "create_record",
		Details: fmt.Sprintf("Created %d records across %d record sets (batch of %d rows)", batchRecordCount, len(merged), len(logEntries)),
	}); err != nil {
		logger.Error("failed to log create_record activity", "zone_id", zoneID, "error", err)
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// batchLogEntry captures the user-facing details of one submitted record row
// for the activity log, written after the PowerDNS create succeeds.
type batchLogEntry struct {
	recordType string
	name       string
	content    string
}

// batchPendingComment is one row's comment textarea text plus its explicit
// "clear" flag. Rows that merge into the same RRSet contribute their comments
// together, and the per-row clear signal must survive the merge.
type batchPendingComment struct {
	text  string
	clear bool
}

// collectBatchRows parses and validates the parallel name/type/content/...
// form arrays of a batch-create submission. name/type/content are iterated
// only up to the shortest of the three so a mismatched POST cannot index out
// of range. It returns the built one-record RRSets, the activity-log entries
// and the per name+type pending comments. A validation failure yields a
// user-facing error (the caller renders err.Error()).
//
// TTL/priority validation mirrors the single-record CreateRecord path: an
// empty field means "use the default" (3600 / 0), but an explicit non-numeric
// or out-of-range value is rejected rather than silently substituted, so the
// activity log records what the user actually typed. Priority 0 is a valid MX
// value, so the presence check ("0 provided" vs "not provided") is the
// empty-string test, not a > 0 test.
func collectBatchRows(names, types, contents, ttls, priorities, comments, commentClears []string, zoneID string) ([]models.RRSet, []batchLogEntry, map[string][]batchPendingComment, error) {
	count := min(len(names), len(types), len(contents))

	var rrsets []models.RRSet
	var logs []batchLogEntry
	pending := make(map[string][]batchPendingComment)

	for i := 0; i < count; i++ {
		name := strings.TrimSpace(names[i])
		recordType := strings.TrimSpace(types[i])
		content := strings.TrimSpace(contents[i])

		if name == "" || recordType == "" || content == "" {
			continue
		}

		name = normalizeRecordName(name, zoneID)

		if err := validators.ValidateRecordName(name); err != nil {
			return nil, nil, nil, fmt.Errorf("Invalid record name '%s': %w", name, err)
		}

		// An empty TTL means "no preference" (0 until the merge resolves it:
		// existing RRSet TTL on a merge, defaultRecordTTL otherwise); an
		// explicit non-numeric or non-positive value is rejected rather than
		// silently substituted, so the activity log records what the user
		// actually typed.
		ttl := 0
		if i < len(ttls) {
			if ttlStr := strings.TrimSpace(ttls[i]); ttlStr != "" {
				v, err := strconv.Atoi(ttlStr)
				if err != nil || v <= 0 {
					return nil, nil, nil, fmt.Errorf("Invalid TTL: must be a positive integer")
				}
				ttl = v
			}
		}
		priority := 0
		if i < len(priorities) {
			if priorityStr := strings.TrimSpace(priorities[i]); priorityStr != "" {
				v, err := strconv.Atoi(priorityStr)
				if err != nil || v < 0 {
					return nil, nil, nil, fmt.Errorf("Invalid priority: must be a non-negative integer")
				}
				priority = v
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
			return nil, nil, nil, fmt.Errorf("Invalid record type '%s': %w", recordType, err)
		}
		if err := validators.ValidateRecordContent(recordType, content); err != nil {
			return nil, nil, nil, fmt.Errorf("Invalid record content: %w", err)
		}
		if err := validators.ValidateRecordPriority(recordType, priority); err != nil {
			return nil, nil, nil, fmt.Errorf("Invalid priority '%s': %w", recordType, err)
		}

		rrsets = append(rrsets, models.RRSet{
			Name: name,
			Type: recordType,
			TTL:  ttl,
			Records: []models.RecordInfo{
				{Content: content, Priority: priority, Disabled: false},
			},
		})
		logs = append(logs, batchLogEntry{recordType: recordType, name: name, content: content})

		key := name + "|" + recordType
		if rowComment != "" || rowCommentClear {
			pending[key] = append(pending[key], batchPendingComment{text: rowComment, clear: rowCommentClear})
		}
	}

	return rrsets, logs, pending, nil
}

// mergeBatchRRSets groups the new one-record RRSets by name+type and merges
// them into the existing RRSets fetched from PowerDNS, so a batch that adds
// several records to the same RRSet (or to an existing one) produces a single
// merged RRSet per name+type. An explicit TTL on the new submission is applied
// to the merged RRSet; an unspecified (0) TTL keeps the existing RRSet's TTL —
// PowerDNS applies the RRSet-level TTL to every record, so inheriting the
// submission default here would silently rewrite the siblings' TTL. Returns
// the merged RRSets keyed by "name|type".
func mergeBatchRRSets(newRRSets []models.RRSet, existing []models.RRSet) map[string]*models.RRSet {
	existingMap := make(map[string]*models.RRSet)
	for i := range existing {
		existingMap[existing[i].Name+"|"+existing[i].Type] = &existing[i]
	}

	merged := make(map[string]*models.RRSet)
	for _, newRR := range newRRSets {
		key := newRR.Name + "|" + newRR.Type
		if ex, ok := existingMap[key]; ok {
			if m, seen := merged[key]; seen {
				m.Records = append(m.Records, newRR.Records...)
			} else {
				clone := *ex
				for _, nr := range newRR.Records {
					clone.Records = mergeRecordIntoRRSet(clone.Records, "", 0, nr)
				}
				if newRR.TTL > 0 {
					clone.TTL = newRR.TTL
				}
				merged[key] = &clone
			}
		} else {
			if m, seen := merged[key]; seen {
				m.Records = append(m.Records, newRR.Records...)
			} else {
				merged[key] = &newRR
			}
		}
	}
	return merged
}

// finalizeBatchRRSets prepares each merged RRSet for the PowerDNS write:
// normalises record content/priority, drops records that produced identical
// wire content (PowerDNS rejects duplicates — e.g. duplicate batch rows, or a
// new row duplicating an existing record; MX/SRV priority is embedded in the
// content so targets with different priorities are kept), and assembles the
// comment patch from the per-row pending comments merged with any comments
// already on the RRSet (PowerDNS PATCH comments REPLACE the list). It mutates
// the RRSets in merged in place and returns them as a slice; the caller also
// reads merged (by key) for the activity-log snapshot, which therefore
// reflects the finalised, post-normalisation record set. Map iteration order
// is non-deterministic, but each RRSet is sent as an independent PATCH so the
// order does not matter.
func finalizeBatchRRSets(merged map[string]*models.RRSet, pending map[string][]batchPendingComment) []models.RRSet {
	var out []models.RRSet
	for key, rr := range merged {
		// Last-resort TTL resolution: a merged RRSet that neither inherited an
		// existing TTL (new RRSet) nor carried an explicit one still needs a
		// positive value for PowerDNS.
		if rr.TTL <= 0 {
			rr.TTL = defaultRecordTTL
		}
		for i := range rr.Records {
			rr.Records[i].Content, rr.Records[i].Priority =
				prepareRecordContent(rr.Type, rr.Records[i].Content, rr.Records[i].Priority)
		}
		rr.Records = dedupRecordsByContent(rr.Records)

		var existing []models.Comment
		if rr.Comments != nil {
			existing = rr.Comments.Items
		}
		if userComments := pending[key]; len(userComments) > 0 {
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
		out = append(out, *rr)
	}
	return out
}

// rrsetSnapshot serialises an RRSet to JSON for storage in activity_logs,
// rendered in the logical API representation (priority as a dedicated field,
// content without the leading priority prefix) so the activity-log "View
// change" matches the REST API payload and the zone view rather than the
// PowerDNS wire format.
//
// The write-path callers pass an RRSet already processed by
// prepareRecordContent, which embeds MX/SRV priority into the content (PDNS
// rejects a separate priority element in a PATCH); SplitPriority reverses that
// for display. The read-path callers pass an RRSet straight from ListRecords,
// which already splits the priority — SplitPriority is idempotent, so applying
// it uniformly keeps Before and After consistent within a single entry.
//
// It returns an empty string for a nil RRSet (e.g. create on a new RRSet or
// delete when the RRSet could not be fetched).
func rrsetSnapshot(rrset *models.RRSet) string {
	if rrset == nil {
		return ""
	}
	// Copy rather than mutate: callers reuse this RRSet for the PDNS PATCH,
	// whose content must keep the priority embedded.
	records := make([]models.RecordInfo, len(rrset.Records))
	for i, r := range rrset.Records {
		records[i] = r
		if p, c, ok := models.SplitPriority(rrset.Type, r.Content); ok {
			records[i].Content = c
			records[i].Priority = p
		}
	}
	snapshot := *rrset
	snapshot.Records = records
	b, err := json.Marshal(snapshot)
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

	// Empty TTL defaults to 3600; an explicit non-numeric or non-positive
	// value is rejected so the activity log records what the user actually
	// typed, not a silent substitution (REVIEW.md L-4).
	ttl = 3600
	if ttlStr != "" {
		v, parseErr := strconv.Atoi(ttlStr)
		if parseErr != nil || v <= 0 {
			err = &recordValidationError{Message: "Invalid TTL: must be a positive integer"}
			return
		}
		ttl = v
	}

	priority = 0
	if priorityStr != "" {
		v, parseErr := strconv.Atoi(priorityStr)
		if parseErr != nil || v < 0 {
			err = &recordValidationError{Message: "Invalid priority: must be a non-negative integer"}
			return
		}
		priority = v
	}
	return
}

// DeleteRecord deletes a single DNS record from a zone (POST /zones/{zone_id}/records/delete).
//
// Identifies the record by "name", "type", "content" and "priority" form
// values. When the RRSet holds several records only the selected one is removed
// (the RRSet is REPLACEd with the remaining records); when it is the sole
// record the whole RRSet is DELETEd. MX/SRV priority is re-embedded into the
// content of the remaining records because PowerDNS rejects a separate priority
// element in a PATCH.
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

	content := strings.TrimSpace(r.FormValue("content"))
	priority, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("priority")))

	// removal identifies the single record to drop by content+priority, matching
	// the recordIdentity used on the PowerDNS read path (SplitPriority has
	// already detached the priority for MX/SRV).
	removal := map[string]map[recordIdentity]struct{}{
		recordName + "|" + recordType: {
			{Content: content, Priority: priority}: {},
		},
	}

	allRecords, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch records", err)
		return
	}

	// Snapshot the full RRSet before mutation for the activity log.
	var oldRRSet *models.RRSet
	for i := range allRecords {
		if allRecords[i].Name == recordName && allRecords[i].Type == recordType {
			oldRRSet = &allRecords[i]
			break
		}
	}

	patch, _, _ := buildRemovalPatch(allRecords, removal)
	if len(patch) == 0 {
		h.renderError(w, r, "Record not found")
		return
	}

	if err := h.PDNS.PatchRecords(r.Context(), zoneID, patch); err != nil {
		h.renderInternalError(w, r, "Failed to delete record", err)
		return
	}

	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, ZoneID: zoneID, Action: "delete_record", Details: fmt.Sprintf("Deleted %s record %s", recordType, recordName), OldValue: rrsetSnapshot(oldRRSet)}); err != nil {
		logger.Error("failed to log delete_record activity", "zone_id", zoneID, "error", err)
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// recordIdentity uniquely identifies a single record within an RRSet on the
// PowerDNS read path: content is the post-SplitPriority value and priority is
// the detached priority (0 for non-priority types). Two MX records pointing at
// the same target differ only by priority, so both fields are required.
type recordIdentity struct {
	Content  string
	Priority int
}

// buildRemovalPatch computes the RRSet PATCH body needed to drop the records
// identified by removal (keyed "name|type" -> set of record identities) from
// allRecords. When every record of an RRSet is selected the whole RRSet is
// removed with changetype DELETE; otherwise the RRSet is REPLACEd with the
// remaining records, re-encoding MX/SRV priority into the content (PowerDNS
// rejects a separate priority element in a PATCH) and re-applying FQDN/quote
// normalisation idempotently.
//
// It also returns a snapshot of the records actually removed (for the activity
// log) and the total count. RRSets referenced by removal whose selected
// records no longer exist (stale rows) are skipped. allRecords is not mutated.
func buildRemovalPatch(allRecords []models.RRSet, removal map[string]map[recordIdentity]struct{}) (patch []models.RRSet, removedSnapshot []models.RRSet, totalRemoved int) {
	for i := range allRecords {
		rr := allRecords[i]
		key := rr.Name + "|" + rr.Type
		drop, ok := removal[key]
		if !ok {
			continue
		}

		var remaining, removed []models.RecordInfo
		for _, rec := range rr.Records {
			if _, hit := drop[recordIdentity{Content: rec.Content, Priority: rec.Priority}]; hit {
				removed = append(removed, rec)
			} else {
				remaining = append(remaining, rec)
			}
		}
		if len(removed) == 0 {
			// Selection referenced nothing that still exists (stale row); skip.
			continue
		}

		if len(remaining) == 0 {
			patch = append(patch, models.RRSet{Name: rr.Name, Type: rr.Type, ChangeType: "DELETE"})
		} else {
			for j := range remaining {
				remaining[j].Content, remaining[j].Priority =
					prepareRecordContent(rr.Type, remaining[j].Content, remaining[j].Priority)
			}
			patch = append(patch, models.RRSet{
				Name:       rr.Name,
				Type:       rr.Type,
				TTL:        rr.TTL,
				ChangeType: "REPLACE",
				Records:    remaining,
			})
		}

		removedSnapshot = append(removedSnapshot, models.RRSet{
			Name:    rr.Name,
			Type:    rr.Type,
			TTL:     rr.TTL,
			Records: removed,
		})
		totalRemoved += len(removed)
	}
	return patch, removedSnapshot, totalRemoved
}

// BulkDeleteRecords deletes several records from a zone in a single PATCH
// (POST /zones/{zone_id}/records/bulk-delete).
//
// The selection is transmitted as parallel form arrays (name, type,
// original_content, original_priority) — one tuple per selected row. Records
// are grouped by name+type. When every record of an RRSet is selected the whole
// RRSet is removed with changetype DELETE; otherwise the RRSet is REPLACEd with
// the remaining records. Because PowerDNS rejects a separate priority element
// in a PATCH, remaining records are re-encoded via prepareRecordContent so
// MX/SRV priority is embedded back into the content. Returns JSON so the
// AJAX caller can refresh the page on success.
func (h *Handler) BulkDeleteRecords(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid form data"})
		return
	}

	names := r.PostForm["name"]
	types := r.PostForm["type"]
	contents := r.PostForm["original_content"]
	priorities := r.PostForm["original_priority"]

	// Parallel arrays; iterate only over indices present in name+type so a
	// mismatched POST cannot index out of range. content/priority are read
	// defensively per index.
	count := len(names)
	if len(types) < count {
		count = len(types)
	}

	// removal[name|type] -> set of record identities to drop.
	removal := make(map[string]map[recordIdentity]struct{})
	processed := 0
	for i := 0; i < count; i++ {
		name := strings.TrimSpace(names[i])
		recordType := strings.TrimSpace(types[i])
		if name == "" || recordType == "" {
			continue
		}
		if err := validators.ValidateRecordType(recordType); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid record type: " + err.Error()})
			return
		}
		name = normalizeRecordName(name, zoneID)
		if err := validators.ValidateRecordName(name); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid record name: " + err.Error()})
			return
		}

		content := ""
		if i < len(contents) {
			content = strings.TrimSpace(contents[i])
		}
		priority := 0
		if i < len(priorities) {
			priority, _ = strconv.Atoi(strings.TrimSpace(priorities[i]))
		}

		key := name + "|" + recordType
		if removal[key] == nil {
			removal[key] = make(map[recordIdentity]struct{})
		}
		removal[key][recordIdentity{Content: content, Priority: priority}] = struct{}{}
		processed++
	}

	if processed == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No records selected"})
		return
	}

	allRecords, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		logger.Error("BulkDeleteRecords: failed to list records", "zone_id", zoneID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch records"})
		return
	}

	patch, removedSnapshot, totalRemoved := buildRemovalPatch(allRecords, removal)

	if len(patch) > 0 {
		if err := h.PDNS.PatchRecords(r.Context(), zoneID, patch); err != nil {
			logger.Error("BulkDeleteRecords: PatchRecords failed", "zone_id", zoneID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete records"})
			return
		}
	}

	snapshotJSON := ""
	if b, err := json.Marshal(removedSnapshot); err == nil {
		snapshotJSON = string(b)
	}
	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, ZoneID: zoneID, Action: "delete_record", Details: fmt.Sprintf("Bulk deleted %d record(s) across %d RRSet(s)", totalRemoved, len(removedSnapshot)), OldValue: snapshotJSON}); err != nil {
		logger.Error("failed to log bulk delete_record activity", "zone_id", zoneID, "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": totalRemoved,
	})
}

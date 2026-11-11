package handlers

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// ImportZone handles file upload for zone import (BIND or CSV).
//
// The upload is parsed and validated first: any line or directive that cannot
// be turned into a record is reported, and the import is rejected before
// PowerDNS is called (a partial import would make the file's description of
// every RRSet it touches incomplete).
//
// The write itself runs under the per-zone lock in one of two modes, selected
// by the `mode` form field:
//
//   - merge (default; any missing, empty or unknown value falls back to it):
//     the imported RRSets are merged into the existing zone state — sibling
//     records, comments and disabled flags on existing RRSets survive, exact
//     duplicates keep the existing occurrence, and an imported SOA replaces
//     the existing SOA RRSet because the file carries the authoritative serial.
//   - replace: each imported name+type pair REPLACes the existing RRSet if
//     present, or creates it if absent; records not in the import file are
//     untouched, but extra existing records within a touched name+type are
//     removed.
//
// Both modes fetch the pre-import zone state under the lock (the before-image)
// and audit a bounded snapshot of the affected RRSets — capped at
// importBeforeImageMaxSets entries and importBeforeImageMaxBytes bytes, with
// the truncation noted in the activity details.
func (h *Handler) ImportZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")

	// #nosec G120 — Form size limited to 10MB via ParseMultipartForm argument
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		logger.Warn("ImportZone: parse multipart failed", "zone", zoneID, "error", err)
		h.renderError(w, r, "Failed to parse upload. Ensure the request is a valid multipart form under 10 MB.")
		return
	}

	file, header, err := r.FormFile("zonefile")
	if err != nil {
		logger.Warn("ImportZone: no file in upload", "zone", zoneID, "error", err)
		h.renderError(w, r, "No file uploaded or the form did not include a zonefile field.")
		return
	}
	defer file.Close()

	format := r.FormValue("format")
	if format != "bind" && format != "csv" {
		format = detectFormat(header.Filename)
	}
	if format != "bind" && format != "csv" {
		h.renderError(w, r, "Could not detect format. Please select BIND or CSV.")
		return
	}

	var rrsets []models.RRSet
	var skipped []skippedLine
	switch format {
	case "bind":
		data, readErr := io.ReadAll(io.LimitReader(file, 10<<20))
		if readErr != nil {
			logger.Error("ImportZone: read failed", "zone", zoneID, "error", readErr)
			h.renderError(w, r, "Failed to read uploaded file")
			return
		}
		rrsets, skipped, err = parseBindZone(data, zoneID)
	case "csv":
		cr := csv.NewReader(file)
		rrsets, skipped, err = parseCSVZone(cr, zoneID)
	}

	if err != nil {
		logger.Error("ImportZone: parse failed", "zone", zoneID, "format", format, "error", err)
		h.renderError(w, r, "Failed to parse the uploaded file. Verify the format and record syntax.")
		return
	}

	if len(skipped) > 0 {
		for _, s := range skipped {
			logger.Warn("Zone import rejected invalid input", "zone", zoneID, "line", s.Line, "reason", s.Reason)
		}
		h.renderError(w, r, fmt.Sprintf("Import file contains %d invalid or unsupported line(s) or directive(s). Fix the file and retry; no records were imported.", len(skipped)))
		return
	}

	if len(rrsets) == 0 {
		h.renderError(w, r, "No valid records found in file")
		return
	}

	// Parsing runs outside the lock; the fetch→merge→PATCH sequence itself is
	// serialized against concurrent writers on the same zone (web
	// create/update, batch, REST, MCP, imports on other instances). Without
	// the lock, a create whose fetch→merge lands around this PATCH silently
	// loses either the imported RRSet or the new record.
	release, ok := h.lockZone(w, r, zoneID)
	if !ok {
		return
	}
	defer release()

	// Both modes need the pre-import zone state: merge mode merges into it,
	// and the audit trail snapshots it. A failure here aborts the import
	// before any PATCH and before any audit row.
	existing, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch existing records", err)
		return
	}

	oldValue, affected, shown := importBeforeImage(existing, rrsets)

	mode := r.FormValue("mode")
	if mode != "replace" {
		mode = "merge"
	}

	var patch []models.RRSet
	if mode == "replace" {
		// Historical REPLACE semantics, unchanged write shape: the parsed
		// wire-form RRSets describe the complete desired state of every
		// RRSet they touch.
		patch = rrsets
	} else {
		patch, err = buildImportMergePatch(rrsets, existing)
		if err != nil {
			h.renderError(w, r, err.Error())
			return
		}
	}

	// Route every PowerDNS failure through renderInternalError so the raw
	// upstream error text (which may quote SQL fragments or internal paths on a
	// backend failure) never reaches the user; pdnsUserFacingStatus maps each
	// sentinel to a fixed, category-level message and the cause is logged
	// server-side.
	if err := h.PDNS.CreateRecords(r.Context(), zoneID, patch); err != nil {
		h.renderInternalError(w, r, "Failed to create records", err)
		return
	}

	user := middleware.GetUser(r)
	logger.Info("Zone imported", "zone", zoneID, "format", format, "mode", mode, "count", len(rrsets), "user", user.Username)

	// A single summary entry instead of one activity_logs row per RRSet: a
	// 10 MiB import can carry thousands of RRSets, and each row was its own
	// implicit transaction — on SQLite (one connection) that serialized the
	// whole application behind the loop and drowned the zone's activity view.
	recordCount := 0
	for _, rs := range rrsets {
		recordCount += len(rs.Records)
	}
	details := fmt.Sprintf("Imported %d RRSets (%d records) from %s zone file (%s mode)", len(rrsets), recordCount, strings.ToUpper(format), mode)
	if shown < affected {
		details += fmt.Sprintf("; before-image limited to first %d of %d affected record set(s)", shown, affected)
	}
	if err := logActivity(r.Context(), h.DB, activityEntry{UserID: user.ID, ZoneID: zoneID, Action: "import_zone", Details: details, OldValue: oldValue}); err != nil {
		logger.Error("failed to log import_zone activity", "zone_id", zoneID, "error", err)
	}

	// #nosec G710 — redirect target is "/zones/" + zoneID (chi PathValue, route-controlled); no user-controlled host/path.
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// buildImportMergePatch merges the parsed (wire-form) import RRSets into the
// existing zone state, exactly like BatchCreateRecords and ApplyTemplateToZone:
// split embedded MX/SRV priorities back to the read form, merge under the
// canonical RRSetKey, then a single final normalisation/dedup pass. On top of
// the plain merge, an imported SOA whose name+type already exists in the zone
// replaces the existing SOA RRSet — the zone file carries the authoritative
// serial, so the old SOA record must never survive. When the imported SOA
// carries no comments, the existing SOA comments are kept (a nil comment patch
// would be omitted from the PATCH, but carrying them keeps the audit and the
// sent state consistent).
func buildImportMergePatch(rrsets, existing []models.RRSet) ([]models.RRSet, error) {
	converted := splitEmbeddedPriorities(rrsets)
	mergedMap, err := mergeBatchRRSets(converted, existing)
	if err != nil {
		return nil, err
	}

	for i := range rrsets {
		if !strings.EqualFold(rrsets[i].Type, "SOA") {
			continue
		}
		key := dnsops.RRSetKey(rrsets[i].Name, rrsets[i].Type)
		clone := rrsets[i]
		if clone.Comments == nil {
			if prev := mergedMap[key]; prev != nil {
				clone.Comments = prev.Comments
			}
		}
		// Assigning unconditionally also covers a brand-new SOA: the merge
		// already put the imported records at that key.
		mergedMap[key] = &clone
	}

	return finalizeBatchRRSets(mergedMap, nil)
}

const (
	// importBeforeImageMaxSets caps how many RRSets of the pre-import zone
	// state are snapshotted into the audit row's old_value.
	importBeforeImageMaxSets = 100
	// importBeforeImageMaxBytes caps the serialized size of that snapshot so
	// a huge import cannot blow up the activity_logs row.
	importBeforeImageMaxBytes = 48 * 1024
)

// importBeforeImage builds the bounded audit snapshot of the pre-import zone
// state: the JSON-array serialization (single-encoded) of the existing RRSets
// whose canonical key matches an imported key. It stops before exceeding
// EITHER importBeforeImageMaxSets entries OR importBeforeImageMaxBytes
// serialized bytes (accounting for the JSON array framing: 2 + sum(len) +
// (n-1)), so the result is always valid JSON. It returns the snapshot ("" when
// nothing fits), the number of affected existing RRSets, and how many were
// included.
func importBeforeImage(existing, imported []models.RRSet) (oldValue string, affected, shown int) {
	importedKeys := make(map[string]struct{}, len(imported))
	for i := range imported {
		importedKeys[dnsops.RRSetKey(imported[i].Name, imported[i].Type)] = struct{}{}
	}

	var snaps []json.RawMessage
	total := 2 // "[" + "]"
	capped := false
	for i := range existing {
		key := dnsops.RRSetKey(existing[i].Name, existing[i].Type)
		if _, ok := importedKeys[key]; !ok {
			continue
		}
		affected++
		if capped || len(snaps) >= importBeforeImageMaxSets {
			// A cap is reached: stop including snapshots but keep counting
			// the affected RRSets, so the details can report the real total.
			continue
		}
		snap := rrsetSnapshot(&existing[i])
		if snap == "" {
			continue // defensive: never place an invalid/empty element
		}
		size := len(snap)
		if len(snaps) > 0 {
			size++ // "," separator
		}
		if total+size > importBeforeImageMaxBytes {
			capped = true
			continue
		}
		snaps = append(snaps, json.RawMessage(snap))
		total += size
	}
	if len(snaps) == 0 {
		return "", affected, 0
	}
	data, err := json.Marshal(snaps)
	if err != nil {
		return "", affected, 0
	}
	return string(data), affected, len(snaps)
}

func detectFormat(filename string) string {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".csv") {
		return "csv"
	}
	return "bind"
}

type bindRecord struct {
	name  string
	ttl   int
	rtype string
	data  string
}

// skippedLine records an input line or directive that could not be turned
// into a record (parse failure, validation failure, or unsupported input), so
// the importer can reject the upload instead of silently dropping part of the
// file. Used for both BIND and CSV imports.
type skippedLine struct {
	Line   string
	Reason string
}

// validateParsedRecord validates a parsed record's type, name, content,
// priority and effective TTL (the explicit or $TTL/default-resolved value, so
// an over-bound TTL is rejected here even when it came from a directive rather
// than the record line). contentBare must be the content WITHOUT an embedded
// priority (the caller must SplitPriority first for MX/SRV). It lets the BIND
// and CSV importers reject invalid records before they reach PowerDNS,
// producing a specific reason per line instead of a generic "failed to create
// records" the validation-before-normalisation contract).
func validateParsedRecord(rtype, name, contentBare string, priority, ttl int) error {
	if err := validators.ValidateRecordType(rtype); err != nil {
		return err
	}
	if err := validators.ValidateRecordName(name); err != nil {
		return err
	}
	if err := validators.ValidateRecordContent(rtype, contentBare); err != nil {
		return err
	}
	if err := validators.ValidateRecordTTL(ttl); err != nil {
		return err
	}
	return validators.ValidateRecordPriority(rtype, priority)
}

// parseBindZone parses an RFC 1035 BIND zone file and returns RRSets plus any
// lines or directives that could not be converted into records (so the caller
// can reject an incomplete upload instead of silently dropping part of it).
func parseBindZone(data []byte, zoneID string) ([]models.RRSet, []skippedLine, error) {
	origin := zoneID
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}
	defaultTTL := 3600

	lines := normalizeBindLines(string(data))
	raw := make([]bindRecord, 0)
	var skipped []skippedLine
	lastOwner := "" // owner of the previous record, for RFC 1035 inheritance

	for _, bl := range lines {
		line := bl.text

		// Directives are matched on the first token (space- or tab-separated),
		// case-insensitively. Extra tokens are tolerated; the first argument
		// is used.
		if fields := strings.Fields(line); len(fields) > 0 {
			switch strings.ToUpper(fields[0]) {
			case "$ORIGIN":
				if len(fields) < 2 {
					skipped = append(skipped, skippedLine{Line: bl.text, Reason: "$ORIGIN directive requires a value"})
					continue
				}
				origin = fields[1]
				if !strings.HasSuffix(origin, ".") {
					origin += "."
				}
				continue
			case "$TTL":
				if len(fields) < 2 {
					skipped = append(skipped, skippedLine{Line: bl.text, Reason: "$TTL directive requires a value"})
					continue
				}
				ttl, err := parseBindTTLValue(fields[1])
				if err != nil {
					skipped = append(skipped, skippedLine{Line: bl.text, Reason: err.Error()})
					continue
				}
				defaultTTL = ttl
				continue
			case "$INCLUDE":
				skipped = append(skipped, skippedLine{Line: bl.text, Reason: "$INCLUDE directives are not supported"})
				continue
			}
		}

		// RFC 1035: a line starting with whitespace omits the owner name and
		// reuses the previous record's owner. Prepend it so parseBindLine,
		// which always expects an owner as the first token, stays simple.
		if bl.inheritsOwner {
			if lastOwner == "" {
				continue
			}
			line = lastOwner + " " + line
		} else if f := strings.Fields(line); len(f) > 0 {
			lastOwner = f[0]
		}

		rec, err := parseBindLine(line, origin, defaultTTL)
		if err != nil {
			skipped = append(skipped, skippedLine{Line: bl.text, Reason: err.Error()})
			continue
		}
		// Resolve the RDATA domain-name fields against the current origin
		// before validation: per RFC 1035 §5.1 a name that does not end with
		// "." is relative to $ORIGIN ("@" denotes the origin). A trailing-dot
		// append alone turns "mail" into the TLD "mail." instead of the
		// intended "mail.<origin>.".
		rec.data = resolveBindRData(rec.rtype, rec.data, origin)
		// Validate the parsed record before accepting it. BIND data is wire
		// format (priority embedded for MX/SRV), so split the priority out
		// first and validate the bare content.
		prio, rest, _ := models.SplitPriority(rec.rtype, rec.data)
		if verr := validateParsedRecord(rec.rtype, rec.name, rest, prio, rec.ttl); verr != nil {
			skipped = append(skipped, skippedLine{Line: bl.text, Reason: verr.Error()})
			continue
		}
		// A priority divergence (wire data carrying two leading priorities,
		// e.g. "10 20 5 5060 target") must not be silently re-embedded — that
		// would drop a token from the wire content. Reject the line with the
		// conflict message while the other lines still import.
		if _, _, perr := prepareRecordContent(rec.rtype, rest, prio); perr != nil {
			skipped = append(skipped, skippedLine{Line: bl.text, Reason: perr.Error()})
			continue
		}
		raw = append(raw, rec)
	}

	return groupBindRecords(raw), skipped, nil
}

// parseBindTTLValue parses a $TTL value in the BIND time grammar (RFC 1035
// §5.1-style single-unit form): decimal digits with an optional single
// case-insensitive unit suffix — s=seconds, m=minutes, h=hours, d=days,
// w=weeks. Bare digits are seconds. The accepted range is clamped to
// validators.MaxRecordTTL (RFC 2181 maximum) and the unit multiplication is
// computed in int64: PowerDNS
// TTLs are uint32, but the parser stays conservative so the value fits every
// downstream int consumer and overflows are rejected instead of wrapping.
func parseBindTTLValue(value string) (int, error) {
	invalid := fmt.Errorf("invalid $TTL value %q", value)
	if value == "" {
		return 0, invalid
	}

	unit := int64(1)
	digits := value
	if last := value[len(value)-1]; last < '0' || last > '9' {
		switch strings.ToUpper(string(last)) {
		case "S":
			unit = 1
		case "M":
			unit = 60
		case "H":
			unit = 3600
		case "D":
			unit = 86400
		case "W":
			unit = 604800
		default:
			return 0, invalid
		}
		digits = value[:len(value)-1]
	}

	var n int64
	for i := 0; i < len(digits); i++ {
		if d := digits[i]; d < '0' || d > '9' {
			return 0, invalid
		}
		n = n*10 + int64(digits[i]-'0')
		if n > validators.MaxRecordTTL/unit {
			return 0, invalid
		}
	}
	n *= unit
	if n <= 0 || n > validators.MaxRecordTTL {
		return 0, invalid
	}
	return int(n), nil
}

// bindLine is one logical zone-file line (paren continuations joined, comments
// stripped). inheritsOwner records whether its first physical line began with
// whitespace, i.e. it omits the owner name per RFC 1035.
type bindLine struct {
	text          string
	inheritsOwner bool
}

func normalizeBindLines(input string) []bindLine {
	input = strings.ReplaceAll(input, "\r\n", "\n")
	lines := strings.Split(input, "\n")

	result := make([]bindLine, 0, len(lines))
	// parenDepth is the open-structural-parenthesis depth of the logical
	// line being accumulated. Parens inside quoted strings are literal data
	// and never counted, and an open+close pair on the same line must leave
	// the logical line closed: the previous boolean flip (open on '(' then
	// close only when closes > opens) stayed stuck on a same-line pair like
	// "( 1 2 3 4 5 )" and swallowed every following line into one giant
	// record, and a quoted TXT paren opened a logical line that never
	// closed.
	parenDepth := 0
	current := ""
	currentInherits := false

	for _, raw := range lines {
		// Detect owner inheritance before trimming, on the original line.
		leadingBlank := raw != "" && (raw[0] == ' ' || raw[0] == '\t')
		line := strings.TrimSpace(raw)

		// Strip comments and structural parentheses in one quote-aware
		// scan. Inside a quoted character-string a backslash escapes the next
		// byte (RFC 1035 master-file convention): both bytes are kept verbatim
		// and the escaped byte never toggles the quote state, starts a comment
		// or counts parens. Outside quotes a backslash is plain data.
		var cleaned strings.Builder
		inQuote := false
		depthDelta := 0
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case c == '\\' && inQuote:
				cleaned.WriteByte(c)
				if i+1 < len(line) {
					cleaned.WriteByte(line[i+1])
					i++
				}
			case c == '"':
				inQuote = !inQuote
				cleaned.WriteByte(c)
			case c == ';' && !inQuote:
				// Comment: drop the rest of the physical line.
				i = len(line)
			case c == '(' && !inQuote:
				depthDelta++
			case c == ')' && !inQuote:
				depthDelta--
			default:
				cleaned.WriteByte(c)
			}
		}
		line = strings.TrimSpace(cleaned.String())

		if line == "" && parenDepth == 0 {
			continue
		}

		if parenDepth == 0 {
			current = line
			currentInherits = leadingBlank
		} else {
			current += " " + line
		}

		parenDepth += depthDelta
		if parenDepth < 0 {
			// Stray ')' with no opener: tolerate (treat as data-less noise)
			// rather than desynchronizing every later line.
			parenDepth = 0
		}

		if parenDepth == 0 {
			current = strings.TrimSpace(current)
			if current != "" {
				result = append(result, bindLine{text: current, inheritsOwner: currentInherits})
			}
			current = ""
			currentInherits = false
		}
	}

	// Unterminated parenthesis at EOF: flush what was accumulated.
	if parenDepth > 0 {
		if current = strings.TrimSpace(current); current != "" {
			result = append(result, bindLine{text: current, inheritsOwner: currentInherits})
		}
	}

	return result
}

// errSkipBindLine marks a line that carries no usable record and must be
// dropped by the caller rather than turned into an empty (Name=="") RRSet.
var errSkipBindLine = errors.New("bind line has no record")

func parseBindLine(line, origin string, defaultTTL int) (bindRecord, error) {
	tokens := tokenizeBindLine(line)
	if len(tokens) < 2 {
		return bindRecord{}, fmt.Errorf("%w: not enough fields", errSkipBindLine)
	}

	idx := 0
	name := tokens[idx]
	idx++

	ttl := 0

	ttlNum, err := strconv.Atoi(tokens[idx])
	if err == nil && ttlNum > 0 {
		ttl = ttlNum
		idx++
	}

	if idx < len(tokens) && (strings.ToUpper(tokens[idx]) == "IN" || strings.ToUpper(tokens[idx]) == "CH" || strings.ToUpper(tokens[idx]) == "HS") {
		idx++
	} else if ttl == 0 && idx < len(tokens) {
		ttlNum, err := strconv.Atoi(tokens[idx])
		if err == nil && ttlNum > 0 {
			ttl = ttlNum
			idx++
		}
	}

	if idx >= len(tokens) {
		return bindRecord{}, fmt.Errorf("%w: missing record type", errSkipBindLine)
	}
	rtype := strings.ToUpper(tokens[idx])
	idx++

	data := ""
	if idx < len(tokens) {
		data = strings.Join(tokens[idx:], " ")
	}

	if ttl == 0 {
		ttl = defaultTTL
	}

	recName := resolveBindName(name, origin)

	return bindRecord{
		name:  recName,
		ttl:   ttl,
		rtype: rtype,
		data:  data,
	}, nil
}

func tokenizeBindLine(line string) []string {
	tokens := make([]string, 0)
	current := ""
	inQuote := false

	for i := 0; i < len(line); i++ {
		ch := line[i]

		// Inside a quoted character-string a backslash escapes the next
		// byte: both bytes stay in the token, and the escaped byte never
		// toggles the quote state or acts as whitespace.
		if ch == '\\' && inQuote {
			current += string(ch)
			if i+1 < len(line) {
				current += string(line[i+1])
				i++
			}
			continue
		}

		if ch == '"' {
			inQuote = !inQuote
			current += string(ch)
			continue
		}

		if ch == ' ' || ch == '\t' {
			if inQuote {
				current += string(ch)
			} else if current != "" {
				tokens = append(tokens, current)
				current = ""
			}
			continue
		}

		current += string(ch)
	}

	if current != "" {
		tokens = append(tokens, current)
	}

	return tokens
}

func resolveBindName(name, origin string) string {
	switch {
	case name == "@":
		return origin
	case strings.HasSuffix(name, "."):
		return name
	default:
		return name + "." + origin
	}
}

// resolveBindRData resolves the domain-name fields of a BIND RDATA against
// the current origin, per RFC 1035 §5.1: a name that does not end with "."
// is relative to $ORIGIN, and "@" denotes the origin itself. The affected
// fields follow recordTypeSpecs: FQDN-target types resolve the whole
// content (CNAME/NS/PTR/ALIAS/DNAME) or the last field (MX/SRV/AFSDB/NAPTR,
// after the embedded priority), multi-name types resolve their declared
// fields (SOA/RP/MINFO/NSEC). Other types pass through untouched.
func resolveBindRData(rtype, data, origin string) string {
	if data == "" {
		return data
	}
	switch {
	case models.TypeIsFQDNTarget(rtype):
		fields := strings.Fields(data)
		if len(fields) == 0 {
			return data
		}
		fields[len(fields)-1] = resolveBindName(fields[len(fields)-1], origin)
		return strings.Join(fields, " ")
	case models.TypeHasFQDNFields(rtype):
		fields := strings.Fields(data)
		for _, idx := range models.FQDNFieldIndices(rtype) {
			if idx >= 0 && idx < len(fields) {
				fields[idx] = resolveBindName(fields[idx], origin)
			}
		}
		return strings.Join(fields, " ")
	default:
		return data
	}
}

func groupBindRecords(raw []bindRecord) []models.RRSet {
	type key struct{ name, rtype string }
	groups := make(map[key][]bindRecord)
	order := make([]key, 0)

	for _, rec := range raw {
		k := key{rec.name, rec.rtype}
		if _, exists := groups[k]; !exists {
			order = append(order, k)
		}
		groups[k] = append(groups[k], rec)
	}

	rrsets := make([]models.RRSet, 0, len(order))
	for _, k := range order {
		recs := groups[k]
		ttl := recs[0].ttl
		for _, r := range recs {
			if r.ttl != ttl {
				ttl = r.ttl
			}
		}

		records := make([]models.RecordInfo, 0, len(recs))
		for _, r := range recs {
			// BIND data is already in wire format (priority embedded, TXT
			// quoted). Extract the embedded priority first so
			// prepareRecordContent re-embeds it correctly and applies
			// FQDN-target / multi-FQDN-field trailing-dot normalization.
			prio, rest, _ := models.SplitPriority(r.rtype, r.data)
			normalized, _, _ := prepareRecordContent(r.rtype, rest, prio)
			records = append(records, models.RecordInfo{
				Content:  normalized,
				Disabled: false,
			})
		}

		rrsets = append(rrsets, models.RRSet{
			Name:    k.name,
			Type:    k.rtype,
			TTL:     ttl,
			Records: records,
		})
	}

	return rrsets
}

// parseCSVZone parses CSV zone data and returns RRSets plus any rows that
// could not be converted into records (so the caller can reject an incomplete
// upload instead of silently dropping part of it, matching the BIND path).
// zoneID resolves the record names:
// relative names and the "@" apex shorthand are canonicalised against the
// zone, exactly like the BIND path (resolveBindName) and the web/API write
// paths (normalizeRecordName).
func parseCSVZone(reader *csv.Reader, zoneID string) ([]models.RRSet, []skippedLine, error) {
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(rows) < 2 {
		return nil, nil, nil
	}

	headers := make(map[string]int)
	for i, h := range rows[0] {
		headers[strings.ToLower(strings.TrimSpace(h))] = i
	}

	type key struct{ name, rtype string }
	groups := make(map[key][]models.RecordInfo)
	order := make([]key, 0)
	groupTTLs := make(map[key]int)
	// groupComments collects the comment cell for each row of a given RRSet.
	// The export duplicates the comment on every record row, so we dedup here
	// while preserving insertion order across rows.
	groupComments := make(map[key][]string)
	var skipped []skippedLine

	for _, row := range rows[1:] {
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}

		name := getCSVField(row, headers, "name")
		rtype := strings.ToUpper(getCSVField(row, headers, "type"))
		// Reverse the export's formula-injection escaping so the stored
		// value is the operator's original text (see dnsops.SanitizeCSVField).
		content := dnsops.RestoreCSVField(getCSVField(row, headers, "content"))
		ttl := 3600
		if v, err := strconv.Atoi(getCSVField(row, headers, "ttl")); err == nil && v > 0 {
			ttl = v
		}
		priority := 0
		if v, err := strconv.Atoi(getCSVField(row, headers, "priority")); err == nil {
			priority = v
		}
		disabled := getCSVField(row, headers, "disabled") == "true"

		if name == "" || rtype == "" || content == "" {
			skipped = append(skipped, skippedLine{Line: strings.Join(row, ","), Reason: "missing required name, type or content field"})
			continue
		}

		// Validate before normalizing so an invalid row is reported with a
		// specific reason rather than a generic PowerDNS failure.
		// CSV content is bare (priority is a separate column). The name
		// is validated in its raw form (before the zone-relative resolution
		// below) so the apex shorthand "@" is accepted by ValidateRecordName.
		if verr := validateParsedRecord(rtype, name, content, priority, ttl); verr != nil {
			skipped = append(skipped, skippedLine{Line: strings.Join(row, ","), Reason: verr.Error()})
			continue
		}

		// Resolve the name against the zone like every other write path:
		// "www" → "www.<zone>.", "@" → "<zone>.", an already-absolute name
		// (trailing dot) is kept. The previous bare trailing-dot append
		// turned "www" into the TLD "www." and "@" into "@.", which
		// PowerDNS rejects — failing the whole PATCH.
		name = normalizeRecordName(name, zoneID)

		// Route through the same normalization pipeline as the web/API paths
		// so FQDN-target (CNAME/NS/PTR/…) and multi-FQDN-field (SOA/RP/…)
		// types get trailing dots, not just priority/quoted handling. A
		// priority divergence between embedded and column priority is
		// reported as a skipped row (with the conflict message), like every
		// other per-row validation failure — the remaining rows still import.
		csvContent, csvPriority, perr := prepareRecordContent(rtype, content, priority)
		if perr != nil {
			skipped = append(skipped, skippedLine{Line: strings.Join(row, ","), Reason: perr.Error()})
			continue
		}

		k := key{name, rtype}
		if _, exists := groups[k]; !exists {
			order = append(order, k)
			groupTTLs[k] = ttl
		}

		groups[k] = append(groups[k], models.RecordInfo{
			Content:  csvContent,
			Disabled: disabled,
			Priority: csvPriority,
		})

		if comment := dnsops.RestoreCSVField(getCSVField(row, headers, "comment")); comment != "" {
			groupComments[k] = appendIfMissing(groupComments[k], comment)
		}
	}

	rrsets := make([]models.RRSet, 0, len(order))
	for _, k := range order {
		items := parseCSVComments(groupComments[k])
		var patch *models.CommentPatch
		if len(items) > 0 {
			patch = &models.CommentPatch{Items: items}
		}
		rrsets = append(rrsets, models.RRSet{
			Name:     k.name,
			Type:     k.rtype,
			TTL:      groupTTLs[k],
			Records:  groups[k],
			Comments: patch,
		})
	}

	return rrsets, skipped, nil
}

// parseCSVComments turns the deduplicated per-RRSet comment cells collected by
// parseCSVZone into a Comment slice. Each cell may itself contain multiple
// comments separated by newlines (one comment per line, matching the web UI
// textarea convention).
func parseCSVComments(cells []string) []models.Comment {
	if len(cells) == 0 {
		return nil
	}
	var out []models.Comment
	for _, cell := range cells {
		for _, line := range strings.Split(cell, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			out = append(out, models.Comment{Content: line})
		}
	}
	return out
}

// appendIfMissing appends v to s only if no existing element equals v
// (preserving the original order). Returns s unchanged when v is already
// present or empty.
func appendIfMissing(s []string, v string) []string {
	if v == "" {
		return s
	}
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}

func getCSVField(row []string, headers map[string]int, name string) string {
	if idx, ok := headers[name]; ok && idx < len(row) {
		return strings.TrimSpace(row[idx])
	}
	return ""
}

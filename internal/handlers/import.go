package handlers

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// ImportZone handles file upload for zone import (BIND or CSV).
//
// Uses PowerDNS REPLACE semantics via CreateRecords: each name+type pair
// in the imported file replaces the existing RRSet if present, or creates
// it if absent. Records not in the import file are untouched. Within the
// same name+type, the import replaces the entire set of records — any
// extra existing records with that name+type are removed.
func (h *Handler) ImportZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")

	// #nosec G120 — Form size limited to 10MB via ParseMultipartForm argument
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.renderError(w, r, "Failed to parse upload: "+err.Error())
		return
	}

	file, header, err := r.FormFile("zonefile")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.renderError(w, r, "No file uploaded: "+err.Error())
		return
	}
	defer file.Close()

	format := r.FormValue("format")
	if format != "bind" && format != "csv" {
		format = detectFormat(header.Filename)
	}
	if format != "bind" && format != "csv" {
		w.WriteHeader(http.StatusBadRequest)
		h.renderError(w, r, "Could not detect format. Please select BIND or CSV.")
		return
	}

	var rrsets []models.RRSet
	switch format {
	case "bind":
		data, readErr := io.ReadAll(io.LimitReader(file, 10<<20))
		if readErr != nil {
			logger.Error("ImportZone: read failed", "zone", zoneID, "error", readErr)
			w.WriteHeader(http.StatusBadRequest)
			h.renderError(w, r, "Failed to read uploaded file")
			return
		}
		rrsets, err = parseBindZone(data, zoneID)
	case "csv":
		cr := csv.NewReader(file)
		rrsets, err = parseCSVZone(cr)
	}

	if err != nil {
		logger.Error("ImportZone: parse failed", "zone", zoneID, "format", format, "error", err)
		w.WriteHeader(http.StatusBadRequest)
		h.renderError(w, r, "Failed to parse file: "+err.Error())
		return
	}

	if len(rrsets) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		h.renderError(w, r, "No valid records found in file")
		return
	}

	if err := h.PDNS.CreateRecords(r.Context(), zoneID, rrsets); err != nil {
		logger.Error("ImportZone: CreateRecords failed", "zone", zoneID, "error", err)
		status := pdnsErrorHTTPStatus(err)
		w.WriteHeader(status)
		h.renderError(w, r, "Failed to create records: "+err.Error())
		return
	}

	user := middleware.GetUser(r)
	logger.Info("Zone imported", "zone", zoneID, "format", format, "count", len(rrsets), "user", user.Username)

	for _, rs := range rrsets {
		contents := make([]string, 0, len(rs.Records))
		for _, r := range rs.Records {
			contents = append(contents, r.Content)
		}
		details := fmt.Sprintf("Imported %s %s -> %s", rs.Type, rs.Name, strings.Join(contents, ", "))
		if _, err := h.DB.Exec(
			"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'import_zone', ?)",
			user.ID, zoneID, details,
		); err != nil {
			logger.Error("failed to log import_zone activity", "zone_id", zoneID, "error", err)
		}
	}

	// #nosec G710 — zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
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

// parseBindZone parses an RFC 1035 BIND zone file and returns RRSets.
func parseBindZone(data []byte, zoneID string) ([]models.RRSet, error) {
	origin := zoneID
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}
	defaultTTL := 3600

	lines := normalizeBindLines(string(data))
	raw := make([]bindRecord, 0)
	lastOwner := "" // owner of the previous record, for RFC 1035 inheritance

	for _, bl := range lines {
		line := bl.text
		upper := strings.ToUpper(line)

		if strings.HasPrefix(upper, "$ORIGIN ") {
			origin = strings.TrimSpace(line[8:])
			if !strings.HasSuffix(origin, ".") {
				origin += "."
			}
			continue
		}
		if strings.HasPrefix(upper, "$TTL ") {
			ttl, err := strconv.Atoi(strings.TrimSpace(line[5:]))
			if err == nil && ttl > 0 {
				defaultTTL = ttl
			}
			continue
		}
		if strings.HasPrefix(upper, "$INCLUDE") {
			continue
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
			continue
		}
		raw = append(raw, rec)
	}

	return groupBindRecords(raw), nil
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

	result := make([]bindLine, 0)
	inParen := false
	current := ""
	currentInherits := false

	for _, raw := range lines {
		// Detect owner inheritance before trimming, on the original line.
		leadingBlank := raw != "" && (raw[0] == ' ' || raw[0] == '\t')
		line := strings.TrimSpace(raw)

		commentIdx := -1
		inQuote := false
		for i := 0; i < len(line); i++ {
			if line[i] == '"' {
				inQuote = !inQuote
			}
			if line[i] == ';' && !inQuote {
				commentIdx = i
				break
			}
		}
		if commentIdx >= 0 {
			line = line[:commentIdx]
		}
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if !inParen {
			current = line
			currentInherits = leadingBlank
		} else {
			current += " " + line
		}

		opens := strings.Count(line, "(")
		closes := strings.Count(line, ")")

		if opens > 0 && !inParen {
			inParen = true
			current = strings.Replace(current, "(", "", 1)
		}

		if closes > opens && inParen {
			inParen = false
			current = strings.Replace(current, ")", "", 1)
		}

		if !inParen {
			current = strings.TrimSpace(current)
			if current != "" {
				result = append(result, bindLine{text: current, inheritsOwner: currentInherits})
			}
			current = ""
			currentInherits = false
		}
	}

	if inParen && strings.TrimSpace(current) != "" {
		current = strings.ReplaceAll(current, ")", "")
		result = append(result, bindLine{text: strings.TrimSpace(current), inheritsOwner: currentInherits})
	}

	return result
}

// errSkipBindLine marks a line that carries no usable record and must be
// dropped by the caller rather than turned into an empty (Name=="") RRSet.
var errSkipBindLine = errors.New("bind line has no record")

func parseBindLine(line, origin string, defaultTTL int) (bindRecord, error) {
	tokens := tokenizeBindLine(line)
	if len(tokens) < 2 {
		return bindRecord{}, errSkipBindLine
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
		return bindRecord{}, errSkipBindLine
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
			records = append(records, models.RecordInfo{
				Content:  r.data,
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

// parseCSVZone parses CSV zone data and returns RRSets.
func parseCSVZone(reader *csv.Reader) ([]models.RRSet, error) {
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, nil
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

	for _, row := range rows[1:] {
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}

		name := getCSVField(row, headers, "name")
		rtype := strings.ToUpper(getCSVField(row, headers, "type"))
		content := getCSVField(row, headers, "content")
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
			continue
		}

		if !strings.HasSuffix(name, ".") {
			name += "."
		}

		csvContent := content
		csvPriority := 0
		switch {
		case models.TypeHasPriority(rtype):
			csvContent = models.JoinPriority(rtype, priority, content)
		case models.TypeIsQuoted(rtype):
			csvContent = models.QuoteContent(rtype, content)
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

		if comment := getCSVField(row, headers, "comment"); comment != "" {
			groupComments[k] = appendIfMissing(groupComments[k], comment)
		}
	}

	rrsets := make([]models.RRSet, 0, len(order))
	for _, k := range order {
		rrsets = append(rrsets, models.RRSet{
			Name:     k.name,
			Type:     k.rtype,
			TTL:      groupTTLs[k],
			Records:  groups[k],
			Comments: parseCSVComments(groupComments[k]),
		})
	}

	return rrsets, nil
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

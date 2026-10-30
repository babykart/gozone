package dnsops

import (
	"context"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"

	"github.com/babykart/gozone/internal/models"
)

// ExportZone renders a whole zone for export: it authorizes the caller,
// fetches the zone metadata and records from PowerDNS, and renders them in
// the requested format ("bind" = RFC 1035 zone file, disabled records
// omitted; "csv" = one row per record, disabled records flagged). It
// returns the body and the record count the format reports (records for
// csv, enabled records for bind). Upstream failures are returned as-is so
// each transport maps its own status/code. Every transport — web export,
// REST export endpoint, MCP export_zone tool and gozone://zones/{zone}
// resource — goes through this method so their output is byte-identical.
func (s *Service) ExportZone(ctx context.Context, user *models.User, zoneID, format string) (string, int, error) {
	if format != "bind" && format != "csv" {
		return "", 0, fmt.Errorf("unknown export format %q: use \"bind\" or \"csv\"", format)
	}
	if err := s.authorizeZone(ctx, user, zoneID); err != nil {
		return "", 0, err
	}
	zone, err := s.PDNS.GetZone(ctx, zoneID)
	if err != nil {
		return "", 0, err
	}
	records, err := s.PDNS.ListRecords(ctx, zoneID)
	if err != nil {
		return "", 0, err
	}
	recordCount := 0
	if format == "csv" {
		for _, rr := range records {
			recordCount += len(rr.Records)
		}
		return RenderZoneCSV(zone, records), recordCount, nil
	}
	for _, rr := range records {
		for _, rec := range rr.Records {
			if !rec.Disabled {
				recordCount++
			}
		}
	}
	return RenderZoneFile(zone, records), recordCount, nil
}

// RelativeBindName converts an absolute record name to relative form for
// BIND output.
func RelativeBindName(name, origin string) string {
	originNorm := strings.TrimSuffix(origin, ".")
	nameNorm := strings.TrimSuffix(name, ".")

	if nameNorm == originNorm {
		return "@"
	}

	suffix := "." + originNorm
	if strings.HasSuffix(nameNorm, suffix) {
		return strings.TrimSuffix(nameNorm, suffix)
	}

	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// FormatRecordContent renders one record's wire content for a BIND zone
// file: MX/SRV re-emit their priority (the wire content carries it embedded;
// RecordInfo.Priority is authoritative when non-zero), quoted-field types
// pass through, and TXT/SPF keep their wire quoting.
func FormatRecordContent(rtype, content string, priority int) string {
	if models.TypeHasPriority(rtype) {
		return models.JoinPriority(rtype, priority, content)
	}
	if models.TypeHasQuotedFields(rtype) {
		// CAA/HINFO/URI already arrive in wire form (values quoted); the
		// pass-through keeps already-quoted fields intact and is a no-op in
		// practice, kept for symmetry with PrepareRecordContent.
		return models.QuoteContentFields(content, models.QuotedFieldIndices(rtype))
	}
	return models.QuoteContent(rtype, content)
}

// FindSOATTL returns the TTL from the first SOA RRSet, or 3600 as default.
func FindSOATTL(records []models.RRSet) int {
	for _, rr := range records {
		if rr.Type == "SOA" && rr.TTL > 0 {
			return rr.TTL
		}
	}
	return 3600
}

// SortRRSets orders records: SOA first, then NS, then others alphabetically
// by name. The comparator is a strict weak ordering: two records of the same
// priority are resolved by name+type, never by returning true in both
// directions — an inconsistent comparator hands sort an ill-defined problem
// (and pdqsort may panic on some inputs).
func SortRRSets(records []models.RRSet) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Type == "SOA" && b.Type != "SOA" {
			return true
		}
		if b.Type == "SOA" && a.Type != "SOA" {
			return false
		}
		if a.Type == "NS" && b.Type != "NS" {
			return true
		}
		if b.Type == "NS" && a.Type != "NS" {
			return false
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Type < b.Type
	})
}

// RenderZoneFile renders a zone and its RRSets as an RFC 1035 BIND zone
// file: $ORIGIN/$TTL header from the SOA, records sorted (SOA, NS, then by
// name), names relative to the origin, per-record TTLs omitted when they
// match the $TTL default, and disabled records skipped.
//
// The rendering is shared by the web export (handlers.ExportZone) and the
// MCP resource gozone://zones/{zone} so both produce byte-identical output.
func RenderZoneFile(zone *models.Zone, records []models.RRSet) string {
	origin := zone.Name
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}

	records = append([]models.RRSet(nil), records...)
	SortRRSets(records)

	defaultTTL := FindSOATTL(records)

	var b strings.Builder
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	fmt.Fprintf(&b, "$TTL %d\n\n", defaultTTL)

	for _, rr := range records {
		for _, rec := range rr.Records {
			if rec.Disabled {
				continue
			}

			name := RelativeBindName(rr.Name, origin)
			ttl := rr.TTL
			if ttl == 0 {
				ttl = defaultTTL
			}

			if ttl != defaultTTL {
				fmt.Fprintf(&b, "%s %d", name, ttl)
			} else {
				fmt.Fprint(&b, name)
			}

			fmt.Fprintf(&b, " IN %s", rr.Type)
			content := FormatRecordContent(rr.Type, rec.Content, rec.Priority)
			fmt.Fprintf(&b, " %s\n", content)
		}
	}
	return b.String()
}

// RenderZoneCSV renders a zone and its RRSets as CSV: one row per record
// (including disabled ones, flagged in the disabled column), with the
// canonical header "name,type,content,ttl,priority,disabled,comment".
// Multi-string TXT/SPF content keeps its wire form; single-string values are
// unquoted so encoding/csv applies its own quoting (see UnquoteContent).
//
// The rendering is shared by the web export (handlers.ExportZone) and the
// MCP export_zone tool so both produce byte-identical output. Free-text
// cells (content, comments) pass through SanitizeCSVField: lines starting
// with a spreadsheet formula trigger (= + - @) gain an escape prefix the
// CSV importer reverses, so opening an export in Excel or LibreOffice can
// never evaluate a record or comment as a formula.
func RenderZoneCSV(zone *models.Zone, records []models.RRSet) string {
	var b strings.Builder
	writer := csv.NewWriter(&b)
	// #nosec G104 — writing into a strings.Builder cannot fail
	_ = writer.Write([]string{"name", "type", "content", "ttl", "priority", "disabled", "comment"})

	// Multiple comments per RRSet are joined with newlines so the cell can
	// round-trip via the standard CSV embedded-newline quoting. The same
	// value is repeated on every row of the RRSet for consistency.
	joinedComments := func(comments *models.CommentPatch) string {
		if comments == nil || len(comments.Items) == 0 {
			return ""
		}
		parts := make([]string, len(comments.Items))
		for i, c := range comments.Items {
			parts[i] = c.Content
		}
		return strings.Join(parts, "\n")
	}

	for _, rr := range records {
		commentCell := joinedComments(rr.Comments)
		for _, rec := range rr.Records {
			ttl := rr.TTL
			disabled := "false"
			if rec.Disabled {
				disabled = "true"
			}
			priority := 0
			if models.TypeHasPriority(rr.Type) {
				priority = rec.Priority
			}
			// Strip the PDNS TXT/SPF quotes of a single-string value so
			// the CSV writer can apply proper quoting itself. Multi-string
			// values ("part1" "part2") are exported in wire form: their
			// outer quotes are string delimiters, and stripping them would
			// corrupt the round trip.
			content := models.UnquoteContent(rr.Type, rec.Content)
			// Neutralize spreadsheet formula triggers in the free-text
			// cells: a value whose line begins with = + - or @ would be
			// evaluated when an operator opens the export in Excel or
			// LibreOffice. The importer reverses the escaping (see
			// SanitizeCSVField), so the round trip stays lossless.
			// #nosec G104 — writing into a strings.Builder cannot fail
			_ = writer.Write([]string{
				rr.Name,
				rr.Type,
				SanitizeCSVField(content),
				fmt.Sprintf("%d", ttl),
				fmt.Sprintf("%d", priority),
				disabled,
				SanitizeCSVField(commentCell),
			})
		}
	}
	writer.Flush()
	return b.String()
}

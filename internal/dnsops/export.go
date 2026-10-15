package dnsops

import (
	"fmt"
	"sort"
	"strings"

	"github.com/babykart/gozone/internal/models"
)

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

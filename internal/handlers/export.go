package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// ExportZone outputs zone records in BIND or CSV format.
func (h *Handler) ExportZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	format := r.URL.Query().Get("format")

	if format != "bind" && format != "csv" {
		h.renderError(w, r, "Invalid format. Use ?format=bind or ?format=csv")
		return
	}

	zone, err := h.PDNS.GetZone(r.Context(), zoneID)
	if err != nil {
		logger.Error("ExportZone: GetZone failed", "zone", zoneID, "error", err)
		h.renderErrorStatus(w, r, http.StatusInternalServerError, "Failed to get zone")
		return
	}

	records, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		logger.Error("ExportZone: ListRecords failed", "zone", zoneID, "error", err)
		h.renderErrorStatus(w, r, http.StatusInternalServerError, "Failed to list records")
		return
	}

	user := middleware.GetUser(r)
	logger.Info("Zone exported", "zone", zoneID, "format", format, "user", user.Username)

	switch format {
	case "bind":
		h.exportBind(w, zone, records)
	case "csv":
		h.exportCSV(w, zone, records)
	}
}

// relativeBindName converts an absolute record name to relative form for BIND output.
func relativeBindName(name, origin string) string {
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

// exportBind writes records in RFC 1035 BIND zone file format.
func (h *Handler) exportBind(w http.ResponseWriter, zone *models.Zone, records []models.RRSet) {
	origin := zone.Name
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}

	filename := fmt.Sprintf("%s.zone", strings.TrimSuffix(origin, "."))
	w.Header().Set("Content-Type", "text/plain")
	// #nosec G601 — filename derived from PowerDNS zone name (server-controlled)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	sortRRSets(records)

	defaultTTL := findSOATTL(records)

	// #nosec G705 — zone data from PowerDNS server, rendered as text/plain
	fmt.Fprintf(w, "$ORIGIN %s\n", origin)
	// #nosec G705 — zone data from PowerDNS server, rendered as text/plain
	fmt.Fprintf(w, "$TTL %d\n", defaultTTL)
	fmt.Fprintln(w)

	for _, rr := range records {
		for _, rec := range rr.Records {
			if rec.Disabled {
				continue
			}

			name := relativeBindName(rr.Name, origin)
			ttl := rr.TTL
			if ttl == 0 {
				ttl = defaultTTL
			}

			if ttl != defaultTTL {
				// #nosec G705 — zone data from PowerDNS server, rendered as text/plain
				fmt.Fprintf(w, "%s %d", name, ttl)
			} else {
				// #nosec G705 — zone data from PowerDNS server, rendered as text/plain
				fmt.Fprint(w, name)
			}

			fmt.Fprintf(w, " IN %s", rr.Type)

			content := formatRecordContent(rr.Type, rec.Content, rec.Priority)

			// #nosec G705 — zone data from PowerDNS server, rendered as text/plain
			fmt.Fprintf(w, " %s\n", content)
		}
	}
}

func formatRecordContent(rtype, content string, priority int) string {
	if models.TypeHasPriority(rtype) {
		return models.JoinPriority(rtype, priority, content)
	}
	return models.QuoteContent(rtype, content)
}

// exportCSV writes records in CSV format.
func (h *Handler) exportCSV(w http.ResponseWriter, zone *models.Zone, records []models.RRSet) {
	filename := fmt.Sprintf("%s.csv", strings.TrimSuffix(zone.Name, "."))
	w.Header().Set("Content-Type", "text/csv")
	// #nosec G601 — filename derived from PowerDNS zone name (server-controlled)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	writer := csv.NewWriter(w)
	// #nosec G104 — csv.Writer.Write errors in HTTP handler context; Flush at end reports accumulated errors
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
			// Strip the PDNS TXT/SPF quotes so encoding/csv.Writer can apply
			// proper CSV quoting itself.
			content := models.UnquoteContent(rr.Type, rec.Content)
			// #nosec G104 — csv.Writer.Write errors in HTTP handler context; Flush reports cumulative errors
			_ = writer.Write([]string{
				rr.Name,
				rr.Type,
				content,
				fmt.Sprintf("%d", ttl),
				fmt.Sprintf("%d", priority),
				disabled,
				commentCell,
			})
		}
	}
	writer.Flush()
}

// findSOATTL returns the TTL from the first SOA RRSet, or 3600 as default.
func findSOATTL(records []models.RRSet) int {
	for _, rr := range records {
		if rr.Type == "SOA" && rr.TTL > 0 {
			return rr.TTL
		}
	}
	return 3600
}

// sortRRSets orders records: SOA first, then NS, then others alphabetically by name.
func sortRRSets(records []models.RRSet) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Type == "SOA" {
			return true
		}
		if b.Type == "SOA" {
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

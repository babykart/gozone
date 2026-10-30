package handlers

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/dnsops"
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
		status, msg := pdnsPageStatus(err, "Zone not found")
		logger.Error("ExportZone: GetZone failed", "zone", zoneID, "error", err)
		h.renderErrorStatus(w, r, status, msg)
		return
	}

	records, err := h.PDNS.ListRecords(r.Context(), zoneID)
	if err != nil {
		logger.Error("ExportZone: ListRecords failed", "zone", zoneID, "error", err)
		h.renderInternalError(w, r, "Failed to list records", err)
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

// relativeBindName converts an absolute record name to relative form for
// BIND output; the implementation lives in the dnsops service layer (shared
// with the MCP zone resource).
func relativeBindName(name, origin string) string {
	return dnsops.RelativeBindName(name, origin)
}

// exportBind writes records in RFC 1035 BIND zone file format. The rendering
// lives in the dnsops service layer (dnsops.RenderZoneFile) so the web
// export and the MCP gozone://zones/{zone} resource produce byte-identical
// output.
func (h *Handler) exportBind(w http.ResponseWriter, zone *models.Zone, records []models.RRSet) {
	origin := zone.Name
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}

	filename := fmt.Sprintf("%s.zone", strings.TrimSuffix(origin, "."))
	w.Header().Set("Content-Type", "text/plain")
	// #nosec G601 — filename derived from PowerDNS zone name (server-controlled)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	// #nosec G104 — writing the export to the ResponseWriter; an error here
	// only means the client went away mid-transfer.
	// #nosec G705 -- explicit non-HTML download (text/plain + attachment + nosniff)
	_, _ = io.WriteString(w, dnsops.RenderZoneFile(zone, records))
}

// formatRecordContent renders one record's wire content for a BIND zone
// file; the implementation lives in the dnsops service layer.
func formatRecordContent(rtype, content string, priority int) string {
	return dnsops.FormatRecordContent(rtype, content, priority)
}

// exportCSV writes records in CSV format. The rendering lives in the dnsops
// service layer (dnsops.RenderZoneCSV) so the web export and the MCP
// export_zone tool produce byte-identical output.
func (h *Handler) exportCSV(w http.ResponseWriter, zone *models.Zone, records []models.RRSet) {
	filename := fmt.Sprintf("%s.csv", strings.TrimSuffix(zone.Name, "."))
	w.Header().Set("Content-Type", "text/csv")
	// #nosec G601 — filename derived from PowerDNS zone name (server-controlled)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	// #nosec G104 — writing the export to the ResponseWriter; an error here
	// only means the client went away mid-transfer.
	// #nosec G705 -- explicit non-HTML download (text/csv + attachment + nosniff)
	_, _ = io.WriteString(w, dnsops.RenderZoneCSV(zone, records))
}

// findSOATTL returns the TTL from the first SOA RRSet, or 3600 as default;
// the implementation lives in the dnsops service layer.
func findSOATTL(records []models.RRSet) int {
	return dnsops.FindSOATTL(records)
}

// sortRRSets orders records: SOA first, then NS, then others alphabetically
// by name; the implementation lives in the dnsops service layer
// (dnsops.SortRRSets).
func sortRRSets(records []models.RRSet) {
	dnsops.SortRRSets(records)
}

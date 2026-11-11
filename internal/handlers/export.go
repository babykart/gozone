package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
)

// ExportZone outputs zone records in BIND or CSV format. The authorization,
// fetch and rendering all go through the dnsops service layer
// (dnsops.Service.ExportZone), which re-checks the zone grant fail-closed
// before any PowerDNS call and renders byte-identical output for the REST
// export endpoint and the MCP resource.
func (h *Handler) ExportZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	format := r.URL.Query().Get("format")

	if format != "bind" && format != "csv" {
		h.renderError(w, r, "Invalid format. Use ?format=bind or ?format=csv")
		return
	}

	body, _, err := h.Ops.ExportZone(r.Context(), middleware.GetUser(r), zoneID, format)
	if err != nil {
		// Mirror writeServiceAuthzError: a genuine denial is a 403 rendered
		// before any pdnsPageStatus mapping; an authorization-lookup fault
		// (StageError{StageZoneAccess}, fail-closed) stays a 500 via the
		// default path below.
		if errors.Is(err, dnsops.ErrForbidden) {
			logger.Warn("ExportZone: access denied", "zone", zoneID)
			h.renderErrorStatus(w, r, http.StatusForbidden, "Access to this zone is denied.")
			return
		}
		status, msg := pdnsPageStatus(err, "Zone not found")
		logger.Error("ExportZone failed", "zone", zoneID, "format", format, "error", err)
		h.renderErrorStatus(w, r, status, msg)
		return
	}

	user := middleware.GetUser(r)
	logger.Info("Zone exported", "zone", zoneID, "format", format, "user", user.Username)

	ext := "zone"
	contentType := "text/plain"
	if format == "csv" {
		ext = "csv"
		contentType = "text/csv"
	}
	filename := fmt.Sprintf("%s.%s", strings.TrimSuffix(zoneID, "."), ext)
	w.Header().Set("Content-Type", contentType)
	// #nosec G601 — filename derived from the zone ID (server-controlled)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	// #nosec G104 — writing the export to the ResponseWriter; an error here
	// only means the client went away mid-transfer.
	// #nosec G705 -- explicit non-HTML download (attachment disposition)
	_, _ = io.WriteString(w, body)
}

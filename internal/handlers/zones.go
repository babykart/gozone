package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// ListZones renders the zones listing page with record counts per zone (GET /zones).
func (h *Handler) ListZones(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	zones, err := h.PDNS.ListZonesWithInfo()
	if err != nil {
		h.renderError(w, r, "Failed to fetch zones: "+err.Error())
		return
	}

	data := map[string]interface{}{
		"Title":   "Zones - GoZone",
		"User":    user,
		"Zones":   zones,
		"IsAdmin": user.IsAdmin(),
	}
	h.render(w, r, "zones.html", data)
}

// CreateZonePage renders the zone creation form (GET /zones/new).
func (h *Handler) CreateZonePage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	data := map[string]interface{}{
		"Title":    "Create Zone - GoZone",
		"User":     user,
		"DNSTypes": []string{"Native", "Master", "Slave"},
	}
	h.render(w, r, "zone_create.html", data)
}

// CreateZone creates a new PowerDNS zone from form data (POST /zones/create).
//
// Requires admin role. The zone name, kind, and optional comma-separated
// nameservers are submitted via form values.
func (h *Handler) CreateZone(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	nameservers := strings.TrimSpace(r.FormValue("nameservers"))

	if name == "" {
		h.renderError(w, r, "Zone name is required")
		return
	}

	if err := validators.ValidateDomainName(name); err != nil {
		h.renderError(w, r, "Invalid zone name: "+err.Error())
		return
	}

	if kind == "" {
		kind = "Native"
	}

	req := models.ZoneCreateRequest{
		Name: name,
		Kind: kind,
	}

	if nameservers != "" {
		for _, ns := range strings.Split(nameservers, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				req.Nameservers = append(req.Nameservers, ns)
			}
		}
	}

	zone, err := h.PDNS.CreateZone(req)
	if err != nil {
		h.renderError(w, r, "Failed to create zone: "+err.Error())
		return
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_zone', ?)",
		user.ID, zone.ID, fmt.Sprintf("Created zone %s (kind: %s)", zone.Name, zone.Kind),
	)

	http.Redirect(w, r, "/zones", http.StatusSeeOther)
}

// DeleteZone deletes a zone by zone_id form value (POST /zones/delete).
//
// Requires admin role.
func (h *Handler) DeleteZone(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}

	zoneID := r.FormValue("zone_id")
	if zoneID == "" {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}

	if err := h.PDNS.DeleteZone(zoneID); err != nil {
		h.renderError(w, r, "Failed to delete zone: "+err.Error())
		return
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'delete_zone', ?)",
		user.ID, zoneID, fmt.Sprintf("Deleted zone %s", zoneID),
	)

	http.Redirect(w, r, "/zones", http.StatusSeeOther)
}

// ViewZone renders a zone detail page with its records, activity logs, and
// PowerDNS version (GET /zones/{zone_id}).
func (h *Handler) ViewZone(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	zoneID := r.PathValue("zone_id")

	zone, err := h.PDNS.GetZone(zoneID)
	if err != nil {
		h.renderError(w, r, "Zone not found: "+err.Error())
		return
	}

	records, err := h.PDNS.ListRecords(zoneID)
	if err != nil {
		h.renderError(w, r, "Failed to fetch records: "+err.Error())
		return
	}

	// Get activity logs for this zone
	logs := h.getZoneActivityLogs(zoneID)

	// Get server info for version
	server, _ := h.PDNS.GetServer()
	pdnsVersion := "unknown"
	if server != nil {
		pdnsVersion = server.Version
	}

	data := map[string]interface{}{
		"Title":       zone.Name + " - GoZone",
		"User":        user,
		"Zone":        zone,
		"Records":     records,
		"Logs":        logs,
		"PDNSVersion": pdnsVersion,
		"RecordTypes": GetRecordTypes(),
		"IsAdmin":     user.IsAdmin(),
	}
	h.render(w, r, "zone_view.html", data)
}

// RectifyZone triggers DNSSEC rectification for a zone (POST /zones/{zone_id}/rectify).
//
// Requires admin role. After rectification, redirects back to the zone view.
func (h *Handler) RectifyZone(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	zoneID := r.PathValue("zone_id")
	if err := h.PDNS.RectifyZone(zoneID); err != nil {
		h.renderError(w, r, "Rectify failed: "+err.Error())
		return
	}

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'rectify_zone', ?)",
		user.ID, zoneID, fmt.Sprintf("Rectified zone %s", zoneID),
	)

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// NotifyZone sends a NOTIFY message to slave servers for a zone (POST /zones/{zone_id}/notify).
//
// Requires admin role. Redirects back to the zone view after completion.
func (h *Handler) NotifyZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	if err := h.PDNS.NotifySlaves(zoneID); err != nil {
		h.renderError(w, r, "Notify failed: "+err.Error())
		return
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

func (h *Handler) getZoneActivityLogs(zoneID string) []models.ActivityLog {
	rows, err := h.DB.Query(
		`SELECT al.id, al.user_id, al.zone_id, al.action, al.details, al.created_at, u.username
		 FROM activity_logs al
		 LEFT JOIN users u ON al.user_id = u.id
		 WHERE al.zone_id = ?
		 ORDER BY al.created_at DESC
		 LIMIT 50`, zoneID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var logs []models.ActivityLog
	for rows.Next() {
		var log models.ActivityLog
		var username sql.NullString
		rows.Scan(&log.ID, &log.UserID, &log.ZoneID, &log.Action, &log.Details, &log.CreatedAt, &username)
		logs = append(logs, log)
	}
	return logs
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, msg string) {
	data := map[string]interface{}{
		"Title":   "Error - GoZone",
		"Message": msg,
	}
	h.render(w, r, "error.html", data)
}

// GetRecordTypes returns the list of common DNS record types.
func GetRecordTypes() []string {
	return []string{
		"A", "AAAA", "AFSDB", "ALIAS", "CAA", "CERT", "CNAME",
		"DNSKEY", "DS", "HINFO", "KEY", "LOC", "MX", "NAPTR",
		"NS", "NSEC", "NSEC3", "NSEC3PARAM", "OPENPGPKEY", "PTR",
		"RP", "RRSIG", "SOA", "SPF", "SRV", "SSHFP", "TLSA",
		"TXT", "URI",
	}
}

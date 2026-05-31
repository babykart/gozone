package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// PageInfo holds pagination state for template rendering.
type PageInfo struct {
	Current    int
	PerPage    int
	TotalPages int
	Total      int
}

// paginate slices a slice into a page and returns the pagination info.
func paginate[T any](items []T, page, perPage int) ([]T, PageInfo) {
	total := len(items)
	totalPages := 0
	if perPage > 0 {
		totalPages = (total + perPage - 1) / perPage
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages && totalPages > 0 {
		page = totalPages
	}
	start := (page - 1) * perPage
	if start >= total || perPage <= 0 {
		return nil, PageInfo{Current: page, PerPage: perPage, TotalPages: totalPages, Total: total}
	}
	end := start + perPage
	if end > total {
		end = total
	}
	return items[start:end], PageInfo{Current: page, PerPage: perPage, TotalPages: totalPages, Total: total}
}

// ListZones renders the zones listing page with record counts per zone (GET /zones).
func (h *Handler) ListZones(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	zones, err := h.PDNS.ListZonesWithInfo()
	if err != nil {
		h.renderError(w, r, "Failed to fetch zones: "+err.Error())
		return
	}

	zones, _ = h.filterZonesWithInfoForUser(r, zones)
	if zones == nil {
		zones = []models.ZoneWithInfo{}
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	paginated, pageInfo := paginate(zones, page, 10)

	data := map[string]interface{}{
		"Title":    "Zones - GoZone",
		"User":     user,
		"Zones":    paginated,
		"PageInfo": pageInfo,
		"IsAdmin":  user.IsAdmin(),
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

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_zone', ?)",
		user.ID, zone.ID, fmt.Sprintf("Created zone %s (kind: %s)", zone.Name, zone.Kind),
	); err != nil {
		logger.Error("failed to log create_zone activity", "zone_id", zone.ID, "error", err)
	}

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

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'delete_zone', ?)",
		user.ID, zoneID, fmt.Sprintf("Deleted zone %s", zoneID),
	); err != nil {
		logger.Error("failed to log delete_zone activity", "zone_id", zoneID, "error", err)
	}

	http.Redirect(w, r, "/zones", http.StatusSeeOther)
}

// ViewZone renders a zone detail page with its records, activity logs, and
// metadata (GET /zones/{zone_id}).
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

	recordPage, _ := strconv.Atoi(r.URL.Query().Get("page"))
	paginatedRecords, recordPageInfo := paginate(records, recordPage, 10)

	// Get zone metadata
	metadata, _ := h.PDNS.GetMetadata(zoneID)

	// Get activity logs for this zone
	logs := h.getZoneActivityLogs(zoneID)

	// Get server info for version
	server, _ := h.PDNS.GetServer()
	pdnsVersion := "unknown"
	if server != nil {
		pdnsVersion = server.Version
	}

	data := map[string]interface{}{
		"Title":           zone.Name + " - GoZone",
		"User":            user,
		"Zone":            zone,
		"Records":         paginatedRecords,
		"RecordPageInfo":  recordPageInfo,
		"MetaData":        metadata,
		"Logs":            logs,
		"PDNSVersion":     pdnsVersion,
		"RecordTypes":     GetRecordTypes(),
		"MetaKinds":       GetMetadataKinds(),
		"IsAdmin":         user.IsAdmin(),
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

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'rectify_zone', ?)",
		user.ID, zoneID, fmt.Sprintf("Rectified zone %s", zoneID),
	); err != nil {
		logger.Error("failed to log rectify_zone activity", "zone_id", zoneID, "error", err)
	}

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

// CreateMetadata creates a zone metadata entry (POST /zones/{zone_id}/metadata/create).
//
// Requires admin role. The kind and values are submitted via form values.
// Redirects back to the zone view on success.
func (h *Handler) CreateMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}

	zoneID := r.PathValue("zone_id")
	kind := strings.TrimSpace(r.FormValue("kind"))
	valuesRaw := strings.TrimSpace(r.FormValue("values"))

	if kind == "" {
		h.renderError(w, r, "Metadata kind is required")
		return
	}
	if valuesRaw == "" {
		h.renderError(w, r, "At least one value is required")
		return
	}

	var values []string
	for _, v := range strings.Split(valuesRaw, "\n") {
		v = strings.TrimSpace(v)
		if v != "" {
			values = append(values, v)
		}
	}

	if len(values) == 0 {
		h.renderError(w, r, "At least one non-empty value is required")
		return
	}

	meta := models.Metadata{
		Kind:     kind,
		Metadata: values,
	}

	if err := h.PDNS.SetMetadata(zoneID, meta); err != nil {
		h.renderError(w, r, "Failed to set metadata: "+err.Error())
		return
	}

	user := middleware.GetUser(r)
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_metadata', ?)",
		user.ID, zoneID, fmt.Sprintf("Set metadata %s on zone %s", kind, zoneID),
	); err != nil {
		logger.Error("failed to log create_metadata activity", "zone_id", zoneID, "kind", kind, "error", err)
	}

	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// DeleteMetadata removes a zone metadata entry (POST /zones/{zone_id}/metadata/delete).
//
// Requires admin role. The kind is submitted via form value.
// Redirects back to the zone view on success.
func (h *Handler) DeleteMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}

	zoneID := r.PathValue("zone_id")
	kind := strings.TrimSpace(r.FormValue("kind"))

	if kind == "" {
		h.renderError(w, r, "Metadata kind is required")
		return
	}

	if err := h.PDNS.DeleteMetadata(zoneID, kind); err != nil {
		h.renderError(w, r, "Failed to delete metadata: "+err.Error())
		return
	}

	user := middleware.GetUser(r)
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'delete_metadata', ?)",
		user.ID, zoneID, fmt.Sprintf("Deleted metadata %s from zone %s", kind, zoneID),
	); err != nil {
		logger.Error("failed to log delete_metadata activity", "zone_id", zoneID, "kind", kind, "error", err)
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
		if err := rows.Scan(&log.ID, &log.UserID, &log.ZoneID, &log.Action, &log.Details, &log.CreatedAt, &username); err != nil {
			logger.Error("failed to scan activity log row", "zone_id", zoneID, "error", err)
			continue
		}
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for zone activity logs", "zone_id", zoneID, "error", err)
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

// GetMetadataKinds returns the list of common PowerDNS zone metadata kinds.
func GetMetadataKinds() []string {
	return []string{
		"ALLOW-AXFR-FROM",
		"ALSO-NOTIFY",
		"AXFR-SOURCE",
		"FORWARD-DNSSEC",
		"GSS-ALLOW-AXFR-PRINCIPALS",
		"LUA-AXFR-SCRIPT",
		"NSEC3NARROW",
		"NSEC3PARAM",
		"PRESIGNED",
		"PUBLISH-CDNSKEY",
		"PUBLISH-CDS",
		"SOA-EDIT",
		"SOA-EDIT-API",
		"TSIG-ALLOW-AXFR",
	}
}

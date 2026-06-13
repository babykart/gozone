package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"sort"
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
// When perPage is 0 or negative, all items are returned as a single page.
func paginate[T any](items []T, page, perPage int) ([]T, PageInfo) {
	total := len(items)
	totalPages := 0
	if perPage > 0 {
		totalPages = (total + perPage - 1) / perPage
	} else {
		perPage = 0
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages && totalPages > 0 {
		page = totalPages
	}
	if perPage <= 0 {
		return items, PageInfo{Current: 1, PerPage: 0, TotalPages: 1, Total: total}
	}
	start := (page - 1) * perPage
	if start >= total {
		return nil, PageInfo{Current: page, PerPage: perPage, TotalPages: totalPages, Total: total}
	}
	end := start + perPage
	if end > total {
		end = total
	}
	return items[start:end], PageInfo{Current: page, PerPage: perPage, TotalPages: totalPages, Total: total}
}

// parsePaginationParams extracts the page and perPage query parameters.
// page defaults to 1 if missing or invalid; perPage uses the provided default
// unless a valid non-negative value is supplied.
func parsePaginationParams(r *http.Request, defaultPerPage int) (page, perPage int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage = defaultPerPage
	if pp := r.URL.Query().Get("perPage"); pp != "" {
		if n, err := strconv.Atoi(pp); err == nil && n >= 0 {
			perPage = n
		}
	}
	return page, perPage
}

// ListZones renders the zones listing page with record counts per zone (GET /zones).
func (h *Handler) ListZones(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	zones, err := h.PDNS.ListZonesWithInfo(r.Context())
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch zones", err)
		return
	}

	zones, _ = h.filterZonesWithInfoForUser(r, zones)
	if zones == nil {
		zones = []models.ZoneWithInfo{}
	}

	search := strings.TrimSpace(r.URL.Query().Get("search"))
	if search != "" {
		searchLower := strings.ToLower(search)
		var filtered []models.ZoneWithInfo
		for _, z := range zones {
			if strings.Contains(strings.ToLower(z.Zone.Name), searchLower) {
				filtered = append(filtered, z)
			}
		}
		zones = filtered
		if zones == nil {
			zones = []models.ZoneWithInfo{}
		}
	}

	page, perPage := parsePaginationParams(r, 10)
	paginated, pageInfo := paginate(zones, page, perPage)

	data := map[string]interface{}{
		"Title":    "Zones - GoZone",
		"User":     user,
		"Zones":    paginated,
		"PageInfo": pageInfo,
		"Search":   search,
		"IsAdmin":  user.IsAdmin(),
	}
	h.render(w, r, "zones.html", data)
}

// CreateZonePage renders the zone creation form (GET /zones/new).
func (h *Handler) CreateZonePage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	templates, _ := h.getAllTemplates()
	data := map[string]interface{}{
		"Title":        "Create Zone - GoZone",
		"User":         user,
		"DNSTypes":     []string{"Native", "Master", "Slave"},
		"Templates":    templates,
		"TemplateVars": TemplateVariables,
	}
	h.render(w, r, "zone_create.html", data)
}

// CreateZone creates a new PowerDNS zone from form data (POST /zones/create).
//
// Requires admin role. The zone name, kind, and optional comma-separated
// nameservers are submitted via form values.
func (h *Handler) CreateZone(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

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

	if err := validators.ValidateZoneKind(kind); err != nil {
		h.renderError(w, r, "Invalid zone kind: "+err.Error())
		return
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

	zone, err := h.PDNS.CreateZone(r.Context(), req)
	if err != nil {
		h.renderInternalError(w, r, "Failed to create zone", err)
		return
	}

	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_zone', ?)",
		user.ID, zone.ID, fmt.Sprintf("Created zone %s (kind: %s)", zone.Name, zone.Kind),
	); err != nil {
		logger.Error("failed to log create_zone activity", "zone_id", zone.ID, "error", err)
	}

	// Apply template if selected
	if templateIDStr := strings.TrimSpace(r.FormValue("template_id")); templateIDStr != "" {
		if templateID, err := strconv.ParseInt(templateIDStr, 10, 64); err == nil {
			records := h.getTemplateRecords(templateID)
			if len(records) > 0 {
				vars := h.collectTemplateVars(r)
				if vars["ZONE"] == "" {
					vars["ZONE"] = zone.Name
				}
				rrsets, err := h.substituteTemplateRecords(zone.ID, records, vars)
				if err == nil {
					err = h.PDNS.CreateRecords(r.Context(), zone.ID, rrsets)
				}
				if err != nil {
					// The zone was created; only the template could not be
					// applied. Surface it instead of redirecting to success.
					h.renderInternalError(w, r,
						fmt.Sprintf("Zone %s was created, but applying the template failed. Add records manually.", zone.Name),
						err)
					return
				}
			}
		}
	}

	http.Redirect(w, r, "/zones", http.StatusSeeOther)
}

// DeleteZone deletes a zone by zone_id form value (POST /zones/delete).
//
// Requires admin role.
func (h *Handler) DeleteZone(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	zoneID := r.FormValue("zone_id")
	if zoneID == "" {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}

	if err := h.PDNS.DeleteZone(r.Context(), zoneID); err != nil {
		h.renderInternalError(w, r, "Failed to delete zone", err)
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

	// GetZone and ListRecords share the same path dependency (zoneID) but are
	// independent of each other. GetMetadata and GetServer are also independent.
	// Run all four concurrently to reduce total latency from ~4× RTT to ~1× RTT.
	type zoneRes struct {
		v   *models.Zone
		err error
	}
	type recordsRes struct {
		v   []models.RRSet
		err error
	}
	zoneCh := make(chan zoneRes, 1)
	recordsCh := make(chan recordsRes, 1)
	metadataCh := make(chan []models.Metadata, 1)
	serverCh := make(chan *models.ServerInfo, 1)
	cryptoCh := make(chan []models.Cryptokey, 1)

	go func() { z, err := h.PDNS.GetZone(r.Context(), zoneID); zoneCh <- zoneRes{z, err} }()
	go func() { recs, err := h.PDNS.ListRecords(r.Context(), zoneID); recordsCh <- recordsRes{recs, err} }()
	go func() { m, _ := h.PDNS.GetMetadata(r.Context(), zoneID); metadataCh <- m }()
	go func() { s, _ := h.PDNS.GetServer(r.Context()); serverCh <- s }()
	go func() { ck, _ := h.PDNS.ListCryptokeys(r.Context(), zoneID); cryptoCh <- ck }()

	zr := <-zoneCh
	if zr.err != nil {
		h.renderInternalError(w, r, "Zone not found", zr.err)
		return
	}
	zone := zr.v

	rr := <-recordsCh
	if rr.err != nil {
		h.renderInternalError(w, r, "Failed to fetch records", rr.err)
		return
	}
	records := rr.v

	metadata := <-metadataCh
	srv := <-serverCh
	cryptokeys := <-cryptoCh

	search := strings.TrimSpace(r.URL.Query().Get("search"))
	if search != "" {
		searchLower := strings.ToLower(search)
		searchIsAt := search == "@"
		var filtered []models.RRSet
		for _, rrset := range records {
			nameLower := strings.ToLower(rrset.Name)
			if searchIsAt && nameLower == strings.ToLower(zone.Name) {
				filtered = append(filtered, rrset)
				continue
			}
			if !searchIsAt && (strings.Contains(nameLower, searchLower) ||
				strings.Contains(strings.ToLower(rrset.Type), searchLower)) {
				filtered = append(filtered, rrset)
				continue
			}
			if searchIsAt {
				continue
			}
			for _, rec := range rrset.Records {
				if strings.Contains(strings.ToLower(rec.Content), searchLower) {
					filtered = append(filtered, rrset)
					break
				}
			}
		}
		records = filtered
	}

	// Sort records: SOA first, NS second, zone apex next, then alpha by name+type.
	sortZoneRecords(records, zone.Name)

	recordPage, recordPerPage := parsePaginationParams(r, 10)
	paginatedRecords, recordPageInfo := paginate(records, recordPage, recordPerPage)

	logs := h.getZoneActivityLogs(zoneID)
	templates, _ := h.getAllTemplates()

	pdnsVersion := "unknown"
	if srv != nil {
		pdnsVersion = srv.Version
	}

	data := map[string]interface{}{
		"Title":          zone.Name + " - GoZone",
		"User":           user,
		"Zone":           zone,
		"Records":        paginatedRecords,
		"RecordPageInfo": recordPageInfo,
		"Search":         search,
		"MetaData":       metadata,
		"Logs":           logs,
		"PDNSVersion":    pdnsVersion,
		"RecordTypes":    GetRecordTypes(),
		"MetaKinds":      GetMetadataKinds(),
		"IsAdmin":        user.IsAdmin(),
		"Templates":      templates,
		"TemplateVars":   TemplateVariables,
		"Cryptokeys":     cryptokeys,
		"DNSSECAlgos":    GetDNSSECAlgorithms(),
	}
	h.render(w, r, "zone_view.html", data)
}

// RectifyZone triggers DNSSEC rectification for a zone (POST /zones/{zone_id}/rectify).
//
// Requires admin role. After rectification, redirects back to the zone view.
func (h *Handler) RectifyZone(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	zoneID := r.PathValue("zone_id")
	if err := h.PDNS.RectifyZone(r.Context(), zoneID); err != nil {
		h.renderInternalError(w, r, "Rectify failed", err)
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
	if err := h.PDNS.NotifySlaves(r.Context(), zoneID); err != nil {
		h.renderInternalError(w, r, "Notify failed", err)
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

	if err := h.PDNS.SetMetadata(r.Context(), zoneID, meta); err != nil {
		h.renderInternalError(w, r, "Failed to set metadata", err)
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
	zoneID := r.PathValue("zone_id")
	kind := strings.TrimSpace(r.FormValue("kind"))

	if kind == "" {
		h.renderError(w, r, "Metadata kind is required")
		return
	}

	if err := h.PDNS.DeleteMetadata(r.Context(), zoneID, kind); err != nil {
		h.renderInternalError(w, r, "Failed to delete metadata", err)
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
		log.Username = username.String
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for zone activity logs", "zone_id", zoneID, "error", err)
	}
	return logs
}

// renderError shows the error page with HTTP 400 (Bad Request), the right
// status for the validation/bad-input cases that make up most callers. Use
// renderErrorStatus for not-found (404) or other statuses.
func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, msg string) {
	h.renderErrorStatus(w, r, http.StatusBadRequest, msg)
}

// renderErrorStatus writes the given HTTP status and renders the error page.
func (h *Handler) renderErrorStatus(w http.ResponseWriter, r *http.Request, status int, msg string) {
	// Set Content-Type explicitly: once WriteHeader is called the body write no
	// longer triggers content sniffing.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	data := map[string]interface{}{
		"Title":   "Error - GoZone",
		"Message": msg,
	}
	h.render(w, r, "error.html", data)
}

// sortZoneRecords orders RRSets for display: SOA first, NS second, zone apex
// next, then alphabetically by name and finally by type. The comparator is a
// strict weak ordering: two records of the same priority are resolved by
// name+type, never by returning true in both directions.
func sortZoneRecords(records []models.RRSet, zoneName string) {
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
		aIsApex := a.Name == zoneName
		bIsApex := b.Name == zoneName
		if aIsApex && !bIsApex {
			return true
		}
		if !aIsApex && bIsApex {
			return false
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Type < b.Type
	})
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
		"ALLOW-DNSUPDATE-FROM",
		"ALSO-NOTIFY",
		"AXFR-MASTER-TSIG",
		"AXFR-SOURCE",
		"FORWARD-DNSSEC",
		"GSS-ACCEPTOR-PRINCIPAL",
		"GSS-ALLOW-AXFR-PRINCIPALS",
		"IXFR",
		"LUA-AXFR-SCRIPT",
		"NOTIFY-DNSUPDATE",
		"NSEC3NARROW",
		"NSEC3PARAM",
		"PRESIGNED",
		"PUBLISH-CDNSKEY",
		"PUBLISH-CDS",
		"SOA-EDIT",
		"SOA-EDIT-API",
		"SOA-EDIT-DNSUPDATE",
		"TSIG-ALLOW-AXFR",
		"TSIG-ALLOW-DNSUPDATE",
	}
}

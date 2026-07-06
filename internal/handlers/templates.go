package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// TemplateVariables are the substitution variables available in template records.
var TemplateVariables = []string{"ZONE", "IP", "IP6", "MX_HOST", "TTL", "REFRESH", "RETRY", "EXPIRE", "MINIMUM"}

// templateVarDefaults provides fallback values for SOA timer variables so the
// built-in "standard" template yields a valid SOA even when the operator leaves
// these fields blank. Variables without a default (ZONE, IP, MX_HOST, ...) stay
// required and are reported by substituteTemplateRecords if left unsubstituted.
var templateVarDefaults = map[string]string{
	"REFRESH": "10800",
	"RETRY":   "3600",
	"EXPIRE":  "604800",
	"MINIMUM": "3600",
}

// unsubstitutedVar matches any template placeholder left after substitution
// (variable names are upper-case alphanumeric with underscores, e.g. IP6).
var unsubstitutedVar = regexp.MustCompile(`\{\{[A-Z0-9_]+\}\}`)

// ListTemplates renders the template management page.
func (h *Handler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	where, args := buildSearchLikeWhere(search, "name", "description")

	countQuery := "SELECT COUNT(*) FROM zone_templates"
	selectQuery := "SELECT id, name, description, is_builtin, created_at, updated_at FROM zone_templates"
	if where != "" {
		countQuery += " WHERE " + where
		selectQuery += " WHERE " + where
	}
	selectQuery += " ORDER BY name"

	var total int
	if err := h.DB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		h.renderInternalError(w, r, "Failed to count templates", err)
		return
	}

	page, perPage := parsePaginationParams(r, 10)
	pageInfo := pageInfoFromTotal(total, page, perPage)

	var rows *sql.Rows
	var err error
	if perPage > 0 {
		offset := (pageInfo.Current - 1) * perPage
		selectArgs := append([]any(nil), args...)
		selectArgs = append(selectArgs, perPage, offset)
		rows, err = h.DB.Query(selectQuery+" LIMIT ? OFFSET ?", selectArgs...)
	} else {
		rows, err = h.DB.Query(selectQuery, args...)
	}
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch templates", err)
		return
	}
	defer rows.Close()

	var templates []models.ZoneTemplate
	for rows.Next() {
		var t models.ZoneTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.IsBuiltin, &t.CreatedAt, &t.UpdatedAt); err != nil {
			logger.Error("failed to scan template", "error", err)
			continue
		}
		templates = append(templates, t)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for templates list", "error", err)
	}

	if templates == nil {
		templates = []models.ZoneTemplate{}
	}

	data := map[string]interface{}{
		"Title":     "Templates - " + h.Cfg.Server.AppName,
		"User":      user,
		"Templates": templates,
		"PageInfo":  pageInfo,
		"Search":    search,
		"IsAdmin":   user.IsAdmin(),
	}
	h.render(w, r, "templates.html", data)
}

// CreateTemplatePage renders the template creation form.
func (h *Handler) CreateTemplatePage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	data := map[string]interface{}{
		"Title":        "Create Template - " + h.Cfg.Server.AppName,
		"User":         user,
		"IsAdmin":      user.IsAdmin(),
		"RecordTypes":  GetRecordTypes(),
		"Template":     models.ZoneTemplate{},
		"Records":      []models.ZoneTemplateRecord{},
		"TemplateVars": TemplateVariables,
	}
	h.render(w, r, "template_edit.html", data)
}

// CreateTemplate inserts a new zone template.
func (h *Handler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))

	if name == "" {
		h.renderError(w, r, "Template name is required")
		return
	}

	result, err := h.DB.Exec(
		"INSERT INTO zone_templates (name, description) VALUES (?, ?)",
		name, description,
	)
	if err != nil {
		if errors.Is(err, database.ErrUniqueViolation) {
			h.renderError(w, r, "A template with that name already exists")
			return
		}
		h.renderInternalError(w, r, "Failed to create template", err)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		h.renderError(w, r, "Failed to get template ID")
		return
	}
	http.Redirect(w, r, "/templates/"+strconv.FormatInt(id, 10)+"/edit", http.StatusSeeOther)
}

// EditTemplatePage renders the template edit form with records.
func (h *Handler) EditTemplatePage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	templateIDStr := r.PathValue("template_id")
	templateID, err := strconv.ParseInt(templateIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid template ID")
		return
	}

	var t models.ZoneTemplate
	err = h.DB.QueryRow(
		"SELECT id, name, description, is_builtin, created_at, updated_at FROM zone_templates WHERE id = ?", templateID,
	).Scan(&t.ID, &t.Name, &t.Description, &t.IsBuiltin, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		h.renderErrorStatus(w, r, http.StatusNotFound, "Template not found")
		return
	}
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch template", err)
		return
	}

	records := h.getTemplateRecords(templateID)

	data := map[string]interface{}{
		"Title":        t.Name + " - " + h.Cfg.Server.AppName,
		"User":         user,
		"IsAdmin":      user.IsAdmin(),
		"RecordTypes":  GetRecordTypes(),
		"Template":     t,
		"Records":      records,
		"TemplateVars": TemplateVariables,
	}
	h.render(w, r, "template_edit.html", data)
}

// UpdateTemplate updates a template's name and description.
func (h *Handler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	templateIDStr := r.PathValue("template_id")
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))

	if name == "" {
		h.renderError(w, r, "Template name is required")
		return
	}

	_, err := h.DB.Exec(
		"UPDATE zone_templates SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		name, description, templateIDStr,
	)
	if err != nil {
		if errors.Is(err, database.ErrUniqueViolation) {
			h.renderError(w, r, "A template with that name already exists")
			return
		}
		h.renderInternalError(w, r, "Failed to update template", err)
		return
	}

	// #nosec G710 -- templateIDStr from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/templates/"+templateIDStr+"/edit", http.StatusSeeOther)
}

// DeleteTemplate deletes a template. Built-in templates cannot be deleted.
func (h *Handler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateIDStr := r.PathValue("template_id")

	var isBuiltin bool
	err := h.DB.QueryRow("SELECT is_builtin FROM zone_templates WHERE id = ?", templateIDStr).Scan(&isBuiltin)
	if err != nil {
		h.renderInternalError(w, r, "Template not found", err)
		return
	}
	if isBuiltin {
		h.renderError(w, r, "Cannot delete a built-in template")
		return
	}

	if _, err := h.DB.Exec("DELETE FROM zone_templates WHERE id = ?", templateIDStr); err != nil {
		h.renderInternalError(w, r, "Failed to delete template", err)
		return
	}
	// #nosec G710 -- templateIDStr from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

// BulkDeleteTemplates deletes several zone templates by template_id
// (POST /templates/bulk-delete).
//
// Admin-only. The selection arrives as repeated "template_id" form values.
// Built-in templates are never deletable: the DELETE is scoped with
// "is_builtin = 0" so a built-in id (or one that no longer exists) is reported
// in `failed` via RowsAffected==0 without aborting the rest. Returns JSON
// {deleted, failed} for the AJAX toolbar.
func (h *Handler) BulkDeleteTemplates(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid form data"})
		return
	}

	// Dedupe while preserving order; drop anything that is not a positive int.
	seen := make(map[int64]struct{})
	var templateIDs []int64
	for _, idStr := range r.PostForm["template_id"] {
		id, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		templateIDs = append(templateIDs, id)
	}

	if len(templateIDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No templates selected"})
		return
	}

	deleted := 0
	var failed []string
	for _, tid := range templateIDs {
		// Built-in guard: "is_builtin = 0" refuses built-in templates atomically.
		res, err := h.DB.Exec("DELETE FROM zone_templates WHERE id = ? AND is_builtin = 0", tid)
		if err != nil {
			logger.Error("bulk delete template failed", "template_id", tid, "error", err)
			failed = append(failed, strconv.FormatInt(tid, 10))
			continue
		}
		if n, _ := res.RowsAffected(); n == 0 {
			failed = append(failed, strconv.FormatInt(tid, 10))
			continue
		}
		deleted++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}

// AddTemplateRecord adds a record to a template.
func (h *Handler) AddTemplateRecord(w http.ResponseWriter, r *http.Request) {
	templateIDStr := r.PathValue("template_id")
	rec := parseTemplateRecordForm(r, templateIDStr)

	if _, err := h.DB.Exec(
		"INSERT INTO zone_template_records (template_id, name, type, content, ttl, priority, disabled) VALUES (?, ?, ?, ?, ?, ?, ?)",
		rec.TemplateID, rec.Name, rec.Type, rec.Content, rec.TTL, rec.Priority, rec.Disabled,
	); err != nil {
		h.renderInternalError(w, r, "Failed to add record", err)
		return
	}
	// #nosec G710 -- templateIDStr from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/templates/"+templateIDStr+"/edit", http.StatusSeeOther)
}

// UpdateTemplateRecord updates a template record.
func (h *Handler) UpdateTemplateRecord(w http.ResponseWriter, r *http.Request) {
	templateIDStr := r.PathValue("template_id")
	recordIDStr := r.PathValue("record_id")
	rec := parseTemplateRecordForm(r, templateIDStr)

	if _, err := h.DB.Exec(
		"UPDATE zone_template_records SET name = ?, type = ?, content = ?, ttl = ?, priority = ?, disabled = ? WHERE id = ? AND template_id = ?",
		rec.Name, rec.Type, rec.Content, rec.TTL, rec.Priority, rec.Disabled, recordIDStr, templateIDStr,
	); err != nil {
		h.renderInternalError(w, r, "Failed to update record", err)
		return
	}
	// #nosec G710 -- templateIDStr from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/templates/"+templateIDStr+"/edit", http.StatusSeeOther)
}

// DeleteTemplateRecord deletes a record from a template.
func (h *Handler) DeleteTemplateRecord(w http.ResponseWriter, r *http.Request) {
	templateIDStr := r.PathValue("template_id")
	recordIDStr := r.PathValue("record_id")

	if _, err := h.DB.Exec("DELETE FROM zone_template_records WHERE id = ? AND template_id = ?", recordIDStr, templateIDStr); err != nil {
		h.renderInternalError(w, r, "Failed to delete record", err)
		return
	}
	// #nosec G710 -- templateIDStr from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/templates/"+templateIDStr+"/edit", http.StatusSeeOther)
}

// ApplyTemplateToZone applies template records to an existing zone.
func (h *Handler) ApplyTemplateToZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	templateIDStr := strings.TrimSpace(r.FormValue("template_id"))

	if templateIDStr == "" {
		h.renderError(w, r, "Template ID is required")
		return
	}

	templateID, err := strconv.ParseInt(templateIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid template ID")
		return
	}

	records := h.getTemplateRecords(templateID)
	if len(records) == 0 {
		h.renderError(w, r, "Template has no records")
		return
	}

	vars := h.collectTemplateVars(r)
	if vars["ZONE"] == "" {
		vars["ZONE"] = zoneID
	}
	rrsets, err := h.substituteTemplateRecords(zoneID, records, vars)
	if err != nil {
		h.renderError(w, r, err.Error())
		return
	}

	if err := h.PDNS.CreateRecords(r.Context(), zoneID, rrsets); err != nil {
		h.renderInternalError(w, r, "Failed to create records from template", err)
		return
	}

	user := middleware.GetUser(r)
	if _, err := h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'apply_template', ?)",
		user.ID, zoneID, fmt.Sprintf("Applied template %s", templateIDStr),
	); err != nil {
		logger.Error("failed to log activity", "error", err)
	}
	// #nosec G710 -- zoneID from chi r.PathValue, controlled by route pattern
	http.Redirect(w, r, "/zones/"+zoneID, http.StatusSeeOther)
}

// getTemplateRecords returns all records for a template.
func (h *Handler) getTemplateRecords(templateID int64) []models.ZoneTemplateRecord {
	rows, err := h.DB.Query(
		"SELECT id, template_id, name, type, content, ttl, priority, disabled FROM zone_template_records WHERE template_id = ? ORDER BY type, name",
		templateID,
	)
	if err != nil {
		logger.Error("failed to fetch template records", "error", err)
		return nil
	}
	defer rows.Close()

	var records []models.ZoneTemplateRecord
	for rows.Next() {
		var r models.ZoneTemplateRecord
		var disabled int
		if err := rows.Scan(&r.ID, &r.TemplateID, &r.Name, &r.Type, &r.Content, &r.TTL, &r.Priority, &disabled); err != nil {
			logger.Error("failed to scan template record", "error", err)
			continue
		}
		r.Disabled = disabled != 0
		records = append(records, r)
	}
	return records
}

// getAllTemplates returns all templates (for dropdown selectors).
func (h *Handler) getAllTemplates() ([]models.ZoneTemplate, error) {
	rows, err := h.DB.Query("SELECT id, name, description, is_builtin, created_at, updated_at FROM zone_templates ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []models.ZoneTemplate
	for rows.Next() {
		var t models.ZoneTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.IsBuiltin, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, nil
}

// substituteTemplateRecords replaces template variables in record names and
// contents and converts template records to PowerDNS RRSets. Missing SOA timer
// variables fall back to templateVarDefaults. It returns an error if any
// placeholder is left unsubstituted (a required variable was not provided).
func (h *Handler) substituteTemplateRecords(zoneID string, records []models.ZoneTemplateRecord, vars map[string]string) ([]models.RRSet, error) {
	// Merge defaults under the caller-provided values without mutating vars.
	merged := make(map[string]string, len(vars)+len(templateVarDefaults))
	for k, v := range templateVarDefaults {
		merged[k] = v
	}
	for k, v := range vars {
		if v != "" {
			merged[k] = v
		}
	}

	rrsets := make([]models.RRSet, 0, len(records))
	missing := make(map[string]struct{})

	for _, r := range records {
		name := r.Name
		content := r.Content

		for v, val := range merged {
			name = strings.ReplaceAll(name, "{{"+v+"}}", val)
			content = strings.ReplaceAll(content, "{{"+v+"}}", val)
		}

		for _, leftover := range unsubstitutedVar.FindAllString(name+" "+content, -1) {
			missing[strings.Trim(leftover, "{}")] = struct{}{}
		}

		if name == "@" {
			name = zoneID
		} else if !strings.HasSuffix(name, ".") {
			name = name + "." + zoneID
		}

		// Embed MX/SRV priority into the content; PDNS rejects a separate
		// "priority" element in the PATCH body.
		content, priority := prepareRecordContent(r.Type, content, r.Priority)

		rrsets = append(rrsets, models.RRSet{
			Name:    name,
			Type:    r.Type,
			TTL:     r.TTL,
			Records: []models.RecordInfo{{Content: content, Priority: priority, Disabled: r.Disabled}},
		})
	}

	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for v := range missing {
			names = append(names, v)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("missing template variable(s): %s", strings.Join(names, ", "))
	}

	return rrsets, nil
}

// collectTemplateVars extracts template variable values from a form.
func (h *Handler) collectTemplateVars(r *http.Request) map[string]string {
	vars := make(map[string]string)
	for _, v := range TemplateVariables {
		if val := strings.TrimSpace(r.FormValue("var_" + v)); val != "" {
			vars[v] = val
		}
	}
	return vars
}

// parseTemplateRecordForm extracts a template record from form values.
func parseTemplateRecordForm(r *http.Request, templateIDStr string) models.ZoneTemplateRecord {
	templateID, _ := strconv.ParseInt(templateIDStr, 10, 64)
	ttl, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("ttl")))
	if ttl <= 0 {
		ttl = 3600
	}
	priority, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("priority")))
	disabled := r.FormValue("disabled") == "on"

	return models.ZoneTemplateRecord{
		TemplateID: templateID,
		Name:       strings.TrimSpace(r.FormValue("name")),
		Type:       strings.TrimSpace(r.FormValue("type")),
		Content:    strings.TrimSpace(r.FormValue("content")),
		TTL:        ttl,
		Priority:   priority,
		Disabled:   disabled,
	}
}

// SeedBuiltinTemplates creates the built-in zone templates if they don't exist.
func (h *Handler) SeedBuiltinTemplates() error {
	builtins := []struct {
		name    string
		desc    string
		records []models.ZoneTemplateRecord
	}{
		{
			name: "standard",
			desc: "SOA + NS records only",
			records: []models.ZoneTemplateRecord{
				{Name: "@", Type: "SOA", Content: "ns1.{{ZONE}} hostmaster.{{ZONE}} 1 {{REFRESH}} {{RETRY}} {{EXPIRE}} {{MINIMUM}}", TTL: 3600},
				{Name: "@", Type: "NS", Content: "ns1.{{ZONE}}", TTL: 86400},
				{Name: "@", Type: "NS", Content: "ns2.{{ZONE}}", TTL: 86400},
			},
		},
		{
			name: "mail",
			desc: "SOA + NS + MX + SPF + DKIM + DMARC",
			records: []models.ZoneTemplateRecord{
				{Name: "@", Type: "SOA", Content: "ns1.{{ZONE}} hostmaster.{{ZONE}} 1 10800 3600 604800 3600", TTL: 3600},
				{Name: "@", Type: "NS", Content: "ns1.{{ZONE}}", TTL: 86400},
				{Name: "@", Type: "NS", Content: "ns2.{{ZONE}}", TTL: 86400},
				{Name: "@", Type: "MX", Content: "{{MX_HOST}}", TTL: 3600, Priority: 10},
				{Name: "@", Type: "TXT", Content: "v=spf1 mx ~all", TTL: 3600},
				{Name: "*._domainkey", Type: "TXT", Content: "v=DKIM1; k=rsa; p=REPLACE_WITH_PUBLIC_KEY", TTL: 3600},
				{Name: "_dmarc", Type: "TXT", Content: "v=DMARC1; p=none; rua=mailto:dmarc@{{ZONE}}", TTL: 3600},
			},
		},
		{
			name: "web",
			desc: "SOA + NS + A/AAAA + CNAME www",
			records: []models.ZoneTemplateRecord{
				{Name: "@", Type: "SOA", Content: "ns1.{{ZONE}} hostmaster.{{ZONE}} 1 10800 3600 604800 3600", TTL: 3600},
				{Name: "@", Type: "NS", Content: "ns1.{{ZONE}}", TTL: 86400},
				{Name: "@", Type: "NS", Content: "ns2.{{ZONE}}", TTL: 86400},
				{Name: "@", Type: "A", Content: "{{IP}}", TTL: 3600},
				{Name: "@", Type: "AAAA", Content: "{{IP6}}", TTL: 3600},
				{Name: "www", Type: "CNAME", Content: "{{ZONE}}", TTL: 3600},
			},
		},
		{
			name: "redirect",
			desc: "SOA + NS + A + URL redirect",
			records: []models.ZoneTemplateRecord{
				{Name: "@", Type: "SOA", Content: "ns1.{{ZONE}} hostmaster.{{ZONE}} 1 10800 3600 604800 3600", TTL: 3600},
				{Name: "@", Type: "NS", Content: "ns1.{{ZONE}}", TTL: 86400},
				{Name: "@", Type: "NS", Content: "ns2.{{ZONE}}", TTL: 86400},
				{Name: "@", Type: "A", Content: "{{IP}}", TTL: 3600},
			},
		},
	}

	for _, b := range builtins {
		var exists int
		if err := h.DB.QueryRow("SELECT COUNT(*) FROM zone_templates WHERE name = ?", b.name).Scan(&exists); err != nil {
			return fmt.Errorf("check builtin template %s: %w", b.name, err)
		}
		if exists > 0 {
			continue
		}

		result, err := h.DB.Exec(
			"INSERT INTO zone_templates (name, description, is_builtin) VALUES (?, ?, 1)",
			b.name, b.desc,
		)
		if err != nil {
			return fmt.Errorf("insert builtin template %s: %w", b.name, err)
		}

		templateID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("get builtin template ID: %w", err)
		}

		for _, rec := range b.records {
			disabled := 0
			if rec.Disabled {
				disabled = 1
			}
			_, err := h.DB.Exec(
				"INSERT INTO zone_template_records (template_id, name, type, content, ttl, priority, disabled) VALUES (?, ?, ?, ?, ?, ?, ?)",
				templateID, rec.Name, rec.Type, rec.Content, rec.TTL, rec.Priority, disabled,
			)
			if err != nil {
				return fmt.Errorf("insert builtin template record for %s: %w", b.name, err)
			}
		}
		logger.Info("seeded builtin template", "name", b.name)
	}

	return nil
}

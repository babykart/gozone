package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
)

func seedTemplate(t *testing.T, h *Handler, name, description string) int64 {
	t.Helper()
	result, err := h.DB.Exec(
		"INSERT INTO zone_templates (name, description) VALUES (?, ?)",
		name, description,
	)
	if err != nil {
		t.Fatalf("seed template: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

func seedTemplateRecord(t *testing.T, h *Handler, templateID int64, name, rtype, content string, ttl int) int64 {
	t.Helper()
	result, err := h.DB.Exec(
		"INSERT INTO zone_template_records (template_id, name, type, content, ttl) VALUES (?, ?, ?, ?, ?)",
		templateID, name, rtype, content, ttl,
	)
	if err != nil {
		t.Fatalf("seed template record: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

func TestListTemplates(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedTemplate(t, h, "my-template", "A test template")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/templates", nil), user)
	h.ListTemplates(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "my-template") {
		t.Errorf("expected response to contain template name")
	}
}

func TestListTemplates_Empty(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/templates", nil), user)
	h.ListTemplates(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListTemplates_PaginationAndSearch(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedTemplate(t, h, "alpha-template", "first")
	seedTemplate(t, h, "beta-template", "second")
	seedTemplate(t, h, "gamma-other", "third")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/templates?search=template&PerPage=1&Page=2", nil), user)
	h.ListTemplates(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "beta-template") {
		t.Errorf("expected page 2 to contain beta-template, body: %s", body)
	}
	if strings.Contains(body, "alpha-template") {
		t.Errorf("did not expect alpha-template on page 2, body: %s", body)
	}
	if strings.Contains(body, "gamma-other") {
		t.Errorf("did not expect gamma-other after filtering by 'template', body: %s", body)
	}
	if !strings.Contains(body, "PageInfo=") || !strings.Contains(body, "Search=template") {
		t.Errorf("expected pagination info in response, body: %s", body)
	}
}

func TestCreateTemplatePage(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/templates/new", nil), user)
	h.CreateTemplatePage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCreateTemplate_Success(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "name=web-template&description=A+web+template"
	r := withUserContext(httptest.NewRequest(http.MethodPost, "/templates/create", strings.NewReader(body)), user)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateTemplate(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/templates/") || !strings.HasSuffix(loc, "/edit") {
		t.Errorf("expected redirect to /templates/{id}/edit, got %s", loc)
	}
}

func TestCreateTemplate_EmptyName(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodPost, "/templates/create", strings.NewReader("name=")), user)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateTemplate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Template name is required") {
		t.Errorf("expected error message, got %s", w.Body.String())
	}
}

func TestCreateTemplate_DuplicateName(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedTemplate(t, h, "dup-template", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodPost, "/templates/create", strings.NewReader("name=dup-template")), user)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateTemplate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("expected duplicate name error, got %s", w.Body.String())
	}
}

func TestEditTemplatePage(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	templateID := seedTemplate(t, h, "edit-tmpl", "desc")
	seedTemplateRecord(t, h, templateID, "@", "A", "{{IP}}", 3600)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/templates/"+strconv.FormatInt(templateID, 10)+"/edit", nil)
	r.SetPathValue("template_id", strconv.FormatInt(templateID, 10))
	r = withUserContext(r, user)
	h.EditTemplatePage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "edit-tmpl") {
		t.Errorf("expected response to contain template name")
	}
}

func TestEditTemplatePage_NotFound(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/templates/99999/edit", nil)
	r.SetPathValue("template_id", "99999")
	r = withUserContext(r, user)
	h.EditTemplatePage(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Template not found") {
		t.Errorf("expected 'Template not found', got %s", w.Body.String())
	}
}

func TestUpdateTemplate_Success(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	templateID := seedTemplate(t, h, "old-name", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "name=new-name&description=new+desc"
	r := httptest.NewRequest(http.MethodPost, "/templates/"+strconv.FormatInt(templateID, 10)+"/update", strings.NewReader(body))
	r.SetPathValue("template_id", strconv.FormatInt(templateID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.UpdateTemplate(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	var name string
	h.DB.QueryRow("SELECT name FROM zone_templates WHERE id = ?", templateID).Scan(&name)
	if name != "new-name" {
		t.Errorf("expected name 'new-name', got %q", name)
	}
}

func TestDeleteTemplate(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	templateID := seedTemplate(t, h, "delete-me", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/templates/"+strconv.FormatInt(templateID, 10)+"/delete", nil)
	r.SetPathValue("template_id", strconv.FormatInt(templateID, 10))
	r = withUserContext(r, user)
	h.DeleteTemplate(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_templates WHERE id = ?", templateID).Scan(&count)
	if count != 0 {
		t.Error("expected template to be deleted")
	}
}

func TestDeleteBuiltinTemplate(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	result, err := h.DB.Exec(
		"INSERT INTO zone_templates (name, description, is_builtin) VALUES (?, ?, ?)",
		"builtin-tmpl", "A built-in template", true,
	)
	if err != nil {
		t.Fatalf("seed builtin template: %v", err)
	}
	templateID, _ := result.LastInsertId()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/templates/"+strconv.FormatInt(templateID, 10)+"/delete", nil)
	r.SetPathValue("template_id", strconv.FormatInt(templateID, 10))
	r = withUserContext(r, user)
	h.DeleteTemplate(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "Cannot delete a built-in template") {
		t.Errorf("expected built-in guard error, got: %s", body)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_templates WHERE id = ?", templateID).Scan(&count)
	if count != 1 {
		t.Error("expected built-in template to still exist")
	}
}

func TestAddTemplateRecord(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	templateID := seedTemplate(t, h, "record-tmpl", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "name=@&type=A&content=192.0.2.1&ttl=3600&priority=0"
	r := httptest.NewRequest(http.MethodPost, "/templates/"+strconv.FormatInt(templateID, 10)+"/records/add", strings.NewReader(body))
	r.SetPathValue("template_id", strconv.FormatInt(templateID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.AddTemplateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_template_records WHERE template_id = ?", templateID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}
}

func TestDeleteTemplateRecord(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	templateID := seedTemplate(t, h, "del-record-tmpl", "")
	recordID := seedTemplateRecord(t, h, templateID, "@", "A", "10.0.0.1", 3600)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/templates/"+strconv.FormatInt(templateID, 10)+"/records/"+strconv.FormatInt(recordID, 10)+"/delete", nil)
	r.SetPathValue("template_id", strconv.FormatInt(templateID, 10))
	r.SetPathValue("record_id", strconv.FormatInt(recordID, 10))
	r = withUserContext(r, user)
	h.DeleteTemplateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_template_records WHERE id = ?", recordID).Scan(&count)
	if count != 0 {
		t.Error("expected record to be deleted")
	}
}

func TestApplyTemplateToZone(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	templateID := seedTemplate(t, h, "apply-tmpl", "")
	seedTemplateRecord(t, h, templateID, "@", "A", "{{IP}}", 3600)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	body := "template_id=" + strconv.FormatInt(templateID, 10) + "&var_IP=10.0.0.1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./apply-template", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.ApplyTemplateToZone(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
}

func TestApplyTemplateToZone_ActivityLogged(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	userID := seedUserWithHash(t, h, "templateuser", "pass", "admin")

	templateID := seedTemplate(t, h, "log-tmpl", "")
	seedTemplateRecord(t, h, templateID, "@", "A", "{{IP}}", 3600)

	user := &models.User{ID: userID, Username: "templateuser", Role: "admin"}
	body := "template_id=" + strconv.FormatInt(templateID, 10) + "&var_IP=10.0.0.1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./apply-template", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.ApplyTemplateToZone(w, r)

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='apply_template' AND zone_id='example.com.'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 apply_template activity log entry, got %d", count)
	}
}

func TestSeedBuiltinTemplates(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	// Seed should create 4 built-in templates
	if err := h.SeedBuiltinTemplates(); err != nil {
		t.Fatalf("SeedBuiltinTemplates: %v", err)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_templates WHERE is_builtin = 1").Scan(&count)
	if count != 4 {
		t.Errorf("expected 4 built-in templates, got %d", count)
	}

	// Calling again should be idempotent
	if err := h.SeedBuiltinTemplates(); err != nil {
		t.Fatalf("second SeedBuiltinTemplates: %v", err)
	}

	var count2 int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_templates WHERE is_builtin = 1").Scan(&count2)
	if count2 != 4 {
		t.Errorf("expected still 4 built-in after second seed, got %d", count2)
	}

	// Verify the mail template has DMARC record
	var mailTemplateID int64
	h.DB.QueryRow("SELECT id FROM zone_templates WHERE name = 'mail'").Scan(&mailTemplateID)
	var dmarcCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_template_records WHERE template_id = ? AND name = '_dmarc'", mailTemplateID).Scan(&dmarcCount)
	if dmarcCount != 1 {
		t.Errorf("expected 1 DMARC record in mail template, got %d", dmarcCount)
	}
}

func TestSubstituteTemplateRecords(t *testing.T) {
	h, _ := newTestHandlerWithPDNS(t, pdnsEmptyHandler())

	records := []models.ZoneTemplateRecord{
		{Name: "@", Type: "A", Content: "{{IP}}", TTL: 3600},
		{Name: "www", Type: "CNAME", Content: "{{ZONE}}", TTL: 3600},
		{Name: "@", Type: "MX", Content: "{{MX_HOST}}", TTL: 3600, Priority: 10},
		{Name: "_dmarc", Type: "TXT", Content: "v=DMARC1; p={{POLICY}}", TTL: 3600},
	}

	vars := map[string]string{
		"ZONE":    "example.com.",
		"IP":      "192.0.2.1",
		"MX_HOST": "mail.example.com.",
		"POLICY":  "none",
	}

	rrsets, err := h.substituteTemplateRecords("example.com.", records, vars)
	if err != nil {
		t.Fatalf("substituteTemplateRecords: %v", err)
	}

	if len(rrsets) != 4 {
		t.Fatalf("expected 4 rrsets, got %d", len(rrsets))
	}

	// Apex A record
	if rrsets[0].Name != "example.com." || rrsets[0].Type != "A" || rrsets[0].Records[0].Content != "192.0.2.1" {
		t.Errorf("A record: got name=%q type=%q content=%q", rrsets[0].Name, rrsets[0].Type, rrsets[0].Records[0].Content)
	}

	// www CNAME
	if rrsets[1].Name != "www.example.com." || rrsets[1].Type != "CNAME" || rrsets[1].Records[0].Content != "example.com." {
		t.Errorf("CNAME record: got name=%q content=%q", rrsets[1].Name, rrsets[1].Records[0].Content)
	}

	// MX record - priority embedded in content for the PDNS PATCH API, with the
	// separate Priority element cleared (PDNS rejects it).
	if rrsets[2].Type != "MX" || rrsets[2].Records[0].Content != "10 mail.example.com." || rrsets[2].Records[0].Priority != 0 {
		t.Errorf("MX record: got content=%q priority=%d, want %q and 0",
			rrsets[2].Records[0].Content, rrsets[2].Records[0].Priority, "10 mail.example.com.")
	}

	// DMARC (TXT) - content is quoted for the PDNS API, like the UI write path.
	if rrsets[3].Name != "_dmarc.example.com." || rrsets[3].Records[0].Content != `"v=DMARC1; p=none"` {
		t.Errorf("DMARC record: got name=%q content=%q", rrsets[3].Name, rrsets[3].Records[0].Content)
	}
}

func TestSubstituteTemplateRecords_AbsoluteName(t *testing.T) {
	h, _ := newTestHandlerWithPDNS(t, pdnsEmptyHandler())

	records := []models.ZoneTemplateRecord{
		{Name: "sub.other.com.", Type: "A", Content: "{{IP}}", TTL: 3600},
	}

	vars := map[string]string{"IP": "10.0.0.1"}
	rrsets, err := h.substituteTemplateRecords("example.com.", records, vars)
	if err != nil {
		t.Fatalf("substituteTemplateRecords: %v", err)
	}

	if rrsets[0].Name != "sub.other.com." {
		t.Errorf("absolute name should be preserved: got %q", rrsets[0].Name)
	}
}

func TestSubstituteTemplateRecords_MissingVariable(t *testing.T) {
	h, _ := newTestHandlerWithPDNS(t, pdnsEmptyHandler())

	records := []models.ZoneTemplateRecord{
		{Name: "@", Type: "MX", Content: "{{MX_HOST}}", TTL: 3600, Priority: 10},
		{Name: "@", Type: "AAAA", Content: "{{IP6}}", TTL: 3600},
	}

	// Neither MX_HOST nor IP6 has a default; both must be reported (IP6 also
	// guards the digit in the placeholder regex) instead of being emitted as
	// literals that PDNS would reject.
	_, err := h.substituteTemplateRecords("example.com.", records, map[string]string{"ZONE": "example.com."})
	if err == nil {
		t.Fatal("expected error for missing variables, got nil")
	}
	if !strings.Contains(err.Error(), "MX_HOST") || !strings.Contains(err.Error(), "IP6") {
		t.Errorf("error should name the missing variables, got %q", err.Error())
	}
}

func TestSubstituteTemplateRecords_SOATimerDefaults(t *testing.T) {
	h, _ := newTestHandlerWithPDNS(t, pdnsEmptyHandler())

	// The built-in "standard" SOA relies on timer defaults; with only ZONE
	// provided it must still produce a complete 7-field SOA and no error.
	records := []models.ZoneTemplateRecord{
		{Name: "@", Type: "SOA", Content: "ns1.{{ZONE}} hostmaster.{{ZONE}} 1 {{REFRESH}} {{RETRY}} {{EXPIRE}} {{MINIMUM}}", TTL: 3600},
	}

	rrsets, err := h.substituteTemplateRecords("example.com.", records, map[string]string{"ZONE": "example.com."})
	if err != nil {
		t.Fatalf("substituteTemplateRecords: %v", err)
	}
	want := "ns1.example.com. hostmaster.example.com. 1 10800 3600 604800 3600"
	if got := rrsets[0].Records[0].Content; got != want {
		t.Errorf("SOA content = %q, want %q", got, want)
	}
	if fields := strings.Fields(rrsets[0].Records[0].Content); len(fields) != 7 {
		t.Errorf("SOA must have 7 fields, got %d: %q", len(fields), rrsets[0].Records[0].Content)
	}
}

func TestCollectTemplateVars(t *testing.T) {
	h, _ := newTestHandlerWithPDNS(t, pdnsEmptyHandler())

	body := "var_ZONE=example.com.&var_IP=192.0.2.1&var_MX_HOST=mail.example.com.&var_IGNORED=zzz&var_TTL="
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()

	vars := h.collectTemplateVars(r)
	if vars["ZONE"] != "example.com." {
		t.Errorf("ZONE: got %q", vars["ZONE"])
	}
	if vars["IP"] != "192.0.2.1" {
		t.Errorf("IP: got %q", vars["IP"])
	}
	if vars["MX_HOST"] != "mail.example.com." {
		t.Errorf("MX_HOST: got %q", vars["MX_HOST"])
	}
	if _, ok := vars["TTL"]; ok {
		t.Error("TTL should not be present (empty value)")
	}
	if _, ok := vars["IGNORED"]; ok {
		t.Error("IGNORED should not be present (not a known variable)")
	}
}

func TestParseTemplateRecordForm(t *testing.T) {
	body := "name=www&type=CNAME&content={{ZONE}}&ttl=7200&priority=0&disabled=on"
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()

	rec := parseTemplateRecordForm(r, "42")
	if rec.TemplateID != 42 {
		t.Errorf("TemplateID: got %d, want 42", rec.TemplateID)
	}
	if rec.Name != "www" {
		t.Errorf("Name: got %q", rec.Name)
	}
	if rec.Type != "CNAME" {
		t.Errorf("Type: got %q", rec.Type)
	}
	if rec.Content != "{{ZONE}}" {
		t.Errorf("Content: got %q", rec.Content)
	}
	if rec.TTL != 7200 {
		t.Errorf("TTL: got %d", rec.TTL)
	}
	if !rec.Disabled {
		t.Error("Disabled should be true")
	}
}

func TestGetAllTemplates(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedTemplate(t, h, "t1", "")
	seedTemplate(t, h, "t2", "")

	templates, err := h.getAllTemplates()
	if err != nil {
		t.Fatalf("getAllTemplates: %v", err)
	}
	if len(templates) != 2 {
		t.Errorf("expected 2 templates, got %d", len(templates))
	}
}

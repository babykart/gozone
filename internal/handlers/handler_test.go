package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/testutil"
)

func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	return testutil.NewTestDB(t)
}

// testTemplateSet returns a minimal shared template set for unit tests. It
// defines every template used by the handlers so tests don't need to parse the
// real embedded templates.
func testTemplateSet() *template.Template {
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
		"urlquery": func(s string) string { return s },
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict expects an even number of arguments")
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},
	}
	return template.Must(template.New("test").Funcs(funcMap).Parse(`
		{{define "error.html"}}Error: {{.Message}}{{end}}
		{{define "login.html"}}Login{{end}}
		{{define "dashboard.html"}}Dashboard{{end}}
		{{define "zones.html"}}Zones{{end}}
		{{define "zone_create.html"}}Create Zone{{end}}
		{{define "zone_view.html"}}View Zone: {{.Zone.Name}} Records: {{range .Records}}{{.Record.Content}} {{end}}{{if .RecordPageInfo}} PageInfo={{.RecordPageInfo.Current}}/{{.RecordPageInfo.TotalPages}} PerPage={{.RecordPageInfo.PerPage}} Total={{.RecordPageInfo.Total}}{{end}}{{end}}
		{{define "record_create.html"}}Create Record{{end}}
		{{define "record_edit.html"}}Edit Record{{end}}
		{{define "users.html"}}Users{{range .Users}} {{.Username}}{{end}}{{if .PageInfo}} PageInfo={{.PageInfo.Current}}/{{.PageInfo.TotalPages}} Search={{.Search}}{{end}}{{end}}
		{{define "user_create.html"}}Create User{{end}}
		{{define "user_edit.html"}}Edit User{{end}}
		{{define "profile.html"}}Profile{{end}}
		{{define "api_keys.html"}}API Keys{{range .APIKeys}} {{.Description}}{{end}}{{if .NewKey}} NewKey={{.NewKey}}{{end}}{{if .PageInfo}} PageInfo={{.PageInfo.Current}}/{{.PageInfo.TotalPages}} Search={{.Search}}{{end}}{{end}}
		{{define "groups.html"}}Groups: {{range .Groups}}{{.Name}} {{end}}{{if .PageInfo}} PageInfo={{.PageInfo.Current}}/{{.PageInfo.TotalPages}} Search={{.Search}}{{end}}{{end}}
		{{define "group_edit.html"}}GroupEdit: {{.Group.Name}} {{range .Members}}{{.Username}} {{end}}Zones: {{range .GroupZones}}{{.}} {{end}}AllUsers: {{range .AllUsers}}{{.Username}} {{end}}AllZones: {{range .AllZones}}{{.Zone.Name}} {{end}}{{end}}
		{{define "tsigkeys.html"}}TSIG Keys{{range .Keys}} {{.Name}}{{end}}{{if .PageInfo}} PageInfo={{.PageInfo.Current}}/{{.PageInfo.TotalPages}} Search={{.Search}}{{end}}{{end}}
		{{define "tsigkey_create.html"}}Create TSIG Key{{end}}
		{{define "tsigkey_edit.html"}}Edit TSIG Key{{end}}
		{{define "templates.html"}}Templates: {{range .Templates}}{{.Name}} {{end}}{{if .PageInfo}} PageInfo={{.PageInfo.Current}}/{{.PageInfo.TotalPages}} Search={{.Search}}{{end}}{{end}}
		{{define "template_edit.html"}}TemplateEdit: {{.Template.Name}}{{end}}
		{{define "dnssec.html"}}DNSSEC: {{.Zone.Name}} Keys: {{range .Keys}}{{.ID}}:{{.Active}}:{{.KeyType}} {{end}}{{end}}
		{{define "activity.html"}}Activity: {{range .Logs}}{{.Action}} {{end}}{{if .PageInfo}} PageInfo={{.PageInfo.Current}}/{{.PageInfo.TotalPages}} PerPage={{.PageInfo.PerPage}} Search={{.Search}}{{end}}{{if .Extra}} Extra={{.Extra}}{{end}}{{end}}
	`))
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	_, pdnsClient := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})
	db := newTestDB(t)

	h := &Handler{
		DB:   db,
		PDNS: pdnsClient,
		Cfg:  config.DefaultConfig(),
		Tmpl: testTemplateSet(),
	}
	// Handler unit tests exercise handler logic, not the password policy, so
	// relax it (no length/class requirements, no history) to let the existing
	// weak test passwords through. Dedicated policy tests build their own
	// strict handler.
	h.Cfg.Password = config.PasswordConfig{}
	return h
}

func newTestHandlerWithPDNS(t *testing.T, handler testutil.PDNSHandlerFunc) (*Handler, *httptest.Server) {
	t.Helper()
	srv, client := testutil.NewTestPDNSServer(t, handler)
	db := newTestDB(t)

	h := &Handler{
		DB:   db,
		PDNS: client,
		Cfg:  config.DefaultConfig(),
		Tmpl: testTemplateSet(),
	}
	h.Cfg.Password = config.PasswordConfig{}
	return h, srv
}

func TestGetRecordTypes(t *testing.T) {
	types := GetRecordTypes()
	if len(types) == 0 {
		t.Fatal("expected non-empty record types")
	}

	expected := []string{"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"}
	for _, want := range expected {
		found := false
		for _, got := range types {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected record type %s not found", want)
		}
	}
}

func TestGetMetadataKinds(t *testing.T) {
	kinds := GetMetadataKinds()

	expected := []string{
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

	if len(kinds) != len(expected) {
		t.Errorf("expected %d metadata kinds, got %d", len(expected), len(kinds))
	}

	index := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		index[k] = true
	}
	for _, want := range expected {
		if !index[want] {
			t.Errorf("expected metadata kind %s not found", want)
		}
	}
}

func TestTSIGAlgorithms(t *testing.T) {
	algs := tsigAlgorithms()
	if len(algs) == 0 {
		t.Fatal("expected non-empty tsig algorithms")
	}

	expected := []string{"hmac-md5", "hmac-sha1", "hmac-sha256", "hmac-sha512"}
	for _, want := range expected {
		found := false
		for _, got := range algs {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected algorithm %s not found", want)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	writeJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var decoded map[string]string
	if err := json.NewDecoder(w.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["key"] != "value" {
		t.Errorf("expected value, got %s", decoded["key"])
	}
}

func TestWriteJSON_StatusCreated(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, map[string]string{"message": "created"})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestRender(t *testing.T) {
	h := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	h.render(w, r, "login.html", map[string]interface{}{
		"Title": "Test",
	})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRender_MissingTemplate(t *testing.T) {
	h := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	h.render(w, r, "nonexistent.html", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

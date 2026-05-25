package handlers

import (
	"encoding/json"
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

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	_, pdnsClient := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})
	db := newTestDB(t)

	tmpl := template.Must(template.New("test").Parse(`
		{{define "error.html"}}Error: {{.Message}}{{end}}
		{{define "login.html"}}Login{{end}}
		{{define "dashboard.html"}}Dashboard{{end}}
		{{define "zones.html"}}Zones{{end}}
		{{define "zone_create.html"}}Create Zone{{end}}
		{{define "zone_view.html"}}View Zone{{end}}
		{{define "record_create.html"}}Create Record{{end}}
		{{define "record_edit.html"}}Edit Record{{end}}
		{{define "users.html"}}Users{{end}}
		{{define "user_create.html"}}Create User{{end}}
		{{define "user_edit.html"}}Edit User{{end}}
		{{define "profile.html"}}Profile{{end}}
	`))

	return &Handler{
		DB:   db,
		PDNS: pdnsClient,
		Cfg:  config.DefaultConfig(),
		Tmpl: tmpl,
	}
}

func newTestHandlerWithPDNS(t *testing.T, handler testutil.PDNSHandlerFunc) (*Handler, *httptest.Server) {
	t.Helper()
	srv, client := testutil.NewTestPDNSServer(t, handler)
	db := newTestDB(t)

	tmpl := template.Must(template.New("test").Parse(`
		{{define "error.html"}}Error: {{.Message}}{{end}}
		{{define "login.html"}}Login{{end}}
		{{define "dashboard.html"}}Dashboard{{end}}
		{{define "zones.html"}}Zones{{end}}
		{{define "zone_create.html"}}Create Zone{{end}}
		{{define "zone_view.html"}}View Zone{{end}}
		{{define "record_create.html"}}Create Record{{end}}
		{{define "record_edit.html"}}Edit Record{{end}}
		{{define "users.html"}}Users{{end}}
		{{define "user_create.html"}}Create User{{end}}
		{{define "user_edit.html"}}Edit User{{end}}
		{{define "profile.html"}}Profile{{end}}
	`))

	return &Handler{
		DB:   db,
		PDNS: client,
		Cfg:  config.DefaultConfig(),
		Tmpl: tmpl,
	}, srv
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

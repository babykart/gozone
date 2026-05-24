package handlers

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/pdns"
)

func newTestPDNSServer(t *testing.T) (*httptest.Server, *pdns.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	client := pdns.NewClient(&config.PowerDNSConfig{
		APIURL:   srv.URL,
		APIKey:   "test",
		ServerID: "localhost",
	})
	return srv, client
}

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			first_name TEXT NOT NULL DEFAULT '',
			last_name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT 'user',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			zone_id TEXT,
			action TEXT NOT NULL,
			details TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			last_used_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME
		)`,
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	_, pdnsClient := newTestPDNSServer(t)
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

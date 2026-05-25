package dyndns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
)

func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(&config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedHashedUser(t *testing.T, db *database.DB, username, password, role string, enabled bool) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 4) // cost 4 for speed
	if err != nil {
		t.Fatal(err)
	}
	enabledVal := 0
	if enabled {
		enabledVal = 1
	}
	_, err = db.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, ?)`,
		username, username+"@test.local", string(hash), role, enabledVal,
	)
	if err != nil {
		t.Fatal(err)
	}
}

type pdnsMock struct {
	zones       []models.Zone
	updateCalls int
	lastZone    string
	lastRRSet   models.RRSet
	updateErr   error
}

func newPDNSMock(zones []models.Zone) *pdnsMock {
	return &pdnsMock{zones: zones}
}

func (m *pdnsMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/zones") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(m.zones)
			return
		}

		if r.Method == http.MethodPatch {
			m.updateCalls++
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			if rrsets, ok := payload["rrsets"].([]interface{}); ok && len(rrsets) > 0 {
				rrsetData := rrsets[0].(map[string]interface{})
				m.lastZone = strings.TrimPrefix(r.URL.Path, "/servers/localhost/zones/")
				m.lastRRSet = models.RRSet{
					Name: rrsetData["name"].(string),
					Type: rrsetData["type"].(string),
					TTL:  int(rrsetData["ttl"].(float64)),
				}
				if recs, ok := rrsetData["records"].([]interface{}); ok && len(recs) > 0 {
					rec := recs[0].(map[string]interface{})
					m.lastRRSet.Records = []models.RecordInfo{{Content: rec["content"].(string)}}
				}
			}
			if m.updateErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func setupTestHandler(t *testing.T) (*Handler, *database.DB, *pdnsMock) {
	t.Helper()
	db := newTestDB(t)
	mock := newPDNSMock([]models.Zone{
		{ID: "example.com.", Name: "example.com", Kind: "Native"},
		{ID: "test.org.", Name: "test.org", Kind: "Native"},
	})

	pdnsServer := httptest.NewServer(mock.handler())
	t.Cleanup(pdnsServer.Close)

	pdnsClient := pdns.NewClient(&config.PowerDNSConfig{
		APIURL:   pdnsServer.URL,
		APIKey:   "test",
		ServerID: "localhost",
	})

	return &Handler{
		DB:     db,
		PDNS:   pdnsClient,
		Domain: "",
	}, db, mock
}

func TestServeHTTP_CompleteFlow(t *testing.T) {
	h, db, mock := setupTestHandler(t)
	seedHashedUser(t, db, "dynuser", "secret", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=www.example.com&myip=1.2.3.4", nil)
	r.SetBasicAuth("dynuser", "secret")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "good 1.2.3.4") {
		t.Errorf("expected 'good 1.2.3.4', got %q", body)
	}
	if mock.updateCalls != 1 {
		t.Errorf("expected 1 update call, got %d", mock.updateCalls)
	}
	if mock.lastRRSet.Type != "A" {
		t.Errorf("expected A record, got %s", mock.lastRRSet.Type)
	}
}

func TestValidateUser_Success(t *testing.T) {
	h, db, _ := setupTestHandler(t)
	seedHashedUser(t, db, "valuser", "correct", "user", true)

	if !h.validateUser("valuser", "correct") {
		t.Error("expected validateUser to return true")
	}
}

func TestValidateUser_NotFound(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	if h.validateUser("nonexistent", "any") {
		t.Error("expected validateUser to return false for unknown user")
	}
}

func TestValidateUser_WrongPassword(t *testing.T) {
	h, db, _ := setupTestHandler(t)
	seedHashedUser(t, db, "wrongpass", "realpass", "user", true)

	if h.validateUser("wrongpass", "badpass") {
		t.Error("expected validateUser to return false for wrong password")
	}
}

func TestValidateUser_Disabled(t *testing.T) {
	h, db, _ := setupTestHandler(t)
	seedHashedUser(t, db, "disabled", "pass", "user", false)

	if h.validateUser("disabled", "pass") {
		t.Error("expected validateUser to return false for disabled user")
	}
}

func TestFindZone_ExactMatch(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	zone, err := h.findZone("example.com")
	if err != nil {
		t.Fatalf("findZone failed: %v", err)
	}
	if zone != "example.com" {
		t.Errorf("expected example.com, got %s", zone)
	}
}

func TestFindZone_Subdomain(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	zone, err := h.findZone("www.example.com")
	if err != nil {
		t.Fatalf("findZone failed: %v", err)
	}
	if zone != "example.com" {
		t.Errorf("expected example.com, got %s", zone)
	}
}

func TestFindZone_TrailingDot(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	zone, err := h.findZone("www.example.com.")
	if err != nil {
		t.Fatalf("findZone failed: %v", err)
	}
	if zone != "example.com" {
		t.Errorf("expected example.com, got %s", zone)
	}
}

func TestFindZone_NoMatch(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	_, err := h.findZone("unknown.domain.com")
	if err == nil {
		t.Error("expected error for unmatched hostname")
	}
}

func TestUpdateRecord_Success(t *testing.T) {
	h, _, mock := setupTestHandler(t)

	err := h.updateRecord("example.com", "www.example.com", "A", "10.0.0.1")
	if err != nil {
		t.Fatalf("updateRecord failed: %v", err)
	}
	if mock.updateCalls != 1 {
		t.Errorf("expected 1 update, got %d", mock.updateCalls)
	}
	if mock.lastRRSet.Name != "www.example.com" {
		t.Errorf("expected name www.example.com, got %s", mock.lastRRSet.Name)
	}
}

func TestUpdateRecord_PDNSError(t *testing.T) {
	h, _, mock := setupTestHandler(t)
	mock.updateErr = fmt.Errorf("simulated error")

	err := h.updateRecord("example.com", "www.example.com", "A", "10.0.0.1")
	if err == nil {
		t.Error("expected error from updateRecord")
	}
}

func TestServeHTTP_IPv6(t *testing.T) {
	h, db, mock := setupTestHandler(t)
	seedHashedUser(t, db, "ipv6user", "pass", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=ipv6.example.com&myip=2001:db8::1", nil)
	r.SetBasicAuth("ipv6user", "pass")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "good 2001:db8::1") {
		t.Errorf("expected 'good 2001:db8::1', got %q", w.Body.String())
	}
	if mock.lastRRSet.Type != "AAAA" {
		t.Errorf("expected AAAA record, got %s", mock.lastRRSet.Type)
	}
}

func TestServeHTTP_MultipleHostnames(t *testing.T) {
	h, db, _ := setupTestHandler(t)
	seedHashedUser(t, db, "multi", "pass", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=www.example.com,mail.example.com&myip=5.6.7.8", nil)
	r.SetBasicAuth("multi", "pass")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Count(body, "good") != 2 {
		t.Errorf("expected 2 good results, got %q", body)
	}
}

func TestServeHTTP_FallbackMyipToIP(t *testing.T) {
	h, db, mock := setupTestHandler(t)
	seedHashedUser(t, db, "fallback", "pass", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=www.example.com&ip=9.9.9.9", nil)
	r.SetBasicAuth("fallback", "pass")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "good 9.9.9.9") {
		t.Errorf("expected 'good 9.9.9.9', got %q", w.Body.String())
	}
	if mock.lastRRSet.Records[0].Content != "9.9.9.9" {
		t.Errorf("expected IP 9.9.9.9, got %s", mock.lastRRSet.Records[0].Content)
	}
}

func TestServeHTTP_FallbackToRemoteAddr(t *testing.T) {
	h, db, mock := setupTestHandler(t)
	seedHashedUser(t, db, "remote", "pass", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=www.example.com", nil)
	r.RemoteAddr = "10.20.30.40:12345"
	r.SetBasicAuth("remote", "pass")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "good 10.20.30.40") {
		t.Errorf("expected 'good 10.20.30.40', got %q", w.Body.String())
	}
	if mock.lastRRSet.Records[0].Content != "10.20.30.40" {
		t.Errorf("expected IP 10.20.30.40, got %s", mock.lastRRSet.Records[0].Content)
	}
}

func TestServeHTTP_InvalidIP(t *testing.T) {
	h, db, _ := setupTestHandler(t)
	seedHashedUser(t, db, "badip", "pass", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=www.example.com&myip=not-an-ip", nil)
	r.SetBasicAuth("badip", "pass")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestServeHTTP_BadAuth(t *testing.T) {
	h, db, _ := setupTestHandler(t)
	seedHashedUser(t, db, "badauth", "real", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=www.example.com&myip=1.2.3.4", nil)
	r.SetBasicAuth("badauth", "wrong")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestServeHTTP_NoHost(t *testing.T) {
	h, db, _ := setupTestHandler(t)
	seedHashedUser(t, db, "nohost", "pass", "user", true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=unknown.example.net&myip=1.2.3.4", nil)
	r.SetBasicAuth("nohost", "pass")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "nohost") {
		t.Errorf("expected 'nohost' in response body, got %q", w.Body.String())
	}
}

func TestCheckPassword(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("mypassword"), 4)

	if !checkPassword(string(hash), "mypassword") {
		t.Error("expected checkPassword to return true for correct password")
	}
	if checkPassword(string(hash), "wrongpassword") {
		t.Error("expected checkPassword to return false for wrong password")
	}
}

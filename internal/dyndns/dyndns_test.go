package dyndns

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/pdns"
)

func setupTestHandler(t *testing.T) *Handler {
	t.Helper()

	pdnsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	t.Cleanup(pdnsServer.Close)

	pdnsClient := pdns.NewClient(&config.PowerDNSConfig{
		APIURL:   pdnsServer.URL,
		APIKey:   "test",
		ServerID: "localhost",
	})

	return &Handler{
		DB:     nil,
		PDNS:   pdnsClient,
		Domain: "example.com",
	}
}

func TestDynDNSServeHTTP_MethodNotAllowed(t *testing.T) {
	h := setupTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/nic/update?hostname=test.example.com&myip=1.2.3.4", nil)
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestDynDNSServeHTTP_RequiresAuth(t *testing.T) {
	h := setupTestHandler(t)
	w := httptest.NewRecorder()
	// Must include hostname to pass the hostname check before auth
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=test.example.com&myip=1.2.3.4", nil)
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestDynDNSServeHTTP_NoHostname(t *testing.T) {
	h := setupTestHandler(t)
	w := httptest.NewRecorder()
	// No hostname provided even with valid auth -> 400
	r := httptest.NewRequest(http.MethodGet, "/nic/update?myip=1.2.3.4", nil)
	r.SetBasicAuth("testuser", "testpass")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

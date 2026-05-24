package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthLive(t *testing.T) {
	h := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	h.HealthLive(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
}

func TestHealthReady_AllOK(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"server_id":"localhost","daemon_type":"authoritative","version":"4.8.0"}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.HealthReady(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
	if v, ok := resp.Checks["database"]; !ok || v != "ok" {
		t.Errorf("expected database ok, got %q", resp.Checks["database"])
	}
	if v, ok := resp.Checks["powerdns"]; !ok || v != "ok" {
		t.Errorf("expected powerdns ok, got %q", resp.Checks["powerdns"])
	}
}

func TestHealthReady_PDNSFailure(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.HealthReady(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "degraded" {
		t.Errorf("expected status degraded, got %s", resp.Status)
	}
	if v, ok := resp.Checks["database"]; !ok || v != "ok" {
		t.Errorf("expected database ok, got %q", resp.Checks["database"])
	}
	if v, ok := resp.Checks["powerdns"]; !ok || v == "ok" {
		t.Errorf("expected powerdns error, got %q", resp.Checks["powerdns"])
	}
}

func TestHealthReady_DBFailure(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"server_id":"localhost","daemon_type":"authoritative","version":"4.8.0"}`))
	})
	defer pdnsSrv.Close()

	h.DB.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.HealthReady(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "degraded" {
		t.Errorf("expected status degraded, got %s", resp.Status)
	}
	if v, ok := resp.Checks["database"]; !ok || v == "ok" {
		t.Errorf("expected database error, got %q", resp.Checks["database"])
	}
	if v, ok := resp.Checks["powerdns"]; !ok || v != "ok" {
		t.Errorf("expected powerdns ok, got %q", resp.Checks["powerdns"])
	}
}

func TestHealthReady_BothFail(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	})
	defer pdnsSrv.Close()

	h.DB.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	h.HealthReady(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "degraded" {
		t.Errorf("expected status degraded, got %s", resp.Status)
	}
	if v, ok := resp.Checks["database"]; !ok || v == "ok" {
		t.Errorf("expected database error, got %q", resp.Checks["database"])
	}
	if v, ok := resp.Checks["powerdns"]; !ok || v == "ok" {
		t.Errorf("expected powerdns error, got %q", resp.Checks["powerdns"])
	}
}

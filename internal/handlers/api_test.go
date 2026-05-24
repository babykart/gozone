package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
)

func TestAPIListZones(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "example.com", Name: "example.com", Kind: "Native"},
		})
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	h.APIListZones(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var zones []models.Zone
	if err := json.NewDecoder(w.Body).Decode(&zones); err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if zones[0].Name != "example.com" {
		t.Errorf("expected example.com, got %s", zones[0].Name)
	}
}

func TestAPIListZones_Empty(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`null`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	h.APIListZones(w, r)

	var zones []models.Zone
	json.NewDecoder(w.Body).Decode(&zones)
	if zones == nil {
		t.Error("expected empty slice, got nil")
	}
}

func TestAPIGetZone(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIGetZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var zone models.Zone
	json.NewDecoder(w.Body).Decode(&zone)
	if zone.Name != "example.com" {
		t.Errorf("expected example.com, got %s", zone.Name)
	}
}

func TestAPICreateZone(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req models.ZoneCreateRequest
		json.NewDecoder(r.Body).Decode(&req)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.Zone{
			ID: req.Name, Name: req.Name, Kind: req.Kind,
		})
	})
	defer pdnsSrv.Close()

	body := `{"name":"newzone.com","kind":"Native"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	h.APICreateZone(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestAPICreateZone_InvalidJSON(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones", jsonBody(`not json`))
	r.Header.Set("Content-Type", "application/json")
	h.APICreateZone(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAPIDeleteZone(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIDeleteZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIListRecords(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "www.example.com", Type: "A", TTL: 300},
			},
		})
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var records []models.RRSet
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

func TestAPICreateRecord(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestAPIUpdateRecord(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com","type":"A","ttl":600,"records":[{"content":"5.6.7.8"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIDeleteRecord(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com","type":"A"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIDeleteRecord(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIDeleteRecord_InvalidJSON(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com/records", jsonBody(`bad`))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIDeleteRecord(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAPIStats(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	h.APIStats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if _, ok := result["statistics"]; !ok {
		t.Error("expected statistics in response")
	}
	if _, ok := result["zone_count"]; !ok {
		t.Error("expected zone_count in response")
	}
}

func TestAPIListZones_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	h.APIListZones(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	var resp apiError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Code != ErrCodeInternalError {
		t.Errorf("expected code %s, got %s", ErrCodeInternalError, resp.Code)
	}
}

func TestAPIGetZone_NotFound(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent", nil)
	r.SetPathValue("zone_id", "nonexistent")
	h.APIGetZone(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	var resp apiError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Code != ErrCodeZoneNotFound {
		t.Errorf("expected code %s, got %s", ErrCodeZoneNotFound, resp.Code)
	}
}

func TestAPICreateZone_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	body := `{"name":"fail.example.com","kind":"Native"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	h.APICreateZone(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAPIDeleteZone_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIDeleteZone(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAPIListRecords_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAPIListRecords_NullResponse(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`null`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var records []models.RRSet
	json.NewDecoder(w.Body).Decode(&records)
	if records == nil {
		t.Error("expected empty slice, got nil")
	}
}

func TestAPICreateRecord_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAPICreateRecord_InvalidJSON(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com/records", jsonBody(`bad`))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAPIUpdateRecord_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com","type":"A","ttl":600,"records":[{"content":"5.6.7.8"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAPIUpdateRecord_InvalidJSON(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com/records", jsonBody(`bad`))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAPIDeleteRecord_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com","type":"A"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIDeleteRecord(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAPIStats_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	h.APIStats(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func jsonBody(s string) *strings.Reader {
	return strings.NewReader(s)
}

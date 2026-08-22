package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
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

// TestAPICreateZone_NormalizesNameAndNameservers verifies that the API
// canonicalises the zone name and nameservers to lowercase + trailing dot,
// matching the UI handler's behaviour. Without this, "example.com" (no dot)
// causes a PDNS error.
func TestAPICreateZone_NormalizesNameAndNameservers(t *testing.T) {
	var sent models.ZoneCreateRequest
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&sent)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.Zone{ID: sent.Name, Name: sent.Name, Kind: sent.Kind})
	})
	defer pdnsSrv.Close()

	body := `{"name":"Example.COM","kind":"Native","nameservers":["ns1.example.com","ns2.example.com."]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	h.APICreateZone(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if sent.Name != "example.com." {
		t.Errorf("PDNS received name=%q, want %q", sent.Name, "example.com.")
	}
	if len(sent.Nameservers) != 2 {
		t.Fatalf("expected 2 nameservers, got %d", len(sent.Nameservers))
	}
	if sent.Nameservers[0] != "ns1.example.com." {
		t.Errorf("PDNS received ns[0]=%q, want %q", sent.Nameservers[0], "ns1.example.com.")
	}
	if sent.Nameservers[1] != "ns2.example.com." {
		t.Errorf("PDNS received ns[1]=%q, want %q (no double dot)", sent.Nameservers[1], "ns2.example.com.")
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

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: 1, Username: "admin", Role: "admin"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.APIDeleteZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Regression: an API-driven zone delete must produce a 'delete_zone'
	// activity log entry attributed to the API key owner.
	var (
		count      int
		userID     sql.NullInt64
		hasViaAPI  bool
		detailsStr string
	)
	h.DB.QueryRow(`SELECT COUNT(*) FROM activity_logs WHERE action='delete_zone' AND zone_id='example.com'`).Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 delete_zone activity log, got %d", count)
	}
	h.DB.QueryRow(`SELECT user_id, details FROM activity_logs WHERE action='delete_zone' AND zone_id='example.com'`).Scan(&userID, &detailsStr)
	if !userID.Valid || userID.Int64 != 1 {
		t.Errorf("expected delete_zone attributed to user_id=1, got %v", userID)
	}
	hasViaAPI = strings.Contains(detailsStr, "via API")
	if !hasViaAPI {
		t.Errorf("expected details to mention 'via API', got %q", detailsStr)
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

func TestAPIListRecords_FilteredByName(t *testing.T) {
	var gotPath string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "www.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "1.2.3.4"}}},
				{Name: "www.example.com", Type: "AAAA", TTL: 300, Records: []models.RecordInfo{{Content: "::1"}}},
			},
		})
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records?name=www.example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// REVIEW.md mineur fix: the handler must canonicalise the name to a
	// trailing-dot FQDN before forwarding to PowerDNS — "www.example.com"
	// (no dot) would silently match nothing against the real backend.
	if !strings.Contains(gotPath, "rrset_name=www.example.com.") {
		t.Errorf("expected rrset_name to be FQDN-canonical, got %q", gotPath)
	}

	var records []models.RRSet
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 2 {
		t.Fatalf("expected 2 rrsets (A + AAAA), got %d", len(records))
	}
}

func TestAPIListRecords_FilteredByNameAndType(t *testing.T) {
	var gotPath string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "www.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "1.2.3.4"}}},
			},
		})
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records?name=www.example.com&type=A", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if !strings.Contains(gotPath, "rrset_name=www.example.com.") || !strings.Contains(gotPath, "rrset_type=A") {
		t.Errorf("expected FQDN rrset_name + rrset_type=A, got %q", gotPath)
	}

	var records []models.RRSet
	json.NewDecoder(w.Body).Decode(&records)
	if len(records) != 1 || records[0].Type != "A" {
		t.Fatalf("expected 1 A rrset, got %+v", records)
	}
}

func TestAPIListRecords_TypeWithoutName_Returns400(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("PDNS should not be called when query params are invalid, but got %s", r.Method)
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records?type=A", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "'type' query parameter requires 'name'") {
		t.Errorf("expected validation error message, got %s", w.Body.String())
	}
}

func TestAPIListRecords_Filtered_EmptyResult(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{},
		})
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records?name=missing.example.com&type=A", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var records []models.RRSet
	json.NewDecoder(w.Body).Decode(&records)
	if records == nil {
		t.Errorf("expected non-nil empty array, got nil")
	}
	if len(records) != 0 {
		t.Errorf("expected 0 rrsets, got %d", len(records))
	}
}

func TestAPICreateRecord(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		// APICreateRecord now issues a GET (ListRecords) to merge with any
		// existing RRSet before the PATCH (REVIEW.md M-4).
		if r.Method != http.MethodGet && r.Method != http.MethodPatch {
			t.Errorf("expected GET or PATCH, got %s", r.Method)
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
			return
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

// TestAPICreateRecord_MergesWithExisting is the REVIEW.md M-4 regression test:
// POST /records must append to an existing RRSet (preserving sibling records)
// instead of silently replacing it. The mock serves an existing A record on
// GET; the POST of a second A record must result in a PATCH carrying both.
func TestAPICreateRecord_MergesWithExisting(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Existing RRSet with one record.
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rrsets":[{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}]}]}`)) // #nosec G104 -- test helper
			return
		}
		captureRRSets(t, &sent)(w, r)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"5.6.7.8"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if len(sent) != 1 || len(sent[0].Records) != 2 {
		t.Fatalf("expected 1 rrset with 2 records (existing + new), got %+v", sent)
	}
	got := map[string]bool{}
	for _, rec := range sent[0].Records {
		got[rec.Content] = true
	}
	if !got["1.2.3.4"] || !got["5.6.7.8"] {
		t.Errorf("PATCH must preserve the existing record and add the new one; got %+v", got)
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

// captureRRSets decodes the rrsets PowerDNS receives in a PATCH body.
func captureRRSets(t *testing.T, got *[]models.RRSet) func(http.ResponseWriter, *http.Request) {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode PATCH body: %v", err)
			}
			*got = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Non-PATCH (e.g. the GET ListRecords that APICreateRecord now issues
		// to merge with the existing RRSet): return an empty rrsets list so the
		// client unmarshals cleanly (REVIEW.md M-4).
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
	}
}

func TestAPICreateRecord_MXEmbedsPriority(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	// Client sends the bare target plus a separate priority field — the same
	// shape APIListRecords returns.
	body := `{"name":"example.com.","type":"MX","ttl":3600,"records":[{"content":"mail.example.com.","priority":10}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if len(sent) != 1 || len(sent[0].Records) != 1 {
		t.Fatalf("expected 1 rrset with 1 record sent to PDNS, got %+v", sent)
	}
	// Priority must be embedded in the content and the separate element cleared.
	if got := sent[0].Records[0]; got.Content != "10 mail.example.com." || got.Priority != 0 {
		t.Errorf("PDNS received content=%q priority=%d, want %q and 0", got.Content, got.Priority, "10 mail.example.com.")
	}
}

func TestAPICreateRecord_PriorityZero(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"example.com.","type":"MX","ttl":3600,"records":[{"content":"mail.example.com.","priority":0}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if got := sent[0].Records[0].Content; got != "0 mail.example.com." {
		t.Errorf("PDNS received content=%q, want %q", got, "0 mail.example.com.")
	}
}

// TestAPICreateRecord_PriorityOutOfRange is the m49 regression test: an MX
// priority outside the 16-bit range (0-65535) must be rejected with a 400
// before reaching PowerDNS.
func TestAPICreateRecord_PriorityOutOfRange(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"example.com.","type":"MX","ttl":3600,"records":[{"content":"mail.example.com.","priority":99999}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-range priority, got %d (%s)", w.Code, w.Body.String())
	}
	if len(sent) != 0 {
		t.Errorf("expected no PDNS call for invalid priority, got %d sent rrsets", len(sent))
	}
}

// TestAPICreateRecord_CNAMEEnsuresTrailingDot is the regression test for the
// bug where a CNAME target without a trailing dot (e.g. "target.example.com")
// was forwarded to PowerDNS as-is, causing PDNS to reject the PATCH. The fix
// ensures FQDN-target types (CNAME, NS, PTR, ALIAS) and priority types
// (MX, SRV) get a trailing dot via EnsureTrailingDot in prepareRecordContent.
func TestAPICreateRecord_CNAMEEnsuresTrailingDot(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"CNAME","ttl":300,"records":[{"content":"target.example.com"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if len(sent) != 1 || len(sent[0].Records) != 1 {
		t.Fatalf("expected 1 rrset with 1 record, got %+v", sent)
	}
	if got := sent[0].Records[0].Content; got != "target.example.com." {
		t.Errorf("PDNS received content=%q, want %q (trailing dot must be ensured)", got, "target.example.com.")
	}
}

// TestAPICreateRecord_CNAMEPreservesExistingDot verifies that a CNAME target
// that already ends with a dot is not double-dotted.
func TestAPICreateRecord_CNAMEPreservesExistingDot(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"CNAME","ttl":300,"records":[{"content":"target.example.com."}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if got := sent[0].Records[0].Content; got != "target.example.com." {
		t.Errorf("PDNS received content=%q, want %q (no double dot)", got, "target.example.com.")
	}
}

// TestAPICreateRecord_AFSDBEnsuresTrailingDot verifies that AFSDB hostname
// (last field) gets a trailing dot.
func TestAPICreateRecord_AFSDBEnsuresTrailingDot(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"sub.example.com.","type":"AFSDB","ttl":3600,"records":[{"content":"1 afsdb.example.com"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if got := sent[0].Records[0].Content; got != "1 afsdb.example.com." {
		t.Errorf("PDNS received content=%q, want %q", got, "1 afsdb.example.com.")
	}
}

// TestAPICreateRecord_NAPTREnsuresTrailingDot verifies that NAPTR replacement
// (last field) gets a trailing dot.
func TestAPICreateRecord_NAPTREnsuresTrailingDot(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"sip.example.com.","type":"NAPTR","ttl":3600,"records":[{"content":"100 10 \"\" \"\" \"\" sip.example.com"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if got := sent[0].Records[0].Content; got != "100 10 \"\" \"\" \"\" sip.example.com." {
		t.Errorf("PDNS received content=%q, want trailing dot on replacement", got)
	}
}

// TestAPICreateRecord_DNAMEEnsuresTrailingDot verifies that DNAME target
// gets a trailing dot.
func TestAPICreateRecord_DNAMEEnsuresTrailingDot(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"sub.example.com.","type":"DNAME","ttl":3600,"records":[{"content":"target.example.com"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if got := sent[0].Records[0].Content; got != "target.example.com." {
		t.Errorf("PDNS received content=%q, want %q", got, "target.example.com.")
	}
}

// TestAPICreateRecord_SOANormalizesMnameRname verifies that SOA mname and
// rname (fields 0 and 1) each get a trailing dot, while the numeric fields
// are left untouched.
func TestAPICreateRecord_SOANormalizesMnameRname(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com hostmaster.example.com 1 10800 3600 604800 3600"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	want := "ns1.example.com. hostmaster.example.com. 1 10800 3600 604800 3600"
	if got := sent[0].Records[0].Content; got != want {
		t.Errorf("PDNS received content=%q, want %q", got, want)
	}
}

// TestAPICreateRecord_RPNormalizesBothFields verifies that RP mbox and
// txtname (both FQDN fields) each get a trailing dot.
func TestAPICreateRecord_RPNormalizesBothFields(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"example.com.","type":"RP","ttl":3600,"records":[{"content":"admin.example.com txt.example.com"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	want := "admin.example.com. txt.example.com."
	if got := sent[0].Records[0].Content; got != want {
		t.Errorf("PDNS received content=%q, want %q", got, want)
	}
}

// TestAPICreateRecord_NSECNormalizesNextDomain verifies that NSEC next_domain
// (field 0) gets a trailing dot while type mnemonics are untouched.
func TestAPICreateRecord_NSECNormalizesNextDomain(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"NSEC","ttl":3600,"records":[{"content":"next.example.com A AAAA NS"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	want := "next.example.com. A AAAA NS"
	if got := sent[0].Records[0].Content; got != want {
		t.Errorf("PDNS received content=%q, want %q", got, want)
	}
}

// TestAPICreateRecord_MINFONormalizesBothFields verifies that MINFO rmailbx
// and emailbx (both FQDN fields) each get a trailing dot.
func TestAPICreateRecord_MINFONormalizesBothFields(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"example.com.","type":"MINFO","ttl":3600,"records":[{"content":"rmailbx.example.com emailbx.example.com"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	want := "rmailbx.example.com. emailbx.example.com."
	if got := sent[0].Records[0].Content; got != want {
		t.Errorf("PDNS received content=%q, want %q", got, want)
	}
}

func TestAPICreateRecord_NormalizesName(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	// Relative name must be canonicalised against the zone with a trailing dot.
	body := `{"name":"www","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APICreateRecord(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	if sent[0].Name != "www.example.com." {
		t.Errorf("PDNS received name=%q, want %q", sent[0].Name, "www.example.com.")
	}
}

func TestAPIUpdateRecord_SRVEmbedsPriority(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"_sip._tcp.example.com.","type":"SRV","ttl":3600,"records":[{"content":"5 5060 sip.example.com.","priority":10}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", jsonBody(body))
	r.SetPathValue("zone_id", "example.com.")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if got := sent[0].Records[0]; got.Content != "10 5 5060 sip.example.com." || got.Priority != 0 {
		t.Errorf("PDNS received content=%q priority=%d, want %q and 0", got.Content, got.Priority, "10 5 5060 sip.example.com.")
	}
}

func TestAPIListRecords_FilteredByName_PreservesFQDN(t *testing.T) {
	// When the client already sends a canonical FQDN (with trailing dot) the
	// handler must pass it through unchanged — no double-dot, no rewrite.
	var gotPath string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"rrsets":[]}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./records?name=www.example.com.&type=A", nil)
	r.SetPathValue("zone_id", "example.com.")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(gotPath, "rrset_name=www.example.com.") {
		t.Errorf("expected canonical FQDN to round-trip, got %q", gotPath)
	}
	if strings.Contains(gotPath, "rrset_name=www.example.com..") {
		t.Errorf("normaliser must not add a second trailing dot, got %q", gotPath)
	}
}

func TestAPIListRecords_FilteredByRelativeName(t *testing.T) {
	// "www" must be expanded against the zone into "www.example.com." — the
	// same canonicalisation the write path applies in prepareAPIRecordSet.
	var gotPath string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"rrsets":[]}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./records?name=www&type=A", nil)
	r.SetPathValue("zone_id", "example.com.")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(gotPath, "rrset_name=www.example.com.") {
		t.Errorf("relative name must expand to FQDN, got %q", gotPath)
	}
}

func TestAPIListRecords_FilteredByApex(t *testing.T) {
	// "@" is the standard apex shorthand and must resolve to the zone name
	// with trailing dot, matching the write path's behaviour.
	var gotPath string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"rrsets":[]}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./records?name=%40", nil)
	r.SetPathValue("zone_id", "example.com.")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(gotPath, "rrset_name=example.com.") {
		t.Errorf("@ must resolve to zone apex, got %q", gotPath)
	}
}

func TestAPIListRecords_FilteredByName_CaseInsensitive(t *testing.T) {
	// PDNS canonical names are lowercase; the handler must lowercase before
	// forwarding so a client asking for "WWW.Example.COM" still matches.
	var gotPath string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"rrsets":[]}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com./records?name=WWW.Example.COM", nil)
	r.SetPathValue("zone_id", "example.com.")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(gotPath, "rrset_name=www.example.com.") {
		t.Errorf("name must be lowercased before forwarding, got %q", gotPath)
	}
}

func TestAPIListRecords_NoName_NoNormalization(t *testing.T) {
	// Sanity: when no name is given, the handler must call the unfiltered
	// endpoint and never touch the query string.
	var gotPath string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"rrsets":[]}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com/records", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIListRecords(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotPath != "" {
		t.Errorf("expected empty query string, got %q", gotPath)
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

// TestAPIDeleteRecord_NormalizesName is the m27 regression test: a name
// without a trailing dot must be normalized to the FQDN before reaching
// PowerDNS.
func TestAPIDeleteRecord_NormalizesName(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com","type":"A"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIDeleteRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(sent) != 1 || sent[0].Name != "www.example.com." {
		t.Errorf("expected PDNS to receive name www.example.com., got %+v", sent)
	}
}

// TestAPIDeleteRecord_RejectsEmptyName verifies the m27 name validation: an
// empty name is rejected with 400 before PowerDNS is contacted. This matters
// because normalizeRecordName("") would otherwise resolve to the zone apex and
// could delete apex records (SOA/NS).
func TestAPIDeleteRecord_RejectsEmptyName(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("PDNS should not be called for an empty name")
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"","type":"A"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/zones/example.com/records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com")
	h.APIDeleteRecord(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty name, got %d", w.Code)
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

// TestAPIListZones_FilterErrorFailClosed is the m25 regression test: when
// filterZonesForUser fails (DB error in the zone-group lookup), the endpoint
// must stay fail-closed — never return the unfiltered zones. It now surfaces
// the outage as HTTP 500 instead of 200-with-empty-list: an empty list would
// present a database fault as "you have no zones", indistinguishable from a
// legitimate empty state.
func TestAPIListZones_FilterErrorFailClosed(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "a.example.", Name: "a.example.", Kind: "Native"},
			{ID: "b.example.", Name: "b.example.", Kind: "Native"},
		})
	})
	defer pdnsSrv.Close()

	userID := seedUserWithHash(t, h, "zoneuser", "pass", "user")

	// Break the zone-group lookup so filterZonesForUser returns an error.
	if _, err := h.DB.Exec("DROP TABLE zone_group_zones"); err != nil {
		t.Fatalf("drop zone_group_zones: %v", err)
	}

	user := &models.User{ID: userID, Username: "zoneuser", Role: "user"}
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil), user)
	w := httptest.NewRecorder()
	h.APIListZones(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 (fail-closed with a visible error), got %d: %s", w.Code, w.Body.String())
	}
	var resp apiError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != ErrCodeInternalError {
		t.Errorf("expected code %s, got %s", ErrCodeInternalError, resp.Code)
	}
	// The fail-closed invariant: no zone name may ever appear in the body.
	if body := w.Body.String(); strings.Contains(body, "a.example") || strings.Contains(body, "b.example") {
		t.Errorf("unfiltered zones leaked into the error response: %s", body)
	}
}

func TestAPIGetZone_NotFound(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Not Found"}`))
	})
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

func TestAPIGetZone_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, nil)
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	h.APIGetZone(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	var resp apiError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Code != ErrCodeInternalError {
		t.Errorf("expected code %s, got %s", ErrCodeInternalError, resp.Code)
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

func TestAPIListRecords_NotFound(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Not Found"}`))
	})
	defer pdnsSrv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones/nonexistent/records", nil)
	r.SetPathValue("zone_id", "nonexistent")
	h.APIListRecords(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	var resp apiError
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Code != ErrCodeRecordNotFound {
		t.Errorf("expected code %s, got %s", ErrCodeRecordNotFound, resp.Code)
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

// TestAPIUpdateRecord_CommentsPassedThroughUnchanged verifies the REVIEW.md
// note "reste à vérifier que l'API JSON ne déclenche pas de re-déduplication
// incorrecte": the REST path does NOT go through buildCommentsPatch, so the
// `comments` array is forwarded to PowerDNS exactly as the client sent it
// (no implicit dedup, no clearing, no padding with existing comments). The
// client is in full control — same PDNS REPLACE semantics documented in the
// API section of the README.
func TestAPIUpdateRecord_CommentsPassedThroughUnchanged(t *testing.T) {
	var sent []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer pdnsSrv.Close()

	// Client sends the same content twice in the comments array — the API
	// path must NOT silently dedup them; PowerDNS replaces the list and the
	// duplicates end up on the RRSet exactly as transmitted.
	body := `{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}],"comments":[{"content":"dup"},{"content":"dup"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com.")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if len(sent) != 1 {
		t.Fatalf("expected 1 rrset sent to PDNS, got %d", len(sent))
	}
	patch := sent[0].Comments
	if patch == nil || patch.Clear {
		t.Fatalf("expected Items patch (no Clear), got %+v", patch)
	}
	if len(patch.Items) != 2 {
		t.Fatalf("API must forward duplicates unchanged, expected 2 comments, got %d (%+v)",
			len(patch.Items), patch.Items)
	}
	if patch.Items[0].Content != "dup" || patch.Items[1].Content != "dup" {
		t.Errorf("expected both comments to be 'dup', got %+v", patch.Items)
	}
}

// TestAPIUpdateRecord_CommentsAbsentInBody verifies that omitting the
// `comments` field entirely leaves the existing list untouched (no implicit
// clearing, no implicit padding). The REST API is a pass-through to PDNS,
// which interprets an absent comments field as "preserve".
func TestAPIUpdateRecord_CommentsAbsentInBody(t *testing.T) {
	var sent []byte
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			sent, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com.")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	// PATCH body must omit the comments field so PowerDNS preserves the
	// existing list. The web form path is the one that builds the patch;
	// the API path must never inject one.
	if strings.Contains(string(sent), `"comments"`) {
		t.Errorf("API path must not inject a comments field, got body %s", sent)
	}
}

// TestAPIUpdateRecord_ClearCommentsTrue verifies the REVIEW.md mineur fix
// "API REST : pas de signal explicite pour purger les commentaires RRSet":
// a client can set "clear_comments":true on the PUT body to wipe all existing
// comments without resorting to the round-trip-unsafe "comments":[] convention
// (which UnmarshalJSON normalises to "preserve").
//
// The handler-level state (`CommentPatch.Clear`) is observed indirectly via
// the raw PATCH body, which is the form PDNS actually sees: a `Clear=true`
// patch marshals to `"comments":[]`. Re-decoding the body would lose the
// `Clear` flag (UnmarshalJSON never sets it — by design, see CommentPatch
// doc), so we assert against the raw wire form instead.
func TestAPIUpdateRecord_ClearCommentsTrue(t *testing.T) {
	var sent []byte
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			sent, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}],"clear_comments":true}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com.")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(string(sent), `"comments":[]`) {
		t.Errorf("PDNS body must carry the explicit comments:[] purge, got %s", sent)
	}
	if strings.Contains(string(sent), `"clear_comments"`) {
		t.Errorf("clear_comments sentinel must not leak to PDNS, got %s", sent)
	}
}

// TestAPIUpdateRecord_ClearCommentsTrue_OverridesItems documents the
// exclusivity rule discussed in REVIEW.md: when both `clear_comments` and a
// non-empty `comments` array are sent, the clear wins and the supplied items
// are discarded. This mirrors the web form's behaviour where the
// `comment_clear` checkbox overrides the textarea. Asserted on the raw PATCH
// body since CommentPatch.UnmarshalJSON normalises `[]` to a nil Items slice
// (Clear is never set on re-decode).
func TestAPIUpdateRecord_ClearCommentsTrue_OverridesItems(t *testing.T) {
	var sent []byte
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			sent, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}],"comments":[{"content":"ignored"}],"clear_comments":true}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com.")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(string(sent), `"comments":[]`) {
		t.Errorf("clear_comments must win over supplied items, expected comments:[] in body, got %s", sent)
	}
	if strings.Contains(string(sent), `"ignored"`) {
		t.Errorf("supplied comments items must be discarded, got body %s", sent)
	}
}

// TestAPIUpdateRecord_ClearCommentsFalse verifies that an explicit
// `clear_comments:false` is treated identically to an absent field: the
// PATCH body never carries a `comments` field, so PDNS preserves the existing
// list. The explicit-false case is what the `*bool` sentinel exists for — a
// plain `bool` could not tell "absent" from "false" and would lose the
// distinction on every PUT.
func TestAPIUpdateRecord_ClearCommentsFalse(t *testing.T) {
	var sent []byte
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			sent, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}],"clear_comments":false}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com.")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(string(sent), `"comments"`) {
		t.Errorf("clear_comments:false must not inject a comments field, got %s", sent)
	}
}

// TestAPIUpdateRecord_ClearCommentsAbsentRejectsEmptyComments is the
// round-trip-safety regression: without the `clear_comments` sentinel, the
// API path must never emit a PDNS purge. A client that GETs an RRSet (PDNS
// returns `comments":[]` for an empty list) and PUTs it back must observe a
// preserve, not a purge — i.e. the PATCH body carries `"comments":null`,
// not `"comments":[]` and not a clear flag.
func TestAPIUpdateRecord_ClearCommentsAbsentRejectsEmptyComments(t *testing.T) {
	var sent []byte
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			sent, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	body := `{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"1.2.3.4"}],"comments":[]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/zones/example.com./records", jsonBody(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("zone_id", "example.com.")
	h.APIUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	bodyStr := string(sent)
	if strings.Contains(bodyStr, `"comments":[]`) {
		t.Errorf("comments:[] without clear_comments sentinel must not leak through as a purge, got body %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"comments":null`) {
		t.Errorf("expected comments:null (PDNS preserve) in PATCH body, got %s", bodyStr)
	}
	if strings.Contains(bodyStr, `"clear_comments"`) {
		t.Errorf("clear_comments sentinel must not leak to PDNS, got body %s", bodyStr)
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

// TestAPIStats_ZoneFilterErrorSurfaces500 is the /api/v1/stats variant: a
// failed zone-access lookup must not answer 200 with zone_count: 0, which a
// caller would read as an empty tenant rather than an outage.
func TestAPIStats_ZoneFilterErrorSurfaces500(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/zones") {
			json.NewEncoder(w).Encode([]models.Zone{
				{ID: "a.example.", Name: "a.example.", Kind: "Native"},
			})
			return
		}
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	defer pdnsSrv.Close()

	userID := seedUserWithHash(t, h, "statsuser", "pass", "user")
	if _, err := h.DB.Exec("DROP TABLE zone_group_zones"); err != nil {
		t.Fatalf("drop zone_group_zones: %v", err)
	}

	user := &models.User{ID: userID, Username: "statsuser", Role: "user"}
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil), user)
	w := httptest.NewRecorder()
	h.APIStats(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for a failed zone-access lookup, got %d: %s", w.Code, w.Body.String())
	}
	var resp apiError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != ErrCodeInternalError {
		t.Errorf("expected code %s, got %s", ErrCodeInternalError, resp.Code)
	}
}

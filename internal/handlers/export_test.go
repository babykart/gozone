package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func testExportPDNS() testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if strings.Contains(r.URL.RawQuery, "rrsets") {
			w.Write([]byte(`[{"name":"example.com.","id":"example.com.","kind":"Native","serial":2024010100}]`))
			return
		}

		if strings.Contains(path, "/zones/") && !strings.Contains(path, "/export") && !strings.Contains(path, "/import") && !strings.Contains(path, "/records") && !strings.Contains(path, "/cryptokeys") && !strings.Contains(path, "/metadata") {
			if r.Method == http.MethodGet {
				w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100,"rrsets":[{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600","disabled":false}]},{"name":"example.com.","type":"NS","ttl":3600,"records":[{"content":"ns1.example.com.","disabled":false}]},{"name":"www.example.com.","type":"A","ttl":3600,"records":[{"content":"192.0.2.1","disabled":false}]},{"name":"example.com.","type":"MX","ttl":3600,"records":[{"content":"mail.example.com.","disabled":false,"priority":10}]}]}`))
				return
			}
		}

		w.Write([]byte(`[]`))
	}
}

func testExportPDNSWithDisabled() testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if strings.Contains(r.URL.RawQuery, "rrsets") {
			w.Write([]byte(`[{"name":"example.com.","id":"example.com.","kind":"Native","serial":2024010100}]`))
			return
		}

		if strings.Contains(path, "/zones/") && !strings.Contains(path, "/export") && !strings.Contains(path, "/import") && !strings.Contains(path, "/records") && !strings.Contains(path, "/cryptokeys") && !strings.Contains(path, "/metadata") {
			if r.Method == http.MethodGet {
				w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100,"rrsets":[{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600","disabled":false}]},{"name":"example.com.","type":"NS","ttl":3600,"records":[{"content":"ns1.example.com.","disabled":false}]},{"name":"www.example.com.","type":"A","ttl":3600,"records":[{"content":"192.0.2.1","disabled":false},{"content":"198.51.100.1","disabled":true}]},{"name":"example.com.","type":"MX","ttl":3600,"records":[{"content":"mail.example.com.","disabled":false,"priority":10}]}]}`))
				return
			}
		}

		w.Write([]byte(`[]`))
	}
}

func TestExportZone_BIND(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, testExportPDNS())
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=bind", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()

	if !strings.HasPrefix(body, "$ORIGIN example.com.") {
		t.Errorf("expected $ORIGIN, got: %s", body[:60])
	}
	if !strings.Contains(body, "$TTL") {
		t.Errorf("expected $TTL, got: %s", body[:100])
	}
	if !strings.Contains(body, "IN SOA") {
		t.Errorf("expected SOA record, got: %s", body)
	}
	if !strings.Contains(body, "IN NS") {
		t.Errorf("expected NS record, got: %s", body)
	}
	if !strings.Contains(body, "IN A") {
		t.Errorf("expected A record, got: %s", body)
	}
	if !strings.Contains(body, "IN MX") {
		t.Errorf("expected MX record, got: %s", body)
	}
	if !strings.Contains(body, "10 mail.example.com.") {
		t.Errorf("expected MX priority+content, got: %s", body)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain Content-Type, got: %s", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") {
		t.Errorf("expected Content-Disposition attachment, got: %s", cd)
	}
}

func TestExportZone_CSV(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, testExportPDNS())
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=csv", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()

	if !strings.Contains(body, "name,type,content,ttl,priority,disabled") {
		t.Errorf("expected CSV header, got: %s", body)
	}
	if !strings.Contains(body, "SOA") {
		t.Errorf("expected SOA in CSV, got: %s", body)
	}
	if !strings.Contains(body, "192.0.2.1") {
		t.Errorf("expected A record content in CSV, got: %s", body)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/csv") {
		t.Errorf("expected text/csv Content-Type, got: %s", ct)
	}
}

func TestExportZone_InvalidFormat(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, testExportPDNS())
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=json", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid format, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid format") {
		t.Errorf("expected error message, got: %s", w.Body.String())
	}
}

func TestExportZone_BIND_ExcludesDisabledRecords(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, testExportPDNSWithDisabled())
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=bind", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()

	if !strings.Contains(body, "192.0.2.1") {
		t.Errorf("expected enabled A record content 192.0.2.1 in BIND output, got: %s", body)
	}
	if strings.Contains(body, "198.51.100.1") {
		t.Errorf("disabled A record content 198.51.100.1 should not appear in BIND output, got: %s", body)
	}
	if strings.Contains(body, "; disabled") {
		t.Errorf("BIND output must not contain '; disabled' annotation, got: %s", body)
	}
}

func TestExportZone_CSV_IncludesDisabledRecords(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, testExportPDNSWithDisabled())
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=csv", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()

	if !strings.Contains(body, "192.0.2.1") {
		t.Errorf("expected enabled A record content 192.0.2.1 in CSV output, got: %s", body)
	}
	if !strings.Contains(body, "198.51.100.1") {
		t.Errorf("CSV output should retain disabled records, expected 198.51.100.1, got: %s", body)
	}
	if !strings.Contains(body, "true") {
		t.Errorf("CSV output should mark disabled records with 'true', got: %s", body)
	}
}

func testExportPDNSWithComments() testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if strings.Contains(r.URL.RawQuery, "rrsets") {
			w.Write([]byte(`[{"name":"example.com.","id":"example.com.","kind":"Native","serial":2024010100}]`))
			return
		}

		if strings.Contains(path, "/zones/") && !strings.Contains(path, "/export") && !strings.Contains(path, "/import") && !strings.Contains(path, "/records") && !strings.Contains(path, "/cryptokeys") && !strings.Contains(path, "/metadata") {
			if r.Method == http.MethodGet {
				w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100,"rrsets":[{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600","disabled":false}]},{"name":"example.com.","type":"NS","ttl":3600,"records":[{"content":"ns1.example.com.","disabled":false}]},{"name":"www.example.com.","type":"A","ttl":3600,"records":[{"content":"192.0.2.1","disabled":false},{"content":"198.51.100.1","disabled":false}],"comments":[{"content":"managed by ops"},{"content":"reviewed 2026-01-01"}]}]}`))
				return
			}
		}

		w.Write([]byte(`[]`))
	}
}

func TestExportZone_CSV_IncludesComments(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, testExportPDNSWithComments())
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=csv", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()

	if !strings.Contains(body, ",comment\n") && !strings.HasSuffix(strings.Split(body, "\n")[0], ",comment") {
		t.Errorf("expected CSV header to end with ',comment', got: %s", strings.Split(body, "\n")[0])
	}
	if !strings.Contains(body, "managed by ops") {
		t.Errorf("expected first comment in CSV output, got: %s", body)
	}
	if !strings.Contains(body, "reviewed 2026-01-01") {
		t.Errorf("expected second comment in CSV output, got: %s", body)
	}
	// Both A record rows for www.example.com. should carry the same comment cell.
	count := strings.Count(body, "managed by ops\nreviewed 2026-01-01")
	if count != 2 {
		t.Errorf("expected both A record rows to carry the joined comments, got %d occurrences in: %s", count, body)
	}
}

func TestRelativeBindName(t *testing.T) {
	tests := []struct {
		name, origin, expected string
	}{
		{"example.com.", "example.com.", "@"},
		{"www.example.com.", "example.com.", "www"},
		{"test.www.example.com.", "example.com.", "test.www"},
		{"example.com.", "other.com.", "example.com."},
		{"example.com", "example.com.", "@"},
		{"www.example.com", "example.com.", "www"},
		{"other.com.", "example.com.", "other.com."},
	}

	for _, tc := range tests {
		t.Run(tc.name+"-"+tc.origin, func(t *testing.T) {
			result := relativeBindName(tc.name, tc.origin)
			if result != tc.expected {
				t.Errorf("relativeBindName(%q, %q) = %q, want %q", tc.name, tc.origin, result, tc.expected)
			}
		})
	}
}

func TestSortRRSets(t *testing.T) {
	records := []models.RRSet{
		{Name: "example.com.", Type: "A"},
		{Name: "example.com.", Type: "NS"},
		{Name: "example.com.", Type: "SOA"},
		{Name: "example.com.", Type: "MX"},
	}

	sortRRSets(records)

	if records[0].Type != "SOA" {
		t.Errorf("expected SOA first, got %s", records[0].Type)
	}
	if records[1].Type != "NS" {
		t.Errorf("expected NS second, got %s", records[1].Type)
	}
}

func TestFindSOATTY(t *testing.T) {
	records := []models.RRSet{
		{Name: "example.com.", Type: "SOA", TTL: 7200},
		{Name: "example.com.", Type: "NS", TTL: 3600},
	}

	ttl := findSOATTY(records)
	if ttl != 7200 {
		t.Errorf("expected 7200, got %d", ttl)
	}
}

func TestFindSOATTY_Default(t *testing.T) {
	records := []models.RRSet{
		{Name: "example.com.", Type: "NS", TTL: 3600},
	}

	ttl := findSOATTY(records)
	if ttl != 3600 {
		t.Errorf("expected default 3600, got %d", ttl)
	}
}

func TestFormatRecordContent(t *testing.T) {
	tests := []struct {
		rtype, content string
		priority       int
		expected       string
	}{
		{"MX", "mail.example.com.", 10, "10 mail.example.com."},
		{"MX", "mail.example.com.", 0, "0 mail.example.com."},
		{"SRV", "5 5060 sip.example.com.", 10, "10 5 5060 sip.example.com."},
		{"SRV", "5 5060 sip.example.com.", 0, "0 5 5060 sip.example.com."},
		{"TXT", "unquoted", 0, `"unquoted"`},
		{"TXT", `"already quoted"`, 0, `"already quoted"`},
		{"A", "192.0.2.1", 0, "192.0.2.1"},
		{"CNAME", "example.com.", 0, "example.com."},
	}

	for _, tc := range tests {
		t.Run(tc.rtype, func(t *testing.T) {
			result := formatRecordContent(tc.rtype, tc.content, tc.priority)
			if result != tc.expected {
				t.Errorf("formatRecordContent(%q, %q, %d) = %q, want %q", tc.rtype, tc.content, tc.priority, result, tc.expected)
			}
		})
	}
}

// TestExportZone_GetZoneError_Returns500 is the m23 regression test: a PDNS
// failure on GetZone must surface as HTTP 500 via renderErrorStatus, not be
// silently downgraded to 400 by a double WriteHeader before renderError.
func TestExportZone_GetZoneError_Returns500(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=bind", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on PDNS GetZone failure, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestExportZone_ListRecordsError_Returns500 verifies the second PDNS call
// (ListRecords) also surfaces as 500 via renderErrorStatus, not 400. GetZone
// and ListRecords both hit GET /zones/{id}; the first call (GetZone) succeeds
// and the second (ListRecords) fails.
func TestExportZone_ListRecordsError_Returns500(t *testing.T) {
	var zoneCalls int
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") && zoneCalls == 0 {
			zoneCalls++
			w.Header().Set("Content-Type", "application/json")
			// #nosec G104 — test handler writing to httptest.ResponseRecorder
			w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=bind", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on PDNS ListRecords failure, got %d (body=%s)", w.Code, w.Body.String())
	}
}

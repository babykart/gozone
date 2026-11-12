package handlers

import (
	"encoding/csv"
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
	t.Parallel()
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
	t.Parallel()
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

// TestExportZone_CSV_TXTStrings pins the CSV export shape of quoted types: a
// single-string TXT is exported bare (its one pair of quotes is a removable
// wrapper), while a multi-string TXT keeps its wire form (the quotes are
// per-string delimiters — stripping the outer pair corrupts the value).
func TestExportZone_CSV_TXTStrings(t *testing.T) {
	t.Parallel()
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "rrsets") {
			w.Write([]byte(`[{"name":"example.com.","id":"example.com.","kind":"Native"}]`)) // #nosec G104 -- test helper
			return
		}
		w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","rrsets":[
			{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600"}]},
			{"name":"single.example.com.","type":"TXT","ttl":3600,"records":[{"content":"\"v=spf1 mx ~all\""}]},
			{"name":"multi.example.com.","type":"TXT","ttl":3600,"records":[{"content":"\"k=rsa; p=MIIBIjANBg\" \"hqHzaTBj2w\""}]}
		]}`)) // #nosec G104 -- test helper
	})
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=csv", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	rows, err := csv.NewReader(w.Body).ReadAll()
	if err != nil {
		t.Fatalf("parse exported CSV: %v", err)
	}
	cells := map[string]string{}
	for _, row := range rows {
		if len(row) >= 3 {
			cells[row[0]] = row[2]
		}
	}
	if got := cells["single.example.com."]; got != "v=spf1 mx ~all" {
		t.Errorf("single-string TXT exported as %q, want the bare value", got)
	}
	if got := cells["multi.example.com."]; got != `"k=rsa; p=MIIBIjANBg" "hqHzaTBj2w"` {
		t.Errorf("multi-string TXT exported as %q, want the wire form", got)
	}
}

// TestExportZone_CSV_TXTMultiStringRoundTrip is the export→import round-trip
// contract for quoted types: the CSV cells produced by the export must parse
// back into the exact original wire contents. A multi-string TXT previously
// exported as a quote-mangled cell that re-imported as one string with
// literal quote characters — silently breaking e.g. DKIM keys.
func TestExportZone_CSV_TXTMultiStringRoundTrip(t *testing.T) {
	t.Parallel()
	wireSingle := "v=spf1 mx ~all"
	wireMulti := `"k=rsa; p=MIIBIjANBg" "hqHzaTBj2w"`
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "rrsets") {
			w.Write([]byte(`[{"name":"example.com.","id":"example.com.","kind":"Native"}]`)) // #nosec G104 -- test helper
			return
		}
		w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","rrsets":[
			{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600"}]},
			{"name":"single.example.com.","type":"TXT","ttl":3600,"records":[{"content":"\"v=spf1 mx ~all\""}]},
			{"name":"multi.example.com.","type":"TXT","ttl":3600,"records":[{"content":"\"k=rsa; p=MIIBIjANBg\" \"hqHzaTBj2w\""}]}
		]}`)) // #nosec G104 -- test helper
	})
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=csv", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("export: expected 200, got %d", w.Code)
	}

	rrsets, _, err := parseCSVZone(csv.NewReader(w.Body), "example.com.")
	if err != nil {
		t.Fatalf("re-import exported CSV: %v", err)
	}
	contents := map[string]string{}
	for _, rr := range rrsets {
		if rr.Type == "TXT" {
			contents[rr.Name] = rr.Records[0].Content
		}
	}
	// The single-string export is bare, so the import re-adds the wrapper.
	if got := contents["single.example.com."]; got != `"`+wireSingle+`"` {
		t.Errorf("single-string TXT round trip = %q, want %q", got, `"`+wireSingle+`"`)
	}
	// The multi-string export is wire-form, so the import must pass it through.
	if got := contents["multi.example.com."]; got != wireMulti {
		t.Errorf("multi-string TXT round trip = %q, want the original wire form %q", got, wireMulti)
	}
}

func TestExportZone_InvalidFormat(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestExportZone_GetZoneError_Returns500(t *testing.T) {
	t.Parallel()
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

// TestExportZone_GetZoneNotFound_Returns404 is the status-contract
// regression: a vanished zone is a 404, not a blanket 500 — the operator
// can tell "zone gone" from "server broken".
func TestExportZone_GetZoneNotFound_Returns404(t *testing.T) {
	t.Parallel()
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=bind", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	h.ExportZone(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("a missing zone must be 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestExportZone_ListRecordsError_Returns500 verifies the second PDNS call
// (ListRecords) also surfaces as 500 via renderErrorStatus, not 400. GetZone
// and ListRecords both hit GET /zones/{id}; the first call (GetZone) succeeds
// and the second (ListRecords) fails.
func TestExportZone_ListRecordsError_Returns500(t *testing.T) {
	t.Parallel()
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

// TestExportZone_AuthorizationRechecked is the T2 convergence RED proof. The
// web export must delegate FETCH+AUTHZ+RENDER to dnsops.Service.ExportZone,
// whose authorizeZone re-checks the zone grant fail-closed: a non-admin user
// WITHOUT a group grant on the zone must be refused with 403 BEFORE any
// PowerDNS fetch, and the response must not leak zone content. Pre-fix the
// handler fetched via h.PDNS directly (no in-handler authorization — the
// route middleware is not part of this unit harness), so it serves the
// export: this test fails with 200 + a PDNS hit until the handler converges.
func TestExportZone_AuthorizationRechecked(t *testing.T) {
	t.Parallel()
	pdnsCalled := false
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		pdnsCalled = true
		testExportPDNS()(w, r)
	})
	defer srv.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format=bind", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, &models.User{ID: 2, Username: "plain", Role: "user"})
	h.ExportZone(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("plain user without a grant: expected 403, got %d (body=%s)", w.Code, w.Body.String())
	}
	if pdnsCalled {
		t.Error("authorization must fail closed before any PowerDNS fetch")
	}
	if strings.Contains(w.Body.String(), "$ORIGIN") {
		t.Error("denied export must not leak zone content")
	}
}

// TestExportZone_ContentDispositionFilename is a contract PIN (green pre- and
// post-fix): the converged handler must keep the download contract — an
// attachment disposition whose filename is derived from the zone name, per
// format. The existing BIND/CSV tests pin the media types and attachment
// flag but not the filename itself.
func TestExportZone_ContentDispositionFilename(t *testing.T) {
	t.Parallel()
	cases := []struct {
		format, filename string
	}{
		{"bind", "example.com.zone"},
		{"csv", "example.com.csv"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			h, srv := newTestHandlerWithPDNS(t, testExportPDNS())
			defer srv.Close()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/zones/example.com./export?format="+tc.format, nil)
			r.SetPathValue("zone_id", "example.com.")
			r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
			h.ExportZone(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
			}
			cd := w.Header().Get("Content-Disposition")
			if !strings.Contains(cd, `attachment`) || !strings.Contains(cd, `filename="`+tc.filename+`"`) {
				t.Errorf("Content-Disposition = %q, want attachment with filename %q", cd, tc.filename)
			}
		})
	}
}

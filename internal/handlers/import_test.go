package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func importPDNS() testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100}`))
			return
		}
		w.Write([]byte(`[]`))
	}
}

func TestImportZone_BIND(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, importPDNS())
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600
@ IN NS ns1.example.com.
www IN A 192.0.2.1
@ IN MX 10 mail.example.com.`

	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.zone\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n--boundary--\r\n", bindContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	assertImportRedirect(t, w)

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='import_zone'").Scan(&count)
	if count != 1 {
		t.Errorf("expected a single summary activity log entry, got %d", count)
	}

	var details string
	h.DB.QueryRow("SELECT details FROM activity_logs WHERE action='import_zone' LIMIT 1").Scan(&details)
	if !strings.Contains(details, "Imported 4 RRSets (4 records) from BIND zone file") {
		t.Errorf("expected the summary details to count RRSets and records, got %q", details)
	}
}

func TestImportZone_CSV(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, importPDNS())
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content,ttl,priority,disabled\n@,SOA,\"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600\",3600,0,false\n@,NS,ns1.example.com.,3600,0,false\nwww,A,192.0.2.1,3600,0,false"

	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.csv\"\r\nContent-Type: text/csv\r\n\r\n%s\r\n--boundary--\r\n", csvContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	assertImportRedirect(t, w)

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='import_zone'").Scan(&count)
	if count != 1 {
		t.Errorf("expected a single summary activity log entry, got %d", count)
	}
	var details string
	h.DB.QueryRow("SELECT details FROM activity_logs WHERE action='import_zone' LIMIT 1").Scan(&details)
	if !strings.Contains(details, "Imported 3 RRSets (3 records) from CSV zone file") {
		t.Errorf("expected the summary details to count RRSets and records, got %q", details)
	}
}

func TestImportZone_NoFile(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, importPDNS())
	defer srv.Close()

	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", nil)
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestImportZone_PDNSError_NoLogs(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content\nwww,A,192.0.2.1"
	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.csv\"\r\nContent-Type: text/csv\r\n\r\n%s\r\n--boundary--\r\n", csvContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='import_zone'").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 activity logs on PDNS error, got %d", count)
	}
}

// TestImportZone_PDNSError_NoRawErrorLeak guards the error-leak contract: when PowerDNS
// returns a backend error whose body carries internal detail (e.g. a SQL
// fragment), that detail must NOT be surfaced to the user. The cause is logged
// server-side; the response body carries only a generic message.
func TestImportZone_PDNSError_NoRawErrorLeak(t *testing.T) {
	leak := "Error while executing query: SELECT password_hash FROM users WHERE id=1"
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"` + leak + `"}`))
	})
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content\nwww,A,192.0.2.1"
	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.csv\"\r\nContent-Type: text/csv\r\n\r\n%s\r\n--boundary--\r\n", csvContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// The raw upstream detail (SQL fragment, table/column names) must never
	// reach the response body. Only a generic message is rendered.
	respBody := w.Body.String()
	for _, needle := range []string{leak, "SELECT", "password_hash", "unexpected status"} {
		if strings.Contains(respBody, needle) {
			t.Errorf("response body leaks upstream detail %q: %s", needle, respBody)
		}
	}
	if !strings.Contains(respBody, "Failed to create records") {
		t.Errorf("expected generic user-facing message, got: %s", respBody)
	}
}

func TestImportZone_PDNSValidationError(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/") {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"error":"unknown record type"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content\nwww,A,192.0.2.1"
	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.csv\"\r\nContent-Type: text/csv\r\n\r\n%s\r\n--boundary--\r\n", csvContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for validation error, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='import_zone'").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 activity logs on PDNS validation error, got %d", count)
	}
}

func TestImportZone_PDNSUnauthorizedError(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content\nwww,A,192.0.2.1"
	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.csv\"\r\nContent-Type: text/csv\r\n\r\n%s\r\n--boundary--\r\n", csvContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	// Upstream auth failure is a gateway error (502), not a 401: the user's
	// session is valid, GoZone's own PowerDNS credential is broken.
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for PowerDNS unauthorized error, got %d", w.Code)
	}
}

// TestImportZone_BIND_SkippedLinesReported is the handler-level skipped-lines test at the
// handler level: a BIND file containing a malformed line must redirect with an
// ?import_skipped=N query param so the frontend can surface feedback.
func TestImportZone_BIND_SkippedLinesReported(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, importPDNS())
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600
www IN A 192.0.2.1
www 300`

	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.zone\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n--boundary--\r\n", bindContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d body=%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "import_skipped=1") {
		t.Errorf("expected redirect to carry ?import_skipped=1, got %q", loc)
	}
	var details string
	h.DB.QueryRow("SELECT details FROM activity_logs WHERE action='import_zone' LIMIT 1").Scan(&details)
	if !strings.Contains(details, "Imported 2 RRSets (2 records) from BIND zone file, 1 lines skipped") {
		t.Errorf("expected the summary entry to mention the skipped line count, got %q", details)
	}
}

func assertImportRedirect(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestParseBindZone(t *testing.T) {
	data := []byte(`$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600
@ IN NS ns1.example.com.
www IN A 192.0.2.1
@ IN MX 10 mail.example.com.`)

	rrsets, _, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 4 {
		t.Fatalf("expected 4 rrsets, got %d", len(rrsets))
	}

	types := map[string]bool{}
	for _, rr := range rrsets {
		types[rr.Type] = true
	}
	if !types["SOA"] || !types["NS"] || !types["A"] || !types["MX"] {
		t.Errorf("missing expected types: %v", types)
	}
}

func TestParseBindZone_Parens(t *testing.T) {
	data := []byte(`$ORIGIN example.com.
@ IN SOA ns1.example.com. hostmaster.example.com. (
    2024010100
    3600
    900
    1209600
    3600 )
@ IN NS ns1.example.com.`)

	rrsets, _, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 2 {
		t.Fatalf("expected 2 rrsets, got %d", len(rrsets))
	}
	if rrsets[0].Type != "SOA" {
		t.Errorf("expected SOA, got %s", rrsets[0].Type)
	}
	if len(rrsets[0].Records) != 1 {
		t.Errorf("expected 1 SOA record, got %d", len(rrsets[0].Records))
	}
}

func TestParseBindZone_IncludeDirective(t *testing.T) {
	data := []byte(`$ORIGIN example.com.
$INCLUDE /etc/bind/zones/other.zone
@ IN NS ns1.example.com.`)

	rrsets, _, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(rrsets))
	}
}

func TestParseBindZone_OwnerInheritance(t *testing.T) {
	// The two NS lines begin with whitespace and omit the owner: per RFC 1035
	// they inherit the previous owner ("@" -> the zone apex), rather than being
	// parsed as a record named "IN".
	data := []byte(`$ORIGIN example.com.
@ IN SOA ns1.example.com. hostmaster.example.com. 1 10800 3600 604800 3600
  IN NS ns1.example.com.
  IN NS ns2.example.com.
www IN A 192.0.2.1`)

	rrsets, _, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var ns *models.RRSet
	for i := range rrsets {
		// No record may have an empty owner name.
		if rrsets[i].Name == "" {
			t.Errorf("rrset with empty name: %+v", rrsets[i])
		}
		// No record may be named after a class token.
		if rrsets[i].Name == "IN.example.com." || rrsets[i].Type == "" {
			t.Errorf("class token leaked into a record: %+v", rrsets[i])
		}
		if rrsets[i].Type == "NS" {
			ns = &rrsets[i]
		}
	}

	if ns == nil {
		t.Fatal("no NS rrset found")
	}
	if ns.Name != "example.com." {
		t.Errorf("NS owner = %q, want %q", ns.Name, "example.com.")
	}
	if len(ns.Records) != 2 {
		t.Errorf("expected 2 inherited NS records, got %d", len(ns.Records))
	}
}

func TestParseBindZone_ShortLineNoPanic(t *testing.T) {
	// "www 300" is name + TTL with no class/type: idx runs past the token list.
	// The class check used to read tokens[idx] out of bounds (operator
	// precedence bug) and panic. Parsing must now complete without panicking.
	data := []byte(`$ORIGIN example.com.
www 300
@ IN NS ns1.example.com.`)

	rrsets, _, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var hasNS bool
	for _, rr := range rrsets {
		if rr.Type == "NS" {
			hasNS = true
		}
	}
	if !hasNS {
		t.Errorf("expected the valid NS record to be parsed, got %+v", rrsets)
	}
}

// TestParseBindZone_ReportsSkippedLines is a skipped-lines regression: lines that
// cannot be parsed into records are returned as skipped feedback instead of
// being silently dropped.
func TestParseBindZone_ReportsSkippedLines(t *testing.T) {
	data := []byte(`$ORIGIN example.com.
$TTL 3600
@ IN NS ns1.example.com.
www 300
lonelytoken
www IN A 192.0.2.1`)

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 2 {
		t.Fatalf("expected 2 valid rrsets (NS, A), got %d: %+v", len(rrsets), rrsets)
	}
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped lines, got %d: %+v", len(skipped), skipped)
	}
	gotLines := map[string]bool{}
	for _, s := range skipped {
		if s.Line == "" || s.Reason == "" {
			t.Errorf("skipped entry missing text/reason: %+v", s)
		}
		gotLines[s.Line] = true
	}
	if !gotLines["www 300"] {
		t.Errorf("expected 'www 300' (no type) to be reported as skipped, got %+v", skipped)
	}
	if !gotLines["lonelytoken"] {
		t.Errorf("expected 'lonelytoken' (single token) to be reported as skipped, got %+v", skipped)
	}
}

func TestParseCSVZone_TXT_Quoting(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
txt.example.com.,TXT,v=DMARC1; p=quarantine,3600,0,false
spf.example.com.,SPF,v=spf1 -all,3600,0,false
preq.example.com.,TXT,"""already quoted""",3600,0,false
multi.example.com.,TXT,"""part one"" ""part two""",3600,0,false`

	rrsets, skipped, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 4 {
		t.Fatalf("expected 4 rrsets, got %d (skipped: %+v)", len(rrsets), skipped)
	}

	// Unquoted TXT content should be wrapped in quotes for PDNS
	if rrsets[0].Records[0].Content != `"v=DMARC1; p=quarantine"` {
		t.Errorf("TXT content = %q, want %q", rrsets[0].Records[0].Content, `"v=DMARC1; p=quarantine"`)
	}
	// Unquoted SPF content should be wrapped in quotes
	if rrsets[1].Records[0].Content != `"v=spf1 -all"` {
		t.Errorf("SPF content = %q, want %q", rrsets[1].Records[0].Content, `"v=spf1 -all"`)
	}
	// Already-quoted TXT should pass through without double-quoting
	if rrsets[2].Records[0].Content != `"already quoted"` {
		t.Errorf("TXT pre-quoted content = %q, want %q", rrsets[2].Records[0].Content, `"already quoted"`)
	}
	// A balanced multi-string value passes through verbatim.
	if rrsets[3].Records[0].Content != `"part one" "part two"` {
		t.Errorf("TXT multi-string content = %q, want %q", rrsets[3].Records[0].Content, `"part one" "part two"`)
	}
}

func TestParseCSVZone(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
@,SOA,"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600",3600,0,false
example.com.,NS,ns1.example.com.,3600,0,false
www.example.com.,A,192.0.2.1,3600,0,false`

	rrsets, _, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 3 {
		t.Fatalf("expected 3 rrsets, got %d", len(rrsets))
	}
}

func TestParseCSVZone_NoData(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled`
	rrsets, _, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 0 {
		t.Errorf("expected 0 rrsets, got %d", len(rrsets))
	}
}

// TestParseCSVZone_SkipsInvalidRecords is a stored-input validation regression: invalid record
// types/contents are now validated and skipped (with a reason) instead of being
// forwarded to PowerDNS, which would surface a generic "failed to create
// records". A valid A row alongside is still imported.
func TestParseCSVZone_SkipsInvalidRecords(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
www.example.com.,A,not-an-ip,3600,0,false
www.example.com.,FOO,whatever,3600,0,false
mail.example.com.,A,192.0.2.5,3600,0,false`
	rrsets, skipped, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 valid rrset, got %d", len(rrsets))
	}
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped rows, got %d", len(skipped))
	}
}

// TestParseBindZone_SkipsInvalidRecords is the BIND counterpart: an invalid A
// content and an unknown type are skipped with a reason rather than sent to
// PowerDNS.
func TestParseBindZone_SkipsInvalidRecords(t *testing.T) {
	input := strings.Join([]string{
		"www.example.com. 300 IN A not-an-ip",
		"www.example.com. 300 IN FOO whatever",
		"mail.example.com. 300 IN A 192.0.2.5",
	}, "\n")
	rrsets, skipped, err := parseBindZone([]byte(input), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 valid rrset, got %d", len(rrsets))
	}
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped lines, got %d", len(skipped))
	}
}

func TestDetectFormat(t *testing.T) {
	if format := detectFormat("zone.csv"); format != "csv" {
		t.Errorf("expected csv, got %s", format)
	}
	if format := detectFormat("zone.zone"); format != "bind" {
		t.Errorf("expected bind, got %s", format)
	}
	if format := detectFormat("zone"); format != "bind" {
		t.Errorf("expected bind for unknown, got %s", format)
	}
}

func TestResolveBindName(t *testing.T) {
	origin := "example.com."

	tests := []struct {
		name, expected string
	}{
		{"@", "example.com."},
		{"www.example.com.", "www.example.com."},
		{"www", "www.example.com."},
	}

	for _, tc := range tests {
		result := resolveBindName(tc.name, origin)
		if result != tc.expected {
			t.Errorf("resolveBindName(%q, %q) = %q, want %q", tc.name, origin, result, tc.expected)
		}
	}
}

func TestGetCSVField(t *testing.T) {
	headers := map[string]int{"name": 0, "type": 1, "content": 2}
	row := []string{"example.com.", "A", "192.0.2.1"}

	if v := getCSVField(row, headers, "name"); v != "example.com." {
		t.Errorf("expected example.com., got %s", v)
	}
	if v := getCSVField(row, headers, "nonexistent"); v != "" {
		t.Errorf("expected empty, got %s", v)
	}
}

func TestParseCSVZone_Comments(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled,comment
www.example.com.,A,192.0.2.1,3600,0,false,managed by ops
www.example.com.,A,198.51.100.1,3600,0,false,managed by ops
mail.example.com.,A,192.0.2.10,3600,0,false,multi
mail.example.com.,A,192.0.2.11,3600,0,false,line
api.example.com.,A,192.0.2.20,3600,0,false,
txt.example.com.,TXT,"v=DMARC1; p=none",3600,0,false,"quoted, comment"`

	rrsets, _, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 4 {
		t.Fatalf("expected 4 rrsets, got %d", len(rrsets))
	}

	// www RRSet: two rows with the same comment cell → dedup → 1 Comment
	for _, rr := range rrsets {
		switch rr.Name {
		case "www.example.com.":
			if rr.Comments == nil || len(rr.Comments.Items) != 1 || rr.Comments.Items[0].Content != "managed by ops" {
				t.Errorf("www: expected single dedup comment 'managed by ops', got %+v", rr.Comments)
			}
		case "mail.example.com.":
			// Two rows with different cells ('multi', 'line') → 2 distinct Comments
			if rr.Comments == nil || len(rr.Comments.Items) != 2 {
				t.Errorf("mail: expected 2 distinct comments, got %+v", rr.Comments)
				continue
			}
			if rr.Comments.Items[0].Content != "multi" || rr.Comments.Items[1].Content != "line" {
				t.Errorf("mail: expected ['multi','line'], got %+v", rr.Comments.Items)
			}
		case "api.example.com.":
			if rr.Comments != nil && len(rr.Comments.Items) != 0 {
				t.Errorf("api: expected no comments (empty cell), got %+v", rr.Comments)
			}
		case "txt.example.com.":
			if rr.Comments == nil || len(rr.Comments.Items) != 1 || rr.Comments.Items[0].Content != "quoted, comment" {
				t.Errorf("txt: expected quoted comma comment, got %+v", rr.Comments)
			}
		}
	}
}

func TestParseCSVZone_MultiLineCommentCell(t *testing.T) {
	// A single cell with embedded newlines (CSV-quoted) should split into
	// multiple Comments — matching the web-UI textarea convention.
	input := "name,type,content,ttl,priority,disabled,comment\n" +
		"www.example.com.,A,192.0.2.1,3600,0,false,\"first line\nsecond line\nthird line\""

	rrsets, _, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(rrsets))
	}
	if rrsets[0].Comments == nil {
		t.Fatalf("expected non-nil Comments patch, got nil")
	}
	comments := rrsets[0].Comments.Items
	if len(comments) != 3 {
		t.Fatalf("expected 3 comments from multi-line cell, got %d: %+v", len(comments), comments)
	}
	want := []string{"first line", "second line", "third line"}
	for i, c := range comments {
		if c.Content != want[i] {
			t.Errorf("comment[%d] = %q, want %q", i, c.Content, want[i])
		}
	}
}

func TestAppendIfMissing(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		v    string
		want []string
	}{
		{"nil_empty", nil, "", nil},
		{"nil_new", nil, "x", []string{"x"}},
		{"existing", []string{"a", "b"}, "b", []string{"a", "b"}},
		{"missing", []string{"a", "b"}, "c", []string{"a", "b", "c"}},
		{"empty_into_existing", []string{"a"}, "", []string{"a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := appendIfMissing(tc.in, tc.v)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (%v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestParseCSVZone_FQDNTargetNormalization is a normalization regression test:
// CSV import must route through prepareRecordContent so FQDN-target types
// (CNAME/NS/PTR) get trailing dots, not just priority/quoted handling.
// TestParseCSVZone_RelativeAndApexNames is the zone-relative name regression:
// "www" used to become the TLD "www." and "@" became "@." (bare trailing-dot
// append), which PowerDNS rejects — failing the whole PATCH. Names must
// resolve against the zone like the BIND path and the web/API write paths.
func TestParseCSVZone_RelativeAndApexNames(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
@,A,192.0.2.1,3600,0,false
www,A,192.0.2.2,3600,0,false
www.example.com,A,192.0.2.3,3600,0,false
www.example.com.,A,192.0.2.4,3600,0,false
,NS,ns1.example.com.,3600,0,false`

	rrsets, skipped, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("parseCSVZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("no row should be skipped, got %+v", skipped)
	}

	// All four rows collapse into the same apex/www RRSets under the
	// canonical names; the empty-name NS row is skipped as before.
	byName := map[string]int{}
	for _, rr := range rrsets {
		byName[rr.Name]++
		if rr.Name != "example.com." && rr.Name != "www.example.com." {
			t.Errorf("record name %q is not canonical for the zone", rr.Name)
		}
	}
	if _, ok := byName["www.example.com."]; !ok {
		t.Error("relative name www must resolve to www.example.com.")
	}
	if _, ok := byName["example.com."]; !ok {
		t.Error("apex shorthand @ must resolve to example.com.")
	}
	for _, rr := range rrsets {
		if rr.Name == "www.example.com." && len(rr.Records) != 3 {
			t.Errorf("www rows (relative, dotless FQDN, absolute FQDN) must merge into one RRSet with 3 records, got %d", len(rr.Records))
		}
	}
}

func TestParseCSVZone_FQDNTargetNormalization(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
www.example.com.,CNAME,target.example.com,3600,0,false
example.com.,NS,ns1.example.com,3600,0,false
mail.example.com.,MX,mail.example.com,3600,10,false`

	rrsets, _, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 3 {
		t.Fatalf("expected 3 rrsets, got %d", len(rrsets))
	}

	want := []struct {
		rtype   string
		content string
	}{
		{"CNAME", "target.example.com."},
		{"NS", "ns1.example.com."},
		{"MX", "10 mail.example.com."},
	}
	for i, w := range want {
		if rrsets[i].Type != w.rtype {
			t.Errorf("rrset[%d] type = %q, want %q", i, rrsets[i].Type, w.rtype)
		}
		if rrsets[i].Records[0].Content != w.content {
			t.Errorf("rrset[%d] (%s) content = %q, want %q", i, w.rtype, rrsets[i].Records[0].Content, w.content)
		}
	}
}

// TestParseCSVZone_MultiFQDNFieldNormalization verifies SOA gets per-field
// trailing dots on fields 0 and 1 (mname, rname) when imported via CSV.
func TestParseCSVZone_MultiFQDNFieldNormalization(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
@,SOA,"ns1.example.com hostmaster.example.com 2024010100 3600 900 1209600 3600",3600,0,false`

	rrsets, _, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(rrsets))
	}
	got := rrsets[0].Records[0].Content
	want := "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600"
	if got != want {
		t.Errorf("SOA content = %q, want %q", got, want)
	}
}

// TestParseBindZone_FQDNTargetNormalization is a normalization regression test for
// the BIND parser: a CNAME target without a trailing dot must get one, and MX
// priority must be preserved through normalization.
// TestParseBindZone_SameLineParentheses is the regression test for a SOA
// written on a single physical line: "( 2024010101 3600 900 1209600 300 )".
// The parser used to flip into paren-continuation mode on '(' and only left
// it when closes > opens, so the balanced pair left it stuck and every
// following line was merged into one giant record that got rejected. The
// depth counter now closes the logical line when the parens balance.
func TestParseBindZone_SameLineParentheses(t *testing.T) {
	data := []byte(`$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. ( 2024010101 3600 900 1209600 300 )
@ IN NS ns1.example.com.
www IN A 192.0.2.1`)

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("no line should be skipped, got %+v", skipped)
	}

	contents := map[string]string{}
	for _, rr := range rrsets {
		contents[rr.Type] = rr.Records[0].Content
	}
	if got := contents["SOA"]; got != "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 1209600 300" {
		t.Errorf("SOA content = %q, want the paren-free single-line form", got)
	}
	if _, ok := contents["NS"]; !ok {
		t.Error("NS record after a same-line paren pair must still parse")
	}
	if _, ok := contents["A"]; !ok {
		t.Error("A record after a same-line paren pair must still parse")
	}
}

// TestParseBindZone_ParensInsideQuotes is the regression test for literal
// parentheses inside a quoted TXT payload: they are data, not continuation
// markers. The parser used to count them, opening a logical line that never
// closed and swallowing the rest of the zone.
func TestParseBindZone_ParensInsideQuotes(t *testing.T) {
	data := []byte(`$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 1209600 300
txt1 IN TXT "value (parenthetical) inside"
@ IN NS ns1.example.com.`)

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("no line should be skipped, got %+v", skipped)
	}

	var txtContent string
	sawNS := false
	for _, rr := range rrsets {
		switch {
		case rr.Type == "TXT" && rr.Name == "txt1.example.com.":
			txtContent = rr.Records[0].Content
		case rr.Type == "NS":
			sawNS = true
		}
	}
	if txtContent != `"value (parenthetical) inside"` {
		t.Errorf("TXT content = %q, want the literal parens preserved inside the quotes", txtContent)
	}
	if !sawNS {
		t.Error("records following a TXT with quoted parens must still parse")
	}
}

func TestParseBindZone_FQDNTargetNormalization(t *testing.T) {
	data := []byte(`$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600
@ IN NS ns1.example.com.
www IN CNAME target.example.com
@ IN MX 10 mail.example.com`)

	rrsets, _, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]string{
		"CNAME": "target.example.com.",
		"MX":    "10 mail.example.com.",
		"NS":    "ns1.example.com.",
	}
	found := make(map[string]string)
	for _, rr := range rrsets {
		if w, ok := want[rr.Type]; ok {
			found[rr.Type] = rr.Records[0].Content
			if rr.Records[0].Content != w {
				t.Errorf("%s content = %q, want %q", rr.Type, rr.Records[0].Content, w)
			}
		}
	}
	for rtype := range want {
		if _, ok := found[rtype]; !ok {
			t.Errorf("type %s missing from parsed rrsets", rtype)
		}
	}
}

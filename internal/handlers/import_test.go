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
	if count != 4 {
		t.Errorf("expected 4 activity log entries (SOA, NS, A, MX), got %d", count)
	}

	var details string
	h.DB.QueryRow("SELECT details FROM activity_logs WHERE action='import_zone' AND details LIKE 'Imported SOA%' LIMIT 1").Scan(&details)
	if !strings.Contains(details, "Imported SOA") {
		t.Errorf("expected SOA import log, got %q", details)
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
	if count != 3 {
		t.Errorf("expected 3 activity log entries (SOA, NS, A), got %d", count)
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

	rrsets, err := parseBindZone(data, "example.com.")
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

	rrsets, err := parseBindZone(data, "example.com.")
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

	rrsets, err := parseBindZone(data, "example.com.")
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

	rrsets, err := parseBindZone(data, "example.com.")
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

	rrsets, err := parseBindZone(data, "example.com.")
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

func TestParseCSVZone_TXT_Quoting(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
txt.example.com.,TXT,v=DMARC1; p=quarantine,3600,0,false
spf.example.com.,SPF,v=spf1 -all,3600,0,false
preq.example.com.,TXT,"""already"" quoted",3600,0,false`

	rrsets, err := parseCSVZone(csv.NewReader(strings.NewReader(input)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 3 {
		t.Fatalf("expected 3 rrsets, got %d", len(rrsets))
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
	if rrsets[2].Records[0].Content != `"already" quoted` {
		t.Errorf("TXT pre-quoted content = %q, want %q", rrsets[2].Records[0].Content, `"already" quoted`)
	}
}

func TestParseCSVZone(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled
@,SOA,"ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600",3600,0,false
example.com.,NS,ns1.example.com.,3600,0,false
www.example.com.,A,192.0.2.1,3600,0,false`

	rrsets, err := parseCSVZone(csv.NewReader(strings.NewReader(input)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 3 {
		t.Fatalf("expected 3 rrsets, got %d", len(rrsets))
	}
}

func TestParseCSVZone_NoData(t *testing.T) {
	input := `name,type,content,ttl,priority,disabled`
	rrsets, err := parseCSVZone(csv.NewReader(strings.NewReader(input)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 0 {
		t.Errorf("expected 0 rrsets, got %d", len(rrsets))
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

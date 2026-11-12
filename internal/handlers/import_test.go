package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func importPDNS() testutil.PDNSHandlerFunc {
	// Serves GET /zones/ ListRecords from an empty zone so a merge-aware
	// ImportZone decodes a clean before-image, and ACKs every PATCH with 204.
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			// #nosec G104 -- test helper
			json.NewEncoder(w).Encode(struct {
				RRSets []models.RRSet `json:"rrsets"`
			}{})
			return
		}
		w.Write([]byte(`[]`))
	}
}

func TestImportZone_BIND(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		// The merge path fetches a before-image first; only the PATCH fails.
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
			return
		}
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
	t.Parallel()
	leak := "Error while executing query: SELECT password_hash FROM users WHERE id=1"
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		// The merge path fetches a before-image first; only the PATCH fails.
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
			return
		}
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
	t.Parallel()
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		// The merge path fetches a before-image first; only the PATCH fails.
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
			return
		}
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
	t.Parallel()
	h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		// The merge path fetches a before-image first; only the PATCH fails.
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
			return
		}
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

// TestImportZone_PartialImportsRejected pins the all-or-nothing import
// contract: when any input line or directive cannot be converted into a
// record, the handler must refuse the upload before PowerDNS is called. The
// REPLACE semantics make a partial import destructive for every RRSet the
// file touches.
func TestImportZone_PartialImportsRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		filename    string
		contentType string
		content     string
	}{
		{
			name:        "BIND invalid line",
			filename:    "test.zone",
			contentType: "text/plain",
			content: `$ORIGIN example.com.
$TTL 3600
www IN A 192.0.2.1
www 300`,
		},
		{
			name:        "BIND include directive",
			filename:    "test.zone",
			contentType: "text/plain",
			content: `$ORIGIN example.com.
$INCLUDE other.zone
www IN A 192.0.2.1`,
		},
		{
			name:        "CSV invalid row",
			filename:    "test.csv",
			contentType: "text/csv",
			content: `name,type,content,ttl,priority,disabled
www,A,192.0.2.1,3600,0,false
www,A,not-an-ip,3600,0,false`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patched := false
			h, srv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPatch {
					patched = true
				}
				importPDNS()(w, r)
			})
			defer srv.Close()

			testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

			body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n%s\r\n--boundary--\r\n", tc.filename, tc.contentType, tc.content)
			r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
			r.SetPathValue("zone_id", "example.com.")
			r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
			r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

			w := httptest.NewRecorder()
			h.ImportZone(w, r)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
			}
			if patched {
				t.Fatal("a partial import must not reach PowerDNS")
			}
			if !strings.Contains(w.Body.String(), "no records were imported") {
				t.Errorf("expected the no-mutation message, got: %s", w.Body.String())
			}

			var count int
			h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='import_zone'").Scan(&count)
			if count != 0 {
				t.Errorf("a rejected import must not be audited, got %d activity rows", count)
			}
		})
	}
}

// TestImportZone_ConcurrentCreateSerialized est la régression lost-update
// import↔création: un PATCH REPLACE d'import passant entre le fetch et le
// PATCH d'une création concurrente écrasait silencieusement l'enregistrement
// importé (ou le nouveau, selon l'ordre). Le mock PDNS garde un état en
// mémoire et signale l'instant où la création entre dans son fetch, afin de
// placer l'import strictement dans la fenêtre que le verrou ferme.
func TestImportZone_ConcurrentCreateSerialized(t *testing.T) {
	t.Parallel()
	var (
		mu     sync.Mutex
		rrsets = map[string][]models.RecordInfo{}
	)
	getStarted := make(chan struct{})
	var getOnce sync.Once

	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			getOnce.Do(func() { close(getStarted) })
			mu.Lock()
			out := make([]models.RRSet, 0, len(rrsets))
			for key, records := range rrsets {
				parts := strings.SplitN(key, "|", 2)
				out = append(out, models.RRSet{Name: parts[0], Type: parts[1], TTL: 3600, Records: records})
			}
			mu.Unlock()
			json.NewEncoder(w).Encode(struct {
				RRSets []models.RRSet `json:"rrsets"`
			}{RRSets: out}) // #nosec G104 -- test helper
			return
		}
		if r.Method == http.MethodPatch {
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.NewDecoder(r.Body).Decode(&payload) // #nosec G104 -- test helper
			mu.Lock()
			for _, rr := range payload.RRSets {
				rrsets[rr.Name+"|"+rr.Type] = rr.Records
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: 1, Username: "admin", Role: "admin"})

	// La création démarre et détient le verrou de zone pendant tout son
	// fetch→merge→PATCH.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		body := "name=www&type=A&content=192.0.2.20&ttl=3600"
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/zones/example.com./records/create", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("zone_id", "example.com.")
		h.CreateRecord(w, req.WithContext(ctx))
		if w.Code != http.StatusSeeOther {
			t.Errorf("create: expected 303, got %d (%s)", w.Code, w.Body.String())
		}
	}()

	// N'importer que lorsque la création est à l'intérieur de son fetch: sans
	// le verrou sur l'import, son PATCH REPLACE passerait entre le fetch et le
	// PATCH de la création et serait écrasé.
	<-getStarted

	bindContent := "$ORIGIN example.com.\n$TTL 3600\nwww IN A 192.0.2.10"
	impBody := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.zone\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n--boundary--\r\n", bindContent)
	impReq := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(impBody))
	impReq.SetPathValue("zone_id", "example.com.")
	impReq.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	impReq = withUserContext(impReq, &models.User{ID: 1, Username: "admin", Role: "admin"})
	impW := httptest.NewRecorder()
	h.ImportZone(impW, impReq)
	if impW.Code != http.StatusSeeOther {
		t.Fatalf("import: expected 303, got %d (%s)", impW.Code, impW.Body.String())
	}

	wg.Wait()

	mu.Lock()
	got := rrsets["www.example.com.|A"]
	mu.Unlock()
	// Fusion sérialisée: la création détient le verrou pendant son
	// fetch→merge→PATCH, donc le GET before-image de l'import (mode fusion
	// par défaut) observe 192.0.2.20 et y AJOUTE 192.0.2.10 au lieu de
	// l'écraser. Les deux enregistrements doivent survivre.
	contents := map[string]bool{}
	for _, rec := range got {
		contents[rec.Content] = true
	}
	if len(got) != 2 || !contents["192.0.2.20"] || !contents["192.0.2.10"] {
		t.Fatalf("serialized import merge must keep both records, got %+v", got)
	}
}

// TestImportZone_BindRelativeTargetsResolved vérifie de bout en bout que les
// cibles relatives BIND sont résolues contre $ORIGIN avant l'envoi à
// PowerDNS: "mail" devient "mail.example.com.", "target.example" devient
// "target.example.example.com.", les noms absolus passent inchangés.
func TestImportZone_BindRelativeTargetsResolved(t *testing.T) {
	t.Parallel()
	var sent []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, captureRRSets(t, &sent))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
@ IN MX 10 mail
www IN CNAME target.example
alias IN CNAME target.example.com.`

	body := fmt.Sprintf("--boundary\r\nContent-Disposition: form-data; name=\"zonefile\"; filename=\"test.zone\"\r\nContent-Type: text/plain\r\n\r\n%s\r\n--boundary--\r\n", bindContent)
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./import", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})

	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	assertImportRedirect(t, w)

	want := map[string]string{
		"MX":          "10 mail.example.com.",
		"CNAME:www":   "target.example.example.com.",
		"CNAME:alias": "target.example.com.",
	}
	got := map[string]string{}
	for _, rr := range sent {
		key := rr.Type
		if rr.Type == "CNAME" {
			key = "CNAME:" + strings.Split(rr.Name, ".")[0]
		}
		got[key] = rr.Records[0].Content
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q (all sent: %+v)", k, got[k], w, sent)
		}
	}
}

func assertImportRedirect(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestParseBindZone(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestParseBindZone_ReportsUnsupportedInclude pins the skipped-feedback
// contract for directives the importer does not implement: a $INCLUDE must be
// reported explicitly so the caller can reject the upload instead of treating
// the file as complete.
func TestParseBindZone_ReportsUnsupportedInclude(t *testing.T) {
	t.Parallel()
	data := []byte(`$ORIGIN example.com.
$INCLUDE other.zone
www IN A 192.0.2.1`)

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected the valid A RRSet, got %+v", rrsets)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected one skipped directive, got %+v", skipped)
	}
	if !strings.Contains(skipped[0].Line, "$INCLUDE") || !strings.Contains(skipped[0].Reason, "not supported") {
		t.Errorf("unexpected skipped feedback: %+v", skipped[0])
	}
}

func TestParseCSVZone_TXT_Quoting(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestParseBindZone_SRVPriorityConflictSkipped pins the no-silent-token-drop
// contract for BIND SRV lines whose data carries TWO leading priorities
// ("10 20 5 5060 target" — priority 10 then a 4-field remainder embedding
// priority 20): the line must be REJECTED and reported through the
// skipped-lines mechanism with both numbers in the reason, while every other
// line still imports. Silently re-embedding would have dropped the weight
// token "20" from the wire content.
func TestParseBindZone_SRVPriorityConflictSkipped(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"$ORIGIN example.com.",
		"$TTL 3600",
		"_sip._tcp IN SRV 10 20 5 5060 sip.example.com.",
		"www IN A 192.0.2.1",
	}, "\n")

	rrsets, skipped, err := parseBindZone([]byte(input), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 || rrsets[0].Type != "A" {
		t.Fatalf("expected only the A rrset to import, got %+v", rrsets)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected exactly 1 skipped line (the divergent SRV), got %+v", skipped)
	}
	s := skipped[0]
	if !strings.Contains(s.Line, "SRV") || !strings.Contains(s.Line, "10 20 5 5060") {
		t.Errorf("skipped line must preserve the original line text (no token dropped), got %q", s.Line)
	}
	for _, needle := range []string{"embeds priority 20", "priority field value 10"} {
		if !strings.Contains(s.Reason, needle) {
			t.Errorf("skip reason %q should contain %q", s.Reason, needle)
		}
	}
}

// TestParseCSVZone_SRVPriorityConflictSkipped is the CSV counterpart: a row
// whose SRV content already embeds a priority that disagrees with the row's
// priority column must be reported as a skipped row (with both numbers in the
// reason), not silently rewritten — and the remaining rows still import.
func TestParseCSVZone_SRVPriorityConflictSkipped(t *testing.T) {
	t.Parallel()
	input := `name,type,content,ttl,priority,disabled
_sip._tcp.example.com.,SRV,10 5 5060 sip.example.com.,3600,0,false
www.example.com.,A,192.0.2.1,3600,0,false`

	rrsets, skipped, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 || rrsets[0].Type != "A" {
		t.Fatalf("expected only the A rrset to import, got %+v", rrsets)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected exactly 1 skipped row (the divergent SRV), got %+v", skipped)
	}
	s := skipped[0]
	if !strings.Contains(s.Line, "SRV") || !strings.Contains(s.Line, "10 5 5060 sip.example.com.") {
		t.Errorf("skipped row must preserve the original row text, got %q", s.Line)
	}
	for _, needle := range []string{"embeds priority 10", "priority field value 0"} {
		if !strings.Contains(s.Reason, needle) {
			t.Errorf("skip reason %q should contain %q", s.Reason, needle)
		}
	}
}

// TestParseBindZone_SkipsOverBoundTTL pins the RFC 2181 §8 bound in the BIND
// importer: a record whose effective TTL exceeds 2147483647 must be reported
// as a skipped line (with the maximum in the reason) while the remaining
// lines still import. The over-bound TTL is carried explicitly on the record
// line: parseBindTTLValue already rejects an over-bound $TTL directive, so
// the record-level gate is exercised via the per-line TTL field.
func TestParseBindZone_SkipsOverBoundTTL(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"$ORIGIN example.com.",
		"$TTL 3600",
		"www 2147483648 IN A 192.0.2.1",
		"mail IN A 192.0.2.5",
	}, "\n")

	rrsets, skipped, err := parseBindZone([]byte(input), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 || rrsets[0].Type != "A" {
		t.Fatalf("expected only the valid A rrset to import, got %+v", rrsets)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected exactly 1 skipped line (the over-bound TTL), got %+v", skipped)
	}
	if !strings.Contains(skipped[0].Reason, "2147483647") {
		t.Errorf("skip reason should mention the RFC 2181 maximum 2147483647, got %q", skipped[0].Reason)
	}
}

// TestParseCSVZone_SkipsOverBoundTTL is the CSV counterpart: a row with a TTL
// cell above 2147483647 is skipped with a reason naming the maximum; the
// valid row still imports.
func TestParseCSVZone_SkipsOverBoundTTL(t *testing.T) {
	t.Parallel()
	input := `name,type,content,ttl,priority,disabled
www.example.com.,A,192.0.2.1,2147483648,0,false
mail.example.com.,A,192.0.2.5,3600,0,false`

	rrsets, skipped, err := parseCSVZone(csv.NewReader(strings.NewReader(input)), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rrsets) != 1 || rrsets[0].Type != "A" {
		t.Fatalf("expected only the valid A rrset to import, got %+v", rrsets)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected exactly 1 skipped row (the over-bound TTL), got %+v", skipped)
	}
	if !strings.Contains(skipped[0].Reason, "2147483647") {
		t.Errorf("skip reason should mention the RFC 2181 maximum 2147483647, got %q", skipped[0].Reason)
	}
}

// TestCSVFormulaNeutralizationRoundTrip pins the spreadsheet-formula
// defence across the full export→import cycle: dangerous prefixes in record
// content and comments are escaped by the shared renderer (web, REST and
// MCP) and restored byte-identically by the importer, including multiline
// comment cells and literal leading apostrophes.
func TestCSVFormulaNeutralizationRoundTrip(t *testing.T) {
	t.Parallel()
	zone := &models.Zone{ID: "example.com.", Name: "example.com."}
	records := []models.RRSet{
		{
			Name: "txt.example.com.", Type: "TXT", TTL: 3600,
			Records: []models.RecordInfo{{Content: `"=cmd|'/c calc'!A1"`, Disabled: false}},
			Comments: &models.CommentPatch{Items: []models.Comment{
				{Content: "=2+5"},
				{Content: "second line\n=3+4"},
				{Content: "'literal apostrophe"},
			}},
		},
	}

	csvText := dnsops.RenderZoneCSV(zone, records)
	// The rendered cell must carry the escape prefix.
	if !strings.Contains(csvText, "'=cmd|") {
		t.Fatalf("exported content cell must be neutralized, got:\n%s", csvText)
	}

	rrsets, skipped, err := parseCSVZone(csv.NewReader(strings.NewReader(csvText)), "example.com.")
	if err != nil {
		t.Fatalf("parseCSVZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no row should be skipped, got %+v", skipped)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %+v", rrsets)
	}
	// Content comes back byte-identical (wire form).
	if got := rrsets[0].Records[0].Content; got != `"=cmd|'/c calc'!A1"` {
		t.Errorf("content round trip: got %q", got)
	}
	// Comments: each line restored, dangerous second line included.
	want := []string{"=2+5", "second line", "=3+4", "'literal apostrophe"}
	if rrsets[0].Comments == nil || len(rrsets[0].Comments.Items) != len(want) {
		t.Fatalf("comments: want %d items, got %+v", len(want), rrsets[0].Comments)
	}
	for i, c := range rrsets[0].Comments.Items {
		if c.Content != want[i] {
			t.Errorf("comment[%d] = %q, want %q", i, c.Content, want[i])
		}
	}
}

func TestDetectFormat(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	if len(skipped) != 1 {
		t.Fatalf("expected the empty-name NS row to be skipped, got %+v", skipped)
	}

	// All four rows collapse into the same apex/www RRSets under the
	// canonical names; the malformed empty-name NS row is reported as skipped.
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
	t.Parallel()
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
	t.Parallel()
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
// priority must be preserved through normalization. Relative targets resolve
// against $ORIGIN per RFC 1035 §5.1: "target.example.com" under
// $ORIGIN example.com. means target.example.com.example.com., a bare
// "mail" means mail.example.com., and absolute names pass through unchanged.
func TestParseBindZone_FQDNTargetNormalization(t *testing.T) {
	t.Parallel()
	data := []byte(`$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600
@ IN NS ns1.example.com.
www IN CNAME target.example
alias IN CNAME target.example.com.
@ IN MX 10 mail
@ IN MX 20 mail.example.com.`)

	rrsets, _, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]string{
		"CNAME": "target.example.example.com.",
		"NS":    "ns1.example.com.",
		"MX":    "10 mail.example.com.",
	}
	found := make(map[string]string)
	for _, rr := range rrsets {
		if rr.Type == "CNAME" && rr.Name == "alias.example.com." {
			found["CNAME-ABS"] = rr.Records[0].Content
			continue
		}
		if rr.Type == "MX" {
			if rr.Records[0].Content != "10 mail.example.com." {
				t.Errorf("MX content[0] = %q, want %q", rr.Records[0].Content, "10 mail.example.com.")
			}
			found["MX"] = rr.Records[0].Content
			for _, rec := range rr.Records {
				if rec.Content == "20 mail.example.com." {
					found["MX-ABS"] = rec.Content
				}
			}
			continue
		}
		if w, ok := want[rr.Type]; ok {
			if rr.Records[0].Content != w {
				t.Errorf("%s content = %q, want %q", rr.Type, rr.Records[0].Content, w)
			}
			found[rr.Type] = rr.Records[0].Content
		}
	}
	for rtype := range want {
		if _, ok := found[rtype]; !ok {
			t.Errorf("type %s missing from parsed rrsets", rtype)
		}
	}
	if found["CNAME-ABS"] != "target.example.com." {
		t.Errorf("absolute CNAME target must pass through unchanged, got %q", found["CNAME-ABS"])
	}
	if found["MX-ABS"] != "20 mail.example.com." {
		t.Errorf("absolute MX target must pass through unchanged, got %q", found["MX-ABS"])
	}
}

// TestParseBindZone_RDataOriginResolution covers the RFC 1035 §5.1
// resolution for the multi-name and structured RDATA types: SOA mname/rname,
// RP and MINFO mailbox fields resolve against $ORIGIN, SRV and NAPTR resolve
// their trailing target field while keeping priority/weight/port and the
// quoted flags/service/regexp tokens intact.
func TestParseBindZone_RDataOriginResolution(t *testing.T) {
	t.Parallel()
	data := []byte(`$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2024010100 3600 900 1209600 3600
@ IN RP hostmaster txtref
@ IN MINFO root hostmaster
_sip._tcp IN SRV 10 20 5060 sip
@ IN NAPTR 100 50 "s" "SIP+D2U" "" sip
@ IN NAPTR 200 60 "" "" "" .`)

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no line should be skipped, got %+v", skipped)
	}

	want := map[string]string{
		"SOA":   "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600",
		"RP":    "hostmaster.example.com. txtref.example.com.",
		"MINFO": "root.example.com. hostmaster.example.com.",
		"SRV":   "10 20 5060 sip.example.com.",
		"NAPTR": "100 50 \"s\" \"SIP+D2U\" \"\" sip.example.com.",
	}
	naptrRoot := "200 60 \"\" \"\" \"\" ."
	found := make(map[string]string)
	for _, rr := range rrsets {
		if rr.Type == "NAPTR" && len(rr.Records) == 2 {
			found["NAPTR-ROOT"] = rr.Records[1].Content
		}
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
	if found["NAPTR-ROOT"] != naptrRoot {
		t.Errorf("NAPTR root replacement must stay the root label, got %q", found["NAPTR-ROOT"])
	}
}

// TestParseBindZone_SameLineParentheses is the regression test for a SOA
// written on a single physical line: "( 2024010101 3600 900 1209600 300 )".
// The parser used to flip into paren-continuation mode on '(' and only left
// it when closes > opens, so the balanced pair left it stuck and every
// following line was merged into one giant record that got rejected. The
// depth counter now closes the logical line when the parens balance.
func TestParseBindZone_SameLineParentheses(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// TestParseBindZone_TXTEscapedQuotes pins the backslash-escape contract for
// quoted character-strings: a `\"` inside a TXT value keeps both bytes as
// data, does NOT toggle the quote state, and the whole string stays one
// token: `say \"hi\" now` must arrive verbatim (quotes and backslashes) in
// the RRSet record content.
func TestParseBindZone_TXTEscapedQuotes(t *testing.T) {
	t.Parallel()
	data := []byte("$ORIGIN example.com.\n$TTL 3600\ntxt IN TXT \"say \\\"hi\\\" now\"")

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no line should be skipped, got %+v", skipped)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %+v", rrsets)
	}
	rr := rrsets[0]
	if rr.Name != "txt.example.com." || rr.Type != "TXT" {
		t.Fatalf("unexpected rrset name/type: %+v", rr)
	}
	if got := rr.Records[0].Content; got != `"say \"hi\" now"` {
		t.Errorf("TXT content = %q, want %q", got, `"say \"hi\" now"`)
	}
}

// TestParseBindZone_TXTEscapedQuoteBeforeComment pins the escape-aware comment
// scan: the `;` after an escaped quote is INSIDE the character-string and must
// be kept as data, while the real `; comment` after the closing quote is
// still stripped.
func TestParseBindZone_TXTEscapedQuoteBeforeComment(t *testing.T) {
	t.Parallel()
	data := []byte("$ORIGIN example.com.\ntxt IN TXT \"a\\\";b\" ; trailing comment")

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no line should be skipped, got %+v", skipped)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %+v", rrsets)
	}
	if got := rrsets[0].Records[0].Content; got != `"a\";b"` {
		t.Errorf("TXT content = %q, want %q", got, `"a\";b"`)
	}
}

// TestParseBindZone_TXTEscapedQuoteBeforeParen pins the escape-aware
// parenthesis scan: a `(` following an escaped quote is inside the
// character-string and must NOT open a paren continuation — the following
// plain record must still parse as its own RRSet instead of being merged
// into the TXT line.
func TestParseBindZone_TXTEscapedQuoteBeforeParen(t *testing.T) {
	t.Parallel()
	data := []byte("$ORIGIN example.com.\ntxt IN TXT \"a\\\" (paren\"\nwww IN A 1.2.3.4")

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no line should be skipped, got %+v", skipped)
	}

	contents := map[string]string{}
	for _, rr := range rrsets {
		contents[rr.Type] = rr.Records[0].Content
	}
	if got := contents["TXT"]; got != `"a\" (paren"` {
		t.Errorf("TXT content = %q, want %q", got, `"a\" (paren"`)
	}
	if got := contents["A"]; got != "1.2.3.4" {
		t.Errorf("A content = %q, want %q (record must not be merged into the TXT line)", got, "1.2.3.4")
	}
}

// TestParseBindZone_TXTEscapedBackslashBeforeQuote pins the escape-consumes-
// next-byte rule: in `a\\` the second backslash is escaped, so the following
// quote really CLOSES the string (the content is the four bytes a + \ + \).
func TestParseBindZone_TXTEscapedBackslashBeforeQuote(t *testing.T) {
	t.Parallel()
	data := []byte("$ORIGIN example.com.\ntxt IN TXT \"a\\\\\"")

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no line should be skipped, got %+v", skipped)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %+v", rrsets)
	}
	if got := rrsets[0].Records[0].Content; got != `"a\\"` {
		t.Errorf("TXT content = %q, want %q", got, `"a\\"`)
	}
}

// TestParseBindZone_TTLTabDirective pins first-token directive recognition: a
// TAB separator (`$TTL\t7200`) must set the default TTL exactly like the
// space form. The value is chosen to differ from the hardcoded 3600 default
// so a silently-unrecognized directive cannot pass.
func TestParseBindZone_TTLTabDirective(t *testing.T) {
	t.Parallel()
	data := []byte("$TTL\t7200\nwww IN A 1.2.3.4")

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no line should be skipped, got %+v", skipped)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %+v", rrsets)
	}
	if got := rrsets[0].TTL; got != 7200 {
		t.Errorf("record TTL = %d, want 7200 (default set by $TTL directive)", got)
	}
}

// TestParseBindZone_OriginTabDirective pins first-token recognition for
// $ORIGIN with a TAB separator: relative names after `$ORIGIN\tsub...` must
// resolve against the new origin.
func TestParseBindZone_OriginTabDirective(t *testing.T) {
	t.Parallel()
	data := []byte("$ORIGIN\tsub.example.com.\nwww A 1.2.3.4")

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no line should be skipped, got %+v", skipped)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %+v", rrsets)
	}
	if got := rrsets[0].Name; got != "www.sub.example.com." {
		t.Errorf("record name = %q, want %q", got, "www.sub.example.com.")
	}
}

// TestParseBindZone_TTLTimeUnits pins the BIND time-unit format for $TTL:
// decimal digits with an optional single case-insensitive unit suffix
// (s/m/h/d/w) converted to seconds. Bare digits keep their meaning.
func TestParseBindZone_TTLTimeUnits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		directive string
		wantTTL   int
	}{
		{"bare_seconds", "$TTL 45", 45},
		{"seconds_suffix", "$TTL 30s", 30},
		{"minutes", "$TTL 90m", 5400},
		{"hours", "$TTL 1h", 3600},
		{"hours_distinguishing", "$TTL 2h", 7200},
		{"weeks", "$TTL 1w", 604800},
		{"days_uppercase", "$TTL 2D", 172800},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.directive + "\nwww IN A 1.2.3.4")

			rrsets, skipped, err := parseBindZone(data, "example.com.")
			if err != nil {
				t.Fatalf("parseBindZone: %v", err)
			}
			if len(skipped) != 0 {
				t.Fatalf("no line should be skipped, got %+v", skipped)
			}
			if len(rrsets) != 1 {
				t.Fatalf("expected 1 rrset, got %+v", rrsets)
			}
			if got := rrsets[0].TTL; got != tc.wantTTL {
				t.Errorf("record TTL = %d, want %d (%s)", got, tc.wantTTL, tc.directive)
			}
		})
	}
}

// TestParseBindZone_TTLInvalidValues pins the no-silent-ignore contract for
// $TTL: zero, negative, unparsable and overflowing values are reported as a
// skipped line naming the directive, not dropped. A valid record next to a
// bad directive still imports.
func TestParseBindZone_TTLInvalidValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		directive string
	}{
		{"zero", "$TTL 0"},
		{"negative", "$TTL -5"},
		{"unparsable", "$TTL 1x"},
		{"overflow", "$TTL 99999999999999"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.directive + "\nwww IN A 1.2.3.4")

			rrsets, skipped, err := parseBindZone(data, "example.com.")
			if err != nil {
				t.Fatalf("parseBindZone: %v", err)
			}
			if len(rrsets) != 1 || rrsets[0].Type != "A" {
				t.Fatalf("the valid A record must still import, got %+v", rrsets)
			}
			if len(skipped) != 1 {
				t.Fatalf("expected exactly 1 skipped line for %q, got %+v", tc.directive, skipped)
			}
			if !strings.Contains(skipped[0].Line, "$TTL") {
				t.Errorf("skipped line must carry the directive text, got %q", skipped[0].Line)
			}
			if !strings.Contains(skipped[0].Reason, "$TTL") {
				t.Errorf("skip reason %q should name the $TTL directive", skipped[0].Reason)
			}
		})
	}
}

// TestParseBindZone_DirectiveMissingArg pins the missing-argument contract:
// a bare `$ORIGIN` or `$TTL` directive is reported as a skipped line naming
// the directive (not a panic, not a silent ignore, not a generic parse
// error).
func TestParseBindZone_DirectiveMissingArg(t *testing.T) {
	t.Parallel()
	for _, directive := range []string{"$ORIGIN", "$TTL"} {
		t.Run(strings.TrimPrefix(directive, "$"), func(t *testing.T) {
			data := []byte(directive + "\nwww IN A 1.2.3.4")

			rrsets, skipped, err := parseBindZone(data, "example.com.")
			if err != nil {
				t.Fatalf("parseBindZone: %v", err)
			}
			if len(rrsets) != 1 || rrsets[0].Type != "A" {
				t.Fatalf("the valid A record must still import, got %+v", rrsets)
			}
			if len(skipped) != 1 {
				t.Fatalf("expected exactly 1 skipped line for bare %q, got %+v", directive, skipped)
			}
			if !strings.Contains(skipped[0].Line, directive) {
				t.Errorf("skipped line must carry the directive text, got %q", skipped[0].Line)
			}
			if !strings.Contains(skipped[0].Reason, directive) {
				t.Errorf("skip reason %q should name the %s directive", skipped[0].Reason, directive)
			}
		})
	}
}

// TestParseBindZone_DirectiveSpaceSeparators is the regression pin for the
// historical space-separated directive form (plain `$TTL 7200` and
// `$ORIGIN sub.example.com.` must keep working) and for the skipped-lines
// mechanism staying intact when a file mixes valid records with one bad
// line.
func TestParseBindZone_DirectiveSpaceSeparators(t *testing.T) {
	t.Parallel()
	data := []byte("$ORIGIN sub.example.com.\n$TTL 7200\nwww IN A 1.2.3.4\nbrokenline")

	rrsets, skipped, err := parseBindZone(data, "example.com.")
	if err != nil {
		t.Fatalf("parseBindZone: %v", err)
	}
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %+v", rrsets)
	}
	if rrsets[0].Name != "www.sub.example.com." {
		t.Errorf("record name = %q, want %q", rrsets[0].Name, "www.sub.example.com.")
	}
	if rrsets[0].TTL != 7200 {
		t.Errorf("record TTL = %d, want 7200", rrsets[0].TTL)
	}
	if len(skipped) != 1 || skipped[0].Line != "brokenline" {
		t.Errorf("expected only 'brokenline' to be skipped, got %+v", skipped)
	}
}

// --- Merge/replace mode tests (web zone import) -----------------------------
//
// ImportZone gains a `mode` form field: `merge` (default) merges imported
// RRSets into the existing zone state under the zone lock, `replace` keeps
// the historical REPLACE semantics. Both modes audit a before-image. The
// mocks below serve the pre-import zone state via GET ListRecords (PowerDNS
// read form) and capture the PATCH body.

// importCaptureMock serves GET ListRecords from existing (read form) and
// captures the PATCH body into patched. Unlike the shared captureRRSets
// helper it lets each test pin the pre-import zone state.
func importCaptureMock(t *testing.T, existing []models.RRSet, patched *[]models.RRSet) testutil.PDNSHandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			// #nosec G104 -- test helper
			json.NewEncoder(w).Encode(struct {
				RRSets []models.RRSet `json:"rrsets"`
			}{RRSets: existing})
			return
		}
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/") {
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode PATCH body: %v", err)
			}
			*patched = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte(`[]`)) // #nosec G104 -- test helper
	}
}

// importBody builds the multipart upload body; the mode field is omitted when
// mode is empty so the default-mode path is exercised.
func importBody(filename, contentType, fileContent, mode string) string {
	var b strings.Builder
	b.WriteString("--boundary\r\n")
	fmt.Fprintf(&b, "Content-Disposition: form-data; name=\"zonefile\"; filename=\"%s\"\r\n", filename)
	fmt.Fprintf(&b, "Content-Type: %s\r\n\r\n", contentType)
	b.WriteString(fileContent)
	b.WriteString("\r\n")
	if mode != "" {
		b.WriteString("--boundary\r\n")
		b.WriteString("Content-Disposition: form-data; name=\"mode\"\r\n\r\n")
		b.WriteString(mode)
		b.WriteString("\r\n")
	}
	b.WriteString("--boundary--\r\n")
	return b.String()
}

func postImport(t *testing.T, h *Handler, zoneID, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/zones/"+zoneID+"/import", strings.NewReader(body))
	r.SetPathValue("zone_id", zoneID)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r = withUserContext(r, &models.User{ID: 1, Username: "test", Role: "admin"})
	w := httptest.NewRecorder()
	h.ImportZone(w, r)
	return w
}

// findPatchedRRSet locates a PATCHed RRSet by canonical (case-folded) key —
// the same dnsops.RRSetKey matching the handler must use for the merge.
func findPatchedRRSet(rrsets []models.RRSet, name, rtype string) *models.RRSet {
	for i := range rrsets {
		if dnsops.RRSetKey(rrsets[i].Name, rrsets[i].Type) == dnsops.RRSetKey(name, rtype) {
			return &rrsets[i]
		}
	}
	return nil
}

// assertRecordContents asserts the RRSet carries exactly the wanted wire-form
// record contents (order-insensitive).
func assertRecordContents(t *testing.T, rr *models.RRSet, want []string) {
	t.Helper()
	got := make([]string, 0, len(rr.Records))
	for _, rec := range rr.Records {
		got = append(got, rec.Content)
	}
	if len(got) != len(want) {
		t.Fatalf("%s/%s records = %v, want exactly %v", rr.Name, rr.Type, got, want)
	}
	seen := make(map[string]bool, len(got))
	for _, c := range got {
		seen[c] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("%s/%s missing record %q (got %v)", rr.Name, rr.Type, w, got)
		}
	}
}

func rrsetHasComment(rr *models.RRSet, want string) bool {
	if rr.Comments == nil {
		return false
	}
	for _, c := range rr.Comments.Items {
		if c.Content == want {
			return true
		}
	}
	return false
}

// importAuditRow reads the most recent import_zone audit row.
func importAuditRow(t *testing.T, h *Handler) (details, oldValue string) {
	t.Helper()
	if err := h.DB.QueryRow(`SELECT details, old_value FROM activity_logs WHERE action = 'import_zone' ORDER BY id DESC LIMIT 1`).Scan(&details, &oldValue); err != nil {
		t.Fatalf("read import_zone audit row: %v", err)
	}
	return details, oldValue
}

// TestImportZone_MergeDefaultKeepsSibling pins the default merge mode: with
// no `mode` field, an imported RRSet is merged into the existing one — the
// pre-existing sibling record AND its comments survive — and the audit row
// carries a before-image plus the mode name.
func TestImportZone_MergeDefaultKeepsSibling(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "www.example.com.", Type: "A", TTL: 300,
			Records:  []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
			Comments: &models.CommentPatch{Items: []models.Comment{{Content: "ops", Account: ""}}},
		},
		{
			Name: "example.com.", Type: "SOA", TTL: 3600,
			Records: []models.RecordInfo{{Content: "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024020200 3600 900 1209600 3600
www IN A 5.6.7.8`

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, ""))
	assertImportRedirect(t, w)

	www := findPatchedRRSet(patched, "www.example.com.", "A")
	if www == nil {
		t.Fatalf("PATCH carries no www/A RRSet: %+v", patched)
	}
	assertRecordContents(t, www, []string{"1.2.3.4", "5.6.7.8"})
	if !rrsetHasComment(www, "ops") {
		t.Errorf("merged www/A must preserve the existing 'ops' comment, got %+v", www.Comments)
	}

	details, oldValue := importAuditRow(t, h)
	if oldValue == "" {
		t.Error("import_zone audit row must carry a before-image old_value")
	}
	if !strings.Contains(oldValue, "1.2.3.4") {
		t.Errorf("old_value must snapshot the pre-import www/A record, got %q", oldValue)
	}
	if !strings.Contains(details, "merge") {
		t.Errorf("details must name the merge mode, got %q", details)
	}
}

// TestImportZone_ReplaceModeExplicitAndAudited pins the explicit replace
// mode: the imported RRSet fully replaces the existing one (sibling record
// dropped) and the audit row still snapshots the replaced before-image.
func TestImportZone_ReplaceModeExplicitAndAudited(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "www.example.com.", Type: "A", TTL: 300,
			Records: []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
www IN A 5.6.7.8`

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, "replace"))
	assertImportRedirect(t, w)

	www := findPatchedRRSet(patched, "www.example.com.", "A")
	if www == nil {
		t.Fatalf("PATCH carries no www/A RRSet: %+v", patched)
	}
	assertRecordContents(t, www, []string{"5.6.7.8"})

	details, oldValue := importAuditRow(t, h)
	if !strings.Contains(oldValue, "1.2.3.4") {
		t.Errorf("old_value must snapshot the replaced www/A record, got %q", oldValue)
	}
	if !strings.Contains(details, "replace") {
		t.Errorf("details must name the replace mode, got %q", details)
	}
}

// TestImportZone_SOASingletonMerge pins the SOA overlay contract of merge
// mode: the imported SOA fully replaces the existing SOA RRSet (exactly one
// SOA record survives, with the imported serial and TTL), while a nil
// comments patch on the imported SOA preserves the existing SOA comments;
// NS records merge additively and ordinary RRSets keep their existing
// records.
func TestImportZone_SOASingletonMerge(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "example.com.", Type: "SOA", TTL: 3000,
			Records:  []models.RecordInfo{{Content: "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600", Disabled: false}},
			Comments: &models.CommentPatch{Items: []models.Comment{{Content: "existing soa comment", Account: ""}}},
		},
		{
			Name: "example.com.", Type: "NS", TTL: 3600,
			Records: []models.RecordInfo{{Content: "ns1.example.com.", Disabled: false}},
		},
		{
			Name: "www.example.com.", Type: "A", TTL: 3600,
			Records: []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024020200 3600 900 1209600 3600
@ IN NS ns2.example.com.
www IN A 5.6.7.8`

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, ""))
	assertImportRedirect(t, w)

	soa := findPatchedRRSet(patched, "example.com.", "SOA")
	if soa == nil || len(soa.Records) != 1 {
		t.Fatalf("merge must leave exactly one SOA record, got %+v", soa)
	}
	if !strings.Contains(soa.Records[0].Content, "2024020200") || strings.Contains(soa.Records[0].Content, "2024010100") {
		t.Errorf("imported SOA must fully replace the existing one, got %q", soa.Records[0].Content)
	}
	if soa.TTL != 3600 {
		t.Errorf("imported SOA must set the RRSet TTL, got %d", soa.TTL)
	}
	if !rrsetHasComment(soa, "existing soa comment") {
		t.Errorf("imported SOA with nil comments must preserve the existing SOA comments, got %+v", soa.Comments)
	}

	ns := findPatchedRRSet(patched, "example.com.", "NS")
	if ns == nil {
		t.Fatal("PATCH carries no apex NS RRSet")
	}
	assertRecordContents(t, ns, []string{"ns1.example.com.", "ns2.example.com."})

	www := findPatchedRRSet(patched, "www.example.com.", "A")
	if www == nil {
		t.Fatal("PATCH carries no www/A RRSet")
	}
	assertRecordContents(t, www, []string{"1.2.3.4", "5.6.7.8"})
}

// TestImportZone_SOACommentOverlay pins the non-nil comment case of the SOA
// overlay: an imported SOA carrying comments replaces the whole RRSet
// including its comments — the previous SOA comment must not survive.
func TestImportZone_SOACommentOverlay(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "example.com.", Type: "SOA", TTL: 3000,
			Records:  []models.RecordInfo{{Content: "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600", Disabled: false}},
			Comments: &models.CommentPatch{Items: []models.Comment{{Content: "existing soa comment", Account: ""}}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content,ttl,priority,disabled,comment\n" +
		`@,SOA,"ns1.example.com. hostmaster.example.com. 2024020200 3600 900 1209600 3600",3600,0,false,soa import comment`

	w := postImport(t, h, "example.com.", importBody("test.csv", "text/csv", csvContent, ""))
	assertImportRedirect(t, w)

	soa := findPatchedRRSet(patched, "example.com.", "SOA")
	if soa == nil || len(soa.Records) != 1 {
		t.Fatalf("merge must leave exactly one SOA record, got %+v", soa)
	}
	if !strings.Contains(soa.Records[0].Content, "2024020200") {
		t.Errorf("imported SOA must replace the existing one, got %q", soa.Records[0].Content)
	}
	if soa.TTL != 3600 {
		t.Errorf("imported SOA must set the RRSet TTL, got %d", soa.TTL)
	}
	if !rrsetHasComment(soa, "soa import comment") || rrsetHasComment(soa, "existing soa comment") {
		t.Errorf("imported SOA comments must replace the existing ones when non-empty, got %+v", soa.Comments)
	}
}

// TestImportZone_MergeMultiRecordAndDuplicates pins the dedup contract of
// merge mode: an imported record whose content exactly matches an existing
// sibling keeps the EXISTING occurrence (first-occurrence wins), so merging
// [5.6.7.8, 9.9.9.9, 1.2.3.4] into an existing [1.2.3.4] yields exactly the
// three distinct records.
func TestImportZone_MergeMultiRecordAndDuplicates(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "www.example.com.", Type: "A", TTL: 3600,
			Records: []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
www IN A 5.6.7.8
www IN A 9.9.9.9
www IN A 1.2.3.4`

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, ""))
	assertImportRedirect(t, w)

	www := findPatchedRRSet(patched, "www.example.com.", "A")
	if www == nil {
		t.Fatal("PATCH carries no www/A RRSet")
	}
	assertRecordContents(t, www, []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"})
}

// TestImportZone_BindMXSRVMergeWithSiblings pins priority-type merging: the
// existing zone state arrives in PowerDNS read form (priority separate from
// content); merge mode must re-embed both the existing and the imported
// priorities into the wire content sent to the PATCH.
func TestImportZone_BindMXSRVMergeWithSiblings(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			// PowerDNS wire form, as ListRecords receives it: the priority is
			// embedded in the content and the client detaches it on read.
			Name: "example.com.", Type: "MX", TTL: 3600,
			Records: []models.RecordInfo{{Content: "10 mail1.example.com.", Disabled: false}},
		},
		{
			Name: "_sip._tcp.example.com.", Type: "SRV", TTL: 3600,
			Records: []models.RecordInfo{{Content: "10 5 5060 sip1.example.com.", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
@ IN MX 20 mail2.example.com.
_sip._tcp IN SRV 10 5 5061 sip2.example.com.`

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, ""))
	assertImportRedirect(t, w)

	mx := findPatchedRRSet(patched, "example.com.", "MX")
	if mx == nil {
		t.Fatal("PATCH carries no apex MX RRSet")
	}
	assertRecordContents(t, mx, []string{"10 mail1.example.com.", "20 mail2.example.com."})
	for _, rec := range mx.Records {
		if rec.Priority != 0 {
			t.Errorf("PATCH write form must embed priority in the content, got priority %d on %q", rec.Priority, rec.Content)
		}
	}

	srvRR := findPatchedRRSet(patched, "_sip._tcp.example.com.", "SRV")
	if srvRR == nil {
		t.Fatal("PATCH carries no _sip._tcp SRV RRSet")
	}
	assertRecordContents(t, srvRR, []string{"10 5 5060 sip1.example.com.", "10 5 5061 sip2.example.com."})
}

// TestImportZone_CSVMXPriorityMerge pins CSV priority handling in merge
// mode: the priority column of an MX row merges into an existing MX RRSet
// read from PowerDNS (bare content + separate priority), and the PATCH
// carries both priorities re-embedded in the wire content.
func TestImportZone_CSVMXPriorityMerge(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			// PowerDNS wire form: the priority is embedded in the content.
			Name: "example.com.", Type: "MX", TTL: 3600,
			Records: []models.RecordInfo{{Content: "10 mail1.example.com.", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content,ttl,priority,disabled\n" +
		"@,MX,mail2.example.com.,300,20,false"

	w := postImport(t, h, "example.com.", importBody("test.csv", "text/csv", csvContent, ""))
	assertImportRedirect(t, w)

	mx := findPatchedRRSet(patched, "example.com.", "MX")
	if mx == nil {
		t.Fatal("PATCH carries no apex MX RRSet")
	}
	assertRecordContents(t, mx, []string{"10 mail1.example.com.", "20 mail2.example.com."})
	for _, rec := range mx.Records {
		if rec.Priority != 0 {
			t.Errorf("PATCH write form must embed priority in the content, got priority %d on %q", rec.Priority, rec.Content)
		}
	}
}

// TestImportZone_CSVCommentOnNewRRSetOnly pins the comment contract of merge
// mode: a brand-new RRSet imported from CSV carries its CSV comment, while an
// existing RRSet keeps ONLY its pre-existing comments — the imported CSV
// comment cell is ignored for RRSets that already exist.
func TestImportZone_CSVCommentOnNewRRSetOnly(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "www.example.com.", Type: "A", TTL: 300,
			Records:  []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
			Comments: &models.CommentPatch{Items: []models.Comment{{Content: "existing", Account: ""}}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	csvContent := "name,type,content,ttl,priority,disabled,comment\n" +
		"www,A,5.6.7.8,300,0,false,imported comment\n" +
		"brandnew,A,9.9.9.9,300,0,false,new comment"

	w := postImport(t, h, "example.com.", importBody("test.csv", "text/csv", csvContent, ""))
	assertImportRedirect(t, w)

	brandnew := findPatchedRRSet(patched, "brandnew.example.com.", "A")
	if brandnew == nil {
		t.Fatalf("PATCH carries no brandnew/A RRSet: %+v", patched)
	}
	if !rrsetHasComment(brandnew, "new comment") {
		t.Errorf("new RRSet must carry its imported CSV comment, got %+v", brandnew.Comments)
	}

	www := findPatchedRRSet(patched, "www.example.com.", "A")
	if www == nil {
		t.Fatal("PATCH carries no www/A RRSet")
	}
	assertRecordContents(t, www, []string{"1.2.3.4", "5.6.7.8"})
	if www.Comments == nil || len(www.Comments.Items) != 1 || www.Comments.Items[0].Content != "existing" {
		t.Errorf("existing RRSet must keep only its pre-existing comments, got %+v", www.Comments)
	}
}

// TestImportZone_NewDisabledRecordInExistingRRSet pins the disabled-flag
// contract of merge mode: a NEW record imported with disabled=true keeps its
// disabled flag inside an existing RRSet (the existing sibling stays
// enabled), and an exact duplicate with the OPPOSITE disabled flag keeps the
// EXISTING occurrence — dedup first-occurrence wins.
func TestImportZone_NewDisabledRecordInExistingRRSet(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "www.example.com.", Type: "A", TTL: 300,
			Records: []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
		},
	}

	t.Run("new disabled record merges in", func(t *testing.T) {
		var patched []models.RRSet
		h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
		defer srv.Close()

		testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

		csvContent := "name,type,content,ttl,priority,disabled\n" +
			"www,A,5.6.7.8,300,0,true"

		w := postImport(t, h, "example.com.", importBody("test.csv", "text/csv", csvContent, ""))
		assertImportRedirect(t, w)

		www := findPatchedRRSet(patched, "www.example.com.", "A")
		if www == nil {
			t.Fatal("PATCH carries no www/A RRSet")
		}
		if len(www.Records) != 2 {
			t.Fatalf("www/A must carry both records, got %+v", www.Records)
		}
		byContent := map[string]models.RecordInfo{}
		for _, rec := range www.Records {
			byContent[rec.Content] = rec
		}
		if rec, ok := byContent["5.6.7.8"]; !ok || !rec.Disabled {
			t.Errorf("new imported record must keep its disabled=true flag, got %+v", www.Records)
		}
		if rec, ok := byContent["1.2.3.4"]; !ok || rec.Disabled {
			t.Errorf("existing record must stay enabled, got %+v", www.Records)
		}
	})

	t.Run("duplicate with opposite disabled keeps existing occurrence", func(t *testing.T) {
		var patched []models.RRSet
		h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
		defer srv.Close()

		testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

		csvContent := "name,type,content,ttl,priority,disabled\n" +
			"www,A,1.2.3.4,300,0,true"

		w := postImport(t, h, "example.com.", importBody("test.csv", "text/csv", csvContent, ""))
		assertImportRedirect(t, w)

		www := findPatchedRRSet(patched, "www.example.com.", "A")
		if www == nil {
			t.Fatal("PATCH carries no www/A RRSet")
		}
		if len(www.Records) != 1 {
			t.Fatalf("exact duplicate must not grow the RRSet, got %+v", www.Records)
		}
		if www.Records[0].Disabled {
			t.Errorf("first-occurrence dedup must keep the existing enabled record, got %+v", www.Records[0])
		}
	})
}

// TestImportZone_GETFailureAbortsImport pins the abort contract: both modes
// fetch the before-image under the zone lock before PATCHing, so a ListRecords
// failure must render an error, send no PATCH and write no audit row.
func TestImportZone_GETFailureAbortsImport(t *testing.T) {
	t.Parallel()
	newMock := func(patched *bool) testutil.PDNSHandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/") {
				*patched = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Write([]byte(`[]`)) // #nosec G104 -- test helper
		}
	}

	bindContent := `$ORIGIN example.com.
$TTL 3600
www IN A 5.6.7.8`

	run := func(t *testing.T, mode string) {
		patched := false
		h, srv := newTestHandlerWithPDNS(t, newMock(&patched))
		defer srv.Close()

		testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

		w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, mode))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("a ListRecords failure must abort the import with a 500 render, got %d body=%s", w.Code, w.Body.String())
		}
		if patched {
			t.Error("no PATCH must reach PowerDNS when the before-image fetch fails")
		}

		var count int
		h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='import_zone'").Scan(&count)
		if count != 0 {
			t.Errorf("a failed import must not be audited, got %d activity rows", count)
		}
	}

	t.Run("merge default", func(t *testing.T) { run(t, "") })
	t.Run("replace", func(t *testing.T) { run(t, "replace") })
}

// TestImportZone_MixedCaseOwnerMergeAndAudit pins canonical key matching: the
// pre-import zone state may carry a differently-cased owner name (PowerDNS
// preserves case); the merge must match it against the imported canonical
// name via dnsops.RRSetKey and still capture the before-image for the audit
// row.
func TestImportZone_MixedCaseOwnerMergeAndAudit(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "WWW.Example.COM.", Type: "A", TTL: 300,
			Records: []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
www.example.com. IN A 5.6.7.8`

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, ""))
	assertImportRedirect(t, w)

	www := findPatchedRRSet(patched, "www.example.com.", "A")
	if www == nil {
		t.Fatalf("PATCH carries no www/A RRSet under the canonical key: %+v", patched)
	}
	assertRecordContents(t, www, []string{"1.2.3.4", "5.6.7.8"})

	_, oldValue := importAuditRow(t, h)
	if oldValue == "" || !strings.Contains(oldValue, "1.2.3.4") {
		t.Errorf("before-image must be captured through canonical key matching, got %q", oldValue)
	}
}

// TestImportZone_InvalidModeFallsBackToMerge pins the fallback: an unknown
// mode value behaves exactly like the default merge mode (sibling records
// survive).
func TestImportZone_InvalidModeFallsBackToMerge(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{
		{
			Name: "www.example.com.", Type: "A", TTL: 300,
			Records: []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}},
		},
	}
	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := `$ORIGIN example.com.
$TTL 3600
www IN A 5.6.7.8`

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, "bogus"))
	assertImportRedirect(t, w)

	www := findPatchedRRSet(patched, "www.example.com.", "A")
	if www == nil {
		t.Fatal("PATCH carries no www/A RRSet")
	}
	assertRecordContents(t, www, []string{"1.2.3.4", "5.6.7.8"})
}

// TestImportZone_BeforeImageBoundedAndExcludesUnaffected pins the audit
// before-image contract: only RRSets whose key matches an imported key are
// snapshotted (an untouched RRSet must not leak into old_value), the
// snapshot is a single-encoded JSON array capped at 100 entries, and the
// details name the omitted count when the affected set exceeds the cap.
func TestImportZone_BeforeImageBoundedAndExcludesUnaffected(t *testing.T) {
	t.Parallel()
	// 150 affected RRSets: every name is referenced by the import file, so
	// all 150 qualify for the before-image — 50 over the 100-entry cap. The
	// details must report the full affected count, not stop at the cutoff.
	existing := make([]models.RRSet, 0, 151)
	var bindLines []string
	for i := 0; i < 150; i++ {
		name := fmt.Sprintf("r%d.example.com.", i)
		existing = append(existing, models.RRSet{
			Name:    name,
			Type:    "A",
			TTL:     300,
			Records: []models.RecordInfo{{Content: fmt.Sprintf("10.0.0.%d", i), Disabled: false}},
		})
		bindLines = append(bindLines, fmt.Sprintf("%s IN A 10.1.0.%d", name, i))
	}
	existing = append(existing, models.RRSet{
		Name:    "untouched.example.com.",
		Type:    "A",
		TTL:     300,
		Records: []models.RecordInfo{{Content: "192.0.2.99", Disabled: false}},
	})

	var patched []models.RRSet
	h, srv := newTestHandlerWithPDNS(t, importCaptureMock(t, existing, &patched))
	defer srv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	bindContent := "$ORIGIN example.com.\n$TTL 3600\n" + strings.Join(bindLines, "\n")

	w := postImport(t, h, "example.com.", importBody("test.zone", "text/plain", bindContent, ""))
	assertImportRedirect(t, w)

	details, oldValue := importAuditRow(t, h)
	if oldValue == "" {
		t.Fatal("import_zone audit row must carry a before-image old_value")
	}

	// Single-encoded JSON array of objects (a double-encoded string fails here).
	var snapshot []map[string]interface{}
	if err := json.Unmarshal([]byte(oldValue), &snapshot); err != nil {
		t.Fatalf("old_value must decode as a JSON array of RRSet snapshots: %v", err)
	}
	if len(snapshot) != 100 {
		t.Errorf("before-image must be capped at 100 RRSets, got %d", len(snapshot))
	}
	if !strings.Contains(oldValue, "10.0.0.0") {
		t.Error("before-image must snapshot affected RRSets")
	}
	if strings.Contains(oldValue, "untouched") || strings.Contains(oldValue, "192.0.2.99") {
		t.Error("unaffected RRSets must not appear in the before-image")
	}
	if !strings.Contains(details, "before-image") || !strings.Contains(details, "of 150") {
		t.Errorf("details must note the omitted 150 affected record sets, got %q", details)
	}
}

// --- importBeforeImage helper unit tests ------------------------------------

// beforeImageRRSet builds an A RRSet whose serialized snapshot has length
// snapLen (achieved by padding the record content; plain 'x' bytes marshal
// verbatim inside the JSON string, so snapshot size grows exactly with pad).
func beforeImageRRSet(name string, snapLen int) models.RRSet {
	rr := models.RRSet{
		Name:    name,
		Type:    "A",
		TTL:     300,
		Records: []models.RecordInfo{{Content: "10.0.0.1", Disabled: false}},
	}
	pad := snapLen - len(rrsetSnapshot(&rr))
	if pad < 0 {
		panic("beforeImageRRSet: base snapshot larger than requested size")
	}
	rr.Records[0].Content += strings.Repeat("x", pad)
	if got := len(rrsetSnapshot(&rr)); got != snapLen {
		panic(fmt.Sprintf("beforeImageRRSet: snapshot len = %d, want %d", got, snapLen))
	}
	return rr
}

func assertBeforeImageJSON(t *testing.T, oldValue string, wantLen int) []map[string]interface{} {
	t.Helper()
	var snapshot []map[string]interface{}
	if err := json.Unmarshal([]byte(oldValue), &snapshot); err != nil {
		t.Fatalf("before-image must decode as a JSON array of RRSet snapshots: %v", err)
	}
	if len(snapshot) != wantLen {
		t.Errorf("before-image has %d entries, want %d", len(snapshot), wantLen)
	}
	return snapshot
}

// TestImportBeforeImage_ByteBudgetJustUnder pins the byte budget: a single
// affected RRSet whose snapshot lands ~50 bytes under the budget is fully
// included.
func TestImportBeforeImage_ByteBudgetJustUnder(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{beforeImageRRSet("a.example.com.", importBeforeImageMaxBytes-50)}
	imported := []models.RRSet{{Name: "a.example.com.", Type: "A"}}

	oldValue, affected, shown := importBeforeImage(existing, imported)
	if affected != 1 || shown != 1 {
		t.Fatalf("affected/shown = %d/%d, want 1/1", affected, shown)
	}
	assertBeforeImageJSON(t, oldValue, 1)
}

// TestImportBeforeImage_ByteBudgetJustOver pins the byte budget stop: a
// single affected RRSet whose snapshot lands ~50 bytes over the budget fits
// nothing — oldValue is "" but affected is still reported.
func TestImportBeforeImage_ByteBudgetJustOver(t *testing.T) {
	t.Parallel()
	existing := []models.RRSet{beforeImageRRSet("a.example.com.", importBeforeImageMaxBytes+50)}
	imported := []models.RRSet{{Name: "a.example.com.", Type: "A"}}

	oldValue, affected, shown := importBeforeImage(existing, imported)
	if affected != 1 || shown != 0 {
		t.Fatalf("affected/shown = %d/%d, want 1/0", affected, shown)
	}
	if oldValue != "" {
		t.Errorf("nothing fits the budget: oldValue must be empty, got %d bytes", len(oldValue))
	}
}

// TestImportBeforeImage_ByteBudgetPartialInclusion pins the framing math
// (2 + sum(len) + (n-1)): with three equal snapshots sized so two fit exactly
// under the budget but the third would exceed it, the snapshot holds the
// first two and stays valid JSON.
func TestImportBeforeImage_ByteBudgetPartialInclusion(t *testing.T) {
	t.Parallel()
	perSnap := (importBeforeImageMaxBytes - 3) / 2 // two fit: 2 + 2*perSnap + 1 <= budget
	existing := []models.RRSet{
		beforeImageRRSet("r1.example.com.", perSnap),
		beforeImageRRSet("r2.example.com.", perSnap),
		beforeImageRRSet("r3.example.com.", perSnap),
	}
	imported := []models.RRSet{
		{Name: "r1.example.com.", Type: "A"},
		{Name: "r2.example.com.", Type: "A"},
		{Name: "r3.example.com.", Type: "A"},
	}
	if 2+3*perSnap+2 <= importBeforeImageMaxBytes {
		t.Fatalf("test construction: three snapshots of %d bytes would fit, want them to exceed %d", perSnap, importBeforeImageMaxBytes)
	}

	oldValue, affected, shown := importBeforeImage(existing, imported)
	if affected != 3 || shown != 2 {
		t.Fatalf("affected/shown = %d/%d, want 3/2", affected, shown)
	}
	snapshot := assertBeforeImageJSON(t, oldValue, 2)
	if len(snapshot) > 0 && snapshot[0]["name"] != "r1.example.com." {
		t.Errorf("first included snapshot must be the first affected RRSet, got %v", snapshot[0]["name"])
	}
}

// TestImportBeforeImage_CountCap pins the entry cap: 101 tiny affected RRSets
// yield exactly 100 included snapshots and the correct affected/shown counts.
func TestImportBeforeImage_CountCap(t *testing.T) {
	t.Parallel()
	existing := make([]models.RRSet, 0, 101)
	imported := make([]models.RRSet, 0, 101)
	for i := 0; i <= 100; i++ {
		name := fmt.Sprintf("r%03d.example.com.", i)
		existing = append(existing, models.RRSet{
			Name:    name,
			Type:    "A",
			TTL:     300,
			Records: []models.RecordInfo{{Content: fmt.Sprintf("10.0.0.%d", i), Disabled: false}},
		})
		imported = append(imported, models.RRSet{Name: name, Type: "A"})
	}

	oldValue, affected, shown := importBeforeImage(existing, imported)
	if affected != 101 || shown != 100 {
		t.Fatalf("affected/shown = %d/%d, want 101/100", affected, shown)
	}
	assertBeforeImageJSON(t, oldValue, 100)
}

// (Key-matching coverage lives at handler level: mixed-case canonical keys in
// TestImportZone_MixedCaseOwnerMergeAndAudit, unaffected-exclusion in
// TestImportZone_BeforeImageBoundedAndExcludesUnaffected.)

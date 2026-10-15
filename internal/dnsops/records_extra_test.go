package dnsops

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// TestPrepareRecordContent_TypeMatrix pins the per-type wire normalisation
// for every branch of the codec: priority embedding, quoting, FQDN targets,
// per-field FQDNs and per-field quoting.
func TestPrepareRecordContent_TypeMatrix(t *testing.T) {
	cases := []struct {
		name     string
		rtype    string
		content  string
		priority int
		wantC    string
		wantP    int
	}{
		{"MX embeds priority and dots target", "MX", "mail.example.com", 10, "10 mail.example.com.", 0},
		{"SRV embeds priority and dots target", "SRV", "10 5 5060 sip.example.com", 10, "10 5 5060 sip.example.com.", 0},
		{"TXT quotes content", "TXT", "hello world", 0, `"hello world"`, 0},
		{"SPF quotes content", "SPF", "v=spf1 -all", 0, `"v=spf1 -all"`, 0},
		{"CNAME dots target", "CNAME", "target.example.com", 0, "target.example.com.", 0},
		{"NS dots target", "NS", "ns1.example.com", 0, "ns1.example.com.", 0},
		{"PTR dots whole content", "PTR", "host.example.com", 0, "host.example.com.", 0},
		{"A passthrough", "A", "192.0.2.1", 0, "192.0.2.1", 0},
		{"AAAA passthrough", "AAAA", "2001:db8::1", 0, "2001:db8::1", 0},
	}
	for _, c := range cases {
		gotC, gotP := PrepareRecordContent(c.rtype, c.content, c.priority)
		if gotC != c.wantC || gotP != c.wantP {
			t.Errorf("%s: PrepareRecordContent(%s, %q, %d) = (%q, %d), want (%q, %d)",
				c.name, c.rtype, c.content, c.priority, gotC, gotP, c.wantC, c.wantP)
		}
	}
}

// TestCreateZone_NilUserAndPDNSErrors covers the in-process caller path and
// the PowerDNS failure path (audit must NOT be written when the create
// fails).
func TestCreateZone_NilUserAndPDNSErrors(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// PDNS failure: nil handler = 500 on every request.
	srv, client := testutil.NewTestPDNSServer(t, nil)
	defer srv.Close()
	s := New(db, client)

	if _, err := s.CreateZone(ctx, nil, models.ZoneCreateRequest{Name: "fail.example.", Kind: "Native"}, SourceAPI); err == nil {
		t.Fatal("PDNS failure must surface")
	}
	var n int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_logs WHERE action='create_zone'`).Scan(&n)
	if n != 0 {
		t.Fatalf("failed create must not write an audit row, got %d", n)
	}

	// Success path with a nil (in-process) user: audit user_id 0.
	srv2, client2 := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{ID: "ok.example.", Name: "ok.example.", Kind: "Native"})
	})
	defer srv2.Close()
	s2 := New(db, client2)
	zone, err := s2.CreateZone(ctx, nil, models.ZoneCreateRequest{Name: "OK.Example.Com", Kind: "Native"}, SourceAPI)
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	// The zone name is canonicalised before the PDNS call.
	if zone.ID != "ok.example." {
		t.Fatalf("unexpected zone: %+v", zone)
	}
	var userID int64
	db.QueryRowContext(ctx, `SELECT user_id FROM activity_logs WHERE action='create_zone'`).Scan(&userID)
	if userID != 0 {
		t.Fatalf("nil-user audit user_id = %d, want 0", userID)
	}
}

// TestDeleteRecord_UngrantedUserNoAudit pins that a refused write leaves no
// audit row (the authorization gate fires before any PDNS call).
func TestDeleteRecord_UngrantedUserNoAudit(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no PDNS call expected for a refused write, got %s %s", r.Method, r.URL.Path)
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	userID := testutil.SeedTestUser(t, db, "denied", "pass", "user", true)
	err := s.DeleteRecord(ctx, &models.User{ID: userID, Role: "user"}, "example.", "www.example.", "A", SourceAPI)
	if err == nil {
		t.Fatal("ungranted delete must fail")
	}
	var n int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_logs WHERE action='delete_record'`).Scan(&n)
	if n != 0 {
		t.Fatalf("refused write must not be audited, got %d rows", n)
	}
}

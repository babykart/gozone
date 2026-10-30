package dnsops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func TestListZones_FiltersByGrant(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "a.example.", Name: "a.example.", Kind: "Native"},
			{ID: "b.example.", Name: "b.example.", Kind: "Native"},
		})
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	// Admin: everything.
	admin := &models.User{ID: 1, Role: "admin"}
	zones, err := s.ListZones(ctx, admin)
	if err != nil || len(zones) != 2 {
		t.Fatalf("admin ListZones: (%v, %v)", zones, err)
	}

	// Granted user: only the granted zone.
	userID := testutil.SeedTestUser(t, db, "lister", "pass", "user", true)
	seedGroupGrant(t, db, userID, "a.example.")
	zones, err = s.ListZones(ctx, &models.User{ID: userID, Role: "user"})
	if err != nil || len(zones) != 1 || zones[0].ID != "a.example." {
		t.Fatalf("granted ListZones: (%v, %v)", zones, err)
	}
}

func TestFilterZonesWithInfoForUser(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	zones := []models.ZoneWithInfo{
		{Zone: models.Zone{ID: "a.example."}},
		{Zone: models.Zone{ID: "b.example."}},
	}

	// Nil user fails closed.
	got, err := FilterZonesWithInfoForUser(ctx, db, nil, zones)
	if err != nil || len(got) != 0 {
		t.Fatalf("nil user: (%v, %v)", got, err)
	}

	// Admin sees everything.
	got, err = FilterZonesWithInfoForUser(ctx, db, &models.User{ID: 1, Role: "admin"}, zones)
	if err != nil || len(got) != 2 {
		t.Fatalf("admin: (%v, %v)", got, err)
	}

	// Granted user sees the granted zone only.
	userID := testutil.SeedTestUser(t, db, "infouser", "pass", "user", true)
	seedGroupGrant(t, db, userID, "b.example.")
	got, err = FilterZonesWithInfoForUser(ctx, db, &models.User{ID: userID, Role: "user"}, zones)
	if err != nil || len(got) != 1 || got[0].Zone.ID != "b.example." {
		t.Fatalf("granted: (%v, %v)", got, err)
	}
}

func TestValidateZoneCreate(t *testing.T) {
	// Defaults: empty kind becomes Native.
	req, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "example.com."})
	if err != nil || req.Kind != "Native" {
		t.Fatalf("default kind: (%q, %v)", req.Kind, err)
	}
	// Invalid domain.
	if _, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "not a domain"}); err == nil {
		t.Fatal("invalid domain must be rejected")
	}
	// Invalid kind.
	if _, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "example.com.", Kind: "Fabricated"}); err == nil {
		t.Fatal("invalid kind must be rejected")
	}
}

// TestValidateZoneCreate_Masters covers the Slave/masters contract: a Slave
// zone needs at least one master, and every master must be a valid IPv4 or
// IPv6 address (hostnames are not accepted — PowerDNS transfers from IPs).
func TestValidateZoneCreate_Masters(t *testing.T) {
	// Slave or Consumer without masters is rejected.
	if _, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "example.com.", Kind: "Slave"}); err == nil {
		t.Fatal("Slave without masters must be rejected")
	}
	if _, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "example.com.", Kind: "Consumer"}); err == nil {
		t.Fatal("Consumer without masters must be rejected")
	}
	// Slave with valid IPv4 masters passes.
	if _, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "example.com.", Kind: "Slave", Masters: []string{"192.0.2.53"}}); err != nil {
		t.Fatalf("Slave with an IPv4 master: %v", err)
	}
	// Slave with valid IPv6 masters passes.
	if _, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "example.com.", Kind: "Slave", Masters: []string{"2001:db8::53"}}); err != nil {
		t.Fatalf("Slave with an IPv6 master: %v", err)
	}
	// A hostname is not a valid master address.
	if _, err := ValidateZoneCreate(models.ZoneCreateRequest{Name: "example.com.", Kind: "Slave", Masters: []string{"ns1.example.com."}}); err == nil {
		t.Fatal("a hostname as master must be rejected")
	}
}

func TestListRecords_NameFilterAndAuthz(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/search-data") || r.URL.RawQuery != "" {
			w.Write([]byte(`{"rrsets":[{"name":"www.example.","type":"A","ttl":300,"records":[{"content":"192.0.2.1"}]}]}`)) // #nosec G104 -- test helper
			return
		}
		w.Write([]byte(`{"rrsets":[{"name":"www.example.","type":"A","ttl":300,"records":[{"content":"192.0.2.1"}]},{"name":"mail.example.","type":"A","ttl":300,"records":[{"content":"192.0.2.2"}]}]}`)) // #nosec G104 -- test helper
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()
	admin := &models.User{ID: 1, Role: "admin"}

	// Whole zone.
	all, err := s.ListRecords(ctx, admin, "example.com.", "", "")
	if err != nil || len(all) != 2 {
		t.Fatalf("whole zone: (%v, %v)", all, err)
	}

	// Name (+type) filter.
	one, err := s.ListRecords(ctx, admin, "example.com.", "www.example.", "A")
	if err != nil || len(one) != 1 || one[0].Name != "www.example." {
		t.Fatalf("filtered: (%v, %v)", one, err)
	}

	// Zone authorization applies to reads too.
	userID := testutil.SeedTestUser(t, db, "reader", "pass", "user", true)
	if _, err := s.ListRecords(ctx, &models.User{ID: userID, Role: "user"}, "example.com.", "", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted read: %v, want ErrForbidden", err)
	}
}

func TestUpdateRecord_TTLInheritAndAudit(t *testing.T) {
	var sent []models.RRSet
	existing := []models.RRSet{
		{Name: "www.example.", Type: "A", TTL: 1800, Records: []models.RecordInfo{{Content: "192.0.2.10"}}},
	}
	srv, client := testutil.NewTestPDNSServer(t, captureRRSets(t, &sent, existing))
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()
	adminID := testutil.SeedTestUser(t, db, "admin", "pass", "admin", true)
	admin := &models.User{ID: adminID, Role: "admin"}

	rrset := models.RRSet{Name: "www", Type: "A", TTL: 0, Records: []models.RecordInfo{{Content: "192.0.2.99"}}}
	if err := PrepareValidatedRecordSet(&rrset, "example."); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := s.UpdateRecord(ctx, admin, "example.", rrset, SourceMCP); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	if len(sent) != 1 {
		t.Fatalf("expected one PATCH, got %d", len(sent))
	}
	if sent[0].TTL != 1800 {
		t.Errorf("TTL = %d, want 1800 (inherited from the replaced RRSet)", sent[0].TTL)
	}
	if len(sent[0].Records) != 1 || sent[0].Records[0].Content != "192.0.2.99" {
		t.Errorf("unexpected patch records: %+v", sent[0].Records)
	}

	// Audit row with the MCP transport label.
	var details string
	if err := db.QueryRowContext(ctx,
		`SELECT details FROM activity_logs WHERE action='update_record' AND zone_id='example.'`).Scan(&details); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if details != "Updated A record www.example. via MCP" {
		t.Fatalf("unexpected audit details: %q", details)
	}
}

func TestDeleteRecord_AuditBeforeImage(t *testing.T) {
	var deleted []models.RRSet
	existing := []models.RRSet{
		{Name: "gone.example.", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "192.0.2.1"}}},
	}
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(struct {
				RRSets []models.RRSet `json:"rrsets"`
			}{RRSets: existing})
			return
		}
		deleted = append(deleted, existing...)
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()
	adminID := testutil.SeedTestUser(t, db, "admin", "pass", "admin", true)

	if err := s.DeleteRecord(ctx, &models.User{ID: adminID, Role: "admin"}, "example.", "gone.example.", "A", SourceAPI); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	var oldValue string
	if err := db.QueryRowContext(ctx,
		`SELECT old_value FROM activity_logs WHERE action='delete_record' AND zone_id='example.'`).Scan(&oldValue); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !strings.Contains(oldValue, "192.0.2.1") {
		t.Errorf("audit before-image must contain the deleted content, got %q", oldValue)
	}
}

func TestStats_SuccessAndAuthzFilter(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	userID := testutil.SeedTestUser(t, db, "statuser", "pass", "user", true)
	stats, count, err := s.Stats(ctx, &models.User{ID: userID, Role: "user"})
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats == nil || count != 0 {
		t.Fatalf("stats=%v count=%d, want empty-but-non-nil stats and 0 zones", stats, count)
	}
}

func TestStats_StatisticsStageError(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)

	_, _, err := s.Stats(context.Background(), &models.User{ID: 1, Role: "admin"})
	var se *StageError
	if !errors.As(err, &se) || se.Stage != StageStatistics {
		t.Fatalf("statistics failure: %v, want StageError(StageStatistics)", err)
	}
}

func TestZoneAdminGate_NilUserInProcess(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	// A nil user designates an in-process caller (tests, background jobs)
	// and preserves the historical handler behaviour: no transport-level
	// gate is invented inside the service. Authenticated transports always
	// supply a user.
	if err := s.DeleteZone(ctx, nil, "inprocess.example.", SourceAPI); err != nil {
		t.Fatalf("nil-user DeleteZone: %v", err)
	}
}

func TestNormalizeRecordName(t *testing.T) {
	cases := []struct{ name, zone, want string }{
		{"@", "example.com.", "example.com."},
		{"", "example.com.", "example.com."},
		{"www", "example.com.", "www.example.com."},
		{"www.example.com", "example.com.", "www.example.com."},
		{"WWW.EXAMPLE.COM.", "example.com.", "www.example.com."},
		{"example.com", "example.com.", "example.com."},
		{"www.other.org.", "example.com.", "www.other.org."},
		{"www", "example.com", "www.example.com."},
	}
	for _, c := range cases {
		if got := NormalizeRecordName(c.name, c.zone); got != c.want {
			t.Errorf("NormalizeRecordName(%q, %q) = %q, want %q", c.name, c.zone, got, c.want)
		}
	}
}

func TestValidateRecordSet_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		rrset  models.RRSet
		errMsg string
	}{
		{"unknown type", models.RRSet{Name: "www.example.", Type: "BOGUS"}, "record type"},
		{"negative ttl", models.RRSet{Name: "www.example.", Type: "A", TTL: -1}, "ttl"},
		{"empty records", models.RRSet{Name: "www.example.", Type: "A", TTL: 3600}, "at least one record"},
		{"invalid name", models.RRSet{Name: "not a name", Type: "A", Records: []models.RecordInfo{{Content: "1.2.3.4"}}}, "invalid characters"},
		{"invalid content", models.RRSet{Name: "www.example.", Type: "A", Records: []models.RecordInfo{{Content: "not-an-ip"}}}, "IPv4"},
	}
	for _, c := range cases {
		rr := c.rrset
		err := ValidateRecordSet(&rr, "example.")
		if err == nil || !strings.Contains(err.Error(), c.errMsg) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.errMsg)
		}
	}
}

func TestPrepareValidatedRecordSet_MXPriority(t *testing.T) {
	rrset := models.RRSet{
		Name: "mail", Type: "mx", TTL: 3600,
		Records: []models.RecordInfo{{Content: "mail.example.com.", Priority: 10}},
	}
	if err := PrepareValidatedRecordSet(&rrset, "example.com."); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if rrset.Type != "MX" {
		t.Errorf("type = %q, want MX", rrset.Type)
	}
	if rrset.Name != "mail.example.com." {
		t.Errorf("name = %q, want mail.example.com.", rrset.Name)
	}
	if rrset.Records[0].Content != "10 mail.example.com." {
		t.Errorf("content = %q, want embedded priority", rrset.Records[0].Content)
	}
	if rrset.Records[0].Priority != 0 {
		t.Errorf("priority = %d, want 0 after embedding", rrset.Records[0].Priority)
	}
}

func TestPurgeZoneGroupGrants_Canonicalizes(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	userID := testutil.SeedTestUser(t, db, "purgee", "pass", "user", true)
	seedGroupGrant(t, db, userID, "purge.example.")

	// Non-canonical id (no trailing dot) must still purge the canonical row.
	PurgeZoneGroupGrants(ctx, db, "purge.example")
	var n int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zone_group_zones WHERE zone_id='purge.example.'`).Scan(&n)
	if n != 0 {
		t.Fatalf("grant rows survived: %d", n)
	}
}

func TestCreateRecord_NilUserInProcess(t *testing.T) {
	var sent []models.RRSet
	srv, client := testutil.NewTestPDNSServer(t, captureRRSets(t, &sent, nil))
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)

	rrset := models.RRSet{Name: "www.example.", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "192.0.2.1"}}}
	if err := s.CreateRecord(context.Background(), nil, "example.", rrset, SourceAPI); err != nil {
		t.Fatalf("nil-user CreateRecord: %v", err)
	}
	if len(sent) != 1 || len(sent[0].Records) != 1 {
		t.Fatalf("unexpected patch: %+v", sent)
	}
	// The audit row carries user_id 0 (in-process caller).
	var userID int64
	db.QueryRowContext(context.Background(),
		`SELECT user_id FROM activity_logs WHERE action='create_record'`).Scan(&userID)
	if userID != 0 {
		t.Fatalf("audit user_id = %d, want 0", userID)
	}
}

func TestLogActivity_NullZoneID(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	userID := testutil.SeedTestUser(t, db, "audituser", "pass", "user", true)
	if err := LogActivity(ctx, db, ActivityEntry{UserID: userID, Action: "login", Details: "User x logged in"}); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	var zoneID sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT zone_id FROM activity_logs WHERE action='login'`).Scan(&zoneID); err != nil {
		t.Fatalf("select: %v", err)
	}
	if zoneID.Valid {
		t.Fatalf("zone_id must be NULL for a non-zone activity, got %v", zoneID)
	}
}

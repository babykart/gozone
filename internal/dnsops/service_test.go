package dnsops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
	"github.com/babykart/gozone/internal/testutil"
)

// seedGroupGrant inserts a zone_group grant row so the seeded user holds
// access to zoneID. IDs are retrieved portably (ExecReturnID) so the helper
// works across the dbmatrix dialects (lib/pq has no LastInsertId).
func seedGroupGrant(t *testing.T, db *database.DB, userID int64, zoneID string) {
	t.Helper()
	ctx := context.Background()
	groupID, err := db.ExecReturnID(ctx, `INSERT INTO zone_groups (name) VALUES ('g1')`)
	if err != nil {
		t.Fatalf("seed zone_groups: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)`, groupID, userID); err != nil {
		t.Fatalf("seed zone_group_members: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)`, groupID, zoneID); err != nil {
		t.Fatalf("seed zone_group_zones: %v", err)
	}
}

func TestSourceLabel(t *testing.T) {
	cases := map[Source]string{
		SourceAPI:  "API",
		SourceMCP:  "MCP",
		SourceWeb:  "Web",
		Source(""): "",
	}
	for src, want := range cases {
		if got := src.Label(); got != want {
			t.Errorf("Source(%q).Label() = %q, want %q", string(src), got, want)
		}
	}
}

func TestStageErrorUnwrap(t *testing.T) {
	inner := pdns.ErrNotFound
	err := &StageError{Stage: StageFetch, Err: inner}
	if !errors.Is(err, pdns.ErrNotFound) {
		t.Error("StageError must unwrap to the underlying cause for errors.Is")
	}
	if !strings.HasPrefix(err.Error(), "fetch: ") {
		t.Errorf("unexpected Error() text: %q", err.Error())
	}
}

func TestCanAccessZone(t *testing.T) {
	db := testutil.NewTestDB(t)
	userID := testutil.SeedTestUser(t, db, "zoneuser", "pass", "user", true)
	user := &models.User{ID: userID, Username: "zoneuser", Role: "user"}
	ctx := context.Background()

	// No grant → denied, no error.
	if ok, err := CanAccessZone(ctx, db, user, "example.com."); ok || err != nil {
		t.Fatalf("no grant: got (%v, %v), want (false, nil)", ok, err)
	}

	// Grant → allowed.
	seedGroupGrant(t, db, userID, "example.com.")
	if ok, err := CanAccessZone(ctx, db, user, "example.com."); !ok || err != nil {
		t.Fatalf("with grant: got (%v, %v), want (true, nil)", ok, err)
	}

	// Nil user → denied (fail-closed; transports authenticate first).
	if ok, err := CanAccessZone(ctx, db, nil, "example.com."); ok || err != nil {
		t.Fatalf("nil user: got (%v, %v), want (false, nil)", ok, err)
	}

	// Database fault → distinguishable error (fail-closed, not a denial).
	if _, err := db.ExecContext(ctx, "DROP TABLE zone_group_zones"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, err := CanAccessZone(ctx, db, user, "example.com."); err == nil {
		t.Fatal("DB fault must surface as an error, not a clean denial")
	}
}

func TestFilterZonesForUser(t *testing.T) {
	db := testutil.NewTestDB(t)
	userID := testutil.SeedTestUser(t, db, "filteruser", "pass", "user", true)
	user := &models.User{ID: userID, Username: "filteruser", Role: "user"}
	admin := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.Background()
	zones := []models.Zone{
		{ID: "a.example.", Name: "a.example.", Kind: "Native"},
		{ID: "b.example.", Name: "b.example.", Kind: "Native"},
	}

	// Nil user fails closed to an empty list, not an error and not a leak.
	got, err := FilterZonesForUser(ctx, db, nil, zones)
	if err != nil || len(got) != 0 {
		t.Fatalf("nil user: got (%v, %v), want (empty, nil)", got, err)
	}

	// Admin sees everything.
	got, err = FilterZonesForUser(ctx, db, admin, zones)
	if err != nil || len(got) != 2 {
		t.Fatalf("admin: got (%v, %v), want (all zones, nil)", got, err)
	}

	// Granted user sees only the granted zone.
	seedGroupGrant(t, db, userID, "a.example.")
	got, err = FilterZonesForUser(ctx, db, user, zones)
	if err != nil || len(got) != 1 || got[0].ID != "a.example." {
		t.Fatalf("granted user: got (%v, %v), want ([a.example.], nil)", got, err)
	}

	// A failed lookup is a StageError(StageZoneAccess), never an empty list.
	if _, err := db.ExecContext(ctx, "DROP TABLE zone_group_zones"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	_, err = FilterZonesForUser(ctx, db, user, zones)
	if err == nil {
		t.Fatal("DB fault must be an error, not an empty result")
	}
	var se *StageError
	if !errors.As(err, &se) || se.Stage != StageZoneAccess {
		t.Fatalf("want StageError(StageZoneAccess), got %v", err)
	}
}

func TestCreateZone_AdminGateAndAudit(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{ID: "new.example.", Name: "new.example.", Kind: "Native"})
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	adminID := testutil.SeedTestUser(t, db, "admin", "pass", "admin", true)
	admin := &models.User{ID: adminID, Username: "admin", Role: "admin"}

	zone, err := s.CreateZone(ctx, admin, models.ZoneCreateRequest{Name: "new.example.", Kind: "Native"}, SourceAPI)
	if err != nil {
		t.Fatalf("CreateZone as admin: %v", err)
	}
	if zone.ID != "new.example." {
		t.Fatalf("unexpected zone: %+v", zone)
	}

	// The audit row must carry the "via API" label and the key owner's id.
	var details string
	var userID int64
	if err := db.QueryRowContext(ctx,
		`SELECT details, user_id FROM activity_logs WHERE action='create_zone' AND zone_id='new.example.'`).Scan(&details, &userID); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if details != "Created zone new.example. (kind: Native) via API" {
		t.Fatalf("unexpected audit details: %q", details)
	}
	if userID != adminID {
		t.Fatalf("audit user_id = %d, want %d", userID, adminID)
	}

	// A non-admin is refused by the service gate (defence-in-depth under the
	// REST RequireAdmin middleware; the only gate for a future MCP caller).
	userID2 := testutil.SeedTestUser(t, db, "plain", "pass", "user", true)
	if _, err := s.CreateZone(ctx, &models.User{ID: userID2, Username: "plain", Role: "user"},
		models.ZoneCreateRequest{Name: "other.example.", Kind: "Native"}, SourceMCP); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin CreateZone: got %v, want ErrForbidden", err)
	}
}

func TestDeleteZone_PurgesGrantsAndAudits(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	adminID := testutil.SeedTestUser(t, db, "admin", "pass", "admin", true)
	seedGroupGrant(t, db, adminID, "gone.example.")

	if err := s.DeleteZone(ctx, &models.User{ID: adminID, Username: "admin", Role: "admin"}, "gone.example", SourceAPI); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	// The grant rows are purged immediately (canonicalised zone id), and the
	// audit row carries the "via API" label.
	var grants int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zone_group_zones WHERE zone_id='gone.example.'`).Scan(&grants)
	if grants != 0 {
		t.Fatalf("lingering grant rows: %d", grants)
	}
	var details string
	if err := db.QueryRowContext(ctx,
		`SELECT details FROM activity_logs WHERE action='delete_zone' AND zone_id='gone.example'`).Scan(&details); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if details != "Deleted zone gone.example via API" {
		t.Fatalf("unexpected audit details: %q", details)
	}
}

func TestGetZone_ZoneAuthorization(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{ID: "guarded.example.", Name: "guarded.example.", Kind: "Native"})
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	userID := testutil.SeedTestUser(t, db, "member", "pass", "user", true)
	user := &models.User{ID: userID, Username: "member", Role: "user"}

	// Without a grant the service refuses before any PowerDNS call.
	if _, err := s.GetZone(ctx, user, "guarded.example."); !errors.Is(err, ErrForbidden) {
		t.Fatalf("no grant: got %v, want ErrForbidden", err)
	}

	// With a grant the zone loads.
	seedGroupGrant(t, db, userID, "guarded.example.")
	zone, err := s.GetZone(ctx, user, "guarded.example.")
	if err != nil {
		t.Fatalf("with grant: %v", err)
	}
	if zone.ID != "guarded.example." {
		t.Fatalf("unexpected zone: %+v", zone)
	}
}

// captureRRSets mirrors the handlers test helper: the mock PDNS records the
// PATCH bodies so tests can assert exactly what PowerDNS received.
func captureRRSets(t *testing.T, sent *[]models.RRSet, existing []models.RRSet) testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			// ListRecords decodes the {"rrsets":[…]} envelope.
			json.NewEncoder(w).Encode(struct {
				RRSets []models.RRSet `json:"rrsets"`
			}{RRSets: existing})
		case http.MethodPatch, http.MethodPut:
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode PATCH body: %v", err)
			}
			*sent = append(*sent, payload.RRSets...)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func TestCreateRecord_MergesNormalizesDedups(t *testing.T) {
	var sent []models.RRSet
	existing := []models.RRSet{
		{Name: "www.example.com.", Type: "A", TTL: 7200, Records: []models.RecordInfo{{Content: "192.0.2.10"}}},
	}
	srv, client := testutil.NewTestPDNSServer(t, captureRRSets(t, &sent, existing))
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	adminID := testutil.SeedTestUser(t, db, "admin", "pass", "admin", true)
	admin := &models.User{ID: adminID, Username: "admin", Role: "admin"}

	rrset := models.RRSet{
		Name: "www", Type: "A", TTL: 0,
		Records: []models.RecordInfo{{Content: "192.0.2.20"}},
	}
	if err := ValidateRecordSet(&rrset, "example.com."); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := s.CreateRecord(ctx, admin, "example.com.", rrset, SourceAPI); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	if len(sent) != 1 {
		t.Fatalf("expected exactly one PATCH, got %d", len(sent))
	}
	patch := sent[0]
	// Name canonicalised, sibling preserved, new record appended.
	if patch.Name != "www.example.com." {
		t.Errorf("patch name = %q, want www.example.com.", patch.Name)
	}
	if len(patch.Records) != 2 {
		t.Fatalf("patch records = %d, want 2 (merge preserves siblings)", len(patch.Records))
	}
	// TTL inherited from the existing RRSet (0 would zero the siblings).
	if patch.TTL != 7200 {
		t.Errorf("patch TTL = %d, want 7200 (inherited)", patch.TTL)
	}

	// Audit row with before/after snapshots.
	var action, oldValue, newValue string
	if err := db.QueryRowContext(ctx,
		`SELECT action, old_value, new_value FROM activity_logs WHERE action='create_record' AND zone_id='example.com.'`).Scan(&action, &oldValue, &newValue); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if oldValue == "" || newValue == "" {
		t.Error("audit snapshots must be non-empty on a merge")
	}

	// A duplicate submission (content identical to an existing sibling)
	// collapses to one record: PowerDNS rejects duplicates with an opaque
	// 422, and the first occurrence wins so the existing record keeps its
	// flags.
	sent = nil
	dup := models.RRSet{Name: "www.example.com.", Type: "A", TTL: 0, Records: []models.RecordInfo{{Content: "192.0.2.10"}}}
	if err := s.CreateRecord(ctx, admin, "example.com.", dup, SourceAPI); err != nil {
		t.Fatalf("duplicate CreateRecord: %v", err)
	}
	if len(sent) != 1 || len(sent[0].Records) != 1 {
		t.Errorf("duplicate must collapse to one record, got %d patches / %d records", len(sent), len(sent[0].Records))
	}
}

func TestCreateRecord_ZoneFetchErrorStages(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Not Found"}`)) // #nosec G104 -- test helper
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)

	admin := &models.User{ID: 1, Username: "admin", Role: "admin"}
	err := s.CreateRecord(context.Background(), admin, "missing.example.", models.RRSet{
		Name: "www.missing.example.", Type: "A", TTL: 300,
		Records: []models.RecordInfo{{Content: "192.0.2.1"}},
	}, SourceAPI)
	var se *StageError
	if !errors.As(err, &se) || se.Stage != StageFetch {
		t.Fatalf("missing zone: got %v, want StageError(StageFetch)", err)
	}
	if !errors.Is(err, pdns.ErrNotFound) {
		t.Fatalf("stage error must unwrap to pdns.ErrNotFound, got %v", err)
	}
}

func TestStats_StageErrors(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/zones") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"boom"}`)) // #nosec G104 -- test helper
			return
		}
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)

	_, _, err := s.Stats(context.Background(), &models.User{ID: 1, Role: "admin"})
	var se *StageError
	if !errors.As(err, &se) || se.Stage != StageZoneList {
		t.Fatalf("zone-list failure: got %v, want StageError(StageZoneList)", err)
	}
}

// TestZoneLocks_SharedInstance pins the wiring contract: the Service and the
// handlers layer lock through the SAME ZoneLocks instance, so a REST write
// and a web write on one zone serialize against each other.
func TestZoneLocks_SharedInstance(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, client := testutil.NewTestPDNSServer(t, nil)
	s := New(db, client)

	var locks *ZoneLocks = s.Locks()
	unlock := locks.Lock("example.com.")
	done := make(chan struct{})
	go func() {
		// Must block until the first holder releases.
		s.locks.Lock("example.com.")()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("second Lock on the same zone must wait for the first")
	default:
	}
	unlock()
	<-done
}

// TestExportZone covers the shared export service method: format dispatch,
// record counting (bind omits disabled records, csv counts them) and the
// authorization gate.
func TestExportZone(t *testing.T) {
	rrsets := []models.RRSet{
		{Name: "www.example.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "192.0.2.1"}}},
		{Name: "down.example.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "192.0.2.2", Disabled: true}}},
	}
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			models.Zone
			RRSets []models.RRSet `json:"rrsets"`
		}{Zone: models.Zone{ID: "example.", Name: "example.", Kind: "Native"}, RRSets: rrsets})
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()
	adminID := testutil.SeedTestUser(t, db, "admin", "pass", "admin", true)
	admin := &models.User{ID: adminID, Role: "admin"}

	bind, count, err := s.ExportZone(ctx, admin, "example.", "bind")
	if err != nil {
		t.Fatalf("bind export: %v", err)
	}
	if count != 1 {
		t.Errorf("bind record count = %d, want 1 (disabled records omitted)", count)
	}
	if !strings.Contains(bind, "www IN A 192.0.2.1") || strings.Contains(bind, "192.0.2.2") {
		t.Errorf("bind export must omit the disabled record, got:\n%s", bind)
	}

	csv, count, err := s.ExportZone(ctx, admin, "example.", "csv")
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	if count != 2 {
		t.Errorf("csv record count = %d, want 2 (disabled records included)", count)
	}
	if !strings.Contains(csv, "down.example.,A,192.0.2.2,3600,0,true,") {
		t.Errorf("csv export must flag the disabled record, got:\n%s", csv)
	}

	if _, _, err := s.ExportZone(ctx, admin, "example.", "xml"); err == nil {
		t.Error("unknown format must be rejected")
	}

	userID := testutil.SeedTestUser(t, db, "plain", "pass", "user", true)
	if _, _, err := s.ExportZone(ctx, &models.User{ID: userID, Role: "user"}, "example.", "bind"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted export: %v, want ErrForbidden", err)
	}
}

// TestRecordWrites_SerializedPerZone pins the per-zone serialization of the
// concurrent write paths: a REPLACE or DELETE landing in the middle of a
// concurrent append's fetch→merge→PATCH cycle would be overwritten by that
// merge (or resurrect the deleted record). Holding the per-zone lock across
// each write's whole fetch→PATCH sequence makes every writer's GET and PATCH
// adjacent — the mock widens the fetch window so an unlocked writer would
// interleave.
func TestRecordWrites_SerializedPerZone(t *testing.T) {
	var mu sync.Mutex
	var events []string
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			// Widen the fetch window: without the lock, another writer's
			// GET slips in before this one's PATCH.
			time.Sleep(50 * time.Millisecond)
			mu.Lock()
			events = append(events, "GET")
			mu.Unlock()
			w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
			return
		}
		mu.Lock()
		events = append(events, "PATCH")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()
	admin := &models.User{ID: 1, Role: "admin"}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		_ = s.CreateRecord(ctx, admin, "example.", models.RRSet{
			Name: "a.example.", Type: "A", TTL: 300,
			Records: []models.RecordInfo{{Content: "192.0.2.1"}},
		}, SourceAPI)
	}()
	go func() {
		defer wg.Done()
		rrset := models.RRSet{Name: "b.example.", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "192.0.2.2"}}}
		if err := PrepareValidatedRecordSet(&rrset, "example."); err != nil {
			t.Errorf("prepare: %v", err)
			return
		}
		_ = s.UpdateRecord(ctx, admin, "example.", rrset, SourceAPI)
	}()
	go func() {
		defer wg.Done()
		_ = s.DeleteRecord(ctx, admin, "example.", "c.example.", "A", SourceAPI)
	}()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 6 {
		t.Fatalf("expected 6 upstream calls (3 writers x fetch+write), got %v", events)
	}
	for i, ev := range events {
		want := "GET"
		if i%2 == 1 {
			want = "PATCH"
		}
		if ev != want {
			t.Fatalf("write paths must serialize per zone (each fetch immediately followed by its write), got %v", events)
		}
	}
}

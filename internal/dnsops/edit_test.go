package dnsops

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// newEditTestHarness builds a Service over an in-memory DB and a mock PDNS
// that serves `existing` for the ListRecords fetch and captures PATCH bodies
// into sent. It is the shared setup for the EditRecord contract tests.
func newEditTestHarness(t *testing.T, existing []models.RRSet, sent *[]models.RRSet) (*Service, *database.DB) {
	t.Helper()
	srv, client := testutil.NewTestPDNSServer(t, captureRRSets(t, sent, existing))
	t.Cleanup(srv.Close)
	db := testutil.NewTestDB(t)
	return New(db, client), db
}

func seedEditAdmin(t *testing.T, db *database.DB) *models.User {
	t.Helper()
	adminID := testutil.SeedTestUser(t, db, "admin", "pass", "admin", true)
	return &models.User{ID: adminID, Role: "admin"}
}

// TestEditRecord_TransitionMatrix pins the exact stale-edit transition table
// the web update form implements today (records.go updateRecordFromForm),
// now owned by the service: every branch must send the precise PATCH (or
// refuse without touching PowerDNS) and classify the refusal as a
// *RecordConflictError.
func TestEditRecord_TransitionMatrix(t *testing.T) {
	oldSOA := "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600"
	newSOA := "ns2.example.com. hostmaster.example.com. 2024010102 7200 3600 1209600 3600"

	tests := []struct {
		name string
		// existing is what the ListRecords fetch stage returns (wire form).
		existing []models.RRSet
		in       EditRecordInput
		// wantConflict is a substring of the RecordConflictError message; ""
		// means the edit must succeed.
		wantConflict string
		wantSent     int
		wantContents []string // exact record contents of the single PATCH
		wantTTL      int
	}{
		{
			name:     "missing RRSet without original identity creates",
			existing: nil,
			in: EditRecordInput{
				RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 0,
					Records: []models.RecordInfo{{Content: "192.0.2.10"}}},
			},
			wantSent:     1,
			wantContents: []string{"192.0.2.10"},
			wantTTL:      DefaultRecordTTL, // brand-new RRSet, no TTL to inherit
		},
		{
			name:     "missing RRSet with original identity conflicts",
			existing: nil,
			in: EditRecordInput{
				RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 300,
					Records: []models.RecordInfo{{Content: "192.0.2.10"}}},
				OriginalContent: "192.0.2.1", OriginalPriority: 0,
			},
			wantConflict: "deleted",
			wantSent:     0,
		},
		{
			name: "identity matched replaces and keeps siblings",
			existing: []models.RRSet{
				{Name: "www.example.com.", Type: "A", TTL: 300, Records: []models.RecordInfo{
					{Content: "192.0.2.1"}, {Content: "192.0.2.2"},
				}},
			},
			in: EditRecordInput{
				RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 0,
					Records: []models.RecordInfo{{Content: "192.0.2.9"}}},
				OriginalContent: "192.0.2.1", OriginalPriority: 0,
			},
			wantSent:     1,
			wantContents: []string{"192.0.2.9", "192.0.2.2"},
			wantTTL:      300, // inherited from the existing RRSet
		},
		{
			name: "identity unmatched on multi-record RRSet conflicts",
			existing: []models.RRSet{
				{Name: "www.example.com.", Type: "A", TTL: 300, Records: []models.RecordInfo{
					{Content: "192.0.2.1"}, {Content: "192.0.2.2"},
				}},
			},
			in: EditRecordInput{
				RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 300,
					Records: []models.RecordInfo{{Content: "192.0.2.9"}}},
				OriginalContent: "9.9.9.9", OriginalPriority: 0,
			},
			wantConflict: "modified by someone else",
			wantSent:     0,
		},
		{
			name: "identity unmatched on singleton non-SOA conflicts",
			existing: []models.RRSet{
				{Name: "www.example.com.", Type: "A", TTL: 300, Records: []models.RecordInfo{
					{Content: "10.0.0.1"},
				}},
			},
			in: EditRecordInput{
				RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 300,
					Records: []models.RecordInfo{{Content: "10.0.0.9"}}},
				OriginalContent: "9.9.9.9", OriginalPriority: 0,
			},
			wantConflict: "modified by someone else",
			wantSent:     0,
		},
		{
			name: "SOA singleton unmatched replaces sole record",
			existing: []models.RRSet{
				{Name: "example.com.", Type: "SOA", TTL: 3600, Records: []models.RecordInfo{
					{Content: oldSOA},
				}},
			},
			in: EditRecordInput{
				RRSet: models.RRSet{Name: "example.com.", Type: "SOA", TTL: 0,
					Records: []models.RecordInfo{{Content: newSOA}}},
				// SOA-EDIT bumps the serial between page load and save, so
				// the submitted identity is always stale — must NOT conflict.
				OriginalContent: oldSOA, OriginalPriority: 0,
			},
			wantSent:     1,
			wantContents: []string{newSOA},
			wantTTL:      3600,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sent []models.RRSet
			s, db := newEditTestHarness(t, tc.existing, &sent)
			admin := seedEditAdmin(t, db)
			ctx := context.Background()

			newRRSet, _, err := s.EditRecord(ctx, admin, "example.com.", tc.in, SourceWeb)

			if tc.wantConflict != "" {
				var ce *RecordConflictError
				if !errors.As(err, &ce) {
					t.Fatalf("err = %v, want *RecordConflictError containing %q", err, tc.wantConflict)
				}
				if !strings.Contains(ce.Message, tc.wantConflict) {
					t.Errorf("conflict message %q does not contain %q", ce.Message, tc.wantConflict)
				}
				if len(sent) != 0 {
					t.Errorf("a refused edit must not reach PowerDNS, got PATCH %+v", sent)
				}
				return
			}

			if err != nil {
				t.Fatalf("EditRecord: %v", err)
			}
			if newRRSet == nil {
				t.Fatal("EditRecord returned a nil RRSet on success")
			}
			if len(sent) != tc.wantSent {
				t.Fatalf("expected %d PATCH rrset(s), got %d: %+v", tc.wantSent, len(sent), sent)
			}
			got := sent[0]
			if got.Name != tc.in.RRSet.Name || got.Type != tc.in.RRSet.Type {
				t.Errorf("PATCH identity = %s %s, want %s %s", got.Name, got.Type, tc.in.RRSet.Name, tc.in.RRSet.Type)
			}
			if got.TTL != tc.wantTTL {
				t.Errorf("PATCH TTL = %d, want %d", got.TTL, tc.wantTTL)
			}
			if len(got.Records) != len(tc.wantContents) {
				t.Fatalf("PATCH records = %+v, want contents %v", got.Records, tc.wantContents)
			}
			for i, want := range tc.wantContents {
				if got.Records[i].Content != want {
					t.Errorf("PATCH record %d content = %q, want %q (full: %+v)", i, got.Records[i].Content, want, got.Records)
				}
			}
		})
	}
}

// TestEditRecord_MXNormalizeDedupAndDisplayEcho pins the merge-then-normalise
// contract for priority types plus the M12 dedup index rule: editing the LAST
// record so it duplicates the FIRST collapses to a single record, and the
// returned display record is the survivor (SplitPriority applied) — the value
// the inline editor echoes back into the row.
func TestEditRecord_MXNormalizeDedupAndDisplayEcho(t *testing.T) {
	var sent []models.RRSet
	// Wire form as PowerDNS stores it; the client read path splits the
	// priority out, so the RRSet identities are
	// (mail1.example.com., 10) and (mail2.example.com., 20).
	existing := []models.RRSet{
		{Name: "mx.example.com.", Type: "MX", TTL: 300, Records: []models.RecordInfo{
			{Content: "10 mail1.example.com."},
			{Content: "20 mail2.example.com."},
		}},
	}
	s, _ := newEditTestHarness(t, existing, &sent)
	admin := seedEditAdmin(t, s.DB)
	ctx := context.Background()

	in := EditRecordInput{
		RRSet: models.RRSet{Name: "mx.example.com.", Type: "MX", TTL: 0,
			Records: []models.RecordInfo{{Content: "mail1.example.com", Priority: 10}}},
		OriginalContent: "mail2.example.com.", OriginalPriority: 20,
	}
	newRRSet, updated, err := s.EditRecord(ctx, admin, "example.com.", in, SourceWeb)
	if err != nil {
		t.Fatalf("EditRecord: %v", err)
	}

	if len(sent) != 1 {
		t.Fatalf("expected 1 PATCH, got %+v", sent)
	}
	got := sent[0]
	// First occurrence wins: the merged copy collapsed onto the pre-existing
	// first record, so exactly one record is PATCHed…
	if len(got.Records) != 1 {
		t.Fatalf("expected 1 deduplicated record, got %+v", got.Records)
	}
	// …in wire form: priority embedded, separate priority element cleared.
	if got.Records[0].Content != "10 mail1.example.com." || got.Records[0].Priority != 0 {
		t.Errorf("PATCH record = %+v, want content %q priority 0", got.Records[0], "10 mail1.example.com.")
	}
	if got.TTL != 300 {
		t.Errorf("PATCH TTL = %d, want 300 inherited", got.TTL)
	}

	// The returned RRSet is the PATCHed (wire) form…
	if newRRSet == nil || len(newRRSet.Records) != 1 || newRRSet.Records[0].Content != "10 mail1.example.com." {
		t.Errorf("returned RRSet = %+v, want the wire-form PATCH result", newRRSet)
	}
	// …while the display record is SplitPriority form: the surviving FIRST
	// record, with the priority split back out (the inline editor echo).
	if updated.Content != "mail1.example.com." || updated.Priority != 10 {
		t.Errorf("updated display record = %+v, want content %q priority 10 (first occurrence)", updated, "mail1.example.com.")
	}
}

// TestEditRecord_TTLResolution pins the TTL contract: an explicit TTL wins; a
// blank TTL inherits the existing RRSet's TTL — INCLUDING 0, so a deliberate
// no-cache RRSet is not silently rewritten to the 3600 default.
func TestEditRecord_TTLResolution(t *testing.T) {
	tests := []struct {
		name        string
		existingTTL int
		inTTL       int
		want        int
	}{
		{"explicit TTL wins", 300, 600, 600},
		{"blank inherits existing", 300, 0, 300},
		{"blank inherits no-cache zero", 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sent []models.RRSet
			existing := []models.RRSet{
				{Name: "www.example.com.", Type: "A", TTL: tc.existingTTL, Records: []models.RecordInfo{
					{Content: "192.0.2.1"},
				}},
			}
			s, _ := newEditTestHarness(t, existing, &sent)
			admin := seedEditAdmin(t, s.DB)

			in := EditRecordInput{
				RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: tc.inTTL,
					Records: []models.RecordInfo{{Content: "192.0.2.9"}}},
				OriginalContent: "192.0.2.1", OriginalPriority: 0,
			}
			if _, _, err := s.EditRecord(context.Background(), admin, "example.com.", in, SourceWeb); err != nil {
				t.Fatalf("EditRecord: %v", err)
			}
			if len(sent) != 1 {
				t.Fatalf("expected 1 PATCH, got %+v", sent)
			}
			if sent[0].TTL != tc.want {
				t.Errorf("PATCH TTL = %d, want %d", sent[0].TTL, tc.want)
			}
		})
	}
}

// TestCreateRecord_InheritsZeroTTL is the CreateRecord-side guard of the same
// no-cache contract: appending a sibling to an RRSet whose TTL is 0 must keep
// TTL 0 in the PATCH. Pre-T1 the `existingRRSet.TTL > 0` guard silently
// upgraded it to DefaultRecordTTL.
func TestCreateRecord_InheritsZeroTTL(t *testing.T) {
	var sent []models.RRSet
	existing := []models.RRSet{
		{Name: "www.example.com.", Type: "A", TTL: 0, Records: []models.RecordInfo{
			{Content: "192.0.2.1"},
		}},
	}
	s, _ := newEditTestHarness(t, existing, &sent)

	rrset := models.RRSet{Name: "www", Type: "A", TTL: 0,
		Records: []models.RecordInfo{{Content: "192.0.2.9"}}}
	if err := ValidateRecordSet(&rrset, "example.com."); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := s.CreateRecord(context.Background(), nil, "example.com.", rrset, SourceAPI); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("expected 1 PATCH, got %+v", sent)
	}
	if sent[0].TTL != 0 {
		t.Errorf("PATCH TTL = %d, want 0 (a no-cache RRSet must not become %d)", sent[0].TTL, DefaultRecordTTL)
	}
}

// TestEditRecord_AuditViaWeb pins the delegation contract: the service writes
// exactly one audit row per edit, labelled with the SourceWeb transport, and
// carries Old/New RRSet snapshots — populated for an edit of an existing
// RRSet, empty before-image for a create-through-edit on a missing RRSet.
func TestEditRecord_AuditViaWeb(t *testing.T) {
	var sent []models.RRSet
	existing := []models.RRSet{
		{Name: "www.example.com.", Type: "A", TTL: 300, Records: []models.RecordInfo{
			{Content: "192.0.2.1"},
		}},
	}
	s, db := newEditTestHarness(t, existing, &sent)
	admin := seedEditAdmin(t, db)
	ctx := context.Background()

	in := EditRecordInput{
		RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 0,
			Records: []models.RecordInfo{{Content: "192.0.2.9"}}},
		OriginalContent: "192.0.2.1", OriginalPriority: 0,
	}
	if _, _, err := s.EditRecord(ctx, admin, "example.com.", in, SourceWeb); err != nil {
		t.Fatalf("EditRecord: %v", err)
	}

	// Exactly one audit row so far, whatever its action name.
	var details, oldValue, newValue string
	if err := db.QueryRowContext(ctx, `SELECT details, old_value, new_value FROM activity_logs`).
		Scan(&details, &oldValue, &newValue); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !strings.Contains(details, " via Web") {
		t.Errorf("audit details %q must carry the Web transport label", details)
	}
	if oldValue == "" || !strings.Contains(oldValue, "192.0.2.1") {
		t.Errorf("audit before-image must snapshot the existing RRSet, got %q", oldValue)
	}
	if newValue == "" || !strings.Contains(newValue, "192.0.2.9") {
		t.Errorf("audit after-image must snapshot the new RRSet, got %q", newValue)
	}

	// Create-through-edit on a name absent from the zone: the before-image
	// is empty, the row is still labelled, and only one more row appears.
	in2 := EditRecordInput{
		RRSet: models.RRSet{Name: "new.example.com.", Type: "A", TTL: 0,
			Records: []models.RecordInfo{{Content: "192.0.2.50"}}},
	}
	if _, _, err := s.EditRecord(ctx, admin, "example.com.", in2, SourceWeb); err != nil {
		t.Fatalf("EditRecord (create-through-edit): %v", err)
	}

	var labelled, emptyBefore int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_logs WHERE details LIKE '% via Web'`).Scan(&labelled)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_logs WHERE old_value = ''`).Scan(&emptyBefore)
	if labelled != 2 {
		t.Errorf("expected 2 audit rows labelled ' via Web', got %d", labelled)
	}
	if emptyBefore != 1 {
		t.Errorf("expected exactly 1 audit row with an empty before-image, got %d", emptyBefore)
	}
}

// TestEditRecord_UngrantedUserForbidden pins the fail-closed gate: a user
// without a zone grant is refused before any fetch or PATCH, and no audit row
// is written for a refused edit.
func TestEditRecord_UngrantedUserForbidden(t *testing.T) {
	var sent []models.RRSet
	existing := []models.RRSet{
		{Name: "www.example.com.", Type: "A", TTL: 300, Records: []models.RecordInfo{
			{Content: "192.0.2.1"},
		}},
	}
	s, db := newEditTestHarness(t, existing, &sent)
	userID := testutil.SeedTestUser(t, db, "denied", "pass", "user", true)
	ctx := context.Background()

	in := EditRecordInput{
		RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 0,
			Records: []models.RecordInfo{{Content: "192.0.2.9"}}},
		OriginalContent: "192.0.2.1", OriginalPriority: 0,
	}
	if _, _, err := s.EditRecord(ctx, &models.User{ID: userID, Role: "user"}, "example.com.", in, SourceWeb); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(sent) != 0 {
		t.Errorf("a refused edit must not reach PowerDNS, got %+v", sent)
	}
	var n int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_logs`).Scan(&n)
	if n != 0 {
		t.Errorf("a refused edit must not be audited, got %d rows", n)
	}
}

// TestEditRecord_FetchFailureStage pins the composite-failure tagging: a
// ListRecords failure is a StageError(StageFetch), never a silent write.
func TestEditRecord_FetchFailureStage(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, nil) // 500 on every request
	t.Cleanup(srv.Close)
	db := testutil.NewTestDB(t)
	s := New(db, client)

	in := EditRecordInput{
		RRSet: models.RRSet{Name: "www.example.com.", Type: "A", TTL: 300,
			Records: []models.RecordInfo{{Content: "192.0.2.9"}}},
		OriginalContent: "192.0.2.1", OriginalPriority: 0,
	}
	_, _, err := s.EditRecord(context.Background(), nil, "example.com.", in, SourceWeb)
	var se *StageError
	if !errors.As(err, &se) || se.Stage != StageFetch {
		t.Fatalf("err = %v, want StageError(StageFetch)", err)
	}
}

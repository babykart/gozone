package dnsops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// TestPrepareRecordContent_PriorityConflict pins the defence-in-depth check
// for MX/SRV: content that already embeds a priority (wire data fed back in)
// combined with an explicitly provided Priority that diverges from the
// embedded value is an error — never silently re-embedded with one of the two
// values dropped. This is the SRV regression guard: "10 5 5060 sip." with
// priority 0 previously produced wire "0 5 5060 sip.", losing the 10.
func TestPrepareRecordContent_PriorityConflict(t *testing.T) {
	cases := []struct {
		name     string
		rtype    string
		content  string
		priority int
		wantC    string
		wantP    int
		wantErr  bool
		// Typed-error expectations when wantErr is set.
		wantEmbedded int
		wantProvided int
	}{
		{"SRV embedded 10 vs provided 0 conflicts", "SRV", "10 5 5060 sip.example.com.", 0, "", 0, true, 10, 0},
		{"SRV embedded 10 vs provided 10 aligns", "SRV", "10 5 5060 sip.example.com.", 10, "10 5 5060 sip.example.com.", 0, false, 0, 0},
		{"SRV embedded 10 vs provided 11 conflicts", "SRV", "10 5 5060 t.", 11, "", 0, true, 10, 11},
		// Form content has no embedded priority: the provided one embeds.
		{"SRV form content embeds provided 10", "SRV", "5 5060 sip.example.com.", 10, "10 5 5060 sip.example.com.", 0, false, 0, 0},
		// Form content with zero priority embeds as 0; embedded zero in wire
		// content aligns with provided zero — presence is not a conflict.
		{"SRV form content with zero priority", "SRV", "5 5060 t.", 0, "0 5 5060 t.", 0, false, 0, 0},
		{"SRV embedded zero aligns with provided zero", "SRV", "0 5 5060 t.", 0, "0 5 5060 t.", 0, false, 0, 0},
		// MX divergence is caught here too (defence-in-depth: REST/MCP
		// content validation rejects embedded MX upstream).
		{"MX embedded 10 vs provided 0 conflicts", "MX", "10 mail.example.com", 0, "", 0, true, 10, 0},
		{"MX form content embeds provided 5", "MX", "mail.example.com.", 5, "5 mail.example.com.", 0, false, 0, 0},
		// Non-priority types: unchanged content, priority passthrough.
		{"A passthrough with priority", "A", "192.0.2.1", 42, "192.0.2.1", 42, false, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotC, gotP, err := PrepareRecordContent(c.rtype, c.content, c.priority)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got (%q, %d, nil)", gotC, gotP)
				}
				var pce *PriorityConflictError
				if !errors.As(err, &pce) {
					t.Fatalf("error is %T %v, want *PriorityConflictError", err, err)
				}
				if pce.RecordType != c.rtype {
					t.Errorf("RecordType = %q, want %q", pce.RecordType, c.rtype)
				}
				if pce.Embedded != c.wantEmbedded || pce.Provided != c.wantProvided {
					t.Errorf("Embedded/Provided = %d/%d, want %d/%d",
						pce.Embedded, pce.Provided, c.wantEmbedded, c.wantProvided)
				}
				for _, needle := range []string{c.rtype, strconv.Itoa(c.wantEmbedded), strconv.Itoa(c.wantProvided)} {
					if !strings.Contains(err.Error(), needle) {
						t.Errorf("error message %q must contain %q", err.Error(), needle)
					}
				}
				// The error path returns zero values for content/priority.
				if gotC != "" || gotP != 0 {
					t.Errorf("error path must return (\"\", 0), got (%q, %d)", gotC, gotP)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotC != c.wantC || gotP != c.wantP {
				t.Errorf("PrepareRecordContent(%q, %q, %d) = (%q, %d), want (%q, %d)",
					c.rtype, c.content, c.priority, gotC, gotP, c.wantC, c.wantP)
			}
		})
	}
}

// TestPriorityConflictError_Message pins the user-facing message shape so
// every transport surfaces the same actionable text.
func TestPriorityConflictError_Message(t *testing.T) {
	err := &PriorityConflictError{RecordType: "SRV", Embedded: 10, Provided: 0}
	want := "SRV content embeds priority 10 which conflicts with the priority field value 0; " +
		"align them or remove the priority from the content"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

// TestPrepareValidatedRecordSet_PriorityConflict verifies the REPLACE-path
// caller propagates the typed error and does not overwrite the conflicting
// record with the error path's zero values. This asserts nothing about
// RRSet-wide atomicity across multiple records — only the single conflicting
// record keeps its input content/priority because the error returns before
// the assignment.
func TestPrepareValidatedRecordSet_PriorityConflict(t *testing.T) {
	rrset := models.RRSet{
		Name: "_sip._tcp", Type: "SRV", TTL: 3600,
		Records: []models.RecordInfo{{Content: "10 5 5060 sip.example.com.", Priority: 0}},
	}
	err := PrepareValidatedRecordSet(&rrset, "example.com.")
	var pce *PriorityConflictError
	if !errors.As(err, &pce) {
		t.Fatalf("PrepareValidatedRecordSet: %v, want *PriorityConflictError", err)
	}
	if pce.Embedded != 10 || pce.Provided != 0 {
		t.Errorf("Embedded/Provided = %d/%d, want 10/0", pce.Embedded, pce.Provided)
	}
	if rrset.Records[0].Content != "10 5 5060 sip.example.com." || rrset.Records[0].Priority != 0 {
		t.Errorf("error path must not mutate records, got content=%q priority=%d",
			rrset.Records[0].Content, rrset.Records[0].Priority)
	}
}

// TestCreateRecord_PriorityConflict verifies the merge-path caller
// (Service.CreateRecord, records.go) propagates the typed error before any
// PATCH, and leaves no audit row behind.
func TestCreateRecord_PriorityConflict(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			// No existing RRSet: the merge is a no-op and the conflict
			// fires in the single PrepareRecordContent pass.
			json.NewEncoder(w).Encode(map[string]any{"rrsets": []models.RRSet{}})
			return
		}
		t.Errorf("no PATCH expected when the priority check fails, got %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()
	db := testutil.NewTestDB(t)
	s := New(db, client)
	ctx := context.Background()

	rrset := models.RRSet{
		Name: "_sip._tcp", Type: "SRV", TTL: 3600,
		Records: []models.RecordInfo{{Content: "10 5 5060 sip.example.com.", Priority: 0}},
	}
	// Validate only — CreateRecord runs the PrepareRecordContent merge pass
	// itself, which is where the conflict must surface.
	if err := ValidateRecordSet(&rrset, "example.com."); err != nil {
		t.Fatalf("validate: %v", err)
	}
	err := s.CreateRecord(ctx, nil, "example.com.", rrset, SourceAPI)
	var pce *PriorityConflictError
	if !errors.As(err, &pce) {
		t.Fatalf("CreateRecord: %v, want *PriorityConflictError", err)
	}
	if pce.Embedded != 10 || pce.Provided != 0 {
		t.Errorf("Embedded/Provided = %d/%d, want 10/0", pce.Embedded, pce.Provided)
	}
	var n int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_logs WHERE zone_id='example.com.'`).Scan(&n)
	if n != 0 {
		t.Errorf("conflict must not be audited, got %d rows", n)
	}
}

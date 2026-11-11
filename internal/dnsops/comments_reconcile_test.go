package dnsops

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// cloneCommentPatch deep-copies a comment patch so each subtest starts from
// pristine client-supplied values: the reconciliation under test overwrites
// Account/ModifiedAt in the submitted items in place, and sharing the fixture
// across subtests would mask that behavior.
func cloneCommentPatch(p *models.CommentPatch) *models.CommentPatch {
	if p == nil {
		return nil
	}
	q := &models.CommentPatch{Clear: p.Clear}
	if p.Items != nil {
		q.Items = make([]models.Comment, len(p.Items))
		copy(q.Items, p.Items)
	}
	return q
}

// TestReconcileCommentMetadata pins the server-ownership invariant for RRSet
// comment metadata: client-supplied Account/ModifiedAt must never be forwarded
// to PowerDNS. Each submitted item is matched one-to-one, FIFO, against the
// stored comments of the same RRSet with EXACTLY equal Content; on a match
// the stored metadata is kept, otherwise both fields are zeroed (PowerDNS
// stamps modified_at server-side). A nil patch and a Clear patch are no-ops.
//
// The scenarios run through BOTH write paths (CreateRecord's merge-into-
// existing and UpdateRecord's REPLACE) because the reconciliation is applied
// at the service layer, immediately before the PowerDNS PATCH, in each.
func TestReconcileCommentMetadata(t *testing.T) {
	cases := []struct {
		name       string
		stored     []models.Comment
		submit     *models.CommentPatch
		want       []models.Comment // expected forwarded Items (reconciled)
		wantClear  bool             // Clear patch: forwarded verbatim as comments:[]
		wantAbsent bool             // nil patch: no comments key in the PATCH body
	}{
		{
			name:   "echo keeps stored metadata",
			stored: []models.Comment{{Content: "ops", Account: "alice", ModifiedAt: 100}},
			submit: &models.CommentPatch{Items: []models.Comment{{Content: "ops", Account: "evil", ModifiedAt: 999}}},
			want:   []models.Comment{{Content: "ops", Account: "alice", ModifiedAt: 100}},
		},
		{
			name:   "new content is zeroed",
			stored: []models.Comment{{Content: "other", Account: "alice", ModifiedAt: 100}},
			submit: &models.CommentPatch{Items: []models.Comment{{Content: "new", Account: "spoof", ModifiedAt: 5}}},
			want:   []models.Comment{{Content: "new", Account: "", ModifiedAt: 0}},
		},
		{
			name: "duplicate stored comments match one-to-one FIFO",
			stored: []models.Comment{
				{Content: "dup", Account: "alice", ModifiedAt: 100},
				{Content: "dup", Account: "bob", ModifiedAt: 200},
			},
			submit: &models.CommentPatch{Items: []models.Comment{
				{Content: "dup", Account: "evil", ModifiedAt: 999},
				{Content: "dup", Account: "evil2", ModifiedAt: 998},
				{Content: "new", Account: "spoof", ModifiedAt: 5},
			}},
			want: []models.Comment{
				{Content: "dup", Account: "alice", ModifiedAt: 100},
				{Content: "dup", Account: "bob", ModifiedAt: 200},
				{Content: "new", Account: "", ModifiedAt: 0},
			},
		},
		{
			name:   "stored duplicates are exhausted FIFO then zeroed",
			stored: []models.Comment{{Content: "dup", Account: "alice", ModifiedAt: 100}},
			submit: &models.CommentPatch{Items: []models.Comment{
				{Content: "dup", Account: "evil", ModifiedAt: 1},
				{Content: "dup", Account: "evil2", ModifiedAt: 2},
			}},
			want: []models.Comment{
				{Content: "dup", Account: "alice", ModifiedAt: 100},
				{Content: "dup", Account: "", ModifiedAt: 0},
			},
		},
		{
			name:      "clear patch is not reconciled",
			stored:    []models.Comment{{Content: "ops", Account: "alice", ModifiedAt: 100}},
			submit:    &models.CommentPatch{Clear: true},
			wantClear: true,
		},
		{
			name:       "nil patch is a no-op",
			stored:     []models.Comment{{Content: "ops", Account: "alice", ModifiedAt: 100}},
			submit:     nil,
			wantAbsent: true,
		},
	}

	methods := []struct {
		name string
		run  func(t *testing.T, s *Service, rrset models.RRSet) error
	}{
		{
			name: "CreateRecord",
			run: func(t *testing.T, s *Service, rrset models.RRSet) error {
				t.Helper()
				if err := ValidateRecordSet(&rrset, "example.com."); err != nil {
					return err
				}
				return s.CreateRecord(context.Background(), nil, "example.com.", rrset, SourceAPI)
			},
		},
		{
			name: "UpdateRecord",
			run: func(t *testing.T, s *Service, rrset models.RRSet) error {
				t.Helper()
				if err := PrepareValidatedRecordSet(&rrset, "example.com."); err != nil {
					return err
				}
				return s.UpdateRecord(context.Background(), nil, "example.com.", rrset, SourceAPI)
			},
		},
	}

	for _, tc := range cases {
		for _, m := range methods {
			t.Run(tc.name+"/"+m.name, func(t *testing.T) {
				var sent []models.RRSet
				var raw []byte
				srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch r.Method {
					case http.MethodGet:
						stored := models.RRSet{
							Name: "www.example.com.", Type: "A", TTL: 300,
							Records: []models.RecordInfo{{Content: "1.2.3.4"}},
						}
						if len(tc.stored) > 0 {
							stored.Comments = &models.CommentPatch{Items: tc.stored}
						}
						json.NewEncoder(w).Encode(map[string]any{"rrsets": []models.RRSet{stored}})
					case http.MethodPatch:
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Errorf("read PATCH body: %v", err)
						}
						raw = body
						var payload struct {
							RRSets []models.RRSet `json:"rrsets"`
						}
						if err := json.Unmarshal(body, &payload); err != nil {
							t.Errorf("decode PATCH body: %v", err)
						}
						sent = payload.RRSets
						w.WriteHeader(http.StatusNoContent)
					default:
						t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNoContent)
					}
				})
				defer srv.Close()
				db := testutil.NewTestDB(t)
				s := New(db, client)

				rrset := models.RRSet{
					Name: "www.example.com.", Type: "A", TTL: 300,
					Records:  []models.RecordInfo{{Content: "5.6.7.8"}},
					Comments: cloneCommentPatch(tc.submit),
				}
				if err := m.run(t, s, rrset); err != nil {
					t.Fatalf("%s: %v", m.name, err)
				}

				if len(sent) != 1 {
					t.Fatalf("expected exactly 1 PATCH rrset, got %+v", sent)
				}

				switch {
				case tc.wantClear:
					// The Clear flag is lost on re-decode (UnmarshalJSON
					// never sets it), so assert on the raw wire form: the
					// purge must reach PowerDNS untouched as comments:[].
					if !strings.Contains(string(raw), `"comments":[]`) {
						t.Errorf("Clear patch must be forwarded verbatim as comments:[], got body %s", raw)
					}
					if strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "evil") {
						t.Errorf("Clear patch must not carry reconciled items, got body %s", raw)
					}
				case tc.wantAbsent:
					if sent[0].Comments != nil {
						t.Errorf("nil comment patch must stay absent, got %+v", sent[0].Comments)
					}
				default:
					patch := sent[0].Comments
					if patch == nil || patch.Clear {
						t.Fatalf("expected Items patch (no Clear), got %+v", patch)
					}
					if !reflect.DeepEqual(patch.Items, tc.want) {
						t.Errorf("reconciled comments mismatch\n got: %+v\nwant: %+v", patch.Items, tc.want)
					}
				}
			})
		}
	}
}

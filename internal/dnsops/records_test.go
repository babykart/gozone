package dnsops

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// TestCreateRecord_MergesCaseVariantName is the case-preserving-backend
// regression guard: PowerDNS backends that preserve the original casing
// (bind, LMDB, AXFR-imported zones) return RRSets under their original
// name casing, while GoZone submissions are lowercased by
// NormalizeRecordName. The merge lookup must match case-insensitively —
// an exact match misses the existing RRSet and the REPLACE then silently
// drops its sibling records.
func TestCreateRecord_MergesCaseVariantName(t *testing.T) {
	var sent []models.RRSet
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			// The backend returns the ORIGINAL casing of the RRSet.
			json.NewEncoder(w).Encode(map[string]any{
				"rrsets": []models.RRSet{
					{
						Name: "WWW.Example.COM.", Type: "A", TTL: 300,
						Records: []models.RecordInfo{{Content: "1.2.3.4"}},
					},
				},
			})
		case http.MethodPatch:
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
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
	ctx := context.Background()

	// The submission is the lowercased form, as ValidateRecordSet produces.
	rrset := models.RRSet{
		Name: "www.example.com.", Type: "A", TTL: 0,
		Records: []models.RecordInfo{{Content: "5.6.7.8"}},
	}
	if err := ValidateRecordSet(&rrset, "example.com."); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := s.CreateRecord(ctx, nil, "example.com.", rrset, SourceAPI); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	if len(sent) != 1 {
		t.Fatalf("expected exactly 1 PATCH rrset, got %+v", sent)
	}
	got := map[string]bool{}
	for _, rec := range sent[0].Records {
		got[rec.Content] = true
	}
	if !got["1.2.3.4"] || !got["5.6.7.8"] {
		t.Errorf("PATCH must merge into the case-variant RRSet and carry both the existing sibling and the new record; got %+v", got)
	}
	// The unspecified TTL inherits the existing RRSet's — on a missed
	// merge the default would apply instead.
	if sent[0].TTL != 300 {
		t.Errorf("TTL = %d, want 300 inherited from the existing RRSet", sent[0].TTL)
	}
}

// TestRRSetsMatch pins the case-insensitive RRSet identity: DNS names are
// case-insensitive, so name and type fold case — but the trailing dot is
// significant and must NOT be folded away.
func TestRRSetsMatch(t *testing.T) {
	cases := []struct {
		name         string
		aName, aType string
		bName, bType string
		want         bool
	}{
		{"exact equal", "www.example.com.", "A", "www.example.com.", "A", true},
		{"case-variant name", "WWW.Example.COM.", "A", "www.example.com.", "A", true},
		{"case-variant type", "www.example.com.", "srv", "www.example.com.", "SRV", true},
		{"different names", "www.example.com.", "A", "mail.example.com.", "A", false},
		{"different types", "www.example.com.", "A", "www.example.com.", "AAAA", false},
		// The trailing dot is significant: folding is case-only,
		// so a relative and an absolute name are NOT the same RRSet.
		{"trailing dot is significant", "www.example.com.", "A", "www.example.com", "A", false},
		// DNS folding is ASCII-only (RFC 4343): Unicode case mappings
		// must not merge distinct raw-UTF-8 names — the Kelvin sign
		// U+212A folds to ASCII 'k' under Unicode but is a different
		// DNS name on the wire.
		{"unicode folding must not apply", "\u212a.example.com.", "A", "k.example.com.", "A", false},
		{"unicode name folds only its ASCII letters", "\u212a.EXAMPLE.COM.", "A", "\u212a.example.com.", "A", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RRSetsMatch(c.aName, c.aType, c.bName, c.bType); got != c.want {
				t.Errorf("RRSetsMatch(%q, %q, %q, %q) = %v, want %v",
					c.aName, c.aType, c.bName, c.bType, got, c.want)
			}
		})
	}
}

// TestPrepareRecordContent_QuotedTypesPassThrough pins the validator↔codec
// parity for the quote-aware types: content accepted by ValidateRecordContent
// must survive PrepareRecordContent without error, and pre-quoted fields pass
// through byte-identical (the codec only escapes and wraps bare fields).
func TestPrepareRecordContent_QuotedTypesPassThrough(t *testing.T) {
	tests := []struct {
		name     string
		rtype    string
		content  string
		expected string // "" means byte-identical to the input
	}{
		{"HINFO quoted with spaces", "HINFO", `"Macintosh Plus" "MacOS"`, ""},
		{"HINFO bare tokens get wrapped", "HINFO", "pc intel", `"pc" "intel"`},
		{"CAA quoted value", "CAA", `0 issue "ca.example.net; account=123"`, ""},
		{"CAA bare value gets wrapped", "CAA", "0 issue letsencrypt.org", `0 issue "letsencrypt.org"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, prio, err := PrepareRecordContent(tt.rtype, tt.content, 0)
			if err != nil {
				t.Fatalf("PrepareRecordContent(%s, %q) failed: %v", tt.rtype, tt.content, err)
			}
			want := tt.expected
			if want == "" {
				want = tt.content
			}
			if content != want {
				t.Errorf("PrepareRecordContent(%s, %q) = %q, want %q", tt.rtype, tt.content, content, want)
			}
			if prio != 0 {
				t.Errorf("PrepareRecordContent(%s, %q) priority = %d, want 0", tt.rtype, tt.content, prio)
			}
		})
	}
}

// TestValidateRecordSet_TTLUpperBound pins the RFC 2181 §8 gate at the
// service layer: a TTL above 2147483647 is rejected before any PowerDNS call
// (the service accepted any non-negative int before), the exact maximum is
// accepted, and the legacy negative-TTL message is preserved verbatim.
func TestValidateRecordSet_TTLUpperBound(t *testing.T) {
	over := models.RRSet{
		Name: "www.example.com.", Type: "A", TTL: 2147483648,
		Records: []models.RecordInfo{{Content: "1.2.3.4"}},
	}
	err := ValidateRecordSet(&over, "example.com.")
	if err == nil {
		t.Fatal("ValidateRecordSet accepted TTL 2147483648 (above the RFC 2181 maximum)")
	}
	if !strings.Contains(err.Error(), "2147483647") {
		t.Errorf("error should mention the RFC 2181 maximum 2147483647, got: %v", err)
	}

	atMax := models.RRSet{
		Name: "www.example.com.", Type: "A", TTL: 2147483647,
		Records: []models.RecordInfo{{Content: "1.2.3.4"}},
	}
	if err := ValidateRecordSet(&atMax, "example.com."); err != nil {
		t.Errorf("ValidateRecordSet rejected the RFC 2181 maximum TTL 2147483647: %v", err)
	}

	negative := models.RRSet{
		Name: "www.example.com.", Type: "A", TTL: -1,
		Records: []models.RecordInfo{{Content: "1.2.3.4"}},
	}
	err = ValidateRecordSet(&negative, "example.com.")
	if err == nil || err.Error() != "ttl must be a non-negative integer" {
		t.Errorf("negative TTL must keep the legacy exact message, got: %v", err)
	}
}

// TestRRSetKey pins the canonical map key: both name and type lowercased,
// joined by the "|" separator.
func TestRRSetKey(t *testing.T) {
	cases := []struct {
		name, rtype string
		want        string
	}{
		{"WWW.Example.COM.", "A", "www.example.com.|a"},
		{"www.example.com.", "A", "www.example.com.|a"},
		{"Mail.Example.COM.", "MX", "mail.example.com.|mx"},
		{"www.example.com.", "SRV", "www.example.com.|srv"},
	}
	for _, c := range cases {
		t.Run(c.name+"/"+c.rtype, func(t *testing.T) {
			if got := RRSetKey(c.name, c.rtype); got != c.want {
				t.Errorf("RRSetKey(%q, %q) = %q, want %q", c.name, c.rtype, got, c.want)
			}
		})
	}
}

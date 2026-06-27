package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCommentPatch_MarshalJSON verifies the tri-state wire encoding that
// distinguishes "field absent" (preserve), "field present but empty" (purge)
// and "field present with items" (replace) on PowerDNS PATCH bodies.
//
// The per-item encoding always carries `account`, even when empty: see the
// doc comment on models.Comment for the rationale (PowerDNS stringFromJson
// throws on a missing `account` key, so the field must always be present).
func TestCommentPatch_MarshalJSON(t *testing.T) {
	cases := []struct {
		name  string
		patch *CommentPatch
		want  string
	}{
		{"nil_items_emit_null", &CommentPatch{}, "null"},
		{"clear_emit_empty_array", &CommentPatch{Clear: true}, "[]"},
		{"clear_overrides_items", &CommentPatch{Clear: true, Items: []Comment{{Content: "ignored"}}}, "[]"},
		{"non_empty_items", &CommentPatch{Items: []Comment{{Content: "x"}}}, `[{"content":"x","account":""}]`},
		{"multiple_items", &CommentPatch{Items: []Comment{{Content: "x"}, {Content: "y"}}}, `[{"content":"x","account":""},{"content":"y","account":""}]`},
		{"explicit_account_preserved", &CommentPatch{Items: []Comment{{Content: "x", Account: "alice"}}}, `[{"content":"x","account":"alice"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.patch)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("got %s, want %s", b, tc.want)
			}
		})
	}
}

// TestCommentPatch_NilPointerOmittedFromRRSet verifies that a nil *CommentPatch
// on an RRSet is omitted from the wire payload, so PowerDNS preserves the
// existing comments untouched.
func TestCommentPatch_NilPointerOmittedFromRRSet(t *testing.T) {
	rr := RRSet{Name: "n", Type: "A", TTL: 1, Records: []RecordInfo{{Content: "v"}}, Comments: nil}
	b, err := json.Marshal(rr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"comments"`) {
		t.Errorf("expected comments field to be omitted, got %s", b)
	}
}

// TestCommentPatch_UnmarshalJSON verifies that the round trip preserves the
// read-then-write semantics: both "null" and "[]" inputs normalise to a nil
// Items slice, and Clear is never set by unmarshalling.
//
// The "with_items" sub-case round-trips a comment without an `account` key
// (PDNS may still emit this for legacy entries created before the field was
// always required). GoZone accepts it as Account="" — the absence of the key
// is tolerated on read, but on write we always emit `"account":""` explicitly
// because PowerDNS rejects missing keys on PATCH.
func TestCommentPatch_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"null", `null`},
		{"empty_array", `[]`},
		{"with_items", `[{"content":"x"}]`},
		{"with_items_and_account", `[{"content":"x","account":"alice"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got CommentPatch
			if err := json.Unmarshal([]byte(tc.in), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Clear {
				t.Errorf("Clear must never be set by unmarshal, got Clear=true")
			}
			out, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			switch tc.name {
			case "null", "empty_array":
				if string(out) != "null" {
					t.Errorf("expected null round-trip, got %s", out)
				}
			case "with_items":
				// Input has no `account` key. Read tolerates it (Account="");
				// write emits it explicitly to keep PDNS happy.
				if string(out) != `[{"content":"x","account":""}]` {
					t.Errorf("expected account to be normalised to empty string on write, got %s", out)
				}
			case "with_items_and_account":
				if string(out) != tc.in {
					t.Errorf("expected %s round-trip, got %s", tc.in, out)
				}
			}
		})
	}
}

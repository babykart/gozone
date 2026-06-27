package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCommentPatch_MarshalJSON verifies the tri-state wire encoding that
// distinguishes "field absent" (preserve), "field present but empty" (purge)
// and "field present with items" (replace) on PowerDNS PATCH bodies.
func TestCommentPatch_MarshalJSON(t *testing.T) {
	cases := []struct {
		name  string
		patch *CommentPatch
		want  string
	}{
		{"nil_items_emit_null", &CommentPatch{}, "null"},
		{"clear_emit_empty_array", &CommentPatch{Clear: true}, "[]"},
		{"clear_overrides_items", &CommentPatch{Clear: true, Items: []Comment{{Content: "ignored"}}}, "[]"},
		{"non_empty_items", &CommentPatch{Items: []Comment{{Content: "x"}}}, `[{"content":"x"}]`},
		{"multiple_items", &CommentPatch{Items: []Comment{{Content: "x"}, {Content: "y"}}}, `[{"content":"x"},{"content":"y"}]`},
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
func TestCommentPatch_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"null", `null`},
		{"empty_array", `[]`},
		{"with_items", `[{"content":"x"}]`},
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
				if string(out) != tc.in {
					t.Errorf("expected %s round-trip, got %s", tc.in, out)
				}
			}
		})
	}
}

package dnsops

import "testing"

// TestIsValidZoneID pins the entry-point rejection predicate: dot-only ids
// and ids with empty labels are refused, while legitimate zone ids —
// including underscore zones and RFC 2317 slash delegations — pass.
func TestIsValidZoneID(t *testing.T) {
	cases := []struct {
		name  string
		zone  string
		valid bool
	}{
		{"empty", "", false},
		{"root dot only", ".", false},
		{"dot dot", "..", false},
		{"three dots", "...", false},
		{"empty inner label", "example..com.", false},
		{"empty leading label", ".example.com.", false},
		{"empty inner label no dot", "a..b", false},
		{"canonical zone", "example.com.", true},
		{"zone without trailing dot", "example.com", true},
		{"mixed case", "Example.COM.", true},
		{"underscore zone", "_dmarc.example.com.", true},
		{"rfc2317 slash zone", "0/25.2.0.192.in-addr.arpa.", true},
		{"localhost", "localhost.", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsValidZoneID(c.zone); got != c.valid {
				t.Errorf("IsValidZoneID(%q) = %v, want %v", c.zone, got, c.valid)
			}
		})
	}
}

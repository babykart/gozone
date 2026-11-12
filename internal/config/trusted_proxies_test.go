package config

import (
	"net/netip"
	"strings"
	"testing"
)

// TestParseTrustedProxies is the single-implementation home of the
// server.trusted_proxies parser: CIDR entries parse, and the frequent
// operator typos (a bare IPv4/IPv6, garbage) return an actionable error
// naming the 1-based entry index instead of the netip.MustParsePrefix panic
// this replaced.
func TestParseTrustedProxies(t *testing.T) {
	prefixes, err := ParseTrustedProxies([]string{"10.0.0.0/8", "192.0.2.1/32", "2001:db8::/48"})
	if err != nil {
		t.Fatalf("valid CIDR list: %v", err)
	}
	if len(prefixes) != 3 {
		t.Fatalf("expected 3 prefixes, got %d", len(prefixes))
	}
	if !prefixes[0].Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("10.0.0.0/8 must contain 10.1.2.3")
	}
	if !prefixes[1].Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Error("192.0.2.1/32 must contain 192.0.2.1")
	}
	if !prefixes[2].Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("2001:db8::/48 must contain 2001:db8::1 (IPv6 form accepted)")
	}

	empty, err := ParseTrustedProxies(nil)
	if err != nil || len(empty) != 0 {
		t.Errorf("empty list: prefixes=%v err=%v, want empty/nil", empty, err)
	}

	for _, bad := range []struct {
		entry string
		index string
	}{
		{"10.0.0.1", "entry 1"},
		{"2001:db8::1", "entry 1"},
		{"not-an-ip", "entry 1"},
		{"10.0.0.0/8,192.0.2.1/24", "entry 1"},
	} {
		_, err := ParseTrustedProxies([]string{bad.entry, "10.0.0.0/8"})
		if err == nil {
			t.Errorf("entry %q must be rejected", bad.entry)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "/32") || !strings.Contains(msg, bad.entry) {
			t.Errorf("error for %q should quote the entry and suggest the /32 form: %v", bad.entry, err)
		}
		if !strings.Contains(msg, bad.index) {
			t.Errorf("error for %q should name the 1-based index (%s): %v", bad.entry, bad.index, err)
		}
	}
}

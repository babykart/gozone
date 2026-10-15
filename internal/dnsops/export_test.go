package dnsops

import (
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
)

func TestRelativeBindName(t *testing.T) {
	cases := []struct{ name, origin, expected string }{
		{"www.example.com.", "example.com.", "www"},
		{"example.com.", "example.com.", "@"},
		{"mail.example.com.", "example.com.", "mail"},
		{"www.other.org.", "example.com.", "www.other.org."},
		{"example.com", "example.com.", "@"},
		{"www.example.com", "example.com.", "www"},
		{"sub.www.example.com.", "example.com.", "sub.www"},
	}
	for _, tc := range cases {
		if got := RelativeBindName(tc.name, tc.origin); got != tc.expected {
			t.Errorf("RelativeBindName(%q, %q) = %q, want %q", tc.name, tc.origin, got, tc.expected)
		}
	}
}

func TestFindSOATTL(t *testing.T) {
	if got := FindSOATTL(nil); got != 3600 {
		t.Errorf("no SOA: got %d, want 3600 default", got)
	}
	if got := FindSOATTL([]models.RRSet{{Type: "A", TTL: 60}}); got != 3600 {
		t.Errorf("no SOA record: got %d, want 3600 default", got)
	}
	if got := FindSOATTL([]models.RRSet{{Type: "SOA", TTL: 0}, {Type: "SOA", TTL: 7200}}); got != 7200 {
		t.Errorf("zero-TTL SOA must be skipped: got %d, want 7200", got)
	}
}

func TestFormatRecordContent(t *testing.T) {
	cases := []struct {
		rtype, content string
		priority       int
		expected       string
	}{
		{"MX", "mail.example.com", 10, "10 mail.example.com"},
		{"SRV", "10 5 5060 sip.example.com", 0, "0 5 5060 sip.example.com"},
		{"TXT", "hello", 0, `"hello"`},
		{"A", "192.0.2.1", 0, "192.0.2.1"},
	}
	for _, tc := range cases {
		if got := FormatRecordContent(tc.rtype, tc.content, tc.priority); got != tc.expected {
			t.Errorf("FormatRecordContent(%q, %q, %d) = %q, want %q", tc.rtype, tc.content, tc.priority, got, tc.expected)
		}
	}
}

func TestSortRRSets(t *testing.T) {
	records := []models.RRSet{
		{Name: "b.example.com.", Type: "A"},
		{Name: "example.com.", Type: "A"},
		{Name: "example.com.", Type: "NS"},
		{Name: "example.com.", Type: "SOA"},
		{Name: "a.example.com.", Type: "A"},
	}
	SortRRSets(records)
	want := []string{
		"example.com. SOA",
		"example.com. NS",
		"a.example.com. A",
		"b.example.com. A",
		"example.com. A",
	}
	for i, w := range want {
		got := records[i].Name + " " + records[i].Type
		if got != w {
			t.Fatalf("position %d: got %q, want %q (full: %v)", i, got, w, records)
		}
	}
}

func TestRenderZoneFile(t *testing.T) {
	zone := &models.Zone{ID: "example.com.", Name: "example.com.", Kind: "Native"}
	records := []models.RRSet{
		{Name: "www.example.com.", Type: "A", TTL: 3600, Records: []models.RecordInfo{
			{Content: "192.0.2.1"},
			{Content: "192.0.2.2", Disabled: true}, // skipped
		}},
		{Name: "example.com.", Type: "SOA", TTL: 3600, Records: []models.RecordInfo{
			{Content: "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600"},
		}},
		{Name: "example.com.", Type: "MX", TTL: 1800, Records: []models.RecordInfo{
			{Content: "mail.example.com.", Priority: 10},
		}},
		{Name: "txt.example.com.", Type: "TXT", TTL: 3600, Records: []models.RecordInfo{
			{Content: `"v=spf1 -all"`},
		}},
	}

	out := RenderZoneFile(zone, records)

	for want := range map[string]bool{
		"$ORIGIN example.com.\n":            true,
		"$TTL 3600\n":                       true,
		"@ IN SOA ns1":                      true,
		"@ 1800 IN MX 10 mail.example.com.": true,
		"www IN A 192.0.2.1\n":              true,
		"txt IN TXT \"v=spf1 -all\"\n":      true,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("zone file missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "192.0.2.2") {
		t.Errorf("disabled record must be omitted:\n%s", out)
	}
	if !strings.HasPrefix(out, "$ORIGIN example.com.\n$TTL 3600\n\n") {
		t.Errorf("header shape wrong:\n%q", out[:min(40, len(out))])
	}

	// Zone name without the trailing dot is normalised for $ORIGIN.
	out = RenderZoneFile(&models.Zone{Name: "example.com"}, records)
	if !strings.HasPrefix(out, "$ORIGIN example.com.\n") {
		t.Errorf("$ORIGIN must gain the trailing dot:\n%s", out)
	}
}

func TestRenderZoneFile_SkipsRecordsWhenAllDisabled(t *testing.T) {
	zone := &models.Zone{Name: "example.com."}
	records := []models.RRSet{
		{Name: "www.example.com.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "192.0.2.1", Disabled: true}}},
	}
	out := RenderZoneFile(zone, records)
	if strings.Contains(out, "192.0.2.1") {
		t.Errorf("disabled record must be omitted:\n%s", out)
	}
	if !strings.Contains(out, "$ORIGIN example.com.") {
		t.Errorf("header must still render:\n%s", out)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

package cmd

import (
	"net/url"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/handlers"
)

// TestPaginationPartial exercises the real pagination.html partial (the handler
// tests use stub templates), checking that prev/next links carry the other
// section's pagination state so record and activity-log pagination stay
// independent, that the single-section case (zone list) carries nothing, and
// that extra filter pairs (activity log: action/from/to) survive as separate,
// readable query parameters.
func TestPaginationPartial(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	// Two-section case (zone view records partial): must carry log params.
	var buf strings.Builder
	data := map[string]interface{}{
		"PageInfo":     handlers.PageInfo{Current: 2, PerPage: 10, TotalPages: 3, Total: 25},
		"Search":       "foo",
		"Label":        "records",
		"Prefix":       "",
		"HasOther":     true,
		"OtherPrefix":  "log",
		"OtherPage":    4,
		"OtherPerPage": 50,
	}
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", data); err != nil {
		t.Fatalf("execute records pagination: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Page=1", "PerPage=10", "search=foo", "logPage=4", "logPerPage=50", "Page=3"} {
		if !strings.Contains(out, want) {
			t.Errorf("records pagination output missing %q\n%s", want, out)
		}
	}

	// Single-section case (zones list): no HasOther -> no carry, must still render.
	buf.Reset()
	listData := map[string]interface{}{
		"PageInfo": handlers.PageInfo{Current: 1, PerPage: 10, TotalPages: 2, Total: 15},
		"Search":   "",
		"Label":    "zones",
		"Prefix":   "",
	}
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", listData); err != nil {
		t.Fatalf("execute list pagination: %v", err)
	}
	if strings.Contains(buf.String(), "logPage") {
		t.Errorf("list pagination must not carry other-section params:\n%s", buf.String())
	}

	// Filtered case (activity log): the extra pairs must land in the links
	// as separate, readable query parameters. The old pre-joined string was
	// escaped by html/template as one opaque value (action%3dlogin%26…),
	// silently dropping the filters on page navigation.
	buf.Reset()
	filterData := map[string]interface{}{
		"PageInfo": handlers.PageInfo{Current: 2, PerPage: 10, TotalPages: 3, Total: 25},
		"Search":   "",
		"Label":    "entries",
		"Prefix":   "",
		"Extra":    url.Values{"action": []string{"login"}, "from": []string{"2026-01-01"}},
	}
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", filterData); err != nil {
		t.Fatalf("execute filtered pagination: %v", err)
	}
	out = buf.String()
	for _, want := range []string{"action=login", "from=2026-01-01", "Page=1", "Page=3"} {
		if !strings.Contains(out, want) {
			t.Errorf("filtered pagination output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "%3d") || strings.Contains(out, "%26") {
		t.Errorf("filters must not be escaped into one opaque query value:\n%s", out)
	}
}

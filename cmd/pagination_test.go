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

	// Two-section group edit case (member pager): must carry the zone section
	// AND the dropdown searches (uq/zq) as separate, readable parameters.
	buf.Reset()
	groupData := map[string]interface{}{
		"PageInfo":     handlers.PageInfo{Current: 2, PerPage: 10, TotalPages: 3, Total: 25},
		"Label":        "members",
		"Prefix":       "member",
		"HasOther":     true,
		"OtherPrefix":  "zone",
		"OtherPage":    1,
		"OtherPerPage": 50,
		"Extra":        url.Values{"uq": []string{"ali"}, "zq": []string{"bet"}},
	}
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", groupData); err != nil {
		t.Fatalf("execute group pagination: %v", err)
	}
	out = buf.String()
	for _, want := range []string{"memberPage=1", "memberPage=3", "memberPerPage=10", "zonePage=1", "zonePerPage=50", "uq=ali", "zq=bet"} {
		if !strings.Contains(out, want) {
			t.Errorf("group pagination output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "%3d") || strings.Contains(out, "%26") {
		t.Errorf("dropdown searches must not be escaped into one opaque query value:\n%s", out)
	}
}

// TestPaginationPartial_AllCap exercises the AllCap-aware "All" option of the
// real pagination.html partial: when a caller passes AllCap (the zone view
// records pager), the last option offers the bounded "All (max N)" instead of
// the unbounded value="0" "All"; when AllCap is absent (every other page) the
// partial keeps the historical All option and behavior.
func TestPaginationPartial_AllCap(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	// Capped page (PerPage = AllCap): the bounded option is selected.
	var buf strings.Builder
	data := map[string]interface{}{
		"PageInfo": handlers.PageInfo{Current: 1, PerPage: 1000, TotalPages: 2, Total: 1005},
		"Search":   "",
		"Label":    "records",
		"Prefix":   "",
		"AllCap":   1000,
	}
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", data); err != nil {
		t.Fatalf("execute capped pagination: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`value="1000"`, "All (max 1000)", `value="1000" selected>All (max 1000)`} {
		if !strings.Contains(out, want) {
			t.Errorf("capped pagination output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, `value="0"`) {
		t.Errorf("capped pagination must not render the unbounded All option:\n%s", out)
	}

	// Uncapped page (no AllCap): the historical All option and behavior.
	buf.Reset()
	listData := map[string]interface{}{
		"PageInfo": handlers.PageInfo{Current: 1, PerPage: 10, TotalPages: 2, Total: 15},
		"Search":   "",
		"Label":    "zones",
		"Prefix":   "",
	}
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", listData); err != nil {
		t.Fatalf("execute uncapped pagination: %v", err)
	}
	out = buf.String()
	for _, want := range []string{`value="0"`, ">All</option>"} {
		if !strings.Contains(out, want) {
			t.Errorf("uncapped pagination output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "All (max") {
		t.Errorf("uncapped pagination must not render the bounded All option:\n%s", out)
	}

	// Capped selector showing a normal page size: the 10 option is selected
	// and the bounded All option is not.
	buf.Reset()
	data["PageInfo"] = handlers.PageInfo{Current: 1, PerPage: 10, TotalPages: 101, Total: 1005}
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", data); err != nil {
		t.Fatalf("execute capped small-page pagination: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, `value="10" selected`) {
		t.Errorf("capped small-page pagination must select the 10 option:\n%s", out)
	}
	if strings.Contains(out, `value="1000" selected`) {
		t.Errorf("capped small-page pagination must not select the All (max) option:\n%s", out)
	}
}

// controlElement extracts the full element (open tag through close tag) that
// renders the pagination control carrying the given visible label, e.g.
// "← Previous". It walks back from the label to its opening "<" and forward
// to the next "</...>" close tag.
func controlElement(t *testing.T, out, label string) string {
	t.Helper()
	labelIdx := strings.Index(out, ">"+label)
	if labelIdx < 0 {
		t.Fatalf("pagination output missing control label %q:\n%s", label, out)
	}
	start := strings.LastIndex(out[:labelIdx], "<")
	closeRel := strings.Index(out[labelIdx:], "</")
	if closeRel < 0 {
		t.Fatalf("pagination control %q has no closing tag:\n%s", label, out)
	}
	gtRel := strings.Index(out[labelIdx+closeRel:], ">")
	if gtRel < 0 {
		t.Fatalf("pagination control %q has malformed closing tag:\n%s", label, out)
	}
	end := labelIdx + closeRel + gtRel + 1
	return out[start:end]
}

// TestPaginationPartial_BoundaryAccessibility exercises the real
// pagination.html partial's Previous / Next boundary rendering: at the first
// or last page the boundary control must be a non-focusable
// <span aria-disabled="true" class="btn btn-sm btn-secondary disabled">
// (no href), and only that control may carry aria-disabled; on a middle page
// both controls stay plain links with no aria-disabled anywhere.
func TestPaginationPartial_BoundaryAccessibility(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	render := func(current int) string {
		t.Helper()
		var buf strings.Builder
		data := map[string]interface{}{
			"PageInfo": handlers.PageInfo{Current: current, PerPage: 10, TotalPages: 3, Total: 25},
			"Search":   "",
			"Label":    "records",
			"Prefix":   "",
		}
		if err := tmpl.ExecuteTemplate(&buf, "pagination.html", data); err != nil {
			t.Fatalf("execute pagination (Current=%d): %v", current, err)
		}
		return buf.String()
	}

	// First page: Previous is the disabled span (no href), Next is a link.
	out := render(1)
	prev := controlElement(t, out, "← Previous")
	if !strings.HasPrefix(prev, `<span aria-disabled="true"`) {
		t.Errorf("first-page Previous must be <span aria-disabled=\"true\"...>, got:\n%s", prev)
	}
	if !strings.Contains(prev, "disabled") {
		t.Errorf("first-page Previous span must keep the disabled class:\n%s", prev)
	}
	if strings.Contains(prev, "href") {
		t.Errorf("first-page Previous span must not carry an href (stays focusable otherwise):\n%s", prev)
	}
	next := controlElement(t, out, "Next →")
	if !strings.HasPrefix(next, "<a href=") {
		t.Errorf("first-page Next must stay an <a href=...> link, got:\n%s", next)
	}
	if !strings.Contains(next, "Page=2") {
		t.Errorf("first-page Next link must point at Page=2:\n%s", next)
	}
	if strings.Contains(next, "aria-disabled") {
		t.Errorf("first-page Next link must not carry aria-disabled:\n%s", next)
	}
	if n := strings.Count(out, "aria-disabled"); n != 1 {
		t.Errorf("first-page output must contain exactly one aria-disabled (got %d):\n%s", n, out)
	}

	// Last page: mirrored — Next is the disabled span, Previous is a link.
	out = render(3)
	next = controlElement(t, out, "Next →")
	if !strings.HasPrefix(next, `<span aria-disabled="true"`) {
		t.Errorf("last-page Next must be <span aria-disabled=\"true\"...>, got:\n%s", next)
	}
	if !strings.Contains(next, "disabled") {
		t.Errorf("last-page Next span must keep the disabled class:\n%s", next)
	}
	if strings.Contains(next, "href") {
		t.Errorf("last-page Next span must not carry an href (stays focusable otherwise):\n%s", next)
	}
	prev = controlElement(t, out, "← Previous")
	if !strings.HasPrefix(prev, "<a href=") {
		t.Errorf("last-page Previous must stay an <a href=...> link, got:\n%s", prev)
	}
	if !strings.Contains(prev, "Page=2") {
		t.Errorf("last-page Previous link must point at Page=2:\n%s", prev)
	}
	if strings.Contains(prev, "aria-disabled") {
		t.Errorf("last-page Previous link must not carry aria-disabled:\n%s", prev)
	}
	if n := strings.Count(out, "aria-disabled"); n != 1 {
		t.Errorf("last-page output must contain exactly one aria-disabled (got %d):\n%s", n, out)
	}

	// Middle page: no disabled control at all, both are plain links.
	out = render(2)
	if n := strings.Count(out, "aria-disabled"); n != 0 {
		t.Errorf("middle-page output must contain no aria-disabled (got %d):\n%s", n, out)
	}
	prev = controlElement(t, out, "← Previous")
	if !strings.HasPrefix(prev, "<a href=") || !strings.Contains(prev, "Page=1") {
		t.Errorf("middle-page Previous must be a link to Page=1, got:\n%s", prev)
	}
	next = controlElement(t, out, "Next →")
	if !strings.HasPrefix(next, "<a href=") || !strings.Contains(next, "Page=3") {
		t.Errorf("middle-page Next must be a link to Page=3, got:\n%s", next)
	}
}

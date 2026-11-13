package cmd

import (
	"html"
	"strings"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/models"
)

// TestActivityTemplate_ChangeRowFullWidth renders the REAL activity.html (the
// handler tests use stub templates) and locks the layout contract of the
// "View change" diff: the Before/After panels live in a dedicated full-width
// row (colspan=5) that starts hidden, toggled by a data-action button — so
// opening a change never re-flows the ACTION/ZONE/USER/TIME columns the old
// in-cell <details> squeezed. Entries without old/new values get no toggle
// and no change row at all.
func TestActivityTemplate_ChangeRowFullWidth(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	zone := "example.com."
	logs := []models.ActivityLog{
		{
			ID:        7,
			Action:    "update_record",
			Details:   "Updated A record",
			OldValue:  `{"ttl":3600}`,
			NewValue:  `{"ttl":600}`,
			ZoneID:    &zone,
			Username:  "alice",
			CreatedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
		},
		{
			ID:        8,
			Action:    "login",
			Details:   "User logged in",
			Username:  "alice",
			CreatedAt: time.Date(2026, 11, 12, 11, 0, 0, 0, time.UTC),
		},
		{
			ID:        9,
			Action:    "delete_record",
			Details:   "Deleted record",
			OldValue:  `{"ttl":900}`,
			ZoneID:    &zone,
			Username:  "bob",
			CreatedAt: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC),
		},
		{
			ID:        10,
			Action:    "create_record",
			Details:   "Created record",
			NewValue:  `{"ttl":300}`,
			ZoneID:    &zone,
			Username:  "bob",
			CreatedAt: time.Date(2026, 11, 12, 13, 0, 0, 0, time.UTC),
		},
	}
	data := map[string]interface{}{
		"Title":          "Activity",
		"User":           &models.User{ID: 1, Username: "alice", Role: "admin"},
		"CSRFToken":      "csrf-token",
		"Search":         "",
		"Action":         "",
		"From":           "",
		"To":             "",
		"Actions":        []string{},
		"Logs":           logs,
		"FilterWarnings": []string{},
		"PageInfo":       handlers.PageInfo{Current: 1, PerPage: 10, TotalPages: 1, Total: len(logs)},
		"Extra":          map[string][]string{},
		"Truncated":      false,
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "activity.html", data); err != nil {
		t.Fatalf("execute activity.html: %v", err)
	}
	out := buf.String()

	// The change row is a sibling of the log row, start-hidden, spanning all
	// five columns of the auto-layout table.
	for _, want := range []string{
		`<tr class="activity-change-row hidden" id="activity-change-7">`,
		`data-action="toggle-activity-change"`,
		`aria-expanded="false"`,
		`aria-controls="activity-change-7"`,
		`>Before<`,
		`>After<`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered activity.html must contain %q", want)
		}
	}

	// html/template escapes the JSON payloads inside <pre>; assert the
	// escaped wire form so the test does not depend on template internals.
	for _, payload := range []string{`{"ttl":3600}`, `{"ttl":600}`} {
		if !strings.Contains(out, html.EscapeString(payload)) {
			t.Errorf("rendered activity.html must contain the diff payload %q", payload)
		}
	}

	if n := strings.Count(out, `colspan="5"`); n != 3 {
		t.Errorf("expected one colspan=5 change row per value-carrying entry (7, 9, 10), got %d", n)
	}

	// The native in-cell <details> diff is gone — it re-flowed the table.
	if strings.Contains(out, "<details") {
		t.Error("rendered activity.html must not contain a <details> element anymore")
	}

	// Entry B (login, no old/new values) gets no toggle and no change row.
	if strings.Contains(out, "activity-change-8") {
		t.Error("an entry without old/new values must not render a change row or toggle")
	}

	// The change row must FOLLOW its log row, never precede it.
	logIdx := strings.Index(out, "Updated A record")
	rowIdx := strings.Index(out, `id="activity-change-7"`)
	if logIdx == -1 || rowIdx == -1 {
		t.Fatalf("log row or change row missing (logIdx=%d, rowIdx=%d)", logIdx, rowIdx)
	}
	if logIdx > rowIdx {
		t.Errorf("change row (idx %d) must come after its log row (idx %d)", rowIdx, logIdx)
	}

	// One-sided diffs render only their panel: OldValue-only entries (7, 9)
	// produce the removed panel, NewValue-only (7, 10) the added one.
	if n := strings.Count(out, `diff-panel diff-removed`); n != 2 {
		t.Errorf("expected 2 removed panels (entries 7 and 9), got %d", n)
	}
	if n := strings.Count(out, `diff-panel diff-added`); n != 2 {
		t.Errorf("expected 2 added panels (entries 7 and 10), got %d", n)
	}
}

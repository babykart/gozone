package cmd

import (
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/models"
)

// zoneViewTestData builds the minimal data map the real zone_view.html
// executes against, with one DNSSEC cryptokey so the actions column renders.
func zoneViewTestData(isAdmin bool) map[string]interface{} {
	return map[string]interface{}{
		"Title":     "Zone",
		"User":      &models.User{ID: 1, Username: "viewer", Role: "user"},
		"CSRFToken": "csrf-token",
		"Zone":      models.Zone{ID: "example.com.", Name: "example.com.", Kind: "Native"},
		"Search":    "",
		"Records":   []handlers.ZoneRecordRow{},
		"RecordPageInfo": handlers.PageInfo{
			Current: 1, PerPage: 10, TotalPages: 1, Total: 0,
		},
		"LogPageInfo": handlers.PageInfo{
			Current: 1, PerPage: 10, TotalPages: 1, Total: 0,
		},
		"IsAdmin": isAdmin,
		"Cryptokeys": []models.Cryptokey{
			{ID: 7, KeyType: "ksk", Algorithm: "ECDSAP256SHA256", Bits: 256, Active: true, DS: []string{"6454 8 2 abcdef"}},
		},
	}
}

// TestZoneView_DNSSECActionsAdminGated renders the REAL zone_view.html (the
// handler tests use stub templates) and locks the property that the
// Activate/Deactivate and Delete DNSSEC actions are only offered to admins:
// the routes require the admin role, so a non-admin must never see a form
// that can only be refused.
func TestZoneView_DNSSECActionsAdminGated(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "zone_view.html", zoneViewTestData(false)); err != nil {
		t.Fatalf("execute zone_view (non-admin): %v", err)
	}
	out := buf.String()
	// The key itself is visible to any zone viewer…
	if !strings.Contains(out, "ECDSAP256SHA256") {
		t.Fatalf("the cryptokey row must render for a zone viewer:\n%s", out)
	}
	// …but none of its action forms are.
	for _, forbidden := range []string{"/cryptokeys/7/toggle", "/cryptokeys/7/delete", ">Activate<", ">Deactivate<", ">Delete<"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("non-admin view must not offer DNSSEC action %q", forbidden)
		}
	}

	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "zone_view.html", zoneViewTestData(true)); err != nil {
		t.Fatalf("execute zone_view (admin): %v", err)
	}
	out = buf.String()
	for _, want := range []string{"/cryptokeys/7/toggle", "/cryptokeys/7/delete", ">Deactivate<"} {
		if !strings.Contains(out, want) {
			t.Errorf("admin view must offer DNSSEC action %q", want)
		}
	}
}

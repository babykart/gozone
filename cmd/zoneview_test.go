package cmd

import (
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/models"
)

// zoneViewTestData builds the minimal data map the real zone_view.html
// executes against, with one DNSSEC cryptokey so the actions column renders.
// canManageDNS mirrors the render() injection: same value as IsAdmin for
// admin/user data, and the distinguishing flag for the operator role
// (CanManageDNS=true, IsAdmin=false).
func zoneViewTestData(isAdmin, canManageDNS bool) map[string]interface{} {
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
		"IsAdmin":      isAdmin,
		"CanManageDNS": canManageDNS,
		"Cryptokeys": []models.Cryptokey{
			{ID: 7, KeyType: "ksk", Algorithm: "ECDSAP256SHA256", Bits: 256, Active: true, DS: []string{"6454 8 2 abcdef"}},
		},
	}
}

// TestZoneView_DNSSECActionsAdminGated renders the REAL zone_view.html (the
// handler tests use stub templates) and locks the property that the
// Activate/Deactivate and Delete DNSSEC actions are only offered to users
// with DNS-admin rights (admins and operators): the routes are gated by
// RequireDNSAdmin, so a user without DNS-admin rights must never see a form
// that can only be refused.
func TestZoneView_DNSSECActionsAdminGated(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "zone_view.html", zoneViewTestData(false, false)); err != nil {
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
	if err := tmpl.ExecuteTemplate(&buf, "zone_view.html", zoneViewTestData(true, true)); err != nil {
		t.Fatalf("execute zone_view (admin): %v", err)
	}
	out = buf.String()
	for _, want := range []string{"/cryptokeys/7/toggle", "/cryptokeys/7/delete", ">Deactivate<"} {
		if !strings.Contains(out, want) {
			t.Errorf("admin view must offer DNSSEC action %q", want)
		}
	}
}

// TestZoneView_DNSSECActionsOperatorCanManage extends the DNSSEC-gating lock
// to the operator role: an operator (CanManageDNS=true, IsAdmin=false) must
// see the per-key Activate/Deactivate and Delete actions — the underlying
// routes are DNS operations the role manages — and has full DNS parity in the
// danger zone too (cache clear, rectify, notify, zone deletion): those routes
// are RequireDNSAdmin-gated server-side, so the operator must see their
// forms. Only the admin-only Users/Groups surfaces stay out of reach.
func TestZoneView_DNSSECActionsOperatorCanManage(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "zone_view.html", zoneViewTestData(false, true)); err != nil {
		t.Fatalf("execute zone_view (operator): %v", err)
	}
	out := buf.String()
	// The key itself is visible to any zone viewer…
	if !strings.Contains(out, "ECDSAP256SHA256") {
		t.Fatalf("the cryptokey row must render for an operator:\n%s", out)
	}
	// …and its management actions must be offered to an operator.
	for _, want := range []string{"/cryptokeys/7/toggle", "/cryptokeys/7/delete", ">Deactivate<"} {
		if !strings.Contains(out, want) {
			t.Errorf("operator view must offer DNSSEC action %q (CanManageDNS=true, IsAdmin=false)", want)
		}
	}
	// Full DNS parity: the danger-zone operations are DNS operations too and
	// the RequireDNSAdmin routes gate them server-side — the operator must
	// see the delete-zone form, not be shielded from it.
	for _, want := range []string{"/zones/delete", ">Delete Zone<"} {
		if !strings.Contains(out, want) {
			t.Errorf("operator view must offer DNS action %q (CanManageDNS=true, IsAdmin=false)", want)
		}
	}
}

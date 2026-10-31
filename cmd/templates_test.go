package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/babykart/gozone/web"
)

func TestParseTemplates(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates failed: %v", err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil template")
	}
}

func TestStaticAssetVersion(t *testing.T) {
	// Cache-busting regression guard: the asset version is a short content hash
	// of the bundled JS/CSS so a new deployment busts the browser cache via
	// ?v=… despite the 24h max-age served by fileServer.
	got := staticAssetVersion()
	if len(got) != 16 { // first 8 bytes of SHA-256, hex-encoded
		t.Fatalf("expected a 16-hex-char content hash, got %q (len %d)", got, len(got))
	}
	// Determinism: the version must match an independent computation over the
	// same embedded bytes.
	h := sha256.New()
	for _, name := range []string{"static/js/theme.js", "static/js/app.js", "static/css/style.css"} {
		data, err := web.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		h.Write(data)
	}
	want := hex.EncodeToString(h.Sum(nil)[:8])
	if got != want {
		t.Errorf("asset version = %q, want %q", got, want)
	}
}

func TestAssetVersionRenderedInTemplates(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	data := map[string]interface{}{"Title": "x"}

	var head strings.Builder
	if err := tmpl.ExecuteTemplate(&head, "head", data); err != nil {
		t.Fatalf("execute head: %v", err)
	}
	if !strings.Contains(head.String(), "/static/css/style.css?v=") {
		t.Errorf("head partial missing cache-busted style.css:\n%s", head.String())
	}
	// FOUC fix: theme.js runs synchronously in <head> so the persisted colour
	// theme is applied before the body paints.
	if !strings.Contains(head.String(), "/static/js/theme.js?v=") {
		t.Errorf("head partial missing cache-busted theme.js:\n%s", head.String())
	}

	var tail strings.Builder
	if err := tmpl.ExecuteTemplate(&tail, "tail", data); err != nil {
		t.Fatalf("execute tail: %v", err)
	}
	if !strings.Contains(tail.String(), "/static/js/app.js?v=") {
		t.Errorf("tail partial missing cache-busted app.js:\n%s", tail.String())
	}
}

func TestSkipLinkAndMainAnchor(t *testing.T) {
	// Accessibility requirement: every authenticated page must expose a
	// skip-to-content link as the first focusable element and a focusable main
	// landmark it targets, so keyboard users can jump past the sidebar/topbar.
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	data := map[string]interface{}{
		"Title":     "Test",
		"AppName":   "GoZone",
		"Section":   "dashboard",
		"IsAdmin":   true,
		"CSRFToken": "tok",
		"User":      map[string]interface{}{"Username": "admin"},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "app_layout_start", data); err != nil {
		t.Fatalf("execute app_layout_start: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="skip-link"`) || !strings.Contains(out, `href="#main-content"`) {
		t.Errorf("missing skip-to-content link:\n%s", out)
	}
	if !strings.Contains(out, `id="main-content"`) {
		t.Errorf("main landmark missing id=\"main-content\":\n%s", out)
	}
	// No-JS degradation notice: the JS-only features (bulk selection, inline
	// record editing, confirm dialogs) must be announced to users browsing
	// without JavaScript.
	if !strings.Contains(out, "<noscript>") || !strings.Contains(out, "JavaScript is disabled") {
		t.Errorf("app_layout_start missing the noscript notice:\n%s", out)
	}
}

// TestSidebarLinksOperatorCanManageDNS locks the operator-role sidebar split:
// with CanManageDNS=true and IsAdmin=false the TSIG Keys link (a DNS
// management surface) must render, while the admin-only Users and Groups
// links stay hidden.
func TestSidebarLinksOperatorCanManageDNS(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	data := map[string]interface{}{
		"Title":        "Test",
		"AppName":      "GoZone",
		"Section":      "tsigkeys",
		"IsAdmin":      false,
		"CanManageDNS": true,
		"CSRFToken":    "tok",
		"User":         map[string]interface{}{"Username": "operator"},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "app_layout_start", data); err != nil {
		t.Fatalf("execute app_layout_start (operator): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `href="/tsigkeys"`) {
		t.Errorf("operator sidebar must include the TSIG Keys link:\n%s", out)
	}
	for _, forbidden := range []string{`href="/users"`, `href="/groups"`} {
		if strings.Contains(out, forbidden) {
			t.Errorf("operator sidebar must not include admin-only link %s", forbidden)
		}
	}
}

func TestProfilePageLinksChangePassword(t *testing.T) {
	// The self-service change-password form (/change-password) is mounted in
	// the authenticated group — not behind RequireAdmin — but without a link
	// on the profile page a non-admin has no visible path to it: /users is
	// admin-only and the dashboard banner only renders inside the
	// expiry_warn_days window (default 0 = never).
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	data := map[string]interface{}{
		"Title":     "Test",
		"AppName":   "GoZone",
		"Section":   "profile",
		"IsAdmin":   false,
		"CSRFToken": "tok",
		"User": map[string]interface{}{
			"Username":  "alice",
			"Email":     "alice@example.com",
			"FirstName": "Alice",
			"LastName":  "Doe",
			"Role":      "user",
			"CreatedAt": "2026-01-01",
		},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "profile.html", data); err != nil {
		t.Fatalf("execute profile.html: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `href="/change-password"`) {
		t.Errorf("profile.html missing the /change-password link:\n%s", out)
	}
}

func TestAppJSNoNativeConfirm(t *testing.T) {
	// Accessibility regression guard: blocking window.confirm() must be gone in
	// favour of the custom confirmDialog modal. "confirm(" is not a substring of
	// confirmDialog( / closeConfirmDialog(, so a Contains check reliably guards
	// against a revert.
	js, err := web.FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	if strings.Contains(string(js), "confirm(") {
		t.Error("app.js must not call the native window.confirm(); use confirmDialog() instead (blocking confirm() regression)")
	}
}

// TestTemplateFuncMap_Dict covers the dict template helper's error branches,
// which template rendering alone cannot reach (a template calling dict with
// odd arguments or non-string keys fails at parse time, so the runtime error
// paths are only exercisable by calling the function directly).
func TestTemplateFuncMap_Dict(t *testing.T) {
	fm := templateFuncMap("testv")
	dict, ok := fm["dict"].(func(...interface{}) (map[string]interface{}, error))
	if !ok {
		t.Fatal("dict func missing from the FuncMap")
	}

	got, err := dict("k1", "v1", "k2", 42)
	if err != nil {
		t.Fatalf("dict: %v", err)
	}
	if got["k1"] != "v1" || got["k2"] != 42 {
		t.Errorf("dict = %#v, want k1=v1 k2=42", got)
	}

	if _, err := dict("k1", "v1", "odd"); err == nil {
		t.Error("odd argument count: expected an error")
	}
	if _, err := dict(123, "v1"); err == nil {
		t.Error("non-string key: expected an error")
	}
}

// TestRelativeName is the unit test for the relativeName template func (m2):
// it covers the apex, sub-domains, case-insensitivity, the dot-boundary guard,
// and the missing-trailing-dot edge case that previously returned "" for apex.
func TestRelativeName(t *testing.T) {
	tests := []struct {
		name       string
		recordName string
		zoneName   string
		want       string
	}{
		// Apex with trailing dot on both sides.
		{"apex both dotted", "example.com.", "example.com.", "@"},
		// Apex without trailing dot on zone name — the main m2 bug: returned "" before.
		{"apex zone undotted", "example.com.", "example.com", "@"},
		// Sub-domain, single label.
		{"single label", "www.example.com.", "example.com.", "www"},
		// Sub-domain, single label, zone undotted.
		{"single label zone undotted", "www.example.com.", "example.com", "www"},
		// Sub-domain, multiple labels.
		{"multi label", "a.b.example.com.", "example.com.", "a.b"},
		// Case-insensitivity (DNS names are).
		{"uppercase record", "WWW.Example.COM.", "example.com.", "WWW"},
		{"uppercase zone", "www.example.com.", "EXAMPLE.COM", "www"},
		{"mixed case both", "MaIl.ExAmPlE.cOm.", "ExAmPle.Com", "MaIl"},
		// Dot-boundary guard: "notexample.com." is NOT a subdomain of "example.com.".
		{"prefix without dot boundary", "notexample.com.", "example.com.", "notexample.com."},
		// Record outside the zone entirely.
		{"other zone", "www.other.com.", "example.com.", "www.other.com."},
		// Root-level zone (".") edge case.
		{"root zone apex", ".", ".", "@"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relativeName(tt.recordName, tt.zoneName)
			if got != tt.want {
				t.Errorf("relativeName(%q, %q) = %q, want %q",
					tt.recordName, tt.zoneName, got, tt.want)
			}
		})
	}
}

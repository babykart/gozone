package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_AllPresent(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)

	tests := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"},
	}
	for _, tt := range tests {
		got := w.Header().Get(tt.header)
		if got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.header, got, tt.want)
		}
	}

	// m39: X-XSS-Protection is deprecated (buggy Auditor, removed from modern
	// browsers) and must not be emitted. The strong CSP is the real mitigation.
	if xss := w.Header().Get("X-XSS-Protection"); xss != "" {
		t.Errorf("X-XSS-Protection must not be set (deprecated, m39), got %q", xss)
	}

	if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS must not be set on plain HTTP, got %q", hsts)
	}
}

func TestSecurityHeaders_HSTSOnTLS(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	handler.ServeHTTP(w, r)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS must be set on TLS connection")
	}
	if hsts != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS: got %q, want %q", hsts, "max-age=31536000; includeSubDomains")
	}
}

// TestSecurityHeaders_HSTSWhenResolverSetsHTTPS verifies that SecurityHeaders
// emits HSTS when the HTTPS resolver (trusted-proxy-gated, m40) has stashed a
// positive decision. SecurityHeaders delegates to IsHTTPS, which reads the
// resolver's context value — NOT a raw client header.
func TestSecurityHeaders_HSTSWhenResolverSetsHTTPS(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Simulate the resolver having validated X-Forwarded-Proto behind a trusted proxy.
	r = WithHTTPS(r, true)
	handler.ServeHTTP(w, r)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS must be set when the resolver stashed HTTPS=true")
	}
}

// TestSecurityHeaders_NoHSTSForBareXFP is the m40 regression test: a bare
// X-Forwarded-Proto header with NO resolver in the stack MUST NOT trigger HSTS.
// Before m40, IsHTTPS honoured the header unconditionally, so a direct-access
// attacker over plain HTTP could inject it to pin HSTS.
func TestSecurityHeaders_NoHSTSForBareXFP(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https") // spoofable client header, no resolver
	handler.ServeHTTP(w, r)

	if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS must NOT be set for a bare X-Forwarded-Proto without the resolver (m40), got %q", hsts)
	}
}

func TestSecurityHeaders_PassesThroughStatusCode(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTeapot {
		t.Errorf("expected 418, got %d", w.Code)
	}
}

// TestSecurityHeaders_CSPHardenedDirectives verifies that the CSP includes the
// hardening directives added in m38: object-src 'none', base-uri 'self',
// frame-ancestors 'none', form-action 'self'. Each is checked individually so
// the test pinpoints which directive regressed.
func TestSecurityHeaders_CSPHardenedDirectives(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}

	// Parse the CSP into a map of directive -> raw value for precise checks.
	directives := map[string]string{}
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		name := fields[0]
		directives[name] = strings.Join(fields[1:], " ")
	}

	required := []struct {
		directive string
		want      string
	}{
		{"object-src", "'none'"},
		{"base-uri", "'self'"},
		{"frame-ancestors", "'none'"},
		{"form-action", "'self'"},
	}
	for _, tt := range required {
		got, ok := directives[tt.directive]
		if !ok {
			t.Errorf("CSP missing directive %q (full CSP: %q)", tt.directive, csp)
			continue
		}
		if got != tt.want {
			t.Errorf("CSP %q: got %q, want %q", tt.directive, got, tt.want)
		}
	}
}

// TestIsHTTPS verifies the resolution order of IsHTTPS (m40): r.TLS wins;
// otherwise the resolver-stashed context value is used; otherwise fail-closed
// to false. IsHTTPS no longer reads X-Forwarded-Proto directly — that decision
// is the resolver's job (gated on RemoteAddr ∈ trustedProxies), so a bare
// header is ignored here.
func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		name  string
		tls   bool
		xfp   string // raw X-Forwarded-Proto set on the request (must be IGNORED)
		stash *bool  // resolver-set context value; nil = no resolver ran
		want  bool
	}{
		{"direct TLS", true, "", nil, true},
		{"TLS wins even when resolver said false", true, "", boolPtr(false), true},
		{"plain HTTP, no resolver → fail-closed false", false, "", nil, false},
		{"resolver stashed true → true", false, "", boolPtr(true), true},
		{"resolver stashed false → false", false, "", boolPtr(false), false},
		{"bare XFP header without resolver → ignored (m40)", false, "https", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", tt.xfp)
			}
			if tt.stash != nil {
				r = WithHTTPS(r, *tt.stash)
			}
			if got := IsHTTPS(r); got != tt.want {
				t.Errorf("IsHTTPS() = %v, want %v (tls=%v, xfp=%q, stash=%v)", got, tt.want, tt.tls, tt.xfp, tt.stash)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

// TestForwardedProtoIsHTTPS covers the multi-hop-aware X-Forwarded-Proto
// parsing (m6) now that the logic lives in ForwardedProtoIsHTTPS — the value
// parser the resolver uses AFTER its RemoteAddr ∈ trustedProxies gate (m40).
func TestForwardedProtoIsHTTPS(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"empty", "", false},
		{"single hop https", "https", true},
		{"single hop http", "http", false},
		{"multi-hop https then http", "https, http", true},
		{"multi-hop http then https", "http, https", false},
		{"uppercase HTTPS", "HTTPS", true},
		{"whitespace around value", " https , http ", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ForwardedProtoIsHTTPS(tt.header); got != tt.want {
				t.Errorf("ForwardedProtoIsHTTPS(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

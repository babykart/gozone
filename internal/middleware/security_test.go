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

func TestSecurityHeaders_HSTSOnForwardedProto(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	handler.ServeHTTP(w, r)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS must be set when X-Forwarded-Proto is https")
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

// TestIsHTTPS verifies that IsHTTPS handles direct TLS, single-hop proxies,
// and multi-hop chains where X-Forwarded-Proto is comma-separated (m6).
func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		name  string
		tls   bool
		proto string
		want  bool
	}{
		{"direct TLS", true, "", true},
		{"plain HTTP no header", false, "", false},
		{"single hop https", false, "https", true},
		{"single hop http", false, "http", false},
		{"multi-hop https then http", false, "https, http", true},
		{"multi-hop http then https", false, "http, https", false},
		{"uppercase HTTPS", false, "HTTPS", true},
		{"whitespace around value", false, " https , http ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.proto != "" {
				r.Header.Set("X-Forwarded-Proto", tt.proto)
			}
			if got := IsHTTPS(r); got != tt.want {
				t.Errorf("IsHTTPS() = %v, want %v (proto=%q, tls=%v)", got, tt.want, tt.proto, tt.tls)
			}
		})
	}
}

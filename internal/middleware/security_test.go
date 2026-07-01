package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
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
		{"X-XSS-Protection", "1; mode=block"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"},
	}
	for _, tt := range tests {
		got := w.Header().Get(tt.header)
		if got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.header, got, tt.want)
		}
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

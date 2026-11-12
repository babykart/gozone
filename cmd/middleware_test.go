package cmd

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/middleware"
)

// mustTrustedProxies parses CIDR entries for the resolver tests, failing the
// test on a malformed fixture (production code validates via
// config.ParseTrustedProxies and returns the error through runServer).
func mustTrustedProxies(t *testing.T, entries ...string) []netip.Prefix {
	t.Helper()
	prefixes, err := config.ParseTrustedProxies(entries)
	if err != nil {
		t.Fatalf("fixture parse: %v", err)
	}
	return prefixes
}

// TestClientIPMiddleware_TrustedProxyHonorsXFF verifies that when the direct
// TCP connection (RemoteAddr) arrives from a configured trusted proxy, the
// X-Forwarded-For header is honoured and the real client IP is resolved.
func TestClientIPMiddleware_TrustedProxyHonorsXFF(t *testing.T) {
	trusted := []string{"10.0.0.0/8"}
	prefixes := mustTrustedProxies(t, trusted...)

	mw := clientIPMiddleware(trusted, prefixes)
	var resolved string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved = chimw.GetClientIP(r.Context())
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Connection from a trusted proxy (10.x) with a spoofed-looking XFF chain.
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	handler.ServeHTTP(w, r)

	if resolved != "203.0.113.9" {
		t.Errorf("trusted-proxy connection: expected client IP from XFF %q, got %q", "203.0.113.9", resolved)
	}
}

// TestClientIPMiddleware_UntrustedRemoteAddrIgnoresXFF is the M-SEC4
// regression test: when RemoteAddr is NOT a trusted proxy, XFF must be
// ignored entirely so a direct-access attacker cannot rotate rate-limit
// buckets by injecting X-Forwarded-For.
func TestClientIPMiddleware_UntrustedRemoteAddrIgnoresXFF(t *testing.T) {
	trusted := []string{"10.0.0.0/8"}
	prefixes := mustTrustedProxies(t, trusted...)

	mw := clientIPMiddleware(trusted, prefixes)
	var resolved string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved = chimw.GetClientIP(r.Context())
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Direct connection from an untrusted IP with a forged XFF header.
	r.RemoteAddr = "198.51.100.7:54321"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	handler.ServeHTTP(w, r)

	if resolved != "198.51.100.7" {
		t.Errorf("untrusted direct connection: expected RemoteAddr %q, got %q (XFF spoofing regression — M-SEC4)",
			"198.51.100.7", resolved)
	}
}

// TestClientIPMiddleware_NoTrustedProxiesUsesRemoteAddr verifies that with no
// trusted_proxies configured, XFF is always ignored (existing behaviour).
func TestClientIPMiddleware_NoTrustedProxiesUsesRemoteAddr(t *testing.T) {
	mw := clientIPMiddleware(nil, nil)
	var resolved string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved = chimw.GetClientIP(r.Context())
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.7:54321"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	handler.ServeHTTP(w, r)

	if resolved != "198.51.100.7" {
		t.Errorf("no trusted proxies: expected RemoteAddr %q, got %q", "198.51.100.7", resolved)
	}
}

// runHTTPSResolver runs the httpsResolverMiddleware against a single synthetic
// request and reports the IsHTTPS value the downstream handler observes. It is
// the shared harness for the m40 resolver tests below.
func runHTTPSResolver(t *testing.T, trusted []string, remoteAddr, xfp string, tlsState *tls.ConnectionState) bool {
	t.Helper()
	mw := httpsResolverMiddleware(mustTrustedProxies(t, trusted...))
	var got bool
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = middleware.IsHTTPS(r)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xfp != "" {
		r.Header.Set("X-Forwarded-Proto", xfp)
	}
	r.TLS = tlsState
	handler.ServeHTTP(w, r)
	return got
}

// TestHTTPSResolver_TrustedProxyHonorsXFP verifies that when the direct TCP
// connection arrives from a configured trusted proxy, X-Forwarded-Proto is
// honoured. The rightmost comma-separated value — the one written by the last
// trusted hop — decides; the leftmost value is client-controlled when a proxy
// appends.
func TestHTTPSResolver_TrustedProxyHonorsXFP(t *testing.T) {
	trusted := []string{"10.0.0.0/8"}

	if got := runHTTPSResolver(t, trusted, "10.0.0.1:1234", "https", nil); !got {
		t.Error("trusted proxy + XFP https: expected IsHTTPS=true")
	}
	if got := runHTTPSResolver(t, trusted, "10.0.0.1:1234", "http", nil); got {
		t.Error("trusted proxy + XFP http: expected IsHTTPS=false")
	}
	if got := runHTTPSResolver(t, trusted, "10.0.0.1:1234", "https, http", nil); got {
		t.Error("trusted proxy + multi-hop 'https, http': expected IsHTTPS=false (rightmost wins)")
	}
	if got := runHTTPSResolver(t, trusted, "10.0.0.1:1234", "http, https", nil); !got {
		t.Error("trusted proxy + multi-hop 'http, https': expected IsHTTPS=true (rightmost wins)")
	}
}

// TestHTTPSResolver_TrustedProxyRepeatedXFPLines verifies that a proxy which
// appends X-Forwarded-Proto as repeated header lines (not one comma-joined
// line) is parsed with the same rightmost semantics: the last line decides.
func TestHTTPSResolver_TrustedProxyRepeatedXFPLines(t *testing.T) {
	mw := httpsResolverMiddleware(mustTrustedProxies(t, "10.0.0.0/8"))
	var got bool
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = middleware.IsHTTPS(r)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Proto", "https")
	handler.ServeHTTP(w, r)
	if !got {
		t.Error("trusted proxy + XFP as two lines 'http' then 'https': expected IsHTTPS=true (rightmost line wins)")
	}
}

// TestHTTPSResolver_UntrustedRemoteAddrIgnoresXFP is the m40 regression test:
// when RemoteAddr is NOT a trusted proxy, a forged X-Forwarded-Proto: https
// must NOT be honoured — otherwise a direct-access attacker over plain HTTP
// could force HSTS and the Secure cookie flag.
func TestHTTPSResolver_UntrustedRemoteAddrIgnoresXFP(t *testing.T) {
	if got := runHTTPSResolver(t, []string{"10.0.0.0/8"}, "198.51.100.7:54321", "https", nil); got {
		t.Error("untrusted direct connection + forged XFP https: expected IsHTTPS=false (m40 spoofing regression)")
	}
}

// TestHTTPSResolver_NoTrustedProxiesIgnoresXFP verifies that with no
// trusted_proxies configured, X-Forwarded-Proto is always ignored.
func TestHTTPSResolver_NoTrustedProxiesIgnoresXFP(t *testing.T) {
	if got := runHTTPSResolver(t, nil, "198.51.100.7:54321", "https", nil); got {
		t.Error("no trusted proxies + XFP https: expected IsHTTPS=false")
	}
}

// TestHTTPSResolver_DirectTLSAlwaysWins verifies that a genuine TLS transport
// is reported as HTTPS regardless of proxy configuration.
func TestHTTPSResolver_DirectTLSAlwaysWins(t *testing.T) {
	if got := runHTTPSResolver(t, nil, "198.51.100.7:54321", "", &tls.ConnectionState{}); !got {
		t.Error("direct TLS with no trusted proxies: expected IsHTTPS=true")
	}
}

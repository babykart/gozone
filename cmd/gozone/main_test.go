package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/middleware"
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

func TestRun_InvalidDatabaseDriver(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := `
database:
  driver: unsupported
  dsn: ""
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"-config", cfgPath})
	if err == nil {
		t.Fatal("expected error for unsupported database driver")
	}
	if !strings.Contains(err.Error(), "unsupported database driver") {
		t.Errorf("expected unsupported database driver error, got: %v", err)
	}
}

func TestRun_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("not: [ valid yaml"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"-config", cfgPath})
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestRun_InvalidFlag(t *testing.T) {
	err := run([]string{"-unknown-flag"})
	if err == nil {
		t.Fatal("expected error for invalid flag")
	}
}

func TestStartPeriodicJob(t *testing.T) {
	var count int32
	job := func(ctx context.Context) error {
		atomic.AddInt32(&count, 1)
		return nil
	}

	stop := startPeriodicJob(context.Background(), "test job", 50*time.Millisecond, 100*time.Millisecond, job)
	defer stop()

	// The job should run once immediately.
	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&count) < 1 {
		t.Fatal("expected job to run immediately")
	}

	// It should then run again on the next tick.
	time.Sleep(80 * time.Millisecond)
	if atomic.LoadInt32(&count) < 2 {
		t.Fatalf("expected at least one periodic run, got %d", atomic.LoadInt32(&count))
	}
}

// TestAPIRateLimitRunsBeforeAuth guards the M-SEC2 fix: the IP-based rate
// limiter on /api/v1 must execute BEFORE the APIKeyAuth middleware so that a
// key-rotation flood is rejected with 429 without ever reaching the DB lookup
// (SELECT ... FROM api_keys). A regression that reverts the order would let an
// attacker exhaust the database with arbitrary keys.
//
// The test builds the same middleware composition used in run() — IP limiter,
// then a stand-in for APIKeyAuth that counts invocations, then the per-key
// limiter — and verifies the auth step is never called once the IP bucket is
// drained.
func TestAPIRateLimitRunsBeforeAuth(t *testing.T) {
	const ipLimit = 3
	ipLimiter := middleware.NewRateLimiter(ipLimit)
	t.Cleanup(ipLimiter.Close)
	keyLimiter := middleware.NewRateLimiter(100)
	t.Cleanup(keyLimiter.Close)

	var authCalls int32
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&authCalls, 1)
			next.ServeHTTP(w, r)
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Compose in the production order: IP limit -> auth -> key limit.
	stack := ipLimiter.Limit(middleware.ExtractIP)(authMiddleware(keyLimiter.Limit(middleware.ExtractAPIKey)(handler)))

	// Fire one more request than the IP bucket allows, all from the same source
	// address (httptest always sets RemoteAddr to "192.0.2.1:1234").
	for i := 0; i < ipLimit+1; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
		r.Header.Set("X-API-Key", "rotating-random-key")
		stack.ServeHTTP(w, r)
	}

	got := atomic.LoadInt32(&authCalls)
	if got != ipLimit {
		t.Errorf("auth middleware invoked %d times, want %d (IP limiter must block the last request BEFORE auth — M-SEC2 regression)",
			got, ipLimit)
	}
}

// TestClientIPMiddleware_TrustedProxyHonorsXFF verifies that when the direct
// TCP connection (RemoteAddr) arrives from a configured trusted proxy, the
// X-Forwarded-For header is honoured and the real client IP is resolved.
func TestClientIPMiddleware_TrustedProxyHonorsXFF(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}

	mw := clientIPMiddleware(cfg)
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
	cfg := config.DefaultConfig()
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}

	mw := clientIPMiddleware(cfg)
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
	cfg := config.DefaultConfig()
	cfg.Server.TrustedProxies = nil

	mw := clientIPMiddleware(cfg)
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

// TestOperatorIdentity verifies that operatorIdentity returns a non-empty
// "user@host" string suitable for audit logging (m4).
func TestOperatorIdentity(t *testing.T) {
	got := operatorIdentity()
	if !strings.Contains(got, "@") {
		t.Errorf("operatorIdentity() = %q, expected to contain '@'", got)
	}
	if strings.HasPrefix(got, "@") || strings.HasSuffix(got, "@") {
		t.Errorf("operatorIdentity() = %q, empty user or host", got)
	}
}

// TestFileServer_CacheControlAndNoDirListing verifies that static files get a
// Cache-Control header and that directory listing is disabled (m9).
func TestFileServer_CacheControlAndNoDirListing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	os.Mkdir(filepath.Join(dir, "css"), 0755)
	if err := os.WriteFile(filepath.Join(dir, "css", "style.css"), []byte("body{}"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	r := chi.NewRouter()
	fileServer(r, "/static", http.Dir(dir))

	// Regular file: 200 + Cache-Control header.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("file request: expected 200, got %d", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("Cache-Control: got %q, want %q", cc, "public, max-age=86400")
	}

	// File in subdirectory: still served (dir listing block must not break
	// normal file access).
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("subdirectory file request: expected 200, got %d", w2.Code)
	}

	// Directory listing: 404, not a file listing.
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/static/", nil)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Errorf("directory listing: expected 404, got %d", w3.Code)
	}

	// Directory without trailing slash: also 404 (no redirect to listing).
	w4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodGet, "/static/css", nil)
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusNotFound {
		t.Errorf("directory without slash: expected 404, got %d", w4.Code)
	}
}

package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/web"
)

// executeServer builds a fresh root command and runs `gozone server` with
// the given args, returning the resulting error. Each call gets its own
// command tree so flag state is never shared between tests.
func executeServer(args ...string) error {
	cmd := newRootCmd()
	cmd.SetArgs(append([]string{"server"}, args...))
	return cmd.Execute()
}

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
	// REVIEW.md L-16c: the asset version is a short content hash of the bundled
	// JS/CSS so a new deployment busts the browser cache via ?v=… despite the
	// 24h max-age served by fileServer.
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
	// REVIEW.md L-16d: every authenticated page must expose a skip-to-content
	// link as the first focusable element and a focusable main landmark it
	// targets, so keyboard users can jump past the sidebar/topbar.
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
}

func TestAppJSNoNativeConfirm(t *testing.T) {
	// REVIEW.md L-16d: blocking window.confirm() must be gone in favour of the
	// custom confirmDialog modal. "confirm(" is not a substring of confirmDialog(
	// / closeConfirmDialog(, so a Contains check reliably guards against a revert.
	js, err := web.FS.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	if strings.Contains(string(js), "confirm(") {
		t.Error("app.js must not call the native window.confirm(); use confirmDialog() instead (REVIEW.md L-16d)")
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

	err := executeServer("--config", cfgPath)
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

	err := executeServer("--config", cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestRun_InvalidFlag(t *testing.T) {
	if err := executeServer("--unknown-flag"); err == nil {
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

// TestLoginUsernameKey covers the m35 fix at the key-function level: an empty
// (or whitespace-only) username must map to a dedicated sentinel bucket rather
// than "" (which bypasses the per-username rate limiter), while real usernames
// are lowercased and trimmed.
func TestLoginUsernameKey(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty body", "", emptyUsernameRateLimitKey},
		{"no username field", "foo=bar", emptyUsernameRateLimitKey},
		{"whitespace only", "username=%20%20%20", emptyUsernameRateLimitKey},
		{"simple", "username=admin", "admin"},
		{"uppercased", "username=ADMIN", "admin"},
		{"surrounding spaces", "username=+admin+", "admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if got := loginUsernameKey(r); got != tt.want {
				t.Errorf("loginUsernameKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoginUsernameRateLimit_EmptyUsernameNotBypassed is the m35 behavioral
// regression test: empty-username login attempts must consume the per-username
// rate-limit bucket instead of bypassing the limiter.
func TestLoginUsernameRateLimit_EmptyUsernameNotBypassed(t *testing.T) {
	const userLimit = 3
	limiter := middleware.NewRateLimiter(userLimit)
	t.Cleanup(limiter.Close)

	handler := limiter.Limit(loginUsernameKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Fire userLimit+1 login POSTs with NO username. Before the fix every one
	// bypassed the limiter (key "" -> no bucket consumed) and all returned 200.
	// After the fix they share the <empty-username> bucket, so the last request
	// must be 429.
	var lastCode int
	for i := 0; i < userLimit+1; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(w, r)
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after %d empty-username requests, expected the %dth to be 429, got %d (limiter bypassed — m35 regression)",
			userLimit, userLimit+1, lastCode)
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

// runHTTPSResolver runs the httpsResolverMiddleware against a single synthetic
// request and reports the IsHTTPS value the downstream handler observes. It is
// the shared harness for the m40 resolver tests below.
func runHTTPSResolver(t *testing.T, cfg *config.Config, remoteAddr, xfp string, tlsState *tls.ConnectionState) bool {
	t.Helper()
	mw := httpsResolverMiddleware(cfg)
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
// honoured (single-hop and multi-hop, m6 preserved).
func TestHTTPSResolver_TrustedProxyHonorsXFP(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}

	if got := runHTTPSResolver(t, cfg, "10.0.0.1:1234", "https", nil); !got {
		t.Error("trusted proxy + XFP https: expected IsHTTPS=true")
	}
	if got := runHTTPSResolver(t, cfg, "10.0.0.1:1234", "http", nil); got {
		t.Error("trusted proxy + XFP http: expected IsHTTPS=false")
	}
	if got := runHTTPSResolver(t, cfg, "10.0.0.1:1234", "https, http", nil); !got {
		t.Error("trusted proxy + multi-hop 'https, http': expected IsHTTPS=true (m6 leftmost wins)")
	}
}

// TestHTTPSResolver_UntrustedRemoteAddrIgnoresXFP is the m40 regression test:
// when RemoteAddr is NOT a trusted proxy, a forged X-Forwarded-Proto: https
// must NOT be honoured — otherwise a direct-access attacker over plain HTTP
// could force HSTS and the Secure cookie flag.
func TestHTTPSResolver_UntrustedRemoteAddrIgnoresXFP(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}

	if got := runHTTPSResolver(t, cfg, "198.51.100.7:54321", "https", nil); got {
		t.Error("untrusted direct connection + forged XFP https: expected IsHTTPS=false (m40 spoofing regression)")
	}
}

// TestHTTPSResolver_NoTrustedProxiesIgnoresXFP verifies that with no
// trusted_proxies configured, X-Forwarded-Proto is always ignored.
func TestHTTPSResolver_NoTrustedProxiesIgnoresXFP(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.TrustedProxies = nil

	if got := runHTTPSResolver(t, cfg, "198.51.100.7:54321", "https", nil); got {
		t.Error("no trusted proxies + XFP https: expected IsHTTPS=false")
	}
}

// TestHTTPSResolver_DirectTLSAlwaysWins verifies that a genuine TLS transport
// is reported as HTTPS regardless of proxy configuration.
func TestHTTPSResolver_DirectTLSAlwaysWins(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.TrustedProxies = nil
	if got := runHTTPSResolver(t, cfg, "198.51.100.7:54321", "", &tls.ConnectionState{}); !got {
		t.Error("direct TLS with no trusted proxies: expected IsHTTPS=true")
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

// TestCSRFSecureCookieWriter verifies that csrfSecureCookieWriter dynamically
// adds the Secure attribute to the CSRF cookie based on the per-request HTTPS
// flag (REVIEW.md L-2). The session cookie already uses IsHTTPS(r) per-request;
// this wrapper brings the CSRF cookie in line so the two never disagree.
func TestCSRFSecureCookieWriter(t *testing.T) {
	// Helper: build a ResponseRecorder wrapped in csrfSecureCookieWriter,
	// set a CSRF cookie + a non-CSRF cookie, trigger the rewrite, and return
	// the parsed cookies.
	run := func(t *testing.T, https bool) (csrfCookie, otherCookie *http.Cookie) {
		t.Helper()
		rec := httptest.NewRecorder()
		w := &csrfSecureCookieWriter{ResponseWriter: rec, https: https}

		// Simulate what gorilla/csrf's cookieStore.Save does (csrf.Secure(false)
		// → no Secure attribute on the cookie).
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    "encoded-token-value",
			Path:     "/",
			HttpOnly: true,
		})
		// A non-CSRF cookie should never be touched.
		http.SetCookie(w, &http.Cookie{
			Name:  "other-cookie",
			Value: "other",
			Path:  "/",
		})

		w.WriteHeader(http.StatusOK)

		for _, c := range rec.Result().Cookies() {
			switch c.Name {
			case csrfCookieName:
				csrfCookie = c
			case "other-cookie":
				otherCookie = c
			}
		}
		if csrfCookie == nil {
			t.Fatal("CSRF cookie not found in response")
		}
		if otherCookie == nil {
			t.Fatal("other cookie not found in response")
		}
		return csrfCookie, otherCookie
	}

	t.Run("HTTPS adds Secure to CSRF cookie only", func(t *testing.T) {
		csrfCookie, otherCookie := run(t, true)
		if !csrfCookie.Secure {
			t.Errorf("CSRF cookie Secure = false, want true (HTTPS request — REVIEW.md L-2)")
		}
		if otherCookie.Secure {
			t.Errorf("other cookie should not have been modified (Secure = true)")
		}
	})

	t.Run("HTTP does not add Secure", func(t *testing.T) {
		csrfCookie, otherCookie := run(t, false)
		if csrfCookie.Secure {
			t.Errorf("CSRF cookie Secure = true, want false (HTTP request — plain-HTTP dev must work)")
		}
		if otherCookie.Secure {
			t.Errorf("other cookie should not have Secure flag")
		}
	})
}

// TestCSRFSecureCookieWriter_FlushAfterHandler covers the edge case where the
// handler returns without calling Write/WriteHeader (e.g. a handler that sets
// only a Location header via http.Redirect without calling WriteHeader).
// applySecureFlag must be called by the middleware's post-handler flush so the
// CSRF cookie still gets the Secure attribute.
func TestCSRFSecureCookieWriter_FlushAfterHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &csrfSecureCookieWriter{ResponseWriter: rec, https: true}

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "token",
		Path:     "/",
		HttpOnly: true,
	})

	// Simulate a handler that sets the cookie but never calls Write/WriteHeader.
	// The middleware calls applySecureFlag() after next.ServeHTTP returns.
	w.applySecureFlag()

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not found")
	}
	if !csrfCookie.Secure {
		t.Errorf("CSRF cookie Secure = false, want true (post-handler flush failed)")
	}
}

// TestCSRFSecureCookieWriter_Idempotent verifies that applySecureFlag does not
// append duplicate "; Secure" attributes even if called multiple times.
func TestCSRFSecureCookieWriter_Idempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &csrfSecureCookieWriter{ResponseWriter: rec, https: true}

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "token",
		Path:     "/",
		HttpOnly: true,
	})

	w.applySecureFlag()
	w.applySecureFlag() // second call should be a no-op
	w.applySecureFlag() // third call should also be a no-op

	var count int
	for _, c := range rec.Header()["Set-Cookie"] {
		if strings.HasPrefix(c, csrfCookieName+"=") {
			count = strings.Count(c, "Secure")
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 'Secure' attribute, got %d (not idempotent)", count)
	}
}

// hasMiddleware reports whether target appears in middlewares, comparing by
// function code pointer — the exact value r.Use(middleware.RequireAdmin) stores.
func hasMiddleware(middlewares []func(http.Handler) http.Handler, target func(http.Handler) http.Handler) bool {
	want := reflect.ValueOf(target).Pointer()
	for _, mw := range middlewares {
		if reflect.ValueOf(mw).Pointer() == want {
			return true
		}
	}
	return false
}

// TestAdminRoutesProtectedByRequireAdmin locks the B-5 property: every route
// registered by mountAdminRoutes must carry middleware.RequireAdmin in its
// middleware chain. A routing refactor that moves an admin handler outside the
// RequireAdmin group (or drops the r.Use) makes this test fail. It walks the
// real chi router built by mountAdminRoutes — the single source of truth used
// by runServer — so it verifies the production wiring rather than a copy.
func TestAdminRoutesProtectedByRequireAdmin(t *testing.T) {
	r := chi.NewRouter()
	// A zero-value Handler is fine: routes are walked, never invoked, so the
	// bound method values are never called. db=nil is safe because
	// CheckZoneAccess only captures it in a closure used at request time.
	mountAdminRoutes(r, &handlers.Handler{}, nil)

	var checked int
	err := chi.Walk(r, func(method, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		checked++
		if !hasMiddleware(middlewares, middleware.RequireAdmin) {
			return fmt.Errorf("%s %s is not protected by middleware.RequireAdmin (admin route escaped the RequireAdmin group — REVIEW.md B-5)", method, route)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: mountAdminRoutes must register a meaningful number of admin
	// routes — a regression that registers none would otherwise pass vacuously.
	if checked == 0 {
		t.Fatal("walked 0 admin routes — mountAdminRoutes registered nothing (B-5 lock is vacuous)")
	}
	t.Logf("verified %d admin routes are guarded by RequireAdmin", checked)
}

package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
)

// executeServer builds a fresh root command and runs `gozone server` with
// the given args, returning the resulting error. Each call gets its own
// command tree so flag state is never shared between tests.
func executeServer(args ...string) error {
	cmd := newRootCmd()
	cmd.SetArgs(append([]string{"server"}, args...))
	return cmd.Execute()
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

// TestRun_InvalidTrustedProxies pins the fail mode for a malformed
// server.trusted_proxies entry (a bare IP without "/"): a clean startup error
// with actionable guidance, not a netip.MustParsePrefix panic. The
// validation runs before the database is opened, so nothing half-starts.
func TestRun_InvalidTrustedProxies(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := `
server:
  host: 127.0.0.1
  port: 8080
  secret_key: 0123456789abcdef0123456789abcdef
  trusted_proxies:
    - 10.0.0.1
database:
  driver: sqlite3
  dsn: ":memory:"
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := executeServer("--config", cfgPath)
	if err == nil {
		t.Fatal("expected error for bare-IP trusted_proxies entry")
	}
	if !strings.Contains(err.Error(), "trusted_proxies") || !strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("error should name the setting and the offending entry, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/32") {
		t.Errorf("error should suggest the /32 form for the operator, got: %v", err)
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

// freePort reserves an ephemeral TCP port on the loopback interface and
// returns its number. The listener is released before the caller can bind it,
// which is a (small, test-acceptable) TOCTOU race against other processes.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitForHealthy polls the liveness endpoint until it answers 200 or the
// timeout elapses. runServer binds its listener asynchronously from the test's
// point of view, so the first requests may hit a closed port.
func waitForHealthy(t *testing.T, baseURL string) error {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/health/live") // #nosec G107 -- fixed test-local URL
		if err == nil {
			io.Copy(io.Discard, resp.Body) // #nosec G104 -- drain for keep-alive reuse
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server did not become healthy within the timeout at %s", baseURL)
}

// TestRunServer_BootAndGracefulShutdown is the end-to-end wiring test: it
// boots the real `gozone server` stack (config load → DB migrate+seed →
// template parsing → router with the full middleware chain → HTTP listener),
// exercises one endpoint per routing branch, then delivers SIGTERM and asserts
// runServer drains and returns nil. This is the coverage the per-component
// unit tests cannot give: the middleware ORDER, the route table assembly, the
// limiter construction and the shutdown sequencing are only exercised by the
// composed wiring itself.
func TestRunServer_BootAndGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := fmt.Sprintf(`
server:
  host: 127.0.0.1
  port: %d
  secret_key: integration-test-secret-key-0123456789ab
database:
  driver: sqlite3
  dsn: %s
powerdns:
  api_url: http://127.0.0.1:1
  api_key: test
logging:
  level: warn
`, port, filepath.ToSlash(filepath.Join(dir, "gozone.db")))
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// runServer blocks until shutdown completes; run it off-thread and
	// collect its return value.
	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		done <- result{err: runServer(cfg)}
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := waitForHealthy(t, baseURL); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Full middleware chain reaches the login page and the security headers
	// are applied (clientIP → logger → compress → httpsResolver →
	// SecurityHeaders → CSRF → LoginPage).
	resp, err := client.Get(baseURL + "/login") // #nosec G107 -- fixed test-local URL
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login: expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers missing from the /login response (middleware chain not applied)")
	}
	if !strings.Contains(string(body), `name="gorilla.csrf.Token"`) {
		t.Error("login page missing the CSRF token input (CSRF middleware not applied)")
	}

	// Unauthenticated web request redirects to /login (auth middleware).
	resp, err = client.Get(baseURL + "/dashboard") // #nosec G107 -- fixed test-local URL
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	io.Copy(io.Discard, resp.Body) // #nosec G104
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("unauthenticated /dashboard: expected 303 to /login, got %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// API branch: API-key auth rejects anonymous callers with 401 (the
	// pre-auth IP limiter must not interfere at this volume).
	resp, err = client.Get(baseURL + "/api/v1/zones") // #nosec G107 -- fixed test-local URL
	if err != nil {
		t.Fatalf("GET /api/v1/zones: %v", err)
	}
	io.Copy(io.Discard, resp.Body) // #nosec G104
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous /api/v1/zones: expected 401, got %d", resp.StatusCode)
	}

	// Static files are served with cache-busting headers.
	resp, err = client.Get(baseURL + "/static/css/style.css") // #nosec G107 -- fixed test-local URL
	if err != nil {
		t.Fatalf("GET /static/css/style.css: %v", err)
	}
	io.Copy(io.Discard, resp.Body) // #nosec G104
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("static asset: expected 200, got %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("static asset Cache-Control: got %q", cc)
	}

	// Graceful shutdown: deliver SIGTERM to ourselves (runServer's signal
	// watcher catches it, drains the listener, and returns nil).
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("runServer returned error after shutdown: %v", r.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("runServer did not return within 20s of SIGTERM (shutdown hang)")
	}
}

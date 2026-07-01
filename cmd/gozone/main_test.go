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
	keyLimiter := middleware.NewRateLimiter(100)

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

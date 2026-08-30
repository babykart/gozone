package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/validators"
)

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
// are lowercased and trimmed. Over-long usernames (which cannot name a real
// account) also collapse onto the sentinel so the bucket map key stays bounded.
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
		// Exactly the maximum valid length: kept as its own key.
		{"max length username", "username=" + strings.Repeat("a", validators.MaxUsernameLength), strings.Repeat("a", validators.MaxUsernameLength)},
		// One byte past the maximum: cannot name a real account, shares the sentinel.
		{"over max length", "username=" + strings.Repeat("a", validators.MaxUsernameLength+1), emptyUsernameRateLimitKey},
		// Pathological payload: a kilobyte-long username collapses onto the sentinel.
		{"kilobyte username", "username=" + strings.Repeat("z", 1024), emptyUsernameRateLimitKey},
		// Multi-byte input is bounded by BYTES, not runes: 33 × 'é' is 33
		// runes but 66 bytes — one byte past the cap even though the rune
		// count is not — so it shares the sentinel. 10 × 'é' (20 bytes)
		// stays under the cap and keeps its own key.
		{"multi-byte over cap", "username=" + strings.Repeat("\u00e9", 33), emptyUsernameRateLimitKey},
		{"multi-byte under cap", "username=" + strings.Repeat("\u00e9", 10), strings.Repeat("\u00e9", 10)},
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

// TestLoginUsernameRateLimit_LongUsernamesShareBucket is the behavioural
// companion to the key-function table above: login attempts carrying many
// distinct over-long usernames must all consume the same shared bucket (and
// eventually hit 429) instead of allocating one bucket per distinct payload,
// which previously let an unauthenticated caller grow the limiter's memory
// with the request body as the only bound.
func TestLoginUsernameRateLimit_LongUsernamesShareBucket(t *testing.T) {
	const userLimit = 3
	limiter := middleware.NewRateLimiter(userLimit)
	t.Cleanup(limiter.Close)

	handler := limiter.Limit(loginUsernameKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// userLimit+1 distinct over-long usernames: they share the sentinel
	// bucket, so the last request must be 429.
	var lastCode int
	for i := 0; i < userLimit+1; i++ {
		body := "username=" + strings.Repeat("a", 64) + fmt.Sprint(i)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(w, r)
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("expected the last distinct over-long username to be rate-limited (shared bucket), got %d", lastCode)
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

// TestHealthReadyRateLimit_BlocksBeforeOutboundWork pins the readiness wiring
// semantics: the per-IP limiter runs BEFORE the handler, so once the bucket is
// drained an anonymous flooder gets 429s and the handler — which performs a DB
// ping and an uncached outbound PowerDNS call per hit — is never invoked.
// Without the bound, every cheap request forced real outbound work (an
// amplification surface) and leaked dependency status to unauthenticated
// callers.
func TestHealthReadyRateLimit_BlocksBeforeOutboundWork(t *testing.T) {
	limiter := middleware.NewRateLimiter(healthReadyRateLimitPerMinute)
	t.Cleanup(limiter.Close)

	var handlerCalls int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&handlerCalls, 1)
		w.WriteHeader(http.StatusOK)
	})

	stack := limiter.Limit(middleware.ExtractIP)(handler)

	// httptest pins RemoteAddr to "192.0.2.1:1234", so every request draws
	// from the same per-IP bucket.
	var lastCode int
	for i := 0; i < healthReadyRateLimitPerMinute+5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		stack.ServeHTTP(w, r)
		lastCode = w.Code
	}

	if lastCode != http.StatusTooManyRequests {
		t.Errorf("request past the bucket must return 429, got %d", lastCode)
	}
	if got := atomic.LoadInt32(&handlerCalls); got != healthReadyRateLimitPerMinute {
		t.Errorf("handler invoked %d times, want exactly %d (the limiter must gate the outbound DB/PowerDNS work)",
			got, healthReadyRateLimitPerMinute)
	}
	if ra := lastRetryAfter(stack); ra == "" {
		t.Error("expected a Retry-After header on the 429 response")
	}
}

// lastRetryAfter drives one more request through the (drained) stack and
// returns its Retry-After header value, or "" when absent.
func lastRetryAfter(stack http.Handler) string {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	stack.ServeHTTP(w, r)
	return w.Header().Get("Retry-After")
}

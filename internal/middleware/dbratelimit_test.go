package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
)

func newDBRateLimitTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// fixedKey returns a constant rate-limit key so consecutive requests in a
// test share one bucket regardless of timing.
func fixedKey(r *http.Request) string { return "test-bucket" }

func TestDBRateLimiter_BlocksPastLimit(t *testing.T) {
	db := newDBRateLimitTestDB(t)
	limiter := NewDBRateLimiter(db, 3)

	handler := limiter.Limit(fixedKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var lastCode int
	for i := 0; i < 4; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("4th request past a limit of 3: expected 429, got %d", lastCode)
	}
}

func TestDBRateLimiter_CountersSharedAcrossLimiterInstances(t *testing.T) {
	// Two limiter instances over the same database model two replicas behind
	// a load balancer: the shared counter must cap the TOTAL at the limit,
	// not the per-instance rate.
	db := newDBRateLimitTestDB(t)
	a := NewDBRateLimiter(db, 4)
	b := NewDBRateLimiter(db, 4)

	handler := func(l *DBRateLimiter) http.Handler {
		return l.Limit(fixedKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}

	var last int
	for i := 0; i < 4; i++ {
		w := httptest.NewRecorder()
		handler(a).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
		last = w.Code
	}
	if last != http.StatusOK {
		t.Fatalf("4 requests across both replicas must still be allowed, got %d", last)
	}
	w := httptest.NewRecorder()
	handler(b).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("5th request via the second replica must hit the shared budget: expected 429, got %d", w.Code)
	}
}

func TestDBRateLimiter_SharedBudgetWithinWindow(t *testing.T) {
	// The shared-budget property at the DB-layer level: an instance that has
	// never seen the traffic still gets rejected once the window is drained
	// by others. Uses the raw HitRateLimit API to pin the window explicitly.
	db := newDBRateLimitTestDB(t)
	window := time.Now().UTC().Truncate(time.Minute)

	for i := 0; i < 3; i++ {
		if allowed, err := db.HitRateLimit(t.Context(), "shared", window, 3); err != nil || !allowed {
			t.Fatalf("hit %d: allowed=%v err=%v", i+1, allowed, err)
		}
	}
	if allowed, err := db.HitRateLimit(t.Context(), "shared", window, 3); err != nil || allowed {
		t.Fatalf("4th hit: allowed=%v err=%v", allowed, err)
	}
}

func TestDBRateLimiter_EmptyKeyBypasses(t *testing.T) {
	db := newDBRateLimitTestDB(t)
	limiter := NewDBRateLimiter(db, 1)

	handler := limiter.Limit(func(*http.Request) string { return "" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("empty-key request %d must bypass limiting, got %d", i+1, w.Code)
		}
	}
}

func TestDBRateLimiter_FailsOpenOnDBError(t *testing.T) {
	db := newDBRateLimitTestDB(t)
	limiter := NewDBRateLimiter(db, 1)
	// Break the database underneath the limiter: every counter check errors,
	// which must fail OPEN (the guarded endpoints are DB-dependent anyway).
	db.Close()

	handler := limiter.Limit(fixedKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d under a DB outage must be allowed (fail-open), got %d", i+1, w.Code)
		}
	}
}

func TestDBRateLimiter_429BodyAndRetryAfter(t *testing.T) {
	db := newDBRateLimitTestDB(t)
	limiter := NewDBRateLimiter(db, 1)

	handler := limiter.Limit(fixedKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/login", nil))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("429 response missing Retry-After")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
	if !strings.Contains(w.Body.String(), "rate_limit_exceeded") {
		t.Errorf("body missing the error code: %s", w.Body.String())
	}
}

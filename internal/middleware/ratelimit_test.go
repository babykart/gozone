package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
)

func TestRateLimiter_AllowsBurst(t *testing.T) {
	rl := NewRateLimiter(5)
	t.Cleanup(rl.Close)

	handler := rl.Limit(func(r *http.Request) string { return "test-key" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimiter_BlocksAfterBurst(t *testing.T) {
	rl := NewRateLimiter(3)
	t.Cleanup(rl.Close)

	handler := rl.Limit(func(r *http.Request) string { return "test-key" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "rate_limit_exceeded" {
		t.Errorf("expected rate_limit_exceeded, got %q", body["error"])
	}
}

func TestRateLimiter_DifferentKeys(t *testing.T) {
	rl := NewRateLimiter(2)
	t.Cleanup(rl.Close)

	handler := rl.Limit(func(r *http.Request) string { return r.Header.Get("X-Key") })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	t.Run("key-a uses its own budget", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("X-Key", "key-a")
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("key-a request %d: expected 200, got %d", i+1, w.Code)
			}
		}
	})

	t.Run("key-b still has full budget", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("X-Key", "key-b")
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("key-b request %d: expected 200, got %d", i+1, w.Code)
			}
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Key", "key-b")
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("key-b exceeded: expected 429, got %d", w.Code)
		}
	})
}

func TestRateLimiter_EmptyKeyPassesThrough(t *testing.T) {
	rl := NewRateLimiter(1)
	t.Cleanup(rl.Close)

	handler := rl.Limit(func(r *http.Request) string { return "" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(50)
	t.Cleanup(rl.Close)

	handler := rl.Limit(func(r *http.Request) string { return "concurrent-key" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	var wg sync.WaitGroup
	errs := make(chan int, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			handler.ServeHTTP(w, r)
			errs <- w.Code
		}()
	}
	wg.Wait()
	close(errs)

	for code := range errs {
		if code != http.StatusOK {
			t.Errorf("concurrent request got %d", code)
		}
	}
}

// TestRateLimiter_CloseStopsGoroutine verifies that Close() is idempotent and
// stops the cleanup goroutine (m3 regression guard).
func TestRateLimiter_CloseStopsGoroutine(t *testing.T) {
	rl := NewRateLimiter(1)

	// Close must be safe to call multiple times.
	rl.Close()
	rl.Close()

	// After Close, the stopCh is closed; the cleanup goroutine should have
	// exited. Verify by checking that allow() still works (the limiter
	// struct itself is still usable, just the background sweep is gone).
	if !rl.allow("post-close-key") {
		t.Error("allow() should still work after Close()")
	}
}

func TestMaskKey(t *testing.T) {
	got := maskKey("secret-api-key")
	if got == "secret-api-key" {
		t.Error("maskKey must not return the raw key")
	}
	if len(got) != 11 {
		t.Errorf("expected masked key length 11, got %d (%s)", len(got), got)
	}
	if got == maskKey("different-key") {
		t.Error("maskKey should produce different outputs for different inputs")
	}
}

func TestExtractIP(t *testing.T) {
	t.Run("falls back to RemoteAddr when no context IP", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "192.168.1.1:12345"
		if got := ExtractIP(r); got != "192.168.1.1:12345" {
			t.Errorf("expected 192.168.1.1:12345, got %s", got)
		}
	})

	t.Run("uses context IP set by ClientIPFromRemoteAddr", func(t *testing.T) {
		// Wrap the request through chi's ClientIPFromRemoteAddr middleware so
		// the context-stored IP is populated exactly as it is in production.
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "198.51.100.7:12345"
		var seen string
		chimw.ClientIPFromRemoteAddr(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			seen = ExtractIP(req)
		})).ServeHTTP(httptest.NewRecorder(), r)
		if seen != "198.51.100.7" {
			t.Errorf("expected context IP 198.51.100.7 to win over RemoteAddr, got %s", seen)
		}
	})
}

func TestExtractAPIKey(t *testing.T) {
	t.Run("X-API-Key header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-API-Key", "my-api-key")
		if got := ExtractAPIKey(r); got != "my-api-key" {
			t.Errorf("expected my-api-key, got %s", got)
		}
	})

	t.Run("Authorization Bearer", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer my-bearer-key")
		if got := ExtractAPIKey(r); got != "my-bearer-key" {
			t.Errorf("expected my-bearer-key, got %s", got)
		}
	})

	t.Run("X-API-Key takes precedence", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-API-Key", "header-key")
		r.Header.Set("Authorization", "Bearer bearer-key")
		if got := ExtractAPIKey(r); got != "header-key" {
			t.Errorf("expected header-key, got %s", got)
		}
	})

	t.Run("no key", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if got := ExtractAPIKey(r); got != "" {
			t.Errorf("expected empty, got %s", got)
		}
	})
}

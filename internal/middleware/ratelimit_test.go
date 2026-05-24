package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestRateLimiter_AllowsBurst(t *testing.T) {
	rl := NewRateLimiter(5)

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

func TestExtractIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	if got := ExtractIP(r); got != "192.168.1.1:12345" {
		t.Errorf("expected 192.168.1.1:12345, got %s", got)
	}
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

func TestExtractUsername(t *testing.T) {
	t.Run("basic auth", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth("myuser", "mypass")
		if got := ExtractUsername(r); got != "myuser" {
			t.Errorf("expected myuser, got %s", got)
		}
	})

	t.Run("no auth", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if got := ExtractUsername(r); got != "" {
			t.Errorf("expected empty, got %s", got)
		}
	})
}

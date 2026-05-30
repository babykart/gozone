package middleware

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/babykart/gozone/internal/logger"
)

// RateLimiter tracks per-key request rates with token bucket algorithm.
//
// Each unique key (e.g., IP address, API key, username) gets its own
// token bucket limiter. Unused limiters are periodically cleaned up.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiterEntry
	rate     rate.Limit
	burst    int
	ttl      time.Duration
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a rate limiter allowing n requests per minute with burst=n.
//
// Parameters:
//   - n: maximum number of requests allowed per minute per key
func NewRateLimiter(n int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		rate:     rate.Limit(n) / 60.0,
		burst:    n,
		ttl:      5 * time.Minute,
	}
	go rl.cleanup()
	return rl
}

// cleanup periodically removes entries not seen for ttl duration.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for key, entry := range rl.limiters {
			if time.Since(entry.lastSeen) > rl.ttl {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// allow reports whether the given key is within the rate limit.
func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	entry, ok := rl.limiters[key]
	if !ok {
		entry = &rateLimiterEntry{
			limiter: rate.NewLimiter(rl.rate, rl.burst),
		}
		rl.limiters[key] = entry
	}
	entry.lastSeen = time.Now()
	rl.mu.Unlock()

	return entry.limiter.Allow()
}

// KeyFunc extracts a rate-limiting key from an HTTP request.
type KeyFunc func(r *http.Request) string

// Limit returns middleware that rate-limits requests using the given key function.
//
// When the rate limit is exceeded, returns HTTP 429 with a Retry-After header
// and a JSON error body.
func (rl *RateLimiter) Limit(keyFn KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			if !rl.allow(key) {
				logger.Warn("rate limit exceeded", "key", key)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate_limit_exceeded","message":"too many requests, retry after 60 seconds"}`)) // #nosec G104
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ExtractIP returns the client IP from the request.
//
// It reads r.RemoteAddr which already includes the real IP when chi's
// RealIP middleware is in the stack.
func ExtractIP(r *http.Request) string {
	return r.RemoteAddr
}

// ExtractAPIKey returns the API key from X-API-Key or Authorization header.
func ExtractAPIKey(r *http.Request) string {
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

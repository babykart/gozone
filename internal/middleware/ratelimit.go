package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"

	"github.com/babykart/gozone/internal/logger"
)

// RateLimiter tracks per-key request rates with token bucket algorithm.
//
// Each unique key (e.g., IP address, API key, username) gets its own
// token bucket limiter. Unused limiters are periodically cleaned up.
//
// Buckets are held in-process: the limit is enforced **per instance**, not
// shared across a fleet. In a multi-instance deployment the effective ceiling
// per client therefore scales with the instance count (N instances → up to
// roughly N× the configured rate). For the login endpoints this is mitigated:
// DBRateLimiter (dbratelimit.go) enforces the authoritative, cluster-wide
// budget in the shared database, with this in-process limiter kept in front
// as a cheap pre-DB gate for floods. The API and health limiters stay
// per-instance deliberately — they are anti-flood throttles, and the health
// limiter must never depend on the database it probes. Durable brute-force
// protection (account lockout in the DB) is independent of both and stays
// cluster-wide. See the README "High Availability / Multi-Instance
// Deployments" section.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiterEntry
	rate     rate.Limit
	burst    int
	ttl      time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
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
		stopCh:   make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Close stops the background cleanup goroutine. It is safe to call multiple
// times (m3).
func (rl *RateLimiter) Close() {
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
}

// cleanup periodically removes entries not seen for ttl duration. It exits
// when Close() is called or the stopCh is closed.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			for key, entry := range rl.limiters {
				if time.Since(entry.lastSeen) > rl.ttl {
					delete(rl.limiters, key)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
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
//
// A key function that returns "" for a request causes that request to bypass
// rate-limiting entirely (no bucket is consumed). This is intended for key
// functions that legitimately cannot extract a key (so blocking would be
// wrong); a key function that wants empty-key requests limited must return a
// non-empty sentinel — e.g. loginUsernameKey maps an empty username to a shared
// bucket (m35).
func (rl *RateLimiter) Limit(keyFn KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			if !rl.allow(key) {
				logger.Warn("rate limit exceeded", "key", maskKey(key))
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

// maskKey returns a non-reversible truncated SHA-256 hex hash of key.
// It avoids logging raw API keys or IP addresses, matching the pattern
// used in auth.go for key_hash logging.
func maskKey(key string) string {
	if key == "" {
		return ""
	}
	h := sha256.Sum256([]byte(key))
	hash := hex.EncodeToString(h[:])
	if len(hash) > 8 {
		return hash[:8] + "..."
	}
	return hash
}

// ExtractIP returns the client IP from the request context.
//
// It reads the IP set by the chi ClientIPFrom* middleware in cmd/server.go
// (ClientIPFromRemoteAddr by default, or ClientIPFromXFF when trusted_proxies
// is configured). When no IP has been resolved (e.g., a test request or a
// misconfigured middleware stack) it falls back to r.RemoteAddr so the
// rate-limit key is never empty.
func ExtractIP(r *http.Request) string {
	ip := chimw.GetClientIP(r.Context())
	if ip != "" {
		return ip
	}
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

package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
)

// dbRateLimitWindow is the fixed-window width. One minute keeps the semantics
// identical to the in-process limiter (N per minute) and bounds the Retry-After
// hint.
const dbRateLimitWindow = time.Minute

// DBRateLimiter enforces a cluster-wide fixed-window rate limit backed by the
// shared database (the rate_limit_counters table): every instance draws from
// the same per-key budget, so the ceiling does not scale with the replica
// count — unlike the in-process RateLimiter, which stays in front as a cheap
// pre-DB gate for floods.
//
// Semantics: a request over the limit gets the same 429 + Retry-After + JSON
// body as the in-process limiter. A database error fails OPEN (the request
// proceeds): the endpoints this guards (login) are already DB-dependent — if
// the database is unreachable the request fails there anyway — and failing
// closed would amplify an outage into a login blackout. Durable account
// lockout remains the brute-force backstop in both cases.
//
// Window boundaries derive from each instance's clock, so small clock skew
// across replicas can shift a boundary by that skew; the budget itself stays
// shared. Keys should be bounded-length (IPs, usernames via loginUsernameKey,
// masked API keys) because they are stored verbatim as the counter's primary
// key.
type DBRateLimiter struct {
	db    *database.DB
	limit int
}

// NewDBRateLimiter creates a cluster-wide limiter allowing limit requests per
// dbRateLimitWindow per key. It spawns no goroutines and needs no Close.
func NewDBRateLimiter(db *database.DB, limit int) *DBRateLimiter {
	return &DBRateLimiter{db: db, limit: limit}
}

// Limit returns middleware that enforces the cluster-wide rate limit using the
// given key function. A key function returning "" bypasses limiting for that
// request, mirroring RateLimiter.Limit.
func (d *DBRateLimiter) Limit(keyFn KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Truncating a UTC time to a whole minute is safe across time
			// zones (no DST in UTC); every instance derives the same bucket
			// for a given wall-clock minute.
			now := time.Now().UTC()
			window := now.Truncate(dbRateLimitWindow)

			allowed, err := d.db.HitRateLimit(r.Context(), key, window, d.limit)
			if err != nil {
				// Fail open — see the type documentation for the rationale.
				logger.Warn("cluster-wide rate limit check failed, allowing request",
					"key", maskKey(key), "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				retryAfter := int(time.Until(window.Add(dbRateLimitWindow)).Seconds()) + 1
				logger.Warn("cluster-wide rate limit exceeded", "key", maskKey(key))
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate_limit_exceeded","message":"too many requests"}`)) // #nosec G104
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

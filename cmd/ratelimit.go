// Rate-limit key functions and ceilings wired by runServer. The limiters
// themselves live in internal/middleware; this file holds the cmd-level keys
// (which know about form fields and username validation bounds) and the
// readiness ceiling the wiring test locks onto.
package cmd

import (
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/validators"
)

// healthReadyRateLimitPerMinute bounds unauthenticated /health/ready requests
// per source IP (see healthLimiter in runServer for the rationale). Exported
// scope: package-level so the wiring test references the same value the
// server uses instead of duplicating the number.
const healthReadyRateLimitPerMinute = 120

// emptyUsernameRateLimitKey is the shared rate-limit bucket for login attempts
// that carry no username, or one that is too long to be a valid username. It
// is not a valid username (ValidateUsername requires ≥3 chars starting with a
// letter, and at most MaxUsernameLength bytes), so it cannot collide with a
// real account.
const emptyUsernameRateLimitKey = "<empty-username>"

// loginUsernameKey returns the attempted login username (lowercased and
// trimmed) so the per-username rate-limit bucket is shared across casing
// variants and surrounding whitespace.
//
// An empty username maps to a dedicated sentinel bucket (m35) so that requests
// with no username do not bypass the per-username rate limiter —
// RateLimiter.Limit skips enforcement when the key is "". The sentinel is not a
// valid username, so it cannot collide with a real account's bucket.
//
// A username longer than MaxUsernameLength bytes also maps to the sentinel.
// Two reasons: such an input cannot name a real account (validation rejects
// it), so it needs no dedicated bucket; and the username is client-controlled
// and used verbatim as the bucket map key — without the bound, an unauthenticated
// caller could grow the limiter's memory by ~1 MiB of distinct keys per request
// (the body limit). The byte-length check runs on the final value, after trim
// and lowercasing, so every stored key is bounded by MaxUsernameLength bytes
// regardless of how the transformations reshape the input.
func loginUsernameKey(r *http.Request) string {
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	if username == "" || len(username) > validators.MaxUsernameLength {
		return emptyUsernameRateLimitKey
	}
	return username
}

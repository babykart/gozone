// Rate-limit key functions and ceilings wired by runServer. The limiters
// themselves live in internal/middleware; this file holds the cmd-level keys
// (which know about form fields, client IP resolution and username validation
// bounds) and the readiness ceiling the wiring test locks onto.
//
// The login limiters use three key families, every key namespaced by a
// family prefix (see below): the per-IP family ("login:ip:"), the
// per-(username, IP) pair family ("login:pair:") and the global per-username
// family ("login:user:").
package cmd

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/middleware"
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

// loginMaxKeyBytes is the hard cap on any composed login rate-limit key. The
// IP half of a key is client-influenced (IPv6 zone ids, unparseable
// RemoteAddr fallbacks that ExtractIP returns verbatim), and every login
// limiter family — in-process and cluster-wide — stores its counters under
// these keys (the DB families in rate_limit_counters.bucket_key, a MySQL
// VARCHAR(191)). Bounding every stored key at 160 bytes keeps the worst
// case (prefix + IPv6 zone id + malformed fallback) comfortably inside that
// column; anything longer folds to a family-prefixed sentinel instead of
// being used verbatim.
const loginMaxKeyBytes = 160

// Login rate-limit bucket-key family prefixes. All three families share the
// rate_limit_counters bucket_key namespace, so the raw key material must
// never overlap across families: before the prefixes, a crafted username
// such as "192.0.2.1" drew from the same DB bucket as a real client
// connecting from 192.0.2.1, letting one family pollute another. The
// disjoint prefixes make the families structurally disjoint regardless of
// what an attacker puts in the username field.
const (
	loginIPFamilyPrefix   = "login:ip:"
	loginPairFamilyPrefix = "login:pair:"
	loginUserFamilyPrefix = "login:user:"
)

// boundLoginKey joins key material onto its family prefix, folding anything
// past loginMaxKeyBytes to the family's oversized sentinel. The sentinel is
// family-prefixed too, so folded keys stay disjoint across families and the
// cap holds even for the fold itself.
func boundLoginKey(familyPrefix, key, oversizedSentinel string) string {
	if len(familyPrefix)+len(key) > loginMaxKeyBytes {
		return familyPrefix + oversizedSentinel
	}
	return familyPrefix + key
}

// loginIPKey returns the per-IP family key: the resolved client IP under the
// "login:ip:" prefix. /login, the OIDC login/callback routes and the
// cluster-wide DB counterpart all key on this, so every per-IP login bucket
// draws from the same namespaced key regardless of which route was hit.
func loginIPKey(r *http.Request) string {
	return boundLoginKey(loginIPFamilyPrefix, middleware.ExtractIP(r), "<oversized-ip>")
}

// loginUserIPKey returns the per-(username, IP) pair family key:
// "login:pair:" + byte-length of the username + ":" + username + "|" + IP.
// Keying the per-username limiter on the pair (instead of the username
// alone, the previous behaviour) stops one attacker IP from exhausting the shared
// per-username bucket and 429-ing the legitimate owner of that account for
// everyone: each (username, IP) combination gets its own bucket. The
// username part reuses loginUsernameKey verbatim (lowercased, trimmed,
// sentinel for empty/over-long), so casing and whitespace variants of the
// same attempt share a bucket, and the byte-length prefix makes the encoding
// injective — a crafted username embedding the "|" separator and a victim IP
// ("admin|192.0.2.1") can no longer reproduce the victim's pair key.
func loginUserIPKey(r *http.Request) string {
	u := loginUsernameKey(r)
	pair := strconv.Itoa(len(u)) + ":" + u + "|" + middleware.ExtractIP(r)
	return boundLoginKey(loginPairFamilyPrefix, pair, "<oversized-key>")
}

// loginUserKey returns the global per-username family key: "login:user:" +
// the attempted username. Unlike the pair key it deliberately ignores the
// source IP — it is the fleet-wide, deliberately generous ceiling (default
// 60/min) on attempts at a single targeted username across ALL source IPs,
// bounding distributed brute-force that rotates IPs to dodge the per-IP and
// pair buckets. It can never exceed the cap (prefix + at most
// MaxUsernameLength bytes), so it never folds.
func loginUserKey(r *http.Request) string {
	return loginUserFamilyPrefix + loginUsernameKey(r)
}

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
// "login:ip:" prefix. POST /login and the cluster-wide DB counterpart all key
// on this, so every per-IP login bucket draws from the same namespaced key
// regardless of which layer counted the hit. The OIDC login/callback routes
// do NOT draw from this family anymore — they have their own dedicated
// "sso:ip:" family (see ssoIPKey).
func loginIPKey(r *http.Request) string {
	return boundLoginKey(loginIPFamilyPrefix, middleware.ExtractIP(r), "<oversized-ip>")
}

// ssoIPFamilyPrefix is the dedicated SSO per-IP family prefix. Like the login
// families it stores counters in the shared rate_limit_counters bucket_key
// namespace, so the disjoint prefix keeps SSO buckets structurally separate
// from "login:ip:" no matter what a client puts in the request.
const ssoIPFamilyPrefix = "sso:ip:"

// ssoIPKey returns the dedicated SSO per-IP family key: "sso:ip:" + the
// resolved client IP, bounded like the login keys. The OIDC login and
// callback routes draw from THIS budget, not the /login one: a single SSO
// sign-in costs two route hits (redirect + callback) and SSO traffic behind a
// shared egress address must not exhaust the password-login brute-force
// budget (nor be exhausted by it).
func ssoIPKey(r *http.Request) string {
	return boundLoginKey(ssoIPFamilyPrefix, middleware.ExtractIP(r), "<oversized-ip>")
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

// Change-password rate-limit bucket-key family prefixes. Both families share
// the rate_limit_counters bucket_key namespace with the login families, so
// the "chpw:" prefix keeps the raw key material structurally disjoint from
// "login:ip:" / "login:pair:" / "login:user:" no matter what a username
// looks like.
const (
	chgPairFamilyPrefix = "chpw:pair:"
	chgUserFamilyPrefix = "chpw:user:"
)

// changePasswordUserKey returns the authenticated session user's username,
// or "" when the request carries no user. POST /change-password sits behind
// the auth middleware, so a request without a user never reaches these
// limiters in production; the empty key makes RateLimiter.Limit skip
// enforcement (same sentinel convention as the login family).
func changePasswordUserKey(r *http.Request) string {
	if u := middleware.GetUser(r); u != nil {
		return u.Username
	}
	return ""
}

// changePasswordUserIPKey returns the per-(user, IP) pair family key:
// "chpw:pair:" + byte-length of the username + ":" + username + "|" + IP.
// The pair bucket (rather than a per-IP bucket) keeps one user's retry burst
// from 429-ing another user behind the same NAT address, and the byte-length
// prefix keeps the encoding injective (same reasoning as loginUserIPKey).
func changePasswordUserIPKey(r *http.Request) string {
	u := changePasswordUserKey(r)
	if u == "" {
		return ""
	}
	pair := strconv.Itoa(len(u)) + ":" + u + "|" + middleware.ExtractIP(r)
	return boundLoginKey(chgPairFamilyPrefix, pair, "<oversized-key>")
}

// changePasswordUserGlobalKey returns the global per-user family key:
// "chpw:user:" + username. IP-independent: bounds distributed guessing of
// the current password for ONE account across rotated source addresses.
// Usernames are validated at creation and bounded by MaxUsernameLength, so
// the key never exceeds loginMaxKeyBytes and never folds.
func changePasswordUserGlobalKey(r *http.Request) string {
	u := changePasswordUserKey(r)
	if u == "" {
		return ""
	}
	return chgUserFamilyPrefix + u
}

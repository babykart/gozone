package middleware

import (
	"context"
	"net/http"
	"strings"
)

// httpsCtxKey is the context key under which the HTTPS resolver stores the
// resolved effective-HTTPS flag. It is unexported so only WithHTTPS/IsHTTPS
// (and the resolver that calls WithHTTPS) can touch it.
type httpsCtxKey struct{}

// WithHTTPS returns r carrying the resolver-computed effective-HTTPS flag in
// its context. It is set by the HTTPS resolver middleware installed in the
// global request stack (cmd/server.go), which honours X-Forwarded-Proto only when
// the direct TCP connection comes from a configured trusted proxy (m40/M-SEC4).
func WithHTTPS(r *http.Request, https bool) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), httpsCtxKey{}, https))
}

// IsHTTPS reports whether the request is effectively served over HTTPS.
//
// Resolution order:
//  1. r.TLS != nil → the underlying transport is genuinely TLS. net/http sets
//     this from the actual handshake, so it is not header-spoofable.
//  2. A value stashed by the HTTPS resolver middleware → the trusted-proxy-gated
//     X-Forwarded-Proto decision (see WithHTTPS). The resolver honours
//     X-Forwarded-Proto only when r.RemoteAddr is itself a trusted proxy
//     (mirroring M-SEC4), so a direct-access attacker cannot inject the header
//     to force HSTS (SecurityHeaders) or the Secure cookie flag (isSecure) over
//     plain HTTP (m40).
//  3. Otherwise false — fail-closed. X-Forwarded-Proto is never trusted without
//     an explicit trust gate.
func IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if v, ok := r.Context().Value(httpsCtxKey{}).(bool); ok {
		return v
	}
	return false
}

// ForwardedProtoIsHTTPS reports whether the leftmost X-Forwarded-Proto value is
// "https" (case-insensitive), tolerating multi-hop comma-separated chains
// ("https, http") where the leftmost value is the original client's protocol.
//
// Callers MUST gate this on the direct TCP connection being a trusted proxy:
// the header is client-supplied and trivially spoofable. This function performs
// NO trust check — it only parses the value. The resolver middleware in
// cmd/server.go calls it after the M-SEC4-style RemoteAddr ∈ trustedProxies gate.
func ForwardedProtoIsHTTPS(header string) bool {
	if header == "" {
		return false
	}
	if i := strings.IndexByte(header, ','); i >= 0 {
		header = header[:i]
	}
	return strings.EqualFold(strings.TrimSpace(header), "https")
}

// permissionsPolicy denies the powerful device/browser features GoZone never
// uses (it is a DNS admin panel — no media capture, no location, no sensors, no
// payments, no USB). Locking them down hardens the page against a future XSS
// or rogue dependency that would otherwise be able to request them. Features
// with benign uses (fullscreen, sync-xhr, picture-in-picture) are deliberately
// left alone. (REVIEW.md I-5.)
const permissionsPolicy = "accelerometer=(), ambient-light-sensor=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"

// SecurityHeaders adds common HTTP security headers to all responses.
//
// Headers added:
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'
//   - Permissions-Policy: accelerometer=(), ambient-light-sensor=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains (only over HTTPS)
//
// Note: X-XSS-Protection is intentionally omitted (m39). The header is
// deprecated (the Auditor was removed from Chrome/Edge and never shipped in
// Firefox; it was known to introduce cross-site information leaks). The strong
// CSP above — script-src 'self' with no 'unsafe-inline' — is the modern,
// robust XSS mitigation. An explicit "0" is unnecessary since modern browsers
// no longer act on this header and the application does not support legacy
// user agents that ship a non-default Auditor.
//
// Strict-Transport-Security intentionally omits "preload" (REVIEW.md I-5):
// preload is an opt-in to the browser HSTS preload list (hstspreload.org) and is
// effectively irreversible for the apex domain — it forces HTTPS for all
// subdomains for years even if TLS is later removed. It must only be added by
// an operator who owns the domain, has submitted it to the preload list, and is
// certain every subdomain serves HTTPS. Adding it unconditionally here would
// risk bricking a deployment. max-age + includeSubDomains is the safe default.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", permissionsPolicy)

		if IsHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

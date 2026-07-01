package middleware

import (
	"net/http"
	"strings"
)

// IsHTTPS reports whether the request was made over HTTPS, either via direct
// TLS or via the X-Forwarded-Proto header set by a trusted reverse proxy.
//
// In a multi-hop proxy chain each proxy appends to X-Forwarded-Proto, so the
// header may be "https, http" (HTTPS client → internal HTTP hop). The leftmost
// value is the original client's protocol; this function checks that value
// rather than comparing the whole header (m6 — strict equality broke
// multi-hop chains).
func IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		return false
	}
	if i := strings.IndexByte(proto, ','); i >= 0 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// SecurityHeaders adds common HTTP security headers to all responses.
//
// Headers added:
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains (only over HTTPS)
//
// Note: X-XSS-Protection is intentionally omitted (m39). The header is
// deprecated (the Auditor was removed from Chrome/Edge and never shipped in
// Firefox; it was known to introduce cross-site information leaks). The strong
// CSP above — script-src 'self' with no 'unsafe-inline' — is the modern,
// robust XSS mitigation. An explicit "0" is unnecessary since modern browsers
// no longer act on this header and the application does not support legacy
// user agents that ship a non-default Auditor.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")

		if IsHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

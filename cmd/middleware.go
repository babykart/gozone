// cmd-level HTTP middlewares wired by runServer ahead of the shared
// internal/middleware stack: request logging, trusted-proxy-gated client-IP
// resolution (X-Forwarded-For) and the effective-HTTPS resolver that
// SecurityHeaders and the Secure cookie flags read.
package cmd

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
)

// requestLogger logs each HTTP request. It uses r.URL.Path instead of
// r.RequestURI to avoid leaking query-string secrets (e.g., API keys) into logs.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wr := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wr, r)
		remote := chimw.GetClientIP(r.Context())
		if remote == "" {
			remote = r.RemoteAddr
		}
		logger.Info("request",
			"request_id", chimw.GetReqID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", wr.Status(),
			"duration", time.Since(start).String(),
			"remote", remote,
		)
	})
}

// parseTrustedProxies validates every server.trusted_proxies entry and
// returns the parsed prefixes. Entries must be CIDR prefixes; a bare IP (a
// frequent operator typo) fails with an actionable message instead of the
// netip.MustParsePrefix panic this used to hit at startup. The error surfaces
// through runServer, so a typo yields a clean startup failure with guidance.
func parseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, len(entries))
	for i, entry := range entries {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("entry %d (%q) is not a CIDR prefix — use \"10.0.0.1/32\" for a single host or \"10.0.0.0/8\" for a range (IPv6: \"2001:db8::1/128\"): %w", i+1, entry, err)
		}
		prefixes[i] = p
	}
	return prefixes, nil
}

// clientIPMiddleware returns chi middleware that resolves the client IP into
// the request context without mutating r.RemoteAddr. When server.trusted_proxies
// is empty the middleware keys strictly off the TCP source address (fail-closed
// against XFF/Real-IP spoofing); otherwise it walks XFF right-to-left and
// stops at the first entry that does not fall within a trusted CIDR.
//
// M-SEC4: XFF is honoured ONLY when the direct TCP connection (r.RemoteAddr)
// itself arrives from a trusted proxy. Without this check an attacker with
// direct access to the server could inject X-Forwarded-For to rotate
// rate-limit buckets even though trusted_proxies is configured.
//
// trustedProxies carries the raw configured entries (chi's ClientIPFromXFF
// takes strings) and prefixes their parsed form — both come from
// parseTrustedProxies, called once in runServer, so no parsing happens here.
func clientIPMiddleware(trustedProxies []string, prefixes []netip.Prefix) func(http.Handler) http.Handler {
	if len(trustedProxies) == 0 {
		return chimw.ClientIPFromRemoteAddr
	}

	return func(h http.Handler) http.Handler {
		// Pre-wrap with both strategies so we can switch per-request without
		// re-wrapping on every request.
		xff := chimw.ClientIPFromXFF(trustedProxies...)(h)
		remote := chimw.ClientIPFromRemoteAddr(h)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr // RemoteAddr may be a bare IP (e.g. in tests).
			}
			if ip, err := netip.ParseAddr(host); err == nil && trustedProxy(ip.Unmap(), prefixes) {
				xff.ServeHTTP(w, r)
				return
			}
			// Direct connection is NOT a trusted proxy — ignore XFF entirely.
			remote.ServeHTTP(w, r)
		})
	}
}

// trustedProxy reports whether ip falls within any of the configured trusted
// proxy CIDR prefixes.
func trustedProxy(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// httpsResolverMiddleware resolves the effective HTTPS status of each request
// and stashes it in the request context (via middleware.WithHTTPS) so that
// IsHTTPS — used by SecurityHeaders (HSTS), the CSRF plaintext gate and
// isSecure (Secure cookie flag) — reads a trusted value instead of a raw,
// client-supplied header.
//
// m40 / M-SEC4: X-Forwarded-Proto is honoured ONLY when the direct TCP
// connection (r.RemoteAddr) itself arrives from a configured trusted proxy.
// Without this gate a direct-access attacker could inject
// X-Forwarded-Proto: https over plain HTTP to force HSTS and mark the session
// cookie Secure (which a browser would then refuse to send back over the
// attacker's plain-HTTP connection is not the risk — the risk is the server
// believing the session is protected when it is not, plus HSTS pinning). When
// trusted_proxies is empty, X-Forwarded-Proto is ignored entirely and only a
// genuine r.TLS connection counts.
//
// prefixes comes from parseTrustedProxies (runServer validates once at
// startup); no parsing happens here.
func httpsResolverMiddleware(prefixes []netip.Prefix) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			https := r.TLS != nil
			if !https && len(prefixes) > 0 {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					host = r.RemoteAddr // RemoteAddr may be a bare IP (e.g. in tests).
				}
				if ip, perr := netip.ParseAddr(host); perr == nil && trustedProxy(ip.Unmap(), prefixes) {
					https = middleware.ForwardedProtoIsHTTPS(r.Header.Get("X-Forwarded-Proto"))
				}
			}
			h.ServeHTTP(w, middleware.WithHTTPS(r, https))
		})
	}
}

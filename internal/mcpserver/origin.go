package mcpserver

import (
	"net/http"
	"strings"
)

// originGuard enforces the Streamable HTTP spec's DNS-rebinding protection:
// a browser may only reach the MCP endpoint from a explicitly allowed
// origin. Non-browser clients (the common case — the API key travels in a
// header, not a cookie) send no Origin header and always pass. An empty
// allow-list rejects every request that carries an Origin at all, so
// enabling the endpoint without configuring origins is fail-closed for
// browser contexts while leaving CLI/agent clients unaffected.
type originGuard struct {
	allowed map[string]struct{}
}

func newOriginGuard(allowed []string) *originGuard {
	m := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		// Origins are compared exactly (scheme://host[:port], lowercased);
		// the config layer already rejected entries with a path.
		m[strings.ToLower(strings.TrimSpace(o))] = struct{}{}
	}
	return &originGuard{allowed: m}
}

// Wrap returns a handler that rejects disallowed Origins with 403 before
// the wrapped handler runs.
func (g *originGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := g.allowed[strings.ToLower(origin)]; !ok {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

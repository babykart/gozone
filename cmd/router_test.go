package cmd

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/handlers"
)

// TestRoutePrefixesCoveredByReservedMCPList locks the overlap invariant
// between the MCP endpoint path and the routing table: every first-level
// prefix the production router mounts must appear in
// config.ReservedMCPRoutePrefixes, so validateMCP rejects any mcp.path that
// would shadow a route tree. It walks the router built by buildRouter — the
// exact handler runServer serves — so a route added later without extending
// the reserved list fails here instead of silently depending on mcp.path
// for its reachability.
func TestRoutePrefixesCoveredByReservedMCPList(t *testing.T) {
	cfg := config.DefaultConfig()
	// Load() normally derives these from the secret key; csrf.Protect
	// requires a 32-byte key at construction time.
	cfg.Server.JWTKey = make([]byte, 32)
	cfg.Server.CSRFKey = make([]byte, 32)
	cfg.MCP.Enabled = true

	handler, cleanup := buildRouter(cfg, nil, &handlers.Handler{}, nil)
	defer cleanup()

	mux, ok := handler.(*chi.Mux)
	if !ok {
		t.Fatalf("buildRouter must return a *chi.Mux so tests can walk it, got %T", handler)
	}

	reserved := map[string]bool{}
	for _, p := range config.ReservedMCPRoutePrefixes {
		reserved[p] = true
	}

	// firstLevelPrefix maps a route pattern to its first path segment:
	// "/" for the root, "/api" for "/api/v1/zones", the full pattern for a
	// single-segment route like "/favicon.ico".
	firstLevelPrefix := func(route string) string {
		if route == "/" {
			return "/"
		}
		if i := strings.Index(route[1:], "/"); i >= 0 {
			return route[:i+1]
		}
		return route
	}

	seen := map[string]bool{}
	var prefixes []string
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		prefix := firstLevelPrefix(route)
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
		// The configured MCP path is legitimately mounted and cannot overlap
		// itself; everything else must be reserved.
		if prefix != cfg.MCP.Path && !reserved[prefix] {
			t.Errorf("route %s mounts under first-level prefix %s, missing from config.ReservedMCPRoutePrefixes — an mcp.path there would shadow it", route, prefix)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the walk must find a meaningful set of prefixes, otherwise the
	// lock is vacuous.
	if len(prefixes) < 10 {
		t.Fatalf("walked only %d first-level prefixes (%v) — the invariant lock is vacuous", len(prefixes), prefixes)
	}
	t.Logf("verified %d first-level route prefixes are covered by the reserved list", len(prefixes))
}

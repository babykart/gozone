package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/middleware"
)

// hasMiddleware reports whether target appears in middlewares, comparing by
// function code pointer — the exact value r.Use(middleware.RequireAdmin) stores.
func hasMiddleware(middlewares []func(http.Handler) http.Handler, target func(http.Handler) http.Handler) bool {
	want := reflect.ValueOf(target).Pointer()
	for _, mw := range middlewares {
		if reflect.ValueOf(mw).Pointer() == want {
			return true
		}
	}
	return false
}

// TestAdminRoutesProtectedByRequireAdmin locks the B-5 property: every route
// registered by mountAdminRoutes must carry middleware.RequireAdmin in its
// middleware chain. A routing refactor that moves an admin handler outside the
// RequireAdmin group (or drops the r.Use) makes this test fail. It walks the
// real chi router built by mountAdminRoutes — the single source of truth used
// by runServer — so it verifies the production wiring rather than a copy.
func TestAdminRoutesProtectedByRequireAdmin(t *testing.T) {
	r := chi.NewRouter()
	// A zero-value Handler is fine: routes are walked, never invoked, so the
	// bound method values are never called. db=nil is safe because
	// CheckZoneAccess only captures it in a closure used at request time.
	mountAdminRoutes(r, &handlers.Handler{}, nil)

	var checked int
	err := chi.Walk(r, func(method, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		checked++
		if !hasMiddleware(middlewares, middleware.RequireAdmin) {
			return fmt.Errorf("%s %s is not protected by middleware.RequireAdmin (admin route escaped the RequireAdmin group)", method, route)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: mountAdminRoutes must register a meaningful number of admin
	// routes — a regression that registers none would otherwise pass vacuously.
	if checked == 0 {
		t.Fatal("walked 0 admin routes — mountAdminRoutes registered nothing (B-5 lock is vacuous)")
	}
	t.Logf("verified %d admin routes are guarded by RequireAdmin", checked)
}

// TestMCPRouteMounting locks the MCP endpoint wiring: when mcp.enabled is
// true the route exists and sits behind middleware.APIKeyAuth (a request
// without an API key gets the middleware's 401 envelope, never reaching the
// MCP handler); when disabled the route must not be mounted at all (404, not
// a refusal). Driving the real router verifies the production wiring.
func TestMCPRouteMounting(t *testing.T) {
	build := func(enabled bool) http.Handler {
		r := chi.NewRouter()
		cfg := config.DefaultConfig()
		cfg.MCP.Enabled = enabled
		ip := middleware.NewRateLimiter(300)
		defer ip.Close()
		perKey := middleware.NewRateLimiter(100)
		defer perKey.Close()
		mountMCPRoute(r, &handlers.Handler{Ops: dnsops.New(nil, nil)}, nil, cfg, ip, perKey)
		return r
	}

	// Enabled: the route is mounted and the API-key gate fires first — an
	// unauthenticated POST gets 401 (APIKeyAuth), proving the middleware
	// order; it must not 404 (route missing) nor 200 (gate bypassed).
	w := httptest.NewRecorder()
	build(true).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("enabled /mcp without an API key: got %d, want 401 (route mounted + APIKeyAuth in the chain)", w.Code)
	}

	// Disabled: not mounted at all — 404 from the router's NotFound handler.
	w = httptest.NewRecorder()
	build(false).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`)))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled /mcp: got %d, want 404 (route must not be mounted)", w.Code)
	}
}

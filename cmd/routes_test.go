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
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
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

// TestAPIKeyScopeSurfaceRouting drives the production /api/v1 and /mcp
// middleware composition with real API keys to lock the surface split:
// an mcp:* key is refused on /api/v1, an api:* key on /mcp (both
// API_KEY_SCOPE_MISMATCH), an api:read key passes GET but is stopped by
// RequireWriteScope on POST (INSUFFICIENT_SCOPE), and api:write passes.
// The IP limiter always runs before auth (TestAPIRateLimitRunsBeforeAuth
// pins that order on this same composition).
func TestAPIKeyScopeSurfaceRouting(t *testing.T) {
	db := testutil.NewTestDB(t)
	userID := testutil.SeedTestUser(t, db, "routeruser", "pass", "user", true)
	testutil.SeedTestAPIKeyScope(t, db, userID, "api-write-key", nil, models.ScopeAPIWrite)
	testutil.SeedTestAPIKeyScope(t, db, userID, "api-read-key", nil, models.ScopeAPIRead)
	testutil.SeedTestAPIKeyScope(t, db, userID, "mcp-read-key", nil, models.ScopeMCPRead)

	ipLimiter := middleware.NewRateLimiter(300)
	t.Cleanup(ipLimiter.Close)
	keyLimiter := middleware.NewRateLimiter(100)
	t.Cleanup(keyLimiter.Close)

	r := chi.NewRouter()

	// Same composition as the /api/v1 mount in buildRouter.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(ipLimiter.Limit(middleware.ExtractIP))
		r.Use(middleware.APIKeyAuth(db, models.SurfaceAPI))
		r.Use(keyLimiter.Limit(middleware.ExtractAPIKey))
		r.Use(middleware.RequireWriteScope)
		r.Get("/zones", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		r.Post("/zones/{zone_id}/records", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	// Same wiring as mountMCPRoute (route gated by APIKeyAuth on SurfaceMCP).
	cfg := config.DefaultConfig()
	cfg.MCP.Enabled = true
	mountMCPRoute(r, &handlers.Handler{Ops: dnsops.New(nil, nil)}, db, cfg, ipLimiter, keyLimiter)

	do := func(method, path, key string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Header.Set("X-API-Key", key)
		r.ServeHTTP(w, req)
		return w
	}

	if w := do(http.MethodGet, "/api/v1/zones", "mcp-read-key"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "api_key_wrong_surface") {
		t.Errorf("mcp key on /api/v1: got %d %s, want 403 api_key_wrong_surface", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/mcp", "api-write-key"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "api_key_wrong_surface") {
		t.Errorf("api key on /mcp: got %d %s, want 403 api_key_wrong_surface", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/api/v1/zones/z1/records", "api-read-key"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "insufficient_scope") {
		t.Errorf("api:read POST records: got %d %s, want 403 insufficient_scope", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/api/v1/zones", "api-read-key"); w.Code != http.StatusOK {
		t.Errorf("api:read GET zones: got %d (%s), want 200", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/api/v1/zones", "api-write-key"); w.Code != http.StatusOK {
		t.Errorf("api:write GET zones: got %d (%s), want 200", w.Code, w.Body.String())
	}
}

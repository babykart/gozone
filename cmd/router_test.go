package cmd

import (
	"html"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
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

// loginChainMiddlewareCount builds the production router with the given
// global per-username ceiling and returns the number of middlewares mounted
// on POST /login (-1 when the route is missing).
func loginChainMiddlewareCount(globalKnob int) int {
	cfg := config.DefaultConfig()
	cfg.Server.JWTKey = make([]byte, 32)
	cfg.Server.CSRFKey = make([]byte, 32)
	cfg.LoginLock.UsernameGlobalRateLimitPerMinute = globalKnob

	handler, cleanup := buildRouter(cfg, nil, &handlers.Handler{}, nil)
	defer cleanup()

	mux, ok := handler.(*chi.Mux)
	if !ok {
		return -1
	}
	n := -1
	_ = chi.Walk(mux, func(method, route string, _ http.Handler, mw ...func(http.Handler) http.Handler) error {
		if method == http.MethodPost && route == "/login" {
			n = len(mw)
		}
		return nil
	})
	return n
}

// TestLoginChainGlobalUserLimitersWiring locks the route-level wiring of the
// new global per-username ceiling: with login_lock.username_global_rate_limit_per_minute
// > 0, BOTH global limiters (in-process + cluster-wide DB counterpart) join
// the POST /login chain; with the knob at 0 both are absent. The pair
// limiters are present in both configurations (their own knob defaults to 5),
// so the observed delta isolates the global pair exactly.
func TestLoginChainGlobalUserLimitersWiring(t *testing.T) {
	off := loginChainMiddlewareCount(0)
	if off < 0 {
		t.Fatal("POST /login route not found in the production router")
	}
	on := loginChainMiddlewareCount(60)
	if on != off+2 {
		t.Errorf("POST /login middleware count with global knob=60 is %d, want %d (knob off) + 2 (in-memory + DB global limiters); knob=0 must remove BOTH global limiters from the chain",
			on, off)
	}
}

// csrfTokenInputRe extracts the gorilla/csrf form token from a rendered page
// (the stub login page below emits exactly this input).
var csrfTokenInputRe = regexp.MustCompile(`name="gorilla\.csrf\.Token" value="([^"]+)"`)

// changePasswordTestTemplates is the minimal stub template set for driving
// GET /login (CSRF-token bootstrap; the stub renders the token input a real
// browser form would carry) and POST /change-password (the 400 error page the
// handler renders for a wrong current password) through the production router.
func changePasswordTestTemplates() *template.Template {
	return template.Must(template.New("test").Parse(`
{{define "login.html"}}<html><body><form method="post" action="/login"><input type="hidden" name="gorilla.csrf.Token" value="{{ .CSRFToken }}"></form></body></html>{{end}}
{{define "error.html"}}ERROR: {{ .Message }}{{end}}
`))
}

// setupChangePasswordRouter builds the production router (buildRouter) over an
// in-memory DB seeded with two users ("alice", "bob") and returns a POST
// helper per user. Each helper carries a real session JWT (minted with the
// cfg key, so the Auth middleware's revocation/credential-version checks run
// for real) plus the CSRF cookie and form token bootstrapped from GET /login,
// exactly like a browser. Submissions use a wrong current password, so the
// handler is reached (400 "Current password is incorrect") without the
// credential_version bump a successful change would trigger — the session
// stays valid across all attempts.
func setupChangePasswordRouter(t *testing.T) map[string]func(remoteAddr string) int {
	t.Helper()

	db := testutil.NewTestDB(t)
	cfg := config.DefaultConfig()
	// csrf.Protect requires a 32-byte key at construction time (Load() would
	// derive these from the secret key).
	cfg.Server.JWTKey = make([]byte, 32)
	cfg.Server.CSRFKey = make([]byte, 32)

	h := &handlers.Handler{
		DB:   db,
		Cfg:  cfg,
		Tmpl: changePasswordTestTemplates(),
	}
	router, cleanup := buildRouter(cfg, db, h, nil)
	t.Cleanup(cleanup)

	// CSRF bootstrap from the public login page (same path a browser takes).
	// The token is not user-bound, so both sessions share the cookie+token.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login: got %d, want 200 (CSRF bootstrap failed)", w.Code)
	}
	var csrfCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookieName {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("GET /login did not set the CSRF cookie (_gorilla_csrf)")
	}
	m := csrfTokenInputRe.FindSubmatch(w.Body.Bytes())
	if m == nil {
		t.Fatal("stub login page did not render the gorilla.csrf.Token input")
	}
	csrfToken := html.UnescapeString(string(m[1]))

	posts := make(map[string]func(remoteAddr string) int)
	for _, username := range []string{"alice", "bob"} {
		id := testutil.SeedTestUser(t, db, username, "CorrectPass1!", "user", true)
		user := &models.User{ID: id, Username: username, Role: "user"}
		jwt, err := middleware.GenerateToken(user, cfg.Server.JWTKey, time.Duration(cfg.Auth.SessionDurationHours)*time.Hour)
		if err != nil {
			t.Fatalf("mint session token for %s: %v", username, err)
		}

		posts[username] = func(remoteAddr string) int {
			form := url.Values{
				"gorilla.csrf.Token": {csrfToken},
				// Wrong current password: the handler answers 400 AFTER the
				// change-password limiters, without
				// bumping credential_version, so the session stays valid.
				"current_password": {"WrongPass1!"},
				// Policy-valid (default policy: 8+ chars, all four classes) so
				// validation passes and the handler reaches the bcrypt compare.
				"new_password":     {"NewPass1!x"},
				"confirm_password": {"NewPass1!x"},
			}
			r := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if remoteAddr != "" {
				r.RemoteAddr = remoteAddr
			}
			r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: jwt})
			r.AddCookie(csrfCookie)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			return w.Code
		}
	}
	return posts
}

// TestChangePasswordPairRateLimit_RouterLevel is the wiring + behaviour test
// for the per-(user, IP) limiter family on POST /change-password
// (5/min, in-memory + cluster-wide DB counterpart): five failed submissions
// from one user+IP must be answered by the handler (400), the sixth must be
// 429, and a SECOND user submitting from the SAME IP must still reach the
// handler (400, not 429) — the pair key isolates their buckets.
func TestChangePasswordPairRateLimit_RouterLevel(t *testing.T) {
	posts := setupChangePasswordRouter(t)
	alice, bob := posts["alice"], posts["bob"]
	const sharedIP = "198.0.2.1:4444"

	// Five failed submissions from (alice, sharedIP): each passes the limiters
	// and reaches the handler, which answers 400 (wrong current password).
	// The first iteration also proves the harness end-to-end: session JWT
	// accepted by Auth, CSRF token accepted, handler reached.
	for i := 0; i < 5; i++ {
		if code := alice(sharedIP); code != http.StatusBadRequest {
			t.Fatalf("alice attempt %d from %s: got %d, want 400 (the handler must be reached before the limit is exhausted; a 303 here means the harness lost auth/CSRF)",
				i+1, sharedIP, code)
		}
	}

	// The sixth submission from the SAME (user, IP) pair must be rejected by
	// the limiter before the handler.
	if code := alice(sharedIP); code != http.StatusTooManyRequests {
		t.Fatalf("alice attempt 6 from %s: got %d, want 429 (per-(user,IP) limiter missing or mis-keyed on POST /change-password)", sharedIP, code)
	}

	// bob from the SAME IP has his own pair bucket: the request must pass the
	// limiter and reach the handler (400), proving the key is per-(user, IP)
	// and not per-IP alone.
	if code := bob(sharedIP); code != http.StatusBadRequest {
		t.Fatalf("bob attempt 1 from the shared IP %s: got %d, want 400 (bob must not inherit alice's exhausted pair bucket)", sharedIP, code)
	}
}

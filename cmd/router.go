package cmd

import (
	"io/fs"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/web"
)

// buildRouter assembles the production HTTP routing table: the global
// middleware stack, the CSRF-protected web UI (public, OIDC and
// authenticated routes), the API-key REST API, health checks, static files
// and the MCP endpoint. Extracted from runServer so tests can walk the
// REAL router and lock routing invariants on it (first-level prefix
// inventory, admin gating, MCP mounting) instead of on a copy that would
// drift.
//
// trustedPrefixes is the parsed server.trusted_proxies CIDR list (validated
// earlier by runServer). The returned cleanup stops the background
// goroutines the rate limiters and session tracker spawn; runServer defers
// it so their lifecycle matches the server's.
func buildRouter(cfg *config.Config, db *database.DB, h *handlers.Handler, trustedPrefixes []netip.Prefix) (http.Handler, func()) {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	// Resolve the client IP into the request context without ever mutating
	// r.RemoteAddr. When trusted_proxies is configured the leftmost XFF entry
	// outside the trusted CIDRs wins; otherwise only the TCP source address is
	// honoured and XFF headers are ignored entirely (fail-closed). The
	// previous chimw.RealIP let a direct-access attacker rotate XFF and obtain
	// a fresh rate-limit bucket per request.
	r.Use(clientIPMiddleware(cfg.Server.TrustedProxies, trustedPrefixes))
	r.Use(requestLogger)
	r.Use(chimw.Compress(5))
	// Resolve the effective HTTPS flag (trusted-proxy-gated) BEFORE
	// SecurityHeaders so HSTS and the Secure cookie flag read a trusted value
	// instead of a raw, spoofable X-Forwarded-Proto header (m40/M-SEC4).
	r.Use(httpsResolverMiddleware(trustedPrefixes))
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.BodyLimit)
	r.Use(middleware.ErrorHandler)

	// CSRF protection for web UI forms.
	//
	// csrf.Secure(false) is intentional: the Secure flag is set per-request by
	// csrfSecureCookieWriter (see below) based on middleware.IsHTTPS(r), so the
	// CSRF and session cookies always agree. The static server.secure_cookies
	// flag is no longer used for CSRF — deriving Secure from the TLS context is
	// strictly more correct.
	csrfMiddleware := csrf.Protect(
		cfg.Server.CSRFKey,
		csrf.Secure(false),
		csrf.Path("/"),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Warn("CSRF validation failed",
				"reason", csrf.FailureReason(r),
				"method", r.Method,
				"path", r.URL.Path,
			)
			http.Redirect(w, r, "/login?error=csrf_invalid", http.StatusSeeOther)
		})),
	)

	// Rate limiters.
	//
	// /login stack (both limiters BEFORE the handler — there is no separate
	// auth step, the handler IS the auth):
	//   loginLimiter (per-IP) → loginUsernameLimiter (per-username) → Login
	// The per-IP limiter catches floods before the form body is even parsed;
	// the per-username limiter prevents distributed brute-force (many IPs,
	// one target). Both must pass.
	//
	// /api stack (IP limiter BEFORE auth, per-key limiter AFTER auth):
	//   apiIPLimiter (per-IP) → APIKeyAuth (DB lookup) → apiLimiter (per-key)
	// The IP limiter is a pre-auth gate so an attacker rotating arbitrary
	// keys cannot flood the DB with SELECT-against-api_keys lookups (M-SEC2).
	// The per-key limiter runs AFTER auth because it needs the authenticated
	// key identity to apply the per-key bucket — it caps authenticated abuse,
	// not DB-flooding. This ordering asymmetry vs /login is intentional:
	// /login has no separate auth middleware, so all limiting is pre-handler;
	// /api splits at the auth boundary.
	loginLimiter := middleware.NewRateLimiter(5)   // 5 requests per minute per IP
	apiLimiter := middleware.NewRateLimiter(100)   // 100 requests per minute per API key (post-auth)
	apiIPLimiter := middleware.NewRateLimiter(300) // 300 requests per minute per IP (pre-auth gate)
	// Cluster-wide counterparts of the login limiters, backed by the shared
	// rate_limit_counters table: every replica draws from the same budget, so
	// the login ceiling no longer scales with the instance count. The
	// in-process limiters stay in front as a cheap pre-DB gate — a flood is
	// absorbed there before it reaches the database. The API and health
	// limiters remain per-instance on purpose: they are anti-flood throttles,
	// and the health limiter must never depend on the database it probes.
	dbLoginIPLimiter := middleware.NewDBRateLimiter(db, 5)
	var dbLoginUserLimiter *middleware.DBRateLimiter
	if cfg.LoginLock.UsernameRateLimitPerMinute > 0 {
		dbLoginUserLimiter = middleware.NewDBRateLimiter(db, cfg.LoginLock.UsernameRateLimitPerMinute)
	}
	// The readiness endpoint is unauthenticated and does real work per hit:
	// a DB ping plus a PowerDNS HTTP call that deliberately bypasses the
	// cache. Without a bound it is an amplification surface (each cheap
	// request forces outbound work) and leaks dependency status to anonymous
	// callers. The ceiling is generous on purpose: one probe per second
	// sustained, which also absorbs several pods' kubelet probes aggregating
	// behind a single node IP. Liveness (/health/live) is deliberately NOT
	// limited: it does no work (constant response) and throttling it could
	// get a healthy container killed during a traffic spike.
	healthLimiter := middleware.NewRateLimiter(healthReadyRateLimitPerMinute)
	var loginUsernameLimiter *middleware.RateLimiter
	if cfg.LoginLock.UsernameRateLimitPerMinute > 0 {
		loginUsernameLimiter = middleware.NewRateLimiter(cfg.LoginLock.UsernameRateLimitPerMinute)
	}

	// Session lifetime policy: idle inactivity timeout and/or an absolute
	// refresh cap. Both default to 0 (disabled) → AuthWithPolicy behaves
	// exactly like the legacy Auth middleware. When either is > 0 a
	// SessionTracker is created to enforce idle/absolute limits and to
	// transparently refresh the access JWT near expiry (sliding the session up
	// to the absolute cap). The tracker state is persisted in the sessions table
	// so multi-instance deployments share the same idle/absolute window; an
	// in-memory cache coarsens writes to keep the hot path cheap.
	accessTTL := time.Duration(cfg.Auth.SessionDurationHours) * time.Hour
	sessionPolicy := middleware.SessionPolicy{
		Idle:      time.Duration(cfg.Auth.IdleTimeoutMinutes) * time.Minute,
		Absolute:  time.Duration(cfg.Auth.AbsoluteSessionTimeoutHours) * time.Hour,
		AccessTTL: accessTTL,
	}
	var sessionTracker *middleware.SessionTracker
	if sessionPolicy.Idle > 0 || sessionPolicy.Absolute > 0 {
		sessionTracker = middleware.NewSessionTracker(db, sessionPolicy)
	}
	authMiddleware := middleware.AuthWithPolicy(db, cfg.Server.JWTKey, sessionTracker, accessTTL)

	// CSRF-protected web UI routes (login + authenticated)
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				https := middleware.IsHTTPS(r)
				if !https {
					r = csrf.PlaintextHTTPRequest(r)
				}
				// Wrap the ResponseWriter so the CSRF cookie's Secure flag
				// tracks IsHTTPS(r) on every response — mirroring the session
				// cookie's Secure: IsHTTPS(r) behaviour.
				sw := &csrfSecureCookieWriter{ResponseWriter: w, https: https}
				next.ServeHTTP(sw, r)
				// Cover the edge case where the handler returned without
				// calling Write/WriteHeader (e.g. a pure redirect that sets
				// only the Location header). applySecureFlag is idempotent.
				sw.applySecureFlag()
			})
		})
		r.Use(csrfMiddleware)

		// Public routes
		r.Get("/login", h.LoginPage)
		// Both limiters run BEFORE the Login handler (no separate auth
		// middleware — see the rate-limiter documentation above for the
		// /login vs /api ordering asymmetry, m7). Each in-process limiter is
		// paired with its cluster-wide DB counterpart: in-memory absorbs
		// floods cheaply, the shared counter caps the real budget across
		// replicas.
		loginChain := []func(http.Handler) http.Handler{
			loginLimiter.Limit(middleware.ExtractIP),
			dbLoginIPLimiter.Limit(middleware.ExtractIP),
		}
		if loginUsernameLimiter != nil {
			loginChain = append(loginChain, loginUsernameLimiter.Limit(loginUsernameKey))
		}
		if dbLoginUserLimiter != nil {
			loginChain = append(loginChain, dbLoginUserLimiter.Limit(loginUsernameKey))
		}
		r.With(loginChain...).Post("/login", h.Login)

		// OpenID Connect / OAuth2 SSO endpoints. These are public (the user
		// is not authenticated yet): the login endpoint redirects to the IdP,
		// and the callback completes the flow and establishes a session. They
		// share the login rate limiters to throttle callback brute-forcing of
		// the state parameter (ROADMAP "Security").
		r.With(loginLimiter.Limit(middleware.ExtractIP),
			dbLoginIPLimiter.Limit(middleware.ExtractIP)).
			Get("/auth/oidc/{provider}/login", h.OIDCLogin)
		r.With(loginLimiter.Limit(middleware.ExtractIP),
			dbLoginIPLimiter.Limit(middleware.ExtractIP)).
			Get("/auth/oidc/{provider}/callback", h.OIDCCallback)

		// Authenticated routes (web UI)
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware)

			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			})
			r.Get("/dashboard", h.Dashboard)
			r.Get("/activity", h.ActivityPage)
			r.Post("/logout", h.Logout)
			r.Get("/profile", h.ProfilePage)
			r.Get("/change-password", h.ChangePasswordPage)
			r.Post("/change-password", h.ChangePassword)
			r.Get("/profile/api-keys", h.ListAPIKeys)
			r.Post("/profile/api-keys/create", h.CreateAPIKey)
			r.Post("/profile/api-keys/delete", h.DeleteAPIKey)
			r.Post("/profile/api-keys/bulk-delete", h.BulkDeleteAPIKeys)

			// Zones list (filtered by group membership for non-admin users)
			r.Get("/zones", h.ListZones)

			// Zone-specific routes with group authorization
			r.Group(func(r chi.Router) {
				r.Use(middleware.CheckZoneAccess(db))

				r.Get("/zones/{zone_id}", h.ViewZone)
				r.Get("/zones/{zone_id}/export", h.ExportZone)
				r.Post("/zones/{zone_id}/apply-template", h.ApplyTemplateToZone)

				r.Get("/zones/{zone_id}/records/new", h.CreateRecordPage)
				r.Post("/zones/{zone_id}/records/create", h.CreateRecord)
				r.Post("/zones/{zone_id}/records/batch-create", h.BatchCreateRecords)
				r.Get("/zones/{zone_id}/records/edit", h.EditRecordPage)
				r.Post("/zones/{zone_id}/records/update", h.UpdateRecord)
				r.Post("/zones/{zone_id}/records/inline-update", h.InlineUpdateRecord)
				r.Post("/zones/{zone_id}/records/delete", h.DeleteRecord)
				r.Post("/zones/{zone_id}/records/bulk-delete", h.BulkDeleteRecords)
				r.Post("/zones/{zone_id}/import", h.ImportZone)
			})

			// Admin-only routes — mounted via mountAdminRoutes so the admin
			// routing table has a single source of truth that a test can walk
			// and lock (every admin route must stay inside RequireAdmin).
			mountAdminRoutes(r, h, db)
		})
	})

	// Static files (no CSRF)
	staticFS, err := fs.Sub(web.FS, "static")
	if err != nil {
		// Unreachable in practice: "static" is embedded at build time. The
		// router cannot serve without it, and returning an error would change
		// the signature for a can't-happen — fail loudly instead.
		logger.Fatal("open embedded static files", "error", err)
	}
	fileServer(r, "/static", http.FS(staticFS))

	// Favicon at root — browsers request /favicon.ico, not /static/favicon.ico
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := web.FS.ReadFile("static/favicon.ico")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		// Cache aggressively — favicon changes rarely
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data) // #nosec G104
	})

	// API routes (API key auth, no CSRF)
	r.Route("/api/v1", func(r chi.Router) {
		// IP-based rate limit BEFORE auth so key-rotation floods hit the limiter
		// before any DB lookup (M-SEC2). The per-key limiter runs after auth.
		r.Use(apiIPLimiter.Limit(middleware.ExtractIP))
		r.Use(middleware.APIKeyAuth(db))
		r.Use(apiLimiter.Limit(middleware.ExtractAPIKey))

		r.Get("/zones", h.APIListZones)
		r.Get("/stats", h.APIStats)

		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)

			r.Post("/zones", h.APICreateZone)
			r.Delete("/zones/{zone_id}", h.APIDeleteZone)
		})

		r.Group(func(r chi.Router) {
			r.Use(middleware.CheckZoneAccess(db))

			r.Get("/zones/{zone_id}", h.APIGetZone)
			r.Get("/zones/{zone_id}/records", h.APIListRecords)
			r.Get("/zones/{zone_id}/export", h.APIExportZone)
			r.Post("/zones/{zone_id}/records", h.APICreateRecord)
			r.Put("/zones/{zone_id}/records", h.APIUpdateRecord)
			r.Delete("/zones/{zone_id}/records", h.APIDeleteRecord)
		})
	})

	// Health checks. Readiness is rate-limited per IP (see healthLimiter);
	// liveness and the /health alias are unlimited constant responders.
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) // #nosec G104
	})
	r.With(healthLimiter.Limit(middleware.ExtractIP)).Get("/health/ready", h.HealthReady)
	r.Get("/health/live", h.HealthLive)

	// MCP endpoint (Streamable HTTP), behind the same limiter instances and
	// API-key authentication as /api/v1. Not mounted at all when disabled.
	mountMCPRoute(r, h, db, cfg, apiIPLimiter, apiLimiter)

	// Stop the background cleanup goroutines each limiter (and the session
	// tracker) spawns. In production the process exits shortly after
	// runServer returns and the goroutines die with it, but the explicit
	// cleanup keeps the lifecycle symmetrical with db.Close /
	// cachedClient.Close / stopCleanupRevokedTokens and — crucially — stops
	// the leak in tests that build a router and return without os.Exit.
	// LIFO order, mirroring the defers this extraction replaced: these run
	// BEFORE db.Close on shutdown, which is fine — the limiters hold no DB
	// state.
	cleanup := func() {
		if sessionTracker != nil {
			sessionTracker.Close()
		}
		if loginUsernameLimiter != nil {
			loginUsernameLimiter.Close()
		}
		healthLimiter.Close()
		apiIPLimiter.Close()
		apiLimiter.Close()
		loginLimiter.Close()
	}
	return r, cleanup
}

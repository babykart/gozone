// Package cmd holds the GoZone command-line tree (Cobra) and the HTTP
// server bootstrap. The server is started by the `gozone server` command;
// runServer wires the chi router, loads config, seeds the admin user and
// serves with graceful shutdown. The wiring helpers live in sibling files:
// routes.go (admin route table), templates.go (embedded template set),
// csrf.go (CSRF cookie Secure rewriting), middleware.go (logging and
// proxy-gated IP/HTTPS resolvers), ratelimit.go (rate-limit keys and
// ceilings) and static.go (static file serving).
package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/spf13/cobra"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/oidc"
	"github.com/babykart/gozone/internal/pdns"
	versionpkg "github.com/babykart/gozone/internal/version"
	"github.com/babykart/gozone/web"
)

// newServerCmd builds the `gozone server` command, which starts the HTTP
// server. It is the primary process run by the container (see Dockerfile
// CMD).
func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "server",
		Short:         "Start the HTTP server",
		Long:          "Starts the GoZone HTTP server (the PowerDNS admin interface). This is the primary process run by the container.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			configPath, err := c.Flags().GetString("config")
			if err != nil {
				return fmt.Errorf("read --config flag: %w", err)
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("load configuration: %w", err)
			}
			return runServer(cfg)
		},
	}
	return cmd
}

func runServer(cfg *config.Config) error {
	logger.Info("starting PowerDNS Admin interface")

	// Initialize structured logging with configured level
	logger.Init(cfg.Logging.Level)

	// Ensure .ico files are served with the correct MIME type
	if err := mime.AddExtensionType(".ico", "image/x-icon"); err != nil {
		logger.Warn("failed to register favicon MIME type", "error", err)
	}

	// Open database
	db, err := database.New(&cfg.Database)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// Create PowerDNS client with read-through cache
	pdnsClient := pdns.NewClient(&cfg.PowerDNS)
	cachedClient := pdns.NewCachedClient(pdnsClient)
	defer cachedClient.Close()

	// Periodically purge expired JWT revocation entries so the revoked_tokens
	// table does not grow without bound. Runs once at startup, then hourly until
	// shutdown.
	stopCleanupRevokedTokens := startPeriodicJob(context.Background(), "cleanup revoked tokens", time.Hour, 30*time.Second, func(ctx context.Context) error {
		return db.CleanupRevokedTokens(ctx)
	})
	defer stopCleanupRevokedTokens()

	// Periodically purge stale cluster-wide rate-limit windows (they are one
	// minute wide; anything a few minutes old can never be incremented again)
	// so the rate_limit_counters table does not grow without bound.
	stopPurgeRateLimits := startPeriodicJob(context.Background(), "purge rate limit counters", time.Hour, 30*time.Second, func(ctx context.Context) error {
		_, err := db.PurgeRateLimitCounters(ctx, time.Now().UTC().Add(-15*time.Minute))
		return err
	})
	defer stopPurgeRateLimits()

	// Periodically purge old activity logs based on the configured retention
	// period (default 90 days). Runs once at startup, then daily. A retention
	// period of 0 means "keep forever" and skips the background job entirely.
	var stopActivityPurge func()
	if cfg.Activity.RetentionDays > 0 {
		stopActivityPurge = startPeriodicJob(context.Background(), "purge activity logs", 24*time.Hour, 5*time.Minute, func(ctx context.Context) error {
			start := time.Now()
			n, err := db.PurgeActivityLogs(ctx, cfg.Activity.RetentionDays, cfg.Activity.BatchSize)
			if err != nil {
				return err
			}
			logger.Info("activity log retention purge completed",
				"deleted", n,
				"duration", time.Since(start).String(),
			)
			return nil
		})
	}

	// Periodically purge login attempts older than the configured retention
	// window. The retention window must outlast the lockout window so failed
	// attempts remain visible while a user could still be locked out.
	var stopLoginAttemptsPurge func()
	if cfg.LoginLock.AttemptsRetentionHours > 0 {
		stopLoginAttemptsPurge = startPeriodicJob(context.Background(), "purge login attempts", time.Hour, 30*time.Second, func(ctx context.Context) error {
			start := time.Now()
			n, err := db.PurgeLoginAttempts(ctx, cfg.LoginLock.AttemptsRetentionHours)
			if err != nil {
				return err
			}
			if n > 0 {
				logger.Info("login attempts purge completed",
					"deleted", n,
					"duration", time.Since(start).String(),
				)
			}
			return nil
		})
	}

	// Periodically purge expired SSO ID-token hints (server-side id_token_hint
	// storage for RP-initiated logout) so the sso_id_tokens table does not grow
	// without bound. Runs once at startup, then hourly until shutdown; rows are
	// also deleted at logout. Only needed when SSO is configured.
	var stopSSOTokensPurge func()
	if cfg.OIDC.Enabled {
		stopSSOTokensPurge = startPeriodicJob(context.Background(), "purge expired SSO id tokens", time.Hour, 30*time.Second, func(ctx context.Context) error {
			_, err := db.PurgeExpiredSSOIDTokens(ctx, time.Now().UTC())
			return err
		})
	}

	// Seed admin user if no users exist
	if err := database.SeedAdminUser(context.Background(), db, cfg); err != nil {
		return fmt.Errorf("seed admin user: %w", err)
	}

	// Stop the periodic purge goroutines on exit.
	if stopActivityPurge != nil {
		defer stopActivityPurge()
	}
	if stopLoginAttemptsPurge != nil {
		defer stopLoginAttemptsPurge()
	}
	if stopSSOTokensPurge != nil {
		defer stopSSOTokensPurge()
	}

	// Parse templates
	tmpl, err := parseTemplates()
	if err != nil {
		return err
	}

	// Create handler
	h := handlers.New(db, cachedClient, cfg, tmpl)
	// Surface the resolved build version in the UI (dashboard). ldflags-injected
	// values win; internal/version falls back to embedded VCS metadata.
	h.Version = versionpkg.Resolve(version, commit, buildDate)

	// Periodically reconcile zone-group grants with the PowerDNS zone list:
	// a zone deleted or renamed directly in PowerDNS leaves its grant rows
	// orphaned otherwise. Skipped when PowerDNS is unreachable (a failed zone
	// list must never look like "all zones gone").
	defer startPeriodicJob(context.Background(), "reconcile group zone grants", time.Hour, time.Minute, func(ctx context.Context) error {
		_, err := h.ReconcileGroupZones(ctx)
		return err
	})()

	// Initialize OpenID Connect / OAuth2 single sign-on. Discovery is best-effort
	// per provider (a temporarily unreachable IdP is skipped, not fatal); the
	// returned service is disabled when OIDC is not configured or no provider
	// could be discovered.
	oidcSvc := oidc.NewService(context.Background(), cfg, cfg.Server.OIDCStateKey)
	h.OIDC = oidcSvc
	// Stop the per-provider JWKS background refresh goroutines on shutdown.
	defer oidcSvc.Close()
	if oidcSvc.Enabled() {
		logger.Info("oidc single sign-on enabled")
	}

	// Seed built-in zone templates
	if err := h.SeedBuiltinTemplates(); err != nil {
		return fmt.Errorf("seed builtin templates: %w", err)
	}

	// Set up router
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	// Resolve the client IP into the request context without ever mutating
	// r.RemoteAddr. When trusted_proxies is configured the leftmost XFF entry
	// outside the trusted CIDRs wins; otherwise only the TCP source address is
	// honoured and XFF headers are ignored entirely (fail-closed). This is the
	// fix for the REVIEW.md "Rate-limit du login contournable" finding: the
	// previous chimw.RealIP let a direct-access attacker rotate XFF and obtain
	// a fresh rate-limit bucket per request.
	r.Use(clientIPMiddleware(cfg))
	r.Use(requestLogger)
	r.Use(chimw.Compress(5))
	// Resolve the effective HTTPS flag (trusted-proxy-gated) BEFORE
	// SecurityHeaders so HSTS and the Secure cookie flag read a trusted value
	// instead of a raw, spoofable X-Forwarded-Proto header (m40/M-SEC4).
	r.Use(httpsResolverMiddleware(cfg))
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.BodyLimit)
	r.Use(middleware.ErrorHandler)

	// CSRF protection for web UI forms.
	//
	// csrf.Secure(false) is intentional: the Secure flag is set per-request by
	// csrfSecureCookieWriter (see below) based on middleware.IsHTTPS(r), so the
	// CSRF and session cookies always agree. The static server.secure_cookies
	// flag is no longer used for CSRF — deriving Secure from the TLS context is
	// strictly more correct (REVIEW.md L-2).
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
	// /api splits at the auth boundary (m7).
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

	// Stop the background cleanup goroutines each limiter spawns. In
	// production the process exits shortly after runServer returns and the
	// goroutines die with it, but the explicit Close keeps the lifecycle
	// symmetrical with db.Close / cachedClient.Close /
	// stopCleanupRevokedTokens and — crucially — stops the leak in tests
	// that build a server and return without os.Exit (REVIEW.md L-10).
	// LIFO order: these run BEFORE db.Close on shutdown, which is fine — the
	// limiters hold no DB state.
	defer loginLimiter.Close()
	defer apiLimiter.Close()
	defer apiIPLimiter.Close()
	defer healthLimiter.Close()
	if loginUsernameLimiter != nil {
		defer loginUsernameLimiter.Close()
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
		defer sessionTracker.Close()
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
				// cookie's Secure: IsHTTPS(r) behaviour (REVIEW.md L-2).
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
				r.Post("/zones/{zone_id}/cache/clear", h.ClearZoneCache)
			})

			// Admin-only routes — mounted via mountAdminRoutes so the admin
			// routing table has a single source of truth that a test can walk
			// and lock (every admin route must stay inside RequireAdmin —
			// REVIEW.md B-5).
			mountAdminRoutes(r, h, db)
		})
	})

	// Static files (no CSRF)
	staticFS, err := fs.Sub(web.FS, "static")
	if err != nil {
		return fmt.Errorf("open embedded static files: %w", err)
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

	// Start server
	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))

	// Graceful shutdown
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		// Explicit bound on the request header bytes (REVIEW.md I-5). Go's
		// default is http.DefaultMaxHeaderBytes (1 MiB), which is correct for
		// this app; setting it explicitly documents the limit rather than
		// relying on an implicit zero → default fallback, and pins it if a
		// future Go release ever changed the default.
		MaxHeaderBytes: http.DefaultMaxHeaderBytes,
	}

	// Bind the listener BEFORE starting the signal-watcher goroutine so a
	// port-in-use error returns cleanly without leaking the goroutine and
	// its signal.Notify registration (m1). ListenAndServe would bind and
	// serve in one blocking call, making the leak unavoidable on bind
	// failure because the goroutine is already running by the time the
	// error surfaces.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	shutdownDone := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(),
			time.Duration(cfg.Server.ShutdownTimeoutSeconds)*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
		close(shutdownDone)
	}()

	logger.Info("server starting", "addr", addr)
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed: %w", err)
	}
	// Serve returns ErrServerClosed as soon as Shutdown begins; wait for the
	// drain to finish before returning so deferred cleanup (db.Close, etc.)
	// does not run while in-flight requests are still being served.
	<-shutdownDone
	logger.Info("server stopped")
	return nil
}

// startPeriodicJob starts a goroutine that runs job immediately, then again on
// every tick of interval. Each invocation gets a fresh context with the
// provided timeout and runs in the given parent context. The returned stop
// function cancels the periodic job and stops the goroutine; it is safe to call
// multiple times.
func startPeriodicJob(ctx context.Context, name string, interval, timeout time.Duration, job func(context.Context) error) func() {
	ctx, stop := context.WithCancel(ctx)
	go func() {
		run := func() {
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			if err := job(c); err != nil && ctx.Err() == nil {
				logger.Error(name+" failed", "error", err)
			}
		}
		run()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
	return stop
}

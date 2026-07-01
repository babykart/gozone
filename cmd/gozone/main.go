// gozone - PowerDNS Admin Interface in Go
// Main entry point

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/pdns"
	"github.com/babykart/gozone/web"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		logger.Fatal("gozone failed", "error", err)
	}
}

func run(args []string) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "unlock":
			return runUnlock(args[1:])
		}
	}

	flags := flag.NewFlagSet("gozone", flag.ContinueOnError)
	configPath := flags.String("config", "config.yaml", "Path to YAML configuration file")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	logger.Info("starting PowerDNS Admin interface")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

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
	defer startPeriodicJob(context.Background(), "cleanup revoked tokens", time.Hour, 30*time.Second, func(ctx context.Context) error {
		return db.CleanupRevokedTokens(ctx)
	})()

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

	// Parse templates
	tmpl, err := parseTemplates()
	if err != nil {
		return err
	}

	// Create handler
	h := handlers.New(db, cachedClient, cfg, tmpl)

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
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.BodyLimit)
	r.Use(middleware.ErrorHandler)

	// CSRF protection for web UI forms
	csrfMiddleware := csrf.Protect(
		cfg.Server.CSRFKey,
		// Mark the CSRF cookie Secure when served over HTTPS. Configurable via
		// server.secure_cookies / GOZONE_SECURE_COOKIES (see config.yaml).
		csrf.Secure(cfg.Server.SecureCookies),
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
	var loginUsernameLimiter *middleware.RateLimiter
	if cfg.LoginLock.UsernameRateLimitPerMinute > 0 {
		loginUsernameLimiter = middleware.NewRateLimiter(cfg.LoginLock.UsernameRateLimitPerMinute)
	}

	// CSRF-protected web UI routes (login + authenticated)
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !middleware.IsHTTPS(r) {
					r = csrf.PlaintextHTTPRequest(r)
				}
				next.ServeHTTP(w, r)
			})
		})
		r.Use(csrfMiddleware)

		// Public routes
		r.Get("/login", h.LoginPage)
		// Both limiters run BEFORE the Login handler (no separate auth
		// middleware — see the rate-limiter documentation above for the
		// /login vs /api ordering asymmetry, m7).
		loginChain := []func(http.Handler) http.Handler{
			loginLimiter.Limit(middleware.ExtractIP),
		}
		if loginUsernameLimiter != nil {
			loginChain = append(loginChain, loginUsernameLimiter.Limit(loginUsernameKey))
		}
		r.With(loginChain...).Post("/login", h.Login)

		// Authenticated routes (web UI)
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(db, cfg.Server.JWTKey))

			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			})
			r.Get("/dashboard", h.Dashboard)
			r.Get("/activity", h.ActivityPage)
			r.Post("/logout", h.Logout)
			r.Get("/profile", h.ProfilePage)
			r.Get("/profile/api-keys", h.ListAPIKeys)
			r.Post("/profile/api-keys/create", h.CreateAPIKey)
			r.Post("/profile/api-keys/delete", h.DeleteAPIKey)

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
				r.Post("/zones/{zone_id}/import", h.ImportZone)
				r.Post("/zones/{zone_id}/cache/clear", h.ClearZoneCache)
				r.Post("/zones/{zone_id}/cryptokeys/{key_id}/toggle", h.ToggleCryptokey)
			})

			// Admin-only routes
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAdmin)

				r.Get("/zones/new", h.CreateZonePage)
				r.Post("/zones/create", h.CreateZone)
				r.Post("/zones/delete", h.DeleteZone)

				r.Group(func(r chi.Router) {
					r.Use(middleware.CheckZoneAccess(db))

					r.Post("/zones/{zone_id}/rectify", h.RectifyZone)
					r.Post("/zones/{zone_id}/notify", h.NotifyZone)
					r.Post("/zones/{zone_id}/metadata/create", h.CreateMetadata)
					r.Post("/zones/{zone_id}/metadata/delete", h.DeleteMetadata)
					r.Post("/zones/{zone_id}/cryptokeys/create", h.CreateCryptokey)
					r.Post("/zones/{zone_id}/cryptokeys/{key_id}/delete", h.DeleteCryptokey)
				})

				r.Get("/users", h.ListUsers)
				r.Get("/users/new", h.CreateUserPage)
				r.Post("/users/create", h.CreateUser)
				r.Get("/users/{user_id}/edit", h.EditUserPage)
				r.Post("/users/{user_id}/update", h.UpdateUser)
				r.Post("/users/{user_id}/lock", h.LockUser)
				r.Post("/users/{user_id}/unlock", h.UnlockUser)
				r.Post("/users/delete", h.DeleteUser)

				r.Get("/groups", h.ListGroups)
				r.Get("/groups/new", h.CreateGroupPage)
				r.Post("/groups/create", h.CreateGroup)
				r.Get("/groups/{group_id}/edit", h.EditGroupPage)
				r.Post("/groups/{group_id}/update", h.UpdateGroup)
				r.Post("/groups/{group_id}/delete", h.DeleteGroup)
				r.Post("/groups/{group_id}/add-member", h.AddMemberToGroup)
				r.Post("/groups/{group_id}/remove-member", h.RemoveMemberFromGroup)
				r.Post("/groups/{group_id}/add-zone", h.AddZoneToGroup)
				r.Post("/groups/{group_id}/remove-zone", h.RemoveZoneFromGroup)

				r.Get("/tsigkeys", h.ListTSIGKeys)
				r.Get("/tsigkeys/new", h.CreateTSIGKeyPage)
				r.Post("/tsigkeys/create", h.CreateTSIGKey)
				r.Get("/tsigkeys/{key_id}/edit", h.EditTSIGKeyPage)
				r.Post("/tsigkeys/{key_id}/update", h.UpdateTSIGKey)
				r.Post("/tsigkeys/delete", h.DeleteTSIGKey)

				r.Get("/templates", h.ListTemplates)
				r.Get("/templates/new", h.CreateTemplatePage)
				r.Post("/templates/create", h.CreateTemplate)
				r.Get("/templates/{template_id}/edit", h.EditTemplatePage)
				r.Post("/templates/{template_id}/update", h.UpdateTemplate)
				r.Post("/templates/{template_id}/delete", h.DeleteTemplate)
				r.Post("/templates/{template_id}/records/add", h.AddTemplateRecord)
				r.Post("/templates/{template_id}/records/{record_id}/update", h.UpdateTemplateRecord)
				r.Post("/templates/{template_id}/records/{record_id}/delete", h.DeleteTemplateRecord)
			})
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

	// Health checks
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) // #nosec G104
	})
	r.Get("/health/ready", h.HealthReady)
	r.Get("/health/live", h.HealthLive)

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	// Graceful shutdown
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

// fileServer serves static files with proper caching headers.
func fileServer(r chi.Router, path string, root http.FileSystem) {
	fs := http.StripPrefix(path, http.FileServer(root))
	r.Get(path+"/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}

// relativeName strips the zone suffix from a record name. The apex (zone name
// itself) is displayed as "@". For example, with zone "example.com.", the
// record "www.example.com." becomes "www" and "example.com." becomes "@".
//
// The comparison is case-insensitive (DNS names are), and the zone name is
// normalized to end with a dot before matching so callers may pass either
// "example.com" or "example.com.".
func relativeName(recordName, zoneName string) string {
	// Normalize the zone name: lowercase, ensure trailing dot.
	zone := strings.ToLower(zoneName)
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}

	record := strings.ToLower(recordName)

	// Apex: record name matches the zone name exactly.
	if record == zone {
		return "@"
	}

	// Sub-domain: record name ends with ".<zone>". The leading dot prevents
	// "notexample.com." from matching zone "example.com.".
	dotZone := "." + zone
	if len(record) > len(dotZone) && strings.HasSuffix(record, dotZone) {
		rel := recordName[:len(recordName)-len(dotZone)]
		return strings.TrimSuffix(rel, ".")
	}

	// Record is not in this zone; return as-is.
	return recordName
}

// parseTemplates loads all HTML templates from the embedded filesystem.
func parseTemplates() (*template.Template, error) {
	funcMap := template.FuncMap{
		"add":          func(a, b int) int { return a + b },
		"sub":          func(a, b int) int { return a - b },
		"urlquery":     url.QueryEscape,
		"relativeName": relativeName,
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict expects an even number of arguments")
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},
	}
	tmpl, err := template.New("base").Funcs(funcMap).ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("load embedded templates: %w", err)
	}
	logger.Info("templates loaded", "count", len(tmpl.Templates()))
	return tmpl, nil
}

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
			"method", r.Method,
			"path", r.URL.Path,
			"status", wr.Status(),
			"duration", time.Since(start).String(),
			"remote", remote,
		)
	})
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
func clientIPMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	if len(cfg.Server.TrustedProxies) == 0 {
		return chimw.ClientIPFromRemoteAddr
	}

	prefixes := make([]netip.Prefix, len(cfg.Server.TrustedProxies))
	for i, p := range cfg.Server.TrustedProxies {
		prefixes[i] = netip.MustParsePrefix(p)
	}

	return func(h http.Handler) http.Handler {
		// Pre-wrap with both strategies so we can switch per-request without
		// re-wrapping on every request.
		xff := chimw.ClientIPFromXFF(cfg.Server.TrustedProxies...)(h)
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

// loginUsernameKey returns the attempted login username (lowercased and
// trimmed) so the per-username rate-limit bucket is shared across casing
// variants and surrounding whitespace.
func loginUsernameKey(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.FormValue("username")))
}

// runUnlock implements the `gozone unlock` emergency CLI.
//
// Usage:
//
//	gozone unlock --user <id|username> [--config <path>]
//
// It opens the configured database, resolves the user (by numeric ID or
// username), clears their lockout and failed-login counter, then exits.
// Designed for operators who have shell access to the host but lost the
// admin password or got themselves locked out by a brute-force storm —
// the web UI alone is not enough to recover.
func runUnlock(args []string) error {
	flags := flag.NewFlagSet("gozone unlock", flag.ContinueOnError)
	configPath := flags.String("config", "config.yaml", "Path to YAML configuration file")
	userFlag := flags.String("user", "", "User ID or username to unlock (required)")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if *userFlag == "" {
		return fmt.Errorf("--user is required (use --user <id> or --user <username>)")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	logger.Init(cfg.Logging.Level)

	db, err := database.New(&cfg.Database)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		userID     int64
		username   string
		resolveErr error
	)
	if id, perr := strconv.ParseInt(*userFlag, 10, 64); perr == nil && id > 0 {
		userID = id
		resolveErr = db.QueryRowContext(ctx,
			`SELECT username FROM users WHERE id = ?`,
			id,
		).Scan(&username)
		if resolveErr != nil {
			if resolveErr == sql.ErrNoRows {
				return fmt.Errorf("user id=%d not found", id)
			}
			return fmt.Errorf("lookup user id=%d: %w", id, resolveErr)
		}
	} else {
		// Username lookup — case-insensitive; the Login handler does the same.
		resolveErr = db.QueryRowContext(ctx,
			`SELECT id, username FROM users WHERE lower(username) = lower(?)`,
			*userFlag,
		).Scan(&userID, &username)
		if resolveErr != nil {
			if resolveErr == sql.ErrNoRows {
				return fmt.Errorf("user %q not found", *userFlag)
			}
			return fmt.Errorf("lookup user %q: %w", *userFlag, resolveErr)
		}
	}

	logger.Info("unlocking user via CLI", "user_id", userID, "username", username)

	if err := db.AdminUnlockUser(ctx, userID); err != nil {
		return fmt.Errorf("unlock user %d: %w", userID, err)
	}

	// Log with user_id=NULL: the actor is the shell operator, not a GoZone
	// user. Capture the OS identity (username@hostname) for audit (m4).
	if _, err := db.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (NULL, 'unlock_user_cli', ?)",
		fmt.Sprintf("Unlocked user id=%d username=%q by CLI operator %s", userID, username, operatorIdentity()),
	); err != nil {
		// Best-effort: the unlock itself succeeded, so we don't fail the CLI.
		logger.Warn("failed to log CLI unlock activity", "user_id", userID, "error", err)
	}

	logger.Info("user unlocked", "user_id", userID, "username", username)
	return nil
}

// operatorIdentity returns a string identifying the shell user running the
// CLI, for audit purposes. Best-effort: falls back to "unknown" when the OS
// user or hostname cannot be determined.
func operatorIdentity() string {
	var username, host string
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	if h, err := os.Hostname(); err == nil {
		host = h
	}
	if username == "" {
		username = "unknown"
	}
	if host == "" {
		host = "unknown"
	}
	return username + "@" + host
}

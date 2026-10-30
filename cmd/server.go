// Package cmd holds the GoZone command-line tree (Cobra) and the HTTP
// server bootstrap. The server is started by the `gozone server` command;
// runServer loads config, seeds the admin user, wires the handler and
// serves with graceful shutdown. The wiring helpers live in sibling files:
// routes.go (admin route table), router.go (the production routing table
// and its middleware stack, extracted so tests can walk the real router),
// templates.go (embedded template set), csrf.go (CSRF cookie Secure
// rewriting), middleware.go (logging and proxy-gated IP/HTTPS resolvers),
// ratelimit.go (rate-limit keys and ceilings) and static.go (static file
// serving).
package cmd

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/oidc"
	"github.com/babykart/gozone/internal/pdns"
	versionpkg "github.com/babykart/gozone/internal/version"
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
			cfg, err := loadConfig(c)
			if err != nil {
				return err
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

	// Validate server.trusted_proxies before anything else starts: a
	// malformed entry (a bare IP without "/") previously panicked deep inside
	// netip.MustParsePrefix; a clean, actionable startup error is the right
	// fail mode for an operator typo.
	trustedPrefixes, err := parseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("invalid server.trusted_proxies: %w", err)
	}

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
	// The stop is deferred RIGHT HERE: registering it later (after the admin
	// seed below) meant a seed failure returned without stopping the job,
	// leaving goroutines running against the closing database.
	if cfg.Activity.RetentionDays > 0 {
		stopActivityPurge := startPeriodicJob(context.Background(), "purge activity logs", 24*time.Hour, 5*time.Minute, func(ctx context.Context) error {
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
		defer stopActivityPurge()
	}

	// Periodically purge login attempts older than the configured retention
	// window. The retention window must outlast the lockout window so failed
	// attempts remain visible while a user could still be locked out.
	// Stop deferred right here — see the activity-purge note above.
	if cfg.LoginLock.AttemptsRetentionHours > 0 {
		stopLoginAttemptsPurge := startPeriodicJob(context.Background(), "purge login attempts", time.Hour, 30*time.Second, func(ctx context.Context) error {
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
		defer stopLoginAttemptsPurge()
	}

	// Periodically purge expired SSO ID-token hints (server-side id_token_hint
	// storage for RP-initiated logout) so the sso_id_tokens table does not grow
	// without bound. Runs once at startup, then hourly until shutdown; rows are
	// also deleted at logout. Only needed when SSO is configured.
	// Stop deferred right here — see the activity-purge note above.
	if cfg.OIDC.Enabled {
		stopSSOTokensPurge := startPeriodicJob(context.Background(), "purge expired SSO id tokens", time.Hour, 30*time.Second, func(ctx context.Context) error {
			_, err := db.PurgeExpiredSSOIDTokens(ctx, time.Now().UTC())
			return err
		})
		defer stopSSOTokensPurge()
	}

	// Seed admin user if no users exist
	if err := database.SeedAdminUser(context.Background(), db, cfg); err != nil {
		return fmt.Errorf("seed admin user: %w", err)
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

	// Assemble the production routing table (see router.go). Extracted from
	// runServer so tests can walk the REAL router and lock routing
	// invariants on it. The returned cleanup stops the limiter and session
	// tracker goroutines; LIFO-wise it runs before db.Close on shutdown.
	router, stopRouter := buildRouter(cfg, db, h, trustedPrefixes)
	defer stopRouter()

	// Start server
	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))

	// Graceful shutdown
	srv := &http.Server{
		Addr:    addr,
		Handler: router,

		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		// Explicit bound on the request header bytes. Go's
		// default is http.DefaultMaxHeaderBytes (1 MiB), which is correct for
		// this app; setting it explicitly documents the limit rather than
		// relying on an implicit zero → default fallback, and pins it if a
		// future Go release ever changed the default.
		MaxHeaderBytes: http.DefaultMaxHeaderBytes,
	}

	// Bind the listener BEFORE starting the signal-watcher goroutine so a
	// port-in-use error returns cleanly without leaking the goroutine and
	// its signal.Notify registration. ListenAndServe would bind and
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
		defer signal.Stop(sigCh)
		<-sigCh
		logger.Info("shutting down")
		// A second signal force-exits: an operator pressing Ctrl-C twice
		// wants out NOW, not after a stuck drain or a slow deferred cleanup.
		go func() {
			<-sigCh
			logger.Warn("second shutdown signal received; forcing exit")
			os.Exit(130) // 128 + SIGINT
		}()
		ctx, cancel := context.WithTimeout(context.Background(),
			time.Duration(cfg.Server.ShutdownTimeoutSeconds)*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			// The graceful drain expired. Close force-cancels the remaining
			// connections so the deferred cleanup (db.Close, caches) never
			// runs against requests that are still being served — proceeding
			// anyway would close the database under in-flight handlers.
			logger.Error("shutdown timed out; force-closing remaining connections", "error", err)
			if cerr := srv.Close(); cerr != nil {
				logger.Error("force close failed", "error", cerr)
			}
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
// function cancels the periodic job, WAITS for an in-flight invocation to
// finish (the invocation's context is canceled first, so a context-aware job
// aborts promptly), and stops the goroutine; it is safe to call multiple
// times. Waiting is what keeps shutdown ordered: a deferred db.Close() can
// never race a purge that is still executing.
func startPeriodicJob(ctx context.Context, name string, interval, timeout time.Duration, job func(context.Context) error) func() {
	ctx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	return func() {
		stop()
		wg.Wait()
	}
}

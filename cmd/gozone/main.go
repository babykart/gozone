// gozone - PowerDNS Admin Interface in Go
// Main entry point

package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
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
	// shutdown. The deferred cancel runs before db.Close (defers are LIFO), so
	// the goroutine stops before the connection pool is closed.
	cleanupCtx, stopCleanup := context.WithCancel(context.Background())
	defer stopCleanup()
	go func() {
		purge := func() {
			ctx, cancel := context.WithTimeout(cleanupCtx, 30*time.Second)
			defer cancel()
			// Suppress the error when it stems from shutdown cancellation.
			if err := db.CleanupRevokedTokens(ctx); err != nil && cleanupCtx.Err() == nil {
				logger.Error("failed to clean up revoked tokens", "error", err)
			}
		}
		purge()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				purge()
			}
		}
	}()

	// Periodically purge old activity logs based on the configured retention
	// period (default 90 days). Runs once at startup, then daily. A retention
	// period of 0 means "keep forever" and skips the background job entirely.
	if cfg.Activity.RetentionDays > 0 {
		retentionCtx, stopRetention := context.WithCancel(context.Background())
		defer stopRetention()
		go func() {
			purge := func() {
				start := time.Now()
				ctx, cancel := context.WithTimeout(retentionCtx, 5*time.Minute)
				defer cancel()
				n, err := db.PurgeActivityLogs(ctx, cfg.Activity.RetentionDays, cfg.Activity.BatchSize)
				if err != nil && retentionCtx.Err() == nil {
					logger.Error("failed to purge old activity logs", "error", err)
					return
				}
				logger.Info("activity log retention purge completed",
					"deleted", n,
					"duration", time.Since(start).String(),
				)
			}
			purge()
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-retentionCtx.Done():
					return
				case <-ticker.C:
					purge()
				}
			}
		}()
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

	// Seed built-in zone templates
	if err := h.SeedBuiltinTemplates(); err != nil {
		return fmt.Errorf("seed builtin templates: %w", err)
	}

	// Set up router
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(requestLogger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Compress(5))
	r.Use(middleware.SecurityHeaders)
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

	// Rate limiters
	loginLimiter := middleware.NewRateLimiter(5) // 5 requests per minute per IP
	apiLimiter := middleware.NewRateLimiter(100) // 100 requests per minute per API key

	// CSRF-protected web UI routes (login + authenticated)
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
					r = csrf.PlaintextHTTPRequest(r)
				}
				next.ServeHTTP(w, r)
			})
		})
		r.Use(csrfMiddleware)

		// Public routes
		r.Get("/login", h.LoginPage)
		r.With(loginLimiter.Limit(middleware.ExtractIP)).Post("/login", h.Login)

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
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed: %w", err)
	}
	// ListenAndServe returns ErrServerClosed as soon as Shutdown begins; wait
	// for the drain to finish before returning so deferred cleanup (db.Close,
	// etc.) does not run while in-flight requests are still being served.
	<-shutdownDone
	logger.Info("server stopped")
	return nil
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
func relativeName(recordName, zoneName string) string {
	if recordName == zoneName {
		return "@"
	}
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}
	if strings.HasSuffix(recordName, zoneName) {
		rel := strings.TrimSuffix(recordName, zoneName)
		return strings.TrimSuffix(rel, ".")
	}
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
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wr.Status(),
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
		)
	})
}

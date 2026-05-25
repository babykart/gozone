// gozone - PowerDNS Admin Interface in Go
// Main entry point

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/dyndns"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/pdns"
)

//go:embed templates/*.html
var templateFS embed.FS

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	logger.Info("starting PowerDNS Admin interface")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("failed to load configuration", "error", err)
	}

	// Initialize structured logging with configured level
	logger.Init(cfg.Logging.Level)

	// Open database
	db, err := database.New(&cfg.Database)
	if err != nil {
		logger.Fatal("failed to open database", "error", err)
	}
	defer db.Close()

	// Create PowerDNS client
	pdnsClient := pdns.NewClient(&cfg.PowerDNS)

	// Seed admin user if no users exist
	if err := database.SeedAdminUser(db, cfg); err != nil {
		logger.Fatal("failed to seed admin user", "error", err)
	}

	// Parse templates
	tmpl := parseTemplates()

	// Create handler
	h := handlers.New(db, pdnsClient, cfg, tmpl)

	// Set up router
	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Compress(5))
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.ErrorHandler)

	// CSRF protection for web UI forms
	csrfMiddleware := csrf.Protect(
		[]byte(cfg.Server.SecretKey),
		csrf.Secure(false), // set true in production with HTTPS
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
	loginLimiter := middleware.NewRateLimiter(5)   // 5 requests per minute per IP
	apiLimiter := middleware.NewRateLimiter(100)   // 100 requests per minute per API key
	dyndnsLimiter := middleware.NewRateLimiter(10) // 10 requests per minute per user

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
			r.Use(middleware.Auth(db, []byte(cfg.Server.SecretKey)))

			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			})
			r.Get("/dashboard", h.Dashboard)
			r.Get("/logout", h.Logout)
			r.Get("/profile", h.ProfilePage)

			// Zones (viewing accessible to all authenticated users)
			r.Get("/zones", h.ListZones)
			r.Get("/zones/{zone_id}", h.ViewZone)

			// Records (accessible to all authenticated users)
			r.Get("/zones/{zone_id}/records/new", h.CreateRecordPage)
			r.Post("/zones/{zone_id}/records/create", h.CreateRecord)
			r.Get("/zones/{zone_id}/records/edit", h.EditRecordPage)
			r.Post("/zones/{zone_id}/records/update", h.UpdateRecord)
			r.Post("/zones/{zone_id}/records/delete", h.DeleteRecord)

			// Admin-only routes
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAdmin)

				r.Get("/zones/new", h.CreateZonePage)
				r.Post("/zones/create", h.CreateZone)
				r.Post("/zones/delete", h.DeleteZone)
				r.Post("/zones/{zone_id}/rectify", h.RectifyZone)
				r.Post("/zones/{zone_id}/notify", h.NotifyZone)

				r.Get("/users", h.ListUsers)
				r.Get("/users/new", h.CreateUserPage)
				r.Post("/users/create", h.CreateUser)
				r.Get("/users/{user_id}/edit", h.EditUserPage)
				r.Post("/users/{user_id}/update", h.UpdateUser)
				r.Post("/users/delete", h.DeleteUser)
			})
		})
	})

	// Static files (no CSRF)
	fileServer(r, "/static", http.Dir("web/static"))

	// API routes (API key auth, no CSRF)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(db))
		r.Use(apiLimiter.Limit(middleware.ExtractAPIKey))

		r.Get("/zones", h.APIListZones)
		r.Post("/zones", h.APICreateZone)
		r.Get("/zones/{zone_id}", h.APIGetZone)
		r.Delete("/zones/{zone_id}", h.APIDeleteZone)
		r.Get("/zones/{zone_id}/records", h.APIListRecords)
		r.Post("/zones/{zone_id}/records", h.APICreateRecord)
		r.Put("/zones/{zone_id}/records", h.APIUpdateRecord)
		r.Delete("/zones/{zone_id}/records", h.APIDeleteRecord)
		r.Get("/stats", h.APIStats)
	})

	// DynDNS endpoint (Basic Auth, no web middleware)
	dyndnsHandler := dyndns.NewHandler(db, pdnsClient, "")
	r.With(dyndnsLimiter.Limit(middleware.ExtractUsername)).Get("/nic/update", func(w http.ResponseWriter, r *http.Request) {
		dyndnsHandler.ServeHTTP(w, r)
	})
	r.With(dyndnsLimiter.Limit(middleware.ExtractUsername)).Post("/nic/update", func(w http.ResponseWriter, r *http.Request) {
		dyndnsHandler.ServeHTTP(w, r)
	})

	// Health checks
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/health/ready", h.HealthReady)
	r.Get("/health/live", h.HealthLive)

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Info("listening", "addr", addr)

	// Graceful shutdown
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

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
	}()

	logger.Info("server starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("server failed", "error", err)
	}
	logger.Info("server stopped")
}

// fileServer serves static files with proper caching headers.
func fileServer(r chi.Router, path string, root http.Dir) {
	fs := http.StripPrefix(path, http.FileServer(root))
	r.Get(path+"/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}

// parseTemplates loads all HTML templates from the embedded filesystem.
func parseTemplates() *template.Template {
	tmpl, err := template.New("base").Funcs(template.FuncMap{
		"eq": func(a, b interface{}) bool { return a == b },
		"ne": func(a, b interface{}) bool { return a != b },
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		logger.Fatal("failed to load embedded templates", "error", err)
	}
	logger.Info("templates loaded", "count", len(tmpl.Templates()))
	return tmpl
}

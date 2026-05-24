// gozone - PowerDNS Admin Interface in Go
// Main entry point

package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/dyndns"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/pdns"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[gozone] starting PowerDNS Admin interface...")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Open database
	db, err := database.New(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create PowerDNS client
	pdnsClient := pdns.NewClient(&cfg.PowerDNS)

	// Seed admin user if no users exist
	seedAdminUser(db, cfg)

	// Parse templates
	tmpl := parseTemplates()

	// Create handler
	h := handlers.New(db.Conn, pdnsClient, cfg, tmpl)

	// Set up router
	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Compress(5))

	// CSRF protection for web UI forms
	csrfMiddleware := csrf.Protect(
		[]byte(cfg.Server.SecretKey),
		csrf.Secure(false), // set true in production with HTTPS
		csrf.Path("/"),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
		})),
	)

	// Rate limiters
	loginLimiter := middleware.NewRateLimiter(5)    // 5 requests per minute per IP
	apiLimiter := middleware.NewRateLimiter(100)    // 100 requests per minute per API key
	dyndnsLimiter := middleware.NewRateLimiter(10)  // 10 requests per minute per user

	// CSRF-protected web UI routes (login + authenticated)
	r.Group(func(r chi.Router) {
		r.Use(csrfMiddleware)

		// Public routes
		r.Get("/login", h.LoginPage)
		r.With(loginLimiter.Limit(middleware.ExtractIP)).Post("/login", h.Login)

		// Authenticated routes (web UI)
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(db.Conn, []byte(cfg.Server.SecretKey)))

			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			})
			r.Get("/dashboard", h.Dashboard)
			r.Get("/logout", h.Logout)
			r.Get("/profile", h.ProfilePage)

			// Zones
			r.Get("/zones", h.ListZones)
			r.Get("/zones/new", h.CreateZonePage)
			r.Post("/zones/create", h.CreateZone)
			r.Post("/zones/delete", h.DeleteZone)
			r.Get("/zones/{zone_id}", h.ViewZone)
			r.Post("/zones/{zone_id}/rectify", h.RectifyZone)
			r.Post("/zones/{zone_id}/notify", h.NotifyZone)

			// Records
			r.Get("/zones/{zone_id}/records/new", h.CreateRecordPage)
			r.Post("/zones/{zone_id}/records/create", h.CreateRecord)
			r.Get("/zones/{zone_id}/records/edit", h.EditRecordPage)
			r.Post("/zones/{zone_id}/records/update", h.UpdateRecord)
			r.Post("/zones/{zone_id}/records/delete", h.DeleteRecord)

			// Users (admin only)
			r.Get("/users", h.ListUsers)
			r.Get("/users/new", h.CreateUserPage)
			r.Post("/users/create", h.CreateUser)
			r.Get("/users/{user_id}/edit", h.EditUserPage)
			r.Post("/users/{user_id}/update", h.UpdateUser)
			r.Post("/users/delete", h.DeleteUser)
		})
	})

	// Static files (no CSRF)
	fileServer(r, "/static", http.Dir("web/static"))

	// API routes (API key auth, no CSRF)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(db.Conn))
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
	dyndnsHandler := dyndns.NewHandler(db.Conn, pdnsClient, "")
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
	log.Printf("[gozone] listening on %s", addr)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("[gozone] shutting down...")
		os.Exit(0)
	}()

	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// fileServer serves static files with proper caching headers.
func fileServer(r chi.Router, path string, root http.Dir) {
	fs := http.StripPrefix(path, http.FileServer(root))
	r.Get(path+"/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}

// parseTemplates loads all HTML templates from the web/templates directory.
func parseTemplates() *template.Template {
	pattern := filepath.Join("web", "templates", "*.html")
	tmpl, err := template.New("base").Funcs(template.FuncMap{
		"eq": func(a, b interface{}) bool { return a == b },
		"ne": func(a, b interface{}) bool { return a != b },
	}).ParseGlob(pattern)
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
	log.Printf("[gozone] loaded %d templates", len(tmpl.Templates()))
	return tmpl
}

// seedAdminUser creates an admin user if no users exist in the database.
func seedAdminUser(db *database.DB, cfg *config.Config) {
	var count int
	db.Conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		return
	}

	username := "admin"
	email := "admin@gozone.local"
	password := os.Getenv("GOZONE_ADMIN_PASSWORD")
	if password == "" {
		password = "admin"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cfg.Auth.BcryptCost)
	if err != nil {
		log.Printf("[gozone] WARNING: failed to hash admin password: %v", err)
		return
	}

	_, err = db.Conn.Exec(
		`INSERT INTO users (username, email, password_hash, first_name, last_name, role)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		username, email, string(hash), "Admin", "User", "admin",
	)
	if err != nil {
		log.Printf("[gozone] WARNING: failed to seed admin user: %v", err)
		return
	}

	log.Printf("[gozone] seeded admin user (username: %s, password: %s)", username, password)
	log.Printf("[gozone] CHANGE THE DEFAULT PASSWORD IMMEDIATELY!")
}

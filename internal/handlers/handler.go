// Package handlers contains HTTP handler methods for the GoZone web UI
// and REST API. All handler methods are attached to the Handler struct,
// which holds shared dependencies (database, PowerDNS client, config, templates).
package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/pdns"
)

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	DB   *database.DB
	PDNS pdns.ZoneService
	Cfg  *config.Config
	Tmpl *template.Template
}

// New creates a new Handler with all dependencies.
func New(db *database.DB, pdnsClient pdns.ZoneService, cfg *config.Config, tmpl *template.Template) *Handler {
	return &Handler{
		DB:   db,
		PDNS: pdnsClient,
		Cfg:  cfg,
		Tmpl: tmpl,
	}
}

func sectionFromTemplate(name string) string {
	name = strings.TrimSuffix(name, ".html")
	switch {
	case name == "login", name == "error":
		return ""
	case name == "dashboard":
		return "dashboard"
	case name == "zones", strings.HasPrefix(name, "zone_"), strings.HasPrefix(name, "record_"):
		return "zones"
	case name == "users", strings.HasPrefix(name, "user_"):
		return "users"
	case name == "groups", strings.HasPrefix(name, "group_"):
		return "groups"
	case name == "profile":
		return "profile"
	case name == "api_keys":
		return "apikeys"
	case name == "tsigkeys", strings.HasPrefix(name, "tsigkey_"):
		return "tsigkeys"
	}
	return ""
}

// render executes a template and automatically injects the CSRF token,
// authenticated user, admin flag, and active section into the data map.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["CSRFToken"] = csrf.Token(r)
	if _, ok := data["User"]; !ok {
		data["User"] = middleware.GetUser(r)
	}
	if _, ok := data["IsAdmin"]; !ok {
		user := middleware.GetUser(r)
		data["IsAdmin"] = user != nil && user.IsAdmin()
	}
	if _, ok := data["Section"]; !ok {
		data["Section"] = sectionFromTemplate(name)
	}
	if err := h.Tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

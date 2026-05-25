// Package handlers contains HTTP handler methods for the GoZone web UI
// and REST API. All handler methods are attached to the Handler struct,
// which holds shared dependencies (database, PowerDNS client, config, templates).
package handlers

import (
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
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

// render executes a template and automatically injects the CSRF token into the data map.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["CSRFToken"] = csrf.Token(r)
	if err := h.Tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

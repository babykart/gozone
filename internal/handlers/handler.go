package handlers

import (
	"database/sql"
	"html/template"
	"net/http"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/pdns"
)

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	DB   *sql.DB
	PDNS *pdns.Client
	Cfg  *config.Config
	Tmpl *template.Template
}

// New creates a new Handler with all dependencies.
func New(db *sql.DB, pdnsClient *pdns.Client, cfg *config.Config, tmpl *template.Template) *Handler {
	return &Handler{
		DB:   db,
		PDNS: pdnsClient,
		Cfg:  cfg,
		Tmpl: tmpl,
	}
}

// render executes a template with the given data.
func (h *Handler) render(w http.ResponseWriter, name string, data interface{}) {
	if err := h.Tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

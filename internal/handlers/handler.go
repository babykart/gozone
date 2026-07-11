// Package handlers contains HTTP handler methods for the GoZone web UI
// and REST API. All handler methods are attached to the Handler struct,
// which holds shared dependencies (database, PowerDNS client, config, templates).
package handlers

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/oidc"
	"github.com/babykart/gozone/internal/pdns"
	"github.com/babykart/gozone/internal/version"
)

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	DB      *database.DB
	PDNS    pdns.ZoneService
	Cfg     *config.Config
	Tmpl    *template.Template
	Version version.Info
	// OIDC is the single sign-on service. It is nil/disabled when SSO is not
	// configured; the OIDC handlers no-op (redirect to /login) in that case.
	// Declared as an interface so tests can substitute a fake without spinning
	// up a live identity provider.
	OIDC SSOService
}

// SSOService is the subset of the OIDC service used by the handlers. The
// concrete implementation lives in internal/oidc; this interface keeps the
// handler package decoupled and unit-testable without a live IdP.
type SSOService interface {
	// Enabled reports whether at least one provider is configured.
	Enabled() bool
	// Providers returns the configured providers (login-button rendering).
	Providers() []*oidc.ProviderInstance
	// AuthCodeURL builds the IdP authorization-endpoint redirect URL.
	AuthCodeURL(provider, callbackURL string) (string, error)
	// HandleCallback verifies the state, exchanges the code, verifies the ID
	// token and returns the normalized user claims.
	HandleCallback(ctx context.Context, provider, code, state, callbackURL string) (*oidc.Claims, error)
	// EndSessionURL returns the provider's RP-initiated logout endpoint, or ""
	// when the provider is unknown or does not advertise one.
	EndSessionURL(provider string) string
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
	case name == "activity":
		return "activity"
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
	case name == "templates", strings.HasPrefix(name, "template_"):
		return "templates"
	}
	return ""
}

// renderInternalError logs the error server-side and shows a generic message to
// the user with HTTP 500, since these are server-side failures. Known
// non-transient PowerDNS configuration errors are surfaced as 400 with a
// user-friendly message instead.
func (h *Handler) renderInternalError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	if status, message := pdnsUserFacingStatus(err); status != 0 {
		logger.Warn(msg, "error", err, "user_message", message)
		h.renderErrorStatus(w, r, status, msg+": "+message)
		return
	}
	logger.Error(msg, "error", err)
	h.renderErrorStatus(w, r, http.StatusInternalServerError, msg)
}

// pdnsUserFacingStatus returns the HTTP status and a user-facing message for a
// PowerDNS client error. It never includes the raw upstream error text — only
// category-level, fixed strings — so a backend error surfacing SQL fragments or
// internal paths through PDNS's {"error":...} body cannot reach the user
// (REVIEW.md M-3). The detailed cause is logged server-side by the caller
// (renderInternalError).
//
// Returns (0, "") for any non-PowerDNS error (e.g. a DB failure), in which case
// the caller falls back to a generic 500.
func pdnsUserFacingStatus(err error) (int, string) {
	switch {
	case errors.Is(err, pdns.ErrValidation):
		return http.StatusBadRequest, "PowerDNS rejected one or more records as invalid."
	case errors.Is(err, pdns.ErrConflict):
		return http.StatusConflict, "PowerDNS reported a conflict for the requested change."
	case errors.Is(err, pdns.ErrNotFound):
		return http.StatusNotFound, "PowerDNS could not find the target resource."
	case errors.Is(err, pdns.ErrUnauthorized):
		return http.StatusUnauthorized, "PowerDNS rejected the operation (authentication failure)."
	case errors.Is(err, pdns.ErrLuaUpdatesDisabled):
		return http.StatusBadRequest, "LUA record updates are disabled on the PowerDNS server. Ask the administrator to set enable-lua-record-updates=yes."
	default:
		return 0, ""
	}
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
		user, _ := data["User"].(*models.User)
		data["IsAdmin"] = user != nil && user.IsAdmin()
	}
	if _, ok := data["AppName"]; !ok {
		data["AppName"] = h.Cfg.Server.AppName
	}
	if _, ok := data["Version"]; !ok {
		data["Version"] = h.Version
	}
	if _, ok := data["Section"]; !ok {
		data["Section"] = sectionFromTemplate(name)
	}
	// Render into a buffer first so a mid-template error never streams a
	// half-written page to the client (which would also make the subsequent
	// 500 status a no-op, since headers are committed on the first Write).
	// The full error is logged server-side; the client gets a generic message
	// so internal details (template paths, field/type names) are not leaked
	// (REVIEW.md L-1).
	var buf bytes.Buffer
	if err := h.Tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		logger.Error("template render failed", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// #nosec G104 -- writing the fully-rendered page to the ResponseWriter;
	// an error here only means the client went away mid-transfer.
	_, _ = w.Write(buf.Bytes())
}

package cmd

import (
	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/mcpserver"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// mountAdminRoutes registers the privileged web UI routes on r, split into two
// sibling role groups: the DNS administration plane (zone create/delete,
// per-zone operations, TSIG keys, templates) is guarded by
// middleware.RequireDNSAdmin — admins and operators — while user and group
// administration stays admin-only via middleware.RequireAdmin. It is the
// single source of truth for the admin routing table so
// TestAdminRoutesProtectedByRequireAdmin can walk it and lock the property
// "every route sits behind its agreed role guard" — a defence-in-depth guard
// against a routing refactor accidentally exposing a privileged handler.
//
// Callers MUST already have applied authentication middleware on r: this
// function adds the role checks on top of the authenticated user, it does not
// establish identity.
func mountAdminRoutes(r chi.Router, h *handlers.Handler, db *database.DB) {
	// DNS administration: admins and operators.
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireDNSAdmin)

		r.Get("/zones/new", h.CreateZonePage)
		r.Post("/zones/create", h.CreateZone)
		r.Post("/zones/delete", h.DeleteZone)
		r.Post("/zones/bulk-delete", h.BulkDeleteZones)

		r.Group(func(r chi.Router) {
			r.Use(middleware.CheckZoneAccess(db))

			r.Post("/zones/{zone_id}/rectify", h.RectifyZone)
			r.Post("/zones/{zone_id}/notify", h.NotifyZone)
			// Admin/operator-only: the cache flush clears the GLOBAL
			// zone-list caches (the lists are not per-zone), so a user with
			// access to a single zone must not be able to trigger it —
			// repeated calls would push every read of every zone back onto
			// PowerDNS.
			r.Post("/zones/{zone_id}/cache/clear", h.ClearZoneCache)
			r.Post("/zones/{zone_id}/metadata/create", h.CreateMetadata)
			r.Post("/zones/{zone_id}/metadata/delete", h.DeleteMetadata)
			r.Post("/zones/{zone_id}/cryptokeys/create", h.CreateCryptokey)
			r.Post("/zones/{zone_id}/cryptokeys/{key_id}/toggle", h.ToggleCryptokey)
			r.Post("/zones/{zone_id}/cryptokeys/{key_id}/delete", h.DeleteCryptokey)
		})

		r.Get("/tsigkeys", h.ListTSIGKeys)
		r.Get("/tsigkeys/new", h.CreateTSIGKeyPage)
		r.Post("/tsigkeys/create", h.CreateTSIGKey)
		r.Get("/tsigkeys/{key_id}/edit", h.EditTSIGKeyPage)
		r.Post("/tsigkeys/{key_id}/update", h.UpdateTSIGKey)
		r.Post("/tsigkeys/delete", h.DeleteTSIGKey)
		r.Post("/tsigkeys/bulk-delete", h.BulkDeleteTSIGKeys)

		r.Get("/templates", h.ListTemplates)
		r.Get("/templates/new", h.CreateTemplatePage)
		r.Post("/templates/create", h.CreateTemplate)
		r.Get("/templates/{template_id}/edit", h.EditTemplatePage)
		r.Post("/templates/{template_id}/update", h.UpdateTemplate)
		r.Post("/templates/{template_id}/delete", h.DeleteTemplate)
		r.Post("/templates/bulk-delete", h.BulkDeleteTemplates)
		r.Post("/templates/{template_id}/records/add", h.AddTemplateRecord)
		r.Post("/templates/{template_id}/records/{record_id}/delete", h.DeleteTemplateRecord)
	})

	// Identity administration: admins only.
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)

		r.Get("/users", h.ListUsers)
		r.Get("/users/new", h.CreateUserPage)
		r.Post("/users/create", h.CreateUser)
		r.Get("/users/{user_id}/edit", h.EditUserPage)
		r.Post("/users/{user_id}/update", h.UpdateUser)
		r.Post("/users/{user_id}/lock", h.LockUser)
		r.Post("/users/{user_id}/unlock", h.UnlockUser)
		r.Post("/users/delete", h.DeleteUser)
		r.Post("/users/bulk-delete", h.BulkDeleteUsers)

		r.Get("/groups", h.ListGroups)
		r.Get("/groups/new", h.CreateGroupPage)
		r.Post("/groups/create", h.CreateGroup)
		r.Get("/groups/{group_id}/edit", h.EditGroupPage)
		r.Post("/groups/{group_id}/update", h.UpdateGroup)
		r.Post("/groups/{group_id}/delete", h.DeleteGroup)
		r.Post("/groups/bulk-delete", h.BulkDeleteGroups)
		r.Post("/groups/{group_id}/add-member", h.AddMemberToGroup)
		r.Post("/groups/{group_id}/remove-member", h.RemoveMemberFromGroup)
		r.Post("/groups/{group_id}/add-zone", h.AddZoneToGroup)
		r.Post("/groups/{group_id}/remove-zone", h.RemoveZoneFromGroup)
	})
}

// mountMCPRoute registers the MCP endpoint on r, behind the same middleware
// stack as /api/v1: pre-auth IP rate limit → API-key authentication →
// per-key rate limit. The SAME limiter instances must be passed as the /api
// group uses, so a client alternating REST and MCP requests draws from one
// budget instead of doubling it.
//
// The endpoint is intentionally NOT under the CSRF middleware: MCP requests
// authenticate by header (API key), not by cookie — and the web session
// cookie must never be accepted on /mcp.
//
// When mcp.enabled is false the route is not mounted at all (404), not
// merely refused; TestMCPRoute tests both states.
func mountMCPRoute(r chi.Router, h *handlers.Handler, db *database.DB, cfg *config.Config, apiIPLimiter, apiLimiter *middleware.RateLimiter) {
	if !cfg.MCP.Enabled {
		return
	}
	r.Group(func(r chi.Router) {
		r.Use(apiIPLimiter.Limit(middleware.ExtractIP))
		r.Use(middleware.APIKeyAuth(db, models.SurfaceMCP))
		r.Use(apiLimiter.Limit(middleware.ExtractAPIKey))
		r.Handle(cfg.MCP.Path, mcpserver.New(h.Ops, &cfg.MCP, h.Version.Version))
	})
}

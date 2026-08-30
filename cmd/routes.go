package cmd

import (
	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/middleware"
)

// mountAdminRoutes registers the admin-only web UI routes on r, every one
// guarded by middleware.RequireAdmin. It is the single source of truth for the
// admin routing table so TestAdminRoutesProtectedByRequireAdmin can walk it and
// lock the property "no admin route escapes RequireAdmin" — a defence-in-depth
// guard against a routing refactor accidentally exposing an admin handler
// (REVIEW.md B-5).
//
// Callers MUST already have applied authentication middleware on r: this
// function adds the admin role check on top of the authenticated user, it does
// not establish identity.
func mountAdminRoutes(r chi.Router, h *handlers.Handler, db *database.DB) {
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)

		r.Get("/zones/new", h.CreateZonePage)
		r.Post("/zones/create", h.CreateZone)
		r.Post("/zones/delete", h.DeleteZone)
		r.Post("/zones/bulk-delete", h.BulkDeleteZones)

		r.Group(func(r chi.Router) {
			r.Use(middleware.CheckZoneAccess(db))

			r.Post("/zones/{zone_id}/rectify", h.RectifyZone)
			r.Post("/zones/{zone_id}/notify", h.NotifyZone)
			r.Post("/zones/{zone_id}/metadata/create", h.CreateMetadata)
			r.Post("/zones/{zone_id}/metadata/delete", h.DeleteMetadata)
			r.Post("/zones/{zone_id}/cryptokeys/create", h.CreateCryptokey)
			r.Post("/zones/{zone_id}/cryptokeys/{key_id}/toggle", h.ToggleCryptokey)
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
		r.Post("/templates/{template_id}/records/{record_id}/update", h.UpdateTemplateRecord)
		r.Post("/templates/{template_id}/records/{record_id}/delete", h.DeleteTemplateRecord)
	})
}

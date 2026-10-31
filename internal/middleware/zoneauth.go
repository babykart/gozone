package middleware

import (
	"net/http"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/logger"
)

func CheckZoneAccess(db *database.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUser(r)
			if user == nil {
				if isAPIRequest(r) {
					writeAPIErrorEnvelope(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
				} else {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				}
				return
			}
			// Admins and operators manage every zone: both skip the
			// per-zone grant probe (see models.User.CanManageDNS).
			if user.CanManageDNS() {
				next.ServeHTTP(w, r)
				return
			}

			zoneID := canonicalizeZonePathValue(r)
			// Routes without a {zone_id} parameter (e.g. /zones list, /api/v1/stats)
			// are handled by handler-level filtering (dnsops.FilterZonesForUser).
			// This middleware only guards routes that carry a specific zone in the URL.
			if zoneID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// The zone-grant query lives in the dnsops service layer
			// (dnsops.CanAccessZone) so the HTTP middleware and the service
			// methods share one authorization source of truth: a future MCP
			// transport, whose zone arrives as a tool argument instead of a
			// URL path segment, re-checks the exact same function.
			allowed, err := dnsops.CanAccessZone(r.Context(), db, user, zoneID)
			if err != nil {
				// A genuine DB error fails closed but surfaces as a
				// distinguishable 500 and is logged server-side; a missing
				// membership row (ErrNoRows) or a client that gave up
				// (context cancellation) stays a 403 — CanAccessZone folds
				// those into (false, nil).
				logger.Error("zone access check failed; denying fail-closed",
					"user_id", user.ID, "zone_id", zoneID, "error", err)
				if isAPIRequest(r) {
					writeAPIErrorEnvelope(w, http.StatusInternalServerError, "INTERNAL_ERROR", "zone access check failed")
				} else {
					http.Error(w, "zone access check failed", http.StatusInternalServerError)
				}
				return
			}
			if allowed {
				next.ServeHTTP(w, r)
				return
			}
			if isAPIRequest(r) {
				writeAPIErrorEnvelope(w, http.StatusForbidden, "FORBIDDEN", "forbidden")
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
		})
	}
}

// CanonicalizeZoneID rewrites the {zone_id} path value to its canonical form
// (lowercase, trailing dot) so every downstream consumer — authorization,
// per-zone write lock, PowerDNS calls, audit trail — keys on the same ID
// whatever spelling the client used ("example.com", "Example.COM.",
// "example.com."), exactly like MCP canonicalises its tool argument at entry.
// Zone-scoped routes that do NOT go through CheckZoneAccess (admin-only
// routes where the access probe is skipped) mount this middleware instead, so
// no path can reach a handler with a non-canonical zone ID. It is a no-op for
// routes without a {zone_id} parameter.
func CanonicalizeZoneID() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			canonicalizeZonePathValue(r)
			next.ServeHTTP(w, r)
		})
	}
}

// canonicalizeZonePathValue normalises the {zone_id} path value in place and
// returns it ("" when the route carries no zone). Without this, two spellings
// of one zone take different mutexes and different audit keys, and an alias
// write can silently drop a concurrent one.
func canonicalizeZonePathValue(r *http.Request) string {
	zoneID := r.PathValue("zone_id")
	if zoneID == "" {
		return ""
	}
	if canonical := dnsops.NormalizeZoneName(zoneID); canonical != zoneID {
		r.SetPathValue("zone_id", canonical)
		zoneID = canonical
	}
	return zoneID
}

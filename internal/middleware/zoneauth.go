package middleware

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
)

func CheckZoneAccess(db *database.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUser(r)
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if user.IsAdmin() {
				next.ServeHTTP(w, r)
				return
			}

			zoneID := r.PathValue("zone_id")
			// Routes without a {zone_id} parameter (e.g. /zones list, /api/v1/stats)
			// are handled by handler-level filtering (filterZonesForUser). This
			// middleware only guards routes that carry a specific zone in the URL.
			if zoneID == "" {
				next.ServeHTTP(w, r)
				return
			}

			var exists int
			err := db.QueryRowContext(
				r.Context(),
				`SELECT 1 FROM zone_group_members m
				 JOIN zone_group_zones z ON m.group_id = z.group_id
				 WHERE m.user_id = ? AND z.zone_id = ?
				 LIMIT 1`,
				user.ID, zoneID,
			).Scan(&exists)

			if err == nil && exists == 1 {
				next.ServeHTTP(w, r)
				return
			}

			// Access could not be confirmed. Distinguish a genuine denial from a
			// real DB fault: previously every non-nil error (including a DB
			// outage) collapsed into a 403, so a database downpour looked
			// identical to a stream of legitimate denials and the error was
			// swallowed. Now a genuine DB error fails closed but surfaces as a
			// distinguishable 500 and is logged server-side; a missing
			// membership row (ErrNoRows) or a client that gave up
			// (context cancellation) stays a 403.
			if err != nil &&
				!errors.Is(err, sql.ErrNoRows) &&
				!errors.Is(err, context.Canceled) &&
				!errors.Is(err, context.DeadlineExceeded) {
				logger.Error("zone access check failed; denying fail-closed",
					"user_id", user.ID, "zone_id", zoneID, "error", err)
				http.Error(w, "zone access check failed", http.StatusInternalServerError)
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

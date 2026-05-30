package middleware

import (
	"net/http"

	"github.com/babykart/gozone/internal/database"
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
			if zoneID == "" {
				next.ServeHTTP(w, r)
				return
			}

			var exists int
			err := db.QueryRow(
				`SELECT 1 FROM zone_group_members m
				 JOIN zone_group_zones z ON m.group_id = z.group_id
				 WHERE m.user_id = ? AND z.zone_id = ?
				 LIMIT 1`,
				user.ID, zoneID,
			).Scan(&exists)

			if err != nil || exists != 1 {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

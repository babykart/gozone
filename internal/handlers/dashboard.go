package handlers

import (
	"net/http"
	"strconv"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
)

// Dashboard renders the main dashboard page with PowerDNS server statistics,
// zone and user counts, and recent activity logs (GET /dashboard).
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	// Fetch statistics
	stats, err := h.PDNS.GetStatistics()

	// Get server info
	server, _ := h.PDNS.GetServer()

	// Get zone count (filtered by user's allowed zones)
	zones, _ := h.PDNS.ListZones()
	zones, _ = h.filterZonesForUser(r, zones)
	zoneCount := 0
	if zones != nil {
		zoneCount = len(zones)
	}

	// Get recent activity logs
	logs := h.getRecentActivityLogs(20)

	// Get user count
	var userCount int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		logger.Error("failed to scan user count", "error", err)
	}

	type StatItem struct {
		Label string
		Value string
	}

	var dashboardStats []StatItem
	dashboardStats = append(dashboardStats, StatItem{Label: "Zones", Value: strconv.Itoa(zoneCount)})
	dashboardStats = append(dashboardStats, StatItem{Label: "Users", Value: strconv.Itoa(userCount)})

	if server != nil {
		dashboardStats = append(dashboardStats, StatItem{Label: "PDNS Version", Value: server.Version})
		dashboardStats = append(dashboardStats, StatItem{Label: "Daemon Type", Value: server.Daemon})
	}

	if stats != nil && err == nil {
		for _, s := range stats {
			switch s.Name {
			case "udp-queries", "udp-answers", "tcp-queries", "tcp-answers":
				dashboardStats = append(dashboardStats, StatItem{Label: s.Name, Value: s.Value})
			}
		}
	}

	data := map[string]interface{}{
		"Title":   "Dashboard - GoZone",
		"User":    user,
		"Stats":   dashboardStats,
		"Logs":    logs,
		"Zones":   zoneCount,
		"Server":  server,
		"IsAdmin": user.IsAdmin(),
	}
	h.render(w, r, "dashboard.html", data)
}

func (h *Handler) getRecentActivityLogs(limit int) []map[string]interface{} {
	rows, err := h.DB.Query(
		`SELECT al.id, al.action, al.details, al.zone_id, al.created_at, u.username
		 FROM activity_logs al
		 LEFT JOIN users u ON al.user_id = u.id
		 ORDER BY al.created_at DESC
		 LIMIT ?`, limit,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id int64
		var action, details, username string
		var zoneID *string
		var createdAt string
		if err := rows.Scan(&id, &action, &details, &zoneID, &createdAt, &username); err != nil {
			logger.Error("failed to scan activity log row", "error", err)
			continue
		}

		log := map[string]interface{}{
			"id":         id,
			"action":     action,
			"details":    details,
			"username":   username,
			"created_at": createdAt,
		}
		if zoneID != nil {
			log["zone_id"] = *zoneID
		}
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for activity logs", "error", err)
	}
	return logs
}

package handlers

import (
	"fmt"
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
	stats, err := h.PDNS.GetStatistics(r.Context())
	if err != nil {
		logger.Error("failed to fetch PDNS statistics", "error", err)
	}

	// Get server info
	server, _ := h.PDNS.GetServer(r.Context())

	// Get zone count (filtered by user's allowed zones)
	zones, _ := h.PDNS.ListZones(r.Context())
	zones, _ = h.filterZonesForUser(r, zones)
	zoneCount := 0
	if zones != nil {
		zoneCount = len(zones)
	}

	// Get recent activity logs with pagination
	page, perPage := parsePaginationParams(r, 10)
	logs, total := h.getRecentActivityLogs(page, perPage)
	totalPages := 0
	if perPage > 0 {
		totalPages = (total + perPage - 1) / perPage
	} else {
		totalPages = 1
	}
	pageInfo := PageInfo{
		Current:    page,
		PerPage:    perPage,
		TotalPages: totalPages,
		Total:      total,
	}

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

	if err == nil {
		for _, s := range stats {
			switch s.Name {
			case "udp-queries", "udp-answers", "tcp-queries", "tcp-answers":
				dashboardStats = append(dashboardStats, StatItem{Label: s.Name, Value: valToString(s.Value)})
			}
		}
	}

	serverStats := make(map[string]string)
	for _, s := range stats {
		serverStats[s.Name] = valToString(s.Value)
	}

	data := map[string]interface{}{
		"Title":       "Dashboard - GoZone",
		"User":        user,
		"Stats":       dashboardStats,
		"Logs":        logs,
		"PageInfo":    pageInfo,
		"Search":      "",
		"Zones":       zoneCount,
		"Server":      server,
		"ServerStats": serverStats,
		"IsAdmin":     user.IsAdmin(),
	}
	h.render(w, r, "dashboard.html", data)
}

func (h *Handler) getRecentActivityLogs(page, perPage int) ([]map[string]interface{}, int) {
	var total int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs").Scan(&total); err != nil {
		logger.Error("failed to count activity logs", "error", err)
		return nil, 0
	}

	offset := 0
	limit := perPage
	if perPage > 0 {
		if page < 1 {
			page = 1
		}
		offset = (page - 1) * perPage
		limit = perPage
	}

	var query string
	var args []interface{}
	if perPage > 0 {
		query = `SELECT al.id, al.action, al.details, al.zone_id, al.created_at, u.username
		 FROM activity_logs al
		 LEFT JOIN users u ON al.user_id = u.id
		 ORDER BY al.created_at DESC
		 LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	} else {
		query = `SELECT al.id, al.action, al.details, al.zone_id, al.created_at, u.username
		 FROM activity_logs al
		 LEFT JOIN users u ON al.user_id = u.id
		 ORDER BY al.created_at DESC`
	}

	rows, err := h.DB.Query(query, args...)
	if err != nil {
		return nil, 0
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
	return logs, total
}

// valToString converts a PDNS statistic value (string, number, bool, array, or nil)
// to its string representation for display in the dashboard.
func valToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

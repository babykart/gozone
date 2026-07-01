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
	filtered, filterErr := h.filterZonesForUser(r, zones)
	if filterErr != nil {
		logger.Error("failed to filter zones for user", "error", filterErr)
	}
	zones = filtered
	zoneCount := 0
	if zones != nil {
		zoneCount = len(zones)
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
		"Title":       "Dashboard - " + h.Cfg.Server.AppName,
		"User":        user,
		"Stats":       dashboardStats,
		"Search":      "",
		"Zones":       zoneCount,
		"Server":      server,
		"ServerStats": serverStats,
		"IsAdmin":     user.IsAdmin(),
	}
	h.render(w, r, "dashboard.html", data)
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

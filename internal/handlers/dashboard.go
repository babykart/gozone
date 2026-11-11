package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
)

// Dashboard renders the main dashboard page with PowerDNS server statistics,
// zone and user counts, and recent activity logs (GET /dashboard).
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	// Password-expiry warning: days remaining when the password is inside the
	// configured warning window (0 otherwise — disabled or not yet imminent).
	passwordWarnDays := 0
	if user != nil {
		passwordWarnDays = passwordExpiryWarnDays(h.Cfg.Password.MaxAgeDays, h.Cfg.Password.ExpiryWarnDays, user.PasswordChangedAt)
	}

	// Statistics and the visible zone count are one composite service call:
	// the zone count is meaningless without the zone list, and the upstream
	// calls are independent, so the service tags the failing stage and the
	// mapping below decides how far the page may degrade.
	stats, zoneCount, err := h.Ops.Stats(r.Context(), user)
	if err != nil {
		var se *dnsops.StageError
		if errors.As(err, &se) {
			switch se.Stage {
			case dnsops.StageStatistics:
				// Statistics stay degraded-by-design: the dashboard remains
				// useful without the PDNS counter items, so log and render
				// with nil stats (no counter items, empty serverStats).
				logger.Error("failed to fetch PDNS statistics", "error", err)
			case dnsops.StageZoneList:
				// A failed zone list is an upstream outage, not an empty
				// result: rendering the dashboard with "0 zones" would
				// present the outage as if the zones had vanished. Fail
				// closed with a visible error.
				h.renderInternalError(w, r, "Failed to list zones", err)
				return
			default:
				// A failed zone-access lookup is a database fault, not an
				// empty result; fail closed with a visible error rather than
				// a dashboard that claims zero zones.
				h.renderInternalError(w, r, "Failed to load zone access", err)
				return
			}
		} else {
			h.renderInternalError(w, r, "Failed to load zone access", err)
			return
		}
	}

	// Get server info
	server, _ := h.PDNS.GetServer(r.Context())

	// Get user count
	var userCount int
	if err := h.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
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

	for _, s := range stats {
		switch s.Name {
		case "udp-queries", "udp-answers", "tcp-queries", "tcp-answers":
			dashboardStats = append(dashboardStats, StatItem{Label: s.Name, Value: valToString(s.Value)})
		}
	}

	serverStats := make(map[string]string)
	for _, s := range stats {
		serverStats[s.Name] = valToString(s.Value)
	}

	data := map[string]interface{}{
		"Title":              "Dashboard - " + h.Cfg.Server.AppName,
		"User":               user,
		"Stats":              dashboardStats,
		"Search":             "",
		"Zones":              zoneCount,
		"Server":             server,
		"ServerStats":        serverStats,
		"IsAdmin":            user.IsAdmin(),
		"PasswordExpiryWarn": passwordWarnDays,
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

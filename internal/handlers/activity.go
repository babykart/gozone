package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

// ActivityPage renders the full activity log page with search, filters,
// date range selection, and pagination (GET /activity).
func (h *Handler) ActivityPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	page, perPage := parsePaginationParams(r, 10)
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	fromDate := strings.TrimSpace(r.URL.Query().Get("from"))
	toDate := strings.TrimSpace(r.URL.Query().Get("to"))

	actions, err := h.getDistinctActivityActions(r.Context(), user)
	if err != nil {
		logger.Error("failed to fetch activity actions", "error", err)
	}

	logs, total := h.getActivityLogs(r.Context(), user, search, action, fromDate, toDate, page, perPage)
	// pageInfoFromTotal clamps Current to the last page, matching the clamp
	// getActivityLogs applies to the SQL OFFSET — the displayed page is
	// always the page that was actually fetched ("page 3 / 3", never
	// "page 1000 / 3").
	pageInfo := pageInfoFromTotal(total, page, perPage)

	// extra carries the active filters as separate key/value pairs. The
	// pagination partial re-renders each pair individually: interpolating a
	// pre-joined "action=login&from=…" string makes html/template escape it
	// as one opaque query value (action%3dlogin%26…), silently dropping the
	// filters on page navigation.
	extra := url.Values{}
	if action != "" {
		extra.Set("action", action)
	}
	if fromDate != "" {
		extra.Set("from", fromDate)
	}
	if toDate != "" {
		extra.Set("to", toDate)
	}

	data := map[string]interface{}{
		"Title":      "Activity - " + h.Cfg.Server.AppName,
		"User":       user,
		"Logs":       logs,
		"PageInfo":   pageInfo,
		"Search":     search,
		"Action":     action,
		"From":       fromDate,
		"To":         toDate,
		"Actions":    actions,
		"IsAdmin":    user.IsAdmin(),
		"ServerTime": time.Now().UTC(),
		"Extra":      extra,
	}
	h.render(w, r, "activity.html", data)
}

// getDistinctActivityActions returns the distinct action values visible to the
// given user, ordered alphabetically, so the filter dropdown can be built.
// Admin users see all actions; non-admin users see only actions from logs they
// are allowed to view. ctx propagates request cancellation into the query.
func (h *Handler) getDistinctActivityActions(ctx context.Context, user *models.User) ([]string, error) {
	query := "SELECT DISTINCT action FROM activity_logs AS al"
	var args []interface{}
	if clause, clauseArgs := activityLogVisibilityClause(user); clause != "" {
		query += " WHERE " + clause
		args = clauseArgs
	}
	query += " ORDER BY action"

	rows, err := h.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			logger.Error("failed to scan distinct activity action", "error", err)
			continue
		}
		actions = append(actions, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return actions, nil
}

// activityLogVisibilityClause returns the SQL WHERE clause (and args) that
// restricts activity logs to the ones visible to the given user. Admins see
// everything; non-admins see zone-scoped logs for zones in their groups plus
// their own non-zone logs.
func activityLogVisibilityClause(user *models.User) (string, []interface{}) {
	if user.IsAdmin() {
		return "", nil
	}
	return "((al.zone_id IS NULL AND al.user_id = ?) OR al.zone_id IN (SELECT z.zone_id FROM zone_group_members m JOIN zone_group_zones z ON m.group_id = z.group_id WHERE m.user_id = ?))", []interface{}{user.ID, user.ID}
}

// activityLogAllCap bounds the "All" (perPage = 0) view of the activity
// log. Without it any authenticated user could load the entire table —
// including the old/new JSON snapshots — in one request; a large deployment
// turns that into a memory DoS. The cap applies to both the global activity
// view and the per-zone tab; "All" now means "at most 1000 most recent".
const activityLogAllCap = 1000

// getActivityLogs returns activity logs visible to the given user, after
// applying text search, action filter, date range, and pagination. Admin users
// see all logs; non-admin users see zone-scoped logs for zones assigned to
// their groups together with non-zone logs created by themselves. ctx
// propagates request cancellation into both queries.
//
// perPage = 0 ("All") is capped at activityLogAllCap rows: the snapshots make
// each row expensive, and an unbounded fetch of the whole table is a memory
// DoS vector. The total count still reflects the real row count, so the UI
// keeps showing the true size of the log.
func (h *Handler) getActivityLogs(ctx context.Context, user *models.User, search, action, fromDate, toDate string, page, perPage int) ([]models.ActivityLog, int) {
	var total int
	countQuery, countArgs := h.buildActivityLogQuery(user, search, action, fromDate, toDate)
	if err := h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM activity_logs AS al "+countQuery, countArgs...).Scan(&total); err != nil {
		logger.Error("failed to count activity logs", "error", err)
		return nil, 0
	}

	if page < 1 {
		page = 1
	}
	// Clamp to the last page BEFORE the offset math: an oversized page from
	// the query string would otherwise overflow (page-1)*perPage into a
	// nonsense (possibly negative) OFFSET, and the UI would show
	// "page 1000 / 3".
	page = clampPageToTotal(page, perPage, total)
	offset := 0
	limit := perPage
	if perPage > 0 {
		offset = (page - 1) * perPage
	}

	query, args := h.buildActivityLogQuery(user, search, action, fromDate, toDate)
	query = `SELECT al.id, al.user_id, al.zone_id, al.action, al.details, al.old_value, al.new_value, al.created_at, u.username
	FROM activity_logs AS al ` + query + `
	ORDER BY al.created_at DESC`
	if perPage > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	} else {
		// "All" is capped: see activityLogAllCap.
		query += " LIMIT ?"
		args = append(args, activityLogAllCap)
	}

	rows, err := h.DB.QueryContext(ctx, query, args...)
	if err != nil {
		logger.Error("failed to query activity logs", "error", err)
		return nil, total
	}
	defer rows.Close()

	var logs []models.ActivityLog
	for rows.Next() {
		var log models.ActivityLog
		var username sql.NullString
		if err := rows.Scan(&log.ID, &log.UserID, &log.ZoneID, &log.Action, &log.Details, &log.OldValue, &log.NewValue, &log.CreatedAt, &username); err != nil {
			logger.Error("failed to scan activity log row", "error", err)
			continue
		}
		log.Username = username.String
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for activity logs", "error", err)
	}
	return logs, total
}

// buildActivityLogQuery constructs the JOIN and WHERE clauses for activity log
// filtering. The returned clause always includes the users join so that both
// the SELECT and COUNT queries can reference u.username when a search term is
// supplied.
func (h *Handler) buildActivityLogQuery(user *models.User, search, action, fromDate, toDate string) (string, []interface{}) {
	var filters []string
	var args []interface{}

	selectClause := "LEFT JOIN users u ON al.user_id = u.id "

	if search != "" {
		// Wildcards in the term are neutralised (escapeLikePattern) and the
		// ESCAPE clause is paired with every LIKE — same semantics as the
		// list-view searches, so "%" or "_" in the input match literally.
		term := "%" + strings.ToLower(escapeLikePattern(search)) + "%"
		filters = append(filters,
			"(LOWER(al.action) LIKE ? ESCAPE '"+likeEscapeChar+"' OR LOWER(al.details) LIKE ? ESCAPE '"+likeEscapeChar+"'"+
				" OR LOWER(al.zone_id) LIKE ? ESCAPE '"+likeEscapeChar+"' OR LOWER(u.username) LIKE ? ESCAPE '"+likeEscapeChar+"')")
		args = append(args, term, term, term, term)
	}

	if action != "" {
		filters = append(filters, "al.action = ?")
		args = append(args, action)
	}

	if fromDate != "" {
		if t, err := time.Parse("2006-01-02", fromDate); err == nil {
			filters = append(filters, "al.created_at >= ?")
			args = append(args, t.Format("2006-01-02 15:04:05"))
		}
	}
	if toDate != "" {
		if t, err := time.Parse("2006-01-02", toDate); err == nil {
			// Include the full selected day.
			end := t.Add(24*time.Hour - time.Second)
			filters = append(filters, "al.created_at <= ?")
			args = append(args, end.Format("2006-01-02 15:04:05"))
		}
	}

	if !user.IsAdmin() {
		clause, clauseArgs := activityLogVisibilityClause(user)
		filters = append(filters, clause)
		args = append(args, clauseArgs...)
	}

	where := ""
	if len(filters) > 0 {
		where = "WHERE " + strings.Join(filters, " AND ")
	}

	return selectClause + where, args
}

// PurgeActivityLogs is a helper used by admin/background processes to purge
// activity logs older than the configured retention period. It returns the
// number of rows deleted.
func (h *Handler) PurgeActivityLogs() (int64, error) {
	return h.DB.PurgeActivityLogs(context.Background(), h.Cfg.Activity.RetentionDays, h.Cfg.Activity.BatchSize)
}

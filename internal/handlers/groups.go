package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

type groupInfo struct {
	ID          int64
	Name        string
	Description string
	CreatedAt   string
}

// ListGroups renders the zone groups management page (GET /groups).
func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	where, args := buildSearchLikeWhere(search, "name", "description")

	countQuery := "SELECT COUNT(*) FROM zone_groups"
	selectQuery := "SELECT id, name, description, created_at FROM zone_groups"
	if where != "" {
		countQuery += " WHERE " + where
		selectQuery += " WHERE " + where
	}
	selectQuery += " ORDER BY name"

	var total int
	if err := h.DB.QueryRowContext(r.Context(), countQuery, args...).Scan(&total); err != nil {
		h.renderInternalError(w, r, "Failed to count groups", err)
		return
	}

	page, perPage := parsePaginationParams(r, 10)
	pageInfo := pageInfoFromTotal(total, page, perPage)

	var rows *sql.Rows
	var err error
	if perPage > 0 {
		offset := (pageInfo.Current - 1) * perPage
		selectArgs := append([]any(nil), args...)
		selectArgs = append(selectArgs, perPage, offset)
		rows, err = h.DB.QueryContext(r.Context(), selectQuery+" LIMIT ? OFFSET ?", selectArgs...)
	} else {
		rows, err = h.DB.QueryContext(r.Context(), selectQuery, args...)
	}
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch groups", err)
		return
	}
	defer rows.Close()

	var groups []groupInfo
	for rows.Next() {
		var g groupInfo
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
			logger.Error("failed to scan group row", "error", err)
			continue
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for groups list", "error", err)
	}

	if groups == nil {
		groups = []groupInfo{}
	}

	data := map[string]interface{}{
		"Title":    "Groups - " + h.Cfg.Server.AppName,
		"User":     user,
		"Groups":   groups,
		"PageInfo": pageInfo,
		"Search":   search,
		"IsAdmin":  user.IsAdmin(),
	}
	h.render(w, r, "groups.html", data)
}

// maxGroupSelectOptions caps how many users/zones the group forms render in
// their <select> dropdowns. Rendering the full tables made the page grow with
// the deployment (every user, every PowerDNS zone) while every other list
// view is paginated or searchable server-side. Beyond the cap the edit page
// narrows the list through its server-side search fields; the create form
// keeps its first-N slice and points larger selections at the edit page.
const maxGroupSelectOptions = 100

// CreateGroupPage renders the group creation form (GET /groups/new).
func (h *Handler) CreateGroupPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)

	// No search fields here: the multi-select carries the operator's pending
	// selection in the DOM, and a server-side search reload would drop it.
	// The lists are merely capped; the truncation flags let the template
	// point large selections at the edit page's incremental add + search.
	allUsers, usersTruncated, _ := h.getAllUsers(r.Context(), "")
	zonesAll, _ := h.PDNS.ListZonesWithInfo(r.Context())
	allZones, zonesTruncated := filterZonesWithInfoForSearch(zonesAll, "")

	data := map[string]interface{}{
		"Title":          "Create Group - " + h.Cfg.Server.AppName,
		"User":           user,
		"Group":          groupInfo{},
		"Members":        []models.User{},
		"GroupZones":     []string{},
		"AllUsers":       allUsers,
		"AllZones":       allZones,
		"UsersTruncated": usersTruncated,
		"ZonesTruncated": zonesTruncated,
		"IsAdmin":        user.IsAdmin(),
		"FormAction":     "/groups/create",
	}
	h.render(w, r, "group_edit.html", data)
}

// CreateGroup inserts a new zone group and attaches the members and zones
// selected on the create page (POST /groups/create).
//
// The create form posts name + description plus, optionally, repeated
// "user_ids" and "zone_ids" values from the multi-select dropdowns. Selections
// are attached best-effort after the group row is inserted: an invalid or
// duplicate entry is skipped (INSERT OR IGNORE / ON CONFLICT DO NOTHING) and
// logged, it never aborts the create.
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, "Invalid form data")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))

	if name == "" {
		h.renderError(w, r, "Group name is required")
		return
	}

	id, err := h.DB.ExecReturnID(r.Context(),
		"INSERT INTO zone_groups (name, description) VALUES (?, ?)",
		name, description,
	)
	if err != nil {
		if errors.Is(err, database.ErrUniqueViolation) {
			h.renderError(w, r, "A group with that name already exists")
			return
		}
		h.renderInternalError(w, r, "Failed to create group", err)
		return
	}

	skipped := h.attachGroupSelections(r, id)

	target := "/groups/" + strconv.FormatInt(id, 10) + "/edit"
	if skipped > 0 {
		// Some submitted members did not exist (stale form / tampered request)
		// and were skipped — surface it so the admin is not left with a silent
		// partial add (REVIEW.md B-4).
		target += "?flash=members_skipped"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// groupValidFlashCodes is the allow-list of ?flash codes the server actually
// emits for /groups/{id}/edit (CreateGroup -> members_skipped). EditGroupPage
// validates the incoming query param against this set so a crafted link cannot
// inject arbitrary text into the page — the handler is the trust boundary,
// mirroring apiKeyValidFlashCodes (REVIEW.md B-4 / L-1).
var groupValidFlashCodes = map[string]struct{}{
	"members_skipped": {},
}

// existingUserIDBatchSize caps how many bound parameters one validation query
// carries. SQL engines limit the number of variables per statement (SQLite
// historically 999, modern SQLite 32766, some servers 2100); an IN (...) built
// with one placeholder per submitted id fails wholesale once a selection
// exceeds that limit. 500 stays comfortably below the strictest common limit.
const existingUserIDBatchSize = 500

// existingUserIDs returns the subset of ids that exist in the users table. It
// validates in batches of existingUserIDBatchSize bound parameters, so a
// selection of any size works regardless of the driver's per-statement
// variable limit — one round-trip per 500 ids.
func (h *Handler) existingUserIDs(ctx context.Context, ids []int64) (map[int64]bool, error) {
	exists := make(map[int64]bool, len(ids))
	for start := 0; start < len(ids); start += existingUserIDBatchSize {
		end := min(start+existingUserIDBatchSize, len(ids))
		if err := h.queryExistingUserIDs(ctx, ids[start:end], exists); err != nil {
			return nil, err
		}
	}
	return exists, nil
}

// queryExistingUserIDs runs the single-batch IN (...) lookup, recording the
// ids that match a users row into exists.
func (h *Handler) queryExistingUserIDs(ctx context.Context, batch []int64, exists map[int64]bool) error {
	placeholders := make([]string, len(batch))
	args := make([]any, len(batch))
	for i, id := range batch {
		placeholders[i] = "?"
		args[i] = id
	}
	q := "SELECT id FROM users WHERE id IN (" + strings.Join(placeholders, ",") + ")"
	rows, err := h.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		exists[id] = true
	}
	return rows.Err()
}

// attachGroupSelections inserts the multi-select members (user_ids) and zones
// (zone_ids) carried by the create form into the just-created group. User IDs
// are validated as positive ints and their existence is checked in one batched
// query before insertion: a stale or tampered user_id would otherwise be
// silently dropped by InsertIgnore (FK violation) with no feedback to the
// admin. Non-existent users are skipped and counted; the count is returned so
// CreateGroup can surface a warning. Zone IDs are trimmed strings referencing
// PowerDNS zones (no users-table FK to validate against). Both lists are
// de-duplicated while preserving order. Each row uses InsertIgnore so a
// repeated selection is tolerated. Errors are logged, not fatal (REVIEW.md
// B-4).
func (h *Handler) attachGroupSelections(r *http.Request, groupID int64) int {
	var userIDs []int64
	seenUsers := make(map[int64]struct{})
	for _, raw := range r.PostForm["user_ids"] {
		uid, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || uid <= 0 {
			continue
		}
		if _, dup := seenUsers[uid]; dup {
			continue
		}
		seenUsers[uid] = struct{}{}
		userIDs = append(userIDs, uid)
	}

	// Validate existence before insertion. On a transient query error fail open
	// (attempt every id, the previous behaviour) so group creation is not
	// blocked by the validation query.
	existing, err := h.existingUserIDs(r.Context(), userIDs)
	if err != nil {
		logger.Error("failed to validate group member existence; failing open",
			"group_id", groupID, "error", err)
		existing = make(map[int64]bool, len(userIDs))
		for _, uid := range userIDs {
			existing[uid] = true
		}
	}

	skipped := 0
	for _, uid := range userIDs {
		if !existing[uid] {
			skipped++
			logger.Warn("skipped non-existent user on group create",
				"group_id", groupID, "user_id", uid)
			continue
		}
		if _, err := h.DB.InsertIgnore(r.Context(), "zone_group_members",
			[]string{"group_id", "user_id"},
			[]string{"group_id", "user_id"},
			groupID, uid); err != nil {
			logger.Error("failed to add member to group on create",
				"group_id", groupID, "user_id", uid, "error", err)
		}
	}

	seenZones := make(map[string]struct{})
	for _, raw := range r.PostForm["zone_ids"] {
		zoneID := strings.TrimSpace(raw)
		if zoneID == "" {
			continue
		}
		if _, dup := seenZones[zoneID]; dup {
			continue
		}
		seenZones[zoneID] = struct{}{}
		if _, err := h.DB.InsertIgnore(r.Context(), "zone_group_zones",
			[]string{"group_id", "zone_id"},
			[]string{"group_id", "zone_id"},
			groupID, zoneID); err != nil {
			logger.Error("failed to add zone to group on create",
				"group_id", groupID, "zone_id", zoneID, "error", err)
		}
	}

	return skipped
}

// EditGroupPage renders the group edit form with members and zones (GET /groups/{group_id}/edit).
func (h *Handler) EditGroupPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	groupIDStr := r.PathValue("group_id")
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid group ID")
		return
	}

	var g groupInfo
	err = h.DB.QueryRowContext(r.Context(),
		"SELECT id, name, description, created_at FROM zone_groups WHERE id = ?", groupID,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		h.renderErrorStatus(w, r, http.StatusNotFound, "Group not found")
		return
	}
	if err != nil {
		h.renderInternalError(w, r, "Failed to fetch group", err)
		return
	}

	members := h.getGroupMembers(r.Context(), groupID)
	zones := h.getGroupZones(r.Context(), groupID)

	// Server-side search for the incremental add dropdowns. Unlike the create
	// form (whose multi-select carries the pending selection in the DOM and
	// must not reload), these are single-selects: narrowing via a GET reload
	// is lossless and matches how every other list view searches.
	userSearch := strings.TrimSpace(r.URL.Query().Get("uq"))
	zoneSearch := strings.TrimSpace(r.URL.Query().Get("zq"))
	allUsers, usersTruncated, _ := h.getAllUsers(r.Context(), userSearch)
	zonesAll, zonesErr := h.PDNS.ListZonesWithInfo(r.Context())
	allZones, zonesTruncated := filterZonesWithInfoForSearch(zonesAll, zoneSearch)
	if zonesErr != nil {
		// PowerDNS is unreachable: the dropdown renders empty (previous
		// behaviour) and the grant reconciliation below is skipped — a failed
		// zone list must never look like "all zones gone".
		logger.Error("failed to list zones for group edit", "group_id", groupID, "error", zonesErr)
	} else {
		// Opportunistic garbage collection: an admin opening the group page
		// is the natural moment to drop grants for zones that vanished from
		// PowerDNS (the hourly background job covers deployments where nobody
		// visits). Best-effort — a failure here must not block the page.
		if _, err := h.reconcileGroupZones(r.Context(), zonesAll); err != nil {
			logger.Error("group zone grant reconciliation failed", "group_id", groupID, "error", err)
		}
		// The reconciliation above may have removed rows the zones slice
		// fetched earlier still holds; re-read so the assigned-zones table
		// matches the database.
		zones = h.getGroupZones(r.Context(), groupID)
	}

	flash := allowListedCode(r.URL.Query().Get("flash"), groupValidFlashCodes)

	data := map[string]interface{}{
		"Title":          g.Name + " - " + h.Cfg.Server.AppName,
		"User":           user,
		"Group":          g,
		"Members":        members,
		"GroupZones":     zones,
		"AllUsers":       allUsers,
		"AllZones":       allZones,
		"UsersTruncated": usersTruncated,
		"ZonesTruncated": zonesTruncated,
		"UserSearch":     userSearch,
		"ZoneSearch":     zoneSearch,
		"IsAdmin":        user.IsAdmin(),
		"FormAction":     "/groups/" + groupIDStr + "/update",
		"Flash":          flash,
	}
	h.render(w, r, "group_edit.html", data)
}

// UpdateGroup updates a group's name and description (POST /groups/{group_id}/update).
func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid group ID")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))

	if name == "" {
		h.renderError(w, r, "Group name is required")
		return
	}

	_, err = h.DB.ExecContext(r.Context(),
		"UPDATE zone_groups SET name = ?, description = ? WHERE id = ?",
		name, description, groupID,
	)
	if err != nil {
		if errors.Is(err, database.ErrUniqueViolation) {
			h.renderError(w, r, "A group with that name already exists")
			return
		}
		h.renderInternalError(w, r, "Failed to update group", err)
		return
	}

	http.Redirect(w, r, "/groups/"+strconv.FormatInt(groupID, 10)+"/edit", http.StatusSeeOther)
}

// DeleteGroup deletes a group (POST /groups/{group_id}/delete).
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	// Validate as a positive int before binding: the column is typed INTEGER,
	// so an unvalidated string yields a 500 on PostgreSQL and a confusing
	// partial result on MySQL/SQLite — the same class the neighbouring
	// member/zone handlers guard against.
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil || groupID <= 0 {
		h.renderError(w, r, "Invalid group ID")
		return
	}

	res, err := h.DB.ExecContext(r.Context(), "DELETE FROM zone_groups WHERE id = ?", groupID)
	if err != nil {
		h.renderInternalError(w, r, "Failed to delete group", err)
		return
	}
	// A delete that matched no row is a missing group (already deleted or a
	// stale link): surface 404 instead of a silent success redirect, mirroring
	// EditGroupPage.
	if n, _ := res.RowsAffected(); n == 0 {
		h.renderErrorStatus(w, r, http.StatusNotFound, "Group not found")
		return
	}
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

// BulkDeleteGroups deletes several zone groups by group_id
// (POST /groups/bulk-delete).
//
// Admin-only. The selection arrives as repeated "group_id" form values. Child
// rows (members, zones) are removed by the foreign-key cascade, exactly as for
// the single DeleteGroup. The operation is best-effort: a group that no longer
// exists (or whose DELETE fails) is reported in `failed` without aborting the
// rest. Returns JSON {deleted, failed} for the AJAX toolbar.
func (h *Handler) BulkDeleteGroups(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid form data"})
		return
	}

	// Dedupe while preserving order; drop anything that is not a positive int.
	seen := make(map[int64]struct{})
	var groupIDs []int64
	for _, idStr := range r.PostForm["group_id"] {
		id, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		groupIDs = append(groupIDs, id)
	}

	if len(groupIDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No groups selected"})
		return
	}

	deleted := 0
	var failed []string
	for _, gid := range groupIDs {
		res, err := h.DB.ExecContext(r.Context(), "DELETE FROM zone_groups WHERE id = ?", gid)
		if err != nil {
			logger.Error("bulk delete group failed", "group_id", gid, "error", err)
			failed = append(failed, strconv.FormatInt(gid, 10))
			continue
		}
		if n, _ := res.RowsAffected(); n == 0 {
			failed = append(failed, strconv.FormatInt(gid, 10))
			continue
		}
		deleted++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}

// AddMemberToGroup adds a user to a group (POST /groups/{group_id}/add-member).
func (h *Handler) AddMemberToGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid group ID")
		return
	}
	// Validate user_id as a positive int — the column is typed INTEGER, so an
	// unvalidated string yields a 500 on Postgres (and a confusing partial
	// insert on MySQL/SQLite). Mirrors attachGroupSelections (REVIEW.md M-4).
	userIDStr := strings.TrimSpace(r.FormValue("user_id"))
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || userID <= 0 {
		h.renderError(w, r, "Invalid user ID")
		return
	}

	// Validate existence before inserting: InsertIgnore would otherwise drop a
	// non-existent user_id silently (FK violation) with no feedback — the same
	// gap as attachGroupSelections (REVIEW.md B-4).
	existing, err := h.existingUserIDs(r.Context(), []int64{userID})
	if err != nil {
		h.renderInternalError(w, r, "Failed to validate user", err)
		return
	}
	if !existing[userID] {
		h.renderError(w, r, "User does not exist")
		return
	}

	if _, err := h.DB.InsertIgnore(r.Context(), "zone_group_members",
		[]string{"group_id", "user_id"},
		[]string{"group_id", "user_id"}, // PK on this table
		groupID, userID); err != nil {
		logger.Error("failed to add member to group", "group_id", groupID, "user_id", userID, "error", err)
	}
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(groupID, 10)+"/edit", http.StatusSeeOther)
}

// RemoveMemberFromGroup removes a user from a group (POST /groups/{group_id}/remove-member).
func (h *Handler) RemoveMemberFromGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid group ID")
		return
	}
	// Validate user_id as a positive int (REVIEW.md M-4).
	userIDStr := strings.TrimSpace(r.FormValue("user_id"))
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || userID <= 0 {
		h.renderError(w, r, "Invalid user ID")
		return
	}

	if _, err := h.DB.ExecContext(r.Context(),
		"DELETE FROM zone_group_members WHERE group_id = ? AND user_id = ?",
		groupID, userID,
	); err != nil {
		logger.Error("failed to remove member from group", "group_id", groupID, "user_id", userID, "error", err)
	}
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(groupID, 10)+"/edit", http.StatusSeeOther)
}

// AddZoneToGroup assigns a zone to a group (POST /groups/{group_id}/add-zone).
func (h *Handler) AddZoneToGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid group ID")
		return
	}
	zoneID := strings.TrimSpace(r.FormValue("zone_id"))

	if zoneID != "" {
		if _, err := h.DB.InsertIgnore(r.Context(), "zone_group_zones",
			[]string{"group_id", "zone_id"},
			[]string{"group_id", "zone_id"}, // PK on this table
			groupID, zoneID); err != nil {
			logger.Error("failed to add zone to group", "group_id", groupIDStr, "zone_id", zoneID, "error", err)
		}
	}
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(groupID, 10)+"/edit", http.StatusSeeOther)
}

// RemoveZoneFromGroup removes a zone from a group (POST /groups/{group_id}/remove-zone).
func (h *Handler) RemoveZoneFromGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	groupID, err := strconv.ParseInt(groupIDStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid group ID")
		return
	}
	zoneID := r.FormValue("zone_id")

	if _, err := h.DB.ExecContext(r.Context(),
		"DELETE FROM zone_group_zones WHERE group_id = ? AND zone_id = ?",
		groupID, zoneID,
	); err != nil {
		logger.Error("failed to remove zone from group", "group_id", groupIDStr, "zone_id", zoneID, "error", err)
	}
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(groupID, 10)+"/edit", http.StatusSeeOther)
}

// getGroupMembers returns the group's members, ordered by username. ctx
// propagates cancellation: a client that gives up aborts the query instead of
// holding the (serialised, on SQLite) connection.
func (h *Handler) getGroupMembers(ctx context.Context, groupID int64) []models.User {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.role, u.enabled
		 FROM zone_group_members m
		 JOIN users u ON m.user_id = u.id
		 WHERE m.group_id = ?
		 ORDER BY u.username`, groupID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var members []models.User
	for rows.Next() {
		var u models.User
		var enabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName, &u.Role, &enabled); err != nil {
			logger.Error("failed to scan group member row", "group_id", groupID, "error", err)
			continue
		}
		u.Enabled = enabled == 1
		members = append(members, u)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for group members", "group_id", groupID, "error", err)
	}
	return members
}

// getGroupZones returns the zone IDs assigned to the group, ordered. See
// getGroupMembers for the ctx rationale.
func (h *Handler) getGroupZones(ctx context.Context, groupID int64) []string {
	rows, err := h.DB.QueryContext(ctx,
		"SELECT zone_id FROM zone_group_zones WHERE group_id = ? ORDER BY zone_id", groupID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var zones []string
	for rows.Next() {
		var z string
		if err := rows.Scan(&z); err != nil {
			logger.Error("failed to scan group zone row", "group_id", groupID, "error", err)
			continue
		}
		zones = append(zones, z)
	}
	if err := rows.Err(); err != nil {
		logger.Error("rows iteration error for group zones", "group_id", groupID, "error", err)
	}
	return zones
}

// getAllUsers returns the users for the group-form dropdowns: ordered by
// username, narrowed by an optional case-insensitive search over
// username/email, capped at maxGroupSelectOptions, with a flag reporting
// whether matching rows exist beyond the cap.
func (h *Handler) getAllUsers(ctx context.Context, search string) (users []models.User, truncated bool, err error) {
	where, args := buildSearchLikeWhere(search, "username", "email")
	q := `SELECT id, username, email, first_name, last_name, role, enabled FROM users`
	if where != "" {
		q += " WHERE " + where
	}
	// LIMIT goes through a placeholder like every other dynamic value, even
	// though it is an internal constant: the codebase routes nothing through
	// string concatenation, so a future edit here has no pattern to copy and
	// no regression can hide.
	q += " ORDER BY username LIMIT ?"
	args = append(args, maxGroupSelectOptions)
	rows, err := h.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	for rows.Next() {
		var u models.User
		var enabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName, &u.Role, &enabled); err != nil {
			logger.Error("failed to scan user row", "error", err)
			continue
		}
		u.Enabled = enabled == 1
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	if len(users) == maxGroupSelectOptions {
		// A full page may or may not be all the matches; one COUNT settles
		// the truncation flag so the template hint only shows when rows were
		// actually left out.
		countQ := "SELECT COUNT(*) FROM users"
		if where != "" {
			countQ += " WHERE " + where
		}
		var total int
		if err := h.DB.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
			return nil, false, err
		}
		truncated = total > maxGroupSelectOptions
	}
	return users, truncated, nil
}

// filterZonesWithInfoForSearch narrows a zone list by a case-insensitive name
// substring and caps it at maxGroupSelectOptions, reporting whether matching
// zones exist beyond the cap. The input comes from the cached ListZones call,
// so filtering in-process avoids a second PowerDNS round-trip per keystroke.
func filterZonesWithInfoForSearch(zones []models.ZoneWithInfo, search string) ([]models.ZoneWithInfo, bool) {
	search = strings.ToLower(strings.TrimSpace(search))
	filtered := make([]models.ZoneWithInfo, 0, min(maxGroupSelectOptions, len(zones)))
	truncated := false
	for _, z := range zones {
		if search != "" && !strings.Contains(strings.ToLower(z.Zone.Name), search) {
			continue
		}
		if len(filtered) >= maxGroupSelectOptions {
			truncated = true
			break
		}
		filtered = append(filtered, z)
	}
	return filtered, truncated
}

// getUserAllowedZoneIDs returns the set of zone IDs accessible to a non-admin
// user. It sits on the authorization hot path (every zone list/filter), so ctx
// propagation matters most here: a client that gives up cancels the lookup
// instead of holding the connection while the response has no reader left.
func (h *Handler) getUserAllowedZoneIDs(ctx context.Context, userID int64) (map[string]bool, error) {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT z.zone_id FROM zone_group_members m
		 JOIN zone_group_zones z ON m.group_id = z.group_id
		 WHERE m.user_id = ?`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	zoneIDs := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			logger.Error("failed to scan allowed zone_id", "user_id", userID, "error", err)
			continue
		}
		zoneIDs[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return zoneIDs, nil
}

// filterZonesForUser returns the PowerDNS zones the user is allowed to see.
func (h *Handler) filterZonesForUser(r *http.Request, zones []models.Zone) ([]models.Zone, error) {
	user := middleware.GetUser(r)
	if user == nil || user.IsAdmin() {
		return zones, nil
	}

	allowed, err := h.getUserAllowedZoneIDs(r.Context(), user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user zone permissions: %w", err)
	}

	filtered := make([]models.Zone, 0)
	for _, z := range zones {
		if allowed[z.ID] {
			filtered = append(filtered, z)
		}
	}
	return filtered, nil
}

// filterZonesWithInfoForUser returns the PowerDNS zones with info the user is allowed to see.
func (h *Handler) filterZonesWithInfoForUser(r *http.Request, zones []models.ZoneWithInfo) ([]models.ZoneWithInfo, error) {
	user := middleware.GetUser(r)
	if user == nil || user.IsAdmin() {
		return zones, nil
	}

	allowed, err := h.getUserAllowedZoneIDs(r.Context(), user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user zone permissions: %w", err)
	}

	filtered := make([]models.ZoneWithInfo, 0)
	for _, z := range zones {
		if allowed[z.Zone.ID] {
			filtered = append(filtered, z)
		}
	}
	return filtered, nil
}

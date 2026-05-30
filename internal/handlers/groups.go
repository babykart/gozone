package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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

	rows, err := h.DB.Query(`SELECT id, name, description, created_at FROM zone_groups ORDER BY name`)
	if err != nil {
		h.renderError(w, r, "Failed to fetch groups: "+err.Error())
		return
	}
	defer rows.Close()

	var groups []groupInfo
	for rows.Next() {
		var g groupInfo
		rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
		groups = append(groups, g)
	}

	data := map[string]interface{}{
		"Title":   "Groups - GoZone",
		"User":    user,
		"Groups":  groups,
		"IsAdmin": user.IsAdmin(),
	}
	h.render(w, r, "groups.html", data)
}

// CreateGroupPage renders the group creation form (GET /groups/new).
func (h *Handler) CreateGroupPage(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	data := map[string]interface{}{
		"Title":   "Create Group - GoZone",
		"User":    user,
		"IsAdmin": user.IsAdmin(),
	}
	h.render(w, r, "group_edit.html", data)
}

// CreateGroup inserts a new zone group (POST /groups/create).
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))

	if name == "" {
		h.renderError(w, r, "Group name is required")
		return
	}

	result, err := h.DB.Exec(
		"INSERT INTO zone_groups (name, description) VALUES (?, ?)",
		name, description,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			h.renderError(w, r, "A group with that name already exists")
			return
		}
		h.renderError(w, r, "Failed to create group: "+err.Error())
		return
	}

	id, _ := result.LastInsertId()
	http.Redirect(w, r, "/groups/"+strconv.FormatInt(id, 10)+"/edit", http.StatusSeeOther)
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
	err = h.DB.QueryRow(
		"SELECT id, name, description, created_at FROM zone_groups WHERE id = ?", groupID,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	if err == sql.ErrNoRows {
		h.renderError(w, r, "Group not found")
		return
	}
	if err != nil {
		h.renderError(w, r, "Failed to fetch group: "+err.Error())
		return
	}

	members := h.getGroupMembers(groupID)
	zones := h.getGroupZones(groupID)

	allUsers, _ := h.getAllUsers()

	allZones, _ := h.PDNS.ListZonesWithInfo()

	data := map[string]interface{}{
		"Title":      g.Name + " - GoZone",
		"User":       user,
		"Group":      g,
		"Members":    members,
		"GroupZones": zones,
		"AllUsers":   allUsers,
		"AllZones":   allZones,
		"IsAdmin":    user.IsAdmin(),
	}
	h.render(w, r, "group_edit.html", data)
}

// UpdateGroup updates a group's name and description (POST /groups/{group_id}/update).
func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}

	groupIDStr := r.PathValue("group_id")
	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))

	if name == "" {
		h.renderError(w, r, "Group name is required")
		return
	}

	_, err := h.DB.Exec(
		"UPDATE zone_groups SET name = ?, description = ? WHERE id = ?",
		name, description, groupIDStr,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			h.renderError(w, r, "A group with that name already exists")
			return
		}
		h.renderError(w, r, "Failed to update group: "+err.Error())
		return
	}

	http.Redirect(w, r, "/groups/"+groupIDStr+"/edit", http.StatusSeeOther)
}

// DeleteGroup deletes a group (POST /groups/{group_id}/delete).
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}

	groupIDStr := r.PathValue("group_id")
	if _, err := h.DB.Exec("DELETE FROM zone_groups WHERE id = ?", groupIDStr); err != nil {
		logger.Error("failed to delete group", "group_id", groupIDStr, "error", err)
	}
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

// AddMemberToGroup adds a user to a group (POST /groups/{group_id}/add-member).
func (h *Handler) AddMemberToGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	userIDStr := r.FormValue("user_id")

	if _, err := h.DB.Exec(
		"INSERT OR IGNORE INTO zone_group_members (group_id, user_id) VALUES (?, ?)",
		groupIDStr, userIDStr,
	); err != nil {
		logger.Error("failed to add member to group", "group_id", groupIDStr, "user_id", userIDStr, "error", err)
	}
	http.Redirect(w, r, "/groups/"+groupIDStr+"/edit", http.StatusSeeOther)
}

// RemoveMemberFromGroup removes a user from a group (POST /groups/{group_id}/remove-member).
func (h *Handler) RemoveMemberFromGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	userIDStr := r.FormValue("user_id")

	if _, err := h.DB.Exec(
		"DELETE FROM zone_group_members WHERE group_id = ? AND user_id = ?",
		groupIDStr, userIDStr,
	); err != nil {
		logger.Error("failed to remove member from group", "group_id", groupIDStr, "user_id", userIDStr, "error", err)
	}
	http.Redirect(w, r, "/groups/"+groupIDStr+"/edit", http.StatusSeeOther)
}

// AddZoneToGroup assigns a zone to a group (POST /groups/{group_id}/add-zone).
func (h *Handler) AddZoneToGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	zoneID := strings.TrimSpace(r.FormValue("zone_id"))

	if zoneID != "" {
		if _, err := h.DB.Exec(
			"INSERT OR IGNORE INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)",
			groupIDStr, zoneID,
		); err != nil {
			logger.Error("failed to add zone to group", "group_id", groupIDStr, "zone_id", zoneID, "error", err)
		}
	}
	http.Redirect(w, r, "/groups/"+groupIDStr+"/edit", http.StatusSeeOther)
}

// RemoveZoneFromGroup removes a zone from a group (POST /groups/{group_id}/remove-zone).
func (h *Handler) RemoveZoneFromGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := r.PathValue("group_id")
	zoneID := r.FormValue("zone_id")

	if _, err := h.DB.Exec(
		"DELETE FROM zone_group_zones WHERE group_id = ? AND zone_id = ?",
		groupIDStr, zoneID,
	); err != nil {
		logger.Error("failed to remove zone from group", "group_id", groupIDStr, "zone_id", zoneID, "error", err)
	}
	http.Redirect(w, r, "/groups/"+groupIDStr+"/edit", http.StatusSeeOther)
}

func (h *Handler) getGroupMembers(groupID int64) []models.User {
	rows, err := h.DB.Query(
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

func (h *Handler) getGroupZones(groupID int64) []string {
	rows, err := h.DB.Query(
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

func (h *Handler) getAllUsers() ([]models.User, error) {
	rows, err := h.DB.Query(
		`SELECT id, username, email, first_name, last_name, role, enabled
		 FROM users ORDER BY username`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
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
		return nil, err
	}
	return users, nil
}

// getUserAllowedZoneIDs returns the set of zone IDs accessible to a non-admin user.
func (h *Handler) getUserAllowedZoneIDs(userID int64) (map[string]bool, error) {
	rows, err := h.DB.Query(
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

	allowed, err := h.getUserAllowedZoneIDs(user.ID)
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

	allowed, err := h.getUserAllowedZoneIDs(user.ID)
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

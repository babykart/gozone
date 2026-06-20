package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

func seedGroup(t *testing.T, h *Handler, name, description string) int64 {
	t.Helper()
	result, err := h.DB.Exec(
		"INSERT INTO zone_groups (name, description) VALUES (?, ?)",
		name, description,
	)
	if err != nil {
		t.Fatalf("seed group: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

func seedUserWithHash(t *testing.T, h *Handler, username, password, role string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.DB.Exec(
		"INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, 1)",
		username, username+"@test.local", string(hash), role,
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

func withUserContext(r *http.Request, user *models.User) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.UserContextKey, user)
	return r.WithContext(ctx)
}

func pdnsEmptyHandler() testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}
}

func TestListGroups(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedGroup(t, h, "test-group", "A test group")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/groups", nil), user)
	h.ListGroups(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "test-group") {
		t.Errorf("expected response to contain group name")
	}
}

func TestListGroups_Empty(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/groups", nil), user)
	h.ListGroups(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListGroups_PaginationAndSearch(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedGroup(t, h, "alpha-group", "first")
	seedGroup(t, h, "beta-group", "second")
	seedGroup(t, h, "gamma-zone", "third")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/groups?search=group&PerPage=1&Page=2", nil), user)
	h.ListGroups(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "beta-group") {
		t.Errorf("expected page 2 to contain beta-group, body: %s", body)
	}
	if strings.Contains(body, "alpha-group") {
		t.Errorf("did not expect alpha-group on page 2, body: %s", body)
	}
	if strings.Contains(body, "gamma-zone") {
		t.Errorf("did not expect gamma-zone after filtering by 'group', body: %s", body)
	}
	if !strings.Contains(body, "PageInfo=") {
		t.Errorf("expected pagination info in response, body: %s", body)
	}
	if !strings.Contains(body, "Search=group") {
		t.Errorf("expected search term in pagination info, body: %s", body)
	}
}

func TestCreateGroupPage(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedUserWithHash(t, h, "regularuser", "pass", "user")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/groups/new", nil), user)
	h.CreateGroupPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "regularuser") {
		t.Errorf("expected response to contain seeded user in AllUsers dropdown, got: %s", w.Body.String())
	}
}

func TestCreateGroup_Success(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "name=test-group&description=my+description"
	r := withUserContext(httptest.NewRequest(http.MethodPost, "/groups/create", strings.NewReader(body)), user)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/groups/") || !strings.HasSuffix(loc, "/edit") {
		t.Errorf("expected redirect to /groups/{id}/edit, got %s", loc)
	}
}

func TestCreateGroup_EmptyName(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodPost, "/groups/create", strings.NewReader("name=")), user)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateGroup(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Group name is required") {
		t.Errorf("expected error message, got %s", w.Body.String())
	}
}

func TestCreateGroup_DuplicateName(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedGroup(t, h, "test-group", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := withUserContext(httptest.NewRequest(http.MethodPost, "/groups/create", strings.NewReader("name=test-group")), user)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateGroup(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "A group with that name already exists") {
		t.Errorf("expected duplicate name error, got %s", w.Body.String())
	}
}

func TestEditGroupPage_Success(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "edit-group", "test description")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/groups/"+strconv.FormatInt(groupID, 10)+"/edit", nil)
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r = withUserContext(r, user)
	h.EditGroupPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "edit-group") {
		t.Errorf("expected response to contain group name")
	}
}

func TestEditGroupPage_NotFound(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/groups/99999/edit", nil)
	r.SetPathValue("group_id", "99999")
	r = withUserContext(r, user)
	h.EditGroupPage(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Group not found") {
		t.Errorf("expected 'Group not found' error, got %s", w.Body.String())
	}
}

func TestEditGroupPage_InvalidID(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/groups/abc/edit", nil)
	r.SetPathValue("group_id", "abc")
	r = withUserContext(r, user)
	h.EditGroupPage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid group ID") {
		t.Errorf("expected 'Invalid group ID' error, got %s", w.Body.String())
	}
}

func TestUpdateGroup_Success(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "original-name", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "name=new-name&description=new+description"
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/update", strings.NewReader(body))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.UpdateGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var name string
	h.DB.QueryRow("SELECT name FROM zone_groups WHERE id = ?", groupID).Scan(&name)
	if name != "new-name" {
		t.Errorf("expected name 'new-name', got %q", name)
	}
}

func TestUpdateGroup_EmptyName(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "some-group", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/update", strings.NewReader("name="))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.UpdateGroup(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Group name is required") {
		t.Errorf("expected error message, got %s", w.Body.String())
	}
}

func TestUpdateGroup_DuplicateName(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedGroup(t, h, "existing-group", "")
	groupID := seedGroup(t, h, "my-group", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/update", strings.NewReader("name=existing-group"))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.UpdateGroup(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("expected duplicate name error, got %s", w.Body.String())
	}
}

func TestDeleteGroup(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "delete-me", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/delete", nil)
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r = withUserContext(r, user)
	h.DeleteGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_groups WHERE id = ?", groupID).Scan(&count)
	if count != 0 {
		t.Error("expected group to be deleted")
	}
}

func TestAddMemberToGroup(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "test-group", "")
	userID := seedUserWithHash(t, h, "memberuser", "pass", "user")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "user_id=" + strconv.FormatInt(userID, 10)
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/add-member", strings.NewReader(body))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.AddMemberToGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow(
		"SELECT COUNT(*) FROM zone_group_members WHERE group_id = ? AND user_id = ?",
		groupID, userID,
	).Scan(&count)
	if count != 1 {
		t.Error("expected member to be added")
	}
}

func TestRemoveMemberFromGroup(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "test-group", "")
	userID := seedUserWithHash(t, h, "removemember", "pass", "user")

	h.DB.Exec("INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)", groupID, userID)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "user_id=" + strconv.FormatInt(userID, 10)
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/remove-member", strings.NewReader(body))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.RemoveMemberFromGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow(
		"SELECT COUNT(*) FROM zone_group_members WHERE group_id = ? AND user_id = ?",
		groupID, userID,
	).Scan(&count)
	if count != 0 {
		t.Error("expected member to be removed")
	}
}

func TestAddZoneToGroup(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "test-group", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "zone_id=example.com."
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/add-zone", strings.NewReader(body))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.AddZoneToGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow(
		"SELECT COUNT(*) FROM zone_group_zones WHERE group_id = ? AND zone_id = ?",
		groupID, "example.com.",
	).Scan(&count)
	if count != 1 {
		t.Error("expected zone to be added to group")
	}
}

func TestAddZoneToGroup_EmptyZoneID(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "test-group", "")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/add-zone", strings.NewReader("zone_id="))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.AddZoneToGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM zone_group_zones WHERE group_id = ?", groupID).Scan(&count)
	if count != 0 {
		t.Error("expected no zones to be added for empty zone_id")
	}
}

func TestRemoveZoneFromGroup(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	groupID := seedGroup(t, h, "test-group", "")
	h.DB.Exec("INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)", groupID, "example.com.")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	body := "zone_id=example.com."
	r := httptest.NewRequest(http.MethodPost, "/groups/"+strconv.FormatInt(groupID, 10)+"/remove-zone", strings.NewReader(body))
	r.SetPathValue("group_id", strconv.FormatInt(groupID, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.RemoveZoneFromGroup(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow(
		"SELECT COUNT(*) FROM zone_group_zones WHERE group_id = ? AND zone_id = ?",
		groupID, "example.com.",
	).Scan(&count)
	if count != 0 {
		t.Error("expected zone to be removed from group")
	}
}

func TestFilterZonesForUser_AdminReturnsAll(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	zones := []models.Zone{
		{ID: "zone1.com.", Name: "zone1.com."},
		{ID: "zone2.com.", Name: "zone2.com."},
	}

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/", nil), user)

	result, err := h.filterZonesForUser(r, zones)
	if err != nil {
		t.Fatalf("filterZonesForUser: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 zones for admin, got %d", len(result))
	}
}

func TestFilterZonesForUser_NilUserReturnsAll(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	zones := []models.Zone{
		{ID: "zone1.com.", Name: "zone1.com."},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	result, err := h.filterZonesForUser(r, zones)
	if err != nil {
		t.Fatalf("filterZonesForUser: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 zone for nil user, got %d", len(result))
	}
}

func TestFilterZonesForUser_UserWithNoGroups(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedUserWithHash(t, h, "regularuser", "pass", "user")

	zones := []models.Zone{
		{ID: "zone1.com.", Name: "zone1.com."},
	}

	user := &models.User{ID: 1, Username: "regularuser", Role: "user"}
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/", nil), user)

	result, err := h.filterZonesForUser(r, zones)
	if err != nil {
		t.Fatalf("filterZonesForUser: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 zones for user with no groups, got %d", len(result))
	}
}

func TestFilterZonesForUser_UserWithGroupAccess(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	userID := seedUserWithHash(t, h, "zoneuser", "pass", "user")
	groupID := seedGroup(t, h, "zone-group", "")

	h.DB.Exec("INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)", groupID, userID)
	h.DB.Exec("INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)", groupID, "allowed.com.")

	zones := []models.Zone{
		{ID: "allowed.com.", Name: "allowed.com."},
		{ID: "blocked.com.", Name: "blocked.com."},
	}

	user := &models.User{ID: userID, Username: "zoneuser", Role: "user"}
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/", nil), user)

	result, err := h.filterZonesForUser(r, zones)
	if err != nil {
		t.Fatalf("filterZonesForUser: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(result))
	}
	if result[0].ID != "allowed.com." {
		t.Errorf("expected 'allowed.com.', got %s", result[0].ID)
	}
}

func TestFilterZonesWithInfoForUser_AdminReturnsAll(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	zones := []models.ZoneWithInfo{
		{Zone: models.Zone{ID: "z1.com.", Name: "z1.com."}},
		{Zone: models.Zone{ID: "z2.com.", Name: "z2.com."}},
	}

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/", nil), user)

	result, err := h.filterZonesWithInfoForUser(r, zones)
	if err != nil {
		t.Fatalf("filterZonesWithInfoForUser: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 zones for admin, got %d", len(result))
	}
}

func TestFilterZonesWithInfoForUser_Filtered(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	userID := seedUserWithHash(t, h, "infouser", "pass", "user")
	groupID := seedGroup(t, h, "info-group", "")
	h.DB.Exec("INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)", groupID, userID)
	h.DB.Exec("INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)", groupID, "visible.com.")

	zones := []models.ZoneWithInfo{
		{Zone: models.Zone{ID: "visible.com.", Name: "visible.com."}},
		{Zone: models.Zone{ID: "hidden.com.", Name: "hidden.com."}},
	}

	user := &models.User{ID: userID, Username: "infouser", Role: "user"}
	r := withUserContext(httptest.NewRequest(http.MethodGet, "/", nil), user)

	result, err := h.filterZonesWithInfoForUser(r, zones)
	if err != nil {
		t.Fatalf("filterZonesWithInfoForUser: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(result))
	}
	if result[0].Zone.ID != "visible.com." {
		t.Errorf("expected 'visible.com.', got %s", result[0].Zone.ID)
	}
}

func TestGetUserAllowedZoneIDs(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	userID := seedUserWithHash(t, h, "alloweduser", "pass", "user")
	groupID := seedGroup(t, h, "access-group", "")
	h.DB.Exec("INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)", groupID, userID)
	h.DB.Exec("INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)", groupID, "zone-a.com.")
	h.DB.Exec("INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)", groupID, "zone-b.com.")

	zones, err := h.getUserAllowedZoneIDs(userID)
	if err != nil {
		t.Fatalf("getUserAllowedZoneIDs: %v", err)
	}
	if len(zones) != 2 {
		t.Errorf("expected 2 zone IDs, got %d", len(zones))
	}
	if !zones["zone-a.com."] {
		t.Error("expected zone-a.com. to be allowed")
	}
	if !zones["zone-b.com."] {
		t.Error("expected zone-b.com. to be allowed")
	}
	if zones["zone-c.com."] {
		t.Error("expected zone-c.com. to NOT be allowed")
	}
}

func TestGetUserAllowedZoneIDs_NoMemberships(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	userID := seedUserWithHash(t, h, "isolateduser", "pass", "user")

	zones, err := h.getUserAllowedZoneIDs(userID)
	if err != nil {
		t.Fatalf("getUserAllowedZoneIDs: %v", err)
	}
	if len(zones) != 0 {
		t.Errorf("expected 0 zone IDs for user with no groups, got %d", len(zones))
	}
}

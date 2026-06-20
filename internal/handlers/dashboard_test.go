package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func TestDashboard(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestActivityPage(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/activity", nil)
	r = r.WithContext(ctx)
	h.ActivityPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestActivityPage_EscapesDateParams(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/activity?from=2024-01-01%26action%3Dfake&to=2024-01-02", nil)
	r = r.WithContext(ctx)
	h.ActivityPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if strings.Contains(body, "action=fake") {
		t.Errorf("unescaped action parameter leaked into pagination links: %s", body)
	}
	if !strings.Contains(body, "from=2024-01-01%26action%3Dfake") {
		t.Errorf("from date not properly escaped in pagination links: %s", body)
	}
}

func TestGetActivityLogs_Admin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	if _, err := h.DB.Exec("INSERT INTO activity_logs (zone_id, action, details) VALUES (?, 'create_zone', 'test')", "example.com."); err != nil {
		t.Fatalf("insert activity log: %v", err)
	}

	logs, total := h.getActivityLogs(user, "", "", "", "", 1, 10)
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(logs))
	}
}

func TestGetActivityLogs_Search(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	if _, err := h.DB.Exec("INSERT INTO activity_logs (zone_id, action, details) VALUES (?, 'create_zone', 'test zone')", "example.com."); err != nil {
		t.Fatalf("insert activity log: %v", err)
	}
	if _, err := h.DB.Exec("INSERT INTO activity_logs (action, details) VALUES ('create_user', 'test user')"); err != nil {
		t.Fatalf("insert activity log: %v", err)
	}

	logs, total := h.getActivityLogs(user, "create_zone", "", "", "", 1, 10)
	if total != 1 {
		t.Errorf("expected total 1 for search, got %d", total)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 log for search, got %d", len(logs))
	}
	if logs[0].Action != "create_zone" {
		t.Errorf("expected create_zone, got %s", logs[0].Action)
	}
}

func TestGetActivityLogs_NonAdminSearchRespectsVisibility(t *testing.T) {
	h := newTestHandler(t)

	// Seed two users: an admin and a regular member.
	adminID := testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	userID := testutil.SeedTestUser(t, h.DB, "member", "member", "user", true)

	// Create a group and assign the regular user to zone "visible.example.com.".
	res, err := h.DB.Exec("INSERT INTO zone_groups (name) VALUES ('test-group')")
	if err != nil {
		t.Fatalf("insert group: %v", err)
	}
	groupID, _ := res.LastInsertId()
	if _, err := h.DB.Exec("INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)", groupID, userID); err != nil {
		t.Fatalf("insert group member: %v", err)
	}
	if _, err := h.DB.Exec("INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)", groupID, "visible.example.com."); err != nil {
		t.Fatalf("insert group zone: %v", err)
	}

	// Insert two zone logs: one the user can access, one they cannot.
	if _, err := h.DB.Exec("INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_record', 'visible marker')", adminID, "visible.example.com."); err != nil {
		t.Fatalf("insert visible log: %v", err)
	}
	if _, err := h.DB.Exec("INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_record', 'hidden marker')", adminID, "hidden.example.com."); err != nil {
		t.Fatalf("insert hidden log: %v", err)
	}

	// The non-admin searches for a term that only appears in the hidden log.
	user := &models.User{ID: userID, Username: "member", Role: "user"}
	logs, total := h.getActivityLogs(user, "hidden", "", "", "", 1, 10)
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs for non-admin searching hidden zone, got %d", len(logs))
	}

	// Searching for the visible term returns the allowed log.
	logs, total = h.getActivityLogs(user, "visible", "", "", "", 1, 10)
	if total != 1 {
		t.Errorf("expected total 1 for visible search, got %d", total)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 log for visible search, got %d", len(logs))
	}
}

func TestDashboard_ServerStats(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"uptime","type":"StatisticItem","value":"3600"},{"name":"questions","type":"StatisticItem","value":"12345"},{"name":"packetcache-hit","type":"StatisticItem","value":"5000"},{"name":"packetcache-miss","type":"StatisticItem","value":"100"},{"name":"query-cache-hit","type":"StatisticItem","value":"8000"},{"name":"query-cache-miss","type":"StatisticItem","value":"200"},{"name":"qsize-q","type":"StatisticItem","value":"0"}]`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with server stats, got %d", w.Code)
	}
}

func TestDashboard_GetStatisticsError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/statistics") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal server error"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/zones") {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`{"id":"localhost","type":"Server","url":"/api/v1/servers/localhost","daemon_type":"authoritative","version":"4.9.0","config_url":"/api/v1/servers/localhost/config","zones_url":"/api/v1/servers/localhost/zones"}`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even when PDNS statistics fail, got %d", w.Code)
	}
}

func TestValToString(t *testing.T) {
	tests := []struct {
		input interface{}
		want  string
	}{
		{nil, ""},
		{"hello", "hello"},
		{"", ""},
		{float64(3600), "3600"},
		{float64(3.14), "3.14"},
		{float64(0), "0"},
		{true, "true"},
		{false, "false"},
		{[]int{1, 2, 3}, "[1 2 3]"},
	}
	for _, tt := range tests {
		got := valToString(tt.input)
		if got != tt.want {
			t.Errorf("valToString(%v): got %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDashboard_NumericStats(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"uptime","type":"StatisticItem","value":3600},{"name":"questions","type":"StatisticItem","value":12345}]`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with numeric stats, got %d", w.Code)
	}
}

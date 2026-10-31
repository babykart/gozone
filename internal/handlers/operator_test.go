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

// seedOperatorUser inserts an enabled "operator"-role user and returns the
// in-memory user for the request context. The role string is stored as
// submitted (the users.role column is free-form); the operator semantics are
// owned by the models/handler layer.
func seedOperatorUser(t *testing.T, h *Handler) *models.User {
	t.Helper()
	id := testutil.SeedTestUser(t, h.DB, "operator", "operatorpass", "operator", true)
	return &models.User{ID: id, Username: "operator", Email: "operator@test.local", Role: "operator"}
}

// TestOperator_CanReachCreateZonePage pins the handler-level contract of the
// operator role: the zone creation page must render for an operator. The
// handler itself carries no admin gate (the router owns that decision), so
// this asserts the operator user flows through render() and the template
// without an authorisation stop.
func TestOperator_CanReachCreateZonePage(t *testing.T) {
	h := newTestHandler(t)
	operator := seedOperatorUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, operator)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/new", nil)
	r = r.WithContext(ctx)
	h.CreateZonePage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("operator GET /zones/new: expected 200, got %d", w.Code)
	}
}

// TestOperator_CanListTSIGKeys pins that the TSIG keys listing page renders
// for an operator-role user (the mock PDNS answers with an empty key list).
func TestOperator_CanListTSIGKeys(t *testing.T) {
	h := newTestHandler(t)
	operator := seedOperatorUser(t, h)

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, operator)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/tsigkeys", nil)
	r = r.WithContext(ctx)
	h.ListTSIGKeys(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("operator GET /tsigkeys: expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "TSIG Keys") {
		t.Errorf("expected the TSIG keys page to render, got: %s", w.Body.String())
	}
}

// TestOperator_ActivityPage_ShowsOtherUsersActivity is the operator-role
// visibility test: an operator (a DNS-management role, not admin) must see
// the global activity log including rows created by OTHER users.
func TestOperator_ActivityPage_ShowsOtherUsersActivity(t *testing.T) {
	h := newTestHandler(t)
	operator := seedOperatorUser(t, h)
	otherID := testutil.SeedTestUser(t, h.DB, "bob", "bobpass", "user", true)

	seedActivity := func(userID int64, action string) {
		t.Helper()
		if _, err := h.DB.Exec(
			`INSERT INTO activity_logs (user_id, zone_id, action, details, created_at) VALUES (?, NULL, ?, ?, CURRENT_TIMESTAMP)`,
			userID, action, "activity page visibility seed",
		); err != nil {
			t.Fatalf("seed %q: %v", action, err)
		}
	}
	// One non-zone row per user: the visibility clause only ever hid
	// other users' non-zone rows from non-admins.
	seedActivity(otherID, "other_user_action")
	seedActivity(operator.ID, "operator_own_action")

	ctx := context.WithValue(context.Background(), middleware.UserContextKey, operator)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/activity", nil)
	r = r.WithContext(ctx)
	h.ActivityPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("operator GET /activity: expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "operator_own_action") {
		t.Errorf("operator must still see their own activity entries, body: %s", body)
	}
	if !strings.Contains(body, "other_user_action") {
		t.Errorf("operator must see activity entries created by other users (operator is a DNS-management role, not a plain user), body: %s", body)
	}
}

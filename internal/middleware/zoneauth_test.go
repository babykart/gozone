package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/models"
)

// seedZoneAccess grants userID access to zoneID by inserting a zone_group
// rooted at (group_id, user_id, zone_id). Used by the CheckZoneAccess tests
// to construct the membership row the middleware probes.
func seedZoneAccess(t *testing.T, db *database.DB, userID int64, zoneID string) {
	t.Helper()
	res, err := db.Exec(`INSERT INTO zone_groups (name, description) VALUES (?, '')`, "g-"+zoneID)
	if err != nil {
		t.Fatalf("seed zone_group: %v", err)
	}
	groupID, _ := res.LastInsertId()
	if _, err := db.Exec(
		`INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)`, groupID, userID,
	); err != nil {
		t.Fatalf("seed zone_group_member: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)`, groupID, zoneID,
	); err != nil {
		t.Fatalf("seed zone_group_zone: %v", err)
	}
}

// withTestUser attaches user to r via the middleware's UserContextKey, mirroring
// what the Auth middleware does in production.
func withTestUser(r *http.Request, user *models.User) *http.Request {
	ctx := context.WithValue(r.Context(), UserContextKey, user)
	return r.WithContext(ctx)
}

func TestCheckZoneAccess_NilUser_Unauthorized(t *testing.T) {
	db := newTestAuthDB(t)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com.", nil)
	r.SetPathValue("zone_id", "example.com.")

	CheckZoneAccess(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when user is nil")
	})).ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for nil user, got %d", rr.Code)
	}
}

func TestCheckZoneAccess_Admin_SkipsProbe(t *testing.T) {
	db := newTestAuthDB(t)
	admin := &models.User{ID: 1, Username: "admin", Role: "admin"}

	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/anything.", nil)
	r.SetPathValue("zone_id", "anything.")
	r = withTestUser(r, admin)

	called := false
	CheckZoneAccess(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin, got %d", rr.Code)
	}
	if !called {
		t.Error("admin must bypass the zone-access probe and reach the next handler")
	}
}

func TestCheckZoneAccess_NoZoneID_SkipsProbe(t *testing.T) {
	db := newTestAuthDB(t)
	user := &models.User{ID: 2, Username: "regular", Role: "user"}

	// No {zone_id} path value — handler-level filtering applies instead.
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones", nil)
	r = withTestUser(r, user)

	called := false
	CheckZoneAccess(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when no zone_id in URL, got %d", rr.Code)
	}
	if !called {
		t.Error("routes without zone_id must reach the next handler (handler-level filtering applies)")
	}
}

func TestCheckZoneAccess_UserWithAccess_Allowed(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "member", "user", true)
	seedZoneAccess(t, db, userID, "example.com.")

	user := &models.User{ID: userID, Username: "member", Role: "user"}
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com.", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withTestUser(r, user)

	called := false
	CheckZoneAccess(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for member with access, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !called {
		t.Error("member with access must reach the next handler")
	}
}

func TestCheckZoneAccess_UserWithoutAccess_Forbidden(t *testing.T) {
	db := newTestAuthDB(t)
	// Seed access for user 5, then log in as user 6 — no shared group.
	otherID := seedTestUser(t, db, "other", "user", true)
	seedZoneAccess(t, db, otherID, "secret.example.com.")

	userID := seedTestUser(t, db, "outsider", "user", true)
	user := &models.User{ID: userID, Username: "outsider", Role: "user"}

	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/secret.example.com.", nil)
	r.SetPathValue("zone_id", "secret.example.com.")
	r = withTestUser(r, user)

	called := false
	CheckZoneAccess(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for outsider, got %d", rr.Code)
	}
	if called {
		t.Error("outsider must NOT reach the next handler")
	}
}

// TestCheckZoneAccess_CancelledContext_Forbidden is the L-8 regression test:
// the probe MUST honour r.Context() so a client disconnect (or any caller that
// cancels the request context) aborts the in-flight QueryRow instead of
// running to completion. Previously the middleware used db.QueryRow(...) with
// no context, so a cancelled request still consumed the single SQLite writer
// connection until the SELECT returned. With QueryRowContext(r.Context(),
// ...) the cancelled Scan surfaces a non-nil error → 403. This test would
// fail (return 200) if the middleware regressed back to the contextless call.
func TestCheckZoneAccess_CancelledContext_Forbidden(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "member", "user", true)
	seedZoneAccess(t, db, userID, "example.com.")

	user := &models.User{ID: userID, Username: "member", Role: "user"}

	// Build a request whose context is already cancelled but still carries
	// the user, exactly like the Auth middleware would have populated before
	// the downstream client went away.
	ctx := context.WithValue(context.Background(), UserContextKey, user)
	ctx, cancel := context.WithCancel(ctx)
	cancel()

	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com.", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = r.WithContext(ctx)

	called := false
	CheckZoneAccess(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when request context is cancelled (probe must abort), got %d", rr.Code)
	}
	if called {
		t.Error("next handler must not run when the access probe is aborted by context cancellation")
	}
}

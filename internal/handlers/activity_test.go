package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
)

// TestActivityLogSearch_LiteralWildcardMatch guards the activity-log free-text
// search: the term is bound as a LIKE pattern, so "%" or "_" typed by the
// operator must match literally (paired ESCAPE clause) instead of acting as
// wildcards — searching "%" used to return every log entry.
func TestActivityLogSearch_LiteralWildcardMatch(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	seed := func(details string) {
		t.Helper()
		// action deliberately carries no wildcard characters: the search also
		// matches against the action column, and every seeded row shares it.
		if _, err := h.DB.Exec(
			`INSERT INTO activity_logs (user_id, zone_id, action, details, created_at) VALUES (?, NULL, 'testaction', ?, CURRENT_TIMESTAMP)`,
			admin.ID, details,
		); err != nil {
			t.Fatalf("seed %q: %v", details, err)
		}
	}
	seed("removed 100% of records")
	seed("user_has_underscore logged in")
	seed("plain entry")

	logs, total := h.getActivityLogs(context.Background(), admin, "%", "", "", "", 1, 0)
	if total != 1 || len(logs) != 1 || !strings.Contains(logs[0].Details, "100%") {
		t.Errorf(`searching "%%" must match only the entry containing a literal percent, got total=%d`, total)
	}

	logs, total = h.getActivityLogs(context.Background(), admin, "_", "", "", "", 1, 0)
	if total != 1 || len(logs) != 1 || !strings.Contains(logs[0].Details, "underscore") {
		t.Errorf(`searching "_" must match only the entry containing a literal underscore, got total=%d`, total)
	}

	_, total = h.getActivityLogs(context.Background(), admin, "entry", "", "", "", 1, 0)
	if total != 1 {
		t.Errorf(`plain term must still match normally, got total=%d`, total)
	}
}

// TestActivityVisibility_ByRole pins the three-way visibility split of the
// global activity log: admins see the full trail (zone-scoped and account
// entries alike), operators manage DNS rather than accounts so they only see
// zone-scoped entries, and regular users keep the historical scope (their own
// non-zone entries plus zone-scoped entries for zones in their groups). The
// distinct-action dropdown must reflect the same split.
func TestActivityVisibility_ByRole(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)
	operatorID := seedUserWithHash(t, h, "opuser", "pass", "operator")
	regularID := seedUserWithHash(t, h, "reguser", "pass", "user")

	seed := func(userID int64, zoneID, action, details string) {
		t.Helper()
		var zoneArg interface{}
		if zoneID != "" {
			zoneArg = zoneID
		}
		if _, err := h.DB.Exec(
			`INSERT INTO activity_logs (user_id, zone_id, action, details, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
			userID, zoneArg, action, details,
		); err != nil {
			t.Fatalf("seed %s: %v", action, err)
		}
	}
	seed(operatorID, "example.com.", "import_zone", "zone op")
	seed(regularID, "", "login", "someone logged in")
	seed(admin.ID, "", "create_user", "account created")

	operator := &models.User{ID: operatorID, Username: "opuser", Role: "operator"}
	regular := &models.User{ID: regularID, Username: "reguser", Role: "user"}

	assertActions := func(user *models.User, want map[string]bool) {
		t.Helper()
		actions, err := h.getDistinctActivityActions(context.Background(), user)
		if err != nil {
			t.Fatalf("getDistinctActivityActions(%s): %v", user.Role, err)
		}
		for _, action := range []string{"import_zone", "login", "create_user"} {
			if got := want[action]; containsString(actions, action) != got {
				t.Errorf("role %s: distinct actions %v, want %q present=%v", user.Role, actions, action, got)
			}
		}
	}

	// Admin: full visibility.
	logs, total := h.getActivityLogs(context.Background(), admin, "", "", "", "", 1, 0)
	if total != 3 || len(logs) != 3 {
		t.Errorf("admin must see all 3 seeded entries, got total=%d rows=%d", total, len(logs))
	}
	assertActions(admin, map[string]bool{"import_zone": true, "login": true, "create_user": true})

	// Operator: zone-scoped entries only; account/log entries are out of role.
	logs, total = h.getActivityLogs(context.Background(), operator, "", "", "", "", 1, 0)
	if total != 1 || len(logs) != 1 || logs[0].Action != "import_zone" {
		t.Errorf("operator must see only the zone-scoped entry, got total=%d rows=%v", total, logs)
	}
	assertActions(operator, map[string]bool{"import_zone": true, "login": false, "create_user": false})

	// Regular user: own non-zone entries plus group zones (none seeded).
	logs, total = h.getActivityLogs(context.Background(), regular, "", "", "", "", 1, 0)
	if total != 1 || len(logs) != 1 || logs[0].Action != "login" {
		t.Errorf("regular user must see only their own login entry, got total=%d rows=%v", total, logs)
	}
	assertActions(regular, map[string]bool{"import_zone": false, "login": true, "create_user": false})
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// TestActivityLogs_AllViewCapped pins the "All" (perPage = 0) bound: without
// it any authenticated user could load the entire activity_logs table —
// old/new JSON snapshots included — in one request, a memory DoS vector on
// large deployments. "All" must fetch at most activityLogAllCap rows on both
// the global view and the per-zone tab, while the total keeps reflecting the
// real row count.
func TestActivityLogs_AllViewCapped(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsEmptyHandler())
	defer srv.Close()

	seedUserWithHash(t, h, "logadmin", "pass", "admin")

	// activityLogAllCap + a few extra rows, split across the global view and
	// one zone.
	n := activityLogAllCap + 5
	for i := 0; i < n; i++ {
		zoneID := ""
		if i >= 5 { // the last `n-5` rows belong to the zone tab
			zoneID = "capped.example.com."
		}
		if _, err := h.DB.Exec(
			"INSERT INTO activity_logs (user_id, zone_id, action, details, old_value, new_value) VALUES (1, ?, 'test_cap', ?, ?, ?)",
			zoneID, fmt.Sprintf("row %d", i), fmt.Sprintf(`{"old":%d}`, i), fmt.Sprintf(`{"new":%d}`, i),
		); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}

	logs, total := h.getActivityLogs(context.Background(), &models.User{ID: 1, Username: "logadmin", Role: "admin"}, "", "", "", "", 1, 0)
	if total != n {
		t.Errorf("total must reflect the real row count, got %d want %d", total, n)
	}
	if len(logs) != activityLogAllCap {
		t.Errorf("global \"All\" view must be capped at %d rows, got %d", activityLogAllCap, len(logs))
	}
	// Most recent first: the cap keeps the newest rows.
	if logs[0].Details != fmt.Sprintf("row %d", n-1) {
		t.Errorf("cap must keep the most recent rows, got %q", logs[0].Details)
	}

	zoneLogs, zoneTotal := h.getZoneActivityLogs(context.Background(), "capped.example.com.", 1, 0)
	if zoneTotal != n-5 {
		t.Errorf("zone total = %d, want %d", zoneTotal, n-5)
	}
	if len(zoneLogs) != n-5 {
		// The zone subset is under the cap, so it must come back whole.
		t.Errorf("zone \"All\" view under the cap must be complete, got %d want %d", len(zoneLogs), n-5)
	}
}

// TestActivityPage_InvalidDateWarning pins the filter-feedback contract:
// non-empty, unparsable from/to values are not silently dropped — the page
// must surface one warning per invalid field naming the offending value.
func TestActivityPage_InvalidDateWarning(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	r := withUserContext(httptest.NewRequest(http.MethodGet, "/activity?from=not-a-date&to=also/bad", nil), admin)
	w := httptest.NewRecorder()
	h.ActivityPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Warnings:", "not-a-date", "also/bad", "is not a valid date"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected body to contain %q, got: %s", want, body)
		}
	}
}

// TestActivityPage_ValidDatesNoWarning is the complement: a well-formed date
// range must not produce any warning banner.
func TestActivityPage_ValidDatesNoWarning(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	r := withUserContext(httptest.NewRequest(http.MethodGet, "/activity?from=2026-01-01&to=2026-01-02", nil), admin)
	w := httptest.NewRecorder()
	h.ActivityPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "Warnings:") {
		t.Errorf("valid date range must not render a warnings banner, got: %s", body)
	}
}

// TestActivityToBound_IncludesLastSecond pins the inclusive upper bound of
// the to-date filter: an entry stored at 2026-03-10 23:59:59.4 (fractional
// second) belongs to the selected day and must be included, while an entry
// on the following midnight must stay excluded. The seeds use sub-second
// fractions that round DOWN on fsp-0 MySQL DATETIME columns (23:59:59.4 →
// 23:59:59, 00:00:00.2 → 00:00:00) so the pair stays portable across the
// dialect matrix while still exercising the fractional last second on
// engines that retain it (SQLite text storage).
func TestActivityToBound_IncludesLastSecond(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	seedAt := func(createdAt string) {
		t.Helper()
		if _, err := h.DB.Exec(
			`INSERT INTO activity_logs (user_id, zone_id, action, details, created_at) VALUES (?, NULL, 'to_bound', ?, ?)`,
			admin.ID, "entry at "+createdAt, createdAt,
		); err != nil {
			t.Fatalf("seed %s: %v", createdAt, err)
		}
	}
	seedAt("2026-03-10 23:59:59.4") // last second of the selected day (fractional; rounds down to 23:59:59 on fsp-0 MySQL DATETIME)
	seedAt("2026-03-11 00:00:00.2") // next midnight (rounds to 00:00:00 on fsp-0 MySQL): excluded by the exclusive bound

	logs, total := h.getActivityLogs(context.Background(), admin, "", "", "", "2026-03-10", 1, 0)
	if total != 1 {
		t.Fatalf("to=2026-03-10 must include the 23:59:59.4 entry exactly once, got total=%d logs=%v", total, logs)
	}
	if len(logs) != 1 || !strings.Contains(logs[0].Details, "23:59:59.4") {
		t.Errorf("expected the 23:59:59.4 entry, got %v", logs)
	}
}

// TestActivityPage_TruncationNotice pins the UI feedback for the "All"
// (PerPage=0) cap: with more rows than activityLogAllCap, the page must tell
// the operator the listing was truncated instead of silently dropping rows.
func TestActivityPage_TruncationNotice(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	n := activityLogAllCap + 1
	for i := 0; i < n; i++ {
		if _, err := h.DB.Exec(
			"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, NULL, 'trunc_cap', ?)",
			admin.ID, fmt.Sprintf("row %d", i),
		); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}

	r := withUserContext(httptest.NewRequest(http.MethodGet, "/activity?PerPage=0", nil), admin)
	w := httptest.NewRecorder()
	h.ActivityPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "Truncated") {
		t.Errorf("All view over the %d-row cap must render a truncation notice, got: %s", activityLogAllCap, body)
	}
}

// TestActivityPage_TruncationAbsentUnderCap is the complement: a small log
// rendered with PerPage=0 must not claim truncation.
func TestActivityPage_TruncationAbsentUnderCap(t *testing.T) {
	h := newTestHandler(t)
	admin := seedAdminUser(t, h)

	for i := 0; i < 5; i++ {
		if _, err := h.DB.Exec(
			"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, NULL, 'trunc_small', ?)",
			admin.ID, fmt.Sprintf("row %d", i),
		); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}

	r := withUserContext(httptest.NewRequest(http.MethodGet, "/activity?PerPage=0", nil), admin)
	w := httptest.NewRecorder()
	h.ActivityPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "Truncated") {
		t.Errorf("All view under the cap must not render a truncation notice, got: %s", body)
	}
}

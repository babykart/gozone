package handlers

import (
	"context"
	"fmt"
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

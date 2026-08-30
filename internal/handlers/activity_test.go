package handlers

import (
	"context"
	"strings"
	"testing"
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

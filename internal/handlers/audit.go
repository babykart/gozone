package handlers

import (
	"context"
	"database/sql"
)

// auditExecer is the subset of *database.DB / *database.Tx that logActivity
// needs. Accepting either lets an audit row be written either as a standalone
// statement or inside a handler transaction, so the audit commits atomically
// with the operation it records.
type auditExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// activityEntry describes a single activity_logs row. ZoneID, OldValue and
// NewValue are optional: an empty ZoneID is written as NULL (the activity is
// not zone-scoped), and OldValue/NewValue default to ” when omitted.
type activityEntry struct {
	UserID   int64
	ZoneID   string // optional; "" → NULL
	Action   string
	Details  string
	OldValue string // optional; recorded for record mutations
	NewValue string // optional; recorded for record mutations
}

// logActivity writes one activity_logs row. It executes via ExecContext so the
// request context (cancellation/deadline) propagates — the audit write is no
// longer pinned to context.Background as the bare h.DB.Exec variants were — and
// returns the error so each caller keeps its own policy: best-effort callers
// log it and continue, transactional callers treat it as fatal and roll back
// (preserving the "no operation without its audit trail" invariant).
// Centralising the INSERT removes the duplicate statements that were spread
// across the handlers.
func logActivity(ctx context.Context, db auditExecer, e activityEntry) error {
	var zoneID any
	if e.ZoneID != "" {
		zoneID = e.ZoneID
	}
	_, err := db.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, zone_id, action, details, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?)",
		e.UserID, zoneID, e.Action, e.Details, e.OldValue, e.NewValue,
	)
	return err
}

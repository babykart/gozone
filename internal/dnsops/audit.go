package dnsops

import (
	"context"
	"database/sql"
)

// auditExecer is the subset of *database.DB / *database.Tx that LogActivity
// needs. Accepting either lets an audit row be written either as a standalone
// statement or inside a caller transaction, so the audit commits atomically
// with the operation it records.
type auditExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ActivityEntry describes a single activity_logs row. ZoneID, OldValue and
// NewValue are optional: an empty ZoneID is written as NULL (the activity is
// not zone-scoped), and OldValue/NewValue default to "" when omitted.
type ActivityEntry struct {
	UserID   int64
	ZoneID   string // optional; "" → NULL
	Action   string
	Details  string
	OldValue string // optional; recorded for record mutations
	NewValue string // optional; recorded for record mutations
}

// LogActivity writes one activity_logs row via the service's audit
// convention: ExecContext (so the caller's context —
// cancellation/deadline — propagates) and a returned error, leaving the
// failure policy to the caller. Best-effort callers log it and continue;
// transactional callers treat it as fatal and roll back (preserving the
// "no operation without its audit trail" invariant).
func LogActivity(ctx context.Context, db auditExecer, e ActivityEntry) error {
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

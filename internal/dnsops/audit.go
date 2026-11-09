package dnsops

import (
	"context"
	"database/sql"
	"time"
)

// auditWriteTimeout bounds the detached audit-write context: short enough
// that a dead database cannot hang the handler, long enough for a single
// INSERT. A variable, not a constant, so tests may shorten it (restore via
// t.Cleanup).
var auditWriteTimeout = 5 * time.Second

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
// convention: ExecContext and a returned error, leaving the failure policy
// to the caller. Best-effort callers log it and continue; transactional
// callers treat it as fatal and roll back (preserving the "no operation
// without its audit trail" invariant).
//
// The row must outlive the request that produced it: a client disconnect
// right after a successful mutation cancels the request context, and
// propagating that cancellation would drop the audit trail for a change
// that already happened. The INSERT therefore runs on a detached context —
// context.WithoutCancel keeps the values the caller's context carries,
// while WithTimeout(auditWriteTimeout) bounds the write so a dead database
// cannot hang the handler. Honest limit: when db is a *database.Tx whose
// own BeginTx context is already cancelled (e.g. the request-scoped
// transaction on PostgreSQL), the surrounding transaction is being rolled
// back and the insert cannot be saved — this fix covers the
// standalone-statement path used by best-effort and service-level audit
// writes.
func LogActivity(ctx context.Context, db auditExecer, e ActivityEntry) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()

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

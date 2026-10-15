package handlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/middleware"
)

// auditExecer is the subset of *database.DB / *database.Tx that logActivity
// needs. Accepting either lets an audit row be written either as a standalone
// statement or inside a handler transaction, so the audit commits atomically
// with the operation it records.
type auditExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// activityEntry describes a single activity_logs row; the INSERT itself
// lives in the dnsops service layer (dnsops.LogActivity) so every transport
// writes the identical audit shape.
type activityEntry = dnsops.ActivityEntry

// activityUserIDOf returns the acting user's id for the activity log, or 0
// when the request carries no authenticated user (defensive: every mutating
// route sits behind auth). Shared by the web and API write paths.
func activityUserIDOf(r *http.Request) int64 {
	if user := middleware.GetUser(r); user != nil {
		return user.ID
	}
	return 0
}

// logActivity writes one activity_logs row through the shared dnsops audit
// writer. It returns the error so each caller keeps its own policy:
// best-effort callers log it and continue, transactional callers treat it as
// fatal and roll back (preserving the "no operation without its audit
// trail" invariant).
func logActivity(ctx context.Context, db auditExecer, e activityEntry) error {
	return dnsops.LogActivity(ctx, db, e)
}

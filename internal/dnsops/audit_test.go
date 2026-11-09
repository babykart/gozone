package dnsops

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/testutil"
)

// ctxCaptureExecer wraps an auditExecer and snapshots the context the INSERT
// actually ran with, so tests can assert how LogActivity rebinds the
// caller's context. The snapshot is taken AT CALL TIME: LogActivity cancels
// its derived context when it returns, so inspecting the live context
// afterwards would only see the cleanup cancellation.
type ctxCaptureExecer struct {
	inner                auditExecer
	gotErr               error
	gotValue             any
	gotDeadlineRemaining time.Duration
	gotHasDeadline       bool
}

func (c *ctxCaptureExecer) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	c.gotErr = ctx.Err()
	c.gotValue = ctx.Value(auditCtxKey{})
	if d, ok := ctx.Deadline(); ok {
		c.gotHasDeadline = true
		c.gotDeadlineRemaining = time.Until(d)
	}
	return c.inner.ExecContext(ctx, query, args...)
}

type auditCtxKey struct{}

// TestLogActivity_CancelledContextStillWrites pins the core invariant: the
// audit row must outlive the request that produced it. A client disconnect
// right after a successful DNS mutation cancels the request context; the
// audit INSERT must still land (regression: the cancelled context used to
// make database/sql skip the statement, leaving the change unaudited).
func TestLogActivity_CancelledContextStillWrites(t *testing.T) {
	db := testutil.NewTestDB(t)
	userID := testutil.SeedTestUser(t, db, "auditor", "pass", "admin", true)

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), auditCtxKey{}, "kept"))
	cancel() // client disconnected before the audit write

	entry := ActivityEntry{
		UserID:   userID,
		ZoneID:   "example.",
		Action:   "delete_record",
		Details:  "A www.example.",
		OldValue: `{"content":"192.0.2.1"}`,
		NewValue: "",
	}
	if err := LogActivity(ctx, db, entry); err != nil {
		t.Fatalf("LogActivity with pre-cancelled context: %v", err)
	}

	// SELECT the row back and assert every field round-tripped.
	var gotUser int64
	var gotZone, gotAction, gotDetails, gotOld, gotNew string
	err := db.QueryRowContext(context.Background(),
		`SELECT user_id, COALESCE(zone_id, ''), action, details, COALESCE(old_value, ''), COALESCE(new_value, '') FROM activity_logs`,
	).Scan(&gotUser, &gotZone, &gotAction, &gotDetails, &gotOld, &gotNew)
	if err != nil {
		t.Fatalf("audit row not found: %v", err)
	}
	if gotUser != entry.UserID || gotZone != entry.ZoneID || gotAction != entry.Action ||
		gotDetails != entry.Details || gotOld != entry.OldValue || gotNew != entry.NewValue {
		t.Fatalf("audit row mismatch: got (%d, %q, %q, %q, %q, %q), want (%d, %q, %q, %q, %q, %q)",
			gotUser, gotZone, gotAction, gotDetails, gotOld, gotNew,
			entry.UserID, entry.ZoneID, entry.Action, entry.Details, entry.OldValue, entry.NewValue)
	}
}

// TestLogActivity_DetachedButBoundedAndValuePreserving pins how the context
// is rebound: cancellation must not propagate (the INSERT runs on a context
// that is not the caller's cancelled one), the write must be bounded by
// auditWriteTimeout (a dead database cannot hang the handler), and values
// carried by the caller's context must survive the detachment.
func TestLogActivity_DetachedButBoundedAndValuePreserving(t *testing.T) {
	db := testutil.NewTestDB(t)
	userID := testutil.SeedTestUser(t, db, "auditor-detach", "pass", "admin", true)
	capt := &ctxCaptureExecer{inner: db}

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), auditCtxKey{}, "kept"))
	cancel() // the caller is gone; the audit write must not care.

	if err := LogActivity(ctx, capt, ActivityEntry{UserID: userID, Action: "login", Details: "x"}); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	if err := capt.gotErr; err != nil {
		t.Fatalf("detached context must not inherit caller cancellation, got Err() = %v", err)
	}
	if v := capt.gotValue; v != "kept" {
		t.Fatalf("context value lost across detachment: got %v, want %q", v, "kept")
	}
	if !capt.gotHasDeadline {
		t.Fatal("detached context must carry the auditWriteTimeout deadline")
	}
	if remaining := capt.gotDeadlineRemaining; remaining <= 0 || remaining > auditWriteTimeout {
		t.Fatalf("deadline out of range: %v remaining (timeout %v)", remaining, auditWriteTimeout)
	}
}

// TestLogActivity_DeadlineStillApplies proves the bound is real: with
// auditWriteTimeout shaved to nothing the derived context is expired
// synchronously, so the INSERT must fail with the deadline rather than hang.
// Also covers the variable-shortening pattern with the required t.Cleanup
// restore.
func TestLogActivity_DeadlineStillApplies(t *testing.T) {
	db := testutil.NewTestDB(t)
	userID := testutil.SeedTestUser(t, db, "auditor-deadline", "pass", "admin", true)
	capt := &ctxCaptureExecer{inner: db}

	orig := auditWriteTimeout
	auditWriteTimeout = 0
	t.Cleanup(func() { auditWriteTimeout = orig })

	if err := LogActivity(context.Background(), capt, ActivityEntry{UserID: userID, Action: "login", Details: "x"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded with a zero auditWriteTimeout, got %v", err)
	}
}

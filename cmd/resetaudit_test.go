package cmd

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mattn/go-sqlite3"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
)

// Recording spy driver
// ---------------------------------------------------------------------------
//
// TestResetPasswordAuditAfterCommit pins the ORDER of statements in
// resetUserPassword: the audit INSERT must run after the reset transaction
// has committed. On SQLite a failed in-transaction INSERT does not abort the
// surrounding transaction, so a purely behavioural test cannot distinguish
// "audit inside the tx, error swallowed, reset commits without a trace" from
// "audit after the tx, best-effort warning" — both end with a successful
// reset and no audit row. The observable contract is therefore the statement
// order, recorded at the database/sql driver boundary: the spy wraps mattn's
// sqlite3 driver, appends a marker per executed statement to
// resetAuditMarkers, and forces any INSERT INTO activity_logs to fail,
// simulating an audit-write failure. Only one test uses the spy (cmd tests
// run sequentially) and the slice is guarded for the race detector.

var (
	resetAuditSpyMu   sync.Mutex
	resetAuditMarkers []string
)

func resetAuditMark(marker string) {
	resetAuditSpyMu.Lock()
	defer resetAuditSpyMu.Unlock()
	resetAuditMarkers = append(resetAuditMarkers, marker)
}

// resetAuditReset drops everything recorded so far; tests call it once the
// seeding noise is done so only the command's own statements are asserted on.
func resetAuditReset() {
	resetAuditSpyMu.Lock()
	defer resetAuditSpyMu.Unlock()
	resetAuditMarkers = nil
}

func resetAuditSnapshot() []string {
	resetAuditSpyMu.Lock()
	defer resetAuditSpyMu.Unlock()
	return append([]string(nil), resetAuditMarkers...)
}

// resetAuditClassify maps a statement to its marker and reports whether the
// spy consumes it (only audit-log inserts, which are forced to fail).
func resetAuditClassify(query string) (marker string, consume bool, err error) {
	q := strings.TrimSpace(query)
	if strings.HasPrefix(q, "INSERT INTO activity_logs") {
		return "audit-insert", true, errors.New("spy: forced audit-write failure")
	}
	token := q
	if i := strings.IndexAny(q, " \t\r\n("); i >= 0 {
		token = q[:i]
	}
	return "other:" + strings.ToUpper(token), false, nil
}

// resetAuditConnector is a database/sql driver.Connector over the sqlite3
// driver whose connections record every statement (and fail audit inserts).
type resetAuditConnector struct {
	dsn string
}

func (c *resetAuditConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite3.SQLiteDriver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &resetAuditConn{Conn: conn}, nil
}

func (c *resetAuditConnector) Driver() driver.Driver { return &sqlite3.SQLiteDriver{} }

// resetAuditConn wraps a sqlite3 connection, recording every statement seen
// through Prepare (the prepared path) or Exec/ExecContext (the direct-exec
// path database/sql prefers when the connection implements driver.Execer /
// driver.ExecerContext — which sqlite3 does).
type resetAuditConn struct {
	driver.Conn
}

func (c *resetAuditConn) Prepare(query string) (driver.Stmt, error) {
	marker, _, _ := resetAuditClassify(query)
	resetAuditMark(marker)
	return c.Conn.Prepare(query)
}

func (c *resetAuditConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	marker, consume, err := resetAuditClassify(query)
	resetAuditMark(marker)
	if consume {
		return nil, err
	}
	ec, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, errors.New("resetAuditConn: inner driver lacks ExecerContext")
	}
	return ec.ExecContext(ctx, query, args)
}

func (c *resetAuditConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	bc, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, errors.New("resetAuditConn: inner driver lacks ConnBeginTx")
	}
	tx, err := bc.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &resetAuditTx{Tx: tx}, nil
}

// resetAuditTx records the commit; rollback is not recorded (nothing in this
// test rolls back).
type resetAuditTx struct {
	driver.Tx
}

func (t *resetAuditTx) Commit() error {
	resetAuditMark("commit")
	return t.Tx.Commit()
}

// TestResetPasswordAuditAfterCommit proves that the CLI reset-password audit
// INSERT runs after the reset transaction has committed and that an
// audit-write failure never loses the emergency reset:
//
//   - the command succeeds even though the spy forces the audit insert to
//     fail (best-effort: a warning, not a failed recovery),
//   - the password is changed and must_change_password is set,
//   - no reset_password_cli row exists (the audit write genuinely failed),
//   - the recorded statement order places the audit insert AFTER the
//     password write and after every commit — with the audit still inside the
//     transaction this assertion fails, which is the regression pin.
//
// This mirrors unlockUser, which writes its audit row after the unlock,
// best-effort, outside any transaction.
func TestResetPasswordAuditAfterCommit(t *testing.T) {
	cfgPath, _ := writeUnlockTestConfig(t)

	// Route every database open — the seed below and the command run itself —
	// through the spy connector.
	origOpenDB := openDB
	t.Cleanup(func() { openDB = origOpenDB })
	openDB = func(cfg *config.DatabaseConfig) (*database.DB, error) {
		return database.NewWithOpener(cfg, func(_ string, dsn string) (*sql.DB, error) {
			return sql.OpenDB(&resetAuditConnector{dsn: dsn}), nil
		})
	}

	db := openUnlockTestDB(t, cfgPath) // seeds admin; bypasses the spy (database.New directly) — the spy intercepts only the command's own open

	var adminID int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatalf("find admin: %v", err)
	}
	oldHash := storedPasswordHash(t, db, adminID)

	// Drop the migration/seed noise: only the command's own statements are
	// asserted on.
	resetAuditReset()

	if err := executeResetPassword("--config", cfgPath, "--password", "newpass-secret", "admin"); err != nil {
		t.Fatalf("reset-password: %v", err)
	}

	// The reset must survive the audit-write failure, and the new credentials
	// must be in place.
	newHash := storedPasswordHash(t, db, adminID)
	if newHash == oldHash {
		t.Error("expected password_hash to change after reset")
	}
	var mustChange int
	if err := db.QueryRowContext(context.Background(),
		"SELECT must_change_password FROM users WHERE id = ?", adminID).Scan(&mustChange); err != nil {
		t.Fatalf("select must_change_password: %v", err)
	}
	if mustChange != 1 {
		t.Errorf("expected must_change_password=1 after CLI reset, got %d", mustChange)
	}

	// Best-effort means the failed audit write leaves no row behind.
	var auditRows int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM activity_logs WHERE action='reset_password_cli'").Scan(&auditRows); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if auditRows != 0 {
		t.Errorf("expected no reset_password_cli row (the audit write failed), got %d", auditRows)
	}

	// The order pin: the audit insert must come after the password write and
	// after EVERY commit — in particular after the reset's own commit, which
	// is the last one in this flow. With the audit still inside the
	// transaction the insert lands before that final commit and the last
	// assertion fails.
	markers := resetAuditSnapshot()
	auditIdx, updateIdx, lastCommitIdx := -1, -1, -1
	for i, m := range markers {
		switch {
		case m == "audit-insert":
			auditIdx = i
		case m == "other:UPDATE":
			updateIdx = i
		case m == "commit":
			lastCommitIdx = i
		}
	}
	if updateIdx < 0 {
		t.Fatalf("no UPDATE recorded through the spy; markers: %v", markers)
	}
	if lastCommitIdx < 0 {
		t.Fatalf("no commit recorded through the spy; markers: %v", markers)
	}
	if auditIdx < 0 {
		t.Fatalf("no audit insert recorded through the spy; markers: %v", markers)
	}
	if auditIdx <= updateIdx {
		t.Errorf("audit insert must run after the password UPDATE; markers: %v", markers)
	}
	if auditIdx <= lastCommitIdx {
		t.Errorf("audit insert must run after the reset transaction commits; markers: %v", markers)
	}
}

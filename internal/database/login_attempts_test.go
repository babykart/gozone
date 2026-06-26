package database

import (
	"context"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
)

func newLoginAttemptsTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func insertUserForLoginTests(t *testing.T, db *DB, username string) int64 {
	t.Helper()
	res, err := db.ExecContext(context.Background(),
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, 'hash', 'user')",
		username, username+"@example.com",
	)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

func TestRecordLoginAttempt(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()

	if err := db.RecordLoginAttempt(ctx, "alice", "1.2.3.4", 0, false); err != nil {
		t.Fatalf("RecordLoginAttempt: %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM login_attempts").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}
}

func TestRecordLoginAttempt_WithUserID(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "bob")

	if err := db.RecordLoginAttempt(ctx, "bob", "1.2.3.4", uid, true); err != nil {
		t.Fatalf("RecordLoginAttempt: %v", err)
	}
	var storedUID int64
	var success int
	if err := db.QueryRowContext(ctx, "SELECT user_id, success FROM login_attempts WHERE username = 'bob'").Scan(&storedUID, &success); err != nil {
		t.Fatalf("select: %v", err)
	}
	if storedUID != uid {
		t.Errorf("expected user_id %d, got %d", uid, storedUID)
	}
	if success != 1 {
		t.Errorf("expected success=1, got %d", success)
	}
}

func TestPurgeLoginAttempts(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, ip_address, attempted_at) VALUES ('alice', '1.1.1.1', ?)",
		now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, ip_address, attempted_at) VALUES ('alice', '1.1.1.1', ?)",
		now.Add(-1*time.Hour)); err != nil {
		t.Fatalf("insert fresh: %v", err)
	}

	deleted, err := db.PurgeLoginAttempts(ctx, 24)
	if err != nil {
		t.Fatalf("PurgeLoginAttempts: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	var remaining int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM login_attempts").Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("expected 1 remaining, got %d", remaining)
	}
}

func TestPurgeLoginAttempts_Disabled(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, ip_address) VALUES ('alice', '1.1.1.1')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	deleted, err := db.PurgeLoginAttempts(ctx, 0)
	if err != nil {
		t.Fatalf("PurgeLoginAttempts: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted when retention is 0, got %d", deleted)
	}
}

func TestFailedLoginStats(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES ('alice', '1.1.1.1', 0, ?)",
		now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("insert 1: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES ('alice', '1.1.1.1', 0, ?)",
		now.Add(-1*time.Hour)); err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES ('alice', '1.1.1.1', 1, ?)",
		now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("insert success: %v", err)
	}

	count, last, err := db.FailedLoginStats(ctx, "alice", 3*time.Hour)
	if err != nil {
		t.Fatalf("FailedLoginStats: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 failed attempts in window, got %d", count)
	}
	if last.IsZero() {
		t.Errorf("expected non-zero last failure timestamp")
	}
}

func TestFailedLoginStats_Window(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		"INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES ('alice', '1.1.1.1', 0, ?)",
		now.Add(-10*time.Hour)); err != nil {
		t.Fatalf("insert old: %v", err)
	}

	count, _, err := db.FailedLoginStats(ctx, "alice", 1*time.Hour)
	if err != nil {
		t.Fatalf("FailedLoginStats: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 attempts in short window, got %d", count)
	}
}

func TestIncrementFailedLogins_TriggersLockout(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "alice")

	for i := 1; i <= 3; i++ {
		count, err := db.IncrementFailedLogins(ctx, uid, 3, 15*time.Minute)
		if err != nil {
			t.Fatalf("IncrementFailedLogins #%d: %v", i, err)
		}
		if count != i {
			t.Errorf("after %d increments, expected count %d, got %d", i, i, count)
		}
	}

	locked, until, err := db.UserLockStatus(ctx, uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Error("expected user to be locked after threshold")
	}
	if !until.After(time.Now()) {
		t.Errorf("expected locked_until in the future, got %v", until)
	}
}

func TestIncrementFailedLogins_DisabledWhenZeroThreshold(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "alice")

	count, err := db.IncrementFailedLogins(ctx, uid, 0, 15*time.Minute)
	if err != nil {
		t.Fatalf("IncrementFailedLogins: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 when threshold is 0, got %d", count)
	}

	locked, _, err := db.UserLockStatus(ctx, uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected no lockout when threshold is 0")
	}
}

func TestResetFailedLogins(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "alice")

	// Push counter up and lock the account.
	if _, err := db.IncrementFailedLogins(ctx, uid, 1, time.Hour); err != nil {
		t.Fatalf("IncrementFailedLogins: %v", err)
	}

	if err := db.ResetFailedLogins(ctx, uid); err != nil {
		t.Fatalf("ResetFailedLogins: %v", err)
	}

	locked, _, err := db.UserLockStatus(ctx, uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected not locked after reset")
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT failed_login_attempts FROM users WHERE id = ?", uid).Scan(&count); err != nil {
		t.Fatalf("select: %v", err)
	}
	if count != 0 {
		t.Errorf("expected counter reset to 0, got %d", count)
	}
}

func TestUserLockStatus_ExpiredLock(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "alice")

	// Set locked_until to a past time directly.
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET locked_until = ? WHERE id = ?",
		time.Now().Add(-1*time.Hour), uid); err != nil {
		t.Fatalf("update: %v", err)
	}

	locked, _, err := db.UserLockStatus(ctx, uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected unlocked status when locked_until is in the past")
	}
}

func TestUserLockStatus_NotFound(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()

	locked, _, err := db.UserLockStatus(ctx, 99999)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if locked {
		t.Error("expected locked=false for non-existent user")
	}
}

func TestIsLastEnabledAdmin_SoleAdmin(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "solo")
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET role='admin' WHERE id = ?", uid); err != nil {
		t.Fatalf("set role: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck

	last, err := tx.IsLastEnabledAdmin(ctx, uid)
	if err != nil {
		t.Fatalf("IsLastEnabledAdmin: %v", err)
	}
	if !last {
		t.Error("expected IsLastEnabledAdmin=true for sole admin")
	}
}

func TestIsLastEnabledAdmin_OneOfMany(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	id1 := insertUserForLoginTests(t, db, "admin1")
	id2 := insertUserForLoginTests(t, db, "admin2")
	for _, id := range []int64{id1, id2} {
		if _, err := db.ExecContext(ctx,
			"UPDATE users SET role='admin' WHERE id = ?", id); err != nil {
			t.Fatalf("set role: %v", err)
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck

	for _, id := range []int64{id1, id2} {
		last, err := tx.IsLastEnabledAdmin(ctx, id)
		if err != nil {
			t.Fatalf("IsLastEnabledAdmin(%d): %v", id, err)
		}
		if last {
			t.Errorf("expected IsLastEnabledAdmin=false for id=%d (2 admins exist)", id)
		}
	}
}

func TestIsLastEnabledAdmin_NonAdmin(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	adminID := insertUserForLoginTests(t, db, "admin")
	userID := insertUserForLoginTests(t, db, "alice")
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET role='admin' WHERE id = ?", adminID); err != nil {
		t.Fatalf("set role: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck

	last, err := tx.IsLastEnabledAdmin(ctx, userID)
	if err != nil {
		t.Fatalf("IsLastEnabledAdmin: %v", err)
	}
	if last {
		t.Error("expected IsLastEnabledAdmin=false for non-admin user")
	}
}

func TestIsLastEnabledAdmin_DisabledAdmin(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	id1 := insertUserForLoginTests(t, db, "admin1")
	id2 := insertUserForLoginTests(t, db, "admin2")
	for _, id := range []int64{id1, id2} {
		if _, err := db.ExecContext(ctx,
			"UPDATE users SET role='admin' WHERE id = ?", id); err != nil {
			t.Fatalf("set role: %v", err)
		}
	}
	// Disable id2 — id1 becomes the last enabled admin.
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET enabled = 0 WHERE id = ?", id2); err != nil {
		t.Fatalf("disable: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck

	last, err := tx.IsLastEnabledAdmin(ctx, id1)
	if err != nil {
		t.Fatalf("IsLastEnabledAdmin: %v", err)
	}
	if !last {
		t.Error("expected IsLastEnabledAdmin=true when only one admin is enabled")
	}
}

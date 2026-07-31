package database

import (
	"context"
	"sync"
	"sync/atomic"
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
		t.Fatalf("expected non-zero last failure timestamp")
	}
	// The two failures are at now-2h and now-1h; MAX must return the more
	// recent one (now-1h), not the older. -90min sits between them, so a correct
	// MAX is strictly after it (REVIEW.md L-16f).
	if !last.After(now.Add(-90 * time.Minute)) {
		t.Errorf("expected last failure to be the most recent (~now-1h), got %v", last)
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

// TestIncrementFailedLogins_ConcurrentNoLostIncrements is the regression test
// for m19: under a concurrent burst of failed logins the counter must never
// lose or duplicate an increment, and the lockout must take effect once the
// threshold is crossed. The previous non-transactional read-modify-write could
// race and observe stale counts. (SQLite serializes writers via MaxOpenConns=1,
// so this mainly guards against deadlocks and confirms the final count is
// exact; the race is most acute on MySQL/PostgreSQL where writers truly
// overlap.)
func TestIncrementFailedLogins_ConcurrentNoLostIncrements(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "bob")

	const goroutines = 50
	const threshold = 10

	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.IncrementFailedLogins(ctx, uid, threshold, 15*time.Minute); err != nil {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()

	if n := failures.Load(); n != 0 {
		t.Fatalf("%d concurrent IncrementFailedLogins calls returned an error", n)
	}

	var count int
	if err := db.QueryRowContext(ctx,
		"SELECT failed_login_attempts FROM users WHERE id = ?", uid,
	).Scan(&count); err != nil {
		t.Fatalf("select counter: %v", err)
	}
	if count != goroutines {
		t.Errorf("concurrent increments lost or duplicated: counter = %d, want %d", count, goroutines)
	}

	locked, _, err := db.UserLockStatus(ctx, uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Error("expected user to be locked after crossing the threshold under concurrency")
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

// TestIsLastEnabledAdmin_ConcurrentLockOrder exercises the lock-ordering
// invariant fixed in REVIEW.md M-2: IsLastEnabledAdmin must acquire the
// enabled-admin set lock (CountEnabledAdmins' FOR UPDATE) BEFORE the target
// row, matching UpdateUser/DeleteUser. Some goroutines repeatedly call
// IsLastEnabledAdmin while others open a tx, call CountEnabledAdmins (the
// UpdateUser lock pattern) and toggle a target's role — the two lock
// acquisition orders must not deadlock.
//
// SQLite serializes writers via MaxOpenConns=1, so (per the convention in
// TestIncrementFailedLogins_ConcurrentNoLostIncrements) this mainly guards
// against deadlocks and confirms the final state is consistent; the cycle is
// only reachable on MySQL/PostgreSQL where writers truly overlap.
func TestIsLastEnabledAdmin_ConcurrentLockOrder(t *testing.T) {
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

	const goroutines = 40
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			target := id1
			if n%2 == 0 {
				target = id2
			}
			if n%3 == 0 {
				// Reader path: IsLastEnabledAdmin (admin-set lock then target).
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					failures.Add(1)
					return
				}
				defer tx.Rollback() //nolint:errcheck
				if _, err := tx.IsLastEnabledAdmin(ctx, target); err != nil {
					failures.Add(1)
					return
				}
			} else {
				// Writer path mirroring UpdateUser: CountEnabledAdmins (admin-set
				// lock first) then UPDATE the target row.
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					failures.Add(1)
					return
				}
				defer tx.Rollback() //nolint:errcheck
				if _, err := tx.CountEnabledAdmins(ctx); err != nil {
					failures.Add(1)
					return
				}
				if _, err := tx.ExecContext(ctx,
					"UPDATE users SET first_name = ? WHERE id = ?", "x", target); err != nil {
					failures.Add(1)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if n := failures.Load(); n != 0 {
		t.Fatalf("%d concurrent IsLastEnabledAdmin/CountEnabledAdmins calls returned an error", n)
	}
	// Both admins must still be enabled admins — the writer path only touched
	// first_name, never role/enabled.
	var role string
	var enabled int
	if err := db.QueryRowContext(ctx, "SELECT role, enabled FROM users WHERE id = ?", id1).Scan(&role, &enabled); err != nil {
		t.Fatalf("select admin1: %v", err)
	}
	if role != "admin" || enabled != 1 {
		t.Errorf("admin1 unexpectedly changed: role=%q enabled=%d", role, enabled)
	}
}

// TestAdminLockUser_RevokesSessions verifies the M2 fix: a manual admin lock
// bumps tokens_valid_after so the Auth middleware rejects every outstanding
// session for the locked user, not just future logins.
func TestAdminLockUser_RevokesSessions(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "carol")

	var tvaBefore time.Time
	if err := db.QueryRowContext(ctx, "SELECT tokens_valid_after FROM users WHERE id = ?", uid).Scan(&tvaBefore); err != nil {
		t.Fatalf("select tokens_valid_after: %v", err)
	}

	if err := db.AdminLockUser(ctx, uid, 15*time.Minute); err != nil {
		t.Fatalf("AdminLockUser: %v", err)
	}

	var tvaAfter time.Time
	if err := db.QueryRowContext(ctx, "SELECT tokens_valid_after FROM users WHERE id = ?", uid).Scan(&tvaAfter); err != nil {
		t.Fatalf("select tokens_valid_after after lock: %v", err)
	}
	if !tvaAfter.After(tvaBefore) {
		t.Error("expected tokens_valid_after to be bumped by a manual admin lock (M2)")
	}
}

// TestIncrementFailedLogins_DoesNotRevokeSessions locks in the design decision
// that the automatic brute-force lockout must NOT cut active sessions: an
// attacker who triggers the threshold should not be able to kick the
// legitimate user off their other devices (DoS amplification). Only the
// manual, admin-initiated lock revokes sessions.
func TestIncrementFailedLogins_DoesNotRevokeSessions(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "dave")

	var tvaBefore time.Time
	if err := db.QueryRowContext(ctx, "SELECT tokens_valid_after FROM users WHERE id = ?", uid).Scan(&tvaBefore); err != nil {
		t.Fatalf("select tokens_valid_after: %v", err)
	}

	// Cross the threshold to trigger the automatic lockout.
	for i := 0; i < 3; i++ {
		if _, err := db.IncrementFailedLogins(ctx, uid, 3, 15*time.Minute); err != nil {
			t.Fatalf("IncrementFailedLogins #%d: %v", i+1, err)
		}
	}

	locked, _, err := db.UserLockStatus(ctx, uid)
	if err != nil {
		t.Fatalf("UserLockStatus: %v", err)
	}
	if !locked {
		t.Fatal("expected the account to be locked after crossing the threshold")
	}

	var tvaAfter time.Time
	if err := db.QueryRowContext(ctx, "SELECT tokens_valid_after FROM users WHERE id = ?", uid).Scan(&tvaAfter); err != nil {
		t.Fatalf("select tokens_valid_after after auto-lockout: %v", err)
	}
	if !tvaAfter.Equal(tvaBefore) {
		t.Errorf("automatic lockout must not revoke sessions: tokens_valid_after before=%v after=%v", tvaBefore, tvaAfter)
	}
}

// TestAdminLockUser_SetsManualLockMarker verifies the B3 decoupling: a manual
// admin lock sets the dedicated manual_lock_until marker (in addition to
// locked_until), so the login path can enforce it independently of the
// automatic brute-force feature flag.
func TestAdminLockUser_SetsManualLockMarker(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "erin")

	if err := db.AdminLockUser(ctx, uid, 15*time.Minute); err != nil {
		t.Fatalf("AdminLockUser: %v", err)
	}
	manual, err := db.IsManualLock(ctx, uid)
	if err != nil {
		t.Fatalf("IsManualLock: %v", err)
	}
	if !manual {
		t.Error("expected AdminLockUser to set the manual-lock marker (manual_lock_until)")
	}

	// AdminUnlockUser must clear it.
	if err := db.AdminUnlockUser(ctx, uid); err != nil {
		t.Fatalf("AdminUnlockUser: %v", err)
	}
	manual, err = db.IsManualLock(ctx, uid)
	if err != nil {
		t.Fatalf("IsManualLock after unlock: %v", err)
	}
	if manual {
		t.Error("expected AdminUnlockUser to clear the manual-lock marker")
	}
}

// TestIncrementFailedLogins_DoesNotSetManualLockMarker is the counterpart: the
// automatic brute-force lockout must only set locked_until, never the manual
// marker — otherwise disabling the auto feature would not decouple from
// manual enforcement.
func TestIncrementFailedLogins_DoesNotSetManualLockMarker(t *testing.T) {
	db := newLoginAttemptsTestDB(t)
	ctx := context.Background()
	uid := insertUserForLoginTests(t, db, "frank")

	for i := 0; i < 3; i++ {
		if _, err := db.IncrementFailedLogins(ctx, uid, 3, 15*time.Minute); err != nil {
			t.Fatalf("IncrementFailedLogins #%d: %v", i+1, err)
		}
	}
	manual, err := db.IsManualLock(ctx, uid)
	if err != nil {
		t.Fatalf("IsManualLock: %v", err)
	}
	if manual {
		t.Error("automatic brute-force lockout must not set the manual-lock marker")
	}
}

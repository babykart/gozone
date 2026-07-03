package database

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/config"
)

// newHistoryTestDB returns an in-memory DB with a single seeded user. The
// caller must close the returned DB.
func newHistoryTestDB(t *testing.T) (*DB, int64) {
	t.Helper()
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	res, err := db.ExecContext(context.Background(),
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, 'x', 'user', 1)`,
		"histuser", "hist@test.local",
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	uid, _ := res.LastInsertId()
	return db, uid
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return string(h)
}

func TestPasswordHistory_ReuseDetection(t *testing.T) {
	db, uid := newHistoryTestDB(t)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() // #nosec G104

	if err := tx.RecordPassword(ctx, uid, mustHash(t, "oldpass1")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := tx.RecordPassword(ctx, uid, mustHash(t, "oldpass2")); err != nil {
		t.Fatalf("record: %v", err)
	}

	// The two recorded passwords must be detected as reused.
	if reused, err := tx.PasswordHistoryReused(ctx, uid, "oldpass1", 5); err != nil || !reused {
		t.Errorf("oldpass1: expected reuse, got reused=%v err=%v", reused, err)
	}
	if reused, err := tx.PasswordHistoryReused(ctx, uid, "oldpass2", 5); err != nil || !reused {
		t.Errorf("oldpass2: expected reuse, got reused=%v err=%v", reused, err)
	}
	// A brand-new password is not a reuse.
	if reused, err := tx.PasswordHistoryReused(ctx, uid, "brandnew", 5); err != nil || reused {
		t.Errorf("brandnew: expected no reuse, got reused=%v err=%v", reused, err)
	}
}

func TestPasswordHistory_DisabledByZeroLimit(t *testing.T) {
	db, uid := newHistoryTestDB(t)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() // #nosec G104

	// Even with a recorded password, limit <= 0 short-circuits to "no reuse".
	if err := tx.RecordPassword(ctx, uid, mustHash(t, "samepass")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if reused, err := tx.PasswordHistoryReused(ctx, uid, "samepass", 0); err != nil || reused {
		t.Errorf("limit=0: expected no reuse, got reused=%v err=%v", reused, err)
	}
	// Prune with limit <= 0 is a no-op.
	if err := tx.PrunePasswordHistory(ctx, uid, 0); err != nil {
		t.Fatalf("prune limit=0: %v", err)
	}
	if n, err := tx.PasswordHistoryCount(ctx, uid); err != nil || n != 1 {
		t.Errorf("after prune(0): expected count=1, got %d err=%v", n, err)
	}
}

func TestPasswordHistory_RespectsLimit(t *testing.T) {
	db, uid := newHistoryTestDB(t)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() // #nosec G104

	// Record two passwords; the oldest falls outside a limit of 1.
	if err := tx.RecordPassword(ctx, uid, mustHash(t, "oldest")); err != nil {
		t.Fatalf("record oldest: %v", err)
	}
	if err := tx.RecordPassword(ctx, uid, mustHash(t, "newest")); err != nil {
		t.Fatalf("record newest: %v", err)
	}
	// Only the most recent entry is inspected.
	if reused, err := tx.PasswordHistoryReused(ctx, uid, "newest", 1); err != nil || !reused {
		t.Errorf("newest (limit 1): expected reuse, got reused=%v err=%v", reused, err)
	}
	if reused, err := tx.PasswordHistoryReused(ctx, uid, "oldest", 1); err != nil || reused {
		t.Errorf("oldest (limit 1): expected NOT reused (out of window), got reused=%v err=%v", reused, err)
	}
	// With limit 2 the oldest is back in scope.
	if reused, err := tx.PasswordHistoryReused(ctx, uid, "oldest", 2); err != nil || !reused {
		t.Errorf("oldest (limit 2): expected reuse, got reused=%v err=%v", reused, err)
	}
}

func TestPasswordHistory_Prune(t *testing.T) {
	db, uid := newHistoryTestDB(t)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() // #nosec G104

	for i := 0; i < 5; i++ {
		if err := tx.RecordPassword(ctx, uid, mustHash(t, "p"+string(rune('1'+i)))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := tx.PrunePasswordHistory(ctx, uid, 3); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n, err := tx.PasswordHistoryCount(ctx, uid); err != nil || n != 3 {
		t.Errorf("after prune to 3: expected count=3, got %d err=%v", n, err)
	}
	// The kept rows must be the 3 newest (largest ids).
	rows, err := tx.QueryContext(ctx,
		`SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC`, uid)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, h)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(got))
	}
	// The newest entry must still validate against "p5" (last recorded).
	if err := bcrypt.CompareHashAndPassword([]byte(got[0]), []byte("p5")); err != nil {
		t.Errorf("newest kept hash should match p5: %v", err)
	}
}

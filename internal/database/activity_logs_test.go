package database

import (
	"context"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
)

func newActivityLogsTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPurgeActivityLogs(t *testing.T) {
	db := newActivityLogsTestDB(t)
	ctx := context.Background()

	// Insert one fresh log and one old log.
	if _, err := db.ExecContext(ctx,
		"INSERT INTO activity_logs (action, details, created_at) VALUES ('create_zone', 'fresh', ?)",
		time.Now().UTC()); err != nil {
		t.Fatalf("insert fresh log: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO activity_logs (action, details, created_at) VALUES ('create_zone', 'old', ?)",
		time.Now().UTC().AddDate(0, 0, -91)); err != nil {
		t.Fatalf("insert old log: %v", err)
	}

	deleted, err := db.PurgeActivityLogs(ctx, 90, 1000)
	if err != nil {
		t.Fatalf("PurgeActivityLogs: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	var remaining int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM activity_logs").Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("expected 1 row remaining, got %d", remaining)
	}
}

func TestPurgeActivityLogs_Disabled(t *testing.T) {
	db := newActivityLogsTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		"INSERT INTO activity_logs (action, details, created_at) VALUES ('create_zone', 'old', ?)",
		time.Now().UTC().AddDate(0, 0, -365)); err != nil {
		t.Fatalf("insert old log: %v", err)
	}

	deleted, err := db.PurgeActivityLogs(ctx, 0, 1000)
	if err != nil {
		t.Fatalf("PurgeActivityLogs: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted when disabled, got %d", deleted)
	}

	var remaining int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM activity_logs").Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("expected 1 row remaining, got %d", remaining)
	}
}

func TestPurgeActivityLogs_BatchSize(t *testing.T) {
	db := newActivityLogsTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := db.ExecContext(ctx,
			"INSERT INTO activity_logs (action, details, created_at) VALUES ('create_zone', ?, ?)",
			i, time.Now().UTC().AddDate(0, 0, -91)); err != nil {
			t.Fatalf("insert old log: %v", err)
		}
	}

	// Batch size of 2 should require multiple iterations.
	deleted, err := db.PurgeActivityLogs(ctx, 90, 2)
	if err != nil {
		t.Fatalf("PurgeActivityLogs: %v", err)
	}
	if deleted != 5 {
		t.Errorf("expected 5 deleted, got %d", deleted)
	}
}

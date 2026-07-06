package database

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSQLiteDialect_DriverName(t *testing.T) {
	d := &sqliteDialect{}
	if got := d.DriverName(); got != "sqlite3" {
		t.Errorf("expected driver sqlite3, got %s", got)
	}
}

func TestSQLiteDialect_MaxOpenConns(t *testing.T) {
	d := &sqliteDialect{}
	if got := d.MaxOpenConns(); got <= 0 {
		t.Errorf("expected positive MaxOpenConns, got %d", got)
	}
}

// TestSQLiteDialect_PoolSettings verifies the SQLite pool is tuned for its
// single serialized connection: idle matches open (keep the lone conn warm)
// and the connection lifetime is unlimited (no proxy to drop a local file
// connection). REVIEW.md m16.
func TestSQLiteDialect_PoolSettings(t *testing.T) {
	d := &sqliteDialect{}
	if got := d.MaxIdleConns(); got != d.MaxOpenConns() {
		t.Errorf("MaxIdleConns %d must match MaxOpenConns %d for SQLite", got, d.MaxOpenConns())
	}
	if got := d.ConnMaxLifetime(); got != 0 {
		t.Errorf("SQLite ConnMaxLifetime must be 0 (unlimited), got %v", got)
	}
}

func TestSQLiteDialect_Rebind(t *testing.T) {
	d := &sqliteDialect{}
	q := "SELECT * FROM users WHERE id = ?"
	if got := d.Rebind(q); got != q {
		t.Errorf("expected SQLite rebinding to be a no-op, got %q", got)
	}
}

// TestSQLiteDialect_InsertIgnore_IgnoresConflictColumns verifies the contract
// from the Dialect interface: SQLite's INSERT OR IGNORE catches any unique
// violation, so the conflictColumns parameter is intentionally unused. The
// returned SQL must match the previous shape exactly so callers don't observe
// a behaviour change after the signature update.
func TestSQLiteDialect_InsertIgnore_IgnoresConflictColumns(t *testing.T) {
	d := &sqliteDialect{}
	got := d.InsertIgnore(
		"zone_group_members",
		[]string{"group_id", "user_id"},
		[]string{"group_id", "user_id"},
	)
	want := "INSERT OR IGNORE INTO zone_group_members (group_id, user_id) VALUES (?, ?)"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}

	// And with empty conflictColumns — same output, proving the parameter
	// is purely cosmetic for SQLite.
	got = d.InsertIgnore("zone_group_members", []string{"group_id", "user_id"}, nil)
	if got != want {
		t.Errorf("empty conflictColumns must not alter SQLite output\ngot:  %q\nwant: %q", got, want)
	}
}

func TestSQLiteDialect_Migrations_NoDoubleOnConflict(t *testing.T) {
	// Defence against a regression on the SQLite side: a future contributor
	// must not "fix" SQLite by adding an ON CONFLICT clause (that's Postgres
	// syntax and would break SQLite). The INSERT OR IGNORE form catches all
	// unique violations without needing an explicit conflict target.
	d := &sqliteDialect{}
	for _, m := range d.Migrations() {
		if strings.Contains(strings.ToUpper(m), "ON CONFLICT") {
			t.Errorf("SQLite migration must not contain ON CONFLICT: %s", m)
		}
	}
}

// TestSQLiteDialect_IsAlreadyExistsError verifies the message-text matching
// that lets the migration runner tolerate re-running an already-applied
// migration after a content edit (REVIEW.md m22).
func TestSQLiteDialect_IsAlreadyExistsError(t *testing.T) {
	d := &sqliteDialect{}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"duplicate column", errors.New("duplicate column name: old_value"), true},
		{"table already exists", errors.New("table users already exists"), true},
		{"index already exists", errors.New("index idx already exists"), true},
		{"wrapped duplicate", fmt.Errorf("migrate: %w", errors.New("duplicate column name: x")), true},
		{"unrelated", errors.New("no such table: x"), false},
		{"syntax error", errors.New("near \"FOO\": syntax error"), false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsAlreadyExistsError(tt.err); got != tt.want {
				t.Errorf("IsAlreadyExistsError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestSQLiteDialect_IsUniqueViolation verifies the message-text matching used
// to classify a UNIQUE-constraint violation (REVIEW.md L-7). The go-sqlite3
// driver exposes no typed error code, so detection relies on the stable
// "UNIQUE constraint failed: ..." prefix that every SQLite version emits.
func TestSQLiteDialect_IsUniqueViolation(t *testing.T) {
	d := &sqliteDialect{}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unique constraint failed", errors.New("UNIQUE constraint failed: zone_groups.name"), true},
		{"wrapped unique", fmt.Errorf("insert: %w", errors.New("UNIQUE constraint failed: users.email")), true},
		{"lowercase unique", errors.New("unique constraint failed: zone_groups.name"), false},
		{"foreign key", errors.New("FOREIGN KEY constraint failed"), false},
		{"not null", errors.New("NOT NULL constraint failed: users.id"), false},
		{"unrelated", errors.New("no such table: x"), false},
		{"empty", errors.New(""), false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.IsUniqueViolation(tt.err); got != tt.want {
				t.Errorf("IsUniqueViolation(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

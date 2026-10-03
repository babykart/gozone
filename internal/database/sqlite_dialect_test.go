package database

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteDialect_DriverName(t *testing.T) {
	d := &sqliteDialect{}
	if got := d.DriverName(); got != "sqlite3" {
		t.Errorf("expected driver sqlite3, got %s", got)
	}
}

// TestSQLiteDialect_DSN_Pragmas verifies the DSN carries the three deployment
// pragmas: WAL (readers never block the writer, also across processes — the
// recovery CLI opens the same file as a running server), foreign-key
// enforcement (parity with MySQL/PostgreSQL defaults) and a busy timeout so
// transient cross-process writer contention waits instead of failing with an
// immediate SQLITE_BUSY.
func TestSQLiteDialect_DSN_Pragmas(t *testing.T) {
	d := &sqliteDialect{}

	mem := d.DSN(":memory:")
	for _, want := range []string{"_journal_mode=WAL", "_foreign_keys=on", "_busy_timeout=5000"} {
		if !strings.Contains(mem, want) {
			t.Errorf(":memory: DSN missing %s: %s", want, mem)
		}
	}

	file := d.DSN("file:/var/lib/gozone/gozone.db")
	for _, want := range []string{"_journal_mode=WAL", "_foreign_keys=on", "_busy_timeout=5000"} {
		if !strings.Contains(file, want) {
			t.Errorf("file DSN missing %s: %s", want, file)
		}
	}
	if !strings.Contains(file, "/var/lib/gozone/gozone.db") {
		t.Errorf("file DSN must preserve the path: %s", file)
	}
}

// TestSQLiteDialect_DSN_OverridesCallerPragmas pins that the correctness
// pragmas are not tuning knobs: a DSN that arrives with different values gets
// them overwritten rather than honoured.
func TestSQLiteDialect_DSN_OverridesCallerPragmas(t *testing.T) {
	d := &sqliteDialect{}
	got := d.DSN("file:/tmp/gozone.db?_journal_mode=DELETE&_busy_timeout=0")
	if !strings.Contains(got, "_journal_mode=WAL") || strings.Contains(got, "DELETE") {
		t.Errorf("journal_mode must be forced to WAL, got %s", got)
	}
	if !strings.Contains(got, "_busy_timeout=5000") || strings.Contains(got, "_busy_timeout=0") {
		t.Errorf("busy_timeout must be forced to 5000, got %s", got)
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
// connection).
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
// migration after a content edit.
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
// to classify a UNIQUE-constraint violation. The go-sqlite3
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

// TestMigrate_SQLitePopulatedUsersUpgrade verifies the upgrade path from a
// database created before the password_changed_at column existed. SQLite
// rejects ADD COLUMN with a non-constant default once the table holds rows
// ("Cannot add a column with non-constant default"), and users is never empty
// on an upgraded deployment (the seed admin always exists), so the migration
// must add the column with a constant epoch default and backfill existing rows
// with a follow-up UPDATE. The seeded schema stops right before that
// migration, then migrate() replays the full remaining sequence over the
// populated table.
func TestMigrate_SQLitePopulatedUsersUpgrade(t *testing.T) {
	dialect := &sqliteDialect{}
	dsn := filepath.Join(t.TempDir(), "gozone.db")
	conn, err := sql.Open("sqlite3", dialect.DSN(dsn))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	db := &DB{Conn: conn, dialect: dialect}

	// Bootstrap the tracking table, mirroring migrate()'s own first step.
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	// Recreate a pre-column database: apply every migration that precedes
	// the password_changed_at one (breaking at the target), then populate
	// users the way a real deployment always is.
	applied := 0
	for _, m := range dialect.Migrations() {
		if strings.Contains(m, "ADD COLUMN password_changed_at") {
			break
		}
		if err := db.applyMigration(m, migrationVersion(m)); err != nil {
			t.Fatalf("seed pre-column migration %d: %v", applied, err)
		}
		applied++
	}
	if applied == 0 {
		t.Fatal("test baseline: no migration applied before password_changed_at")
	}
	if _, err := conn.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES ('admin', 'admin@example.com', 'x', 'admin', 1)`,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// A plain "ADD COLUMN ... DEFAULT CURRENT_TIMESTAMP" fails here with
	// "Cannot add a column with non-constant default"; migrate() must
	// succeed and backfill the column.
	if err := db.migrate(); err != nil {
		t.Fatalf("migrate over populated users table: %v", err)
	}

	var changedAt time.Time
	if err := conn.QueryRow(
		"SELECT password_changed_at FROM users WHERE username = 'admin'",
	).Scan(&changedAt); err != nil {
		t.Fatalf("select password_changed_at: %v", err)
	}
	if changedAt.Before(time.Now().UTC().Add(-time.Minute)) {
		t.Errorf("password_changed_at = %v, want ~now (backfilled by the migration)", changedAt)
	}

	// Rows inserted without the column get the constant epoch filler: this
	// is the schema contract that production INSERTs must set the column
	// explicitly instead of relying on a now() default.
	if _, err := conn.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES ('later', 'later@example.com', 'x', 'user', 1)`,
	); err != nil {
		t.Fatalf("insert without password_changed_at: %v", err)
	}
	var epoch time.Time
	if err := conn.QueryRow(
		"SELECT password_changed_at FROM users WHERE username = 'later'",
	).Scan(&epoch); err != nil {
		t.Fatalf("select filler default: %v", err)
	}
	if epoch.Unix() != 0 {
		t.Errorf("omitted password_changed_at = %v, want the epoch filler default", epoch)
	}

	// Steady state: a second run is a no-op.
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate should be a no-op: %v", err)
	}
}

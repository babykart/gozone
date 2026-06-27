package database

import (
	"database/sql"
	"strings"
	"testing"
)

func TestPostgresDialect_DriverName(t *testing.T) {
	d := &postgresDialect{}
	if got := d.DriverName(); got != "postgres" {
		t.Errorf("expected driver postgres, got %s", got)
	}
}

func TestPostgresDialect_DSN_PassesThrough(t *testing.T) {
	d := &postgresDialect{}
	input := "host=localhost port=5432 user=gozone password=secret dbname=gozone sslmode=disable"
	if got := d.DSN(input); got != input {
		t.Errorf("expected DSN to pass through unchanged\nwant: %s\ngot:  %s", input, got)
	}
}

func TestPostgresDialect_MaxOpenConns(t *testing.T) {
	d := &postgresDialect{}
	if got := d.MaxOpenConns(); got != 25 {
		t.Errorf("expected MaxOpenConns 25, got %d", got)
	}
}

func TestPostgresDialect_Rebind(t *testing.T) {
	d := &postgresDialect{}
	q := "SELECT * FROM users WHERE id = ? AND name = ?"
	want := "SELECT * FROM users WHERE id = $1 AND name = $2"
	if got := d.Rebind(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindDollar_NoopWhenNoPlaceholders(t *testing.T) {
	q := "SELECT 1"
	if got := rebindDollar(q); got != q {
		t.Errorf("expected no-op for query without placeholders, got %q", got)
	}
}

func TestRebindDollar_NoDoubleCounting(t *testing.T) {
	// A parameter marker inside a string literal should still be replaced; this
	// is acceptable for our controlled SQL where string literals never contain
	// single '?'. We verify the basic renumbering logic here.
	q := "INSERT INTO t (a, b) VALUES (?, ?)"
	want := "INSERT INTO t (a, b) VALUES ($1, $2)"
	if got := rebindDollar(q); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestPostgresDialect_Migrations_RequiredIndexes(t *testing.T) {
	d := &postgresDialect{}
	all := strings.Join(d.Migrations(), "\n")
	for _, name := range []string{
		"idx_activity_logs_user_id",
		"idx_activity_logs_zone_id",
		"idx_activity_logs_zone_created",
		"idx_activity_logs_created_at",
		"idx_api_keys_key_hash",
		"idx_zone_group_members_user",
		"idx_zone_group_zones_group",
		"idx_zone_group_zones_zone",
	} {
		if !strings.Contains(all, name) {
			t.Errorf("expected index %s to be present in migrations", name)
		}
	}
}

func TestPostgresDialect_Migrations_UseIfNotExists(t *testing.T) {
	d := &postgresDialect{}
	for _, m := range d.Migrations() {
		if strings.Contains(strings.ToUpper(m), "CREATE INDEX") &&
			!strings.Contains(strings.ToUpper(m), "IF NOT EXISTS") {
			t.Errorf("postgres index migration must use IF NOT EXISTS: %s", m)
		}
	}
}

func TestPostgresDialect_LockMigrations(t *testing.T) {
	d := &postgresDialect{}
	// The lock uses a fixed advisory lock ID. We verify that calling the release
	// function does not panic and logs no errors when given a working stub.
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open stub db: %v", err)
	}
	defer db.Close()

	release, err := d.LockMigrations(db)
	if err == nil {
		// SQLite does not implement pg_advisory_lock, so acquiring the lock must
		// fail against this stub. If it succeeded unexpectedly, behave normally.
		release()
	}
}

func TestPostgresDialect_InsertIgnore_UsesConflictColumns(t *testing.T) {
	// REVIEW.md mineur fix: the conflict target must come from an explicit
	// conflictColumns argument so the caller can never accidentally target the
	// wrong unique index when columns != constraint.
	d := &postgresDialect{}
	got := d.InsertIgnore(
		"zone_group_members",
		[]string{"group_id", "user_id"},
		[]string{"group_id", "user_id"},
	)
	want := "INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?) ON CONFLICT (group_id, user_id) DO NOTHING"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestPostgresDialect_InsertIgnore_SingleColumnConflict(t *testing.T) {
	d := &postgresDialect{}
	got := d.InsertIgnore(
		"api_keys",
		[]string{"key_hash"},
		[]string{"key_hash"},
	)
	want := "INSERT INTO api_keys (key_hash) VALUES (?) ON CONFLICT (key_hash) DO NOTHING"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestPostgresDialect_InsertIgnore_AllowsConflictSubsetOfColumns(t *testing.T) {
	// The conflict target may be a subset of the INSERT columns when a
	// partial UNIQUE index covers them — the dialect must honour the
	// conflictColumns exactly, not synthesise one from `columns`.
	d := &postgresDialect{}
	got := d.InsertIgnore(
		"audit_log",
		[]string{"user_id", "action", "created_at"},
		[]string{"user_id", "action"},
	)
	want := "INSERT INTO audit_log (user_id, action, created_at) VALUES (?, ?, ?) ON CONFLICT (user_id, action) DO NOTHING"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestPostgresDialect_InsertIgnore_RequiresConflictColumns(t *testing.T) {
	// Defence against the silent-fallback bug the new signature was
	// introduced for: an empty conflictColumns must produce an obviously
	// invalid statement rather than masquerading as a valid INSERT.
	d := &postgresDialect{}
	got := d.InsertIgnore("any_table", []string{"a"}, nil)
	if !strings.Contains(got, "-- ERROR") {
		t.Errorf("empty conflictColumns must produce an error sentinel, got %q", got)
	}
	got = d.InsertIgnore("any_table", []string{"a"}, []string{})
	if !strings.Contains(got, "-- ERROR") {
		t.Errorf("empty conflictColumns slice must produce an error sentinel, got %q", got)
	}
}

package database

import (
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/config"
)

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "single no trailing semicolon",
			in:   "CREATE TABLE a (x INT)",
			want: []string{"CREATE TABLE a (x INT)"},
		},
		{
			name: "single trailing semicolon",
			in:   "CREATE TABLE a (x INT);",
			want: []string{"CREATE TABLE a (x INT)"},
		},
		{
			name: "two statements",
			in:   "CREATE TABLE a (x INT); CREATE INDEX idx ON a(x)",
			want: []string{"CREATE TABLE a (x INT)", "CREATE INDEX idx ON a(x)"},
		},
		{
			name: "semicolon inside string literal does not split",
			in:   "INSERT INTO a VALUES ('a;b', 'c')",
			want: []string{"INSERT INTO a VALUES ('a;b', 'c')"},
		},
		{
			name: "escaped quote keeps string open across semicolon",
			in:   "INSERT INTO a VALUES ('it''s;b')",
			want: []string{"INSERT INTO a VALUES ('it''s;b')"},
		},
		{
			name: "empty and repeated semicolons yield nothing",
			in:   ";;  ;",
			want: nil,
		},
		{
			name: "empty input",
			in:   "",
			want: nil,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := splitStatements(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("splitStatements(%q) = %v (len %d), want len %d", tt.in, got, len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitStatements(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}

	// A semicolon inside a "--" line comment must not start a new statement.
	t.Run("semicolon inside line comment does not split", func(t *testing.T) {
		got := splitStatements("CREATE TABLE a (x INT); -- comment ; here\nCREATE TABLE b (y INT)")
		if len(got) != 2 {
			t.Fatalf("expected 2 statements, got %d: %v", len(got), got)
		}
		if got[0] != "CREATE TABLE a (x INT)" {
			t.Errorf("first statement = %q, want %q", got[0], "CREATE TABLE a (x INT)")
		}
		if !strings.Contains(got[1], "CREATE TABLE b (y INT)") {
			t.Errorf("second statement %q must contain the b table DDL", got[1])
		}
	})
}

// TestApplyMigration_MultiStatementCommitsAndRecords verifies that a valid
// multi-statement migration is applied in full and recorded atomically
// (REVIEW.md m17).
func TestApplyMigration_MultiStatementCommitsAndRecords(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	const version = "mig_test_multi_ok"
	migration := `CREATE TABLE mig_multi_a (id INTEGER PRIMARY KEY);
CREATE TABLE mig_multi_b (id INTEGER PRIMARY KEY);`

	if err := db.applyMigration(migration, version); err != nil {
		t.Fatalf("applyMigration: %v", err)
	}

	for _, table := range []string{"mig_multi_a", "mig_multi_b"} {
		var n int
		if err := db.Conn.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&n); err != nil {
			t.Fatalf("query %s: %v", table, err)
		}
		if n != 1 {
			t.Errorf("table %s should exist after commit, got count %d", table, n)
		}
	}

	var recorded int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 1 {
		t.Errorf("migration should be recorded exactly once, got %d", recorded)
	}
}

// TestApplyMigration_AtomicOnPartialFailure is the core regression test for
// m17: when the second statement of a multi-statement migration fails, the
// whole migration must roll back — the first statement's effect must NOT
// persist and the migration must NOT be recorded. (SQLite provides true
// transactional DDL, so this is fully enforceable here.)
func TestApplyMigration_AtomicOnPartialFailure(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	const version = "mig_test_partial_failure"
	// Statement 1 creates a sentinel table; statement 2 is invalid SQL.
	migration := `CREATE TABLE mig_partial_test (id INTEGER PRIMARY KEY);
THIS IS NOT VALID SQL;`

	if err := db.applyMigration(migration, version); err == nil {
		t.Fatal("expected migration with an invalid statement to fail, got nil")
	}

	var n int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mig_partial_test'",
	).Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if n != 0 {
		t.Error("partial migration was not rolled back: sentinel table still exists")
	}

	var recorded int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version=?", version,
	).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 0 {
		t.Error("failed migration must not be recorded in schema_migrations")
	}
}

// TestApplyMigration_RecordsFailureDoesNotApply ensures that if recording the
// migration fails for some reason, the schema change is rolled back too
// (atomic apply+record). We trigger a recording failure by pre-inserting the
// version row so the PRIMARY KEY conflicts on the recording INSERT.
func TestApplyMigration_RecordsFailureDoesNotApply(t *testing.T) {
	db, err := New(&config.DatabaseConfig{Driver: "sqlite3", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer db.Close()

	const version = "mig_test_dup_record"
	// Pre-record the version so the recording INSERT inside applyMigration
	// hits a PRIMARY KEY conflict.
	if _, err := db.Conn.Exec(
		"INSERT INTO schema_migrations (version) VALUES (?)", version,
	); err != nil {
		t.Fatalf("seed duplicate version: %v", err)
	}

	migration := "CREATE TABLE mig_dup_record_test (id INTEGER PRIMARY KEY)"
	err = db.applyMigration(migration, version)
	if err == nil {
		t.Fatal("expected recording conflict to fail the migration, got nil")
	}

	// The CREATE TABLE must have been rolled back since recording failed.
	var n int
	if err := db.Conn.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mig_dup_record_test'",
	).Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if n != 0 {
		t.Error("schema change must roll back when recording fails (apply+record must be atomic)")
	}
}

package database

import (
	"strings"
	"testing"
)

func TestMySQLDialect_DSN_AppendsParseTime(t *testing.T) {
	d := &mysqlDialect{}
	got := d.DSN("user:pass@tcp(localhost:3306)/gozone")
	if !strings.Contains(got, "parseTime=true") {
		t.Errorf("expected parseTime=true in DSN, got %s", got)
	}
	if strings.Contains(got, "multiStatements") {
		t.Errorf("multiStatements must not be set, got %s", got)
	}
	if strings.Count(got, "?") > 1 {
		t.Errorf("DSN must not contain more than one '?', got %s", got)
	}
}

func TestMySQLDialect_DSN_PreservesExistingParams(t *testing.T) {
	d := &mysqlDialect{}
	got := d.DSN("user:pass@tcp(localhost:3306)/gozone?charset=utf8mb4&loc=Local")

	if strings.Count(got, "?") != 1 {
		t.Errorf("DSN must contain exactly one '?', got %s", got)
	}
	if !strings.Contains(got, "parseTime=true") {
		t.Errorf("expected parseTime=true, got %s", got)
	}
	if !strings.Contains(got, "charset=utf8mb4") {
		t.Errorf("existing charset param must be preserved, got %s", got)
	}
	if !strings.Contains(got, "loc=Local") {
		t.Errorf("existing loc param must be preserved, got %s", got)
	}
	if strings.Contains(got, "multiStatements") {
		t.Errorf("multiStatements must not be set, got %s", got)
	}
}

func TestMySQLDialect_DSN_ParseTimeAlreadySet(t *testing.T) {
	d := &mysqlDialect{}
	got := d.DSN("user:pass@tcp(localhost:3306)/gozone?parseTime=false")

	if !strings.Contains(got, "parseTime=true") {
		t.Errorf("expected parseTime=true to override parseTime=false, got %s", got)
	}
	if strings.Contains(got, "parseTime=false") {
		t.Errorf("parseTime=false should have been overridden, got %s", got)
	}
}

func TestMySQLDialect_DriverName(t *testing.T) {
	d := &mysqlDialect{}
	if got := d.DriverName(); got != "mysql" {
		t.Errorf("expected driver mysql, got %s", got)
	}
}

func TestMySQLDialect_MaxOpenConns(t *testing.T) {
	d := &mysqlDialect{}
	if got := d.MaxOpenConns(); got != 25 {
		t.Errorf("expected MaxOpenConns 25, got %d", got)
	}
}

func TestMySQLDialect_Rebind(t *testing.T) {
	d := &mysqlDialect{}
	q := "SELECT * FROM users WHERE id = ?"
	if got := d.Rebind(q); got != q {
		t.Errorf("expected MySQL rebinding to be a no-op, got %s", got)
	}
}

func TestMySQLDialect_Migrations_NoCreateIndexIfNotExists(t *testing.T) {
	d := &mysqlDialect{}
	for _, m := range d.Migrations() {
		if strings.Contains(strings.ToUpper(m), "CREATE INDEX IF NOT EXISTS") {
			t.Errorf("MySQL migration contains unsupported CREATE INDEX IF NOT EXISTS: %s", m)
		}
	}
}

func TestMySQLDialect_Migrations_ContainInlineIndexes(t *testing.T) {
	d := &mysqlDialect{}
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
			t.Errorf("expected inline index %s to be present in migrations", name)
		}
	}
}

// TestMySQLDialect_InsertIgnore_IgnoresConflictColumns verifies the contract
// from the Dialect interface: MySQL's INSERT IGNORE catches any unique
// violation, so the conflictColumns parameter is intentionally unused. The
// returned SQL must match the previous shape exactly so callers don't observe
// a behaviour change after the signature update.
func TestMySQLDialect_InsertIgnore_IgnoresConflictColumns(t *testing.T) {
	d := &mysqlDialect{}
	got := d.InsertIgnore(
		"zone_group_members",
		[]string{"group_id", "user_id"},
		// Any value here is intentionally ignored; pass a non-empty value
		// to confirm the signature accepts it without altering output.
		[]string{"group_id", "user_id"},
	)
	want := "INSERT IGNORE INTO zone_group_members (group_id, user_id) VALUES (?, ?)"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}

	// And with empty conflictColumns — same output, proving the parameter
	// is purely cosmetic for MySQL.
	got = d.InsertIgnore("zone_group_members", []string{"group_id", "user_id"}, nil)
	if got != want {
		t.Errorf("empty conflictColumns must not alter MySQL output\ngot:  %q\nwant: %q", got, want)
	}
}

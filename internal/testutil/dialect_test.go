package testutil

import (
	"strings"
	"testing"
)

func TestMySQLDSNWithDB(t *testing.T) {
	got, err := mysqlDSNWithDB("root:root@tcp(127.0.0.1:3306)/gozone_test", "gozone_test_ab12")
	if err != nil {
		t.Fatalf("mysqlDSNWithDB: %v", err)
	}
	if !strings.Contains(got, "/gozone_test_ab12") {
		t.Errorf("expected database gozone_test_ab12 in DSN, got %s", got)
	}
	// The rewrite must preserve the rest of the DSN, not rebuild a lossy one.
	if !strings.Contains(got, "tcp(127.0.0.1:3306)") || !strings.Contains(got, "root:root") {
		t.Errorf("rewrite dropped host or credentials: %s", got)
	}
}

func TestMySQLDSNWithDB_Invalid(t *testing.T) {
	if _, err := mysqlDSNWithDB("not a dsn", "db"); err == nil {
		t.Error("expected error for invalid MySQL DSN")
	}
}

func TestMySQLDSNWithDB_PreservesParams(t *testing.T) {
	got, err := mysqlDSNWithDB("u:p@tcp(h:3306)/x?charset=utf8mb4", "y")
	if err != nil {
		t.Fatalf("mysqlDSNWithDB: %v", err)
	}
	if !strings.Contains(got, "charset=utf8mb4") {
		t.Errorf("expected charset param preserved, got %s", got)
	}
}

func TestPostgresDSNWithDB(t *testing.T) {
	got, err := postgresDSNWithDB("postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable", "gozone_test_ab12")
	if err != nil {
		t.Fatalf("postgresDSNWithDB: %v", err)
	}
	if !strings.Contains(got, "/gozone_test_ab12?") {
		t.Errorf("expected path /gozone_test_ab12 in DSN, got %s", got)
	}
	if !strings.Contains(got, "sslmode=disable") {
		t.Errorf("expected query preserved, got %s", got)
	}
	if !strings.Contains(got, "postgres:postgres@127.0.0.1:5432") {
		t.Errorf("rewrite dropped credentials or host: %s", got)
	}
}

func TestPostgresDSNWithDB_RejectsKeyValueForm(t *testing.T) {
	if _, err := postgresDSNWithDB("host=127.0.0.1 user=postgres dbname=postgres", "db"); err == nil {
		t.Error("expected error for key=value DSN (URL form required)")
	}
}

func TestRandomDBName(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		name, err := randomDBName("gozone_test_")
		if err != nil {
			t.Fatalf("randomDBName: %v", err)
		}
		if seen[name] {
			t.Fatalf("duplicate database name %s", name)
		}
		seen[name] = true
		if len(name) > 63 {
			t.Errorf("name %s exceeds the 63-byte PostgreSQL identifier limit", name)
		}
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
				t.Errorf("name %s contains character %q outside the safe identifier set", name, r)
			}
		}
	}
}

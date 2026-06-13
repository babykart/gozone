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

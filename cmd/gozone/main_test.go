package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseTemplates(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates failed: %v", err)
	}
	if tmpl == nil {
		t.Fatal("expected non-nil template")
	}
}

func TestRun_InvalidDatabaseDriver(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := `
database:
  driver: unsupported
  dsn: ""
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"-config", cfgPath})
	if err == nil {
		t.Fatal("expected error for unsupported database driver")
	}
	if !strings.Contains(err.Error(), "unsupported database driver") {
		t.Errorf("expected unsupported database driver error, got: %v", err)
	}
}

func TestRun_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("not: [ valid yaml"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"-config", cfgPath})
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestRun_InvalidFlag(t *testing.T) {
	err := run([]string{"-unknown-flag"})
	if err == nil {
		t.Fatal("expected error for invalid flag")
	}
}

func TestStartPeriodicJob(t *testing.T) {
	var count int32
	job := func(ctx context.Context) error {
		atomic.AddInt32(&count, 1)
		return nil
	}

	stop := startPeriodicJob(context.Background(), "test job", 50*time.Millisecond, 100*time.Millisecond, job)
	defer stop()

	// The job should run once immediately.
	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&count) < 1 {
		t.Fatal("expected job to run immediately")
	}

	// It should then run again on the next tick.
	time.Sleep(80 * time.Millisecond)
	if atomic.LoadInt32(&count) < 2 {
		t.Fatalf("expected at least one periodic run, got %d", atomic.LoadInt32(&count))
	}
}

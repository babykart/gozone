package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// serverSubcommand returns the `gozone server` subcommand of a fresh root
// command, with args parsed the way Execute would (inherited persistent
// --config flag included).
func serverSubcommand(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	root := newRootCmd()
	sub, _, err := root.Find([]string{"server"})
	if err != nil {
		t.Fatalf("find server subcommand: %v", err)
	}
	if err := sub.ParseFlags(args); err != nil {
		t.Fatalf("parse flags %v: %v", args, err)
	}
	return sub
}

// TestLoadConfig_ExplicitMissingPathFails is the mistyped-path regression:
// a --config value the operator typed must exist — a typo must not boot a
// defaults-only instance with the built-in default admin.
func TestLoadConfig_ExplicitMissingPathFails(t *testing.T) {
	cmd := serverSubcommand(t, "--config", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	_, err := loadConfig(cmd)
	if err == nil || !strings.Contains(err.Error(), "check the --config path") {
		t.Fatalf("an explicit missing --config path must fail with an actionable error, got %v", err)
	}
}

// TestLoadConfig_ExplicitDirectoryFails: pointing --config at a directory
// is a configuration mistake, not a development default.
func TestLoadConfig_ExplicitDirectoryFails(t *testing.T) {
	cmd := serverSubcommand(t, "--config", t.TempDir())
	if _, err := loadConfig(cmd); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("a directory as --config must fail, got %v", err)
	}
}

// TestLoadConfig_DefaultMissingFileIsDevDefault: without an explicit
// --config flag, a missing config.yaml keeps the documented development
// behaviour (all defaults + environment overrides).
func TestLoadConfig_DefaultMissingFileIsDevDefault(t *testing.T) {
	cmd := serverSubcommand(t) // flag default "config.yaml", not changed
	cfg, err := loadConfig(cmd)
	if err != nil {
		t.Fatalf("the unchanged flag default must tolerate a missing file, got %v", err)
	}
	if cfg == nil || cfg.Server.Port == 0 {
		t.Fatalf("expected the default config, got %+v", cfg)
	}
}

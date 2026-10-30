package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/babykart/gozone/internal/config"
)

// loadConfig loads the YAML configuration, enforcing the explicit-path
// contract: a --config value the operator typed must exist — a typo must
// not boot a defaults-only instance (0.0.0.0 listener, built-in default
// admin password). The flag's DEFAULT ("config.yaml") is exempt: when the
// operator did not pass the flag, a missing file is the documented
// development default (all defaults + GOZONE_* environment overrides), not
// a mistyped path.
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	path, err := cmd.Flags().GetString("config")
	if err != nil {
		return nil, fmt.Errorf("read --config flag: %w", err)
	}
	if cmd.Flags().Changed("config") {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("config file %q: %w (check the --config path)", path, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("config file %q is a directory, not a file", path)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load configuration: %w", err)
	}
	return cfg, nil
}

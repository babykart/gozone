package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/babykart/gozone/internal/config"
)

// newServerCmd builds the `gozone server` command, which starts the HTTP
// server. It is the primary process run by the container (see Dockerfile
// CMD).
func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "server",
		Short:         "Start the HTTP server",
		Long:          "Starts the GoZone HTTP server (the PowerDNS admin interface). This is the primary process run by the container.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return fmt.Errorf("read --config flag: %w", err)
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("load configuration: %w", err)
			}
			return runServer(cfg)
		},
	}
	return cmd
}

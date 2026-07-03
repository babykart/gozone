// root.go defines the root Cobra command for the gozone CLI. The root is a
// namespace: running `gozone` with no subcommand prints help. Use
// `gozone server` to start the HTTP server and `gozone unlock` for the
// emergency user-unlock operation.
package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd is the command executed by the binary. It has no RunE of its
// own: bare `gozone` prints help (cobra default), and the actual work is
// done by its subcommands (server, unlock, ...).
var rootCmd = newRootCmd()

// newRootCmd builds the root command and registers its subcommands. Each
// invocation (the real binary via Execute, and tests) gets a fresh command
// tree so flag state is never shared across calls.
func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gozone",
		Short: "PowerDNS Admin Interface",
		Long:  "GoZone — PowerDNS Admin Interface. Start the HTTP server with `gozone server`, or run `gozone <subcommand>` for administrative tasks (e.g. `gozone unlock`).",
		// Silence cobra's own error/usage printing: errors are surfaced by
		// main() via logger.Fatal so we keep a single, structured report
		// path and avoid stderr noise during tests.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	// Persistent so subcommands (server, unlock, ...) inherit --config too.
	cmd.PersistentFlags().StringP("config", "c", "config.yaml", "path to YAML configuration file")

	cmd.AddCommand(newServerCmd())
	cmd.AddCommand(newUnlockCmd())
	return cmd
}

// Execute runs the root command and returns the first error encountered.
func Execute() error {
	return rootCmd.Execute()
}

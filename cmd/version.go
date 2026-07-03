package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	versionpkg "github.com/babykart/gozone/internal/version"
)

// Build-time identifiers, overridable via -ldflags:
//
//	go build -ldflags \
//	  "-X github.com/babykart/gozone/cmd.version=$(git describe --tags --always) \
//	   -X github.com/babykart/gozone/cmd.commit=$(git rev-parse --short HEAD) \
//	   -X github.com/babykart/gozone/cmd.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
//
// When left at their zero values, versionInfo() enriches them from the VCS
// metadata Go embeds in the binary (runtime/debug.ReadBuildInfo), so
// `go run . version` and a plain `go build .` still report a useful commit.
var (
	version   = "dev"
	commit    = ""
	buildDate = ""
)

// newVersionCmd builds the `gozone version` command, which prints the full
// version banner (version, commit, build date, Go version, platform).
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "version",
		Short:         "Print version information",
		Long:          "Print the gozone version, VCS commit, build date, Go toolchain version and platform.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprint(cmd.OutOrStdout(), versionInfo())
			return nil
		},
	}
}

// versionInfo returns the human-readable version banner. ldflags-injected
// values take precedence; otherwise VCS metadata from debug.ReadBuildInfo is
// used so that un-tagged builds still report a meaningful commit and time.
// Resolution is shared with the UI via internal/version.Resolve.
func versionInfo() string {
	v := versionpkg.Resolve(version, commit, buildDate)

	var b strings.Builder
	fmt.Fprintf(&b, "gozone %s", v.Version)
	if v.Commit != "" {
		fmt.Fprintf(&b, " (%s)", v.Commit)
	}
	b.WriteByte('\n')
	if v.BuildDate != "" {
		fmt.Fprintf(&b, "built: %s\n", v.BuildDate)
	}
	fmt.Fprintf(&b, "go:   %s\n", v.GoVersion)
	fmt.Fprintf(&b, "arch: %s\n", v.Platform)
	return b.String()
}

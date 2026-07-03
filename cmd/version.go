package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
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
func versionInfo() string {
	v, c, d := version, commit, buildDate
	commitInjected := c != "" // ldflags provided the commit
	dirty := false
	if bi, ok := debug.ReadBuildInfo(); ok {
		if c == "" {
			c = buildSetting(bi.Settings, "vcs.revision")
		}
		if d == "" {
			d = buildSetting(bi.Settings, "vcs.time")
		}
		dirty = buildSetting(bi.Settings, "vcs.modified") == "true"
	}
	if v == "" {
		v = "dev"
	}
	c = shortSHA(c)
	// Annotate -dirty on the commit only when it was VCS-derived. When ldflags
	// injected the commit, the version string (typically from
	// `git describe --dirty`) already conveys the dirty status.
	if dirty && !commitInjected {
		c += "-dirty"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "gozone %s", v)
	if c != "" {
		fmt.Fprintf(&b, " (%s)", c)
	}
	b.WriteByte('\n')
	if d != "" {
		fmt.Fprintf(&b, "built: %s\n", d)
	}
	fmt.Fprintf(&b, "go:   %s\n", runtime.Version())
	fmt.Fprintf(&b, "arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return b.String()
}

// buildSetting returns the value for key from a debug.BuildInfo.Settings
// slice, or "" if absent.
func buildSetting(s []debug.BuildSetting, key string) string {
	for _, kv := range s {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

// shortSHA shortens a git SHA to 12 characters (git's default short form).
func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

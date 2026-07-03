// Package version exposes resolved build/version information for gozone.
//
// The ldflags-injected identifiers (see cmd.version, cmd.commit, cmd.buildDate
// and the Makefile/justfile -X targets) are the source of truth; when left at
// their zero values this package enriches them from the VCS metadata Go embeds
// in the binary (runtime/debug.ReadBuildInfo), so a plain `go build`/`go run`
// still reports a meaningful commit and time. Both cmd (for the `gozone
// version` banner) and internal/handlers (to surface the version in the UI)
// consume Resolve so the resolution logic lives in exactly one place.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Info describes a resolved build.
type Info struct {
	Version   string // human version, defaults to "dev"
	Commit    string // short SHA, annotated "-dirty" when VCS-derived & modified
	BuildDate string // VCS time or ldflags-injected build date
	GoVersion string // toolchain reported by runtime.Version()
	Platform  string // GOOS/GOARCH
}

// Resolve builds an Info from the ldflags-injected identifiers, enriching empty
// fields from debug.ReadBuildInfo. A blank version becomes "dev". The commit is
// shortened to git's default 12-char form; "-dirty" is appended only when the
// commit was VCS-derived (not ldflags-injected) and the tree was modified —
// when ldflags provided the commit, the version string (typically from
// `git describe --dirty`) already conveys the dirty status.
func Resolve(version, commit, buildDate string) Info {
	commitInjected := commit != ""
	dirty := false
	if bi, ok := debug.ReadBuildInfo(); ok {
		if commit == "" {
			commit = buildSetting(bi.Settings, "vcs.revision")
		}
		if buildDate == "" {
			buildDate = buildSetting(bi.Settings, "vcs.time")
		}
		dirty = buildSetting(bi.Settings, "vcs.modified") == "true"
	}
	if version == "" {
		version = "dev"
	}
	commit = shortSHA(commit)
	if dirty && !commitInjected {
		commit += "-dirty"
	}
	return Info{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// OneLine returns a compact "gozone <version> (<commit>)" label suitable for a
// dashboard badge. The commit part is omitted when unknown.
func (i Info) OneLine() string {
	if i.Commit == "" {
		return "gozone " + i.Version
	}
	return fmt.Sprintf("gozone %s (%s)", i.Version, i.Commit)
}

// buildSetting returns the value for key from a debug.BuildInfo.Settings slice,
// or "" if absent.
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

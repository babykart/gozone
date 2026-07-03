package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolve_DefaultsToDev(t *testing.T) {
	info := Resolve("", "", "")
	if info.Version != "dev" {
		t.Errorf("expected version 'dev', got %q", info.Version)
	}
	if info.GoVersion == "" {
		t.Error("expected GoVersion to be populated from runtime")
	}
	if info.Platform == "" || !strings.Contains(info.Platform, "/") {
		t.Errorf("expected Platform GOOS/GOARCH, got %q", info.Platform)
	}
}

func TestResolve_LdflagsTakePrecedence(t *testing.T) {
	info := Resolve("v1.2.3", "abcdef1234567890", "2024-01-02T03:04:05Z")
	if info.Version != "v1.2.3" {
		t.Errorf("expected ldflags version, got %q", info.Version)
	}
	// ldflags-injected commit is shortened to 12 chars but never -dirty-annotated.
	if info.Commit != "abcdef123456" {
		t.Errorf("expected short commit 'abcdef123456', got %q", info.Commit)
	}
	if info.BuildDate != "2024-01-02T03:04:05Z" {
		t.Errorf("expected ldflags build date, got %q", info.BuildDate)
	}
}

func TestOneLine(t *testing.T) {
	noCommit := Info{Version: "v1.0"}
	if got := noCommit.OneLine(); got != "gozone v1.0" {
		t.Errorf("expected 'gozone v1.0', got %q", got)
	}
	withCommit := Info{Version: "v1.0", Commit: "abc12345"}
	if got := withCommit.OneLine(); got != "gozone v1.0 (abc12345)" {
		t.Errorf("expected 'gozone v1.0 (abc12345)', got %q", got)
	}
}

func TestShortSHA(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"abc123", "abc123"},
		{"0123456789abcdef0123456789abcdef01234567", "0123456789ab"},
	}
	for _, c := range cases {
		if got := shortSHA(c.in); got != c.want {
			t.Errorf("shortSHA(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildSetting(t *testing.T) {
	settings := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abc"},
		{Key: "vcs.modified", Value: "true"},
	}
	if got := buildSetting(settings, "vcs.revision"); got != "abc" {
		t.Errorf("buildSetting vcs.revision = %q, want %q", got, "abc")
	}
	if got := buildSetting(settings, "vcs.time"); got != "" {
		t.Errorf("buildSetting missing key should return \"\", got %q", got)
	}
}

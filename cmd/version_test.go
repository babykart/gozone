package cmd

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

// executeVersion runs `gozone <args>` against a fresh root command, capturing
// stdout. Used to exercise both the `version` subcommand and the `--version`
// flag.
func executeVersion(args ...string) (string, error) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestVersionCmd_PrintsBanner(t *testing.T) {
	got, err := executeVersion("version")
	if err != nil {
		t.Fatalf("execute version: %v", err)
	}
	for _, want := range []string{"gozone", "go:", "arch:"} {
		if !strings.Contains(got, want) {
			t.Errorf("version output missing %q, got:\n%s", want, got)
		}
	}
}

func TestVersionCmd_NoArgs(t *testing.T) {
	// `gozone version extra` must error (cobra.NoArgs).
	if _, err := executeVersion("version", "extra"); err == nil {
		t.Fatal("expected error when passing args to `gozone version`")
	}
}

func TestVersionFlag_PrintsVersion(t *testing.T) {
	got, err := executeVersion("--version")
	if err != nil {
		t.Fatalf("execute --version: %v", err)
	}
	// Cobra's default template: "<name> version <version>\n".
	if !strings.Contains(got, "gozone") || !strings.Contains(got, "version") {
		t.Errorf("--version output unexpected, got: %q", got)
	}
}

func TestVersionInfo_IncludesRuntime(t *testing.T) {
	got := versionInfo()
	for _, want := range []string{"gozone", "go:", "arch:"} {
		if !strings.Contains(got, want) {
			t.Errorf("versionInfo missing %q: %q", want, got)
		}
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

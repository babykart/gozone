package logger

import (
	"io"
	"os"
	"strings"
	"testing"
)

// capture redirects os.Stderr to a pipe, captures the output written by the
// default logger, and restores os.Stderr at the end of the test.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = pw
	defer func() {
		os.Stderr = oldStderr
		pw.Close()
	}()

	fn()

	if err := pw.Close(); err != nil {
		t.Fatalf("close pipe write end: %v", err)
	}
	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

func TestInit(t *testing.T) {
	cases := []struct {
		level       string
		hasDebug    bool
		hasInfo     bool
		hasWarn     bool
		hasError    bool
		description string
	}{
		{"debug", true, true, true, true, "debug level shows all severities"},
		{"info", false, true, true, true, "info level hides debug messages"},
		{"warn", false, false, true, true, "warn level hides debug and info"},
		{"error", false, false, false, true, "error level shows only errors"},
		{"unknown", false, true, true, true, "unknown level defaults to info"},
		{"", false, true, true, true, "empty level defaults to info"},
	}

	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			out := capture(t, func() {
				Init(tc.level)
				Debug("debug-line")
				Info("info-line")
				Warn("warn-line")
				Error("error-line")
			})

			t.Logf("captured output for level %q:\n%s", tc.level, out)

			if got := strings.Contains(out, "debug-line"); got != tc.hasDebug {
				t.Errorf("debug presence = %v, want %v", got, tc.hasDebug)
			}
			if got := strings.Contains(out, "info-line"); got != tc.hasInfo {
				t.Errorf("info presence = %v, want %v", got, tc.hasInfo)
			}
			if got := strings.Contains(out, "warn-line"); got != tc.hasWarn {
				t.Errorf("warn presence = %v, want %v", got, tc.hasWarn)
			}
			if got := strings.Contains(out, "error-line"); got != tc.hasError {
				t.Errorf("error presence = %v, want %v", got, tc.hasError)
			}
		})
	}
}

func TestLogLevelsWithAttributes(t *testing.T) {
	out := capture(t, func() {
		Init("info")
		Info("user action", "user_id", 42, "action", "login")
		Warn("rate limit", "ip", "10.0.0.1")
		Error("failure", "err", "boom")
	})

	for _, want := range []string{
		"user action",
		"user_id=42",
		"action=login",
		"rate limit",
		"ip=10.0.0.1",
		"failure",
		"err=boom",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestFatal(t *testing.T) {
	oldExit := osExit
	var exitCode int
	osExit = func(code int) {
		exitCode = code
	}
	defer func() {
		osExit = oldExit
		Init("info") // reset default logger to avoid leaking test state
	}()

	out := capture(t, func() {
		Init("error")
		Fatal("catastrophic failure", "component", "database")
	})

	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(out, "catastrophic failure") {
		t.Errorf("output missing fatal message:\n%s", out)
	}
	if !strings.Contains(out, "component=database") {
		t.Errorf("output missing fatal attributes:\n%s", out)
	}
}

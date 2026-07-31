package config

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected 8080, got %d", cfg.Server.Port)
	}
	if cfg.Server.AppName != "GoZone" {
		t.Errorf("expected GoZone, got %s", cfg.Server.AppName)
	}
	if cfg.Database.Driver != "sqlite3" {
		t.Errorf("expected sqlite3, got %s", cfg.Database.Driver)
	}
	if cfg.Auth.BcryptCost != 12 {
		t.Errorf("expected 12, got %d", cfg.Auth.BcryptCost)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected info, got %s", cfg.Logging.Level)
	}
	if cfg.Activity.RetentionDays != 90 {
		t.Errorf("expected activity retention days 90, got %d", cfg.Activity.RetentionDays)
	}
	if cfg.Activity.BatchSize != 1000 {
		t.Errorf("expected activity batch size 1000, got %d", cfg.Activity.BatchSize)
	}
	if cfg.Admin.Username != "admin" {
		t.Errorf("expected admin, got %s", cfg.Admin.Username)
	}
	if cfg.Admin.Password != "admin" {
		t.Errorf("expected admin, got %s", cfg.Admin.Password)
	}
	if cfg.Admin.Email != "admin@gozone.local" {
		t.Errorf("expected admin@gozone.local, got %s", cfg.Admin.Email)
	}
	if cfg.Admin.FirstName != "Admin" {
		t.Errorf("expected Admin, got %s", cfg.Admin.FirstName)
	}
	if cfg.Admin.LastName != "User" {
		t.Errorf("expected User, got %s", cfg.Admin.LastName)
	}
	if cfg.Server.ShutdownTimeoutSeconds != 30 {
		t.Errorf("expected shutdown_timeout_seconds 30, got %d", cfg.Server.ShutdownTimeoutSeconds)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
server:
  host: "127.0.0.1"
  port: 9090
  app_name: "MyDNS"
database:
  dsn: "/tmp/test.db"
auth:
  bcrypt_cost: 10
admin:
  username: "root"
  email: "root@example.com"
  first_name: "Root"
  last_name: "Admin"
activity:
  retention_days: 30
  batch_size: 500
`
	tmpFile, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("expected 9090, got %d", cfg.Server.Port)
	}
	if cfg.Server.AppName != "MyDNS" {
		t.Errorf("expected MyDNS, got %s", cfg.Server.AppName)
	}
	if cfg.Database.DSN != "/tmp/test.db" {
		t.Errorf("expected /tmp/test.db, got %s", cfg.Database.DSN)
	}
	if cfg.Auth.BcryptCost != 10 {
		t.Errorf("expected 10, got %d", cfg.Auth.BcryptCost)
	}
	if cfg.Admin.Username != "root" {
		t.Errorf("expected root, got %s", cfg.Admin.Username)
	}
	if cfg.Admin.Email != "root@example.com" {
		t.Errorf("expected root@example.com, got %s", cfg.Admin.Email)
	}
	if cfg.Admin.FirstName != "Root" {
		t.Errorf("expected Root, got %s", cfg.Admin.FirstName)
	}
	if cfg.Admin.LastName != "Admin" {
		t.Errorf("expected Admin, got %s", cfg.Admin.LastName)
	}
	if cfg.Activity.RetentionDays != 30 {
		t.Errorf("expected activity retention days 30, got %d", cfg.Activity.RetentionDays)
	}
	if cfg.Activity.BatchSize != 500 {
		t.Errorf("expected activity batch size 500, got %d", cfg.Activity.BatchSize)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	const secretKey = "mysecret-mysecret-mysecret-mysecret" // >= minSecretKeyLength
	t.Setenv("GOZONE_SERVER_HOST", "192.168.1.1")
	t.Setenv("GOZONE_SERVER_PORT", "3000")
	t.Setenv("GOZONE_APP_NAME", "CustomApp")
	t.Setenv("GOZONE_SECRET_KEY", secretKey)
	t.Setenv("GOZONE_DB_DSN", "/custom/path.db")
	t.Setenv("GOZONE_PDNS_API_URL", "http://pdns:8081")
	t.Setenv("GOZONE_PDNS_API_KEY", "testkey")
	t.Setenv("GOZONE_PDNS_SERVER_ID", "test-server")
	t.Setenv("GOZONE_SESSION_DURATION", "48")
	t.Setenv("GOZONE_ADMIN_USERNAME", "root")
	t.Setenv("GOZONE_ADMIN_PASSWORD", "secret")
	t.Setenv("GOZONE_ADMIN_EMAIL", "root@example.com")
	t.Setenv("GOZONE_ADMIN_FIRST_NAME", "Root")
	t.Setenv("GOZONE_ADMIN_LAST_NAME", "Admin")
	t.Setenv("GOZONE_ACTIVITY_RETENTION_DAYS", "60")
	t.Setenv("GOZONE_ACTIVITY_BATCH_SIZE", "2500")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Server.Host != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 3000 {
		t.Errorf("expected 3000, got %d", cfg.Server.Port)
	}
	if cfg.Server.SecretKey != secretKey {
		t.Errorf("expected %s, got %s", secretKey, cfg.Server.SecretKey)
	}
	if cfg.Server.AppName != "CustomApp" {
		t.Errorf("expected CustomApp, got %s", cfg.Server.AppName)
	}
	if cfg.Database.DSN != "/custom/path.db" {
		t.Errorf("expected /custom/path.db, got %s", cfg.Database.DSN)
	}
	if cfg.PowerDNS.APIURL != "http://pdns:8081" {
		t.Errorf("expected http://pdns:8081, got %s", cfg.PowerDNS.APIURL)
	}
	if cfg.PowerDNS.APIKey != "testkey" {
		t.Errorf("expected testkey, got %s", cfg.PowerDNS.APIKey)
	}
	if cfg.PowerDNS.ServerID != "test-server" {
		t.Errorf("expected test-server, got %s", cfg.PowerDNS.ServerID)
	}
	if cfg.Auth.SessionDurationHours != 48 {
		t.Errorf("expected 48, got %d", cfg.Auth.SessionDurationHours)
	}
	if cfg.Admin.Username != "root" {
		t.Errorf("expected root, got %s", cfg.Admin.Username)
	}
	if cfg.Admin.Password != "secret" {
		t.Errorf("expected secret, got %s", cfg.Admin.Password)
	}
	if cfg.Admin.Email != "root@example.com" {
		t.Errorf("expected root@example.com, got %s", cfg.Admin.Email)
	}
	if cfg.Admin.FirstName != "Root" {
		t.Errorf("expected Root, got %s", cfg.Admin.FirstName)
	}
	if cfg.Admin.LastName != "Admin" {
		t.Errorf("expected Admin, got %s", cfg.Admin.LastName)
	}
	if cfg.Activity.RetentionDays != 60 {
		t.Errorf("expected activity retention days 60, got %d", cfg.Activity.RetentionDays)
	}
	if cfg.Activity.BatchSize != 2500 {
		t.Errorf("expected activity batch size 2500, got %d", cfg.Activity.BatchSize)
	}
}

func TestLoad_AutoGenerateSecretKey(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Server.SecretKey == defaultSecretKey {
		t.Errorf("secret key should not be the default placeholder %q", defaultSecretKey)
	}
	if len(cfg.Server.SecretKey) != 64 {
		t.Errorf("expected 64-char hex key (32 bytes), got %d chars", len(cfg.Server.SecretKey))
	}

	decoded, err := hex.DecodeString(cfg.Server.SecretKey)
	if err != nil {
		t.Fatalf("generated key is not valid hex: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(decoded))
	}
}

func TestLoad_AutoGenerateFromConfigPlaceholder(t *testing.T) {
	// The sample config.yaml ships a placeholder secret key. Loading a config
	// that still carries any well-known placeholder must trigger generation,
	// never run with the publicly known value.
	for _, placeholder := range []string{
		defaultSecretKey,
		"change-me-to-a-random-secret-key",           // value shipped in config.yaml
		"change-me-to-a-random-secret-in-production", // value shipped in docker-compose.yml
		"Change-Me-To-A-Random-Secret",               // mixed case
		"CHANGEME",                                   // uppercase concatenated prefix
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		content := "server:\n  secret_key: \"" + placeholder + "\"\n"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if cfg.Server.SecretKey == placeholder {
			t.Errorf("placeholder %q must be replaced by a generated key", placeholder)
		}
		if len(cfg.Server.SecretKey) != 64 {
			t.Errorf("expected 64-char generated key, got %d chars", len(cfg.Server.SecretKey))
		}
	}
}

func TestLoad_AutoGenerateKeyDeterministic(t *testing.T) {
	cfg1, _ := Load("")
	cfg2, _ := Load("")

	if cfg1.Server.SecretKey == cfg2.Server.SecretKey {
		t.Error("two generated keys should be different (crypto/rand)")
	}
}

// TestIsPlaceholderSecret verifies that placeholder detection is exhaustive
// (prefix-based) and case-insensitive, so that every known/likely weak
// spelling triggers auto-generation — including the value shipped in
// docker-compose.yml which the previous exact-match map missed.
func TestIsPlaceholderSecret(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"empty", "", true},
		{"default placeholder", defaultSecretKey, true},
		{"config.yaml placeholder", "change-me-to-a-random-secret-key", true},
		{"docker-compose placeholder", "change-me-to-a-random-secret-in-production", true},
		{"changeme concatenated", "changeme", true},
		{"changeme with suffix", "changeme-please", true},
		{"mixed case prefix", "Change-Me-Something", true},
		{"uppercase prefix", "CHANGE-ME-TO-A-RANDOM-SECRET", true},
		{"real 32-char hex key", "0123456789abcdef0123456789abcdef", false},
		{"non-placeholder short", "mysecret", false},
		{"unrelated long value", "a-different-secret-value-of-some-length", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPlaceholderSecret(tt.key); got != tt.want {
				t.Errorf("isPlaceholderSecret(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

// TestLoad_RejectsShortSecretKey is the minimum-length guard (m12): a
// non-placeholder secret below minSecretKeyLength must fail config load
// fail-fast rather than being used to derive low-entropy signing keys.
func TestLoad_RejectsShortSecretKey(t *testing.T) {
	t.Setenv("GOZONE_SECRET_KEY", "tooshort")
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for short secret key, got nil")
	}
	if !strings.Contains(err.Error(), "secret_key") {
		t.Errorf("expected secret_key error, got %v", err)
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' in error, got %v", err)
	}
}

// TestLoad_AcceptsMinLengthSecretKey verifies that a secret of exactly
// minSecretKeyLength characters is accepted (boundary check for the guard).
func TestLoad_AcceptsMinLengthSecretKey(t *testing.T) {
	key := strings.Repeat("a", minSecretKeyLength) // exactly 32 chars
	t.Setenv("GOZONE_SECRET_KEY", key)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("expected valid config for %d-char secret, got error: %v", minSecretKeyLength, err)
	}
	if cfg.Server.SecretKey != key {
		t.Errorf("expected the configured key to be preserved, got %s", cfg.Server.SecretKey)
	}
}

func TestLoad_SecureCookiesDefaultFalse(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.SecureCookies {
		t.Error("secure_cookies should default to false")
	}
}

func TestLoad_SecureCookiesEnvOverride(t *testing.T) {
	valid := []struct {
		env  string
		want bool
	}{
		{"true", true},
		{"TRUE", true}, // case-insensitive
		{"1", true},
		{"on", true},
		{"yes", true},
		{"false", false},
		{"0", false},
		{"off", false},
		{"no", false},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.env, func(t *testing.T) {
			t.Setenv("GOZONE_SECURE_COOKIES", tt.env)
			cfg, err := Load("")
			if err != nil {
				t.Fatalf("GOZONE_SECURE_COOKIES=%q: Load failed: %v", tt.env, err)
			}
			if cfg.Server.SecureCookies != tt.want {
				t.Errorf("GOZONE_SECURE_COOKIES=%q: got %v, want %v", tt.env, cfg.Server.SecureCookies, tt.want)
			}
		})
	}

	// Unrecognized non-empty boolean spellings must fail config load (m13):
	// the override intent is surfaced instead of silently keeping the default.
	for _, bad := range []string{"garbage", "maybe", "2"} {
		t.Run("invalid/"+bad, func(t *testing.T) {
			t.Setenv("GOZONE_SECURE_COOKIES", bad)
			_, err := Load("")
			if err == nil {
				t.Fatalf("GOZONE_SECURE_COOKIES=%q: expected error, got nil", bad)
			}
			if !strings.Contains(err.Error(), "GOZONE_SECURE_COOKIES") {
				t.Errorf("GOZONE_SECURE_COOKIES=%q: expected error to mention the var, got %v", bad, err)
			}
		})
	}
}

func TestLoad_ShutdownTimeoutEnvOverride(t *testing.T) {
	t.Setenv("GOZONE_SHUTDOWN_TIMEOUT", "60")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Server.ShutdownTimeoutSeconds != 60 {
		t.Errorf("expected 60, got %d", cfg.Server.ShutdownTimeoutSeconds)
	}
}

func TestEnvInt(t *testing.T) {
	tests := []struct {
		name    string
		v       string
		want    int
		wantErr bool
	}{
		{"decimal", "8080", 8080, false},
		{"zero", "0", 0, false},
		{"negative", "-1", -1, false},
		{"non-numeric", "abc", 0, true},
		{"float", "1.5", 0, true},
		{"empty-ish", " ", 0, true},
		{"with-spaces", " 42 ", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := envInt("GOZONE_TEST", tt.v)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("envInt(%q): expected error, got %d", tt.v, got)
				}
				if !strings.Contains(err.Error(), "GOZONE_TEST") {
					t.Errorf("envInt(%q): error should mention the var name, got %v", tt.v, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("envInt(%q): unexpected error: %v", tt.v, err)
			}
			if got != tt.want {
				t.Errorf("envInt(%q) = %d, want %d", tt.v, got, tt.want)
			}
		})
	}
}

func TestEnvBool(t *testing.T) {
	valid := []struct {
		v    string
		want bool
	}{
		{"true", true}, {"TRUE", true}, {"Yes", true}, {"1", true}, {"on", true},
		{"false", false}, {"0", false}, {"OFF", false}, {"no", false},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.v, func(t *testing.T) {
			got, err := envBool("GOZONE_TEST", tt.v)
			if err != nil {
				t.Fatalf("envBool(%q): unexpected error: %v", tt.v, err)
			}
			if got != tt.want {
				t.Errorf("envBool(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
	for _, bad := range []string{"garbage", "maybe", "2", " "} {
		t.Run("invalid/"+bad, func(t *testing.T) {
			_, err := envBool("GOZONE_TEST", bad)
			if err == nil {
				t.Fatalf("envBool(%q): expected error, got nil", bad)
			}
			if !strings.Contains(err.Error(), "GOZONE_TEST") {
				t.Errorf("envBool(%q): error should mention the var name, got %v", bad, err)
			}
		})
	}
}

// TestLoad_RejectsInvalidEnvOverride is the regression test for m13: a
// non-integer value on a numeric GOZONE_* override must fail Load (instead of
// the previous behavior of logging a warning and silently keeping the
// default), so the operator's override intent is never lost to a typo.
func TestLoad_RejectsInvalidEnvOverride(t *testing.T) {
	cases := []string{
		"GOZONE_SERVER_PORT",
		"GOZONE_SHUTDOWN_TIMEOUT",
		"GOZONE_SESSION_DURATION",
		"GOZONE_BCRYPT_COST",
		"GOZONE_ACTIVITY_RETENTION_DAYS",
		"GOZONE_ACTIVITY_BATCH_SIZE",
		"GOZONE_LOGIN_MAX_FAILED_ATTEMPTS",
		"GOZONE_LOGIN_LOCKOUT_MINUTES",
		"GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE",
		"GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS",
	}
	for _, env := range cases {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "not-a-number")
			_, err := Load("")
			if err == nil {
				t.Fatalf("%s=not-a-number: expected error, got nil", env)
			}
			if !strings.Contains(err.Error(), env) {
				t.Errorf("%s=not-a-number: expected error to mention %q, got %v", env, env, err)
			}
			if !strings.Contains(err.Error(), "expected an integer") {
				t.Errorf("%s=not-a-number: expected 'expected an integer' in error, got %v", env, err)
			}
		})
	}
}

func TestLoadInvalidFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("Load should not return error for nonexistent file: %v", err)
	}
}

// writeTempConfig writes content to a temp config.yaml and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_FieldValidation covers the previously-unvalidated fields flagged in
// m14 (server.host, powerdns.api_url, powerdns.server_id, database.dsn,
// logging.level, admin.username). Each case drives the value through a YAML
// config so empty strings are honored (env overrides skip empty values), then
// asserts that Load rejects it with a message naming the offending field.
func TestLoad_FieldValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"server.host not an IP", "server:\n  host: \"not-an-ip\"\n", "server.host"},
		{"server.host hostname rejected", "server:\n  host: \"localhost\"\n", "server.host"},
		{"powerdns.api_url empty", "powerdns:\n  api_url: \"\"\n", "powerdns.api_url"},
		{"powerdns.api_url missing scheme", "powerdns:\n  api_url: \"localhost:8081\"\n", "powerdns.api_url"},
		{"powerdns.api_url bad scheme", "powerdns:\n  api_url: \"ftp://localhost\"\n", "powerdns.api_url"},
		{"powerdns.server_id empty", "powerdns:\n  server_id: \"\"\n", "powerdns.server_id"},
		{"database.dsn empty", "database:\n  dsn: \"\"\n", "database.dsn"},
		{"logging.level invalid", "logging:\n  level: \"verbose\"\n", "logging.level"},
		{"admin.username too short", "admin:\n  username: \"ab\"\n", "admin.username"},
		{"admin.username bad chars", "admin:\n  username: \"bad user\"\n", "admin.username"},
		{"server.external_url missing scheme", "server:\n  external_url: \"dns.example.com\"\n", "server.external_url"},
		{"server.external_url bad scheme", "server:\n  external_url: \"ftp://dns.example.com\"\n", "server.external_url"},
		{"server.external_url with path", "server:\n  external_url: \"https://dns.example.com/gozone\"\n", "server.external_url"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestLoad_ExternalURL covers the server.external_url option: a valid absolute
// URL is accepted and normalised to "scheme://host" (trailing slash stripped),
// empty is allowed (default), and the GOZONE_EXTERNAL_URL env var overrides the
// YAML value with the same normalisation.
func TestLoad_ExternalURL(t *testing.T) {
	t.Run("accepts and normalises trailing slash", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, "server:\n  external_url: \"https://dns.example.com/\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if got, want := cfg.Server.ExternalURL, "https://dns.example.com"; got != want {
			t.Errorf("expected normalised %q, got %q", want, got)
		}
	})

	t.Run("empty by default", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, "server:\n  host: \"127.0.0.1\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if cfg.Server.ExternalURL != "" {
			t.Errorf("expected empty external_url by default, got %q", cfg.Server.ExternalURL)
		}
	})

	t.Run("env override normalises", func(t *testing.T) {
		t.Setenv("GOZONE_EXTERNAL_URL", "https://ha.example.com/")
		cfg, err := Load(writeTempConfig(t, "server:\n  host: \"127.0.0.1\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if got, want := cfg.Server.ExternalURL, "https://ha.example.com"; got != want {
			t.Errorf("env override: expected normalised %q, got %q", want, got)
		}
	})
}

// TestLoad_FieldValidation_AcceptsValid ensures the new guards do not reject
// legitimate values: empty host (all interfaces), IPv6 bind, https API URL and
// every supported log level.
func TestLoad_FieldValidation_AcceptsValid(t *testing.T) {
	t.Run("empty host", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, "server:\n  host: \"\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if cfg.Server.Host != "" {
			t.Errorf("expected empty host preserved, got %q", cfg.Server.Host)
		}
	})

	t.Run("ipv6 host", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, "server:\n  host: \"::1\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if cfg.Server.Host != "::1" {
			t.Errorf("expected ::1, got %q", cfg.Server.Host)
		}
	})

	t.Run("ipv6 host bracketed any normalized", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, "server:\n  host: \"[::]\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if cfg.Server.Host != "::" {
			t.Errorf("expected bracketed [::] normalized to \"::\", got %q", cfg.Server.Host)
		}
	})

	t.Run("ipv6 host bracketed loopback normalized", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, "server:\n  host: \"[::1]\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if cfg.Server.Host != "::1" {
			t.Errorf("expected bracketed [::1] normalized to \"::1\", got %q", cfg.Server.Host)
		}
	})

	t.Run("https api_url", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, "powerdns:\n  api_url: \"https://pdns.internal:443\"\n"))
		if err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
		if cfg.PowerDNS.APIURL != "https://pdns.internal:443" {
			t.Errorf("unexpected api_url %q", cfg.PowerDNS.APIURL)
		}
	})

	for _, lvl := range []string{"debug", "info", "warn", "error"} {
		t.Run("level/"+lvl, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, "logging:\n  level: \""+lvl+"\"\n"))
			if err != nil {
				t.Fatalf("level %q: expected valid config, got error: %v", lvl, err)
			}
			if cfg.Logging.Level != lvl {
				t.Errorf("level %q: got %q", lvl, cfg.Logging.Level)
			}
		})
	}
}

// TestLoad_DoesNotCreateHardcodedDataDir is the regression test for m15: Load
// must not create a hardcoded ./data directory. Directory creation is the
// responsibility of database.New, which derives the directory from the actual
// DSN (so a DSN like /var/lib/gozone/data.db no longer litters ./data in the
// process working directory, and a :memory: DSN touches nothing on disk).
func TestLoad_DoesNotCreateHardcodedDataDir(t *testing.T) {
	// Isolate the CWD so we can deterministically assert on ./data.
	t.Chdir(t.TempDir())

	if _, err := Load(""); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if _, err := os.Stat("data"); err == nil {
		t.Error("Load created a spurious ./data directory; directory creation is database.New's job (DSN-derived)")
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected Stat error: %v", err)
	}
}

// TestDefaultConfig_DeferKeyDerivation verifies the I-7 contract: DefaultConfig
// returns the master SecretKey but leaves the derived JWTKey/CSRFKey empty —
// derivation is Load()'s job (it has an error return and runs after env
// overrides). See TestLoad_HasDerivedKeys for the derived-keys coverage.
func TestDefaultConfig_DeferKeyDerivation(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.SecretKey == "" {
		t.Error("DefaultConfig must populate the master SecretKey (Load derives from it)")
	}
	if len(cfg.Server.JWTKey) != 0 {
		t.Errorf("DefaultConfig must not derive JWTKey (Load's job), got %d bytes", len(cfg.Server.JWTKey))
	}
	if len(cfg.Server.CSRFKey) != 0 {
		t.Errorf("DefaultConfig must not derive CSRFKey (Load's job), got %d bytes", len(cfg.Server.CSRFKey))
	}
}

func TestLoad_HasDerivedKeys(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Server.JWTKey) != 32 {
		t.Errorf("expected 32-byte JWTKey, got %d bytes", len(cfg.Server.JWTKey))
	}
	if len(cfg.Server.CSRFKey) != 32 {
		t.Errorf("expected 32-byte CSRFKey, got %d bytes", len(cfg.Server.CSRFKey))
	}
	if bytes.Equal(cfg.Server.JWTKey, cfg.Server.CSRFKey) {
		t.Error("JWTKey and CSRFKey must be different")
	}
}

func TestDeriveKeys_Deterministic(t *testing.T) {
	master := []byte("test-master-key-for-derivation-test")
	jwt1, csrf1, err := deriveKeys(master)
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}
	jwt2, csrf2, err := deriveKeys(master)
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}

	if !bytes.Equal(jwt1, jwt2) {
		t.Error("JWTKey must be deterministic")
	}
	if !bytes.Equal(csrf1, csrf2) {
		t.Error("CSRFKey must be deterministic")
	}
	if bytes.Equal(jwt1, csrf1) {
		t.Error("JWTKey and CSRFKey must be different")
	}
	if bytes.Equal(jwt1, master) {
		t.Error("derived JWTKey must differ from master secret")
	}
}

func TestDeriveKeys_DifferentMaster(t *testing.T) {
	jwt1, _, err := deriveKeys([]byte("master-one"))
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}
	jwt2, _, err := deriveKeys([]byte("master-two"))
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}

	if bytes.Equal(jwt1, jwt2) {
		t.Error("different master secrets must produce different JWT keys")
	}
}

func TestLoad_ValidatesPort(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		envVal  string
		wantErr string
	}{
		{
			name:    "zero port",
			envName: "GOZONE_SERVER_PORT",
			envVal:  "0",
			wantErr: "must be a positive integer",
		},
		{
			name:    "negative port",
			envName: "GOZONE_SERVER_PORT",
			envVal:  "-1",
			wantErr: "must be a positive integer",
		},
		{
			name:    "privileged port",
			envName: "GOZONE_SERVER_PORT",
			envVal:  "80",
			wantErr: "privileged port",
		},
		{
			name:    "port above range",
			envName: "GOZONE_SERVER_PORT",
			envVal:  "65536",
			wantErr: "out of valid range",
		},
		{
			name:    "bcrypt cost too low",
			envName: "GOZONE_BCRYPT_COST",
			envVal:  "3",
			wantErr: "must be between 4 and 31",
		},
		{
			name:    "bcrypt cost too high",
			envName: "GOZONE_BCRYPT_COST",
			envVal:  "32",
			wantErr: "must be between 4 and 31",
		},
		{
			name:    "session duration zero",
			envName: "GOZONE_SESSION_DURATION",
			envVal:  "0",
			wantErr: "session_duration_hours",
		},
		{
			name:    "session duration negative",
			envName: "GOZONE_SESSION_DURATION",
			envVal:  "-1",
			wantErr: "session_duration_hours",
		},
		{
			name:    "activity retention negative",
			envName: "GOZONE_ACTIVITY_RETENTION_DAYS",
			envVal:  "-1",
			wantErr: "retention_days",
		},
		{
			name:    "activity batch size zero",
			envName: "GOZONE_ACTIVITY_BATCH_SIZE",
			envVal:  "0",
			wantErr: "batch_size",
		},
		{
			name:    "shutdown timeout zero",
			envName: "GOZONE_SHUTDOWN_TIMEOUT",
			envVal:  "0",
			wantErr: "shutdown_timeout_seconds",
		},
		{
			name:    "shutdown timeout negative",
			envName: "GOZONE_SHUTDOWN_TIMEOUT",
			envVal:  "-5",
			wantErr: "shutdown_timeout_seconds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envName, tt.envVal)
			_, err := Load("")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestLoad_ValidatesDriver(t *testing.T) {
	t.Setenv("GOZONE_DB_DRIVER", "oracle")
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for unsupported driver, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported database driver") {
		t.Errorf("expected unsupported database driver error, got %v", err)
	}
}

func TestLoad_AcceptsValidBounds(t *testing.T) {
	t.Setenv("GOZONE_SERVER_PORT", "1024")
	t.Setenv("GOZONE_BCRYPT_COST", "4")
	t.Setenv("GOZONE_SESSION_DURATION", "1")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if cfg.Server.Port != 1024 {
		t.Errorf("expected port 1024, got %d", cfg.Server.Port)
	}
	if cfg.Auth.BcryptCost != 4 {
		t.Errorf("expected bcrypt cost 4, got %d", cfg.Auth.BcryptCost)
	}
	if cfg.Auth.SessionDurationHours != 1 {
		t.Errorf("expected session duration 1, got %d", cfg.Auth.SessionDurationHours)
	}
}

func TestLoad_LoginLockEnvOverrides(t *testing.T) {
	t.Setenv("GOZONE_LOGIN_MAX_FAILED_ATTEMPTS", "5")
	t.Setenv("GOZONE_LOGIN_LOCKOUT_MINUTES", "30")
	t.Setenv("GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE", "10")
	t.Setenv("GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS", "48")
	t.Setenv("GOZONE_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1/32, 2001:db8::/32")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if cfg.LoginLock.MaxFailedAttempts != 5 {
		t.Errorf("expected max_failed_attempts 5, got %d", cfg.LoginLock.MaxFailedAttempts)
	}
	if cfg.LoginLock.LockoutDurationMinutes != 30 {
		t.Errorf("expected lockout_duration_minutes 30, got %d", cfg.LoginLock.LockoutDurationMinutes)
	}
	if cfg.LoginLock.UsernameRateLimitPerMinute != 10 {
		t.Errorf("expected username_rate_limit_per_minute 10, got %d", cfg.LoginLock.UsernameRateLimitPerMinute)
	}
	if cfg.LoginLock.AttemptsRetentionHours != 48 {
		t.Errorf("expected attempts_retention_hours 48, got %d", cfg.LoginLock.AttemptsRetentionHours)
	}
	if len(cfg.Server.TrustedProxies) != 3 {
		t.Fatalf("expected 3 trusted_proxies, got %d (%v)", len(cfg.Server.TrustedProxies), cfg.Server.TrustedProxies)
	}
	wantProxies := []string{"10.0.0.0/8", "192.0.2.1/32", "2001:db8::/32"}
	for i, want := range wantProxies {
		if cfg.Server.TrustedProxies[i] != want {
			t.Errorf("trusted_proxies[%d] = %q, want %q", i, cfg.Server.TrustedProxies[i], want)
		}
	}
}

func TestLoad_PasswordDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Password.MinLength != 8 {
		t.Errorf("default min_length = %d, want 8", cfg.Password.MinLength)
	}
	if !cfg.Password.RequireUppercase || !cfg.Password.RequireLowercase || !cfg.Password.RequireDigit || !cfg.Password.RequireSpecial {
		t.Errorf("default class requires should all be true, got %+v", cfg.Password)
	}
	if cfg.Password.HistorySize != 0 {
		t.Errorf("default history_size = %d, want 0 (disabled)", cfg.Password.HistorySize)
	}
}

func TestLoad_PasswordEnvOverrides(t *testing.T) {
	t.Setenv("GOZONE_PASSWORD_MIN_LENGTH", "12")
	t.Setenv("GOZONE_PASSWORD_HISTORY_SIZE", "5")
	t.Setenv("GOZONE_PASSWORD_REQUIRE_UPPERCASE", "false")
	t.Setenv("GOZONE_PASSWORD_REQUIRE_SPECIAL", "0")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Password.MinLength != 12 {
		t.Errorf("min_length = %d, want 12", cfg.Password.MinLength)
	}
	if cfg.Password.HistorySize != 5 {
		t.Errorf("history_size = %d, want 5", cfg.Password.HistorySize)
	}
	if cfg.Password.RequireUppercase {
		t.Errorf("require_uppercase should be false via env")
	}
	if cfg.Password.RequireSpecial {
		t.Errorf("require_special should be false via env")
	}
	// Unset envs keep their defaults.
	if !cfg.Password.RequireLowercase || !cfg.Password.RequireDigit {
		t.Errorf("unset class requires should keep default true, got %+v", cfg.Password)
	}
}

func TestLoad_RejectsBadPasswordBounds(t *testing.T) {
	t.Setenv("GOZONE_PASSWORD_MIN_LENGTH", "-1")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for negative password.min_length, got nil")
	}
	t.Setenv("GOZONE_PASSWORD_MIN_LENGTH", "1000")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for password.min_length > 256, got nil")
	}
	t.Setenv("GOZONE_PASSWORD_MIN_LENGTH", "") // clear
	t.Setenv("GOZONE_PASSWORD_HISTORY_SIZE", "-3")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for negative password.history_size, got nil")
	}
}

func TestPasswordConfig_Policy(t *testing.T) {
	p := PasswordConfig{MinLength: 10, RequireUppercase: true, RequireDigit: true}.Policy()
	if p.MinLength != 10 || !p.RequireUppercase || !p.RequireDigit {
		t.Errorf("Policy() did not mirror fields: %+v", p)
	}
	// HistorySize is intentionally not part of the validators policy.
}

func TestLoad_RejectsBadTrustedProxy(t *testing.T) {
	t.Setenv("GOZONE_TRUSTED_PROXIES", "not-an-ip")
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for malformed trusted_proxies entry, got nil")
	}
	if !strings.Contains(err.Error(), "trusted_proxies") {
		t.Errorf("expected trusted_proxies error, got %v", err)
	}
}

// TestLoad_RejectsPlainIPTrustedProxy is the regression test for the
// startup panic "netip.ParsePrefix(\"172.16.1.27\"): no '/'" that occurred
// when a plain IP (no CIDR prefix) was configured in trusted_proxies. The
// chi middleware calls netip.MustParsePrefix which panics on entries
// without a "/"; config validation now rejects plain IPs with a clear
// error before the middleware is constructed.
func TestLoad_RejectsPlainIPTrustedProxy(t *testing.T) {
	t.Setenv("GOZONE_TRUSTED_PROXIES", "172.16.1.27")
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for plain-IP trusted_proxies entry, got nil")
	}
	if !strings.Contains(err.Error(), "trusted_proxies") {
		t.Errorf("expected trusted_proxies error, got %v", err)
	}
	if !strings.Contains(err.Error(), "CIDR") {
		t.Errorf("expected error to mention CIDR notation, got %v", err)
	}
}

func TestLoad_RejectsNegativeLoginLockFields(t *testing.T) {
	t.Setenv("GOZONE_LOGIN_MAX_FAILED_ATTEMPTS", "-1")
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for negative max_failed_attempts, got nil")
	}
	if !strings.Contains(err.Error(), "max_failed_attempts") {
		t.Errorf("expected max_failed_attempts error, got %v", err)
	}
}

func TestLoad_LoginLockDisabledByZero(t *testing.T) {
	t.Setenv("GOZONE_LOGIN_MAX_FAILED_ATTEMPTS", "0")
	t.Setenv("GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE", "0")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("expected valid config with zero-valued lockout settings, got error: %v", err)
	}
	if cfg.LoginLock.MaxFailedAttempts != 0 {
		t.Errorf("expected max_failed_attempts 0, got %d", cfg.LoginLock.MaxFailedAttempts)
	}
	if cfg.LoginLock.UsernameRateLimitPerMinute != 0 {
		t.Errorf("expected username_rate_limit_per_minute 0, got %d", cfg.LoginLock.UsernameRateLimitPerMinute)
	}
}

func TestSplitNonEmpty(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b ,c", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},
		{"", nil},
		{",", nil},
	}
	for _, tc := range tests {
		got := splitNonEmpty(tc.input, ",")
		if len(got) != len(tc.want) {
			t.Errorf("splitNonEmpty(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitNonEmpty(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

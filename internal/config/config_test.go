package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
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
	if cfg.Database.Driver != "sqlite3" {
		t.Errorf("expected sqlite3, got %s", cfg.Database.Driver)
	}
	if cfg.Auth.BcryptCost != 12 {
		t.Errorf("expected 12, got %d", cfg.Auth.BcryptCost)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected info, got %s", cfg.Logging.Level)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
server:
  host: "127.0.0.1"
  port: 9090
database:
  dsn: "/tmp/test.db"
auth:
  bcrypt_cost: 10
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
	if cfg.Database.DSN != "/tmp/test.db" {
		t.Errorf("expected /tmp/test.db, got %s", cfg.Database.DSN)
	}
	if cfg.Auth.BcryptCost != 10 {
		t.Errorf("expected 10, got %d", cfg.Auth.BcryptCost)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("GOZONE_SERVER_HOST", "192.168.1.1")
	t.Setenv("GOZONE_SERVER_PORT", "3000")
	t.Setenv("GOZONE_SECRET_KEY", "mysecret")
	t.Setenv("GOZONE_DB_DSN", "/custom/path.db")
	t.Setenv("GOZONE_PDNS_API_URL", "http://pdns:8081")
	t.Setenv("GOZONE_PDNS_API_KEY", "testkey")
	t.Setenv("GOZONE_PDNS_SERVER_ID", "test-server")
	t.Setenv("GOZONE_SESSION_DURATION", "48")

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
	if cfg.Server.SecretKey != "mysecret" {
		t.Errorf("expected mysecret, got %s", cfg.Server.SecretKey)
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
		"change-me-to-a-random-secret-key", // value shipped in config.yaml
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

func TestLoad_SecureCookiesDefaultFalse(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.SecureCookies {
		t.Error("secure_cookies should default to false")
	}
}

func TestLoad_SecureCookiesEnvOverride(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"true", true},
		{"1", true},
		{"on", true},
		{"false", false},
		{"0", false},
		{"garbage", false}, // unrecognized keeps the prior value (default false)
	}
	for _, tt := range tests {
		t.Setenv("GOZONE_SECURE_COOKIES", tt.env)
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if cfg.Server.SecureCookies != tt.want {
			t.Errorf("GOZONE_SECURE_COOKIES=%q: got %v, want %v", tt.env, cfg.Server.SecureCookies, tt.want)
		}
	}
}

func TestParseBoolOr(t *testing.T) {
	tests := []struct {
		input string
		def   bool
		want  bool
	}{
		{"true", false, true},
		{"YES", false, true},
		{"Off", true, false},
		{"", true, true},
		{"maybe", true, true},
		{"maybe", false, false},
	}
	for _, tt := range tests {
		if got := parseBoolOr(tt.input, tt.def); got != tt.want {
			t.Errorf("parseBoolOr(%q, %v) = %v, want %v", tt.input, tt.def, got, tt.want)
		}
	}
}

func TestLoadInvalidFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("Load should not return error for nonexistent file: %v", err)
	}
}

func TestParseIntOr(t *testing.T) {
	tests := []struct {
		input string
		def   int
		want  int
	}{
		{"123", 0, 123},
		{"0", 42, 0},
		{"abc", 42, 42},
		{"", 42, 0},
		{"12a34", 42, 42},
	}
	for _, tt := range tests {
		got := parseIntOr(tt.input, tt.def)
		if got != tt.want {
			t.Errorf("parseIntOr(%q, %d) = %d, want %d", tt.input, tt.def, got, tt.def)
		}
	}
}

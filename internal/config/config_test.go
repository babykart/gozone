package config

import (
	"os"
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

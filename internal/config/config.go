package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the application.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	PowerDNS PowerDNSConfig `yaml:"powerdns"`
	Auth     AuthConfig     `yaml:"auth"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	SecretKey string `yaml:"secret_key"`
}

// DatabaseConfig holds database connection settings.
type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

// PowerDNSConfig holds PowerDNS API connection settings.
type PowerDNSConfig struct {
	APIURL   string `yaml:"api_url"`
	APIKey   string `yaml:"api_key"`
	ServerID string `yaml:"server_id"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	SessionDurationHours int `yaml:"session_duration_hours"`
	BcryptCost           int `yaml:"bcrypt_cost"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:      "0.0.0.0",
			Port:      8080,
			SecretKey: "change-me-to-a-random-secret",
		},
		Database: DatabaseConfig{
			Driver: "sqlite3",
			DSN:    "./data/gozone.db",
		},
		PowerDNS: PowerDNSConfig{
			APIURL:   "http://localhost:8081",
			APIKey:   "changeme",
			ServerID: "localhost",
		},
		Auth: AuthConfig{
			SessionDurationHours: 24,
			BcryptCost:           12,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// Load reads a YAML config file and returns a Config.
// It applies defaults first, then overlays values from the file.
// Environment variables override file values (GOZONE_ prefix).
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}

	// Environment variable overrides
	applyEnvOverrides(cfg)

	// Ensure data directory exists for SQLite
	if cfg.Database.Driver == "sqlite3" {
		os.MkdirAll("./data", 0755)
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("GOZONE_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("GOZONE_SERVER_PORT"); v != "" {
		cfg.Server.Port = parseIntOr(v, cfg.Server.Port)
	}
	if v := os.Getenv("GOZONE_SECRET_KEY"); v != "" {
		cfg.Server.SecretKey = v
	}
	if v := os.Getenv("GOZONE_DB_DRIVER"); v != "" {
		cfg.Database.Driver = v
	}
	if v := os.Getenv("GOZONE_DB_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("GOZONE_PDNS_API_URL"); v != "" {
		cfg.PowerDNS.APIURL = v
	}
	if v := os.Getenv("GOZONE_PDNS_API_KEY"); v != "" {
		cfg.PowerDNS.APIKey = v
	}
	if v := os.Getenv("GOZONE_PDNS_SERVER_ID"); v != "" {
		cfg.PowerDNS.ServerID = v
	}
	if v := os.Getenv("GOZONE_SESSION_DURATION"); v != "" {
		cfg.Auth.SessionDurationHours = parseIntOr(v, cfg.Auth.SessionDurationHours)
	}
}

func parseIntOr(s string, defaultVal int) int {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return defaultVal
		}
		n = n*10 + int(c-'0')
	}
	return n
}

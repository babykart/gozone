// Package config handles YAML configuration loading with environment variable
// overrides. It provides DefaultConfig to bootstrap sensible defaults and Load
// to read a config file and apply GOZONE_*-prefixed env var overrides.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/logger"
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
	// SecureCookies marks the CSRF cookie with the Secure flag so browsers only
	// send it over HTTPS. Enable it when GoZone is served over HTTPS (directly
	// or behind a TLS-terminating reverse proxy). Leave it false for plain-HTTP
	// development, otherwise browsers will not return the CSRF cookie.
	SecureCookies bool `yaml:"secure_cookies"`
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

// DefaultConfig returns a Config populated with sensible development defaults.
//
// The default admin credentials are admin/admin. Override via the YAML config
// file or environment variables in production.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:          "0.0.0.0",
			Port:          8080,
			SecretKey:     defaultSecretKey,
			SecureCookies: false,
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
			BcryptCost:           constants.DefaultBcryptCost,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// Load reads a YAML config file and returns a populated Config.
//
// Processing order:
//  1. Start with DefaultConfig() values
//  2. Overlay values from the YAML file at path (if it exists)
//  3. Apply environment variable overrides using the GOZONE_ prefix
//
// Supported environment variables: GOZONE_SERVER_HOST, GOZONE_SERVER_PORT,
// GOZONE_SECRET_KEY, GOZONE_SECURE_COOKIES, GOZONE_DB_DRIVER, GOZONE_DB_DSN,
// GOZONE_PDNS_API_URL, GOZONE_PDNS_API_KEY, GOZONE_PDNS_SERVER_ID,
// GOZONE_SESSION_DURATION.
//
// Parameters:
//   - path: filesystem path to the YAML configuration file
//
// Returns the merged configuration or an error if parsing fails.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		// #nosec G304 -- path comes from CLI flag -config, not user input
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

	// Auto-generate a secret key if the default placeholder is still in use.
	// This prevents deployments from running with a well-known default key.
	if cfg.Server.SecretKey == defaultSecretKey {
		key, err := generateSecretKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate secret key: %w", err)
		}
		cfg.Server.SecretKey = key
		logger.Warn("auto-generated random secret key, set GOZONE_SECRET_KEY to persist")
		logger.Warn("current generated key", "key", key)
	}

	// Ensure data directory exists for SQLite
	if cfg.Database.Driver == "sqlite3" {
		os.MkdirAll("./data", 0750)
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
	if v := os.Getenv("GOZONE_SECURE_COOKIES"); v != "" {
		cfg.Server.SecureCookies = parseBoolOr(v, cfg.Server.SecureCookies)
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

// defaultSecretKey is the placeholder value that triggers auto-generation.
const defaultSecretKey = "change-me-to-a-random-secret"

// generateSecretKey produces a cryptographically random 32-byte key
// encoded as a hexadecimal string (64 characters).
func generateSecretKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret key: %w", err)
	}
	return hex.EncodeToString(b), nil
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

// parseBoolOr parses a boolean environment value, returning defaultVal for
// anything it does not recognize. Accepts the common truthy/falsy spellings.
func parseBoolOr(s string, defaultVal bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "yes", "on":
		return true
	case "0", "f", "false", "no", "off":
		return false
	default:
		return defaultVal
	}
}

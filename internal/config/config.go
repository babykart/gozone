// Package config handles YAML configuration loading with environment variable
// overrides. It provides DefaultConfig to bootstrap sensible defaults and Load
// to read a config file and apply GOZONE_*-prefixed env var overrides.
package config

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
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
	Admin    AdminConfig    `yaml:"admin"`
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
	// JWTKey is derived from SecretKey via HKDF-SHA256 for JWT signing.
	JWTKey []byte `yaml:"-"`
	// CSRFKey is derived from SecretKey via HKDF-SHA256 for CSRF tokens.
	CSRFKey []byte `yaml:"-"`
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

// AdminConfig holds default admin user settings used during database seeding.
type AdminConfig struct {
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	Email     string `yaml:"email"`
	FirstName string `yaml:"first_name"`
	LastName  string `yaml:"last_name"`
}

// DefaultConfig returns a Config populated with sensible development defaults.
//
// The default admin credentials are admin/admin. Override via the YAML config
// file or environment variables in production.
func DefaultConfig() *Config {
	cfg := &Config{
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
		Admin: AdminConfig{
			Username:  "admin",
			Password:  "admin",
			Email:     "admin@gozone.local",
			FirstName: "Admin",
			LastName:  "User",
		},
	}
	cfg.Server.JWTKey, cfg.Server.CSRFKey = deriveKeys([]byte(cfg.Server.SecretKey))
	return cfg
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

	// Auto-generate a secret key if a well-known placeholder is still in use.
	// This prevents deployments from running with a publicly known default key.
	if isPlaceholderSecret(cfg.Server.SecretKey) {
		key, err := generateSecretKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate secret key: %w", err)
		}
		cfg.Server.SecretKey = key
		// Never log the key itself: it signs sessions and CSRF tokens. Logging a
		// secret leaks it into log files, aggregators, and consoles. Operators
		// should set their own persistent key instead of recovering it from logs.
		logger.Warn("no secret key configured; generated an ephemeral random key for this run. " +
			"Sessions and CSRF tokens are invalidated on every restart. " +
			"Set server.secret_key or GOZONE_SECRET_KEY to a persistent value (openssl rand -hex 32)")
	}

	// Derive independent keys for JWT and CSRF from the master secret
	cfg.Server.JWTKey, cfg.Server.CSRFKey = deriveKeys([]byte(cfg.Server.SecretKey))

	// Ensure data directory exists for SQLite
	if cfg.Database.Driver == "sqlite3" {
		if err := os.MkdirAll("./data", 0750); err != nil {
			return cfg, fmt.Errorf("failed to create data directory: %w", err)
		}
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("GOZONE_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("GOZONE_SERVER_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_SERVER_PORT, using default", "value", v, "error", err)
		} else {
			cfg.Server.Port = n
		}
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
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_SESSION_DURATION, using default", "value", v, "error", err)
		} else {
			cfg.Auth.SessionDurationHours = n
		}
	}
	if v := os.Getenv("GOZONE_ADMIN_USERNAME"); v != "" {
		cfg.Admin.Username = v
	}
	if v := os.Getenv("GOZONE_ADMIN_PASSWORD"); v != "" {
		cfg.Admin.Password = v
	}
	if v := os.Getenv("GOZONE_ADMIN_EMAIL"); v != "" {
		cfg.Admin.Email = v
	}
	if v := os.Getenv("GOZONE_ADMIN_FIRST_NAME"); v != "" {
		cfg.Admin.FirstName = v
	}
	if v := os.Getenv("GOZONE_ADMIN_LAST_NAME"); v != "" {
		cfg.Admin.LastName = v
	}
}

// defaultSecretKey is the placeholder value baked into DefaultConfig.
const defaultSecretKey = "change-me-to-a-random-secret"

// placeholderSecrets lists the well-known placeholder secret keys that must
// never be used as a real signing key. Any of these triggers auto-generation
// at startup. Includes the value shipped in the sample config.yaml so that
// running with the unmodified example never uses a publicly known key.
var placeholderSecrets = map[string]bool{
	defaultSecretKey:                   true,
	"change-me-to-a-random-secret-key": true,
}

// isPlaceholderSecret reports whether the given secret key is empty or one of
// the well-known insecure placeholders.
func isPlaceholderSecret(key string) bool {
	return key == "" || placeholderSecrets[key]
}

// deriveKeys splits a master secret into two independent 32-byte sub-keys
// using HKDF-SHA256, one for JWT signing and one for CSRF token protection.
// Compromise of one sub-key does not reveal the other or the master secret.
func deriveKeys(master []byte) (jwtKey, csrfKey []byte) {
	var err error
	jwtKey, err = hkdf.Key(sha256.New, master, nil, "gozone-jwt", 32)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	csrfKey, err = hkdf.Key(sha256.New, master, nil, "gozone-csrf", 32)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return jwtKey, csrfKey
}

// generateSecretKey produces a cryptographically random 32-byte key
// encoded as a hexadecimal string (64 characters).
func generateSecretKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret key: %w", err)
	}
	return hex.EncodeToString(b), nil
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

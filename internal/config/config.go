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
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/logger"
)

// Config holds all configuration for the application.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	PowerDNS  PowerDNSConfig  `yaml:"powerdns"`
	Auth      AuthConfig      `yaml:"auth"`
	Logging   LoggingConfig   `yaml:"logging"`
	Admin     AdminConfig     `yaml:"admin"`
	Activity  ActivityConfig  `yaml:"activity"`
	LoginLock LoginLockConfig `yaml:"login_lock"`
}

// LoginLockConfig holds settings for the login brute-force protection.
//
// The /login endpoint is protected by three complementary defences:
//   - an in-memory IP-based rate limiter (always on; see RateLimiter).
//   - an in-memory username-based rate limiter that compounds with the IP one.
//   - persistent per-account lockout (failed_login_attempts, locked_until on users)
//     that survives server restarts and cluster-wide rollouts.
type LoginLockConfig struct {
	// MaxFailedAttempts is the number of consecutive failed login attempts per
	// account before the account is locked. Set to 0 to disable persistent
	// lockout (the rate limiters still protect the endpoint).
	MaxFailedAttempts int `yaml:"max_failed_attempts"`
	// LockoutDurationMinutes is how long the account stays locked after the
	// threshold is reached. Subsequent failed attempts reset the window.
	LockoutDurationMinutes int `yaml:"lockout_duration_minutes"`
	// UsernameRateLimitPerMinute bounds login attempts per minute per
	// attempted username. Compounded with the per-IP limit by AND-ing both
	// limits at the route level. Set to 0 to disable.
	UsernameRateLimitPerMinute int `yaml:"username_rate_limit_per_minute"`
	// AttemptsRetentionHours is how long a recorded login attempt is kept in
	// the login_attempts table before being purged. Should be greater than
	// LockoutDurationMinutes so the lockout window can be reliably enforced.
	AttemptsRetentionHours int `yaml:"attempts_retention_hours"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	SecretKey string `yaml:"secret_key"`
	// AppName is the human-readable application name displayed in the web UI.
	AppName string `yaml:"app_name"`
	// SecureCookies marks the CSRF cookie with the Secure flag so browsers only
	// send it over HTTPS. Enable it when GoZone is served over HTTPS (directly
	// or behind a TLS-terminating reverse proxy). Leave it false for plain-HTTP
	// development, otherwise browsers will not return the CSRF cookie.
	SecureCookies bool `yaml:"secure_cookies"`
	// TrustedProxies is the list of CIDR ranges from which X-Forwarded-For
	// headers are trusted. When empty, XFF headers are ignored entirely and
	// the rate limiter keys off the raw TCP source address. Each entry MUST
	// be a CIDR prefix — use "/32" for a single IPv4 host ("192.0.2.1/32")
	// and "/128" for a single IPv6 host ("2001:db8::1/128"). Plain IPs
	// without a prefix are rejected at config load to prevent a startup
	// panic inside chi's ClientIPFromXFF (which calls netip.MustParsePrefix
	// and panics on entries without a "/"). Configure this when running
	// behind nginx/Caddy/Traefik/etc. so the real client IP is preserved;
	// leaving it empty is safe (and recommended) for direct internet
	// exposure because attackers cannot forge their IP.
	TrustedProxies []string `yaml:"trusted_proxies"`
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

// ActivityConfig holds activity log settings.
type ActivityConfig struct {
	RetentionDays int `yaml:"retention_days"`
	BatchSize     int `yaml:"batch_size"`
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
			AppName:       "GoZone",
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
			Password:  DefaultAdminPassword,
			Email:     "admin@gozone.local",
			FirstName: "Admin",
			LastName:  "User",
		},
		Activity: ActivityConfig{
			RetentionDays: 90,
			BatchSize:     1000,
		},
		LoginLock: LoginLockConfig{
			MaxFailedAttempts:          10,
			LockoutDurationMinutes:     15,
			UsernameRateLimitPerMinute: 5,
			AttemptsRetentionHours:     24,
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
// GOZONE_APP_NAME, GOZONE_SECRET_KEY, GOZONE_SECURE_COOKIES, GOZONE_DB_DRIVER,
// GOZONE_DB_DSN, GOZONE_PDNS_API_URL, GOZONE_PDNS_API_KEY,
// GOZONE_PDNS_SERVER_ID, GOZONE_SESSION_DURATION, GOZONE_ACTIVITY_RETENTION_DAYS,
// GOZONE_ACTIVITY_BATCH_SIZE.
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

	if err := cfg.validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// validate checks that the merged configuration is within safe, operable
// bounds. It rejects nonsensical values such as privileged ports, bcrypt costs
// outside the bcrypt library range, or negative session durations before the
// server can start and silently behave unexpectedly or insecurely.
func (cfg *Config) validate() error {
	if cfg.Server.Port <= 0 {
		return fmt.Errorf("invalid server port %d: must be a positive integer", cfg.Server.Port)
	}

	if cfg.Server.Port < 1024 {
		return fmt.Errorf("server port %d is a privileged port; use 1024 or higher", cfg.Server.Port)
	}

	if cfg.Server.Port > 65535 {
		return fmt.Errorf("server port %d is out of valid range (1-65535)", cfg.Server.Port)
	}

	if cfg.Auth.BcryptCost < 4 || cfg.Auth.BcryptCost > 31 {
		return fmt.Errorf("invalid bcrypt_cost %d: must be between 4 and 31", cfg.Auth.BcryptCost)
	}

	if cfg.Auth.SessionDurationHours <= 0 {
		return fmt.Errorf("invalid session_duration_hours %d: must be a positive integer", cfg.Auth.SessionDurationHours)
	}

	if cfg.Database.Driver == "" {
		return fmt.Errorf("database driver is required")
	}

	switch cfg.Database.Driver {
	case "sqlite3", "mysql", "postgres":
		// supported
	default:
		return fmt.Errorf("unsupported database driver %q; choose one of sqlite3, mysql, postgres", cfg.Database.Driver)
	}

	if cfg.Activity.RetentionDays < 0 {
		return fmt.Errorf("invalid activity retention_days %d: must be non-negative", cfg.Activity.RetentionDays)
	}

	if cfg.Activity.BatchSize <= 0 {
		return fmt.Errorf("invalid activity batch_size %d: must be positive", cfg.Activity.BatchSize)
	}

	if cfg.LoginLock.MaxFailedAttempts < 0 {
		return fmt.Errorf("invalid login_lock.max_failed_attempts %d: must be non-negative", cfg.LoginLock.MaxFailedAttempts)
	}
	if cfg.LoginLock.LockoutDurationMinutes < 0 {
		return fmt.Errorf("invalid login_lock.lockout_duration_minutes %d: must be non-negative", cfg.LoginLock.LockoutDurationMinutes)
	}
	if cfg.LoginLock.UsernameRateLimitPerMinute < 0 {
		return fmt.Errorf("invalid login_lock.username_rate_limit_per_minute %d: must be non-negative", cfg.LoginLock.UsernameRateLimitPerMinute)
	}
	if cfg.LoginLock.AttemptsRetentionHours < 0 {
		return fmt.Errorf("invalid login_lock.attempts_retention_hours %d: must be non-negative", cfg.LoginLock.AttemptsRetentionHours)
	}

	for _, p := range cfg.Server.TrustedProxies {
		// chi's ClientIPFromXFF calls netip.MustParsePrefix(p) on every
		// entry, which panics at startup when p is a plain IP without a
		// "/" (e.g. "172.16.1.27"). Require CIDR notation here so the
		// error surfaces as a clean config-load failure rather than a
		// panic stack trace. netip.ParsePrefix also accepts the exact
		// forms chi needs (no trailing whitespace, valid prefix length),
		// so we use it as the single source of truth.
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("invalid trusted_proxies entry %q: %w (use CIDR notation such as %q or %q)", p, err, "172.16.1.27/32", "::1/128")
		}
		_ = prefix // validation only; chi re-parses at middleware setup
	}

	return nil
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
	if v := os.Getenv("GOZONE_APP_NAME"); v != "" {
		cfg.Server.AppName = v
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
	if v := os.Getenv("GOZONE_BCRYPT_COST"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_BCRYPT_COST, using default", "value", v, "error", err)
		} else {
			cfg.Auth.BcryptCost = n
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
	if v := os.Getenv("GOZONE_ACTIVITY_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_ACTIVITY_RETENTION_DAYS, using default", "value", v, "error", err)
		} else {
			cfg.Activity.RetentionDays = n
		}
	}
	if v := os.Getenv("GOZONE_ACTIVITY_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_ACTIVITY_BATCH_SIZE, using default", "value", v, "error", err)
		} else {
			cfg.Activity.BatchSize = n
		}
	}
	if v := os.Getenv("GOZONE_LOGIN_MAX_FAILED_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_LOGIN_MAX_FAILED_ATTEMPTS, using default", "value", v, "error", err)
		} else {
			cfg.LoginLock.MaxFailedAttempts = n
		}
	}
	if v := os.Getenv("GOZONE_LOGIN_LOCKOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_LOGIN_LOCKOUT_MINUTES, using default", "value", v, "error", err)
		} else {
			cfg.LoginLock.LockoutDurationMinutes = n
		}
	}
	if v := os.Getenv("GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE, using default", "value", v, "error", err)
		} else {
			cfg.LoginLock.UsernameRateLimitPerMinute = n
		}
	}
	if v := os.Getenv("GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS, using default", "value", v, "error", err)
		} else {
			cfg.LoginLock.AttemptsRetentionHours = n
		}
	}
	if v := os.Getenv("GOZONE_TRUSTED_PROXIES"); v != "" {
		cfg.Server.TrustedProxies = splitNonEmpty(v, ",")
	}
}

// splitNonEmpty splits s by sep and returns the non-empty trimmed entries.
func splitNonEmpty(s, sep string) []string {
	raw := strings.Split(s, sep)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// defaultSecretKey is the placeholder value baked into DefaultConfig.
const defaultSecretKey = "change-me-to-a-random-secret"

// DefaultAdminPassword is the placeholder admin password baked into
// DefaultConfig. Seeding the admin user with this value warrants a warning to
// change it; a custom password configured via YAML/env does not.
const DefaultAdminPassword = "admin"

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

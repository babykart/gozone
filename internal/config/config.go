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
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/validators"
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
	Password  PasswordConfig  `yaml:"password"`
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
	// ShutdownTimeoutSeconds is the maximum time to wait for in-flight
	// requests to finish during graceful shutdown (SIGINT/SIGTERM). Must
	// be positive. Default: 30.
	ShutdownTimeoutSeconds int `yaml:"shutdown_timeout_seconds"`
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

// PasswordConfig holds the password policy enforced whenever a password is set
// or changed (user creation, admin update, `gozone user reset-password`). The
// initial admin seed (SeedAdminUser) bypasses the policy — it is a one-time
// bootstrap that already warns to change the default password.
type PasswordConfig struct {
	// MinLength is the minimum password length in runes. 0 disables the check.
	MinLength int `yaml:"min_length"`
	// RequireUppercase/Lowercase/Digit/Special require at least one character
	// of each class. "Special" means any non-letter, non-digit rune (punctuation,
	// symbols, spaces).
	RequireUppercase bool `yaml:"require_uppercase"`
	RequireLowercase bool `yaml:"require_lowercase"`
	RequireDigit     bool `yaml:"require_digit"`
	RequireSpecial   bool `yaml:"require_special"`
	// HistorySize is the number of previous password hashes retained per user
	// to prevent reuse. 0 (default) disables history checking.
	HistorySize int `yaml:"history_size"`
}

// Policy converts the configuration into a validators.PasswordPolicy. It lives
// here (and not on the handler) to keep the single config→validators mapping
// in one place and avoid a validators→config import cycle.
func (p PasswordConfig) Policy() validators.PasswordPolicy {
	return validators.PasswordPolicy{
		MinLength:        p.MinLength,
		RequireUppercase: p.RequireUppercase,
		RequireLowercase: p.RequireLowercase,
		RequireDigit:     p.RequireDigit,
		RequireSpecial:   p.RequireSpecial,
	}
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
			Host:                   "0.0.0.0",
			Port:                   8080,
			SecretKey:              defaultSecretKey,
			AppName:                "GoZone",
			SecureCookies:          false,
			ShutdownTimeoutSeconds: 30,
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
		Password: PasswordConfig{
			MinLength:        8,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireDigit:     true,
			RequireSpecial:   true,
			HistorySize:      0,
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
// GOZONE_APP_NAME, GOZONE_SECRET_KEY, GOZONE_SECURE_COOKIES,
// GOZONE_SHUTDOWN_TIMEOUT, GOZONE_DB_DRIVER,
// GOZONE_DB_DSN, GOZONE_PDNS_API_URL, GOZONE_PDNS_API_KEY,
// GOZONE_PDNS_SERVER_ID, GOZONE_SESSION_DURATION, GOZONE_ACTIVITY_RETENTION_DAYS,
// GOZONE_ACTIVITY_BATCH_SIZE, GOZONE_PASSWORD_MIN_LENGTH,
// GOZONE_PASSWORD_HISTORY_SIZE, GOZONE_PASSWORD_REQUIRE_UPPERCASE,
// GOZONE_PASSWORD_REQUIRE_LOWERCASE, GOZONE_PASSWORD_REQUIRE_DIGIT,
// GOZONE_PASSWORD_REQUIRE_SPECIAL.
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
	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}

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

	// By the time validate() runs, placeholder secrets have already been
	// replaced by a 64-char generated key, so this floor only catches an
	// operator-configured key that is too weak to safely sign sessions and
	// CSRF tokens. Reject fail-fast rather than silently deriving keys from
	// low-entropy material.
	if len(cfg.Server.SecretKey) < minSecretKeyLength {
		return fmt.Errorf("server.secret_key is too short: %d chars, need at least %d (generate one with: openssl rand -hex 32)", len(cfg.Server.SecretKey), minSecretKeyLength)
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

	if cfg.Password.MinLength < 0 {
		return fmt.Errorf("invalid password.min_length %d: must be non-negative", cfg.Password.MinLength)
	}
	if cfg.Password.MinLength > 256 {
		return fmt.Errorf("invalid password.min_length %d: must be at most 256", cfg.Password.MinLength)
	}
	if cfg.Password.HistorySize < 0 {
		return fmt.Errorf("invalid password.history_size %d: must be non-negative", cfg.Password.HistorySize)
	}

	if cfg.Server.ShutdownTimeoutSeconds <= 0 {
		return fmt.Errorf("invalid server.shutdown_timeout_seconds %d: must be positive", cfg.Server.ShutdownTimeoutSeconds)
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

	// server.host is a bind address: numeric IPs only (a hostname would need
	// resolution and is almost always a mistake). Empty is allowed — Go's
	// net/http then listens on all interfaces. IPv6 may be written with or
	// without surrounding brackets (e.g. "[::]" or "::"); brackets are stripped
	// so the stored value is a bare address that net.JoinHostPort brackets
	// correctly when building the listen address.
	if cfg.Server.Host != "" {
		host := cfg.Server.Host
		if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
			host = host[1 : len(host)-1]
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid server.host %q: must be an IP address (got %v)", cfg.Server.Host, err)
		}
		cfg.Server.Host = host
	}

	// powerdns.api_url must be a usable base URL for the PowerDNS API.
	if cfg.PowerDNS.APIURL == "" {
		return fmt.Errorf("powerdns.api_url is required")
	}
	u, err := url.Parse(cfg.PowerDNS.APIURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid powerdns.api_url %q: must be an absolute URL with a host", cfg.PowerDNS.APIURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid powerdns.api_url %q: scheme must be http or https", cfg.PowerDNS.APIURL)
	}

	if cfg.PowerDNS.ServerID == "" {
		return fmt.Errorf("powerdns.server_id is required")
	}

	if cfg.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}

	switch cfg.Logging.Level {
	case "debug", "info", "warn", "error":
		// ok
	default:
		return fmt.Errorf("invalid logging.level %q: must be one of debug, info, warn, error", cfg.Logging.Level)
	}

	// admin.username is used to seed the first admin user; it must satisfy the
	// same rules as any other username (single source of truth in validators).
	if err := validators.ValidateUsername(cfg.Admin.Username); err != nil {
		return fmt.Errorf("invalid admin.username: %w", err)
	}

	return nil
}

// applyEnvOverrides overlays GOZONE_-prefixed environment variables on top of
// the YAML-provided config. An unparseable override (e.g.
// GOZONE_SERVER_PORT=abc) is returned as a hard error rather than silently
// keeping the default, so a typo fails config load loud-and-early instead of
// hiding the operator's intent (REVIEW.md m13). String overrides are accepted
// as-is since any non-empty value is valid for them.
func applyEnvOverrides(cfg *Config) error {
	if v := os.Getenv("GOZONE_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("GOZONE_SERVER_PORT"); v != "" {
		n, err := envInt("GOZONE_SERVER_PORT", v)
		if err != nil {
			return err
		}
		cfg.Server.Port = n
	}
	if v := os.Getenv("GOZONE_APP_NAME"); v != "" {
		cfg.Server.AppName = v
	}
	if v := os.Getenv("GOZONE_SECRET_KEY"); v != "" {
		cfg.Server.SecretKey = v
	}
	if v := os.Getenv("GOZONE_SECURE_COOKIES"); v != "" {
		b, err := envBool("GOZONE_SECURE_COOKIES", v)
		if err != nil {
			return err
		}
		cfg.Server.SecureCookies = b
	}
	if v := os.Getenv("GOZONE_SHUTDOWN_TIMEOUT"); v != "" {
		n, err := envInt("GOZONE_SHUTDOWN_TIMEOUT", v)
		if err != nil {
			return err
		}
		cfg.Server.ShutdownTimeoutSeconds = n
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
		n, err := envInt("GOZONE_SESSION_DURATION", v)
		if err != nil {
			return err
		}
		cfg.Auth.SessionDurationHours = n
	}
	if v := os.Getenv("GOZONE_BCRYPT_COST"); v != "" {
		n, err := envInt("GOZONE_BCRYPT_COST", v)
		if err != nil {
			return err
		}
		cfg.Auth.BcryptCost = n
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
		n, err := envInt("GOZONE_ACTIVITY_RETENTION_DAYS", v)
		if err != nil {
			return err
		}
		cfg.Activity.RetentionDays = n
	}
	if v := os.Getenv("GOZONE_ACTIVITY_BATCH_SIZE"); v != "" {
		n, err := envInt("GOZONE_ACTIVITY_BATCH_SIZE", v)
		if err != nil {
			return err
		}
		cfg.Activity.BatchSize = n
	}
	if v := os.Getenv("GOZONE_LOGIN_MAX_FAILED_ATTEMPTS"); v != "" {
		n, err := envInt("GOZONE_LOGIN_MAX_FAILED_ATTEMPTS", v)
		if err != nil {
			return err
		}
		cfg.LoginLock.MaxFailedAttempts = n
	}
	if v := os.Getenv("GOZONE_LOGIN_LOCKOUT_MINUTES"); v != "" {
		n, err := envInt("GOZONE_LOGIN_LOCKOUT_MINUTES", v)
		if err != nil {
			return err
		}
		cfg.LoginLock.LockoutDurationMinutes = n
	}
	if v := os.Getenv("GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE"); v != "" {
		n, err := envInt("GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE", v)
		if err != nil {
			return err
		}
		cfg.LoginLock.UsernameRateLimitPerMinute = n
	}
	if v := os.Getenv("GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS"); v != "" {
		n, err := envInt("GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS", v)
		if err != nil {
			return err
		}
		cfg.LoginLock.AttemptsRetentionHours = n
	}
	if v := os.Getenv("GOZONE_TRUSTED_PROXIES"); v != "" {
		cfg.Server.TrustedProxies = splitNonEmpty(v, ",")
	}
	if v := os.Getenv("GOZONE_PASSWORD_MIN_LENGTH"); v != "" {
		n, err := envInt("GOZONE_PASSWORD_MIN_LENGTH", v)
		if err != nil {
			return err
		}
		cfg.Password.MinLength = n
	}
	if v := os.Getenv("GOZONE_PASSWORD_HISTORY_SIZE"); v != "" {
		n, err := envInt("GOZONE_PASSWORD_HISTORY_SIZE", v)
		if err != nil {
			return err
		}
		cfg.Password.HistorySize = n
	}
	if v := os.Getenv("GOZONE_PASSWORD_REQUIRE_UPPERCASE"); v != "" {
		b, err := envBool("GOZONE_PASSWORD_REQUIRE_UPPERCASE", v)
		if err != nil {
			return err
		}
		cfg.Password.RequireUppercase = b
	}
	if v := os.Getenv("GOZONE_PASSWORD_REQUIRE_LOWERCASE"); v != "" {
		b, err := envBool("GOZONE_PASSWORD_REQUIRE_LOWERCASE", v)
		if err != nil {
			return err
		}
		cfg.Password.RequireLowercase = b
	}
	if v := os.Getenv("GOZONE_PASSWORD_REQUIRE_DIGIT"); v != "" {
		b, err := envBool("GOZONE_PASSWORD_REQUIRE_DIGIT", v)
		if err != nil {
			return err
		}
		cfg.Password.RequireDigit = b
	}
	if v := os.Getenv("GOZONE_PASSWORD_REQUIRE_SPECIAL"); v != "" {
		b, err := envBool("GOZONE_PASSWORD_REQUIRE_SPECIAL", v)
		if err != nil {
			return err
		}
		cfg.Password.RequireSpecial = b
	}
	return nil
}

// envInt parses an integer environment override. An unparseable value is
// returned as an error rather than silently falling back to the default, so a
// typo in the override fails config load instead of hiding the operator's
// intent (REVIEW.md m13).
func envInt(name, v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q: expected an integer (%v)", name, v, err)
	}
	return n, nil
}

// envBool parses a boolean environment override. Unrecognized spellings are
// returned as an error for the same reason as envInt (REVIEW.md m13).
func envBool(name, v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "yes", "on":
		return true, nil
	case "0", "f", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid %s=%q: expected a boolean (true/false, 1/0, yes/no, on/off)", name, v)
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

// minSecretKeyLength is the minimum acceptable length for a user-configured
// secret key (non-placeholder). Placeholders are always replaced by a
// 64-character generated key before this floor is enforced. 32 characters
// provide at least 128 bits of entropy for hex-encoded material and a
// reasonable lower bound for base64 / ASCII passphrases; the auto-generated
// key (32 bytes hex = 64 chars) comfortably exceeds it.
const minSecretKeyLength = 32

// placeholderSecretPrefixes lists case-insensitive prefixes that mark a
// secret as a well-known insecure placeholder. Any value starting with one of
// these triggers auto-generation at startup, regardless of the suffix, so the
// docker-compose value "change-me-to-a-random-secret-in-production" and any
// future variant are caught without enumerating every spelling. Both the
// hyphenated ("change-me") and concatenated ("changeme") spellings are
// covered, matching the values shipped in DefaultConfig, config.yaml and
// docker-compose.yml.
var placeholderSecretPrefixes = []string{
	"change-me",
	"changeme",
}

// isPlaceholderSecret reports whether the given secret key is empty or a
// well-known insecure placeholder. Matching is case-insensitive and
// prefix-based so that every known/likely placeholder spelling is caught
// (including the values shipped in config.yaml and docker-compose.yml) without
// having to maintain an exhaustive allow-list of exact strings.
func isPlaceholderSecret(key string) bool {
	if key == "" {
		return true
	}
	lower := strings.ToLower(key)
	for _, p := range placeholderSecretPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
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

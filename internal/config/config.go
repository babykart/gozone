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
	OIDC      OIDCConfig      `yaml:"oidc"`
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
	// account before the account is locked. Set to 0 to disable the AUTOMATIC
	// brute-force lockout (the rate limiters still protect the endpoint).
	//
	// Disabling the automatic lockout (0) means no new auto-locks are recorded
	// AND existing auto-locks (locked_until, set while this setting was > 0)
	// are no longer enforced at login — a previously auto-locked account
	// becomes immediately able to log in again. This is intentional — 0 means
	// "the automatic lockout feature is off" — but operators toggling it off
	// should be aware of the consequence.
	//
	// A MANUAL admin lock (the "Lock user" action / AdminLockUser) is NOT
	// affected by this setting: it is tracked in a separate column
	// (manual_lock_until) and enforced at login unconditionally, so an account
	// an administrator froze stays frozen even with the automatic lockout
	// disabled. To clear a specific lock, use the admin Unlock action or
	// `gozone user unlock <id|username>`.
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
	// SecureCookies was previously used to set the Secure flag on the CSRF cookie
	// at startup. It is now derived per-request from the effective TLS context
	// (middleware.IsHTTPS), matching the session cookie — so this field is no
	// longer read by the server. Retained for backward compatibility with
	// existing YAML/env configurations.
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
	// ExternalURL is the canonical base URL GoZone is served at (e.g.
	// "https://dns.example.com"). When set, OIDC redirect_uri and
	// post_logout_redirect_uri values are built from it instead of being
	// derived per-request from the client-controlled Host header
	// (defense-in-depth: the IdP already validates both against its
	// registered lists, but this removes the app's reliance on the Host
	// header for the SSO flow). When empty, the URLs are derived from the
	// resolved scheme (trusted-proxy aware) and r.Host — the original
	// behaviour. Must be an absolute http(s) URL with a host and no path; it
	// is validated and normalised to "scheme://host" at load. Optional.
	ExternalURL string `yaml:"external_url"`
	// JWTKey is derived from SecretKey via HKDF-SHA256 for JWT signing.
	JWTKey []byte `yaml:"-"`
	// CSRFKey is derived from SecretKey via HKDF-SHA256 for CSRF tokens.
	CSRFKey []byte `yaml:"-"`
	// OIDCStateKey is derived from SecretKey via HKDF-SHA256 and encrypts the
	// OIDC state parameter (AES-256-GCM: confidentiality + CSRF protection for
	// the SSO redirect dance). It is independent of JWTKey/CSRFKey so compromise
	// of one does not reveal the others.
	OIDCStateKey []byte `yaml:"-"`
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
	// IdleTimeoutMinutes bounds session inactivity: a session untouched for
	// longer than this is forced to re-authenticate, even if the JWT has not
	// expired. 0 (default) disables the idle check. Applies to both local and
	// SSO sessions. Tracked in memory per instance (consistent with the rate
	// limiters); a server restart resets idle windows.
	IdleTimeoutMinutes int `yaml:"idle_timeout_minutes"`
	// AbsoluteSessionTimeoutHours caps the total lifetime of a session across
	// refreshes. While a session stays active (within the idle window) and
	// below this cap, the access JWT is transparently refreshed near its
	// expiry — i.e. the session "slides" up to this absolute TTL. After it,
	// full re-authentication is required. 0 (default) disables the cap AND
	// refresh: the session lives exactly SessionDurationHours. For refresh to
	// ever trigger, this must be greater than SessionDurationHours.
	AbsoluteSessionTimeoutHours int `yaml:"absolute_session_timeout_hours"`
	// MaxAPIKeysPerUser caps how many non-deleted API keys a single user may
	// own at once; creating one more is rejected until old keys are deleted.
	// The cap bounds the blast radius of credential sprawl: an API key carries
	// its owner's full permissions, so unbounded accumulation defeats expiry
	// hygiene. 0 disables the cap.
	MaxAPIKeysPerUser int `yaml:"max_api_keys_per_user"`
}

// OIDCConfig holds OpenID Connect / OAuth2 single sign-on settings. When
// Enabled is false (the default) the whole subsystem is inert: no SSO buttons
// are rendered, no /auth/oidc routes are active, and local username/password
// login is the only authentication path. See the GoZone ROADMAP "OpenID Connect
// / OAuth2" section for the design rationale.
type OIDCConfig struct {
	// Enabled is the master switch for SSO. When false, all other OIDC fields
	// are ignored.
	Enabled bool `yaml:"enabled"`
	// AllowLocalLogin keeps the local username/password login form available
	// alongside SSO. When false and SSO is enabled, the local form is hidden
	// (but the POST /login endpoint remains wired so existing sessions and
	// API tooling keep working). Default true.
	AllowLocalLogin bool `yaml:"allow_local_login"`
	// AutoProvision creates a local user automatically on first successful SSO
	// login. It gates ONLY the creation of new accounts: linking an existing
	// local account by a verified email always works (email_verified must be
	// true), as does a pre-existing external-identity link. When false and no
	// matching existing account is found, login is refused. Default false —
	// operators must opt in to JIT provisioning.
	AutoProvision bool `yaml:"auto_provision"`
	// RequireVerifiedEmail gates email-based linking to an existing local
	// account on the IdP's email_verified claim. Default true (secure): an
	// existing account is linked by email only when the IdP asserts the email
	// is verified, preventing account takeover via an unverified email asserted
	// at a compromised IdP. Set to false when the IdP is trusted and its emails
	// are authoritative but not necessarily marked verified (e.g. a Keycloak
	// realm where email_verified is not emitted); linking then keys on the email
	// alone. Has no effect when no local account matches the email.
	RequireVerifiedEmail bool `yaml:"require_verified_email"`
	// DefaultRole is the role assigned to auto-provisioned users ("admin" or
	// "user"). Default "user".
	DefaultRole string `yaml:"default_role"`
	// Scopes is the global fallback scope list requested when a provider does
	// not specify its own. "openid" is always added. Default [openid, profile,
	// email].
	Scopes []string `yaml:"scopes"`
	// Providers is the list of configured identity providers. Each entry
	// becomes a /auth/oidc/{name} route pair and a login button.
	Providers []OIDCProviderConfig `yaml:"providers"`
	// RoleClaim is the dotted path of the ID-token claim inspected for role
	// mapping (e.g. "groups", "roles", "realm_access.roles"). When empty (the
	// default) role mapping is disabled and DefaultRole governs provisioning.
	RoleClaim string `yaml:"role_claim"`
	// AdminRoleValues lists claim values (at RoleClaim) that grant the GoZone
	// admin role. Any user whose claim set contains one of these values is
	// mapped to "admin"; otherwise the DefaultRole applies. Case-sensitive.
	AdminRoleValues []string `yaml:"admin_role_values"`
	// GroupClaim is the dotted path of the ID-token claim inspected for zone-
	// group mapping (e.g. "groups", "teams"). When empty (the default) group
	// mapping is disabled.
	GroupClaim string `yaml:"group_claim"`
	// GroupMapping maps an IdP claim value (at GroupClaim) to a GoZone
	// zone_group name. On each SSO login the user is added (additively) to
	// every mapped group that exists; groups that do not exist are skipped with
	// a warning. Memberships are never auto-removed — revoke manually.
	GroupMapping map[string]string `yaml:"group_mapping"`
	// JWKSCacheTTLMinutes is how long a provider's signing keys are cached
	// before a proactive background refresh, in minutes. A background goroutine
	// re-fetches the JWKS on this cadence so key rotation is picked up without
	// waiting for an unknown key ID. 0 disables the proactive refresh (keys are
	// still fetched on first use and on an unknown kid — the library's
	// behaviour). Default 60 (1 hour).
	JWKSCacheTTLMinutes int `yaml:"jwks_cache_ttl_minutes"`
}

// OIDCProviderConfig describes a single identity provider. Name maps to a
// well-known preset (gitea, google, github, gitlab, keycloak, authentik,
// azure) that supplies defaults (display name, scopes); any other name is
// treated as a generic OIDC provider using standard discovery.
type OIDCProviderConfig struct {
	// Name is the unique provider slug: the URL key (/auth/oidc/{name}/...),
	// the preset lookup key, and the cookie/state prefix. Must be unique within
	// the providers list.
	Name string `yaml:"name"`
	// DisplayName overrides the preset's button label. Empty falls back to the
	// preset display name, or the Name when no preset matches.
	DisplayName string `yaml:"display_name"`
	// IssuerURL is the provider's issuer identifier, used for OIDC discovery
	// (/.well-known/openid-configuration) and as the "iss" claim to validate.
	IssuerURL string `yaml:"issuer_url"`
	// ClientID is the OAuth2 client identifier registered at the provider.
	ClientID string `yaml:"client_id"`
	// ClientSecret is the OAuth2 client secret. Required for the confidential
	// authorization-code flow GoZone uses.
	ClientSecret string `yaml:"client_secret"`
	// Scopes optionally overrides the global/preset scopes for this provider.
	Scopes []string `yaml:"scopes"`
}

// PasswordConfig holds the password policy enforced whenever a password is set
// or changed (user creation, admin update, `gozone user reset-password`). The
// initial admin seed (SeedAdminUser) bypasses the policy — it is a one-time
// bootstrap that already warns to change the default password.
type PasswordConfig struct {
	// MinLength is the minimum password length in runes. 0 disables the check.
	MinLength int `yaml:"min_length"`
	// MaxLength is the maximum password length in BYTES (not runes, unlike
	// min_length). bcrypt — the hashing backend — rejects passwords longer
	// than 72 bytes, so the default of 72 surfaces that hard limit as a clear
	// validation message at every password-set site instead of an opaque
	// "failed to hash" error. Values above 72 are rejected at load time
	// because the hash would fail regardless. 0 disables the check (bcrypt's
	// own limit then applies at hash time).
	MaxLength int `yaml:"max_length"`
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
	// MaxAgeDays is the maximum password age in days. 0 (default) means no
	// expiry: passwords never expire. When > 0, a user whose password is older
	// than MaxAgeDays is forced to change it on next login.
	MaxAgeDays int `yaml:"max_age_days"`
	// ExpiryWarnDays is the number of days before expiry during which the
	// dashboard shows a "password expiring soon" warning. 0 (default) disables
	// the warning. Only meaningful when MaxAgeDays > 0.
	ExpiryWarnDays int `yaml:"expiry_warn_days"`
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
		MaxLength:        p.MaxLength,
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
//
// Note: Server.JWTKey and Server.CSRFKey are left empty. They are derived from
// Server.SecretKey by Load() (which can report an HKDF failure); direct callers
// of DefaultConfig that need a usable key pair should call Load("").
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
			MaxAPIKeysPerUser:    constants.DefaultMaxAPIKeysPerUser,
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
			MaxLength:        72,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireDigit:     true,
			RequireSpecial:   true,
			HistorySize:      0,
		},
		OIDC: OIDCConfig{
			Enabled:              false,
			AllowLocalLogin:      true,
			AutoProvision:        false,
			RequireVerifiedEmail: true,
			DefaultRole:          "user",
			Scopes:               []string{"openid", "profile", "email"},
			JWKSCacheTTLMinutes:  60,
		},
	}
	// JWTKey/CSRFKey are intentionally NOT derived here: DefaultConfig has no
	// error return, and derivation must run after env overrides / placeholder
	// handling anyway. Load() derives them from Server.SecretKey. Direct
	// DefaultConfig() callers get the master SecretKey and an empty key pair.
	return cfg
}

// Load reads a YAML config file and returns a populated Config.
//
// Processing order:
//  1. Start with DefaultConfig() values
//  2. Overlay values from the YAML file at path (if it exists)
//  3. Apply environment variable overrides using the GOZONE_ prefix
//
// Supported environment variables (grouped as in the envOverrides table):
//
//	server:     GOZONE_SERVER_HOST, GOZONE_SERVER_PORT, GOZONE_APP_NAME,
//	            GOZONE_SECRET_KEY, GOZONE_SECURE_COOKIES, GOZONE_EXTERNAL_URL,
//	            GOZONE_SHUTDOWN_TIMEOUT, GOZONE_TRUSTED_PROXIES
//	database:   GOZONE_DB_DRIVER, GOZONE_DB_DSN
//	powerdns:   GOZONE_PDNS_API_URL, GOZONE_PDNS_API_KEY, GOZONE_PDNS_SERVER_ID
//	auth:       GOZONE_SESSION_DURATION, GOZONE_IDLE_TIMEOUT_MINUTES,
//	            GOZONE_ABSOLUTE_SESSION_TIMEOUT_HOURS, GOZONE_BCRYPT_COST,
//	            GOZONE_MAX_API_KEYS
//	admin seed: GOZONE_ADMIN_USERNAME, GOZONE_ADMIN_PASSWORD, GOZONE_ADMIN_EMAIL,
//	            GOZONE_ADMIN_FIRST_NAME, GOZONE_ADMIN_LAST_NAME
//	activity:   GOZONE_ACTIVITY_RETENTION_DAYS, GOZONE_ACTIVITY_BATCH_SIZE
//	login lock: GOZONE_LOGIN_MAX_FAILED_ATTEMPTS, GOZONE_LOGIN_LOCKOUT_MINUTES,
//	            GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE,
//	            GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS
//	password:   GOZONE_PASSWORD_MIN_LENGTH, GOZONE_PASSWORD_MAX_LENGTH,
//	            GOZONE_PASSWORD_HISTORY_SIZE, GOZONE_PASSWORD_MAX_AGE_DAYS,
//	            GOZONE_PASSWORD_EXPIRY_WARN_DAYS, GOZONE_PASSWORD_REQUIRE_UPPERCASE,
//	            GOZONE_PASSWORD_REQUIRE_LOWERCASE, GOZONE_PASSWORD_REQUIRE_DIGIT,
//	            GOZONE_PASSWORD_REQUIRE_SPECIAL
//	logging:    GOZONE_LOG_LEVEL
//	oidc:       GOZONE_OIDC_ENABLED, GOZONE_OIDC_ALLOW_LOCAL_LOGIN,
//	            GOZONE_OIDC_AUTO_PROVISION, GOZONE_OIDC_REQUIRE_VERIFIED_EMAIL,
//	            GOZONE_OIDC_DEFAULT_ROLE, GOZONE_OIDC_SCOPES, GOZONE_OIDC_ROLE_CLAIM,
//	            GOZONE_OIDC_ADMIN_ROLE_VALUES, GOZONE_OIDC_GROUP_CLAIM,
//	            GOZONE_OIDC_JWKS_CACHE_TTL_MINUTES
//	oidc single-provider block: GOZONE_OIDC_PROVIDER_NAME, GOZONE_OIDC_ISSUER_URL,
//	            GOZONE_OIDC_CLIENT_ID, GOZONE_OIDC_CLIENT_SECRET
//
// TestLoadDocListsEveryEnvOverride keeps this list honest: it fails whenever a
// variable is added to the override tables without being documented here, or
// the documentation names a variable the code no longer handles.
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

	// Derive independent keys for JWT and CSRF from the master secret. Key
	// derivation lives here (not in DefaultConfig) so that it always runs after
	// env overrides and the placeholder-secret auto-generation above, and so a
	// (theoretically impossible) HKDF failure is reported through Load's error
	// return instead of aborting the process (REVIEW.md I-7).
	jwtKey, csrfKey, err := deriveKeys([]byte(cfg.Server.SecretKey))
	if err != nil {
		return nil, fmt.Errorf("derive jwt/csrf keys: %w", err)
	}
	cfg.Server.JWTKey, cfg.Server.CSRFKey = jwtKey, csrfKey

	oidcStateKey, err := hkdf.Key(sha256.New, []byte(cfg.Server.SecretKey), nil, "gozone-oidc-state", 32)
	if err != nil {
		return nil, fmt.Errorf("derive oidc state key: %w", err)
	}
	cfg.Server.OIDCStateKey = oidcStateKey

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

	if cfg.Auth.MaxAPIKeysPerUser < 0 {
		return fmt.Errorf("invalid max_api_keys_per_user %d: must be non-negative (0 disables the cap)", cfg.Auth.MaxAPIKeysPerUser)
	}

	if cfg.Auth.IdleTimeoutMinutes < 0 {
		return fmt.Errorf("invalid auth.idle_timeout_minutes %d: must be non-negative", cfg.Auth.IdleTimeoutMinutes)
	}
	if cfg.Auth.AbsoluteSessionTimeoutHours < 0 {
		return fmt.Errorf("invalid auth.absolute_session_timeout_hours %d: must be non-negative", cfg.Auth.AbsoluteSessionTimeoutHours)
	}
	// An absolute cap shorter than the access-token TTL is contradictory: the
	// token would already be dead (or about to die) before the cap could ever
	// enable a refresh, and the absolute gate would just shorten the session
	// silently. Reject it so the operator's intent is surfaced loudly.
	if cfg.Auth.AbsoluteSessionTimeoutHours > 0 && cfg.Auth.AbsoluteSessionTimeoutHours < cfg.Auth.SessionDurationHours {
		return fmt.Errorf("invalid auth.absolute_session_timeout_hours %d: must be >= session_duration_hours (%d) for refresh to be meaningful",
			cfg.Auth.AbsoluteSessionTimeoutHours, cfg.Auth.SessionDurationHours)
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
	if cfg.Password.MaxLength < 0 || cfg.Password.MaxLength > 72 {
		return fmt.Errorf("invalid password.max_length %d: must be between 0 (disabled) and 72 (bcrypt's hard limit)", cfg.Password.MaxLength)
	}
	if cfg.Password.HistorySize < 0 {
		return fmt.Errorf("invalid password.history_size %d: must be non-negative", cfg.Password.HistorySize)
	}
	if cfg.Password.MaxAgeDays < 0 {
		return fmt.Errorf("invalid password.max_age_days %d: must be non-negative", cfg.Password.MaxAgeDays)
	}
	if cfg.Password.ExpiryWarnDays < 0 {
		return fmt.Errorf("invalid password.expiry_warn_days %d: must be non-negative", cfg.Password.ExpiryWarnDays)
	}
	if cfg.Password.MaxAgeDays > 0 && cfg.Password.ExpiryWarnDays >= cfg.Password.MaxAgeDays {
		return fmt.Errorf("invalid password.expiry_warn_days %d: must be less than max_age_days %d", cfg.Password.ExpiryWarnDays, cfg.Password.MaxAgeDays)
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

	// server.external_url: optional canonical base URL for OIDC redirect_uri
	// building (defense-in-depth against Host-header derivation). When set it
	// must be an absolute http(s) URL with a host and no path. Normalise to
	// "scheme://host" so callers can append root-anchored paths without
	// worrying about trailing slashes or stray path/query components.
	if cfg.Server.ExternalURL != "" {
		u, err := url.Parse(cfg.Server.ExternalURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("invalid server.external_url %q: must be an absolute http(s) URL with a host (e.g. %q)",
				cfg.Server.ExternalURL, "https://dns.example.com")
		}
		if p := u.Path; p != "" && p != "/" {
			return fmt.Errorf("invalid server.external_url %q: must not contain a path (scheme and host only)", cfg.Server.ExternalURL)
		}
		cfg.Server.ExternalURL = u.Scheme + "://" + u.Host
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

	if err := cfg.validateOIDC(); err != nil {
		return err
	}

	return nil
}

// validateOIDC checks the OIDC configuration. It only enforces constraints
// when SSO is enabled (or at least one provider is declared), so a default
// disabled config (empty providers, Enabled=false) is always accepted.
func (cfg *Config) validateOIDC() error {
	// Treat a non-empty providers list as an implicit enable so a config that
	// lists providers but omits "enabled: true" still validates the entries.
	declared := len(cfg.OIDC.Providers) > 0
	if !cfg.OIDC.Enabled && !declared {
		return nil
	}

	if cfg.OIDC.DefaultRole != "" {
		if err := validators.ValidateRole(cfg.OIDC.DefaultRole); err != nil {
			return fmt.Errorf("invalid oidc.default_role: %w", err)
		}
	} else {
		cfg.OIDC.DefaultRole = "user"
	}

	seen := make(map[string]bool, len(cfg.OIDC.Providers))
	for i := range cfg.OIDC.Providers {
		p := &cfg.OIDC.Providers[i]
		if p.Name == "" {
			return fmt.Errorf("invalid oidc.providers[%d].name: must not be empty", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("invalid oidc.providers[%d].name %q: duplicate provider name", i, p.Name)
		}
		seen[p.Name] = true
		if p.IssuerURL == "" {
			return fmt.Errorf("invalid oidc.providers[%d] (%s): issuer_url is required", i, p.Name)
		}
		u, err := url.Parse(p.IssuerURL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid oidc.providers[%d] (%s).issuer_url %q: must be an absolute URL with a host", i, p.Name, p.IssuerURL)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("invalid oidc.providers[%d] (%s).issuer_url %q: scheme must be http or https", i, p.Name, p.IssuerURL)
		}
		if p.ClientID == "" {
			return fmt.Errorf("invalid oidc.providers[%d] (%s): client_id is required", i, p.Name)
		}
		// ClientSecret is required for the confidential authorization-code flow.
		// Public clients (no secret, PKCE-only) are intentionally not supported
		// here because GoZone is a server-side app that can hold a secret.
		if p.ClientSecret == "" {
			return fmt.Errorf("invalid oidc.providers[%d] (%s): client_secret is required", i, p.Name)
		}
	}

	// enabled=true with no providers is a no-op footgun: surface it loudly.
	if cfg.OIDC.Enabled && len(cfg.OIDC.Providers) == 0 {
		return fmt.Errorf("oidc.enabled is true but no providers are configured")
	}

	// Role/group mapping sanity: a claim path with no mapped values is a no-op
	// footgun (AdminRoleValues empty means nobody is ever promoted; GroupMapping
	// empty means no memberships are synced). Surface these so an operator who
	// sets the claim but forgets the values is warned at startup.
	if cfg.OIDC.RoleClaim != "" && len(cfg.OIDC.AdminRoleValues) == 0 {
		return fmt.Errorf("oidc.role_claim %q is set but admin_role_values is empty", cfg.OIDC.RoleClaim)
	}
	if cfg.OIDC.GroupClaim != "" && len(cfg.OIDC.GroupMapping) == 0 {
		return fmt.Errorf("oidc.group_claim %q is set but group_mapping is empty", cfg.OIDC.GroupClaim)
	}
	if cfg.OIDC.JWKSCacheTTLMinutes < 0 {
		return fmt.Errorf("invalid oidc.jwks_cache_ttl_minutes %d: must be non-negative", cfg.OIDC.JWKSCacheTTLMinutes)
	}
	return nil
}

// envOverride is a single environment-variable override. The concrete types
// below (strOverride / intOverride / boolOverride / sliceOverride) carry the
// typed setter, so applyEnvOverrides reduces to a one-line loop over a static
// table instead of ~260 lines of repeated read/parse/assign boilerplate.
type envOverride interface {
	apply(*Config) error
}

type strOverride struct {
	env string
	set func(*Config, string)
}

func (o strOverride) apply(c *Config) error {
	if v := os.Getenv(o.env); v != "" {
		o.set(c, v)
	}
	return nil
}

type intOverride struct {
	env string
	set func(*Config, int)
}

func (o intOverride) apply(c *Config) error {
	if v := os.Getenv(o.env); v != "" {
		n, err := envInt(o.env, v)
		if err != nil {
			return err
		}
		o.set(c, n)
	}
	return nil
}

type boolOverride struct {
	env string
	set func(*Config, bool)
}

func (o boolOverride) apply(c *Config) error {
	if v := os.Getenv(o.env); v != "" {
		b, err := envBool(o.env, v)
		if err != nil {
			return err
		}
		o.set(c, b)
	}
	return nil
}

type sliceOverride struct {
	env string
	set func(*Config, []string)
}

func (o sliceOverride) apply(c *Config) error {
	if v := os.Getenv(o.env); v != "" {
		o.set(c, splitNonEmpty(v, ","))
	}
	return nil
}

// envOverrides is the static table of scalar GOZONE_* overrides. Each entry
// touches a distinct field, so order is irrelevant. An unparseable override
// (e.g. GOZONE_SERVER_PORT=abc) surfaces as a hard error via envInt/envBool so
// a typo fails config load loud-and-early instead of hiding the operator's
// intent; string overrides are accepted as-is since any non-empty value is
// valid for them. The OIDC single-provider block (declared from up to four
// GOZONE_OIDC_PROVIDER_* vars) is applied separately by applyOIDCProviderEnv
// after these scalars, because it is conditional on cfg.OIDC.Providers being
// empty.
var envOverrides = []envOverride{
	// server
	strOverride{"GOZONE_SERVER_HOST", func(c *Config, v string) { c.Server.Host = v }},
	intOverride{"GOZONE_SERVER_PORT", func(c *Config, n int) { c.Server.Port = n }},
	strOverride{"GOZONE_APP_NAME", func(c *Config, v string) { c.Server.AppName = v }},
	strOverride{"GOZONE_SECRET_KEY", func(c *Config, v string) { c.Server.SecretKey = v }},
	boolOverride{"GOZONE_SECURE_COOKIES", func(c *Config, b bool) { c.Server.SecureCookies = b }},
	strOverride{"GOZONE_EXTERNAL_URL", func(c *Config, v string) { c.Server.ExternalURL = v }},
	intOverride{"GOZONE_SHUTDOWN_TIMEOUT", func(c *Config, n int) { c.Server.ShutdownTimeoutSeconds = n }},
	sliceOverride{"GOZONE_TRUSTED_PROXIES", func(c *Config, v []string) { c.Server.TrustedProxies = v }},
	// database / powerdns
	strOverride{"GOZONE_DB_DRIVER", func(c *Config, v string) { c.Database.Driver = v }},
	strOverride{"GOZONE_DB_DSN", func(c *Config, v string) { c.Database.DSN = v }},
	strOverride{"GOZONE_PDNS_API_URL", func(c *Config, v string) { c.PowerDNS.APIURL = v }},
	strOverride{"GOZONE_PDNS_API_KEY", func(c *Config, v string) { c.PowerDNS.APIKey = v }},
	strOverride{"GOZONE_PDNS_SERVER_ID", func(c *Config, v string) { c.PowerDNS.ServerID = v }},
	// auth / admin / activity / login-lockout
	intOverride{"GOZONE_SESSION_DURATION", func(c *Config, n int) { c.Auth.SessionDurationHours = n }},
	intOverride{"GOZONE_IDLE_TIMEOUT_MINUTES", func(c *Config, n int) { c.Auth.IdleTimeoutMinutes = n }},
	intOverride{"GOZONE_ABSOLUTE_SESSION_TIMEOUT_HOURS", func(c *Config, n int) { c.Auth.AbsoluteSessionTimeoutHours = n }},
	intOverride{"GOZONE_MAX_API_KEYS", func(c *Config, n int) { c.Auth.MaxAPIKeysPerUser = n }},
	intOverride{"GOZONE_BCRYPT_COST", func(c *Config, n int) { c.Auth.BcryptCost = n }},
	strOverride{"GOZONE_ADMIN_USERNAME", func(c *Config, v string) { c.Admin.Username = v }},
	strOverride{"GOZONE_ADMIN_PASSWORD", func(c *Config, v string) { c.Admin.Password = v }},
	strOverride{"GOZONE_ADMIN_EMAIL", func(c *Config, v string) { c.Admin.Email = v }},
	strOverride{"GOZONE_ADMIN_FIRST_NAME", func(c *Config, v string) { c.Admin.FirstName = v }},
	strOverride{"GOZONE_ADMIN_LAST_NAME", func(c *Config, v string) { c.Admin.LastName = v }},
	intOverride{"GOZONE_ACTIVITY_RETENTION_DAYS", func(c *Config, n int) { c.Activity.RetentionDays = n }},
	intOverride{"GOZONE_ACTIVITY_BATCH_SIZE", func(c *Config, n int) { c.Activity.BatchSize = n }},
	intOverride{"GOZONE_LOGIN_MAX_FAILED_ATTEMPTS", func(c *Config, n int) { c.LoginLock.MaxFailedAttempts = n }},
	intOverride{"GOZONE_LOGIN_LOCKOUT_MINUTES", func(c *Config, n int) { c.LoginLock.LockoutDurationMinutes = n }},
	intOverride{"GOZONE_LOGIN_USERNAME_RATE_PER_MINUTE", func(c *Config, n int) { c.LoginLock.UsernameRateLimitPerMinute = n }},
	intOverride{"GOZONE_LOGIN_ATTEMPTS_RETENTION_HOURS", func(c *Config, n int) { c.LoginLock.AttemptsRetentionHours = n }},
	// password policy
	intOverride{"GOZONE_PASSWORD_MIN_LENGTH", func(c *Config, n int) { c.Password.MinLength = n }},
	intOverride{"GOZONE_PASSWORD_MAX_LENGTH", func(c *Config, n int) { c.Password.MaxLength = n }},
	intOverride{"GOZONE_PASSWORD_HISTORY_SIZE", func(c *Config, n int) { c.Password.HistorySize = n }},
	boolOverride{"GOZONE_PASSWORD_REQUIRE_UPPERCASE", func(c *Config, b bool) { c.Password.RequireUppercase = b }},
	boolOverride{"GOZONE_PASSWORD_REQUIRE_LOWERCASE", func(c *Config, b bool) { c.Password.RequireLowercase = b }},
	boolOverride{"GOZONE_PASSWORD_REQUIRE_DIGIT", func(c *Config, b bool) { c.Password.RequireDigit = b }},
	boolOverride{"GOZONE_PASSWORD_REQUIRE_SPECIAL", func(c *Config, b bool) { c.Password.RequireSpecial = b }},
	intOverride{"GOZONE_PASSWORD_MAX_AGE_DAYS", func(c *Config, n int) { c.Password.MaxAgeDays = n }},
	intOverride{"GOZONE_PASSWORD_EXPIRY_WARN_DAYS", func(c *Config, n int) { c.Password.ExpiryWarnDays = n }},
	// logging — the only way to raise the level during an incident on a
	// containerised deployment without mounting a config file
	strOverride{"GOZONE_LOG_LEVEL", func(c *Config, v string) { c.Logging.Level = v }},
	// OIDC scalar toggles (single-provider block handled by applyOIDCProviderEnv)
	boolOverride{"GOZONE_OIDC_ENABLED", func(c *Config, b bool) { c.OIDC.Enabled = b }},
	boolOverride{"GOZONE_OIDC_ALLOW_LOCAL_LOGIN", func(c *Config, b bool) { c.OIDC.AllowLocalLogin = b }},
	boolOverride{"GOZONE_OIDC_AUTO_PROVISION", func(c *Config, b bool) { c.OIDC.AutoProvision = b }},
	boolOverride{"GOZONE_OIDC_REQUIRE_VERIFIED_EMAIL", func(c *Config, b bool) { c.OIDC.RequireVerifiedEmail = b }},
	strOverride{"GOZONE_OIDC_DEFAULT_ROLE", func(c *Config, v string) { c.OIDC.DefaultRole = v }},
	sliceOverride{"GOZONE_OIDC_SCOPES", func(c *Config, v []string) { c.OIDC.Scopes = v }},
	strOverride{"GOZONE_OIDC_ROLE_CLAIM", func(c *Config, v string) { c.OIDC.RoleClaim = v }},
	sliceOverride{"GOZONE_OIDC_ADMIN_ROLE_VALUES", func(c *Config, v []string) { c.OIDC.AdminRoleValues = v }},
	strOverride{"GOZONE_OIDC_GROUP_CLAIM", func(c *Config, v string) { c.OIDC.GroupClaim = v }},
	intOverride{"GOZONE_OIDC_JWKS_CACHE_TTL_MINUTES", func(c *Config, n int) { c.OIDC.JWKSCacheTTLMinutes = n }},
}

// applyEnvOverrides overlays GOZONE_-prefixed environment variables on top of
// the YAML-provided config by dispatching through the envOverrides table.
func applyEnvOverrides(cfg *Config) error {
	for _, o := range envOverrides {
		if err := o.apply(cfg); err != nil {
			return err
		}
	}
	return applyOIDCProviderEnv(cfg)
}

// applyOIDCProviderEnv declares a single OIDC provider entirely from env vars
// (GOZONE_OIDC_PROVIDER_NAME/ISSUER_URL/CLIENT_ID/CLIENT_SECRET) for
// containerised deployments that configure one IdP without mounting a config
// file; additional providers require YAML. It only takes effect when no
// providers are already declared in YAML, so a file-declared multi-provider
// setup is never partially overwritten.
func applyOIDCProviderEnv(cfg *Config) error {
	if len(cfg.OIDC.Providers) != 0 {
		return nil
	}
	name := os.Getenv("GOZONE_OIDC_PROVIDER_NAME")
	issuer := os.Getenv("GOZONE_OIDC_ISSUER_URL")
	clientID := os.Getenv("GOZONE_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("GOZONE_OIDC_CLIENT_SECRET")
	if name != "" || issuer != "" || clientID != "" || clientSecret != "" {
		cfg.OIDC.Providers = append(cfg.OIDC.Providers, OIDCProviderConfig{
			Name:         name,
			IssuerURL:    issuer,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
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
//
// With sha256 and a 32-byte output the expansion cannot fail in practice —
// HKDF-SHA256 only errors on programming mistakes (nil hash, illegal length) —
// but returning the error (instead of panicking, REVIEW.md I-7) keeps this
// consistent with the rest of Load, which reports errors rather than aborting.
func deriveKeys(master []byte) (jwtKey, csrfKey []byte, err error) {
	jwtKey, err = hkdf.Key(sha256.New, master, nil, "gozone-jwt", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("derive jwt key: %w", err)
	}
	csrfKey, err = hkdf.Key(sha256.New, master, nil, "gozone-csrf", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("derive csrf key: %w", err)
	}
	return jwtKey, csrfKey, nil
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

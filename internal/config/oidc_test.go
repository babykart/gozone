package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSecret = "mysecret-mysecret-mysecret-mysecret" // >= minSecretKeyLength

func TestOIDCDefaultDisabled(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.OIDC.Enabled {
		t.Error("OIDC must default to disabled")
	}
	if !cfg.OIDC.AllowLocalLogin {
		t.Error("allow_local_login must default to true")
	}
	if cfg.OIDC.AutoProvision {
		t.Error("auto_provision must default to false")
	}
	if cfg.OIDC.DefaultRole != "user" {
		t.Errorf("default_role default = %q, want user", cfg.OIDC.DefaultRole)
	}
}

func TestOIDCValidateOK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Providers = []OIDCProviderConfig{
		{Name: "gitea", IssuerURL: "https://gitea.example.com", ClientID: "cid", ClientSecret: "sec"},
	}
	if err := cfg.validateOIDC(); err != nil {
		t.Fatalf("valid OIDC config rejected: %v", err)
	}
}

func TestOIDCValidateEnabledNoProviders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	err := cfg.validateOIDC()
	if err == nil || !strings.Contains(err.Error(), "no providers") {
		t.Fatalf("expected 'no providers' error, got %v", err)
	}
}

func TestOIDCValidateDuplicateProviderName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Providers = []OIDCProviderConfig{
		{Name: "gitea", IssuerURL: "https://gitea.example.com", ClientID: "cid", ClientSecret: "sec"},
		{Name: "gitea", IssuerURL: "https://gitea2.example.com", ClientID: "cid2", ClientSecret: "sec2"},
	}
	err := cfg.validateOIDC()
	if err == nil || !strings.Contains(err.Error(), "duplicate provider name") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestOIDCValidateMissingFields(t *testing.T) {
	tests := []struct {
		name    string
		p       OIDCProviderConfig
		wantErr string
	}{
		{"empty name", OIDCProviderConfig{Name: "", IssuerURL: "https://x", ClientID: "c", ClientSecret: "s"}, "name"},
		{"empty issuer", OIDCProviderConfig{Name: "gitea", IssuerURL: "", ClientID: "c", ClientSecret: "s"}, "issuer_url"},
		{"bad issuer scheme", OIDCProviderConfig{Name: "gitea", IssuerURL: "ftp://x", ClientID: "c", ClientSecret: "s"}, "scheme"},
		{"empty client_id", OIDCProviderConfig{Name: "gitea", IssuerURL: "https://x", ClientID: "", ClientSecret: "s"}, "client_id"},
		{"empty client_secret", OIDCProviderConfig{Name: "gitea", IssuerURL: "https://x", ClientID: "c", ClientSecret: ""}, "client_secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.OIDC.Enabled = true
			cfg.OIDC.Providers = []OIDCProviderConfig{tt.p}
			err := cfg.validateOIDC()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestOIDCValidateBadDefaultRole(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.DefaultRole = "superadmin"
	cfg.OIDC.Providers = []OIDCProviderConfig{
		{Name: "gitea", IssuerURL: "https://gitea.example.com", ClientID: "cid", ClientSecret: "sec"},
	}
	err := cfg.validateOIDC()
	if err == nil || !strings.Contains(err.Error(), "default_role") {
		t.Fatalf("expected default_role error, got %v", err)
	}
}

func TestOIDCValidateRoleClaimWithoutAdminValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.RoleClaim = "groups"
	cfg.OIDC.Providers = []OIDCProviderConfig{
		{Name: "gitea", IssuerURL: "https://gitea.example.com", ClientID: "cid", ClientSecret: "sec"},
	}
	err := cfg.validateOIDC()
	if err == nil || !strings.Contains(err.Error(), "admin_role_values") {
		t.Fatalf("expected admin_role_values error, got %v", err)
	}
}

func TestOIDCValidateGroupClaimWithoutMapping(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.GroupClaim = "groups"
	cfg.OIDC.Providers = []OIDCProviderConfig{
		{Name: "gitea", IssuerURL: "https://gitea.example.com", ClientID: "cid", ClientSecret: "sec"},
	}
	err := cfg.validateOIDC()
	if err == nil || !strings.Contains(err.Error(), "group_mapping") {
		t.Fatalf("expected group_mapping error, got %v", err)
	}
}

func TestOIDCValidateRoleAndGroupMappingOK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDC.Enabled = true
	cfg.OIDC.RoleClaim = "groups"
	cfg.OIDC.AdminRoleValues = []string{"admins"}
	cfg.OIDC.GroupClaim = "groups"
	cfg.OIDC.GroupMapping = map[string]string{"devs": "developers"}
	cfg.OIDC.Providers = []OIDCProviderConfig{
		{Name: "gitea", IssuerURL: "https://gitea.example.com", ClientID: "cid", ClientSecret: "sec"},
	}
	if err := cfg.validateOIDC(); err != nil {
		t.Fatalf("valid role+group mapping rejected: %v", err)
	}
}

func TestOIDCRoleGroupEnvOverrides(t *testing.T) {
	t.Setenv("GOZONE_SECRET_KEY", testSecret)
	t.Setenv("GOZONE_OIDC_ENABLED", "true")
	t.Setenv("GOZONE_OIDC_ROLE_CLAIM", "realm_access.roles")
	t.Setenv("GOZONE_OIDC_ADMIN_ROLE_VALUES", "admins, super-admins")
	t.Setenv("GOZONE_OIDC_PROVIDER_NAME", "keycloak")
	t.Setenv("GOZONE_OIDC_ISSUER_URL", "https://kc.example.com")
	t.Setenv("GOZONE_OIDC_CLIENT_ID", "cid")
	t.Setenv("GOZONE_OIDC_CLIENT_SECRET", "sec")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.OIDC.RoleClaim != "realm_access.roles" {
		t.Errorf("RoleClaim = %q", cfg.OIDC.RoleClaim)
	}
	if len(cfg.OIDC.AdminRoleValues) != 2 || cfg.OIDC.AdminRoleValues[1] != "super-admins" {
		t.Errorf("AdminRoleValues = %v", cfg.OIDC.AdminRoleValues)
	}
	// group_claim is YAML-only (group_mapping cannot be expressed in env), so
	// it is exercised via the YAML/validate tests instead.
}

// TestOIDCValidateDisabledSkipped ensures a disabled config (the default) is
// always accepted even with malformed providers — validation is inert when SSO
// is off and no providers are declared.
func TestOIDCValidateDisabledSkipped(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.validateOIDC(); err != nil {
		t.Fatalf("default disabled config must validate, got %v", err)
	}
}

func TestOIDCEnvOverridesSingleProvider(t *testing.T) {
	t.Setenv("GOZONE_SECRET_KEY", testSecret)
	t.Setenv("GOZONE_OIDC_ENABLED", "true")
	t.Setenv("GOZONE_OIDC_ALLOW_LOCAL_LOGIN", "false")
	t.Setenv("GOZONE_OIDC_AUTO_PROVISION", "yes")
	t.Setenv("GOZONE_OIDC_DEFAULT_ROLE", "user")
	t.Setenv("GOZONE_OIDC_SCOPES", "openid,profile,email,groups")
	t.Setenv("GOZONE_OIDC_PROVIDER_NAME", "gitea")
	t.Setenv("GOZONE_OIDC_ISSUER_URL", "https://gitea.example.com")
	t.Setenv("GOZONE_OIDC_CLIENT_ID", "cid")
	t.Setenv("GOZONE_OIDC_CLIENT_SECRET", "sec")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !cfg.OIDC.Enabled {
		t.Error("OIDC.Enabled should be true")
	}
	if cfg.OIDC.AllowLocalLogin {
		t.Error("AllowLocalLogin should be false")
	}
	if !cfg.OIDC.AutoProvision {
		t.Error("AutoProvision should be true")
	}
	if len(cfg.OIDC.Scopes) != 4 || cfg.OIDC.Scopes[3] != "groups" {
		t.Errorf("unexpected scopes: %v", cfg.OIDC.Scopes)
	}
	if len(cfg.OIDC.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(cfg.OIDC.Providers))
	}
	p := cfg.OIDC.Providers[0]
	if p.Name != "gitea" || p.IssuerURL != "https://gitea.example.com" ||
		p.ClientID != "cid" || p.ClientSecret != "sec" {
		t.Errorf("unexpected provider config: %+v", p)
	}
}

func TestOIDCEnvOverridesInvalidBool(t *testing.T) {
	t.Setenv("GOZONE_SECRET_KEY", testSecret)
	t.Setenv("GOZONE_OIDC_ENABLED", "maybe")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for invalid OIDC_ENABLED boolean")
	}
}

func TestOIDCStateKeyDerived(t *testing.T) {
	t.Setenv("GOZONE_SECRET_KEY", testSecret)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Server.OIDCStateKey) != 32 {
		t.Errorf("OIDCStateKey length = %d, want 32", len(cfg.Server.OIDCStateKey))
	}
	// The state key must be independent of the JWT and CSRF keys.
	if string(cfg.Server.OIDCStateKey) == string(cfg.Server.JWTKey) {
		t.Error("OIDCStateKey must differ from JWTKey")
	}
	if string(cfg.Server.OIDCStateKey) == string(cfg.Server.CSRFKey) {
		t.Error("OIDCStateKey must differ from CSRFKey")
	}
}

func TestSessionPolicyEnvOverrides(t *testing.T) {
	t.Setenv("GOZONE_SECRET_KEY", testSecret)
	t.Setenv("GOZONE_IDLE_TIMEOUT_MINUTES", "15")
	t.Setenv("GOZONE_ABSOLUTE_SESSION_TIMEOUT_HOURS", "48")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Auth.IdleTimeoutMinutes != 15 {
		t.Errorf("IdleTimeoutMinutes = %d, want 15", cfg.Auth.IdleTimeoutMinutes)
	}
	if cfg.Auth.AbsoluteSessionTimeoutHours != 48 {
		t.Errorf("AbsoluteSessionTimeoutHours = %d, want 48", cfg.Auth.AbsoluteSessionTimeoutHours)
	}
}

func TestSessionPolicyRejectsNegative(t *testing.T) {
	t.Setenv("GOZONE_SECRET_KEY", testSecret)
	t.Setenv("GOZONE_IDLE_TIMEOUT_MINUTES", "-5")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for negative idle_timeout_minutes")
	}
}

func TestSessionPolicyAbsoluteMustExceedSessionDuration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  secret_key: ` + testSecret + `
powerdns:
  api_url: http://localhost:8081
  api_key: changeme
  server_id: localhost
auth:
  session_duration_hours: 24
  absolute_session_timeout_hours: 12
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "absolute_session_timeout_hours") {
		t.Fatalf("expected absolute < session_duration error, got %v", err)
	}
}

func TestOIDCLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Use a placeholder secret so Load auto-generates a strong key (and thus
	// derives OIDCStateKey correctly); validation passes because OIDC is off.
	yaml := `
server:
  secret_key: ` + testSecret + `
powerdns:
  api_url: http://localhost:8081
  api_key: changeme
  server_id: localhost
oidc:
  enabled: true
  auto_provision: true
  providers:
    - name: gitea
      issuer_url: https://gitea.example.com
      client_id: cid
      client_secret: sec
    - name: google
      issuer_url: https://accounts.google.com
      client_id: gcid
      client_secret: gsec
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !cfg.OIDC.Enabled {
		t.Error("OIDC.Enabled should be true")
	}
	if !cfg.OIDC.AutoProvision {
		t.Error("AutoProvision should be true")
	}
	if len(cfg.OIDC.Providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(cfg.OIDC.Providers))
	}
	if cfg.OIDC.Providers[0].Name != "gitea" {
		t.Errorf("first provider = %q, want gitea", cfg.OIDC.Providers[0].Name)
	}
}

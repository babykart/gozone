package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/oidc"
)

func TestOIDCLogin_DisabledRedirectsToLogin(t *testing.T) {
	h := newTestHandler(t)
	h.OIDC = nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/gitea/login", nil)
	r.SetPathValue("provider", "gitea")
	h.OIDCLogin(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login?error=sso_error" {
		t.Errorf("expected /login?error=sso_error, got %q", loc)
	}
}

func TestOIDCCallback_DisabledRedirectsToLogin(t *testing.T) {
	h := newTestHandler(t)
	h.OIDC = nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/gitea/callback?code=x&state=y", nil)
	r.SetPathValue("provider", "gitea")
	h.OIDCCallback(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login?error=sso_error" {
		t.Errorf("expected /login?error=sso_error, got %q", loc)
	}
}

func TestOIDCCallback_MissingParams(t *testing.T) {
	h := newTestHandler(t)
	// A service with a provider is needed for the handler to pass the Enabled()
	// gate; a fake stands in for the real discovered service (no live IdP in
	// unit tests). The handler errors out before reaching HandleCallback.
	h.OIDC = &fakeSSOService{providers: []*oidc.ProviderInstance{
		{Name: "gitea", DisplayName: "Gitea", Icon: "gitea"},
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/gitea/callback", nil)
	r.SetPathValue("provider", "gitea")
	h.OIDCCallback(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login?error=sso_error" {
		t.Errorf("missing params should redirect to error, got %q", loc)
	}
}

func TestDeriveSSOUsername(t *testing.T) {
	tests := []struct {
		name        string
		preferred   string
		subject     string
		wantPrefix  string
		mustBeValid bool
	}{
		{name: "valid preferred", preferred: "alice", subject: "sub", wantPrefix: "alice"},
		{name: "needs sanitizing", preferred: "Alice.Doe_99", subject: "sub", wantPrefix: "alice.doe_99"},
		{name: "starts with digit gets prefix", preferred: "2fast", subject: "sub", wantPrefix: "u2fast"},
		{name: "empty preferred uses subject hash", preferred: "", subject: "", wantPrefix: "sso-"},
		{name: "invalid chars replaced", preferred: "a@b c", subject: "sub", wantPrefix: "a-b-c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveSSOUsername(tt.preferred, tt.subject)
			if len(got) < 3 || len(got) > 32 {
				t.Errorf("username %q length %d out of [3,32]", got, len(got))
			}
			if tt.wantPrefix != "" && len(got) < len(tt.wantPrefix) {
				t.Errorf("username %q shorter than prefix %q", got, tt.wantPrefix)
			}
		})
	}
}

func TestSplitName(t *testing.T) {
	tests := []struct {
		in              string
		wantFirst, last string
	}{
		{"", "", ""},
		{"Alice", "Alice", ""},
		{"Alice Smith", "Alice", "Smith"},
		{"Alice Marie Smith", "Alice Marie", "Smith"},
		{"  John   Q   Public  ", "John Q", "Public"},
	}
	for _, tt := range tests {
		first, last := splitName(tt.in)
		if first != tt.wantFirst || last != tt.last {
			t.Errorf("splitName(%q) = (%q,%q), want (%q,%q)", tt.in, first, last, tt.wantFirst, tt.last)
		}
	}
}

func TestOidcCallbackURL(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/gitea/callback", nil)
	r.Host = "gozone.example.com"
	got := oidcCallbackURL(r, "gitea")
	want := "http://gozone.example.com/auth/oidc/gitea/callback"
	if got != want {
		t.Errorf("oidcCallbackURL = %q, want %q", got, want)
	}
}

func TestIssueSSOSessionSetsCookieAndLogs(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.Server.JWTKey = []byte("test-jwt-signing-key-for-sso-test!")
	ctx := context.Background()
	user, err := h.DB.CreateExternalUser(ctx, "ssoalice", "ssoalice@example.com", "Alice", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := h.issueSSOSession(w, r, user, "iss"); err != nil {
		t.Fatalf("issueSSOSession: %v", err)
	}
	cookieFound := false
	for _, c := range w.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			cookieFound = true
			if c.Value == "" {
				t.Error("session cookie value is empty")
			}
		}
	}
	if !cookieFound {
		t.Error("expected gozone_session cookie to be set")
	}
	var n int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='sso_login'").Scan(&n); err != nil {
		t.Fatalf("count activity: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 sso_login activity log, got %d", n)
	}
}

func TestResolveSSOUser_ExistingLink(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	user, err := h.DB.CreateExternalUser(ctx, "linked", "linked@example.com", "", "", "user",
		"https://idp.example.com", "sub-1")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	claims := &oidc.Claims{Issuer: "https://idp.example.com", Subject: "sub-1"}
	got, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		t.Fatalf("resolveSSOUser: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("expected existing linked user %d, got %d", user.ID, got.ID)
	}
}

func TestResolveSSOUser_NoProvisioning(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = false
	ctx := context.Background()
	claims := &oidc.Claims{Issuer: "https://idp.example.com", Subject: "unknown"}
	_, err := h.resolveSSOUser(ctx, claims)
	if err == nil {
		t.Error("expected error when auto_provision disabled and no link")
	}
}

func TestResolveSSOUser_EmailLinkVerified(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = true
	ctx := context.Background()
	// Pre-create a local-style user with a known email. Use a bcrypt hash so
	// it is a normal local account.
	_, err := h.DB.ExecContext(ctx,
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, 1)`,
		"localuser", "local@example.com", "$2a$04$placeholderhashplaceholderhashplaceholderhashplaceholde", "user")
	if err != nil {
		t.Fatalf("insert local user: %v", err)
	}
	claims := &oidc.Claims{
		Issuer: "https://idp.example.com", Subject: "sub-new",
		Email: "local@example.com", EmailVerified: true,
	}
	got, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		t.Fatalf("resolveSSOUser: %v", err)
	}
	if got.Email != "local@example.com" {
		t.Errorf("expected email-linked user, got %+v", got)
	}
	// Identity must now be linked.
	linked, err := h.DB.FindUserByExternalIdentity(ctx, claims.Issuer, claims.Subject)
	if err != nil {
		t.Fatalf("FindUserByExternalIdentity: %v", err)
	}
	if linked == nil || linked.ID != got.ID {
		t.Errorf("identity not linked: %+v", linked)
	}
}

func TestResolveSSOUser_ProvisionNew(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = true
	h.Cfg.OIDC.DefaultRole = "user"
	ctx := context.Background()
	claims := &oidc.Claims{
		Issuer: "https://idp.example.com", Subject: "sub-prov",
		Email: "new@example.com", EmailVerified: false,
		PreferredUsername: "newbie", Name: "New Bie",
	}
	got, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		t.Fatalf("resolveSSOUser: %v", err)
	}
	if got.Username != "newbie" {
		t.Errorf("expected username newbie, got %q", got.Username)
	}
	if got.Role != "user" {
		t.Errorf("expected role user, got %q", got.Role)
	}
	if got.FirstName != "New" || got.LastName != "Bie" {
		t.Errorf("expected New/Bie, got %q/%q", got.FirstName, got.LastName)
	}
}

func TestOIDCCallback_FullFlowProvisionsAndRedirects(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.Server.JWTKey = []byte("test-jwt-signing-key-for-sso-flow!")
	h.Cfg.OIDC.AutoProvision = true
	h.Cfg.OIDC.DefaultRole = "user"
	h.OIDC = &fakeSSOService{
		providers: []*oidc.ProviderInstance{{Name: "gitea", DisplayName: "Gitea", Icon: "gitea"}},
		claims: &oidc.Claims{
			Issuer: "https://gitea.example.com", Subject: "gitea-sub-1",
			Email: "flow@example.com", EmailVerified: true,
			PreferredUsername: "flowuser", Name: "Flow User",
		},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"/auth/oidc/gitea/callback?code=abc&state=xyz", nil)
	r.SetPathValue("provider", "gitea")
	r.Host = "gozone.test"
	h.OIDCCallback(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %q", loc)
	}
	// Session cookie set.
	cookieFound := false
	for _, c := range w.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			cookieFound = true
		}
	}
	if !cookieFound {
		t.Error("expected gozone_session cookie after SSO callback")
	}
	// User provisioned.
	var n int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='flowuser'").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected provisioned user flowuser, got count %d", n)
	}
}

func TestLoginPageRendersSSOProviders(t *testing.T) {
	h := newTestHandler(t)
	h.OIDC = &fakeSSOService{providers: []*oidc.ProviderInstance{
		{Name: "gitea", DisplayName: "Gitea", Icon: "gitea"},
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	h.LoginPage(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// fakeSSOService is a test double for SSOService. It implements just enough of
// the contract (Enabled/Providers) to exercise handler branches without a live
// identity provider. AuthCodeURL/HandleCallback are wired for completeness.
type fakeSSOService struct {
	providers []*oidc.ProviderInstance
	claims    *oidc.Claims
	err       error
}

func (f *fakeSSOService) Enabled() bool                       { return len(f.providers) > 0 }
func (f *fakeSSOService) Providers() []*oidc.ProviderInstance { return f.providers }
func (f *fakeSSOService) AuthCodeURL(provider, _ string) (string, error) {
	return "https://idp.example.com/auth?provider=" + provider, nil
}
func (f *fakeSSOService) HandleCallback(_ context.Context, _, _, _, _ string) (*oidc.Claims, error) {
	return f.claims, f.err
}

// Ensure the models import is used by referencing the User type.
var _ = models.User{}
var _ = middleware.IsHTTPS

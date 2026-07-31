package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	got := oidcCallbackURL("", r, "gitea")
	want := "http://gozone.example.com/auth/oidc/gitea/callback"
	if got != want {
		t.Errorf("oidcCallbackURL (derived) = %q, want %q", got, want)
	}

	// When external_url is set it is used verbatim as the base, ignoring the
	// client-controlled Host header (defense-in-depth, see server.external_url).
	got = oidcCallbackURL("https://dns.example.com", r, "gitea")
	want = "https://dns.example.com/auth/oidc/gitea/callback"
	if got != want {
		t.Errorf("oidcCallbackURL (external_url) = %q, want %q", got, want)
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

// rawClaim builds a single-key raw claim map for OIDC claims used in tests.
func rawClaim(key string, values ...string) map[string]json.RawMessage {
	arr := make([]string, len(values))
	for i, v := range values {
		arr[i] = "\"" + v + "\""
	}
	body := "[" + strings.Join(arr, ",") + "]"
	return map[string]json.RawMessage{key: json.RawMessage(body)}
}

func TestResolveSSOUser_RoleMappingPromotesToAdmin(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = true
	h.Cfg.OIDC.DefaultRole = "user"
	h.Cfg.OIDC.RoleClaim = "groups"
	h.Cfg.OIDC.AdminRoleValues = []string{"admins", "super-admins"}
	ctx := context.Background()
	claims := &oidc.Claims{
		Issuer: "https://idp.example.com", Subject: "sub-role",
		Email: "role@example.com", EmailVerified: false,
		PreferredUsername: "roleuser",
		Raw:               rawClaim("groups", "devs", "admins"),
	}
	user, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		t.Fatalf("resolveSSOUser: %v", err)
	}
	if user.Role != "admin" {
		t.Errorf("expected admin role from group mapping, got %q", user.Role)
	}
}

func TestResolveSSOUser_RoleMappingDefaultWhenNoMatch(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = true
	h.Cfg.OIDC.DefaultRole = "user"
	h.Cfg.OIDC.RoleClaim = "groups"
	h.Cfg.OIDC.AdminRoleValues = []string{"admins"}
	ctx := context.Background()
	claims := &oidc.Claims{
		Issuer: "https://idp.example.com", Subject: "sub-role2",
		Email: "role2@example.com", EmailVerified: false,
		PreferredUsername: "roleuser2",
		Raw:               rawClaim("groups", "devs"),
	}
	user, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		t.Fatalf("resolveSSOUser: %v", err)
	}
	if user.Role != "user" {
		t.Errorf("expected user role, got %q", user.Role)
	}
}

func TestResolveSSOUser_ExistingUserRoleSync(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = true
	h.Cfg.OIDC.RoleClaim = "groups"
	h.Cfg.OIDC.AdminRoleValues = []string{"admins"}
	ctx := context.Background()
	// Provision a user first as a regular user.
	first, err := h.DB.CreateExternalUser(ctx, "syncer", "sync@example.com", "", "", "user",
		"https://idp.example.com", "sub-sync")
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if first.Role != "user" {
		t.Fatalf("setup: expected user, got %q", first.Role)
	}
	// Second login with an admin-group claim must promote the existing user.
	claims := &oidc.Claims{
		Issuer: "https://idp.example.com", Subject: "sub-sync",
		Raw: rawClaim("groups", "admins"),
	}
	got, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		t.Fatalf("resolveSSOUser: %v", err)
	}
	if got.ID != first.ID {
		t.Fatalf("expected same user %d, got %d", first.ID, got.ID)
	}
	if got.Role != "admin" {
		t.Errorf("expected promoted role admin, got %q", got.Role)
	}
	// Persisted in DB too.
	var role string
	if err := h.DB.QueryRow("SELECT role FROM users WHERE id = ?", first.ID).Scan(&role); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if role != "admin" {
		t.Errorf("expected persisted role admin, got %q", role)
	}
}

func TestResolveSSOUser_GroupMappingAddsMembership(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = true
	h.Cfg.OIDC.GroupClaim = "groups"
	h.Cfg.OIDC.GroupMapping = map[string]string{"dev-team": "developers"}
	ctx := context.Background()
	// Pre-create the target zone group.
	res, err := h.DB.ExecContext(ctx,
		"INSERT INTO zone_groups (name, description) VALUES (?, ?)", "developers", "")
	if err != nil {
		t.Fatalf("insert group: %v", err)
	}
	gid, _ := res.LastInsertId()

	claims := &oidc.Claims{
		Issuer: "https://idp.example.com", Subject: "sub-grp",
		Email: "grp@example.com", EmailVerified: false,
		PreferredUsername: "grpuser",
		Raw:               rawClaim("groups", "dev-team", "unmapped"),
	}
	user, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		t.Fatalf("resolveSSOUser: %v", err)
	}
	var n int
	if err := h.DB.QueryRow(
		"SELECT COUNT(*) FROM zone_group_members WHERE group_id = ? AND user_id = ?",
		gid, user.ID).Scan(&n); err != nil {
		t.Fatalf("count members: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 membership, got %d", n)
	}
}

func TestResolveSSOUser_GroupMappingSkipsMissingGroup(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.OIDC.AutoProvision = true
	h.Cfg.OIDC.GroupClaim = "groups"
	h.Cfg.OIDC.GroupMapping = map[string]string{"dev-team": "does-not-exist"}
	ctx := context.Background()
	claims := &oidc.Claims{
		Issuer: "https://idp.example.com", Subject: "sub-grp2",
		Email: "grp2@example.com", EmailVerified: false,
		PreferredUsername: "grpuser2",
		Raw:               rawClaim("groups", "dev-team"),
	}
	if _, err := h.resolveSSOUser(ctx, claims); err != nil {
		t.Fatalf("resolveSSOUser should not fail when target group missing: %v", err)
	}
}

func TestLogout_RPInitiatedForSSOSession(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.Server.JWTKey = []byte("test-jwt-signing-key-for-rp-logout!")
	h.OIDC = &fakeSSOService{
		providers:  []*oidc.ProviderInstance{{Name: "gitea", DisplayName: "Gitea", Icon: "gitea"}},
		endSession: "https://idp.example.com/logout",
	}
	ctx := context.Background()
	user, err := h.DB.CreateExternalUser(ctx, "rpuser", "rp@example.com", "", "", "user", "iss", "sub")
	if err != nil {
		t.Fatalf("CreateExternalUser: %v", err)
	}
	// Establish an SSO session (sets the cookie + AuthProvider=gitea).
	w0 := httptest.NewRecorder()
	r0 := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := h.issueSSOSession(w0, r0, user, "gitea"); err != nil {
		t.Fatalf("issueSSOSession: %v", err)
	}
	var sessionCookie *http.Cookie
	for _, c := range w0.Result().Cookies() {
		if c.Name == constants.SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected a session cookie")
	}

	// POST /logout with that cookie → must redirect to the IdP end_session URL.
	// Inject the user into the context to mirror the Auth middleware (the real
	// Logout route runs behind it).
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(sessionCookie)
	r.Host = "gozone.test"
	r = r.WithContext(context.WithValue(r.Context(), middleware.UserContextKey, user))
	h.Logout(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.example.com/logout") {
		t.Errorf("expected redirect to IdP end_session, got %q", loc)
	}
	if !strings.Contains(loc, "post_logout_redirect_uri=") {
		t.Errorf("expected post_logout_redirect_uri param, got %q", loc)
	}
	// Token revoked.
	var revoked int
	h.DB.QueryRow("SELECT COUNT(*) FROM revoked_tokens").Scan(&revoked)
	if revoked != 1 {
		t.Errorf("expected 1 revoked token, got %d", revoked)
	}
}

func TestLogout_LocalSessionSkipsRPLogout(t *testing.T) {
	h := newTestHandler(t)
	h.Cfg.Server.JWTKey = []byte("test-jwt-signing-key-for-local-logout!")
	h.OIDC = &fakeSSOService{
		providers:  []*oidc.ProviderInstance{{Name: "gitea", DisplayName: "Gitea", Icon: "gitea"}},
		endSession: "https://idp.example.com/logout",
	}
	// A local-login session: AuthProvider empty (GenerateToken path).
	user := &models.User{ID: 1, Username: "local", Role: "user"}
	token, err := middleware.GenerateToken(user, h.Cfg.Server.JWTKey, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: token})
	h.Logout(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("local logout must redirect to /login, got %q", loc)
	}
}

// fakeSSOService is a test double for SSOService. It implements just enough of
// the contract (Enabled/Providers) to exercise handler branches without a live
// identity provider. AuthCodeURL/HandleCallback are wired for completeness.
type fakeSSOService struct {
	providers  []*oidc.ProviderInstance
	claims     *oidc.Claims
	err        error
	endSession string
}

func (f *fakeSSOService) Enabled() bool                       { return len(f.providers) > 0 }
func (f *fakeSSOService) Providers() []*oidc.ProviderInstance { return f.providers }
func (f *fakeSSOService) AuthCodeURL(provider, _ string) (string, error) {
	return "https://idp.example.com/auth?provider=" + provider, nil
}
func (f *fakeSSOService) HandleCallback(_ context.Context, _, _, _, _ string) (*oidc.Claims, error) {
	return f.claims, f.err
}
func (f *fakeSSOService) EndSessionURL(provider string) string {
	if f.endSession == "" {
		return ""
	}
	return f.endSession + "?provider=" + provider
}

// Ensure the models import is used by referencing the User type.
var _ = models.User{}
var _ = middleware.IsHTTPS

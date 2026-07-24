package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/babykart/gozone/internal/config"
)

// integrationStateKey is the HMAC key used to sign/verify state tokens in the
// integration tests (kept in sync with the key used by newTestService).
const integrationStateKey = "test-state-key-32-bytes-long-0000"

// fakeIdP is a minimal OIDC provider used to exercise NewService discovery and
// the full HandleCallback flow end-to-end without an external identity
// provider. It serves a discovery document, a JWKS endpoint, and a token
// endpoint that mints a signed id_token carrying a configurable nonce. The
// discovery's issuer is the server's base URL, which coreos/go-oidc requires to
// match the configured IssuerURL exactly.
type fakeIdP struct {
	srv      *httptest.Server
	priv     *rsa.PrivateKey
	jwksBody []byte
	kid      string
	issuer   string
	clientID string

	mu        sync.Mutex
	nonce     string // nonce embedded in the minted id_token
	omitToken bool   // when true, /token omits the id_token
	tokenFail bool   // when true, /token returns 500
}

func newFakeIdP(t *testing.T, clientID string) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "integration-kid"
	privJWK := jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: "RS256", Use: "sig"}
	pubJWK := privJWK.Public()
	jwksBody, err := json.Marshal(struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}{Keys: []jose.JSONWebKey{pubJWK}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	idp := &fakeIdP{priv: priv, kid: kid, jwksBody: jwksBody, clientID: clientID}
	idp.srv = httptest.NewServer(idp)
	t.Cleanup(idp.srv.Close)
	// The issuer must equal the server's base URL so oidc.NewProvider's issuer
	// assertion passes.
	idp.issuer = idp.srv.URL
	return idp
}

func (idp *fakeIdP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		idp.handleDiscovery(w)
	case "/jwks":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(idp.jwksBody)
	case "/token":
		idp.handleToken(w)
	default:
		http.NotFound(w, r)
	}
}

func (idp *fakeIdP) handleDiscovery(w http.ResponseWriter) {
	doc := map[string]interface{}{
		"issuer":                                idp.issuer,
		"authorization_endpoint":                idp.issuer + "/auth",
		"token_endpoint":                        idp.issuer + "/token",
		"jwks_uri":                              idp.issuer + "/jwks",
		"end_session_endpoint":                  idp.issuer + "/logout",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	writeJSON(w, doc)
}

func (idp *fakeIdP) handleToken(w http.ResponseWriter) {
	idp.mu.Lock()
	omit, fail, nonce := idp.omitToken, idp.tokenFail, idp.nonce
	idp.mu.Unlock()

	if fail {
		http.Error(w, "token endpoint broken", http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	if !omit {
		resp["id_token"] = idp.mintIDToken(nonce)
	}
	writeJSON(w, resp)
}

// mintIDToken signs a compact JWS carrying the given nonce and the fake IdP's
// fixed subject/issuer/audience. exp/iat keep it inside the verifier's skew
// window.
func (idp *fakeIdP) mintIDToken(nonce string) string {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":                idp.issuer,
		"sub":                "user-sub-123",
		"aud":                idp.clientID,
		"nonce":              nonce,
		"email":              "alice@example.com",
		"email_verified":     true,
		"preferred_username": "alice",
		"name":               "Alice Example",
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
	}
	payload, _ := json.Marshal(claims)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: idp.priv},
		&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": idp.kid}},
	)
	if err != nil {
		panic("oidc test: new signer: " + err.Error())
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		panic("oidc test: sign: " + err.Error())
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		panic("oidc test: compact serialize: " + err.Error())
	}
	return compact
}

func (idp *fakeIdP) setNonce(n string) {
	idp.mu.Lock()
	idp.nonce = n
	idp.mu.Unlock()
}

func (idp *fakeIdP) setOmitToken(b bool) {
	idp.mu.Lock()
	idp.omitToken = b
	idp.mu.Unlock()
}

func (idp *fakeIdP) setTokenFail(b bool) {
	idp.mu.Lock()
	idp.tokenFail = b
	idp.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newIntegrationService wires a Service whose single provider points at the
// fake IdP. JWKS background refresh is disabled (TTL 0) to keep the test
// deterministic and free of background goroutines.
func newIntegrationService(t *testing.T, idp *fakeIdP, name string) *Service {
	t.Helper()
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Enabled: true,
			Providers: []config.OIDCProviderConfig{
				{
					Name:         name,
					IssuerURL:    idp.issuer,
					ClientID:     idp.clientID,
					ClientSecret: "test-secret",
				},
			},
			JWKSCacheTTLMinutes: 0,
		},
	}
	svc := NewService(context.Background(), cfg, []byte(integrationStateKey))
	t.Cleanup(svc.Close)
	return svc
}

// extractState pulls the signed state parameter out of an authorization URL.
func extractState(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	return u.Query().Get("state")
}

// mustAuthCodeURL wraps AuthCodeURL for tests that only need the resulting URL.
func mustAuthCodeURL(t *testing.T, svc *Service, provider, callbackURL string) string {
	t.Helper()
	u, err := svc.AuthCodeURL(provider, callbackURL)
	if err != nil {
		t.Fatalf("AuthCodeURL(%q): %v", provider, err)
	}
	return u
}

// stateNonce decrypts a signed state token to recover the nonce the IdP must
// echo back in the id_token.
func stateNonce(t *testing.T, state string) string {
	t.Helper()
	payload, err := verifyStateToken([]byte(integrationStateKey), state)
	if err != nil {
		t.Fatalf("verifyStateToken: %v", err)
	}
	return payload.Nonce
}

// TestNewService_DiscoverWiresProvider exercises the discover() path: a
// reachable IdP yields a provider instance carrying the discovery issuer, the
// end_session_endpoint, the generic display-name fallback, and "openid" as the
// first scope.
func TestNewService_DiscoverWiresProvider(t *testing.T) {
	idp := newFakeIdP(t, "gozone-client")
	svc := newIntegrationService(t, idp, "fake")

	if !svc.Enabled() {
		t.Fatal("service must be enabled with a reachable provider")
	}
	inst, ok := svc.Provider("fake")
	if !ok {
		t.Fatal("provider 'fake' must be discovered")
	}
	if inst.Issuer != idp.issuer {
		t.Errorf("Issuer = %q, want %q", inst.Issuer, idp.issuer)
	}
	if inst.EndSessionURL != idp.issuer+"/logout" {
		t.Errorf("EndSessionURL = %q, want %q", inst.EndSessionURL, idp.issuer+"/logout")
	}
	if inst.DisplayName != "fake" {
		t.Errorf("DisplayName = %q, want 'fake' (generic fallback)", inst.DisplayName)
	}
	if inst.Icon != "" {
		t.Errorf("Icon = %q, want empty for a generic provider", inst.Icon)
	}
	if len(inst.Scopes) == 0 || inst.Scopes[0] != ScopeOpenID {
		t.Errorf("Scopes = %v, want 'openid' first", inst.Scopes)
	}
	// The EndSessionURL must also surface via the Service accessor (Logout path).
	if got := svc.EndSessionURL("fake"); got != idp.issuer+"/logout" {
		t.Errorf("Service.EndSessionURL = %q, want logout URL", got)
	}
}

// TestNewService_DisplayNameOverride confirms an explicit DisplayName in config
// wins over the generic/preset fallback.
func TestNewService_DisplayNameOverride(t *testing.T) {
	idp := newFakeIdP(t, "cid")
	cfg := &config.Config{OIDC: config.OIDCConfig{Enabled: true, JWKSCacheTTLMinutes: 0, Providers: []config.OIDCProviderConfig{
		{Name: "fake", DisplayName: "Custom Label", IssuerURL: idp.issuer, ClientID: "cid", ClientSecret: "s"},
	}}}
	svc := NewService(context.Background(), cfg, []byte(integrationStateKey))
	t.Cleanup(svc.Close)

	inst, _ := svc.Provider("fake")
	if inst.DisplayName != "Custom Label" {
		t.Errorf("DisplayName = %q, want override 'Custom Label'", inst.DisplayName)
	}
}

// TestNewService_PresetDefaults confirms a well-known provider name (gitea)
// picks up the preset display name and icon during discovery.
func TestNewService_PresetDefaults(t *testing.T) {
	idp := newFakeIdP(t, "cid")
	svc := newIntegrationService(t, idp, "gitea")

	inst, _ := svc.Provider("gitea")
	if inst.DisplayName != "Gitea" {
		t.Errorf("DisplayName = %q, want preset 'Gitea'", inst.DisplayName)
	}
	if inst.Icon != "gitea" {
		t.Errorf("Icon = %q, want 'gitea'", inst.Icon)
	}
}

// TestNewService_UnreachableProviderSkipped confirms a provider whose discovery
// fails is skipped (logged) rather than aborting construction, and the resulting
// service is disabled because no provider came up.
func TestNewService_UnreachableProviderSkipped(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "broken", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)

	cfg := &config.Config{OIDC: config.OIDCConfig{Enabled: true, JWKSCacheTTLMinutes: 0, Providers: []config.OIDCProviderConfig{
		{Name: "dead", IssuerURL: bad.URL, ClientID: "c", ClientSecret: "s"},
	}}}
	svc := NewService(context.Background(), cfg, []byte(integrationStateKey))
	t.Cleanup(svc.Close)

	if svc.Enabled() {
		t.Error("service must be disabled when the only provider is unreachable")
	}
	if _, ok := svc.Provider("dead"); ok {
		t.Error("unreachable provider must not be registered")
	}
}

// TestHandleCallback_HappyPath is the end-to-end SSO flow against the fake IdP:
// discover → AuthCodeURL → token exchange → id_token verification → claim
// extraction. It is the primary regression guard for the entire callback path.
func TestHandleCallback_HappyPath(t *testing.T) {
	idp := newFakeIdP(t, "gozone-client")
	svc := newIntegrationService(t, idp, "fake")

	callbackURL := idp.issuer + "/auth/oidc/fake/callback"
	authURL, err := svc.AuthCodeURL("fake", callbackURL)
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	state := extractState(t, authURL)
	// Make the IdP echo the nonce bound into the signed state token.
	idp.setNonce(stateNonce(t, state))

	claims, err := svc.HandleCallback(context.Background(), "fake", "auth-code-xyz", state, callbackURL)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if claims.Subject != "user-sub-123" {
		t.Errorf("Subject = %q, want user-sub-123", claims.Subject)
	}
	if claims.Issuer != idp.issuer {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, idp.issuer)
	}
	if claims.Email != "alice@example.com" || !claims.EmailVerified {
		t.Errorf("email claims = %q/%v, want alice@example.com/true", claims.Email, claims.EmailVerified)
	}
	if claims.PreferredUsername != "alice" || claims.Name != "Alice Example" {
		t.Errorf("profile claims = %q/%q, want alice/Alice Example", claims.PreferredUsername, claims.Name)
	}
	if claims.Raw == nil {
		t.Error("Raw claims must be populated for handler-side role/group mapping")
	}
}

// TestHandleCallback_NonceMismatch verifies the C-1 replay guard: an id_token
// whose nonce does not match the one bound in the signed state is rejected.
func TestHandleCallback_NonceMismatch(t *testing.T) {
	idp := newFakeIdP(t, "gozone-client")
	svc := newIntegrationService(t, idp, "fake")
	callbackURL := idp.issuer + "/auth/oidc/fake/callback"
	state := extractState(t, mustAuthCodeURL(t, svc, "fake", callbackURL))

	idp.setNonce("tampered-nonce")

	_, err := svc.HandleCallback(context.Background(), "fake", "code", state, callbackURL)
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Errorf("expected nonce mismatch error, got %v", err)
	}
}

// TestHandleCallback_NoIDToken verifies the provider that omits the id_token
// from the token response is rejected (GoZone requires an id_token).
func TestHandleCallback_NoIDToken(t *testing.T) {
	idp := newFakeIdP(t, "gozone-client")
	svc := newIntegrationService(t, idp, "fake")
	callbackURL := idp.issuer + "/auth/oidc/fake/callback"
	state := extractState(t, mustAuthCodeURL(t, svc, "fake", callbackURL))
	idp.setNonce(stateNonce(t, state))
	idp.setOmitToken(true)

	_, err := svc.HandleCallback(context.Background(), "fake", "code", state, callbackURL)
	if err == nil || !strings.Contains(err.Error(), "id_token") {
		t.Errorf("expected missing id_token error, got %v", err)
	}
}

// TestHandleCallback_TokenExchangeFailure verifies a failing token endpoint
// surfaces a token-exchange error after the state passes verification.
func TestHandleCallback_TokenExchangeFailure(t *testing.T) {
	idp := newFakeIdP(t, "gozone-client")
	idp.setTokenFail(true)
	svc := newIntegrationService(t, idp, "fake")
	callbackURL := idp.issuer + "/auth/oidc/fake/callback"
	state := extractState(t, mustAuthCodeURL(t, svc, "fake", callbackURL))
	idp.setNonce(stateNonce(t, state))

	_, err := svc.HandleCallback(context.Background(), "fake", "code", state, callbackURL)
	if err == nil || !strings.Contains(err.Error(), "token exchange") {
		t.Errorf("expected token exchange error, got %v", err)
	}
}

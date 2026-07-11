package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/logger"
)

// Claims are the normalized user attributes extracted from a verified ID token
// after a successful OIDC callback. Field names follow the OIDC core claim
// names; the handlers map them onto GoZone user attributes.
type Claims struct {
	// Subject is the IdP-stable identifier (the "sub" claim). Combined with
	// the issuer it uniquely identifies an external identity.
	Subject string
	// Issuer is the token issuer URL (the "iss" claim), used as the link key
	// half (issuer, subject) → local user.
	Issuer string
	// Email is the user's email claim, when provided.
	Email string
	// EmailVerified mirrors the "email_verified" claim.
	EmailVerified bool
	// PreferredUsername mirrors "preferred_username", used as the default
	// username for just-in-time provisioning.
	PreferredUsername string
	// Name mirrors "name", split into first/last for the local user record.
	Name string
	// Raw is the full decoded ID-token claim set. It lets the handler apply
	// config-driven claim mappings (role/group extraction along arbitrary
	// dotted paths such as "realm_access.roles") without the oidc package
	// having to know every provider's claim shape.
	Raw map[string]json.RawMessage
}

// ProviderInstance is a single configured, discovered identity provider.
type ProviderInstance struct {
	Name        string
	DisplayName string
	Icon        string
	Issuer      string
	Scopes      []string
	// EndSessionURL is the provider's RP-initiated logout endpoint
	// (discovery "end_session_endpoint"), or empty when the provider does not
	// advertise one. Used by the Logout handler to redirect the browser back
	// to the IdP so its SSO cookie is also cleared.
	EndSessionURL string
	oauth2        *oauth2.Config
	verifier      *oidc.IDTokenVerifier
}

// Service holds the set of discovered OIDC providers and provides the
// stateless, PKCE-backed authorization flow. The zero value is a disabled
// service (Enabled() == false, every provider lookup misses).
type Service struct {
	providers map[string]*ProviderInstance
	stateKey  []byte
	keySets   []*cachedKeySet // started background refresh goroutines; Close stops them
}

// ErrDisabled is returned by NewService/Service methods when OIDC is not
// configured, so callers can branch without a nil check.
var ErrDisabled = errors.New("oidc: single sign-on is disabled")

// ErrUnknownProvider is returned when a provider name has no configured
// instance (e.g. a stale login button or a tampered state token).
var ErrUnknownProvider = errors.New("oidc: unknown provider")

// NewService discovers and wires every provider declared in the configuration.
//
// Discovery is best-effort per provider: if an IdP is unreachable at startup,
// that provider is skipped (logged at warn level) rather than aborting server
// boot — the remaining providers and local login still work. Operators are
// expected to fix the unreachable IdP; the provider can be made available by
// restarting once it is back.
func NewService(ctx context.Context, cfg *config.Config, stateKey []byte) *Service {
	svc := &Service{stateKey: stateKey}
	if cfg == nil || !cfg.OIDC.Enabled || len(cfg.OIDC.Providers) == 0 {
		return svc
	}
	jwksTTL := time.Duration(cfg.OIDC.JWKSCacheTTLMinutes) * time.Minute
	svc.providers = make(map[string]*ProviderInstance)
	for i := range cfg.OIDC.Providers {
		pc := &cfg.OIDC.Providers[i]
		inst, keySet, err := discover(ctx, pc, cfg.OIDC.Scopes, jwksTTL)
		if err != nil {
			logger.Warn("oidc provider discovery failed; skipping",
				"provider", pc.Name, "issuer", pc.IssuerURL, "error", err)
			continue
		}
		svc.providers[pc.Name] = inst
		if keySet != nil {
			svc.keySets = append(svc.keySets, keySet)
		}
		logger.Info("oidc provider ready",
			"provider", pc.Name, "issuer", pc.IssuerURL,
			"jwks_ttl_minutes", cfg.OIDC.JWKSCacheTTLMinutes)
	}
	return svc
}

// Close stops every provider's JWKS background refresh goroutine. It is safe to
// call on a disabled/zero service (no-op) and to call multiple times.
func (s *Service) Close() {
	if s == nil {
		return
	}
	for _, k := range s.keySets {
		k.Close()
	}
	s.keySets = nil
}

// Enabled reports whether at least one provider was successfully discovered.
func (s *Service) Enabled() bool { return s != nil && len(s.providers) > 0 }

// Provider returns the named provider instance.
func (s *Service) Provider(name string) (*ProviderInstance, bool) {
	if s == nil {
		return nil, false
	}
	p, ok := s.providers[name]
	return p, ok
}

// EndSessionURL returns the RP-initiated logout endpoint for the named provider,
// or "" when the provider is unknown or does not advertise end_session_endpoint.
// The Logout handler uses this to redirect the browser to the IdP so the SSO
// cookie is cleared alongside the local GoZone session.
func (s *Service) EndSessionURL(provider string) string {
	inst, ok := s.Provider(provider)
	if !ok {
		return ""
	}
	return inst.EndSessionURL
}

// Providers returns the configured providers in a stable order (configuration
// order) so the login page can render consistent buttons.
func (s *Service) Providers() []*ProviderInstance {
	if s == nil || len(s.providers) == 0 {
		return nil
	}
	out := make([]*ProviderInstance, 0, len(s.providers))
	for _, p := range s.providers {
		out = append(out, p)
	}
	return out
}

// discover performs OIDC discovery for a single provider config and builds the
// oauth2 client + ID-token verifier. jwksTTL controls the signing-key cache
// TTL (proactive background refresh); 0 disables proactive refresh.
func discover(ctx context.Context, pc *config.OIDCProviderConfig, globalScopes []string, jwksTTL time.Duration) (*ProviderInstance, *cachedKeySet, error) {
	provider, err := oidc.NewProvider(ctx, pc.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("discover %s: %w", pc.Name, err)
	}
	// The authoritative issuer is the "iss" claim in the discovery document
	// (which the ID-token verifier also enforces); it is the link key half
	// (issuer, subject) → local user, so prefer it over the configured URL.
	// Capture jwks_uri, end_session_endpoint and the advertised signing algs.
	var meta struct {
		Issuer                           string   `json:"issuer"`
		EndSessionURL                    string   `json:"end_session_endpoint"`
		JWKSURL                          string   `json:"jwks_uri"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}
	_ = provider.Claims(&meta)
	issuer := meta.Issuer
	if issuer == "" {
		issuer = pc.IssuerURL
	}
	scopes := DefaultScopesFor(pc.Name, pc.Scopes, globalScopes)
	preset, _ := LookupPreset(pc.Name)
	displayName := pc.DisplayName
	if displayName == "" {
		displayName = preset.DisplayName
	}
	if displayName == "" {
		displayName = pc.Name
	}

	// Build the verifier. When the discovery document advertises a jwks_uri we
	// use our own TTL-cached key set (proactive rotation); otherwise we fall
	// back to the library's default verifier (reactive, indefinite cache).
	var verifier *oidc.IDTokenVerifier
	var keySet *cachedKeySet
	vcfg := &oidc.Config{ClientID: pc.ClientID}
	if len(meta.IDTokenSigningAlgValuesSupported) > 0 {
		vcfg.SupportedSigningAlgs = meta.IDTokenSigningAlgValuesSupported
	}
	if meta.JWKSURL != "" {
		keySet = newCachedKeySet(meta.JWKSURL, jwksTTL)
		verifier = oidc.NewVerifier(issuer, keySet, vcfg)
	} else {
		verifier = provider.Verifier(vcfg)
	}

	inst := &ProviderInstance{
		Name:          pc.Name,
		DisplayName:   displayName,
		Icon:          preset.Icon,
		Issuer:        issuer,
		Scopes:        scopes,
		EndSessionURL: meta.EndSessionURL,
		oauth2: &oauth2.Config{
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			RedirectURL:  "", // set per request in AuthCodeURL/Exchange
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier: verifier,
	}
	return inst, keySet, nil
}

// AuthCodeURL builds the authorization-endpoint redirect URL for the given
// provider, embedding a fresh signed state token (carrying the PKCE verifier +
// nonce). The callbackURL is the fully-qualified /auth/oidc/{name}/callback
// URL the IdP must redirect back to.
func (s *Service) AuthCodeURL(provider, callbackURL string) (authURL string, err error) {
	inst, ok := s.Provider(provider)
	if !ok {
		return "", ErrUnknownProvider
	}
	state, _, challenge, _, err := newStateToken(s.stateKey, provider)
	if err != nil {
		return "", fmt.Errorf("build state: %w", err)
	}
	// RedirectURL is set per request because the external URL depends on the
	// request host/scheme (resolved via the trusted-proxy HTTPS resolver). The
	// value must be byte-identical between the auth request and the token
	// exchange, so Exchange() receives the same callbackURL.
	inst.oauth2.RedirectURL = callbackURL
	return inst.oauth2.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

// HandleCallback verifies the state token, exchanges the authorization code for
// tokens (PKCE), verifies the ID token signature and claims, and returns the
// normalized user claims. The callbackURL MUST be identical to the one used in
// AuthCodeURL for the token exchange to succeed.
func (s *Service) HandleCallback(ctx context.Context, provider, code, state, callbackURL string) (*Claims, error) {
	inst, ok := s.Provider(provider)
	if !ok {
		return nil, ErrUnknownProvider
	}
	payload, err := verifyStateToken(s.stateKey, state)
	if err != nil {
		return nil, fmt.Errorf("verify state: %w", err)
	}
	if payload.Provider != provider {
		// The state token was minted for a different provider — a mismatched or
		// replayed callback. Reject rather than risk authenticating against the
		// wrong IdP identity.
		return nil, fmt.Errorf("state provider mismatch: got %q want %q", payload.Provider, provider)
	}

	inst.oauth2.RedirectURL = callbackURL
	token, err := inst.oauth2.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", payload.Verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, fmt.Errorf("provider did not return an id_token")
	}
	idToken, err := inst.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}
	if idToken.Nonce != payload.Nonce {
		return nil, fmt.Errorf("nonce mismatch: possible replay")
	}

	claims := &Claims{Subject: idToken.Subject, Issuer: idToken.Issuer}
	// Stash the raw claim set first so the handler can run config-driven
	// mappings against arbitrary claim paths (role/group extraction). idToken
	// decodes from its stored payload on every Claims() call, so this extra
	// unmarshal does not disturb the profile-claim extraction below.
	var rawMap map[string]json.RawMessage
	_ = idToken.Claims(&rawMap)
	claims.Raw = rawMap
	// Extract the common profile claims. Unknown/missing claims are left zero —
	// the handler falls back to the subject for the username.
	var raw struct {
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decode id token claims: %w", err)
	}
	claims.Email = raw.Email
	claims.EmailVerified = raw.EmailVerified
	claims.PreferredUsername = raw.PreferredUsername
	claims.Name = raw.Name
	return claims, nil
}

// Package oidc implements OpenID Connect / OAuth2 single sign-on for GoZone.
//
// It supports multiple configured identity providers (one or more), each backed
// by a "preset" that supplies sensible defaults (display name, default scopes)
// for well-known providers. Custom/generic OIDC providers are also supported
// via standard discovery (issuer URL + /.well-known/openid-configuration).
//
// The flow is the authorization-code flow with PKCE (S256), a signed state
// parameter (HMAC) to prevent CSRF, and a nonce for ID-token replay
// protection — matching the GoZone ROADMAP "OpenID Connect / OAuth2" section.
package oidc

// Preset describes the defaults for a well-known provider type. It is the
// static, compile-time metadata looked up by provider name (the slug used in
// /auth/oidc/{name}/...). When a configured provider's name matches a preset
// key, the preset's display name and default scopes are used unless the
// provider configuration overrides them.
type Preset struct {
	// Type is the preset key (also used as the default provider name).
	Type string
	// DisplayName is the human-readable label shown on the login button.
	DisplayName string
	// DefaultScopes is the set of OIDC scopes requested when the provider
	// configuration does not specify its own. Always includes "openid".
	DefaultScopes []string
	// Icon is an optional CSS class hint for the login button (rendered by
	// the template). Empty means no provider-specific styling.
	Icon string
}

// presets is the registry of well-known provider types. A provider configured
// with a name not present here is treated as a generic OIDC provider using
// discovery only. The Gitea entry is the addition requested for this feature;
// the others are the standard providers listed in the ROADMAP.
var presets = map[string]Preset{
	"gitea": {
		Type:          "gitea",
		DisplayName:   "Gitea",
		DefaultScopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail},
		Icon:          "gitea",
	},
	"google": {
		Type:          "google",
		DisplayName:   "Google",
		DefaultScopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail},
		Icon:          "google",
	},
	"github": {
		Type:          "github",
		DisplayName:   "GitHub",
		DefaultScopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail},
		Icon:          "github",
	},
	"gitlab": {
		Type:          "gitlab",
		DisplayName:   "GitLab",
		DefaultScopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail},
		Icon:          "gitlab",
	},
	"keycloak": {
		Type:          "keycloak",
		DisplayName:   "Keycloak",
		DefaultScopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail},
		Icon:          "keycloak",
	},
	"authentik": {
		Type:          "authentik",
		DisplayName:   "Authentik",
		DefaultScopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail, "offline_access"},
		Icon:          "authentik",
	},
	"azure": {
		Type:          "azure",
		DisplayName:   "Azure AD",
		DefaultScopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail},
		Icon:          "azure",
	},
}

// LookupPreset returns the preset for the given provider name (type), or the
// generic preset (zero-value DisplayName, empty Icon) when the name is not a
// recognised well-known type. The returned "ok" flag reports whether the name
// matched a registered preset, so callers can log the use of a generic
// provider for discoverability.
func LookupPreset(name string) (Preset, bool) {
	p, ok := presets[name]
	return p, ok
}

// PresetNames returns the sorted list of registered preset keys. Used by config
// validation/help text and tests; not relied upon for correctness.
func PresetNames() []string {
	// Keep gitea first so it surfaces in help output (the explicitly requested
	// provider); the rest follow alphabetically. Map iteration order is not
	// deterministic in Go, so build the slice explicitly.
	names := make([]string, 0, len(presets)+1)
	if _, ok := presets["gitea"]; ok {
		names = append(names, "gitea")
	}
	seen := map[string]bool{"gitea": true}
	for k := range presets {
		if seen[k] {
			continue
		}
		names = append(names, k)
		seen[k] = true
	}
	return names
}

// DefaultScopesFor returns the scopes to request for a provider: the
// provider-specific scopes when non-empty, otherwise the preset default when
// the name matches a preset, otherwise the supplied global fallback. "openid"
// is always present exactly once.
func DefaultScopesFor(name string, providerScopes, globalFallback []string) []string {
	var scopes []string
	switch {
	case len(providerScopes) > 0:
		scopes = providerScopes
	default:
		if p, ok := presets[name]; ok && len(p.DefaultScopes) > 0 {
			scopes = p.DefaultScopes
		} else {
			scopes = globalFallback
		}
	}
	return normalizeScopes(scopes)
}

// normalizeScopes returns scopes with "openid" guaranteed present exactly once
// (first), deduplicated, preserving the original order of the other entries.
// Empty entries are dropped.
func normalizeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes)+1)
	seen := make(map[string]bool, len(scopes)+1)
	for _, s := range scopes {
		if s == "" || s == ScopeOpenID || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	// "openid" is mandatory and conventionally listed first.
	return append([]string{ScopeOpenID}, out...)
}

// Standard OIDC scope values.
const (
	ScopeOpenID  = "openid"
	ScopeEmail   = "email"
	ScopeProfile = "profile"
)

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/oidc"
	"github.com/babykart/gozone/internal/validators"
)

// ssoLoginMaxNameLen is the username length cap (matches validators' 32-char
// ceiling) used when deriving a login name from IdP claims.
const ssoLoginMaxNameLen = 32

// OIDCLogin starts the authorization-code flow for the requested provider,
// redirecting the browser to the IdP authorization endpoint with a signed
// state parameter (CSRF), a PKCE challenge (S256) and a nonce. The provider is
// selected by the {provider} URL parameter.
//
// GET /auth/oidc/{provider}/login
func (h *Handler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if h.OIDC == nil || !h.OIDC.Enabled() {
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	provider := r.PathValue("provider")
	if provider == "" {
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	callbackURL := oidcCallbackURL(h.Cfg.Server.ExternalURL, r, provider)
	authURL, err := h.OIDC.AuthCodeURL(provider, callbackURL)
	if err != nil {
		logger.Warn("oidc login: build auth url", "provider", provider, "error", err)
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	// Defense-in-depth against an open redirect: the URL is built by the OAuth2
	// library from server-side discovered IdP config (not user input), but
	// verify it is an absolute http(s) URL before redirecting so a future bug
	// or a misconfigured provider can never bounce the browser to an attacker.
	if !isAbsoluteHTTPURL(authURL) {
		logger.Error("oidc login: auth url is not an absolute http(s) url",
			"provider", provider, "url", authURL)
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	// #nosec G710 -- authURL is built from server-side discovered IdP config
	// and validated as an absolute http(s) URL immediately above.
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// OIDCCallback completes the authorization-code flow: it verifies the state
// token, exchanges the code for tokens (PKCE), verifies the ID token signature
// and claims, resolves (or just-in-time provisions) the local user, and
// establishes the same JWT session as local login.
//
// GET /auth/oidc/{provider}/callback
func (h *Handler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.OIDC == nil || !h.OIDC.Enabled() {
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	provider := r.PathValue("provider")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if provider == "" || code == "" || state == "" {
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	callbackURL := oidcCallbackURL(h.Cfg.Server.ExternalURL, r, provider)

	claims, err := h.OIDC.HandleCallback(ctx, provider, code, state, callbackURL)
	if err != nil {
		logger.Warn("oidc callback: exchange/verify", "provider", provider, "error", err)
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}

	user, err := h.resolveSSOUser(ctx, claims)
	if err != nil {
		logger.Warn("oidc callback: resolve user",
			"provider", provider, "subject", claims.Subject, "error", err)
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	if !user.Enabled {
		logger.Warn("oidc callback: account disabled",
			"provider", provider, "user_id", user.ID)
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}

	if err := h.issueSSOSession(w, r, user, provider); err != nil {
		http.Redirect(w, r, loginErrorRedirect(ssoError), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// resolveSSOUser maps OIDC claims to a local GoZone user. Resolution order:
//  1. existing external-identity link (issuer, subject) → user;
//  2. when auto_provision is on and the email is verified, an existing local
//     account with a matching email is linked to the identity and used;
//  3. otherwise, when auto_provision is on, a new user is provisioned and
//     linked atomically.
//
// Returns an error (causing an sso_error redirect) when no account can be
// resolved — e.g. auto_provision disabled with no prior link, or a unique
// collision that cannot be resolved deterministically.
func (h *Handler) resolveSSOUser(ctx context.Context, claims *oidc.Claims) (*models.User, error) {
	role := h.desiredRole(claims)
	if user, err := h.DB.FindUserByExternalIdentity(ctx, claims.Issuer, claims.Subject); err != nil {
		return nil, fmt.Errorf("lookup external identity: %w", err)
	} else if user != nil {
		// Existing linked user: sync IdP-authoritative attributes (role when
		// role_claim is set, group memberships when group_claim is set).
		if err := h.syncSSOAttributes(ctx, user, claims); err != nil {
			return nil, err
		}
		return user, nil
	}

	if !h.Cfg.OIDC.AutoProvision {
		return nil, errors.New("no linked local account and auto_provision is disabled")
	}

	// Email linking: only when the provider asserts the email is verified, to
	// avoid an attacker provisioning as a victim by asserting an unverified
	// email at a compromised IdP.
	if claims.EmailVerified && claims.Email != "" {
		if existing, err := h.DB.FindUserByEmail(ctx, claims.Email); err != nil {
			return nil, fmt.Errorf("lookup user by email: %w", err)
		} else if existing != nil {
			if err := h.linkIdentity(ctx, existing.ID, claims.Issuer, claims.Subject); err != nil {
				return nil, err
			}
			if err := h.syncSSOAttributes(ctx, existing, claims); err != nil {
				return nil, err
			}
			return existing, nil
		}
	}

	first, last := splitName(claims.Name)
	username := deriveSSOUsername(claims.PreferredUsername, claims.Subject)
	email := claims.Email
	if email == "" {
		email = "sso+" + shortHash(claims.Issuer+claims.Subject) + "@gozone.local"
	}
	user, err := h.DB.CreateExternalUser(ctx, username, email, first, last, role, claims.Issuer, claims.Subject)
	if err != nil {
		// A username/email collision with an existing account that was not
		// reachable by the email-link path (e.g. email not verified) surfaces
		// here as a unique violation; refuse rather than silently taking over.
		if h.DB.IsUniqueViolation(err) {
			return nil, errors.New("account provisioning conflict; ask an administrator to link your account")
		}
		return nil, fmt.Errorf("provision user: %w", err)
	}
	// A freshly provisioned user already has the desired role; only group
	// memberships remain to be synced.
	if h.Cfg.OIDC.GroupClaim != "" {
		if err := h.syncGroups(ctx, user.ID, claims); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// desiredRole resolves the GoZone role a user should hold based on the OIDC
// claims and the configured role mapping. When role mapping is disabled
// (RoleClaim empty) it returns DefaultRole (defaulting to "user"). When enabled,
// any overlap between the claim values and AdminRoleValues promotes the user to
// "admin"; otherwise DefaultRole applies.
func (h *Handler) desiredRole(claims *oidc.Claims) string {
	role := h.Cfg.OIDC.DefaultRole
	if role == "" {
		role = "user"
	}
	if h.Cfg.OIDC.RoleClaim != "" {
		values := oidc.ClaimStrings(claims.Raw, h.Cfg.OIDC.RoleClaim)
		for _, v := range values {
			for _, admin := range h.Cfg.OIDC.AdminRoleValues {
				if v == admin {
					return "admin"
				}
			}
		}
	}
	return role
}

// syncSSOAttributes applies IdP-authoritative attribute mappings to an existing
// user: role (when role_claim is configured) and zone-group memberships (when
// group_claim is configured). Both are best-effort and never block a successful
// SSO login — a failure is returned so the caller surfaces a generic sso_error,
// but transient/attribute errors are logged and skipped inside the helpers.
func (h *Handler) syncSSOAttributes(ctx context.Context, user *models.User, claims *oidc.Claims) error {
	if h.Cfg.OIDC.RoleClaim != "" {
		desired := h.desiredRole(claims)
		if desired != user.Role {
			if err := h.applySSORole(ctx, user, desired); err != nil {
				return err
			}
			user.Role = desired
		}
	}
	if h.Cfg.OIDC.GroupClaim != "" {
		return h.syncGroups(ctx, user.ID, claims)
	}
	return nil
}

// applySSORole updates a user's role to reflect the IdP mapping. A demotion
// from admin→user is refused (and logged) when the user is the last enabled
// admin, mirroring the guard in UpdateUser so SSO role sync can never lock the
// instance out. The change is recorded in activity_logs.
func (h *Handler) applySSORole(ctx context.Context, user *models.User, desired string) error {
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if user.Role == "admin" && desired != "admin" {
		last, err := tx.IsLastEnabledAdmin(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("check last admin: %w", err)
		}
		if last {
			logger.Warn("refused SSO role demotion of the last enabled admin",
				"user_id", user.ID, "username", user.Username)
			// Commit the empty tx and keep the admin role.
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("commit: %w", err)
			}
			committed = true
			return nil
		}
	}
	if err := tx.SetUserRole(ctx, user.ID, desired); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'sso_role_sync', ?)",
		user.ID, fmt.Sprintf("SSO role sync set role to %s", desired),
	); err != nil {
		return fmt.Errorf("log sso role sync: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// syncGroups adds the user to every GoZone zone_group that the configured
// GroupMapping resolves from the claim values. It is additive only — existing
// memberships are kept, and memberships are never removed automatically (revoke
// manually). Target groups that do not exist are skipped with a warning so the
// operator is nudged to pre-create them.
func (h *Handler) syncGroups(ctx context.Context, userID int64, claims *oidc.Claims) error {
	values := oidc.ClaimStrings(claims.Raw, h.Cfg.OIDC.GroupClaim)
	if len(values) == 0 {
		return nil
	}
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		groupName, ok := h.Cfg.OIDC.GroupMapping[v]
		if !ok || seen[groupName] {
			continue
		}
		seen[groupName] = true
		groupID, err := tx.ZoneGroupIDByNameTx(ctx, groupName)
		if err != nil {
			return fmt.Errorf("lookup group %q: %w", groupName, err)
		}
		if groupID == 0 {
			logger.Warn("oidc group mapping: target group does not exist; skipping",
				"group", groupName, "claim_value", v)
			continue
		}
		if err := tx.AddGroupMembership(ctx, groupID, userID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// linkIdentity links an external identity to an existing user in its own
// transaction. A duplicate link (same issuer+subject already tied to this
// user) is tolerated; a tie to a different user is reported as an error.
func (h *Handler) linkIdentity(ctx context.Context, userID int64, issuer, subject string) error {
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := tx.LinkExternalIdentity(ctx, userID, issuer, subject); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'sso_link', ?)",
		userID, fmt.Sprintf("Linked SSO identity %s", issuer),
	); err != nil {
		return fmt.Errorf("log sso link: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// issueSSOSession mints the JWT session cookie used for all authenticated web
// routes and records an activity log entry. It mirrors the tail of the local
// Login handler so SSO and local sessions are indistinguishable to the Auth
// middleware. The provider name is embedded as AuthProvider so the Logout
// handler can perform RP-initiated logout at the IdP end_session_endpoint.
func (h *Handler) issueSSOSession(w http.ResponseWriter, r *http.Request, user *models.User, provider string) error {
	duration := time.Duration(h.Cfg.Auth.SessionDurationHours) * time.Hour
	token, err := middleware.GenerateSessionToken(user, h.Cfg.Server.JWTKey, duration, provider)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	// The SSO session cookie uses SameSite=Lax, intentionally diverging from
	// the local login's SameSite=Strict (auth.go). The IdP -> /callback hop is
	// a cross-site top-level navigation; the callback then 303-redirects to
	// /dashboard. That first /dashboard request is cross-site-initiated, so a
	// Strict cookie would NOT be carried on it and the Auth middleware would
	// bounce the user back to /login. Lax allows the cookie on the top-level
	// GET landing while still blocking cross-site POST, so state-changing
	// requests remain protected by gorilla/csrf (REVIEW.md B-1).
	// #nosec G124 -- Secure flag set dynamically via isSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     constants.SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(duration),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecure(r),
	})
	if _, err := h.DB.ExecContext(r.Context(),
		"INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'sso_login', ?)",
		user.ID, fmt.Sprintf("User %s logged in via SSO (%s)", user.Username, provider),
	); err != nil {
		logger.Error("failed to log sso login activity", "user_id", user.ID, "error", err)
	}
	return nil
}

// isAbsoluteHTTPURL reports whether u is an absolute URL with an http or https
// scheme and a non-empty host. Used to guard OIDC redirects.
func isAbsoluteHTTPURL(u string) bool {
	parsed, err := neturl.Parse(u)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

// oidcCallbackURL builds the fully-qualified callback URL for a provider. The
// value must be byte-identical between the authorization request and the token
// exchange, so both OIDCLogin and OIDCCallback call this helper with the same
// provider name.
//
// When externalURL is non-empty (server.external_url), it is used as the base
// — pinning the canonical origin instead of deriving it from the
// client-controlled Host header (defense-in-depth; the IdP already validates
// redirect_uri against its registered list). When empty, the URL is derived
// per-request from the resolved scheme (trusted-proxy aware) and r.Host.
func oidcCallbackURL(externalURL string, r *http.Request, provider string) string {
	if externalURL != "" {
		return externalURL + "/auth/oidc/" + provider + "/callback"
	}
	scheme := "http"
	if middleware.IsHTTPS(r) {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/auth/oidc/%s/callback", scheme, r.Host, provider)
}

// deriveSSOUsername builds a GoZone-valid username from the IdP preferred
// username or, failing that, the subject. The result always satisfies
// validators.ValidateUsername (starts with a letter, 3-32 chars of
// [A-Za-z0-9._-]).
func deriveSSOUsername(preferred, subject string) string {
	base := preferred
	if base == "" {
		base = subject
	}
	cleaned := sanitizeUsername(base)
	if validators.ValidateUsername(cleaned) == nil {
		return cleaned
	}
	// Fall back to a deterministic, always-valid name: "sso-" + 12-char
	// subject hash (16 chars, leading letter 's', all chars in the allowed
	// set). Guarantees uniqueness across distinct subjects.
	return "sso-" + shortHash(subject)
}

// sanitizeUsername lowercases the input and keeps only the characters allowed
// by the username regex, replacing others with '-'. It guarantees a leading
// letter ("u" prefix when the first kept char is not a letter) and a minimum
// length so the result is likely valid.
func sanitizeUsername(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	b.Grow(len(in))
	for _, c := range in {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			b.WriteRune(c)
		case c == ' ' || c == '@':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return ""
	}
	// Ensure it starts with a letter (the regex requires it).
	first := out[0]
	if !(first >= 'a' && first <= 'z') {
		out = "u" + out
	}
	if len(out) > ssoLoginMaxNameLen {
		out = out[:ssoLoginMaxNameLen]
	}
	return out
}

// splitName splits a full name into first/last components for the user record.
// A single token becomes the first name; multiple tokens put the last token in
// the last name. Empty input yields two empty strings.
func splitName(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ""
	}
	parts := strings.Fields(name)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return strings.Join(parts[:len(parts)-1], " "), parts[len(parts)-1]
}

// shortHash returns the first 12 hex characters of the SHA-256 of s, suitable
// for deterministic, collision-resistant suffixes.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

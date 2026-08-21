// Package constants defines shared magic strings and configuration defaults
// used across the GoZone application.
package constants

const (
	SessionCookieName   = "gozone_session"
	NewAPIKeyCookieName = "gozone_new_api_key" // #nosec G101 -- cookie name, not a secret
)

const (
	DefaultBcryptCost = 12
	MaxOpenConns      = 1
	// DefaultMaxAPIKeysPerUser is the default auth.max_api_keys_per_user cap:
	// the number of API keys a single user may own at once before creation is
	// rejected (0 would disable the cap entirely).
	DefaultMaxAPIKeysPerUser = 10
)

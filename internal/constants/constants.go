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
)

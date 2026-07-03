package handlers

import "time"

// passwordExpired reports whether the password is older than the configured
// maximum age. maxAgeDays <= 0 (default) means no expiry. A zero changedAt
// (no recorded change time) is treated as non-expired so legacy rows are not
// forced en masse.
func passwordExpired(maxAgeDays int, changedAt time.Time) bool {
	if maxAgeDays <= 0 || changedAt.IsZero() {
		return false
	}
	return time.Since(changedAt) > time.Duration(maxAgeDays)*24*time.Hour
}

// passwordExpiryWarnDays returns the number of days before the password
// expires, but only when it falls inside the warning window (i.e. expiry is
// imminent). Returns 0 when expiry is disabled, when there is no warning
// window, or when the password is not yet within the window. The dashboard
// shows a warning when the return value is > 0.
func passwordExpiryWarnDays(maxAgeDays, warnDays int, changedAt time.Time) int {
	if maxAgeDays <= 0 || warnDays <= 0 || changedAt.IsZero() {
		return 0
	}
	ageDays := int(time.Since(changedAt) / (24 * time.Hour))
	remaining := maxAgeDays - ageDays
	if remaining <= 0 || remaining > warnDays {
		return 0
	}
	return remaining
}

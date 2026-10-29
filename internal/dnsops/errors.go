package dnsops

import "errors"

// ErrForbidden reports that the acting user is not allowed to perform the
// operation: either a zone-scoped call without a group grant on the zone, or
// an admin-only operation by a non-admin. HTTP callers map it to 403.
var ErrForbidden = errors.New("forbidden")

// Stage identifies which stage of a composite service operation failed. The
// REST error mapping (and later the MCP error codes) depends on the stage,
// not just the underlying cause: the same PowerDNS ErrNotFound is a
// ZONE_NOT_FOUND when the pre-write fetch fails and a RECORD_ERROR when the
// PATCH itself fails.
type Stage string

const (
	// StageLock is the acquisition of the per-zone lock that serializes a
	// read-modify-write operation across transports and instances.
	StageLock Stage = "lock"
	// StageFetch is the read of the existing RRSets that precedes a write
	// (merge input, audit before-image).
	StageFetch Stage = "fetch"
	// StagePatch is the PowerDNS PATCH/DELETE write itself.
	StagePatch Stage = "patch"
	// StageStatistics is the PowerDNS statistics call of Stats.
	StageStatistics Stage = "statistics"
	// StageZoneList is the PowerDNS zone-list call of Stats.
	StageZoneList Stage = "zone-list"
	// StageZoneAccess is a failed zone-authorization lookup (database
	// fault while checking group grants — fail-closed, but distinct from a
	// genuine denial, which is ErrForbidden).
	StageZoneAccess Stage = "zone-access"
)

// StageError tags an error with the operation stage it failed in. It
// implements Unwrap so errors.Is/As against the underlying cause (typed
// PowerDNS errors, database errors) keeps working through the tag.
type StageError struct {
	Stage Stage
	Err   error
}

func (e *StageError) Error() string {
	return string(e.Stage) + ": " + e.Err.Error()
}

func (e *StageError) Unwrap() error {
	return e.Err
}

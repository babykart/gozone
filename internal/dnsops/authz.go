package dnsops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
)

// CanAccessZone reports whether user may operate on zoneID: callers fast-path
// DNS admins (see models.User.CanManageDNS) before calling; for everyone else
// a group grant covering the zone is required (zone_group_members ×
// zone_group_zones).
//
// This is the single source of truth for zone authorization. The HTTP
// middleware (middleware.CheckZoneAccess) calls it for routes that carry a
// {zone_id} path segment, and the service layer re-checks it for every
// zone-scoped operation so transports without a zone in the URL (a future
// MCP tool whose zone arrives as an argument) cannot skip it.
//
// Fail-closed semantics, shared by both callers:
//
//   - (true, nil)  → access confirmed (grant row found)
//   - (false, nil) → denied: no grant row (sql.ErrNoRows), or the caller's
//     context was canceled/deadlined mid-query. A denial, not a fault.
//   - (false, err) → the lookup itself failed (database fault). Callers
//     fail closed but surface a distinguishable error (HTTP 500) so an
//     outage does not masquerade as a stream of denials.
//
// A nil user is rejected: every transport authenticates before authorizing.
func CanAccessZone(ctx context.Context, db *database.DB, user *models.User, zoneID string) (bool, error) {
	if user == nil {
		return false, nil
	}
	var exists int
	err := db.QueryRowContext(
		ctx,
		`SELECT 1 FROM zone_group_members m
		 JOIN zone_group_zones z ON m.group_id = z.group_id
		 WHERE m.user_id = ? AND z.zone_id = ?
		 LIMIT 1`,
		user.ID, zoneID,
	).Scan(&exists)
	if err == nil && exists == 1 {
		return true, nil
	}
	if err != nil &&
		!errors.Is(err, sql.ErrNoRows) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		return false, fmt.Errorf("zone access lookup: %w", err)
	}
	return false, nil
}

// UserAllowedZoneIDs returns the set of zone IDs the user holds a group
// grant on. It backs both zone-list filters below.
func UserAllowedZoneIDs(ctx context.Context, db *database.DB, userID int64) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT z.zone_id FROM zone_group_members m
		 JOIN zone_group_zones z ON m.group_id = z.group_id
		 WHERE m.user_id = ?`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	zoneIDs := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			logger.Error("failed to scan allowed zone_id", "user_id", userID, "error", err)
			continue
		}
		zoneIDs[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return zoneIDs, nil
}

// FilterZonesForUser returns the PowerDNS zones the user is allowed to see.
// A nil user (a caller reached without the transport authentication having
// run — a wiring bug) fails CLOSED with an empty list instead of returning
// every zone: the permissive fallback would turn a wiring mistake into a
// full disclosure.
//
// A failed allowed-zone lookup returns a StageError(StageZoneAccess) so
// callers distinguish a database fault from an empty result — returning the
// empty list would present an outage as "you have no zones".
func FilterZonesForUser(ctx context.Context, db *database.DB, user *models.User, zones []models.Zone) ([]models.Zone, error) {
	if user == nil {
		logger.Error("filterZonesForUser reached without an authenticated user; failing closed")
		return []models.Zone{}, nil
	}
	if user.CanManageDNS() {
		return zones, nil
	}

	allowed, err := UserAllowedZoneIDs(ctx, db, user.ID)
	if err != nil {
		return nil, &StageError{Stage: StageZoneAccess, Err: fmt.Errorf("failed to get user zone permissions: %w", err)}
	}

	filtered := make([]models.Zone, 0)
	for _, z := range zones {
		if allowed[z.ID] {
			filtered = append(filtered, z)
		}
	}
	return filtered, nil
}

// FilterZonesWithInfoForUser is FilterZonesForUser over the zone-with-info
// shape (PowerDNS zone list + statistics). Nil user fails closed — see
// FilterZonesForUser.
func FilterZonesWithInfoForUser(ctx context.Context, db *database.DB, user *models.User, zones []models.ZoneWithInfo) ([]models.ZoneWithInfo, error) {
	if user == nil {
		logger.Error("filterZonesWithInfoForUser reached without an authenticated user; failing closed")
		return []models.ZoneWithInfo{}, nil
	}
	if user.CanManageDNS() {
		return zones, nil
	}

	allowed, err := UserAllowedZoneIDs(ctx, db, user.ID)
	if err != nil {
		return nil, &StageError{Stage: StageZoneAccess, Err: fmt.Errorf("failed to get user zone permissions: %w", err)}
	}

	filtered := make([]models.ZoneWithInfo, 0)
	for _, z := range zones {
		if allowed[z.Zone.ID] {
			filtered = append(filtered, z)
		}
	}
	return filtered, nil
}

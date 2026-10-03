package handlers

import (
	"context"
	"fmt"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
)

// ReconcileGroupZones removes zone-group grants whose zone no longer exists
// in PowerDNS, and returns the number of grant rows deleted.
//
// PowerDNS is the source of truth for zones, but zone_group_zones has no
// foreign-key relationship with it: a zone deleted or renamed directly in
// PowerDNS leaves its grant rows behind forever — they clutter the group edit
// page and inflate getUserAllowedZoneIDs. This reconciliation is the garbage
// collection for those rows. It runs hourly from the server bootstrap and
// opportunistically when an admin opens a group's edit page (which already
// holds a fresh zone list).
//
// Fail-safe by construction: when the zone list cannot be fetched the
// reconciliation is skipped entirely — an unreachable PowerDNS must never be
// interpreted as "all zones gone", which would revoke every grant. The same
// applies to a PowerDNS that answers 200 with an empty list while grants
// exist (a broken backend must not mass-revoke either), and the pass reads
// the zone list cache-bypassed so a stale list on one instance cannot drop
// a grant another instance created seconds ago.
func (h *Handler) ReconcileGroupZones(ctx context.Context) (int, error) {
	zones, err := h.PDNS.ListZonesWithInfoFresh(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetch zone list: %w", err)
	}
	return h.reconcileGroupZones(ctx, zones)
}

// reconcileOrphanSmallSetBound is the small-set exemption of the mass-
// revocation circuit breaker below: passes that would drop at most this many
// grants always run, so legitimate cleanups (a renamed zone, a handful of
// deletions) are never blocked.
const reconcileOrphanSmallSetBound = 10

// reconcileGroupZones is the core of ReconcileGroupZones over an
// already-fetched zone list, so callers that hold one avoid a second
// PowerDNS round-trip. The list must be authoritative (cache-bypassed) —
// see ReconcileGroupZones.
func (h *Handler) reconcileGroupZones(ctx context.Context, zones []models.ZoneWithInfo) (int, error) {
	existing := make(map[string]struct{}, len(zones))
	for _, z := range zones {
		existing[z.Zone.ID] = struct{}{}
	}

	granted, err := h.distinctGroupZoneIDs(ctx)
	if err != nil {
		return 0, err
	}
	if len(granted) == 0 {
		return 0, nil
	}

	// Empty-list guard: a PowerDNS answering 200 with zero zones while
	// grants exist is far more likely a broken backend than a real mass
	// deletion — and honouring it would irreversibly revoke every grant.
	if len(zones) == 0 {
		logger.Warn("group zone reconciliation skipped: PowerDNS returned no zones while grants exist",
			"grants", len(granted))
		return 0, nil
	}

	var orphans []string
	for _, zoneID := range granted {
		if _, ok := existing[zoneID]; !ok {
			orphans = append(orphans, zoneID)
		}
	}

	// Mass-revocation circuit breaker: a pass that would drop more than
	// half of a sizeable grant set is treated as an upstream anomaly (a
	// truncated zone list behind an outage or a misbehaving proxy) and is
	// aborted for a human to inspect. Small sets are always processed.
	if len(orphans) > reconcileOrphanSmallSetBound && 2*len(orphans) > len(granted) {
		logger.Error("group zone reconciliation aborted: orphaned grants exceed half of the grant set (likely upstream anomaly)",
			"orphans", len(orphans), "grants", len(granted))
		return 0, nil
	}

	deleted := 0
	for _, zoneID := range orphans {
		// Orphaned grant: the zone is gone from PowerDNS, so the grant can
		// never authorize anything — remove it for every group.
		if _, err := h.DB.ExecContext(ctx,
			"DELETE FROM zone_group_zones WHERE zone_id = ?", zoneID,
		); err != nil {
			// Best-effort per row: a failed delete is logged and skipped, the
			// next reconciliation pass retries it.
			logger.Error("failed to delete orphaned group zone grant",
				"zone_id", zoneID, "error", err)
			continue
		}
		deleted++
	}
	if deleted > 0 {
		logger.Info("reconciled group zone grants against PowerDNS", "deleted", deleted)
	}
	return deleted, nil
}

// distinctGroupZoneIDs returns every zone_id referenced by any group grant.
// The table only grows through admin actions, so this set is small compared
// to the zone list; diffing in-process keeps the reconciliation portable
// (no giant NOT IN (...) statement) and lets the deletes be bounded and
// logged individually.
func (h *Handler) distinctGroupZoneIDs(ctx context.Context) ([]string, error) {
	rows, err := h.DB.QueryContext(ctx, "SELECT DISTINCT zone_id FROM zone_group_zones")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

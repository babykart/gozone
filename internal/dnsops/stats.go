package dnsops

import (
	"context"

	"github.com/babykart/gozone/internal/models"
)

// Stats returns the PowerDNS server statistics combined with the number of
// zones the user is allowed to see (all zones for an admin, the group-granted
// subset otherwise).
//
// The zone count depends only on the zone list and the zone-access lookup,
// so those two stages are fatal: either failing makes the count unknowable
// and returns a StageError (StageZoneList / StageZoneAccess). A failed
// statistics call does not block the count — it is reported as
// StageStatistics with nil statistics and the still-correct zone count, so a
// degraded caller can keep an honest number instead of an outage rendered as
// zone_count: 0. Strict callers (REST, MCP) surface the error and ignore the
// partial values.
func (s *Service) Stats(ctx context.Context, user *models.User) ([]models.StatisticItem, int, error) {
	stats, statsErr := s.PDNS.GetStatistics(ctx)
	if statsErr != nil {
		// The zone count below is independent of the statistics; remember
		// the failure and keep going.
		statsErr = &StageError{Stage: StageStatistics, Err: statsErr}
	}

	zones, err := s.PDNS.ListZones(ctx)
	if err != nil {
		return nil, 0, &StageError{Stage: StageZoneList, Err: err}
	}

	filtered, err := FilterZonesForUser(ctx, s.DB, user, zones)
	if err != nil {
		return nil, 0, &StageError{Stage: StageZoneAccess, Err: err}
	}

	zoneCount := 0
	if filtered != nil {
		zoneCount = len(filtered)
	}

	if statsErr != nil {
		return nil, zoneCount, statsErr
	}
	return filterStatsForUser(stats, user), zoneCount, nil
}

// filterStatsForUser strips RingStatisticItem and MapStatisticItem entries for
// users who cannot manage DNS. Those items expose the most-queried names and
// client resolver IPs and are reserved for DNS admins. The filter always
// builds a new slice — the input can be the shared cached backing array from
// the PDNS cache, which must never be written into.
func filterStatsForUser(stats []models.StatisticItem, user *models.User) []models.StatisticItem {
	if user == nil || user.CanManageDNS() {
		return stats
	}
	filtered := make([]models.StatisticItem, 0, len(stats))
	for _, item := range stats {
		if item.Type == "RingStatisticItem" || item.Type == "MapStatisticItem" {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

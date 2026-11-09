package dnsops

import (
	"context"

	"github.com/babykart/gozone/internal/models"
)

// Stats returns the PowerDNS server statistics combined with the number of
// zones the user is allowed to see (all zones for an admin, the group-granted
// subset otherwise).
//
// The statistics call and the zone list are independent upstream calls; the
// zone count additionally depends on a zone-access lookup. Either failing
// makes the composite answer wrong, so each stage wraps its error in a
// StageError (StageStatistics / StageZoneList / StageZoneAccess) and callers
// surface the failure instead of presenting, say, an outage as zone_count: 0.
func (s *Service) Stats(ctx context.Context, user *models.User) ([]models.StatisticItem, int, error) {
	stats, err := s.PDNS.GetStatistics(ctx)
	if err != nil {
		return nil, 0, &StageError{Stage: StageStatistics, Err: err}
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

package dnsops

import (
	"context"
	"fmt"
	"strings"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// NormalizeZoneName canonicalises a zone name (or nameserver hostname) for
// the PowerDNS API: it trims surrounding whitespace, lowercases the value
// (DNS is case-insensitive and PowerDNS stores canonical lowercase), and
// appends a trailing dot when missing. PowerDNS rejects zone names and
// nameserver hostnames that lack the trailing dot, so without this
// normalisation a user entering "example.com" gets a PDNS error.
func NormalizeZoneName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	return models.EnsureTrailingDot(name)
}

// PurgeZoneGroupGrants deletes the zone's group-grant rows. Deleting or
// renaming a zone directly in PowerDNS leaves orphaned grants: the hourly
// reconciliation eventually revokes the data, but a lingering grant must not
// survive until then — a zone recreated under the same name within that
// window would silently restore the old groups' access to the NEW zone. The
// zone ID is canonicalised because the grants table keys on the canonical
// form while a caller may pass the name without the dot. Best-effort:
// failures are logged, not returned.
func PurgeZoneGroupGrants(ctx context.Context, db *database.DB, zoneID string) {
	zoneID = NormalizeZoneName(zoneID)
	if _, err := db.ExecContext(ctx, "DELETE FROM zone_group_zones WHERE zone_id = ?", zoneID); err != nil {
		logger.Error("failed to purge zone group grants", "zone_id", zoneID, "error", err)
	}
}

// ListZones returns the PowerDNS zones the user is allowed to see (all of
// them for an admin, the group-granted subset otherwise). A nil user fails
// closed to an empty list; a failed authorization lookup returns a
// StageError(StageZoneAccess) rather than an empty result.
func (s *Service) ListZones(ctx context.Context, user *models.User) ([]models.Zone, error) {
	zones, err := s.PDNS.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	return FilterZonesForUser(ctx, s.DB, user, zones)
}

// GetZone returns a single zone by zone_id, re-checking zone authorization
// in the service (the REST middleware already checks it for {zone_id} routes;
// transports without a zone in the URL rely on this check alone).
func (s *Service) GetZone(ctx context.Context, user *models.User, zoneID string) (*models.Zone, error) {
	if err := s.authorizeZone(ctx, user, zoneID); err != nil {
		return nil, err
	}
	return s.PDNS.GetZone(ctx, zoneID)
}

// CreateZone creates a zone (admin-only at the service level, in addition to
// any transport-side RequireAdmin gate). The request must already be
// validated by the caller (domain name, kind, nameservers); this method
// canonicalises name and nameservers, performs the PowerDNS call and writes
// the audit entry. src labels the audit trail ("via API").
func (s *Service) CreateZone(ctx context.Context, user *models.User, req models.ZoneCreateRequest, src Source) (*models.Zone, error) {
	if err := requireAdmin(user); err != nil {
		return nil, err
	}

	// Canonicalise the zone name and nameservers (lowercase + trailing dot)
	// so callers may pass "example.com" without the trailing dot that
	// PowerDNS mandates internally.
	req.Name = NormalizeZoneName(req.Name)
	for i := range req.Nameservers {
		req.Nameservers[i] = NormalizeZoneName(req.Nameservers[i])
	}

	zone, err := s.PDNS.CreateZone(ctx, req)
	if err != nil {
		return nil, err
	}

	// Audit trail: API/MCP-driven creates must show up in the activity log
	// (user_id is the API key owner for key-authenticated transports).
	if err := LogActivity(ctx, s.DB, ActivityEntry{
		UserID:  userIDOf(user),
		ZoneID:  zone.ID,
		Action:  "create_zone",
		Details: fmt.Sprintf("Created zone %s (kind: %s) via %s", zone.Name, zone.Kind, src.Label()),
	}); err != nil {
		logger.Error("failed to log create_zone activity", "zone_id", zone.ID, "error", err)
	}
	return zone, nil
}

// DeleteZone deletes a zone by zone_id (admin-only at the service level),
// writes the audit entry and immediately purges the zone's group grants (no
// lingering access until the hourly reconciliation).
func (s *Service) DeleteZone(ctx context.Context, user *models.User, zoneID string, src Source) error {
	if err := requireAdmin(user); err != nil {
		return err
	}
	if err := s.PDNS.DeleteZone(ctx, zoneID); err != nil {
		return err
	}

	if err := LogActivity(ctx, s.DB, ActivityEntry{
		UserID:  userIDOf(user),
		ZoneID:  zoneID,
		Action:  "delete_zone",
		Details: fmt.Sprintf("Deleted zone %s via %s", zoneID, src.Label()),
	}); err != nil {
		logger.Error("failed to log delete_zone activity", "zone_id", zoneID, "error", err)
	}

	PurgeZoneGroupGrants(ctx, s.DB, zoneID)
	return nil
}

// RecordTypes returns the record types GoZone accepts for record creation
// and updates (the union of the validator whitelist). Single source of truth
// for the REST API surface description and the MCP list_record_types tool.
func RecordTypes() []string {
	return []string{
		"A", "AAAA", "AFSDB", "ALIAS", "CAA", "CERT", "CNAME",
		"DNAME", "DNSKEY", "DS", "HINFO", "KEY", "LOC", "MINFO",
		"MX", "NAPTR", "NS", "NSEC", "NSEC3", "NSEC3PARAM",
		"OPENPGPKEY", "PTR", "RP", "RRSIG", "SOA", "SPF", "SRV",
		"SSHFP", "TLSA", "TXT", "URI",
	}
}

// ValidateZoneCreate validates a zone-creation payload the way the REST
// handler does, so transports that do not decode JSON (an MCP tool) can
// run the exact same checks: domain-name syntax, default kind, kind
// whitelist. Returns the request with the kind default applied.
func ValidateZoneCreate(req models.ZoneCreateRequest) (models.ZoneCreateRequest, error) {
	if err := validators.ValidateDomainName(req.Name); err != nil {
		return req, err
	}
	if req.Kind == "" {
		req.Kind = "Native"
	}
	if err := validators.ValidateZoneKind(req.Kind); err != nil {
		return req, err
	}
	return req, nil
}

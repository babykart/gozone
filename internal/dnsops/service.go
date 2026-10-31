// Package dnsops is the transport-agnostic service layer for GoZone's DNS
// operations (zones, records, statistics). It owns the business invariants
// that every transport must share — per-zone write serialization across
// database-sharing instances, RRSet merge/normalisation semantics, TTL
// resolution, zone authorization and the activity audit trail — so the REST
// handlers, the web UI and the MCP server are thin adapters over one
// implementation instead of divergent copies.
//
// The REST handlers in internal/handlers call this service; the web handlers
// still run their own flows but share the moved helpers (normalisation,
// locks, audit) through thin wrappers.
package dnsops

import (
	"context"
	"fmt"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
)

// Source identifies the transport a service call arrived from. It is only
// used to label the activity-log entries ("… via API") so an operator can
// tell an API-driven change from an MCP-driven or web-driven one.
type Source string

const (
	SourceAPI Source = "api"
	SourceMCP Source = "mcp"
	SourceWeb Source = "web"
)

// Label returns the upper-case transport name used in audit details
// ("via API", "via MCP").
func (s Source) Label() string {
	switch s {
	case SourceAPI:
		return "API"
	case SourceMCP:
		return "MCP"
	case SourceWeb:
		return "Web"
	default:
		return string(s)
	}
}

// Service exposes the DNS business operations. All methods take the acting
// user explicitly (nil designates an in-process caller — see authorizeZone)
// and a Source for the audit label.
type Service struct {
	DB   *database.DB
	PDNS pdns.ZoneService
	// locks serializes read-modify-write record mutations per zone. It is
	// shared with the web handlers (via Handler.zoneLocks) so a REST write
	// and a web write on the same zone cannot interleave.
	locks ZoneLocks
}

// New creates a Service over the given database and PowerDNS client.
func New(db *database.DB, pdnsClient pdns.ZoneService) *Service {
	s := &Service{DB: db, PDNS: pdnsClient}
	if db != nil {
		s.locks.shared = db
	}
	return s
}

// Locks returns the shared per-zone locker. The web handlers keep using it
// directly (Handler.zoneLocks) so REST, web and MCP writes on the same zone
// serialize against each other in this process and across database-sharing
// instances.
func (s *Service) Locks() *ZoneLocks {
	return &s.locks
}

// userIDOf returns the acting user's id for the activity log, or 0 for a
// nil (in-process) caller — mirroring the historical API behaviour where an
// unauthenticated handler invocation wrote user_id 0.
func userIDOf(user *models.User) int64 {
	if user != nil {
		return user.ID
	}
	return 0
}

// requireAdmin enforces the service-level DNS administration gate for
// operations that are admin-only regardless of transport (zone
// create/delete); both DNS-admin roles pass (admins and operators —
// CanManageDNS). The name is historical and kept to avoid call-site churn.
// The REST routes additionally sit behind middleware.RequireDNSAdmin; this
// check is the defence-in-depth that a future MCP caller cannot skip.
//
// A nil user designates an in-process caller that bypassed the transport
// middlewares (tests): it preserves the historical handler behaviour (no
// in-handler admin check) rather than inventing a new failure mode. Every
// real transport authenticates before the handler runs.
func requireAdmin(user *models.User) error {
	if user == nil || user.CanManageDNS() {
		return nil
	}
	return ErrForbidden
}

// authorizeZone enforces zone-scoped authorization for a service call on
// zoneID. DNS admins (admins and operators) pass; any other authenticated
// user must hold a group grant on the zone (CanAccessZone — fail-closed).
// A nil user designates an in-process caller (see requireAdmin); the REST
// middleware stack and the MCP transport both authenticate and authorize
// before handlers run.
//
// A failed lookup returns a StageError(StageZoneAccess) so callers can
// distinguish a database fault (HTTP 500) from a genuine denial
// (ErrForbidden → HTTP 403).
func (s *Service) authorizeZone(ctx context.Context, user *models.User, zoneID string) error {
	if user == nil || user.CanManageDNS() {
		return nil
	}
	ok, err := CanAccessZone(ctx, s.DB, user, zoneID)
	if err != nil {
		return &StageError{Stage: StageZoneAccess, Err: fmt.Errorf("zone access lookup: %w", err)}
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

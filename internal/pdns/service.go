package pdns

import "github.com/babykart/gozone/internal/models"

// ZoneService defines the interface for PowerDNS zone and record operations.
//
// It abstracts the PowerDNS REST API, enabling mocking in tests without
// requiring an HTTP server. The *Client type implements this interface.
type ZoneService interface {
	// Servers
	GetServers() ([]models.ServerInfo, error)
	GetServer() (*models.ServerInfo, error)
	GetStatistics() ([]models.StatisticItem, error)
	ServerID() string

	// Zones
	ListZones() ([]models.Zone, error)
	GetZone(zoneID string) (*models.Zone, error)
	CreateZone(req models.ZoneCreateRequest) (*models.Zone, error)
	DeleteZone(zoneID string) error

	// Records
	ListRecords(zoneID string) ([]models.RRSet, error)
	CreateRecord(zoneID string, rrset models.RRSet) error
	UpdateRecord(zoneID string, rrset models.RRSet) error
	DeleteRecord(zoneID string, name, recordType string) error

	// DNSSEC & replication
	RectifyZone(zoneID string) error
	NotifySlaves(zoneID string) error
}

// Compile-time check that Client implements ZoneService.
var _ ZoneService = (*Client)(nil)

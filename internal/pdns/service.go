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
	ListZonesWithInfo() ([]models.ZoneWithInfo, error)

	// Records
	ListRecords(zoneID string) ([]models.RRSet, error)
	CreateRecord(zoneID string, rrset models.RRSet) error
	CreateRecords(zoneID string, rrsets []models.RRSet) error
	UpdateRecord(zoneID string, rrset models.RRSet) error
	DeleteRecord(zoneID string, name, recordType string) error

	// DNSSEC & replication
	RectifyZone(zoneID string) error
	NotifySlaves(zoneID string) error

	// Metadata
	GetMetadata(zoneID string) ([]models.Metadata, error)
	SetMetadata(zoneID string, meta models.Metadata) error
	DeleteMetadata(zoneID string, kind string) error

	// TSIG Keys
	ListTSIGKeys() ([]models.TSIGKey, error)
	GetTSIGKey(id string) (*models.TSIGKey, error)
	CreateTSIGKey(key models.TSIGKey) (*models.TSIGKey, error)
	UpdateTSIGKey(id string, key models.TSIGKey) error
	DeleteTSIGKey(id string) error
}

// Compile-time check that Client implements ZoneService.
var _ ZoneService = (*Client)(nil)

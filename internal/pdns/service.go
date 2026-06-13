package pdns

import (
	"context"

	"github.com/babykart/gozone/internal/models"
)

// ZoneService defines the interface for PowerDNS zone and record operations.
//
// It abstracts the PowerDNS REST API, enabling mocking in tests without
// requiring an HTTP server. The *Client type implements this interface.
type ZoneService interface {
	// Servers
	GetServers(ctx context.Context) ([]models.ServerInfo, error)
	GetServer(ctx context.Context) (*models.ServerInfo, error)
	GetStatistics(ctx context.Context) ([]models.StatisticItem, error)
	HealthCheck(ctx context.Context) error
	ServerID() string

	// Zones
	ListZones(ctx context.Context) ([]models.Zone, error)
	GetZone(ctx context.Context, zoneID string) (*models.Zone, error)
	CreateZone(ctx context.Context, req models.ZoneCreateRequest) (*models.Zone, error)
	DeleteZone(ctx context.Context, zoneID string) error
	ListZonesWithInfo(ctx context.Context) ([]models.ZoneWithInfo, error)

	// Records
	ListRecords(ctx context.Context, zoneID string) ([]models.RRSet, error)
	CreateRecord(ctx context.Context, zoneID string, rrset models.RRSet) error
	CreateRecords(ctx context.Context, zoneID string, rrsets []models.RRSet) error
	UpdateRecord(ctx context.Context, zoneID string, rrset models.RRSet) error
	DeleteRecord(ctx context.Context, zoneID string, name, recordType string) error

	// DNSSEC & replication
	RectifyZone(ctx context.Context, zoneID string) error
	NotifySlaves(ctx context.Context, zoneID string) error

	// Metadata
	GetMetadata(ctx context.Context, zoneID string) ([]models.Metadata, error)
	SetMetadata(ctx context.Context, zoneID string, meta models.Metadata) error
	DeleteMetadata(ctx context.Context, zoneID string, kind string) error

	// TSIG Keys
	ListTSIGKeys(ctx context.Context) ([]models.TSIGKey, error)
	GetTSIGKey(ctx context.Context, id string) (*models.TSIGKey, error)
	CreateTSIGKey(ctx context.Context, key models.TSIGKey) (*models.TSIGKey, error)
	UpdateTSIGKey(ctx context.Context, id string, key models.TSIGKey) error
	DeleteTSIGKey(ctx context.Context, id string) error

	// DNSSEC Cryptokeys
	ListCryptokeys(ctx context.Context, zoneID string) ([]models.Cryptokey, error)
	CreateCryptokey(ctx context.Context, zoneID string, keyType string, active bool, algorithm string) (*models.Cryptokey, error)
	ToggleCryptokey(ctx context.Context, zoneID string, keyID int, active bool) error
	DeleteCryptokey(ctx context.Context, zoneID string, keyID int) error

	// Cache
	InvalidateZoneCache(ctx context.Context, zoneID string)
}

// Compile-time check that Client implements ZoneService.
var _ ZoneService = (*Client)(nil)

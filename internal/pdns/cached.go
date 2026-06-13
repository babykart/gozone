package pdns

import (
	"context"
	"time"

	"github.com/babykart/gozone/internal/cache"
	"github.com/babykart/gozone/internal/models"
)

const (
	cacheKeyZoneList = "zones"
	cacheKeyZoneInfo = "zones-info"
	cacheKeyServer   = "server"
	cacheKeyStats    = "stats"
	cacheKeyTSIG     = "tsigkeys"
)

// cachedClient wraps a Client with an in-memory TTL cache for frequently
// accessed read operations. All mutation methods invalidate the relevant
// caches before delegating to the underlying client.
type cachedClient struct {
	client *Client

	zoneList *cache.Cache[[]models.Zone]
	zoneInfo *cache.Cache[[]models.ZoneWithInfo]
	server   *cache.Cache[*models.ServerInfo]
	stats    *cache.Cache[[]models.StatisticItem]
	tsigKeys *cache.Cache[[]models.TSIGKey]
}

// NewCachedClient wraps a PowerDNS Client with read-through caching.
//
// Cache TTLs:
//
//	Zone list       1 minute
//	Server info     5 minutes
//	Statistics     30 seconds
//	TSIG keys       5 minutes
func NewCachedClient(client *Client) ZoneService {
	return &cachedClient{
		client:   client,
		zoneList: cache.New[[]models.Zone](1 * time.Minute),
		zoneInfo: cache.New[[]models.ZoneWithInfo](1 * time.Minute),
		server:   cache.New[*models.ServerInfo](5 * time.Minute),
		stats:    cache.New[[]models.StatisticItem](30 * time.Second),
		tsigKeys: cache.New[[]models.TSIGKey](5 * time.Minute),
	}
}

func (c *cachedClient) ServerID() string { return c.client.ServerID() }

// --- Read operations (cached) ---

func (c *cachedClient) GetServers(ctx context.Context) ([]models.ServerInfo, error) {
	return c.client.GetServers(ctx)
}

func (c *cachedClient) GetServer(ctx context.Context) (*models.ServerInfo, error) {
	if v, ok := c.server.Get(cacheKeyServer); ok {
		return v, nil
	}
	s, err := c.client.GetServer(ctx)
	if err != nil {
		return nil, err
	}
	c.server.Set(cacheKeyServer, s)
	return s, nil
}

// HealthCheck bypasses the server cache so readiness probes reflect the
// current availability of PowerDNS rather than a stale cached response.
func (c *cachedClient) HealthCheck(ctx context.Context) error {
	_, err := c.client.GetServer(ctx)
	return err
}

func (c *cachedClient) GetStatistics(ctx context.Context) ([]models.StatisticItem, error) {
	if v, ok := c.stats.Get(cacheKeyStats); ok {
		return v, nil
	}
	s, err := c.client.GetStatistics(ctx)
	if err != nil {
		return nil, err
	}
	c.stats.Set(cacheKeyStats, s)
	return s, nil
}

func (c *cachedClient) ListZones(ctx context.Context) ([]models.Zone, error) {
	if v, ok := c.zoneList.Get(cacheKeyZoneList); ok {
		return v, nil
	}
	z, err := c.client.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	c.zoneList.Set(cacheKeyZoneList, z)
	return z, nil
}

func (c *cachedClient) ListZonesWithInfo(ctx context.Context) ([]models.ZoneWithInfo, error) {
	if v, ok := c.zoneInfo.Get(cacheKeyZoneInfo); ok {
		return v, nil
	}
	z, err := c.client.ListZonesWithInfo(ctx)
	if err != nil {
		return nil, err
	}
	c.zoneInfo.Set(cacheKeyZoneInfo, z)
	return z, nil
}

func (c *cachedClient) GetZone(ctx context.Context, zoneID string) (*models.Zone, error) {
	return c.client.GetZone(ctx, zoneID)
}

func (c *cachedClient) ListRecords(ctx context.Context, zoneID string) ([]models.RRSet, error) {
	return c.client.ListRecords(ctx, zoneID)
}

func (c *cachedClient) GetMetadata(ctx context.Context, zoneID string) ([]models.Metadata, error) {
	return c.client.GetMetadata(ctx, zoneID)
}

// --- TSIG (cached) ---

func (c *cachedClient) ListTSIGKeys(ctx context.Context) ([]models.TSIGKey, error) {
	if v, ok := c.tsigKeys.Get(cacheKeyTSIG); ok {
		return v, nil
	}
	k, err := c.client.ListTSIGKeys(ctx)
	if err != nil {
		return nil, err
	}
	c.tsigKeys.Set(cacheKeyTSIG, k)
	return k, nil
}

func (c *cachedClient) GetTSIGKey(ctx context.Context, id string) (*models.TSIGKey, error) {
	return c.client.GetTSIGKey(ctx, id)
}

// --- Mutation operations (invalidate-related caches) ---

func (c *cachedClient) CreateZone(ctx context.Context, req models.ZoneCreateRequest) (*models.Zone, error) {
	z, err := c.client.CreateZone(ctx, req)
	if err != nil {
		return nil, err
	}
	c.invalidateZones()
	return z, nil
}

func (c *cachedClient) DeleteZone(ctx context.Context, zoneID string) error {
	if err := c.client.DeleteZone(ctx, zoneID); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) CreateRecord(ctx context.Context, zoneID string, rrset models.RRSet) error {
	if err := c.client.CreateRecord(ctx, zoneID, rrset); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) CreateRecords(ctx context.Context, zoneID string, rrsets []models.RRSet) error {
	if err := c.client.CreateRecords(ctx, zoneID, rrsets); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) UpdateRecord(ctx context.Context, zoneID string, rrset models.RRSet) error {
	if err := c.client.UpdateRecord(ctx, zoneID, rrset); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) DeleteRecord(ctx context.Context, zoneID string, name, recordType string) error {
	if err := c.client.DeleteRecord(ctx, zoneID, name, recordType); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) RectifyZone(ctx context.Context, zoneID string) error {
	return c.client.RectifyZone(ctx, zoneID)
}

func (c *cachedClient) NotifySlaves(ctx context.Context, zoneID string) error {
	return c.client.NotifySlaves(ctx, zoneID)
}

func (c *cachedClient) SetMetadata(ctx context.Context, zoneID string, meta models.Metadata) error {
	return c.client.SetMetadata(ctx, zoneID, meta)
}

func (c *cachedClient) DeleteMetadata(ctx context.Context, zoneID string, kind string) error {
	return c.client.DeleteMetadata(ctx, zoneID, kind)
}

func (c *cachedClient) CreateTSIGKey(ctx context.Context, key models.TSIGKey) (*models.TSIGKey, error) {
	k, err := c.client.CreateTSIGKey(ctx, key)
	if err != nil {
		return nil, err
	}
	c.tsigKeys.Clear()
	return k, nil
}

func (c *cachedClient) UpdateTSIGKey(ctx context.Context, id string, key models.TSIGKey) error {
	if err := c.client.UpdateTSIGKey(ctx, id, key); err != nil {
		return err
	}
	c.tsigKeys.Clear()
	return nil
}

func (c *cachedClient) DeleteTSIGKey(ctx context.Context, id string) error {
	if err := c.client.DeleteTSIGKey(ctx, id); err != nil {
		return err
	}
	c.tsigKeys.Clear()
	return nil
}

// invalidateZones clears zone and statistics caches after a zone-level mutation.
func (c *cachedClient) invalidateZones() {
	c.zoneList.Clear()
	c.zoneInfo.Clear()
	c.stats.Clear()
}

// InvalidateZoneCache clears the zone list and zone info caches so the next
// read fetches fresh data from PowerDNS. Does not clear server or TSIG caches.
func (c *cachedClient) InvalidateZoneCache(ctx context.Context, zoneID string) {
	c.zoneList.Clear()
	c.zoneInfo.Clear()
}

// --- DNSSEC Cryptokeys (passthrough, not cached) ---

func (c *cachedClient) ListCryptokeys(ctx context.Context, zoneID string) ([]models.Cryptokey, error) {
	return c.client.ListCryptokeys(ctx, zoneID)
}

func (c *cachedClient) CreateCryptokey(ctx context.Context, zoneID string, keyType string, active bool, algorithm string) (*models.Cryptokey, error) {
	return c.client.CreateCryptokey(ctx, zoneID, keyType, active, algorithm)
}

func (c *cachedClient) ToggleCryptokey(ctx context.Context, zoneID string, keyID int, active bool) error {
	return c.client.ToggleCryptokey(ctx, zoneID, keyID, active)
}

func (c *cachedClient) DeleteCryptokey(ctx context.Context, zoneID string, keyID int) error {
	return c.client.DeleteCryptokey(ctx, zoneID, keyID)
}

// Compile-time check that cachedClient implements ZoneService.
var _ ZoneService = (*cachedClient)(nil)

package pdns

import (
	"context"
	"strconv"
	"sync/atomic"
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
// caches (bumping gen and clearing entries) before delegating to the
// underlying client.
//
// Concurrency properties (m44/m45):
//   - Concurrent misses of the same cache key are single-flighted: only the
//     leader calls PowerDNS; followers share its result.
//   - A read whose fetch is still in flight when an invalidation lands must not
//     repopulate the cache with stale data. Each invalidation bumps a global
//     generation counter (gen) BEFORE clearing; a fetch caches its result only
//     if the generation is unchanged since the fetch started.
type cachedClient struct {
	client *Client

	zoneList *cache.Cache[[]models.Zone]
	zoneInfo *cache.Cache[[]models.ZoneWithInfo]
	server   *cache.Cache[*models.ServerInfo]
	stats    *cache.Cache[[]models.StatisticItem]
	tsigKeys *cache.Cache[[]models.TSIGKey]

	flight singleFlight // coalesces concurrent cache misses (m44)
	gen    atomic.Int64 // bumped on every invalidation (m45)
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

// readThrough is the cache fast-path + single-flight + generation-guard helper
// shared by every cached read.
//
// On a cache hit it returns immediately. On a miss it deduplicates concurrent
// misses via single-flight (m44): the single-flight key embeds the generation
// captured at miss time, so an invalidation mid-flight causes later readers to
// form a new flight and fetch fresh data rather than wait on a stale one. The
// leader's result is written back to the cache ONLY if the generation is
// unchanged since the fetch started (m45) — preventing a slow reader from
// repopulating the cache with data rendered stale by an invalidation that
// landed during its fetch.
//
// Context note: the leader's context drives fetch and followers share the
// leader's outcome. This is the standard single-flight tradeoff and is
// acceptable here (PDNS reads are short and request contexts share lifetimes).
func readThrough[V any](
	c *cachedClient,
	ch *cache.Cache[V],
	key string,
	ctx context.Context,
	fetch func(context.Context) (V, error),
) (V, error) {
	if v, ok := ch.Get(key); ok {
		return v, nil
	}
	gen := c.gen.Load()
	sfKey := key + ":" + strconv.FormatInt(gen, 10)
	val, err := c.flight.Do(sfKey, func() (any, error) {
		v, ferr := fetch(ctx)
		if ferr != nil {
			return nil, ferr
		}
		// m45: only repopulate if no invalidation occurred during the fetch.
		if c.gen.Load() == gen {
			ch.Set(key, v)
		}
		return v, nil
	})
	if err != nil {
		var zero V
		return zero, err
	}
	return val.(V), nil
}

// --- Read operations (cached) ---

func (c *cachedClient) GetServers(ctx context.Context) ([]models.ServerInfo, error) {
	return c.client.GetServers(ctx)
}

func (c *cachedClient) GetServer(ctx context.Context) (*models.ServerInfo, error) {
	return readThrough(c, c.server, cacheKeyServer, ctx, c.client.GetServer)
}

// HealthCheck bypasses the server cache so readiness probes reflect the
// current availability of PowerDNS rather than a stale cached response.
func (c *cachedClient) HealthCheck(ctx context.Context) error {
	_, err := c.client.GetServer(ctx)
	return err
}

func (c *cachedClient) GetStatistics(ctx context.Context) ([]models.StatisticItem, error) {
	return readThrough(c, c.stats, cacheKeyStats, ctx, c.client.GetStatistics)
}

func (c *cachedClient) ListZones(ctx context.Context) ([]models.Zone, error) {
	return readThrough(c, c.zoneList, cacheKeyZoneList, ctx, c.client.ListZones)
}

func (c *cachedClient) ListZonesWithInfo(ctx context.Context) ([]models.ZoneWithInfo, error) {
	return readThrough(c, c.zoneInfo, cacheKeyZoneInfo, ctx, c.client.ListZonesWithInfo)
}

func (c *cachedClient) GetZone(ctx context.Context, zoneID string) (*models.Zone, error) {
	return c.client.GetZone(ctx, zoneID)
}

func (c *cachedClient) ListRecords(ctx context.Context, zoneID string) ([]models.RRSet, error) {
	return c.client.ListRecords(ctx, zoneID)
}

func (c *cachedClient) ListRecord(ctx context.Context, zoneID, name, rrType string) ([]models.RRSet, error) {
	return c.client.ListRecord(ctx, zoneID, name, rrType)
}

func (c *cachedClient) GetMetadata(ctx context.Context, zoneID string) ([]models.Metadata, error) {
	return c.client.GetMetadata(ctx, zoneID)
}

// --- TSIG (cached) ---

func (c *cachedClient) ListTSIGKeys(ctx context.Context) ([]models.TSIGKey, error) {
	return readThrough(c, c.tsigKeys, cacheKeyTSIG, ctx, c.client.ListTSIGKeys)
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

func (c *cachedClient) PatchRecords(ctx context.Context, zoneID string, rrsets []models.RRSet) error {
	if err := c.client.PatchRecords(ctx, zoneID, rrsets); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) RectifyZone(ctx context.Context, zoneID string) error {
	if err := c.client.RectifyZone(ctx, zoneID); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) NotifySlaves(ctx context.Context, zoneID string) error {
	return c.client.NotifySlaves(ctx, zoneID)
}

func (c *cachedClient) SetMetadata(ctx context.Context, zoneID string, meta models.Metadata) error {
	if err := c.client.SetMetadata(ctx, zoneID, meta); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) DeleteMetadata(ctx context.Context, zoneID string, kind string) error {
	if err := c.client.DeleteMetadata(ctx, zoneID, kind); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) CreateTSIGKey(ctx context.Context, key models.TSIGKey) (*models.TSIGKey, error) {
	k, err := c.client.CreateTSIGKey(ctx, key)
	if err != nil {
		return nil, err
	}
	c.invalidateTSIG()
	return k, nil
}

func (c *cachedClient) UpdateTSIGKey(ctx context.Context, id string, key models.TSIGKey) error {
	if err := c.client.UpdateTSIGKey(ctx, id, key); err != nil {
		return err
	}
	c.invalidateTSIG()
	return nil
}

func (c *cachedClient) DeleteTSIGKey(ctx context.Context, id string) error {
	if err := c.client.DeleteTSIGKey(ctx, id); err != nil {
		return err
	}
	c.invalidateTSIG()
	return nil
}

// invalidateZones clears zone and statistics caches after a zone-level mutation.
// gen is bumped BEFORE the clears so an in-flight fetch that completes during
// the invalidation fails its generation check and does not repopulate (m45).
func (c *cachedClient) invalidateZones() {
	c.gen.Add(1)
	c.zoneList.Clear()
	c.zoneInfo.Clear()
	c.stats.Clear()
}

// invalidateTSIG clears the TSIG key cache after a TSIG mutation. gen is bumped
// first for the same reason as invalidateZones (m45).
func (c *cachedClient) invalidateTSIG() {
	c.gen.Add(1)
	c.tsigKeys.Clear()
}

// InvalidateZoneCache clears the zone list and zone info caches so the next
// read fetches fresh data from PowerDNS. Does not clear server or TSIG caches.
func (c *cachedClient) InvalidateZoneCache(ctx context.Context, zoneID string) {
	c.gen.Add(1)
	c.zoneList.Clear()
	c.zoneInfo.Clear()
}

// --- DNSSEC Cryptokeys (reads passthrough, mutations invalidate zones) ---

func (c *cachedClient) ListCryptokeys(ctx context.Context, zoneID string) ([]models.Cryptokey, error) {
	return c.client.ListCryptokeys(ctx, zoneID)
}

func (c *cachedClient) CreateCryptokey(ctx context.Context, zoneID string, keyType string, active bool, algorithm string) (*models.Cryptokey, error) {
	k, err := c.client.CreateCryptokey(ctx, zoneID, keyType, active, algorithm)
	if err != nil {
		return nil, err
	}
	c.invalidateZones()
	return k, nil
}

func (c *cachedClient) ToggleCryptokey(ctx context.Context, zoneID string, keyID int, active bool) error {
	if err := c.client.ToggleCryptokey(ctx, zoneID, keyID, active); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

func (c *cachedClient) DeleteCryptokey(ctx context.Context, zoneID string, keyID int) error {
	if err := c.client.DeleteCryptokey(ctx, zoneID, keyID); err != nil {
		return err
	}
	c.invalidateZones()
	return nil
}

// Close stops the background sweep goroutines of all internal caches.
// It should be called once, typically via defer, during application shutdown.
func (c *cachedClient) Close() {
	c.zoneList.Stop()
	c.zoneInfo.Stop()
	c.server.Stop()
	c.stats.Stop()
	c.tsigKeys.Stop()
}

// Compile-time check that cachedClient implements ZoneService.
var _ ZoneService = (*cachedClient)(nil)

// Package cache provides a generic in-memory cache with per-item TTL expiration
// and background eviction of expired entries.
package cache

import (
	"context"
	"sync"
	"time"
)

// entry holds a cached value and its expiration timestamp.
type entry[V any] struct {
	value  V
	expiry time.Time
}

// Cache is a generic in-memory cache with a fixed TTL for all entries and
// background eviction of expired items. Zero value is not usable; create with New.
// Call Stop() when the cache is no longer needed to halt the eviction goroutine.
type Cache[V any] struct {
	mu     sync.RWMutex
	items  map[string]*entry[V]
	ttl    time.Duration
	cancel context.CancelFunc
}

// New creates a cache where every entry expires after ttl.
// A background goroutine periodically sweeps expired entries.
// Call Stop() to halt the goroutine when the cache is no longer needed.
func New[V any](ttl time.Duration) *Cache[V] {
	// #nosec G118 — cancel stored in struct and called via Stop() on shutdown
	ctx, cancel := context.WithCancel(context.Background())
	c := &Cache[V]{
		items:  make(map[string]*entry[V]),
		ttl:    ttl,
		cancel: cancel,
	}
	go c.runSweep(ctx)
	return c
}

// Stop halts the background eviction goroutine. The cache remains usable
// (Get/Set/Delete still work) but expired entries are no longer auto-cleaned.
func (c *Cache[V]) Stop() {
	c.cancel()
}

// Get returns the cached value and true if the key exists and has not expired.
// When Get observes an already-expired entry it proactively deletes it (under
// the write lock, with a re-check) so stale entries do not linger until the
// next background sweep — this bounds memory retention on read traffic even
// when the sweeper interval is long (REVIEW.md L-16a). The valid-entry path
// stays on the read lock.
func (c *Cache[V]) Get(key string) (V, bool) {
	now := time.Now()
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return *new(V), false
	}
	if !now.After(e.expiry) {
		return e.value, true
	}
	c.mu.Lock()
	if cur, ok := c.items[key]; ok && now.After(cur.expiry) {
		delete(c.items, key)
	}
	c.mu.Unlock()
	return *new(V), false
}

// Set stores a value under key with the configured TTL.
func (c *Cache[V]) Set(key string, value V) {
	c.mu.Lock()
	c.items[key] = &entry[V]{value: value, expiry: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// Delete removes a single key from the cache.
func (c *Cache[V]) Delete(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

// Clear removes all entries from the cache.
func (c *Cache[V]) Clear() {
	c.mu.Lock()
	c.items = make(map[string]*entry[V])
	c.mu.Unlock()
}

// Len returns the number of non-expired entries currently in the cache.
func (c *Cache[V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, e := range c.items {
		if !now.After(e.expiry) {
			count++
		}
	}
	return count
}

// sweep removes all expired entries. Called periodically by the background goroutine.
func (c *Cache[V]) sweep() {
	c.mu.Lock()
	now := time.Now()
	for k, e := range c.items {
		if now.After(e.expiry) {
			delete(c.items, k)
		}
	}
	c.mu.Unlock()
}

// runSweep periodically evicts expired entries until ctx is cancelled.
func (c *Cache[V]) runSweep(ctx context.Context) {
	interval := c.ttl
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.sweep()
		case <-ctx.Done():
			return
		}
	}
}

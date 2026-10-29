package dnsops

import (
	"context"
	"sync"
)

// zoneLockBackend is the database-side half of a per-zone lock. *database.DB
// implements it with the dialect-specific cluster-wide lock.
type zoneLockBackend interface {
	LockZone(ctx context.Context, zoneID string) (release func(), err error)
}

// ZoneLocks serializes read-modify-write record mutations per zone. The
// record write paths fetch the zone's RRSets, merge the submission into them
// and PATCH the result back; two concurrent mutations on the same RRSet can
// otherwise interleave their fetches, and the second PATCH silently drops the
// first's records.
//
// Lock first takes an in-process mutex so goroutines of this process do not
// wait on the database unnecessarily, then takes the database-backed lock so
// every GoZone instance sharing the same MySQL or PostgreSQL database
// serializes the same fetch→merge→write sequence. SQLite keeps the no-op
// database lock: its single-connection pool already serializes one process,
// and SQLite is not a supported shared multi-instance backend.
//
// The instance lives on the Service so REST handlers, web handlers and MCP
// tools serialize against each other on the same zone; a write through one
// transport holds the same locks a write through another transport waits on.
//
// The lock map is write-once per zone and never pruned: a mutex is a few
// dozen bytes and the zone count is bounded by what PowerDNS serves.
type ZoneLocks struct {
	mu     sync.Mutex
	locks  map[string]*sync.Mutex
	shared zoneLockBackend
}

// Lock acquires the local and shared locks for zoneID and returns one release
// function for both. The request-scoped critical section is:
//
//	release, err := locks.Lock(ctx, zoneID)
//	if err != nil { ... }
//	defer release()
//
// The local mutex is released if the shared lock cannot be acquired.
func (z *ZoneLocks) Lock(ctx context.Context, zoneID string) (func(), error) {
	releaseLocal := z.lockLocal(zoneID)
	if z.shared == nil {
		return releaseLocal, nil
	}
	releaseShared, err := z.shared.LockZone(ctx, zoneID)
	if err != nil {
		releaseLocal()
		return nil, err
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		releaseShared()
		releaseLocal()
	}, nil
}

// lockLocal acquires the in-process mutex for zoneID. The map is created
// lazily so a zero-value ZoneLocks remains usable without a constructor.
func (z *ZoneLocks) lockLocal(zoneID string) func() {
	z.mu.Lock()
	if z.locks == nil {
		z.locks = make(map[string]*sync.Mutex)
	}
	m, ok := z.locks[zoneID]
	if !ok {
		m = &sync.Mutex{}
		z.locks[zoneID] = m
	}
	z.mu.Unlock()
	m.Lock()
	return m.Unlock
}
